#!/usr/bin/env python3
"""Security panel for a self-hosted RustDesk server.

Two HTTP listeners, standard library only:

* Audit API (default 0.0.0.0:21114). RustDesk clients post here on their own once
  their API server resolves to this host (the default for clients built from this
  repo and for any client whose ID server is set to this host):
  /api/audit/conn, /api/audit/alarm, /api/audit/file, /api/heartbeat, /api/sysinfo.
* Dashboard (default 127.0.0.1:21120), protected by HTTP Basic auth: connection
  history with IPs, brute-force statistics, client-side alarms, online devices,
  and a server blocklist enforced by hbbr for relayed connections.

Configuration (environment): PANEL_USER, PANEL_PASSWORD (required), PANEL_BIND,
PANEL_PORT, API_BIND, API_PORT, DATA_DIR, RETENTION_DAYS, HBBR_ADMIN.
"""

import base64
import hmac
import ipaddress
import json
import os
import socket
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

PANEL_USER = os.environ.get("PANEL_USER", "admin")
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "")
PANEL_BIND = os.environ.get("PANEL_BIND", "127.0.0.1")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "21120"))
API_BIND = os.environ.get("API_BIND", "0.0.0.0")
API_PORT = int(os.environ.get("API_PORT", "21114"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "180"))
HBBR_ADMIN = os.environ.get("HBBR_ADMIN", "127.0.0.1:21117")

DB_FILE = DATA_DIR / "panel.sqlite3"
BLOCKLIST_FILE = DATA_DIR / "blocklist.txt"  # read by hbbr at start (its cwd is the data dir)
MAX_BODY = 64 * 1024
INGEST_RATE_PER_MIN = 240
ONLINE_SECONDS = 60

CONN_TYPES = {0: "Control", 1: "Transfer fișiere", 2: "Port forward", 3: "Cameră", 4: "Terminal"}
PRIMARY_AUTH = {1: "Acceptat manual", 2: "Parolă unică", 3: "Parolă permanentă", 4: "Inversare roluri"}
TWO_FACTOR = {1: "2FA (TOTP)", 2: "Dispozitiv de încredere"}
ALARMS = {
    0: "Respins: IP-ul nu e în whitelist",
    1: "Blocat: peste 30 de parole greșite",
    2: "Blocat 1 min: peste 6 parole greșite/minut",
    6: "Blocat: prea multe încercări din același prefix IPv6",
    7: "Login OS terminal: întârziere după eșecuri",
    8: "Login OS terminal: prea multe sesiuni simultane",
    9: "Încălcare de scope a sesiunii",
    10: "Respins: ID-ul nu e în whitelist",
}
BLOCKING_ALARMS = (1, 2, 6)

DB_LOCK = threading.Lock()


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


DB = None


def init_db():
    global DB
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DB = db()
    DB.executescript(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY,
            uuid TEXT, device_id TEXT, conn_id INTEGER, remote_ip TEXT,
            started REAL, authed REAL, ended REAL,
            peer_id TEXT, peer_name TEXT, conn_type INTEGER,
            primary_auth INTEGER, two_factor INTEGER, files INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS sessions_key ON sessions(uuid, conn_id, started);
        CREATE INDEX IF NOT EXISTS sessions_ip ON sessions(remote_ip, started);
        CREATE TABLE IF NOT EXISTS alarms (
            id INTEGER PRIMARY KEY, ts REAL, uuid TEXT, device_id TEXT,
            typ INTEGER, ip TEXT, info TEXT
        );
        CREATE INDEX IF NOT EXISTS alarms_ts ON alarms(ts);
        CREATE TABLE IF NOT EXISTS devices (
            uuid TEXT PRIMARY KEY, device_id TEXT, last_seen REAL, src_ip TEXT,
            ver INTEGER, conns TEXT, hostname TEXT, os TEXT, username TEXT,
            cpu TEXT, memory TEXT
        );
        CREATE TABLE IF NOT EXISTS blocklist (ip TEXT PRIMARY KEY, added REAL, note TEXT);
        CREATE TABLE IF NOT EXISTS pending_disconnect (uuid TEXT, conn_id INTEGER, ts REAL);
        CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, ts REAL);
        """
    )


def q(sql, args=()):
    with DB_LOCK:
        return [dict(r) for r in DB.execute(sql, args).fetchall()]


def x(sql, args=()):
    with DB_LOCK:
        return DB.execute(sql, args)


def as_text(v, limit=200):
    if v is None:
        return None
    return str(v)[:limit]


def as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def valid_ip(s):
    try:
        return str(ipaddress.ip_address(str(s).strip()))
    except ValueError:
        return None


# ---------------------------------------------------------------- hbbr blocklist

def hbbr_cmd(cmd):
    host, port = HBBR_ADMIN.rsplit(":", 1)
    try:
        with socket.create_connection((host, int(port)), timeout=2) as s:
            s.sendall(cmd.encode())
            s.settimeout(2)
            return s.recv(4096).decode(errors="replace")
    except OSError as e:
        log(f"hbbr command {cmd.split()[0]} failed: {e}")
        return None


def write_blocklist_file():
    ips = [r["ip"] for r in q("SELECT ip FROM blocklist ORDER BY ip")]
    tmp = BLOCKLIST_FILE.with_suffix(".tmp")
    tmp.write_text("".join(f"{ip}\n" for ip in ips))
    tmp.replace(BLOCKLIST_FILE)
    return ips


def sync_hbbr_blocklist():
    ips = write_blocklist_file()
    if ips:
        hbbr_cmd("Ba " + "|".join(ips))


# ---------------------------------------------------------------- audit ingest

RATE = {}
RATE_LOCK = threading.Lock()


def rate_ok(ip):
    now = int(time.time() // 60)
    with RATE_LOCK:
        minute, n = RATE.get(ip, (now, 0))
        if minute != now:
            minute, n = now, 0
        RATE[ip] = (minute, n + 1)
        if len(RATE) > 10000:
            RATE.clear()
        return n < INGEST_RATE_PER_MIN


def seen_nonce(nonce):
    if not nonce:
        return False
    try:
        x("INSERT INTO nonces(nonce, ts) VALUES(?, ?)", (as_text(nonce, 64), time.time()))
        return False
    except sqlite3.IntegrityError:
        return True


def open_session(uuid, conn_id):
    rows = q(
        "SELECT * FROM sessions WHERE uuid=? AND conn_id=? AND ended IS NULL ORDER BY started DESC LIMIT 1",
        (uuid, conn_id),
    )
    return rows[0] if rows else None


def ingest_conn(v, src_ip):
    if seen_nonce(v.get("nonce")):
        return
    now = time.time()
    uuid, conn_id = as_text(v.get("uuid"), 100), as_int(v.get("conn_id"))
    device_id = as_text(v.get("id"), 40)
    action = v.get("action")
    if action == "new":
        # A conn_id is reused after the client restarts; close any stale row first.
        x("UPDATE sessions SET ended=? WHERE uuid=? AND conn_id=? AND ended IS NULL", (now, uuid, conn_id))
        x(
            "INSERT INTO sessions(uuid, device_id, conn_id, remote_ip, started) VALUES(?,?,?,?,?)",
            (uuid, device_id, conn_id, valid_ip(v.get("ip")) or as_text(v.get("ip"), 64), now),
        )
    elif action == "close":
        s = open_session(uuid, conn_id)
        if s:
            x("UPDATE sessions SET ended=? WHERE id=?", (now, s["id"]))
    elif "peer" in v:
        peer = v.get("peer") or ["", ""]
        if not isinstance(peer, list):
            peer = [peer, ""]
        s = open_session(uuid, conn_id)
        if not s:
            x(
                "INSERT INTO sessions(uuid, device_id, conn_id, started) VALUES(?,?,?,?)",
                (uuid, device_id, conn_id, now),
            )
            s = open_session(uuid, conn_id)
        x(
            "UPDATE sessions SET authed=?, peer_id=?, peer_name=?, conn_type=?, primary_auth=?, two_factor=? WHERE id=?",
            (
                now,
                as_text(peer[0] if len(peer) > 0 else "", 40),
                as_text(peer[1] if len(peer) > 1 else "", 100),
                as_int(v.get("type")),
                as_int(v.get("primary_auth")),
                as_int(v.get("two_factor")),
                s["id"],
            ),
        )


def ingest_alarm(v, src_ip):
    if seen_nonce(v.get("nonce")):
        return
    info = v.get("info")
    try:
        info_obj = json.loads(info) if isinstance(info, str) else (info or {})
    except ValueError:
        info_obj = {}
    if not isinstance(info_obj, dict):
        info_obj = {}
    x(
        "INSERT INTO alarms(ts, uuid, device_id, typ, ip, info) VALUES(?,?,?,?,?,?)",
        (
            time.time(),
            as_text(v.get("uuid"), 100),
            as_text(v.get("id"), 40),
            as_int(v.get("typ")),
            valid_ip(info_obj.get("ip")) or as_text(info_obj.get("ip"), 64),
            as_text(json.dumps(info_obj, ensure_ascii=False), 1000),
        ),
    )


def ingest_file(v, src_ip):
    s = open_session(as_text(v.get("uuid"), 100), as_int(v.get("conn_id")))
    if s:
        x("UPDATE sessions SET files=files+1 WHERE id=?", (s["id"],))


def heartbeat(v, src_ip):
    uuid = as_text(v.get("uuid"), 100)
    if not uuid:
        return {}
    conns = v.get("conns") or []
    conns = [c for c in conns if isinstance(c, int)][:100]
    x(
        """INSERT INTO devices(uuid, device_id, last_seen, src_ip, ver, conns) VALUES(?,?,?,?,?,?)
           ON CONFLICT(uuid) DO UPDATE SET device_id=excluded.device_id, last_seen=excluded.last_seen,
           src_ip=excluded.src_ip, ver=excluded.ver, conns=excluded.conns""",
        (uuid, as_text(v.get("id"), 40), time.time(), src_ip, as_int(v.get("ver")), json.dumps(conns)),
    )
    out = {}
    pending = q("SELECT conn_id FROM pending_disconnect WHERE uuid=?", (uuid,))
    if pending:
        out["disconnect"] = [p["conn_id"] for p in pending]
        x("DELETE FROM pending_disconnect WHERE uuid=?", (uuid,))
    if "modified_at" in v:
        out["modified_at"] = v["modified_at"]
    return out


def sysinfo(v, src_ip):
    uuid = as_text(v.get("uuid"), 100)
    if uuid:
        x(
            """INSERT INTO devices(uuid, device_id, last_seen, src_ip, hostname, os, username, cpu, memory)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(uuid) DO UPDATE SET device_id=excluded.device_id, hostname=excluded.hostname,
               os=excluded.os, username=excluded.username, cpu=excluded.cpu, memory=excluded.memory""",
            (
                uuid, as_text(v.get("id"), 40), time.time(), src_ip,
                as_text(v.get("hostname")), as_text(v.get("os")), as_text(v.get("username")),
                as_text(v.get("cpu")), as_text(v.get("memory"), 40),
            ),
        )
    # Deliberately not "SYSINFO_UPDATED": that answer makes the client treat this
    # server as RustDesk Server Pro.
    return "OK"


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "panel"

    def log_message(self, fmt, *args):
        pass

    def reply(self, code, body=b"", ctype="text/plain"):
        if isinstance(body, (dict, list)):
            body, ctype = json.dumps(body).encode(), "application/json"
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        src_ip = self.client_address[0]
        if not rate_ok(src_ip):
            return self.reply(429, {"error": "rate limited"})
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self.reply(413, {"error": "too large"})
        raw = self.rfile.read(length) if length else b""
        path = urlparse(self.path).path
        try:
            v = json.loads(raw or b"{}")
        except ValueError:
            return self.reply(400, {"error": "bad json"})
        if not isinstance(v, dict):
            return self.reply(400, {"error": "bad json"})
        try:
            if path == "/api/audit/conn":
                ingest_conn(v, src_ip)
                return self.reply(200)
            if path == "/api/audit/alarm":
                ingest_alarm(v, src_ip)
                return self.reply(200)
            if path == "/api/audit/file":
                ingest_file(v, src_ip)
                return self.reply(200)
            if path == "/api/heartbeat":
                return self.reply(200, heartbeat(v, src_ip))
            if path == "/api/sysinfo":
                return self.reply(200, sysinfo(v, src_ip))
        except Exception as e:  # keep the listener alive; the client retries 5xx
            log(f"ingest error on {path}: {e!r}")
            return self.reply(500, {"error": "internal"})
        return self.reply(404, {"error": "not supported by this server"})


# ---------------------------------------------------------------- dashboard

AUTH_FAILS = {}
AUTH_LOCK = threading.Lock()
AUTH_MAX_FAILS = 10
AUTH_LOCK_SECONDS = 900


def state(search):
    now = time.time()
    day, month = now - 86400, now - 30 * 86400
    like = f"%{search}%" if search else None

    where, args = "", []
    if like:
        where = "WHERE s.remote_ip LIKE ? OR s.device_id LIKE ? OR s.peer_id LIKE ? OR s.peer_name LIKE ? OR d.hostname LIKE ?"
        args = [like] * 5
    sessions = q(
        f"""SELECT s.*, d.hostname FROM sessions s LEFT JOIN devices d ON d.uuid = s.uuid
            {where} ORDER BY s.started DESC LIMIT 300""",
        args,
    )

    ip_where, ip_args = "WHERE s.started > ? AND s.remote_ip IS NOT NULL", [month]
    if like:
        ip_where += " AND s.remote_ip LIKE ?"
        ip_args.append(like)
    ip_stats = q(
        f"""SELECT s.remote_ip AS ip, COUNT(*) AS attempts,
                   SUM(CASE WHEN s.authed IS NOT NULL THEN 1 ELSE 0 END) AS ok,
                   SUM(CASE WHEN s.authed IS NULL AND s.ended IS NOT NULL THEN 1 ELSE 0 END) AS failed,
                   COUNT(DISTINCT s.uuid) AS devices, MAX(s.started) AS last
            FROM sessions s {ip_where} GROUP BY s.remote_ip ORDER BY failed DESC, last DESC LIMIT 200""",
        ip_args,
    )
    alarm_counts = {
        r["ip"]: r for r in q(
            "SELECT ip, COUNT(*) AS n, MAX(ts) AS last FROM alarms WHERE ts > ? AND ip IS NOT NULL GROUP BY ip",
            (month,),
        )
    }
    blocked = {r["ip"]: r for r in q("SELECT * FROM blocklist")}
    for r in ip_stats:
        a = alarm_counts.get(r["ip"])
        r["alarms"] = a["n"] if a else 0
        r["blocked"] = r["ip"] in blocked
        r["risk"] = "ridicat" if (r["failed"] >= 10 or r["alarms"]) else "mediu" if r["failed"] >= 3 else "scăzut"

    alarms = q(
        """SELECT a.*, d.hostname FROM alarms a LEFT JOIN devices d ON d.uuid = a.uuid
           ORDER BY a.ts DESC LIMIT 200"""
    )
    for a in alarms:
        a["label"] = ALARMS.get(a["typ"], f"Alarmă {a['typ']}")

    client_blocks = q(
        f"""SELECT a.ip, a.typ, MAX(a.ts) AS last, COUNT(*) AS n, GROUP_CONCAT(DISTINCT a.device_id) AS devices
            FROM alarms a WHERE a.typ IN ({",".join("?" * len(BLOCKING_ALARMS))}) AND a.ts > ? AND a.ip IS NOT NULL
            GROUP BY a.ip, a.typ ORDER BY last DESC""",
        (*BLOCKING_ALARMS, month),
    )
    for b in client_blocks:
        b["label"] = ALARMS.get(b["typ"])
        # typ 2 lifts after a minute; typ 1/6 last until the client app restarts.
        b["active"] = b["typ"] != 2 or now - b["last"] < 60

    devices = q("SELECT * FROM devices ORDER BY last_seen DESC")
    for d in devices:
        d["online"] = now - (d["last_seen"] or 0) < ONLINE_SECONDS
        d["conns"] = json.loads(d["conns"] or "[]") if d["online"] else []

    def one(sql, args=()):
        return q(sql, args)[0]["n"] or 0

    stats = {
        "devices_online": sum(1 for d in devices if d["online"]),
        "devices_total": len(devices),
        "active_sessions": one("SELECT COUNT(*) AS n FROM sessions WHERE ended IS NULL AND authed IS NOT NULL AND started > ?", (day,)),
        "conns_24h": one("SELECT COUNT(*) AS n FROM sessions WHERE authed IS NOT NULL AND started > ?", (day,)),
        "failed_24h": one("SELECT COUNT(*) AS n FROM sessions WHERE authed IS NULL AND ended IS NOT NULL AND started > ?", (day,)),
        "alarms_24h": one("SELECT COUNT(*) AS n FROM alarms WHERE ts > ?", (day,)),
        "blocked": len(blocked),
    }
    for s in sessions:
        s["type_label"] = CONN_TYPES.get(s["conn_type"], "")
        auth = PRIMARY_AUTH.get(s["primary_auth"], "")
        if s["two_factor"] in TWO_FACTOR:
            auth = f"{auth} + {TWO_FACTOR[s['two_factor']]}" if auth else TWO_FACTOR[s["two_factor"]]
        s["auth_label"] = auth
        s["blocked"] = s["remote_ip"] in blocked
    return {
        "now": now,
        "stats": stats,
        "sessions": sessions,
        "ip_stats": ip_stats,
        "alarms": alarms,
        "client_blocks": client_blocks,
        "blocklist": sorted(blocked.values(), key=lambda r: -r["added"]),
        "devices": devices,
        "hbbr_ok": hbbr_cmd("h") is not None,
    }


class PanelHandler(BaseHTTPRequestHandler):
    server_version = "panel"

    def log_message(self, fmt, *args):
        pass

    def reply(self, code, body=b"", ctype="text/plain; charset=utf-8", headers=()):
        if isinstance(body, (dict, list)):
            body, ctype = json.dumps(body, ensure_ascii=False).encode(), "application/json; charset=utf-8"
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def client_ip(self):
        return self.client_address[0]

    def authorized(self):
        ip = self.client_ip()
        now = time.time()
        with AUTH_LOCK:
            fails, until = AUTH_FAILS.get(ip, (0, 0))
            if until > now:
                self.reply(429, "Prea multe încercări greșite. Reîncearcă peste 15 minute.")
                return False
        header = self.headers.get("Authorization", "")
        ok = False
        if header.startswith("Basic "):
            try:
                user, _, pwd = base64.b64decode(header[6:]).decode().partition(":")
                ok = hmac.compare_digest(user.encode(), PANEL_USER.encode()) & hmac.compare_digest(
                    pwd.encode(), PANEL_PASSWORD.encode()
                )
            except (ValueError, UnicodeDecodeError):
                ok = False
        if ok:
            with AUTH_LOCK:
                AUTH_FAILS.pop(ip, None)
            return True
        if header:
            with AUTH_LOCK:
                fails += 1
                AUTH_FAILS[ip] = (fails, now + AUTH_LOCK_SECONDS if fails >= AUTH_MAX_FAILS else 0)
            log(f"panel: failed login from {ip}")
        self.reply(401, "Autentificare necesară", headers=[("WWW-Authenticate", 'Basic realm="Panou securitate", charset="UTF-8"')])
        return False

    def do_GET(self):
        if not self.authorized():
            return
        # Paths are matched on their last segment so the panel also works behind a
        # reverse proxy under a sub-path (e.g. /rustdesk-panel/).
        url = urlparse(self.path)
        if url.path.endswith("/api/state"):
            search = (parse_qs(url.query).get("q") or [""])[0].strip()[:100]
            return self.reply(200, state(search))
        self.reply(200, INDEX_HTML, "text/html; charset=utf-8")

    def do_POST(self):
        if not self.authorized():
            return
        # Browsers cannot add this header cross-site without CORS, which we never grant.
        if self.headers.get("X-Panel") != "1":
            return self.reply(403, {"error": "missing header"})
        length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
        try:
            v = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.reply(400, {"error": "bad json"})
        action = urlparse(self.path).path.rsplit("/api/", 1)[-1]
        if action == "block":
            ip = valid_ip(v.get("ip"))
            if not ip:
                return self.reply(400, {"error": "IP invalid"})
            x("INSERT OR REPLACE INTO blocklist(ip, added, note) VALUES(?,?,?)", (ip, time.time(), as_text(v.get("note"), 200) or ""))
            write_blocklist_file()
            applied = hbbr_cmd(f"Ba {ip}") is not None
            log(f"panel: blocked {ip} (hbbr {'ok' if applied else 'unreachable'})")
            return self.reply(200, {"ok": True, "hbbr": applied})
        if action == "unblock":
            ip = valid_ip(v.get("ip"))
            if not ip:
                return self.reply(400, {"error": "IP invalid"})
            x("DELETE FROM blocklist WHERE ip=?", (ip,))
            write_blocklist_file()
            applied = hbbr_cmd(f"Br {ip}") is not None
            log(f"panel: unblocked {ip}")
            return self.reply(200, {"ok": True, "hbbr": applied})
        if action == "disconnect":
            uuid, conn_id = as_text(v.get("uuid"), 100), as_int(v.get("conn_id"))
            if not uuid or conn_id is None:
                return self.reply(400, {"error": "date lipsă"})
            x("INSERT INTO pending_disconnect(uuid, conn_id, ts) VALUES(?,?,?)", (uuid, conn_id, time.time()))
            log(f"panel: disconnect requested for {uuid}/{conn_id}")
            return self.reply(200, {"ok": True})
        self.reply(404, {"error": "unknown action"})


def housekeeping():
    while True:
        try:
            cutoff = time.time() - RETENTION_DAYS * 86400
            x("DELETE FROM sessions WHERE started < ?", (cutoff,))
            x("DELETE FROM alarms WHERE ts < ?", (cutoff,))
            x("DELETE FROM devices WHERE last_seen < ?", (cutoff,))
            x("DELETE FROM nonces WHERE ts < ?", (time.time() - 3600,))
            x("DELETE FROM pending_disconnect WHERE ts < ?", (time.time() - 300,))
            # Sessions whose close never arrived (client crashed, network lost).
            x(
                "UPDATE sessions SET ended=started WHERE ended IS NULL AND authed IS NULL AND started < ?",
                (time.time() - 600,),
            )
        except Exception as e:
            log(f"housekeeping: {e!r}")
        time.sleep(600)


def serve(handler, bind, port, name):
    httpd = ThreadingHTTPServer((bind, port), handler)
    httpd.daemon_threads = True
    log(f"{name} listening on {bind}:{port}")
    httpd.serve_forever()


def main():
    if len(PANEL_PASSWORD) < 12:
        sys.exit("PANEL_PASSWORD must be set and at least 12 characters (see server/.env)")
    init_db()
    sync_hbbr_blocklist()
    threading.Thread(target=housekeeping, daemon=True).start()
    threading.Thread(target=serve, args=(ApiHandler, API_BIND, API_PORT, "audit API"), daemon=True).start()
    serve(PanelHandler, PANEL_BIND, PANEL_PORT, "dashboard")


INDEX_HTML = (Path(__file__).with_name("index.html")).read_text(encoding="utf-8")

if __name__ == "__main__":
    main()
