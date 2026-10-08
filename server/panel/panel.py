#!/usr/bin/env python3
"""Security panel for a self-hosted RustDesk server.

Two HTTP listeners, standard library only:

* Audit API (default 0.0.0.0:21114). RustDesk clients post here on their own once
  their API server resolves to this host (the default for clients built from this
  repo and for any client whose ID server is set to this host):
  /api/audit/conn, /api/audit/alarm, /api/audit/file, /api/heartbeat, /api/sysinfo.
* Dashboard (default 127.0.0.1:21120), protected by a login page (password + optional authenticator code): connection
  history with IPs, brute-force statistics, client-side alarms, online devices,
  and a server blocklist enforced by hbbr for relayed connections.

Configuration (environment): PANEL_USER, PANEL_PASSWORD (required), PANEL_BIND,
PANEL_PORT, API_BIND, API_PORT, DATA_DIR, RETENTION_DAYS, HBBR_ADMIN.
"""

import base64
import calendar
import csv
import io
import datetime
import secrets
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import struct
import sqlite3
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import backup
import ed25519

PANEL_USER = os.environ.get("PANEL_USER", "admin")
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "")
# Base32 key of the authenticator app (install.sh generates it); empty = password only.
PANEL_TOTP_SECRET = re.sub(r"[\s=]", "", os.environ.get("PANEL_TOTP_SECRET", "")).upper()
PANEL_BIND = os.environ.get("PANEL_BIND", "127.0.0.1")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "21120"))
API_BIND = os.environ.get("API_BIND", "0.0.0.0")
API_PORT = int(os.environ.get("API_PORT", "21114"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "180"))
HBBR_ADMIN = os.environ.get("HBBR_ADMIN", "127.0.0.1:21117")
# Y: devices without a valid license get an empty token and their sessions closed.
LICENSE_REQUIRED = os.environ.get("LICENSE_REQUIRED", "Y").upper() == "Y"
ENV_FILE = Path(os.environ.get("ENV_FILE", "/config/server.env"))
BACKUP_DIR = DATA_DIR / "backups"
AUTO_BACKUP_KEEP = int(os.environ.get("AUTO_BACKUP_KEEP", "14"))
MAX_RESTORE = 300 * 1024 * 1024
MAX_ROWS = int(os.environ.get("MAX_ROWS", "500000"))

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
    1: "Blocat: prea multe parole greșite",
    2: "Blocat 1 min: peste 6 parole greșite/minut",
    6: "Blocat: prea multe încercări din același prefix IPv6",
    7: "Login OS terminal: întârziere după eșecuri",
    8: "Login OS terminal: prea multe sesiuni simultane",
    9: "Încălcare de scope a sesiunii",
    10: "Respins: ID-ul nu e în whitelist",
    100: "Închisă: limita de conexiuni simultane a licenței",
    101: "Închisă: dispozitivul nu are drept de control (portal)",
    102: "Închisă: calculatorul acceptă doar dispozitive din organizație (portal)",
}
ALARM_SESSION_LIMIT = 100
BLOCKING_ALARMS = (1, 2, 6)

DB_LOCK = threading.Lock()


def body_length(headers, limit):
    """Content-Length as a non-negative int no larger than limit, else None."""
    try:
        n = int(headers.get("Content-Length") or 0)
    except ValueError:
        return None
    return n if 0 <= n <= limit else None


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
    # Databases (and backups) from before per-license bandwidth limits.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(licenses)")}
    if cols and "bandwidth" not in cols:
        conn.execute("ALTER TABLE licenses ADD COLUMN bandwidth INTEGER DEFAULT 0")
    if cols and "sessions" not in cols:
        conn.execute("ALTER TABLE licenses ADD COLUMN sessions INTEGER DEFAULT 1")
    # Organization portal: names and rights per device (set by the client's administrator).
    acols = {r[1] for r in conn.execute("PRAGMA table_info(activations)")}
    for col, ddl in (("alias", "TEXT"), ("can_control", "INTEGER DEFAULT 1"), ("accept_external", "INTEGER DEFAULT 1")):
        if acols and col not in acols:
            conn.execute(f"ALTER TABLE activations ADD COLUMN {col} {ddl}")
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
        CREATE TABLE IF NOT EXISTS licenses (
            code TEXT PRIMARY KEY, client TEXT, seats INTEGER, months INTEGER,
            created REAL, starts REAL, expires REAL, revoked INTEGER DEFAULT 0, note TEXT,
            bandwidth INTEGER DEFAULT 0, sessions INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS activations (
            uuid TEXT PRIMARY KEY, code TEXT, device_id TEXT, hostname TEXT,
            activated REAL, last_seen REAL,
            alias TEXT, can_control INTEGER DEFAULT 1, accept_external INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS shop_orders (
            order_id INTEGER PRIMARY KEY, status TEXT, email TEXT, client TEXT, codes TEXT, new_codes TEXT, extended TEXT, message TEXT,
            note_sent INTEGER DEFAULT 0, note_due REAL, cancelled INTEGER DEFAULT 0, error TEXT, created REAL, updated REAL
        );
        CREATE TABLE IF NOT EXISTS shop_licenses (code TEXT PRIMARY KEY, email TEXT, product TEXT, created REAL);
        CREATE TABLE IF NOT EXISTS portal_users (
            id INTEGER PRIMARY KEY, code TEXT, email TEXT UNIQUE, name TEXT, pw_hash TEXT,
            role TEXT DEFAULT 'admin', created REAL, last_login REAL
        );
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
        peer_id = as_text(peer[0] if len(peer) > 0 else "", 40)
        if not enforce_device_rights(uuid, conn_id, peer_id, device_id):
            enforce_session_limit(uuid, conn_id, peer_id, device_id)


# Why the panel closed a connection, per device; sent with the next heartbeat's "disconnect".
DISCONNECT_REASON = {}


def close_session(uuid, conn_id, device_id, typ, reason, info):
    x("INSERT INTO pending_disconnect(uuid, conn_id, ts) VALUES(?,?,?)", (uuid, conn_id, time.time()))
    DISCONNECT_REASON[uuid] = reason
    x(
        "INSERT INTO alarms(ts, uuid, device_id, typ, ip, info) VALUES(?,?,?,?,?,?)",
        (time.time(), uuid, device_id, typ, None, json.dumps(info, ensure_ascii=False)),
    )


def enforce_device_rights(uuid, conn_id, peer_id, device_id):
    """Rights set in the organization portal; True when the session was closed."""
    if not peer_id:
        return False
    ctrl = q("""SELECT a.code, a.can_control, l.client FROM activations a JOIN licenses l ON l.code = a.code
                WHERE a.device_id = ?""", (peer_id,))
    if ctrl and not ctrl[0]["can_control"]:
        close_session(uuid, conn_id, device_id, 101,
                      f"Dispozitivul tău nu are drept de control în organizația {ctrl[0]['client'] or ''}. "
                      "Cere-l administratorului din portalul RDN Remote.",
                      {"licență": ctrl[0]["code"], "de la": peer_id})
        return True
    target = q("""SELECT a.code, a.accept_external, l.client FROM activations a JOIN licenses l ON l.code = a.code
                  WHERE a.uuid = ?""", (uuid,))
    if target and not target[0]["accept_external"] and (not ctrl or ctrl[0]["code"] != target[0]["code"]):
        close_session(uuid, conn_id, device_id, 102,
                      "Acest calculator acceptă conexiuni doar de la dispozitivele organizației lui.",
                      {"licență": target[0]["code"], "de la": peer_id})
        return True
    return False


def enforce_session_limit(uuid, conn_id, peer_id, device_id):
    """Closes a new session when the controller's license already has `sessions` open.

    A session counts once per (controlling device, controlled device): a second window
    (file transfer, camera) on a computer already being controlled is not a new one.
    """
    if not peer_id:
        return
    rows = q("SELECT l.* FROM activations a JOIN licenses l ON l.code = a.code WHERE a.device_id = ?", (peer_id,))
    if not rows:
        return
    lic = rows[0]
    limit = int(lic.get("sessions") or 0)
    if limit <= 0:
        return
    open_rows = q(
        """SELECT s.uuid, s.conn_id, s.peer_id, d.conns, d.last_seen FROM sessions s
           JOIN activations a ON a.device_id = s.peer_id AND a.code = ?
           JOIN devices d ON d.uuid = s.uuid
           WHERE s.ended IS NULL AND s.authed IS NOT NULL""",
        (lic["code"],),
    )
    now, pairs = time.time(), set()
    for r in open_rows:
        if r["uuid"] == uuid and r["conn_id"] == conn_id:
            continue
        try:
            live = r["conn_id"] in json.loads(r["conns"] or "[]")
        except ValueError:
            live = False
        if live and now - (r["last_seen"] or 0) < ONLINE_SECONDS:
            pairs.add((r["peer_id"], r["uuid"]))
    if (peer_id, uuid) in pairs or len(pairs) < limit:
        return
    x("INSERT INTO pending_disconnect(uuid, conn_id, ts) VALUES(?,?,?)", (uuid, conn_id, now))
    DISCONNECT_REASON[uuid] = (
        f"Licența {lic['client'] or ''} permite {limit} "
        f"{'conexiune simultană' if limit == 1 else 'conexiuni simultane'}, iar limita e atinsă. "
        "Închide o altă sesiune sau contactează RDN Network Data pentru mai multe conexiuni."
    )
    x(
        "INSERT INTO alarms(ts, uuid, device_id, typ, ip, info) VALUES(?,?,?,?,?,?)",
        (now, uuid, device_id, ALARM_SESSION_LIMIT, None,
         json.dumps({"licență": lic["code"], "client": lic["client"], "de la": peer_id, "limită": limit}, ensure_ascii=False)),
    )
    log(f"licenses: {lic['code']} at its limit of {limit} sessions; closing {peer_id} -> {device_id}")


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


def latest_release():
    """Release that clients should run, written by web/update_downloads.py."""
    try:
        data = json.loads((DATA_DIR / "latest.json").read_text())
    except (OSError, ValueError):
        return {}
    tag, repo = str(data.get("tag") or ""), str(data.get("repo") or "")
    if not re.fullmatch(r"[0-9A-Za-z._-]{1,40}", tag) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        return {}
    # RustDesk turns ".../releases/tag/X" into ".../releases/download/X/<file>".
    return {"url": f"https://github.com/{repo}/releases/tag/{tag}"}


# ---------------------------------------------------------------- licenses
#
# A license (code) covers `seats` computers for `months` (0 = unlimited), counted from
# its first activation. Clients get a token signed with the rendezvous server key
# (data/id_ed25519), which they verify offline with the key they are built with.
# Tokens live TOKEN_TTL and are refreshed in every heartbeat, so a revoked or expired
# license stops working at the next heartbeat (or after TOKEN_TTL when offline).

TOKEN_TTL = 7 * 86400
# Must match TOKEN_PREFIX in src/license.rs. The same key signs hbbs' protobuf messages;
# a leading zero byte can never start a valid protobuf message, so a token can't be
# mistaken for one (and vice versa).
TOKEN_PREFIX = b"\x00RDN-LICENSE-1\x00"
try:  # libsodium (constant time) when the image provides it; see panel/Dockerfile
    import nacl.signing

    def _sign(seed, msg):
        return nacl.signing.SigningKey(seed).sign(msg).signature
except ImportError:
    _sign = ed25519.sign
PERIODS = (0, 1, 3, 6, 9, 12)
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_SIGNING_SEED = None
_TOKEN_CACHE = {}
ACT_FAILS = {}
ACT_LOCK = threading.Lock()


def signing_seed():
    global _SIGNING_SEED
    if _SIGNING_SEED is None:
        try:
            raw = base64.b64decode((DATA_DIR / "id_ed25519").read_text().strip())
        except (OSError, ValueError):
            return None
        if len(raw) != 64 or ed25519.public_key(raw[:32]) != raw[32:]:
            log("licenses: data/id_ed25519 is not a valid Ed25519 key; licensing disabled")
            return None
        _SIGNING_SEED = raw[:32]
    return _SIGNING_SEED


def add_months(ts, months):
    d = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    m = d.month - 1 + months
    year, month = d.year + m // 12, m % 12 + 1
    day = min(d.day, calendar.monthrange(year, month)[1])
    return d.replace(year=year, month=month, day=day).timestamp()


CODE_GROUPS, CODE_GROUP_LEN = 5, 5  # 25 random characters from 32 symbols: 125 bits


def new_code():
    groups = ["".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_GROUP_LEN)) for _ in range(CODE_GROUPS)]
    return "RDN-" + "-".join(groups)


def normalize_code(raw):
    """Accept codes typed in lowercase, without dashes or with spaces."""
    code = re.sub(r"[^A-Z0-9]", "", str(raw or "").upper())
    if not code.startswith("RDN"):
        return code
    body = code[3:]
    # Current codes: 5 groups of 5; codes created before: 3 groups of 4.
    size = CODE_GROUP_LEN if len(body) == CODE_GROUPS * CODE_GROUP_LEN else 4 if len(body) == 12 else 0
    if not size:
        return code
    return "RDN-" + "-".join(body[i:i + size] for i in range(0, len(body), size))


def license_ok(lic, now=None):
    now = now or time.time()
    if not lic or lic["revoked"]:
        return False
    return lic["expires"] is None or lic["expires"] > now


def license_status(lic, now=None):
    now = now or time.time()
    if lic["revoked"]:
        return "revocată"
    if lic["starts"] is None:
        return "neactivată"
    if lic["expires"] is not None and lic["expires"] <= now:
        return "expirată"
    return "activă"


def issue_token(uuid, lic):
    seed = signing_seed()
    if not seed:
        return None
    expires = lic["expires"]
    bandwidth = int(lic.get("bandwidth") or 0)
    key = (uuid, lic["code"], expires, bandwidth)
    cached = _TOKEN_CACHE.get(key)
    now = time.time()
    if cached and now - cached[1] < 3600:
        return cached[0]
    token_exp = now + TOKEN_TTL if expires is None else min(expires, now + TOKEN_TTL)
    payload = json.dumps(
        {"u": uuid, "e": int(token_exp), "x": int(expires or 0), "n": lic["client"] or "", "b": bandwidth},
        separators=(",", ":"), ensure_ascii=False,
    ).encode()
    payload = TOKEN_PREFIX + payload
    token = base64.b64encode(_sign(seed, payload) + payload).decode()
    if len(_TOKEN_CACHE) > 5000:
        _TOKEN_CACHE.clear()
    _TOKEN_CACHE[key] = (token, now)
    return token


def device_license(uuid):
    rows = q(
        "SELECT l.* FROM activations a JOIN licenses l ON l.code = a.code WHERE a.uuid = ?",
        (uuid,),
    )
    return rows[0] if rows else None


def activate(v, src_ip):
    now = time.time()
    with ACT_LOCK:
        max_fails, lock_seconds = lockout("activation")
        window, fails = ACT_FAILS.get(src_ip, (now, 0))
        if now - window > lock_seconds:
            window, fails = now, 0
        if fails >= max_fails:
            return {"error": f"Prea multe încercări. Reîncearcă peste {minutes_text(window + lock_seconds - now)}."}

    def fail(msg):
        with ACT_LOCK:
            ACT_FAILS[src_ip] = (window, fails + 1)
            if len(ACT_FAILS) > 10000:
                ACT_FAILS.clear()
        return {"error": msg}

    uuid = str(v.get("uuid") or "")
    if not re.fullmatch(r"[A-Za-z0-9+/=]{8,100}", uuid):
        return fail("Date lipsă de la aplicație")
    code = normalize_code(v.get("code"))
    if not uuid:
        return fail("Date lipsă de la aplicație")
    if not signing_seed():
        return {"error": "Serverul de licențe nu este configurat"}
    rows = q("SELECT * FROM licenses WHERE code = ?", (code,))
    if not rows:
        return fail("Cod de licență invalid")
    lic = rows[0]
    if lic["revoked"]:
        return fail("Licența a fost revocată. Contactează RDN Network Data.")
    if lic["expires"] is not None and lic["expires"] <= now:
        return fail("Licența a expirat. Contactează RDN Network Data pentru prelungire.")
    with DB_LOCK:
        already = DB.execute("SELECT 1 FROM activations WHERE uuid=? AND code=?", (uuid, code)).fetchone()
        used = DB.execute("SELECT COUNT(*) FROM activations WHERE code=?", (code,)).fetchone()[0]
        if not already and used >= lic["seats"]:
            return fail(f"Toate cele {lic['seats']} locuri ale licenței sunt ocupate.")
        if lic["starts"] is None:
            expires = add_months(now, lic["months"]) if lic["months"] else None
            DB.execute("UPDATE licenses SET starts=?, expires=? WHERE code=?", (now, expires, code))
        DB.execute(
            """INSERT INTO activations(uuid, code, device_id, hostname, activated, last_seen)
               VALUES(?,?,?,?,?,?) ON CONFLICT(uuid) DO UPDATE SET code=excluded.code,
               device_id=excluded.device_id, hostname=excluded.hostname,
               activated=excluded.activated, last_seen=excluded.last_seen""",
            (uuid, code, as_text(v.get("id"), 40), as_text(v.get("hostname"), 100), now, now),
        )
    lic = q("SELECT * FROM licenses WHERE code = ?", (code,))[0]
    log(f"licenses: {code} activated on {as_text(v.get('id'), 40)} ({src_ip})")
    return {"license": issue_token(uuid, lic), "expires": int(lic["expires"] or 0), "client": lic["client"]}


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
    app_fails, app_seconds = lockout("app")
    out["lockout"] = [app_fails, app_seconds // 60]
    pending = q("SELECT conn_id FROM pending_disconnect WHERE uuid=?", (uuid,))
    if pending:
        out["disconnect"] = [p["conn_id"] for p in pending]
        x("DELETE FROM pending_disconnect WHERE uuid=?", (uuid,))
        reason = DISCONNECT_REASON.pop(uuid, None)
        if reason:
            out["disconnect_reason"] = reason
    lic = device_license(uuid)
    if license_ok(lic):
        token = issue_token(uuid, lic)
        if token:
            out["license"] = token
            x("UPDATE activations SET last_seen=? WHERE uuid=?", (time.time(), uuid))
    elif LICENSE_REQUIRED and signing_seed():
        # Licensed builds drop their token and block themselves; close what is open.
        out["license"] = ""
        if conns:
            out["disconnect"] = sorted(set(out.get("disconnect", []) + conns))
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
    timeout = 20  # per-socket; slow or stalled clients are dropped

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
        if urlparse(self.path).path == "/version/latest":
            return self.reply(200, latest_release() or {"url": ""})
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        src_ip = self.client_address[0]
        if not rate_ok(src_ip):
            return self.reply(429, {"error": "rate limited"})
        length = body_length(self.headers, MAX_BODY)
        if length is None:
            return self.reply(413, {"error": "bad or too large body"})
        raw = self.rfile.read(length) if length else b""
        path = urlparse(self.path).path
        try:
            v = json.loads(raw or b"{}")
        except ValueError:
            return self.reply(400, {"error": "bad json"})
        if not isinstance(v, dict):
            return self.reply(400, {"error": "bad json"})
        try:
            if path == "/version/latest":
                return self.reply(200, latest_release() or {"url": ""})
            if path == "/api/license/activate":
                return self.reply(200, activate(v, src_ip))
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
# Lockouts after wrong attempts, per address: (attempts, minutes). Changed from the panel
# ("IP-uri blocate" tab) and kept in the settings table.
# "app" is the wrong-password lockout on the computers themselves; (0, 0) keeps RustDesk's rules
# (6 in a minute -> 1 minute, 30 -> until the app restarts).
LOCKOUT_DEFAULTS = {"panel": (10, 15), "portal": (10, 15), "activation": (20, 60), "app": (0, 0)}
LOCKOUT_MAX_MINUTES = 7 * 24 * 60


def lockout(kind):
    """(max attempts, lock seconds) for the panel, the portal or license activation."""
    fails, minutes = LOCKOUT_DEFAULTS[kind]
    low = 0 if kind == "app" else 1
    for r in q("SELECT key, value FROM settings WHERE key IN (?, ?)", (f"lock_{kind}_fails", f"lock_{kind}_minutes")):
        value = as_int(r["value"])
        if value is None:
            continue
        if r["key"].endswith("_fails") and low <= value <= 1000:
            fails = value
        elif r["key"].endswith("_minutes") and low <= value <= LOCKOUT_MAX_MINUTES:
            minutes = value
    return fails, minutes * 60


def minutes_text(seconds):
    m = max(1, int(-(-seconds // 60)))
    if m < 120:
        return "1 minut" if m == 1 else f"{m} minute"
    h = round(m / 60)
    return f"{h} ore" if h < 48 else f"{round(h / 24)} zile"


def lockout_state():
    now = time.time()
    with AUTH_LOCK:
        auth = list(AUTH_FAILS.items())
    with ACT_LOCK:
        act = list(ACT_FAILS.items())
    blocked = []
    for key, (fails, until) in auth:
        if until > now:
            kind = "portal" if key.startswith("portal:") else "panel"
            blocked.append({"kind": kind, "ip": key.split(":", 1)[1] if kind == "portal" else key, "fails": fails, "until": until})
    max_fails, lock_seconds = lockout("activation")
    for ip, (window, fails) in act:
        if fails >= max_fails and window + lock_seconds > now:
            blocked.append({"kind": "activation", "ip": ip, "fails": fails, "until": window + lock_seconds})
    settings = {}
    for kind in LOCKOUT_DEFAULTS:
        f, sec = lockout(kind)
        settings[kind] = {"fails": f, "minutes": sec // 60}
    return {"settings": settings, "blocked": sorted(blocked, key=lambda b: -b["until"])}


def lockout_action(action, v):
    if action == "save":
        rows = []
        for kind in LOCKOUT_DEFAULTS:
            cfg = v.get(kind) if isinstance(v.get(kind), dict) else {}
            fails, minutes = as_int(cfg.get("fails")), as_int(cfg.get("minutes"))
            if kind == "app" and (not fails or not minutes):
                fails = minutes = 0  # the app's own rules
            low = 0 if kind == "app" else 1
            if fails is None or not low <= fails <= 1000:
                return 400, {"error": "Numărul de încercări trebuie să fie între 1 și 1000"}
            if minutes is None or not low <= minutes <= LOCKOUT_MAX_MINUTES:
                return 400, {"error": f"Durata blocării trebuie să fie între 1 și {LOCKOUT_MAX_MINUTES} minute (7 zile)"}
            rows += [(f"lock_{kind}_fails", str(fails)), (f"lock_{kind}_minutes", str(minutes))]
        for row in rows:
            x("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)", row)
        log("panel: lockout settings changed " + ", ".join(f"{k}={val}" for k, val in rows))
        return 200, {"ok": True}
    if action == "clear":
        ip = as_text(v.get("ip"), 100)
        with AUTH_LOCK:
            for key in [k for k in AUTH_FAILS if not ip or k in (ip, "portal:" + ip)]:
                del AUTH_FAILS[key]
        with ACT_LOCK:
            for key in [k for k in ACT_FAILS if not ip or k == ip]:
                del ACT_FAILS[key]
        log(f"panel: lockouts cleared for {ip or 'all addresses'}")
        return 200, {"ok": True}
    return 404, {"error": "unknown action"}
SESSION_COOKIE = "rdn_panel"
PANEL_SESSIONS = {}  # token -> expiry
TOTP_LAST = [0]  # last accepted time step; a code works only once


def totp_ok(code, now=None):
    """RFC 6238 (SHA-1, 30 s, 6 digits), accepting one step of clock drift."""
    code = re.sub(r"\s", "", str(code or ""))
    if not re.fullmatch(r"\d{6}", code):
        return False
    try:
        key = base64.b32decode(PANEL_TOTP_SECRET + "=" * (-len(PANEL_TOTP_SECRET) % 8))
    except ValueError:
        return False
    step = int(now if now is not None else time.time()) // 30
    for c in (step - 1, step, step + 1):
        digest = hmac.new(key, struct.pack(">Q", c), "sha1").digest()
        off = digest[-1] & 15
        value = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1000000
        if hmac.compare_digest(f"{value:06d}", code):
            with AUTH_LOCK:
                if c <= TOTP_LAST[0]:
                    return False
                TOTP_LAST[0] = c
            return True
    return False


LOGIN_HTML = """<!doctype html><html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Panou securitate · autentificare</title><style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f3f4f7;color:#1d1f24;
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
form{background:#fff;border:1px solid #e3e5ea;border-radius:14px;padding:28px;width:min(360px,92vw);box-shadow:0 10px 30px rgba(0,0,0,.06)}
h1{font-size:20px;margin:0 0 4px}p{margin:0 0 18px;color:#646a75;font-size:13.5px}
label{display:block;font-size:13px;font-weight:600;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #d5d8de;border-radius:9px;font:inherit}
button{margin-top:18px;width:100%;padding:11px;border:0;border-radius:9px;background:#1d4ed8;color:#fff;font:inherit;font-weight:700;cursor:pointer}
.err{background:#fde8e8;color:#9b1c1c;border-radius:8px;padding:8px 10px;font-size:13.5px;margin-bottom:6px}
</style></head><body><form method="post" action="login" autocomplete="on">
<h1>Panou securitate</h1><p>RDN Remote · autentificare</p><!--ERR-->
<label for="u">Utilizator</label><input id="u" name="user" autocomplete="username" required autofocus>
<label for="p">Parolă</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<!--TOTP--><button type="submit">Intră</button></form></body></html>"""
TOTP_FIELD = """<label for="c">Cod din aplicația de autentificare</label>
<input id="c" name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required>"""


def login_page(error=""):
    html = LOGIN_HTML.replace("<!--TOTP-->", TOTP_FIELD if PANEL_TOTP_SECRET else "")
    if error:
        html = html.replace("<!--ERR-->", '<div class="err">' + error + "</div>")
    return html


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

    app_lock = lockout("app")[1]
    client_blocks = q(
        f"""SELECT a.ip, a.typ, MAX(a.ts) AS last, COUNT(*) AS n, GROUP_CONCAT(DISTINCT a.device_id) AS devices
            FROM alarms a WHERE a.typ IN ({",".join("?" * len(BLOCKING_ALARMS))}) AND a.ts > ? AND a.ip IS NOT NULL
            GROUP BY a.ip, a.typ ORDER BY last DESC""",
        (*BLOCKING_ALARMS, month),
    )
    for b in client_blocks:
        b["label"] = ALARMS.get(b["typ"])
        # typ 2 lifts after a minute; typ 1/6 last until the client app restarts, or for the
        # minutes set in the panel.
        b["active"] = b["typ"] != 2 or now - b["last"] < 60
        if b["typ"] == 1 and app_lock:
            b["active"] = now - b["last"] < app_lock

    devices = q(
        """SELECT d.*, a.code AS lic_code, l.client AS lic_client, l.expires AS lic_expires,
                  l.revoked AS lic_revoked, l.starts AS lic_starts
           FROM devices d LEFT JOIN activations a ON a.uuid = d.uuid
           LEFT JOIN licenses l ON l.code = a.code ORDER BY d.last_seen DESC"""
    )
    for d in devices:
        d["online"] = now - (d["last_seen"] or 0) < ONLINE_SECONDS
        d["conns"] = json.loads(d["conns"] or "[]") if d["online"] else []
        if d["lic_code"]:
            d["lic_status"] = license_status(
                {"revoked": d["lic_revoked"], "starts": d["lic_starts"], "expires": d["lic_expires"]}, now)
        else:
            d["lic_status"] = "fără licență"

    licenses = q("SELECT * FROM licenses ORDER BY created DESC")
    acts = {}
    for a_ in q("""SELECT a.*, d.last_seen AS dev_seen FROM activations a
                   LEFT JOIN devices d ON d.uuid = a.uuid ORDER BY a.activated"""):
        a_["online"] = now - (a_["dev_seen"] or 0) < ONLINE_SECONDS
        acts.setdefault(a_["code"], []).append(a_)
    portal = {r["code"]: r["n"] for r in q("SELECT code, COUNT(*) AS n FROM portal_users GROUP BY code")}
    for l_ in licenses:
        l_["status"] = license_status(l_, now)
        l_["devices"] = acts.get(l_["code"], [])
        l_["portal_users"] = portal.get(l_["code"], 0)

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
        "lockouts": lockout_state(),
        "shop": shop_state(),
        "shop_codes": shop_codes(),
        "config": config_state(),
        "devices": devices,
        "licenses": licenses,
        "licensing_ready": signing_seed() is not None,
        "hbbr_ok": hbbr_cmd("h") is not None,
    }


class PanelHandler(BaseHTTPRequestHandler):
    server_version = "panel"
    timeout = 120

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
            "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def client_ip(self):
        ip = self.client_address[0]
        if ip in ("127.0.0.1", "::1"):
            # Caddy (same host) sets X-Forwarded-For to the real client; the last entry is its own.
            fwd = [p.strip() for p in self.headers.get("X-Forwarded-For", "").split(",") if p.strip()]
            if fwd and valid_ip(fwd[-1]):
                return valid_ip(fwd[-1])
        return ip

    def session_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE and re.fullmatch(r"[A-Za-z0-9_-]{20,100}", value):
                return value
        return None

    def authorized(self):
        token = self.session_token()
        now = time.time()
        with AUTH_LOCK:
            expiry = PANEL_SESSIONS.get(token) if token else None
        if expiry and expiry > now:
            return True
        if "/api/" in urlparse(self.path).path:
            self.reply(401, {"error": "autentificare necesară"})
        else:
            self.reply(200, login_page(), "text/html; charset=utf-8")
        return False

    def login(self):
        ip = self.client_ip()
        now = time.time()
        max_fails, lock_seconds = lockout("panel")
        with AUTH_LOCK:
            fails, until = AUTH_FAILS.get(ip, (0, 0))
        if until > now:
            return self.reply(429, login_page(f"Prea multe încercări greșite. Reîncearcă peste {minutes_text(until - now)}."),
                              "text/html; charset=utf-8")
        length = body_length(self.headers, 4096)
        if length is None:
            return self.reply(413, "body prea mare")
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace") if length else "")
        user = (form.get("user") or [""])[0]
        pwd = (form.get("password") or [""])[0]
        ok = hmac.compare_digest(user.encode(), PANEL_USER.encode()) & hmac.compare_digest(pwd.encode(), PANEL_PASSWORD.encode())
        if ok and PANEL_TOTP_SECRET:
            ok = totp_ok((form.get("code") or [""])[0])
        if not ok:
            with AUTH_LOCK:
                fails += 1
                AUTH_FAILS[ip] = (fails, now + lock_seconds if fails >= max_fails else 0)
            log(f"panel: failed login from {ip}")
            return self.reply(200, login_page("Date de autentificare greșite."), "text/html; charset=utf-8")
        token = secrets.token_urlsafe(32)
        with AUTH_LOCK:
            AUTH_FAILS.pop(ip, None)
            for t in [t for t, e in PANEL_SESSIONS.items() if e <= now]:
                del PANEL_SESSIONS[t]
            ttl = conf("panel_session_hours") * 3600
            PANEL_SESSIONS[token] = now + ttl
        log(f"panel: login from {ip}")
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        path = urlparse(self.path).path
        self.reply(303, "", headers=[
            ("Location", path[: -len("login")] or "/"),
            ("Set-Cookie", f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl}{secure}"),
        ])

    def shop_webhook(self):
        length = body_length(self.headers, SHOP_MAX_BODY)
        if length is None:
            return self.reply(413, {"error": "too large"})
        body = self.rfile.read(length) if length else b""
        secret = setting("shop_secret")
        if len(secret) < SHOP_MIN_SECRET:
            return self.reply(503, {"error": "shop not configured"})
        expected = base64.b64encode(hmac.new(secret.encode(), body, hashlib.sha256).digest()).decode()
        if not hmac.compare_digest(expected, self.headers.get("X-WC-Webhook-Signature", "")):
            log(f"shop: webhook with a bad signature from {self.client_ip()}")
            return self.reply(401, {"error": "bad signature"})
        try:
            order = json.loads(body)
        except ValueError:
            # WooCommerce's test delivery when the webhook is saved: "webhook_id=N".
            return self.reply(200, {"ok": True})
        if not isinstance(order, dict):
            return self.reply(400, {"error": "bad json"})
        return self.reply(200, {"ok": True, "result": shop_order(order)})

    # ------------------------------------------------------------ organization portal

    def portal(self):
        """Handles /portal/...; True when the request was the portal's."""
        path = urlparse(self.path).path
        m = re.search(r"^(.*?/portal)(/.*)?$", path)
        if not m:
            return False
        prefix, rest = m.group(1), m.group(2) or ""
        if not rest:
            self.reply(301, "", headers=[("Location", prefix + "/")])
            return True
        if self.command == "POST" and rest == "/login":
            self.portal_login(prefix)
            return True
        user = self.portal_session()
        if not user:
            if rest.startswith("/api/"):
                self.reply(401, {"error": "autentificare necesară"})
            else:
                self.reply(200, portal_login_page(), "text/html; charset=utf-8")
            return True
        if self.command == "GET":
            self.portal_get(user, rest)
        else:
            self.portal_post(user, prefix, rest)
        return True

    def portal_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == PORTAL_COOKIE and re.fullmatch(r"[A-Za-z0-9_-]{20,100}", value):
                return value
        return None

    def portal_session(self):
        token = self.portal_token()
        with AUTH_LOCK:
            expiry, uid = PORTAL_SESSIONS.get(token, (0, None)) if token else (0, None)
        if expiry <= time.time():
            return None
        return portal_user(uid)

    def portal_login(self, prefix):
        ip, now = self.client_ip(), time.time()
        key = "portal:" + ip
        page = lambda err: self.reply(200, portal_login_page(err), "text/html; charset=utf-8")
        max_fails, lock_seconds = lockout("portal")
        with AUTH_LOCK:
            fails, until = AUTH_FAILS.get(key, (0, 0))
        if until > now:
            return page(f"Prea multe încercări greșite. Reîncearcă peste {minutes_text(until - now)}.")
        length = body_length(self.headers, 4096)
        if length is None:
            return self.reply(413, "body prea mare")
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace") if length else "")
        email = (form.get("user") or [""])[0].strip().lower()[:254]
        pwd = (form.get("password") or [""])[0]
        rows = q("SELECT * FROM portal_users WHERE email = ?", (email,))
        ok = pw_ok(pwd, rows[0]["pw_hash"] if rows else "")
        if not ok:
            with AUTH_LOCK:
                fails += 1
                AUTH_FAILS[key] = (fails, now + lock_seconds if fails >= max_fails else 0)
            log(f"portal: failed login for {email!r} from {ip}")
            return page("E-mail sau parolă greșită.")
        if not portal_user(rows[0]["id"]):
            return page("Licența organizației este suspendată. Contactează RDN Network Data.")
        token = secrets.token_urlsafe(32)
        with AUTH_LOCK:
            AUTH_FAILS.pop(key, None)
            for t in [t for t, (e, _) in PORTAL_SESSIONS.items() if e <= now]:
                del PORTAL_SESSIONS[t]
            ttl = conf("portal_session_hours") * 3600
            PORTAL_SESSIONS[token] = (now + ttl, rows[0]["id"])
        x("UPDATE portal_users SET last_login=? WHERE id=?", (now, rows[0]["id"]))
        log(f"portal: {email} logged in from {ip}")
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        self.reply(303, "", headers=[
            ("Location", prefix + "/"),
            ("Set-Cookie", f"{PORTAL_COOKIE}={token}; Path={prefix}/; HttpOnly; SameSite=Strict; Max-Age={ttl}{secure}"),
        ])

    def portal_get(self, user, rest):
        query = parse_qs(urlparse(self.path).query)
        if rest == "/api/state":
            return self.reply(200, portal_state(user))
        if rest == "/api/report":
            data = portal_report(user["code"], (query.get("month") or [""])[0])
            return self.reply(200, data) if data else self.reply(400, {"error": "lună invalidă"})
        if rest == "/api/report.csv":
            body, name = report_csv((query.get("month") or [""])[0], user["code"])
            if not body:
                return self.reply(400, "lună invalidă")
            return self.reply(200, body, "text/csv; charset=utf-8",
                              headers=[("Content-Disposition", f'attachment; filename="{name}"')])
        if rest.startswith("/api/"):
            return self.reply(404, {"error": "inexistent"})
        self.reply(200, PORTAL_HTML, "text/html; charset=utf-8")

    def portal_post(self, user, prefix, rest):
        if self.headers.get("X-Portal") != "1" or not rest.startswith("/api/"):
            return self.reply(403, {"error": "missing header"})
        action = rest[len("/api/"):]
        if action == "logout":
            with AUTH_LOCK:
                PORTAL_SESSIONS.pop(self.portal_token(), None)
            return self.reply(200, {"ok": True}, headers=[
                ("Set-Cookie", f"{PORTAL_COOKIE}=; Path={prefix}/; HttpOnly; SameSite=Strict; Max-Age=0")])
        length = body_length(self.headers, MAX_BODY)
        if length is None:
            return self.reply(413, {"error": "bad or too large body"})
        try:
            v = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.reply(400, {"error": "bad json"})
        if not isinstance(v, dict):
            return self.reply(400, {"error": "bad json"})
        self.reply(*portal_action(user, action, v))

    def do_GET(self):
        if self.portal():
            return
        if not self.authorized():
            return
        # Paths are matched on their last segment so the panel also works behind a
        # reverse proxy under a sub-path (e.g. /rustdesk-panel/).
        url = urlparse(self.path)
        if url.path.endswith("/api/state"):
            search = (parse_qs(url.query).get("q") or [""])[0].strip()[:100]
            return self.reply(200, state(search))
        if url.path.endswith("/api/report"):
            data = report((parse_qs(url.query).get("month") or [""])[0])
            return self.reply(200, data) if data else self.reply(400, {"error": "lună invalidă"})
        if url.path.endswith("/api/report.csv"):
            qs = parse_qs(url.query)
            body, name = report_csv((qs.get("month") or [""])[0], as_text((qs.get("code") or [""])[0], 40) or None)
            if not body:
                return self.reply(404, "raport inexistent")
            return self.reply(200, body, "text/csv; charset=utf-8",
                              headers=[("Content-Disposition", f'attachment; filename="{name}"')])
        if url.path.endswith("/api/backups"):
            return self.reply(200, {"backups": list_backups(), "dir": str(BACKUP_DIR)})
        if url.path.endswith("/api/backup/download"):
            name = (parse_qs(url.query).get("name") or [""])[0]
            path = BACKUP_DIR / name
            if not re.fullmatch(rf"{backup.PREFIX}-[0-9]{{8}}-[0-9]{{6}}-[a-z-]+\.tar\.gz", name) or not path.is_file():
                return self.reply(404, "backup inexistent")
            return self.reply(200, path.read_bytes(), "application/gzip",
                              headers=[("Content-Disposition", f'attachment; filename="{name}"')])
        self.reply(200, INDEX_HTML, "text/html; charset=utf-8")

    def do_POST(self):
        if urlparse(self.path).path.endswith("/shop/webhook"):
            return self.shop_webhook()
        if self.portal():
            return
        if urlparse(self.path).path.endswith("/login"):
            return self.login()
        if not self.authorized():
            return
        # Browsers cannot add this header cross-site without CORS, which we never grant.
        if self.headers.get("X-Panel") != "1":
            return self.reply(403, {"error": "missing header"})
        action = urlparse(self.path).path.rsplit("/api/", 1)[-1]
        if action == "logout":
            with AUTH_LOCK:
                PANEL_SESSIONS.pop(self.session_token(), None)
            return self.reply(200, {"ok": True}, headers=[("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")])
        if action == "backup/restore":
            length = body_length(self.headers, MAX_RESTORE)
            if not length:
                return self.reply(413, {"error": "fișier prea mare sau gol"})
            return self.reply(*restore_live(self.rfile.read(length)))
        length = body_length(self.headers, MAX_BODY)
        if length is None:
            return self.reply(413, {"error": "bad or too large body"})
        try:
            v = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.reply(400, {"error": "bad json"})
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
        if action.startswith("license/"):
            return self.reply(*license_action(action[len("license/"):], v))
        if action.startswith("lockout/"):
            return self.reply(*lockout_action(action[len("lockout/"):], v))
        if action == "settings":
            return self.reply(*config_action(v))
        if action.startswith("shop/"):
            return self.reply(*shop_settings_action(action[len("shop/"):], v))
        if action == "backup/create":
            try:
                path = backup.create(DATA_DIR, ENV_FILE, BACKUP_DIR, "manual")
            except (OSError, RuntimeError, sqlite3.Error) as e:
                return self.reply(500, {"error": f"backup eșuat: {e}"})
            log(f"backup: {path.name}")
            return self.reply(200, {"ok": True, "name": path.name})
        self.reply(404, {"error": "unknown action"})


def bandwidth_kbps(mbps):
    """Mbit/s typed in the panel -> kbit/s stored in the license; 0 = unlimited."""
    try:
        value = float(str(mbps if mbps not in (None, "") else 0).replace(",", "."))
    except ValueError:
        return None
    if not 0 <= value <= 10000:
        return None
    return int(round(value * 1000))


def license_action(action, v):
    code = as_text(v.get("code"), 40) or ""
    if action == "create":
        seats, months = as_int(v.get("seats")), as_int(v.get("months"))
        client = (as_text(v.get("client"), 100) or "").strip()
        if not client:
            return 400, {"error": "Completează numele clientului"}
        if not seats or not 1 <= seats <= 10000:
            return 400, {"error": "Număr de calculatoare invalid"}
        if months not in PERIODS:
            return 400, {"error": "Perioadă invalidă"}
        kbps = bandwidth_kbps(v.get("mbps"))
        if kbps is None:
            return 400, {"error": "Limită de bandă invalidă (0 = nelimitat, maxim 10000 Mbit/s)"}
        sessions = as_int(v.get("sessions"))
        sessions = 1 if v.get("sessions") in (None, "") else sessions
        if sessions is None or not 0 <= sessions <= 1000:
            return 400, {"error": "Număr de conexiuni simultane invalid (0 = nelimitat)"}
        for _ in range(5):
            code = new_code()
            try:
                x("INSERT INTO licenses(code, client, seats, months, created, note, bandwidth, sessions) VALUES(?,?,?,?,?,?,?,?)",
                  (code, client, seats, months, time.time(), as_text(v.get("note"), 300) or "", kbps, sessions))
                break
            except sqlite3.IntegrityError:
                continue
        log(f"licenses: created {code} for {client} ({seats} seats, {months or 'unlimited'} months)")
        return 200, {"ok": True, "code": code}
    rows = q("SELECT * FROM licenses WHERE code=?", (code,))
    if action in ("extend", "revoke", "restore", "seats", "bandwidth", "sessions", "portal") and not rows:
        return 404, {"error": "Licență inexistentă"}
    if action == "extend":
        lic, months = rows[0], as_int(v.get("months"))
        if months not in (1, 3, 6, 9, 12):
            return 400, {"error": "Perioadă invalidă"}
        if lic["starts"] is None:
            if lic["months"]:
                x("UPDATE licenses SET months=? WHERE code=?", (lic["months"] + months, code))
        elif lic["expires"] is not None:
            base = max(lic["expires"], time.time())
            x("UPDATE licenses SET expires=? WHERE code=?", (add_months(base, months), code))
        log(f"licenses: {code} extended by {months} months")
        return 200, {"ok": True}
    if action in ("revoke", "restore"):
        x("UPDATE licenses SET revoked=? WHERE code=?", (1 if action == "revoke" else 0, code))
        log(f"licenses: {code} {action}d")
        return 200, {"ok": True}
    if action == "seats":
        seats = as_int(v.get("seats"))
        if not seats or not 1 <= seats <= 10000:
            return 400, {"error": "Număr de calculatoare invalid"}
        x("UPDATE licenses SET seats=? WHERE code=?", (seats, code))
        return 200, {"ok": True}
    if action == "bandwidth":
        kbps = bandwidth_kbps(v.get("mbps"))
        if kbps is None:
            return 400, {"error": "Limită invalidă (0 = nelimitat, maxim 10000 Mbit/s)"}
        x("UPDATE licenses SET bandwidth=? WHERE code=?", (kbps, code))
        log(f"licenses: {code} bandwidth {kbps or 'unlimited'} kbit/s")
        return 200, {"ok": True}
    if action == "portal":
        email = (as_text(v.get("email"), 254) or "").strip().lower()
        existing = q("SELECT id FROM portal_users WHERE email = ? AND code = ?", (email, code))
        if existing:
            password = new_password()
            x("UPDATE portal_users SET pw_hash=? WHERE id=?", (pw_hash(password), existing[0]["id"]))
            portal_logout_user(existing[0]["id"])
            log(f"portal: password reset for {email} ({code})")
            return 200, {"ok": True, "email": email, "password": password, "reset": True}
        st, out = portal_create_user(code, email, v.get("name"), "admin")
        if st == 200:
            log(f"portal: administrator {out['email']} created for {code}")
        return st, out
    if action == "sessions":
        sessions = as_int(v.get("sessions"))
        if sessions is None or not 0 <= sessions <= 1000:
            return 400, {"error": "Număr de conexiuni invalid (0 = nelimitat)"}
        x("UPDATE licenses SET sessions=? WHERE code=?", (sessions, code))
        log(f"licenses: {code} simultaneous sessions {sessions or 'unlimited'}")
        return 200, {"ok": True}
    if action == "release":
        uuid = as_text(v.get("uuid"), 100)
        x("DELETE FROM activations WHERE uuid=?", (uuid,))
        log(f"licenses: seat released for {uuid}")
        return 200, {"ok": True}
    return 404, {"error": "unknown action"}


# ---------------------------------------------------------------- reports

def month_range(month):
    """'2026-10' -> (start, end) unix seconds in local time; None if invalid."""
    m = re.fullmatch(r"(\d{4})-(\d{2})", str(month or ""))
    if not m or not 1 <= int(m.group(2)) <= 12:
        return None
    y, mo = int(m.group(1)), int(m.group(2))
    start = datetime.datetime(y, mo, 1).timestamp()
    end = datetime.datetime(y + mo // 12, mo % 12 + 1, 1).timestamp()
    return start, end


def license_sessions(code, start, end, direction):
    """Sessions of a license in [start, end): started from its devices ("out") or received by them ("in")."""
    join = "a.device_id = s.peer_id" if direction == "out" else "a.uuid = s.uuid"
    rows = q(
        f"""SELECT s.*, d.last_seen AS dev_seen, d.device_id AS target_id, d.hostname AS target_name
            FROM sessions s JOIN activations a ON {join} AND a.code = ?
            LEFT JOIN devices d ON d.uuid = s.uuid
            WHERE s.authed IS NOT NULL AND s.authed < ? AND COALESCE(s.ended, ?) >= ?
            ORDER BY s.authed""",
        (code, end, time.time(), start),
    )
    for r in rows:
        # A session whose close never arrived (crash, power loss) ends when its device was last seen.
        stop = r["ended"] or max(r["authed"], r["dev_seen"] or r["authed"])
        r["seconds"] = max(0, min(stop, end) - max(r["authed"], start))
    return rows


def report(month):
    rng = month_range(month)
    if not rng:
        return None
    start, end = rng
    out = []
    for lic in q("SELECT * FROM licenses ORDER BY client, created"):
        sent = license_sessions(lic["code"], start, end, "out")
        recv = license_sessions(lic["code"], start, end, "in")
        acts = q("SELECT COUNT(*) AS n, MAX(last_seen) AS seen FROM activations WHERE code = ?", (lic["code"],))[0]
        limit_hits = q(
            "SELECT COUNT(*) AS n FROM alarms WHERE typ = ? AND ts >= ? AND ts < ? AND info LIKE ?",
            (ALARM_SESSION_LIMIT, start, end, f'%"{lic["code"]}"%'),
        )[0]["n"]
        out.append({
            "code": lic["code"], "client": lic["client"], "status": license_status(lic),
            "devices": acts["n"], "seats": lic["seats"], "last_seen": acts["seen"],
            "sessions_limit": lic.get("sessions") or 0, "bandwidth": lic.get("bandwidth") or 0,
            "out_sessions": len(sent), "out_hours": round(sum(r["seconds"] for r in sent) / 3600, 2),
            "out_targets": len({r["uuid"] for r in sent}),
            "in_sessions": len(recv), "in_hours": round(sum(r["seconds"] for r in recv) / 3600, 2),
            "files": sum(r["files"] or 0 for r in sent + recv),
            "limit_hits": limit_hits,
        })
    return {"month": month, "rows": out, "retention_days": conf("retention_days")}


def csv_bytes(header, rows):
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")  # Excel în română folosește ";" ca separator
    w.writerow(header)
    w.writerows(rows)
    return ("\ufeff" + buf.getvalue()).encode()


def report_csv(month, code=None):
    rng = month_range(month)
    if not rng:
        return None, None
    fmt = lambda t: datetime.datetime.fromtimestamp(t).strftime("%d.%m.%Y %H:%M") if t else ""
    num = lambda v: str(v).replace(".", ",")
    if not code:
        data = report(month)
        rows = [[r["client"], r["code"], r["status"], f'{r["devices"]}/{r["seats"]}', r["sessions_limit"] or "nelimitat",
                 num(r["bandwidth"] / 1000) if r["bandwidth"] else "nelimitată", r["out_sessions"], num(r["out_hours"]),
                 r["out_targets"], r["in_sessions"], num(r["in_hours"]), r["files"], r["limit_hits"], fmt(r["last_seen"])]
                for r in data["rows"]]
        header = ["Client", "Licență", "Stare", "Dispozitive", "Conexiuni simultane", "Bandă (Mbit/s)", "Sesiuni pornite",
                  "Ore pornite", "Calculatoare accesate", "Sesiuni primite", "Ore primite", "Fișiere transferate",
                  "Închise la limită", "Ultima activitate"]
        return csv_bytes(header, rows), f"raport-rdn-remote-{month}.csv"
    if not q("SELECT 1 FROM licenses WHERE code = ?", (code,)):
        return None, None
    start, end = rng
    rows = []
    for direction, label in (("out", "pornită"), ("in", "primită")):
        for r in license_sessions(code, start, end, direction):
            rows.append([fmt(r["authed"]), fmt(r["ended"]), num(round(r["seconds"] / 60, 1)), label,
                         r["peer_id"] or "", r["peer_name"] or "", r["target_id"] or r["device_id"] or "", r["target_name"] or "",
                         CONN_TYPES.get(r["conn_type"], r["conn_type"] or ""), r["remote_ip"] or "", r["files"] or 0])
    rows.sort(key=lambda x: datetime.datetime.strptime(x[0], "%d.%m.%Y %H:%M") if x[0] else datetime.datetime.min)
    header = ["Început", "Sfârșit", "Minute", "Sesiune", "De la (ID)", "De la (nume)", "Către (ID)", "Către (calculator)",
              "Tip", "IP", "Fișiere"]
    return csv_bytes(header, rows), f"raport-{code}-{month}.csv"


# ---------------------------------------------------------------- organization portal
#
# Clients log in at /portal with their own accounts (created by the operator for a license,
# then by the client's administrators). Everything a portal user sees or changes is limited
# to the devices and sessions of that one license.

PORTAL_COOKIE = "rdn_portal"
PORTAL_SESSIONS = {}  # token -> (expiry, user id)
PW_ITER = 200_000
EMAIL_RE = re.compile(r"[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,}")


def pw_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PW_ITER)
    return f"pbkdf2${PW_ITER}${salt.hex()}${digest.hex()}"


def pw_ok(password, stored):
    try:
        _, it, salt, digest = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(it))
    except (ValueError, AttributeError):
        # Same work as a real check, so timing does not reveal unknown accounts.
        hashlib.pbkdf2_hmac("sha256", password.encode(), b"0" * 16, PW_ITER)
        return False
    return hmac.compare_digest(calc.hex(), digest)


def new_password():
    alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(16))


def portal_create_user(code, email, name, role):
    email = (as_text(email, 254) or "").strip().lower()
    if not EMAIL_RE.fullmatch(email):
        return 400, {"error": "Adresă de e-mail invalidă"}
    if role not in ("admin", "viewer"):
        return 400, {"error": "Rol invalid"}
    password = new_password()
    try:
        x("INSERT INTO portal_users(code, email, name, pw_hash, role, created) VALUES(?,?,?,?,?,?)",
          (code, email, (as_text(name, 100) or "").strip(), pw_hash(password), role, time.time()))
    except sqlite3.IntegrityError:
        return 409, {"error": "Există deja un cont cu această adresă de e-mail"}
    return 200, {"ok": True, "email": email, "password": password}


def portal_user(uid):
    rows = q("""SELECT u.*, l.revoked FROM portal_users u JOIN licenses l ON l.code = u.code WHERE u.id = ?""", (uid,))
    return rows[0] if rows and not rows[0]["revoked"] else None


def portal_state(user):
    code, now = user["code"], time.time()
    lic = q("SELECT * FROM licenses WHERE code = ?", (code,))[0]
    devices = q(
        """SELECT a.uuid, a.device_id, COALESCE(d.hostname, a.hostname) AS hostname, a.alias, a.activated,
                  a.can_control, a.accept_external, d.last_seen, d.os, d.username, d.conns, d.ver
           FROM activations a LEFT JOIN devices d ON d.uuid = a.uuid WHERE a.code = ? ORDER BY a.activated""",
        (code,),
    )
    for d in devices:
        d["online"] = now - (d["last_seen"] or 0) < ONLINE_SECONDS
        d["conns"] = json.loads(d["conns"] or "[]") if d["online"] else []
    since = now - 30 * 86400
    sessions = q(
        """SELECT s.id, s.uuid, s.conn_id, s.authed, s.ended, s.peer_id, s.peer_name, s.conn_type, s.files,
                  s.remote_ip, COALESCE(td.hostname, ta.hostname) AS target_name, s.device_id AS target_id,
                  (ta.uuid IS NOT NULL) AS incoming, (pa.uuid IS NOT NULL) AS outgoing
           FROM sessions s
           LEFT JOIN activations ta ON ta.uuid = s.uuid AND ta.code = ?
           LEFT JOIN activations pa ON pa.device_id = s.peer_id AND pa.code = ?
           LEFT JOIN devices td ON td.uuid = s.uuid
           WHERE s.authed IS NOT NULL AND s.authed > ? AND (ta.uuid IS NOT NULL OR pa.uuid IS NOT NULL)
           ORDER BY s.authed DESC LIMIT 300""",
        (code, code, since),
    )
    for r in sessions:
        r["type"] = CONN_TYPES.get(r["conn_type"], "")
    out = {
        "now": now,
        "me": {"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"]},
        "org": {
            "client": lic["client"], "code": lic["code"], "status": license_status(lic, now),
            "expires": lic["expires"], "seats": lic["seats"], "used": len(devices),
            "sessions": lic.get("sessions") or 0, "bandwidth": lic.get("bandwidth") or 0,
        },
        "devices": devices,
        "sessions": sessions,
        "retention_days": conf("retention_days"),
        "min_password": conf("portal_min_password"),
    }
    if user["role"] == "admin":
        out["users"] = q("SELECT id, email, name, role, created, last_login FROM portal_users WHERE code = ? ORDER BY created",
                         (code,))
    return out


def portal_action(user, action, v):
    code = user["code"]
    if action == "password":
        cur, new = str(v.get("current") or ""), str(v.get("new") or "")
        if not pw_ok(cur, user["pw_hash"]):
            return 400, {"error": "Parola actuală e greșită"}
        if len(new) < conf("portal_min_password"):
            return 400, {"error": f"Parola nouă trebuie să aibă cel puțin {conf('portal_min_password')} caractere"}
        x("UPDATE portal_users SET pw_hash=? WHERE id=?", (pw_hash(new), user["id"]))
        return 200, {"ok": True}
    if user["role"] != "admin":
        return 403, {"error": "Doar administratorii organizației pot face modificări"}
    if action.startswith("device/"):
        uuid = as_text(v.get("uuid"), 100)
        if not q("SELECT 1 FROM activations WHERE uuid = ? AND code = ?", (uuid, code)):
            return 404, {"error": "Dispozitiv inexistent"}
        if action == "device/update":
            if "alias" in v:
                x("UPDATE activations SET alias=? WHERE uuid=?", ((as_text(v.get("alias"), 80) or "").strip(), uuid))
            for key in ("can_control", "accept_external"):
                if key in v:
                    x(f"UPDATE activations SET {key}=? WHERE uuid=?", (1 if v.get(key) else 0, uuid))
            return 200, {"ok": True}
        if action == "device/disconnect":
            conn_id = as_int(v.get("conn_id"))
            if conn_id is None:
                return 400, {"error": "Sesiune invalidă"}
            x("INSERT INTO pending_disconnect(uuid, conn_id, ts) VALUES(?,?,?)", (uuid, conn_id, time.time()))
            DISCONNECT_REASON[uuid] = "Sesiunea a fost închisă de administratorul organizației."
            return 200, {"ok": True}
        if action == "device/release":
            x("DELETE FROM activations WHERE uuid=? AND code=?", (uuid, code))
            log(f"portal: {user['email']} released a seat of {code}")
            return 200, {"ok": True}
    if action == "user/create":
        st, out = portal_create_user(code, v.get("email"), v.get("name"), v.get("role") or "viewer")
        if st == 200:
            log(f"portal: {user['email']} created {out['email']} for {code}")
        return st, out
    if action in ("user/delete", "user/reset"):
        uid = as_int(v.get("id"))
        target = q("SELECT * FROM portal_users WHERE id = ? AND code = ?", (uid, code))
        if not target:
            return 404, {"error": "Cont inexistent"}
        if uid == user["id"]:
            return 400, {"error": "Pentru propriul cont folosește „Contul meu”"}
        if action == "user/delete":
            x("DELETE FROM portal_users WHERE id=?", (uid,))
            portal_logout_user(uid)
            log(f"portal: {user['email']} deleted {target[0]['email']} ({code})")
            return 200, {"ok": True}
        password = new_password()
        x("UPDATE portal_users SET pw_hash=? WHERE id=?", (pw_hash(password), uid))
        portal_logout_user(uid)
        return 200, {"ok": True, "email": target[0]["email"], "password": password}
    return 404, {"error": "acțiune necunoscută"}


def portal_report(code, month):
    rng = month_range(month)
    if not rng:
        return None
    start, end = rng
    sent = license_sessions(code, start, end, "out")
    recv = license_sessions(code, start, end, "in")
    names = {a["device_id"]: a["alias"] or a["hostname"] or "" for a in
             q("SELECT device_id, alias, hostname FROM activations WHERE code = ?", (code,))}
    per = {}
    for r in sent:
        d = per.setdefault(r["peer_id"] or "?", {"device_id": r["peer_id"], "name": names.get(r["peer_id"], r["peer_name"] or ""),
                                                 "out_sessions": 0, "out_hours": 0, "in_sessions": 0, "in_hours": 0})
        d["out_sessions"] += 1
        d["out_hours"] += r["seconds"] / 3600
    for r in recv:
        did = r["target_id"] or r["device_id"] or "?"
        d = per.setdefault(did, {"device_id": did, "name": names.get(did, r["target_name"] or ""),
                                 "out_sessions": 0, "out_hours": 0, "in_sessions": 0, "in_hours": 0})
        d["in_sessions"] += 1
        d["in_hours"] += r["seconds"] / 3600
    for d in per.values():
        d["out_hours"], d["in_hours"] = round(d["out_hours"], 2), round(d["in_hours"], 2)
    return {
        "month": month,
        "out_sessions": len(sent), "out_hours": round(sum(r["seconds"] for r in sent) / 3600, 2),
        "in_sessions": len(recv), "in_hours": round(sum(r["seconds"] for r in recv) / 3600, 2),
        "files": sum(r["files"] or 0 for r in sent + recv),
        "devices": sorted(per.values(), key=lambda d: -(d["out_hours"] + d["in_hours"])),
    }


def portal_logout_user(uid):
    with AUTH_LOCK:
        for t in [t for t, (_, u) in PORTAL_SESSIONS.items() if u == uid]:
            del PORTAL_SESSIONS[t]


PORTAL_LOGIN_HTML = LOGIN_HTML.replace("Panou securitate · autentificare", "Portal RDN Remote · autentificare").replace(
    "<h1>Panou securitate</h1><p>RDN Remote · autentificare</p>",
    "<h1>Portal RDN Remote</h1><p>Administrarea dispozitivelor organizației tale</p>").replace(
    '<label for="u">Utilizator</label><input id="u" name="user" autocomplete="username" required autofocus>',
    '<label for="u">E-mail</label><input id="u" name="user" type="email" autocomplete="username" required autofocus>')


def portal_login_page(error=""):
    html = PORTAL_LOGIN_HTML.replace("<!--TOTP-->", "")
    if error:
        html = html.replace("<!--ERR-->", '<div class="err">' + error + "</div>")
    return html


# ---------------------------------------------------------------- shop (WooCommerce)
#
# shop.rdndata.ro sends a webhook ("Order updated", signed with a secret of at least 24
# characters) to /shop/webhook. A paid order creates a license per product, or extends the
# license the same customer already has for that product (the code stays the same). With
# WooCommerce REST API keys set, the code reaches the customer as a note on the order, which
# WooCommerce e-mails; otherwise it waits in the panel's Shop tab.

SHOP_LOCK = threading.Lock()
SHOP_MIN_SECRET = 24
SHOP_MAX_BODY = 1024 * 1024
SHOP_DEFAULT_PRODUCTS = {
    "176": {"name": "Standard", "seats": 500, "sessions": 1, "mbps": 0, "months": 0},
    "183": {"name": "Advanced", "seats": 2000, "sessions": 5, "mbps": 0, "months": 0},
}


def setting(key, default=""):
    rows = q("SELECT value FROM settings WHERE key = ?", (key,))
    return rows[0]["value"] if rows else default


def set_setting(key, value):
    x("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)", (key, value))


SHOP_STATUSES = {"pending": "Plată în așteptare", "on-hold": "În așteptare", "processing": "În procesare",
                 "completed": "Finalizată"}
SHOP_NOTE_NEW = ("Mulțumim pentru comandă!\n\nCodul tău de licență RDN Remote {produs} ({luni}): {cod}\n\n"
                 "Descarcă aplicația de la {site} și introdu codul la prima pornire. Perioada începe la prima activare.")
SHOP_NOTE_RENEW = ("Mulțumim pentru comandă!\n\nLicența RDN Remote {produs} {cod} a fost prelungită cu {luni}. "
                   "Nu trebuie să faci nimic în aplicație.")
SHOP_NOTE_FOOTER = "Suport: office@rdndata.ro | 0723 122 097"

# Everything the operator can change in the panel: key -> (type, default, min, max or choices).
CONFIG = {
    "panel_session_hours": ("int", 12, 1, 720),
    "portal_session_hours": ("int", 12, 1, 720),
    "portal_min_password": ("int", 10, 8, 64),
    "retention_days": ("int", RETENTION_DAYS, 7, 3650),
    "shop_statuses": ("set", "processing,completed", tuple(SHOP_STATUSES)),
    "shop_renew": ("bool", 1),
    "shop_quantity": ("choice", "sessions", ("sessions", "seats", "months", "none")),
    "shop_send_note": ("bool", 1),
    "shop_note_delay_minutes": ("int", 300, 0, 10080),
    "shop_revoke_refund": ("bool", 1),
    "shop_site_url": ("text", "", 0, 200),
    "shop_note_new": ("text", SHOP_NOTE_NEW, 1, 3000),
    "shop_note_renew": ("text", SHOP_NOTE_RENEW, 1, 3000),
    "shop_note_footer": ("text", SHOP_NOTE_FOOTER, 0, 1000),
}


def conf(key):
    kind, default = CONFIG[key][0], CONFIG[key][1]
    raw = setting(key, None)
    if raw is None:
        value = default
    elif kind in ("int", "bool"):
        value = as_int(raw)
        value = default if value is None else value
    else:
        value = raw
    if kind == "int":
        return min(max(value, CONFIG[key][2]), CONFIG[key][3])
    if kind == "bool":
        return 1 if value else 0
    if kind == "set":
        return [v for v in str(value).split(",") if v in CONFIG[key][2]]
    if kind == "choice":
        return value if value in CONFIG[key][2] else default
    return str(value)


def config_state():
    state = {key: conf(key) for key in CONFIG}
    state["defaults"] = {key: spec[1] for key, spec in CONFIG.items() if spec[0] == "text"}
    return state


def config_action(v):
    """Saves the settings present in v; nothing is saved when one of them is invalid."""
    rows = []
    for key, value in v.items():
        if key not in CONFIG:
            return 400, {"error": f"Setare necunoscută: {key}"}
        spec = CONFIG[key]
        kind = spec[0]
        if kind == "int":
            n = as_int(value)
            if n is None or not spec[2] <= n <= spec[3]:
                return 400, {"error": f"Valoare invalidă ({spec[2]}–{spec[3]})", "field": key}
            rows.append((key, str(n)))
        elif kind == "bool":
            rows.append((key, "1" if value else "0"))
        elif kind == "set":
            items = value if isinstance(value, list) else str(value or "").split(",")
            items = [str(i) for i in items if str(i)]
            if not items or any(i not in spec[2] for i in items):
                return 400, {"error": "Alege cel puțin o stare a comenzii", "field": key}
            rows.append((key, ",".join(items)))
        elif kind == "choice":
            if value not in spec[2]:
                return 400, {"error": "Opțiune invalidă", "field": key}
            rows.append((key, value))
        else:
            text = str(value if value is not None else "").replace("\r\n", "\n").strip()
            if not spec[2] <= len(text) <= spec[3]:
                return 400, {"error": f"Textul trebuie să aibă între {spec[2]} și {spec[3]} caractere", "field": key}
            if key == "shop_site_url" and text and not re.fullmatch(r"https?://\S+", text):
                return 400, {"error": "Adresa site-ului trebuie să înceapă cu https://", "field": key}
            rows.append((key, text))
    for row in rows:
        set_setting(*row)
    if rows:
        log("panel: settings changed: " + ", ".join(k for k, _ in rows))
    return 200, {"ok": True}


def shop_products():
    try:
        products = json.loads(setting("shop_products", ""))
        if isinstance(products, dict) and products:
            return products
    except ValueError:
        pass
    return SHOP_DEFAULT_PRODUCTS


def server_host():
    try:
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if line.startswith("SERVER_HOST="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


def shop_state():
    return {
        "secret_set": len(setting("shop_secret")) >= SHOP_MIN_SECRET,
        "url": setting("shop_url", "https://shop.rdndata.ro"),
        "api_set": bool(setting("shop_ck") and setting("shop_cs")),
        "products": shop_products(),
        "statuses": SHOP_STATUSES,
        "orders": q("SELECT * FROM shop_orders ORDER BY updated DESC LIMIT 200"),
    }


def shop_codes():
    """code -> how its shop order stands, for the Licenses tab."""
    out = {}
    for o in q("SELECT order_id, codes, note_sent, note_due, cancelled, error FROM shop_orders WHERE codes IS NOT NULL AND codes != ''"):
        for code in o["codes"].split(", "):
            out[code] = {"order_id": o["order_id"], "note_sent": o["note_sent"], "note_due": o["note_due"],
                         "cancelled": o["cancelled"], "error": o["error"]}
    return out


def shop_settings_action(action, v):
    if action == "secret":
        secret = str(v.get("secret") or "").strip() or secrets.token_urlsafe(30)
        if len(secret) < SHOP_MIN_SECRET or len(secret) > 200 or re.search(r"\s", secret):
            return 400, {"error": f"Cheia trebuie să aibă cel puțin {SHOP_MIN_SECRET} de caractere, fără spații"}
        set_setting("shop_secret", secret)
        log("shop: webhook secret changed")
        return 200, {"ok": True, "secret": secret}
    if action == "api":
        url = str(v.get("url") or "").strip().rstrip("/")
        ck, cs = str(v.get("ck") or "").strip(), str(v.get("cs") or "").strip()
        if not re.fullmatch(r"https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~/-]*)?", url):
            return 400, {"error": "Adresa shopului trebuie să înceapă cu https://"}
        if (ck or cs) and not (re.fullmatch(r"ck_[A-Za-z0-9]{20,100}", ck) and re.fullmatch(r"cs_[A-Za-z0-9]{20,100}", cs)):
            return 400, {"error": "Cheile WooCommerce încep cu ck_ și cs_ (WooCommerce → Setări → Avansat → REST API)"}
        set_setting("shop_url", url)
        if ck:
            set_setting("shop_ck", ck)
            set_setting("shop_cs", cs)
        elif v.get("clear"):
            x("DELETE FROM settings WHERE key IN ('shop_ck', 'shop_cs')")
        return 200, {"ok": True}
    if action == "products":
        products = {}
        for row in v.get("products") or []:
            pid = str(as_int(row.get("id")) or "")
            seats, sessions = as_int(row.get("seats")), as_int(row.get("sessions"))
            months = as_int(row.get("months") or 0)
            kbps = bandwidth_kbps(row.get("mbps"))
            if not pid or not seats or not 1 <= seats <= 10000 or sessions is None or not 0 <= sessions <= 1000 or kbps is None \
                    or months is None or not 0 <= months <= 120:
                return 400, {"error": "Verifică ID-ul produsului, calculatoarele (1–10000), conexiunile (0–1000), "
                                      "perioada (0–120 luni) și banda"}
            products[pid] = {"name": (as_text(row.get("name"), 40) or "").strip() or pid, "seats": seats,
                             "sessions": sessions, "mbps": kbps / 1000, "months": months}
        if not products:
            return 400, {"error": "Adaugă cel puțin un produs"}
        set_setting("shop_products", json.dumps(products, ensure_ascii=False))
        return 200, {"ok": True}
    order = q("SELECT * FROM shop_orders WHERE order_id = ?", (as_int(v.get("order_id")),))
    if action in ("resend", "reschedule", "mark_sent", "cancel", "deactivate") and (not order or not order[0]["codes"]):
        return 404, {"error": "Comandă inexistentă sau fără coduri"}
    if action != "resend" and action in ("reschedule", "mark_sent", "cancel", "deactivate") and order[0]["cancelled"]:
        return 409, {"error": "Codurile acestei comenzi sunt deja anulate"}
    if action == "reschedule":
        minutes = as_int(v.get("minutes"))
        if order[0]["note_sent"]:
            return 409, {"error": "Codul a fost deja trimis"}
        if minutes is None or not 0 <= minutes <= 10080:
            return 400, {"error": "Alege între 0 și 10080 de minute"}
        x("UPDATE shop_orders SET note_due=?, error='', updated=? WHERE order_id=?",
          (time.time() + minutes * 60, time.time(), order[0]["order_id"]))
        return 200, {"ok": True}
    if action == "mark_sent":
        x("UPDATE shop_orders SET note_sent=1, note_due=NULL, error='Trimis manual', updated=? WHERE order_id=?",
          (time.time(), order[0]["order_id"]))
        return 200, {"ok": True}
    if action in ("cancel", "deactivate"):
        if (action == "cancel") == bool(order[0]["note_sent"]):
            return 409, {"error": "Codul a fost deja trimis: folosește Dezactivează" if action == "cancel"
                         else "Codul nu a fost trimis încă: folosește Anulează"}
        return 200, {"ok": True, "result": shop_revoke_order(order[0], "anulat din panou")}
    if action == "resend":
        if order[0]["cancelled"]:
            return 409, {"error": "Codurile acestei comenzi sunt anulate"}
        err = shop_send_note(order[0]["order_id"], order[0]["message"])
        x("UPDATE shop_orders SET note_sent=?, note_due=?, error=?, updated=? WHERE order_id=?",
          (0 if err else 1, order[0]["note_due"] if err else None, err or "", time.time(), order[0]["order_id"]))
        return (502, {"error": err}) if err else (200, {"ok": True})
    return 404, {"error": "unknown action"}


def shop_months(item):
    texts = [str(m.get("value") or "") for m in item.get("meta_data") or [] if isinstance(m, dict)]
    texts.append(str(item.get("name") or ""))
    for t in texts:
        m = re.search(r"(\d{1,2})\s*Lun", t, re.I)
        if m:
            return int(m.group(1))
    return None


def shop_send_note(order_id, text):
    """Adds a customer note to the order (WooCommerce e-mails it); returns an error or None."""
    ck, cs = setting("shop_ck"), setting("shop_cs")
    if not (ck and cs):
        return "Cheile REST API ale shopului nu sunt setate; trimite codul manual."
    url = f"{setting('shop_url', 'https://shop.rdndata.ro')}/wp-json/wc/v3/orders/{int(order_id)}/notes"
    req = urllib.request.Request(url, data=json.dumps({"note": text, "customer_note": True}).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "rdn-panel",
                                          "Authorization": "Basic " + base64.b64encode(f"{ck}:{cs}".encode()).decode()})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read()
        return None
    except (OSError, ValueError) as e:
        return f"Shopul nu a primit nota: {e}"[:300]


def months_text(m):
    return "1 lună" if m == 1 else f"{m} luni"


def fill_template(text, values):
    return re.sub(r"\{(\w+)\}", lambda m: str(values.get(m.group(1), m.group(0))), text)


def shop_extend(code, months):
    lic = q("SELECT * FROM licenses WHERE code=?", (code,))[0]
    if lic["starts"] is None:
        if lic["months"]:
            x("UPDATE licenses SET months=? WHERE code=?", (lic["months"] + months, code))
    elif lic["expires"] is not None:
        x("UPDATE licenses SET expires=? WHERE code=?", (add_months(max(lic["expires"], time.time()), months), code))
    log(f"licenses: {code} extended by {months} months (shop)")


def shop_order(order):
    """Handles one order from the webhook; returns a short status for the log."""
    order_id = as_int(order.get("id"))
    status = as_text(order.get("status"), 30) or ""
    if not order_id:
        return "fără ID de comandă"
    billing = order.get("billing") if isinstance(order.get("billing"), dict) else {}
    email = (as_text(billing.get("email"), 254) or "").strip().lower()
    name = " ".join(filter(None, [(as_text(billing.get("first_name"), 60) or "").strip(),
                                   (as_text(billing.get("last_name"), 60) or "").strip()]))
    client = (as_text(billing.get("company"), 100) or "").strip() or name or email or f"Comanda {order_id}"
    now = time.time()
    with SHOP_LOCK:
        seen = q("SELECT * FROM shop_orders WHERE order_id = ?", (order_id,))
        if seen and seen[0]["codes"]:
            x("UPDATE shop_orders SET status=?, updated=? WHERE order_id=?", (status, now, order_id))
            if status in ("refunded", "cancelled") and seen[0]["status"] != status:
                return shop_cancelled(seen[0], status)
            return "deja procesată"
        if not seen:
            x("INSERT INTO shop_orders(order_id, status, email, client, created, updated) VALUES(?,?,?,?,?,?)",
              (order_id, status, email, client, now, now))
        else:
            x("UPDATE shop_orders SET status=?, updated=? WHERE order_id=?", (status, now, order_id))
        if status not in conf("shop_statuses"):
            return f"în așteptare ({status})"
        products, quantity_mode = shop_products(), conf("shop_quantity")
        site = conf("shop_site_url") or (f"https://{server_host()}/" if server_host() else "")
        codes, new_codes, extended, notes, errors = [], [], {}, [], []
        for item in order.get("line_items") or []:
            if not isinstance(item, dict):
                continue
            pid = str(as_int(item.get("product_id")) or "")
            product = products.get(pid)
            if not product:
                continue
            months = shop_months(item) or product.get("months") or None
            qty = max(1, as_int(item.get("quantity")) or 1)
            if not months or not 1 <= months <= 120:
                errors.append(f"perioadă necunoscută la {item.get('name')}")
                continue
            seats, sessions = product["seats"], product["sessions"]
            if quantity_mode == "sessions":
                sessions *= qty
            elif quantity_mode == "seats":
                seats = min(10000, seats * qty)
            elif quantity_mode == "months":
                months = min(120, months * qty)
            prev = q("""SELECT l.* FROM shop_licenses s JOIN licenses l ON l.code = s.code
                        WHERE s.email = ? AND s.product = ? AND l.revoked = 0 ORDER BY s.created DESC LIMIT 1""",
                     (email, pid)) if email and conf("shop_renew") else []
            if prev:
                code, template = prev[0]["code"], conf("shop_note_renew")
                shop_extend(code, months)
                extended[code] = extended.get(code, 0) + months
                if sessions and (prev[0]["sessions"] or 0) and sessions > prev[0]["sessions"]:
                    x("UPDATE licenses SET sessions=? WHERE code=?", (sessions, code))
                if seats > (prev[0]["seats"] or 0):
                    x("UPDATE licenses SET seats=? WHERE code=?", (seats, code))
            else:
                st, out = license_action("create", {
                    "client": client, "seats": seats, "months": 1, "sessions": sessions,
                    "mbps": product.get("mbps") or 0, "note": f"Shop: comanda #{order_id}, {email}"})
                if st != 200:
                    errors.append(out.get("error", "eroare"))
                    continue
                code, template = out["code"], conf("shop_note_new")
                x("UPDATE licenses SET months=? WHERE code=?", (months, code))
                x("INSERT INTO shop_licenses(code, email, product, created) VALUES(?,?,?,?)", (code, email, pid, now))
                new_codes.append(code)
            codes.append(code)
            notes.append(fill_template(template, {"cod": code, "produs": product["name"], "luni": months_text(months),
                                                  "client": client, "comanda": order_id, "site": site, "email": email}))
        if not codes:
            x("UPDATE shop_orders SET error=? WHERE order_id=?", ("; ".join(errors) or "niciun produs RDN Remote", order_id))
            return "; ".join(errors) or "niciun produs RDN Remote"
        message = "\n\n".join(notes + ([conf("shop_note_footer")] if conf("shop_note_footer") else []))
        x("UPDATE shop_orders SET codes=?, new_codes=?, extended=?, message=?, error=? WHERE order_id=?",
          (", ".join(codes), ", ".join(new_codes), json.dumps(extended), message, "; ".join(errors), order_id))
    delay = conf("shop_note_delay_minutes") * 60
    if conf("shop_send_note") and delay:
        x("UPDATE shop_orders SET note_due=? WHERE order_id=?", (time.time() + delay, order_id))
        log(f"shop: order {order_id} -> {', '.join(codes)} (code e-mailed in {delay // 60} min)")
        return "licențe: " + ", ".join(codes)
    err = shop_send_note(order_id, message) if conf("shop_send_note") else "Trimiterea automată e oprită; trimite codul manual."
    x("UPDATE shop_orders SET note_sent=?, error=? WHERE order_id=?",
      (0 if err else 1, "; ".join(filter(None, errors + [err or ""])), order_id))
    log(f"shop: order {order_id} -> {', '.join(codes)}{' (note not sent)' if err else ''}")
    return "licențe: " + ", ".join(codes)


def shop_send_due(now=None):
    """Sends the codes whose delay has passed; a failed send is retried after 30 minutes."""
    now = now or time.time()
    if not conf("shop_send_note"):
        return
    for row in q("""SELECT order_id, message FROM shop_orders
                    WHERE note_sent=0 AND cancelled=0 AND note_due IS NOT NULL AND note_due <= ?""", (now,)):
        err = shop_send_note(row["order_id"], row["message"])
        if err:
            x("UPDATE shop_orders SET error=?, note_due=? WHERE order_id=?", (err, now + 1800, row["order_id"]))
        else:
            x("UPDATE shop_orders SET note_sent=1, note_due=NULL, error='' WHERE order_id=?", (row["order_id"],))
            log(f"shop: code for order {row['order_id']} sent")


def shop_sender():
    while True:
        try:
            shop_send_due()
        except Exception as e:
            log(f"shop: {e!r}")
        time.sleep(60)


def shop_cancelled(row, status):
    if row["cancelled"]:
        return "deja anulată"
    if not conf("shop_revoke_refund"):
        log(f"shop: order {row['order_id']} is now {status}; its licenses {row['codes']} need a manual check")
        x("UPDATE shop_orders SET error=? WHERE order_id=?", (f"Comanda e {status}; verifică licențele manual", row["order_id"]))
        return "anulată; verifică manual"
    return shop_revoke_order(row, f"comanda e {'rambursată' if status == 'refunded' else 'anulată'} în shop")


def shop_revoke_order(row, reason):
    """Withdraws what an order gave: its new codes are revoked (the apps lock at their next check)
    and the months it added to an existing license are taken back. A code not yet sent is
    "cancelled", one already sent "deactivated"."""
    revoked = [c for c in (row["new_codes"] or "").split(", ") if c]
    for code in revoked:
        x("UPDATE licenses SET revoked=1 WHERE code=?", (code,))
    try:
        extended = json.loads(row["extended"] or "{}")
    except ValueError:
        extended = {}
    for code, months in extended.items():
        lic = q("SELECT * FROM licenses WHERE code=?", (code,))
        if not lic:
            continue
        if lic[0]["starts"] is None:
            x("UPDATE licenses SET months=? WHERE code=?", (max(1, (lic[0]["months"] or 0) - int(months)), code))
        elif lic[0]["expires"] is not None:
            x("UPDATE licenses SET expires=? WHERE code=?", (add_months(lic[0]["expires"], -int(months)), code))
    kind = 2 if row["note_sent"] else 1
    word = "dezactivat" if kind == 2 else "anulat"
    parts = []
    if revoked:
        parts.append(f"{word} {', '.join(revoked)}")
    if extended:
        parts.append("prelungire retrasă pentru " + ", ".join(extended))
    note = f"{reason[:1].upper()}{reason[1:]}: " + ("; ".join(parts) or "nimic de retras")
    x("UPDATE shop_orders SET cancelled=?, note_due=NULL, error=?, updated=? WHERE order_id=?",
      (kind, note, time.time(), row["order_id"]))
    log(f"shop: order {row['order_id']} {word}: {', '.join(revoked) or '-'}; extensions {extended or '-'}")
    return note


# ---------------------------------------------------------------- backups

def list_backups():
    out = []
    for f in sorted(BACKUP_DIR.glob(f"{backup.PREFIX}-*.tar.gz"), reverse=True):
        st = f.stat()
        label = f.name[len(backup.PREFIX) + 1:-len(".tar.gz")].split("-", 2)[-1]
        out.append({"name": f.name, "size": st.st_size, "created": st.st_mtime, "label": label})
    return out


def auto_backup():
    newest = max((f.stat().st_mtime for f in BACKUP_DIR.glob(f"{backup.PREFIX}-*-auto.tar.gz")), default=0)
    if time.time() - newest < 23 * 3600 or not (DATA_DIR / "id_ed25519").exists():
        return
    path = backup.create(DATA_DIR, ENV_FILE, BACKUP_DIR, "auto")
    backup.prune(BACKUP_DIR, "auto", AUTO_BACKUP_KEEP)
    log(f"backup: {path.name}")


def restore_live(blob):
    """Restore licenses, history and the IP blocklist while the server runs. A backup
    from a different server key needs the full restore (server/restore.sh)."""
    global DB
    try:
        manifest, contents = backup.read(blob)
    except ValueError as e:
        return 400, {"error": str(e)}
    current = (DATA_DIR / "id_ed25519").read_bytes().strip() if (DATA_DIR / "id_ed25519").exists() else b""
    if contents["id_ed25519"].strip() != current:
        return 409, {"error": "Backup-ul este de pe un server cu altă cheie. Pentru restaurare completă "
                              "(cheie, ID-uri, licențe) rulează pe server: sudo ./server/restore.sh <fișier>"}
    safety = backup.create(DATA_DIR, ENV_FILE, BACKUP_DIR, "inainte-de-restaurare")
    blocked_before = [r_["ip"] for r_ in q("SELECT ip FROM blocklist")]
    restored = []
    settings = q("SELECT key, value FROM settings")
    with DB_LOCK:
        if "panel.sqlite3" in contents:
            DB.close()
            for suffix in ("-wal", "-shm"):
                (DATA_DIR / ("panel.sqlite3" + suffix)).unlink(missing_ok=True)
            backup._atomic_write(DB_FILE, contents["panel.sqlite3"])
            DB = db()
            DB.executemany("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)", [(r_["key"], r_["value"]) for r_ in settings])
            restored.append("licențe, istoric, dispozitive")
    if "panel.sqlite3" in contents:
        # The blocklist lives in the panel database; make hbbr match the restored one.
        if blocked_before:
            hbbr_cmd("Br " + "|".join(blocked_before))
        sync_hbbr_blocklist()
        restored.append("IP-uri blocate")
    _TOKEN_CACHE.clear()
    log(f"backup: restored {manifest.get('created')} (safety copy {safety.name})")
    return 200, {"ok": True, "restored": restored, "created": manifest.get("created"), "safety": safety.name}


def housekeeping():
    while True:
        try:
            cutoff = time.time() - conf("retention_days") * 86400
            x("DELETE FROM sessions WHERE started < ?", (cutoff,))
            x("DELETE FROM alarms WHERE ts < ?", (cutoff,))
            x("DELETE FROM devices WHERE last_seen < ?", (cutoff,))
            x("DELETE FROM nonces WHERE ts < ?", (time.time() - 3600,))
            x("DELETE FROM pending_disconnect WHERE ts < ?", (time.time() - 300,))
            # The audit API is public: cap what unauthenticated posts can grow to.
            for table, order in (("sessions", "started"), ("alarms", "ts"), ("devices", "last_seen")):
                x(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} "
                  f"ORDER BY {order} DESC LIMIT -1 OFFSET ?)", (MAX_ROWS,))
            auto_backup()
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
    threading.Thread(target=shop_sender, daemon=True).start()
    threading.Thread(target=serve, args=(ApiHandler, API_BIND, API_PORT, "audit API"), daemon=True).start()
    serve(PanelHandler, PANEL_BIND, PANEL_PORT, "dashboard")


INDEX_HTML = (Path(__file__).with_name("index.html")).read_text(encoding="utf-8")
PORTAL_HTML = (Path(__file__).with_name("portal.html")).read_text(encoding="utf-8")

if __name__ == "__main__":
    main()
