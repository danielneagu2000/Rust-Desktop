#!/usr/bin/env python3
"""Backups of the server state, standard library only.

A backup is a .tar.gz with:
  id_ed25519, id_ed25519.pub   server key pair (clients are built with the public key)
  db_v2.sqlite3                hbbs: registered IDs and their keys
  panel.sqlite3                panel: licenses, connection history, alarms, devices
  blocklist.txt                IPs blocked on the relay
  server.env                   server/.env (host, panel password, settings)
  manifest.json                creation time and SHA-256 of every file

SQLite files are copied with SQLite's online backup API, so a backup taken while the
server runs is consistent.

  python3 backup.py create  --data DATA_DIR --env ENV_FILE --out DIR
  python3 backup.py restore ARCHIVE --data DATA_DIR --env ENV_FILE   (server stopped)
"""

import argparse
import hashlib
import io
import json
import os
import socket
import sqlite3
import sys
import tarfile
import tempfile
import time
from pathlib import Path

PREFIX = "rdn-backup"
SQLITE = ("db_v2.sqlite3", "panel.sqlite3")
PLAIN = ("id_ed25519", "id_ed25519.pub", "blocklist.txt")
ENV_NAME = "server.env"
ALLOWED = set(SQLITE) | set(PLAIN) | {ENV_NAME, "manifest.json"}
MAX_MEMBER = 512 * 1024 * 1024


def _sqlite_copy(src, dst):
    s = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    d = sqlite3.connect(dst)
    try:
        s.backup(d)
    finally:
        d.close()
        s.close()


def create(data_dir, env_file, out_dir, label="manual"):
    """Write a backup archive into out_dir and return its path."""
    data_dir, out_dir = Path(data_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    files = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for name in SQLITE:
            if (data_dir / name).exists():
                _sqlite_copy(data_dir / name, tmp / name)
                files[name] = tmp / name
        for name in PLAIN:
            if (data_dir / name).exists():
                (tmp / name).write_bytes((data_dir / name).read_bytes())
                files[name] = tmp / name
        if env_file and Path(env_file).is_file():
            (tmp / ENV_NAME).write_bytes(Path(env_file).read_bytes())
            files[ENV_NAME] = tmp / ENV_NAME
        if "id_ed25519" not in files:
            raise RuntimeError("cheia serverului (id_ed25519) lipsește din " + str(data_dir))
        manifest = {
            "created": int(time.time()),
            "label": label,
            "host": socket.gethostname(),
            "files": {n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in sorted(files.items())},
        }
        stamp = time.strftime("%Y%m%d-%H%M%S")
        final = out_dir / f"{PREFIX}-{stamp}-{label}.tar.gz"
        part = final.with_suffix(".part")
        with tarfile.open(part, "w:gz") as tar:
            for name, path in sorted(files.items()):
                tar.add(path, arcname=name, recursive=False)
            blob = json.dumps(manifest, indent=1).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size, info.mtime = len(blob), manifest["created"]
            tar.addfile(info, io.BytesIO(blob))
        os.chmod(part, 0o600)
        part.replace(final)
    return final


def read(archive):
    """Validate an archive (path or bytes); return (manifest, {name: bytes})."""
    fileobj = io.BytesIO(archive) if isinstance(archive, (bytes, bytearray)) else open(archive, "rb")
    contents = {}
    try:
        with tarfile.open(fileobj=fileobj, mode="r:gz") as tar:
            for m in tar.getmembers():
                if not m.isfile() or m.name not in ALLOWED or m.size > MAX_MEMBER:
                    raise ValueError(f"fișier neașteptat în backup: {m.name}")
                contents[m.name] = tar.extractfile(m).read()
    except (tarfile.TarError, OSError, EOFError) as e:
        raise ValueError(f"nu este o arhivă de backup validă ({e})") from None
    finally:
        fileobj.close()
    if "manifest.json" not in contents:
        raise ValueError("lipsește manifest.json")
    manifest = json.loads(contents.pop("manifest.json"))
    expected = manifest.get("files") or {}
    if set(expected) != set(contents):
        raise ValueError("conținutul nu corespunde cu manifest.json")
    for name, digest in expected.items():
        if hashlib.sha256(contents[name]).hexdigest() != digest:
            raise ValueError(f"{name} este corupt (SHA-256 diferit)")
    if "id_ed25519" not in contents:
        raise ValueError("backup-ul nu conține cheia serverului")
    return manifest, contents


def _atomic_write(path, data, mode=0o600):
    path = Path(path)
    tmp = path.with_name(path.name + ".restore")
    tmp.write_bytes(data)
    os.chmod(tmp, mode)
    tmp.replace(path)


def restore(archive, data_dir, env_file):
    """Full restore; the server (hbbs, hbbr, panel) must be stopped."""
    manifest, contents = read(archive)
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    for name, data in contents.items():
        if name == ENV_NAME:
            if env_file:
                _atomic_write(env_file, data)
            continue
        if name in SQLITE:
            for suffix in ("-wal", "-shm"):
                (data_dir / (name + suffix)).unlink(missing_ok=True)
        _atomic_write(data_dir / name, data, 0o644 if name.endswith(".pub") or name == "blocklist.txt" else 0o600)
    return manifest


def prune(out_dir, label, keep):
    backups = sorted(Path(out_dir).glob(f"{PREFIX}-*-{label}.tar.gz"))
    for old in backups[:-keep] if keep > 0 else []:
        old.unlink(missing_ok=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--data", required=True)
    c.add_argument("--env")
    c.add_argument("--out", required=True)
    c.add_argument("--label", default="manual")
    r = sub.add_parser("restore")
    r.add_argument("archive")
    r.add_argument("--data", required=True)
    r.add_argument("--env")
    args = ap.parse_args()
    try:
        if args.cmd == "create":
            print(create(args.data, args.env, args.out, args.label))
        else:
            m = restore(args.archive, args.data, args.env)
            print("Restaurat backup-ul din", time.strftime("%Y-%m-%d %H:%M", time.localtime(m["created"])),
                  "(" + ", ".join(sorted(m["files"])) + ")")
    except (ValueError, RuntimeError) as e:
        sys.exit(f"Eroare: {e}")


if __name__ == "__main__":
    main()
