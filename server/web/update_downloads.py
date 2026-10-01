#!/usr/bin/env python3
"""Fetch the newest client build from GitHub Releases into server/web/files/.

The download page (index.html) reads files/downloads.json written here, so the
site always offers the latest release without editing HTML.

    python3 server/web/update_downloads.py                      # from GitHub
    python3 server/web/update_downloads.py --from-dir ./builds  # from local files
    python3 server/web/update_downloads.py --tag 1.5.0-2        # a specific release

Environment: GITHUB_REPO (default danielneagu2000/Rust-Desktop), GITHUB_TOKEN
(optional, raises the API rate limit), SERVER_HOST (shown on the page).
Standard library only.
"""

import argparse
import calendar
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.request
from pathlib import Path

WEB = Path(__file__).resolve().parent
FILES = WEB / "files"
DATA = WEB.parent / "data"
REPO = os.environ.get("GITHUB_REPO", "danielneagu2000/Rust-Desktop")
SLUG = "rdn-remote"

# (key, regex on the asset name, platform, label, published file suffix)
ASSETS = [
    ("win-x64", r"-x86_64\.exe$", "windows", "Windows 10/11 (64-bit)", "windows-x64.exe"),
    ("win-x64-msi", r"-x86_64\.msi$", "windows", "Windows, instalare MSI (pentru administratori)", "windows-x64.msi"),
    ("win-arm64", r"-aarch64\.exe$", "windows", "Windows pe ARM", "windows-arm64.exe"),
    ("win7", r"-x86-sciter\.exe$", "windows", "Windows 7 / 32-bit", "windows7-x86.exe"),
    ("mac-arm64", r"-aarch64\.dmg$", "macos", "macOS Apple Silicon (M1–M4)", "macos-apple-silicon.dmg"),
    ("mac-x64", r"-x86_64\.dmg$", "macos", "macOS Intel", "macos-intel.dmg"),
    ("deb-x64", r"-x86_64\.deb$", "linux", "Ubuntu / Debian (.deb)", "linux-x64.deb"),
    ("rpm-x64", r"\.x86_64\.rpm$", "linux", "AlmaLinux / Fedora / RHEL (.rpm)", "linux-x64.rpm"),
    ("appimage-x64", r"-x86_64\.AppImage$", "linux", "Orice distribuție (AppImage)", "linux-x64.AppImage"),
    ("deb-arm64", r"-aarch64\.deb$", "linux", "Linux ARM64 (.deb)", "linux-arm64.deb"),
    ("apk-universal", r"-universal(-signed)?\.apk$", "android", "Android (universal)", "android.apk"),
    ("apk-arm64", r"-aarch64(-signed)?\.apk$", "android", "Android ARM64", "android-arm64.apk"),
    ("apk-armv7", r"-armv7(-signed)?\.apk$", "android", "Android ARMv7 (telefoane vechi)", "android-armv7.apk"),
]


def log(msg):
    print(msg, flush=True)


def http(url, accept="application/vnd.github+json"):
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "rdn-download-updater"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    return urllib.request.urlopen(req, timeout=60)


def match(name):
    if re.search(r"(suse|sciter)", name) and not name.endswith("-x86-sciter.exe"):
        return None
    for key, pattern, *_ in ASSETS:
        if re.search(pattern, name):
            return key
    return None


def pick_release(tag):
    if tag:
        with http(f"https://api.github.com/repos/{REPO}/releases/tags/{tag}") as r:
            return json.load(r)
    # /releases/latest skips pre-releases, and the build workflow publishes as pre-release.
    with http(f"https://api.github.com/repos/{REPO}/releases?per_page=20") as r:
        releases = json.load(r)
    for rel in releases:
        if rel.get("draft"):
            continue
        if any(match(a["name"]) for a in rel.get("assets", [])):
            return rel
    return None


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tag", help="release tag (default: newest release with client builds)")
    ap.add_argument("--from-dir", type=Path, help="take installers from a local folder instead of GitHub")
    ap.add_argument("--version", help="version label when using --from-dir")
    args = ap.parse_args()

    found = {}  # key -> (source name, url or local path)
    if args.from_dir:
        for p in sorted(args.from_dir.iterdir()):
            key = match(p.name)
            if key and key not in found:
                found[key] = (p.name, p)
        version = args.version or time.strftime("%Y.%m.%d")
        published = time.time()
    else:
        rel = pick_release(args.tag)
        if not rel:
            log(f"No release with client builds in {REPO} yet; the page will show 'în curând'.")
            write_manifest(None, [], None)
            return
        for a in rel["assets"]:
            key = match(a["name"])
            if key and key not in found:
                found[key] = (a["name"], a["browser_download_url"])
        version = rel["tag_name"]
        published = calendar.timegm(time.strptime(rel["published_at"], "%Y-%m-%dT%H:%M:%SZ"))

    target = FILES / re.sub(r"[^A-Za-z0-9._-]", "_", version)
    tmp = FILES / f".incoming-{os.getpid()}"
    tmp.mkdir(parents=True, exist_ok=True)
    items = []
    try:
        for key, pattern, platform, label, suffix in ASSETS:
            if key not in found:
                continue
            src_name, src = found[key]
            dest_name = f"{SLUG}-{version}-{suffix}"
            dest = tmp / dest_name
            existing = target / dest_name
            if existing.exists() and not args.from_dir:
                shutil.copy2(existing, dest)
            elif isinstance(src, Path):
                shutil.copy2(src, dest)
            else:
                log(f"downloading {src_name}")
                with http(src, accept="application/octet-stream") as r, open(dest, "wb") as f:
                    shutil.copyfileobj(r, f)
            items.append({
                "key": key, "platform": platform, "label": label,
                "file": f"files/{target.name}/{dest_name}",
                "size": dest.stat().st_size, "sha256": sha256(dest),
            })
        if not items:
            sys.exit("no recognised installers found")
        if target.exists():
            shutil.rmtree(target)
        tmp.rename(target)
    finally:
        if tmp.exists():
            shutil.rmtree(tmp)

    # Keep only the current version on disk.
    for old in FILES.iterdir():
        if old.is_dir() and old != target and not old.name.startswith("."):
            shutil.rmtree(old)
    write_manifest(version, items, published)
    log(f"Published {len(items)} installer(s) for version {version}")


def write_manifest(version, items, published):
    FILES.mkdir(parents=True, exist_ok=True)
    key = ""
    pub = DATA / "id_ed25519.pub"
    if pub.exists():
        key = pub.read_text().strip()
    host = os.environ.get("SERVER_HOST", "")
    env = WEB.parent / ".env"
    if not host and env.exists():
        m = re.search(r"^SERVER_HOST=(.*)$", env.read_text(), re.M)
        host = m.group(1).strip() if m else ""
    manifest = {
        "version": version, "published": published, "updated": time.time(),
        "server": host, "key": key, "items": items,
    }
    tmp = FILES / "downloads.json.tmp"
    tmp.write_text(json.dumps(manifest, ensure_ascii=False, indent=1))
    tmp.replace(FILES / "downloads.json")


if __name__ == "__main__":
    main()
