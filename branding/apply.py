#!/usr/bin/env python3
"""Apply the settings in branding/brand.env and branding/logo.png to the source tree.

Usage:
    python3 branding/apply.py           # patch sources and regenerate icons
    python3 branding/apply.py --check   # exit 1 if the tree is not branded with the current config

The script is idempotent: running it twice gives the same result. After an
upstream RustDesk upgrade, run it again to re-apply the branding.
Requires Pillow (pip install pillow) for icon generation.
"""

import argparse
import base64
import hashlib
import io
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRAND_DIR = ROOT / "branding"
ENV_FILE = BRAND_DIR / "brand.env"
LOGO_FILE = BRAND_DIR / "logo.png"
# Optional simplified mark for icons of SMALL_MAX px and below (tray, taskbar, notifications).
LOGO_SMALL_FILE = BRAND_DIR / "logo-small.png"
SMALL_MAX = 48
STAMP_FILE = BRAND_DIR / ".applied"
PLACEHOLDER = "CHANGE_ME"


def fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def load_config():
    cfg = {}
    for lineno, raw in enumerate(ENV_FILE.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"{ENV_FILE.name}:{lineno}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        cfg[key.strip()] = value.strip().strip('"').strip("'")

    errors = []
    for key in ("APP_NAME", "RENDEZVOUS_SERVER", "RS_PUB_KEY"):
        if not cfg.get(key) or cfg[key] == PLACEHOLDER:
            errors.append(f"{key} is not set in {ENV_FILE.relative_to(ROOT)}")
    if errors:
        fail("\n  ".join(["branding is not configured:"] + errors))

    name = cfg["APP_NAME"]
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{1,30}", name):
        fail("APP_NAME must be 2-31 letters/digits and start with a letter")
    if name == "RustDesk":
        fail("APP_NAME must differ from 'RustDesk'")

    server = cfg["RENDEZVOUS_SERVER"]
    if not re.fullmatch(r"[A-Za-z0-9.\-]+(:\d{1,5})?|\[[0-9A-Fa-f:]+\](:\d{1,5})?", server):
        fail("RENDEZVOUS_SERVER must be a host name or IP, optionally with :port")

    key = cfg["RS_PUB_KEY"]
    try:
        if len(base64.b64decode(key, validate=True)) != 32:
            raise ValueError
    except ValueError:
        fail("RS_PUB_KEY must be the 44-character base64 key from id_ed25519.pub")

    api = cfg.get("API_SERVER", "")
    if api and not re.fullmatch(r"https?://[^\s\"\\]+", api):
        fail("API_SERVER must start with http:// or https://")
    if not api:
        host = re.sub(r":\d+$", "", server)
        api = f"http://{host}:21114"
    cfg["API_SERVER"] = api.rstrip("/")

    color = cfg.get("ANDROID_ICON_BACKGROUND") or "#ffffff"
    if not re.fullmatch(r"#[0-9A-Fa-f]{6}", color):
        fail("ANDROID_ICON_BACKGROUND must look like #RRGGBB")
    cfg["ANDROID_ICON_BACKGROUND"] = color.lower()

    if not LOGO_FILE.exists():
        fail(f"missing {LOGO_FILE.relative_to(ROOT)} (square PNG, ideally 1024x1024, transparent background)")
    return cfg


def xml_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# Each entry: (file, regex, replacement builder). The regex must match exactly
# once, both in pristine upstream sources and in already-branded sources.
def text_patches(cfg):
    name = cfg["APP_NAME"]
    return [
        ("libs/hbb_common/src/config.rs",
         r'pub const RENDEZVOUS_SERVERS: &\[&str\] = &\["[^"]*"\];',
         f'pub const RENDEZVOUS_SERVERS: &[&str] = &["{cfg["RENDEZVOUS_SERVER"]}"];'),
        ("libs/hbb_common/src/config.rs",
         r'pub const RS_PUB_KEY: &str = "[^"]*";',
         f'pub const RS_PUB_KEY: &str = "{cfg["RS_PUB_KEY"]}";'),
        ("libs/hbb_common/src/config.rs",
         r'APP_NAME: RwLock<String> = RwLock::new\("[^"]*"\.to_owned\(\)\);',
         f'APP_NAME: RwLock<String> = RwLock::new("{name}".to_owned());'),
        # Fallback API server when the user configured none (upstream: admin.rustdesk.com).
        ("src/common.rs",
         r'    "[^"]*"\.to_owned\(\)\n\}\n\n#\[inline\]\npub fn is_public',
         f'    "{cfg["API_SERVER"]}".to_owned()\n}}\n\n#[inline]\npub fn is_public'),
        # Display names only; executable/bundle names stay "rustdesk"/"RustDesk"
        # so the upstream build and packaging scripts keep working.
        ("flutter/android/app/src/main/AndroidManifest.xml",
         r'(<application\b[^>]*?android:label=")[^"]*(")',
         rf'\g<1>{xml_escape(name)}\g<2>'),
        ("flutter/android/app/src/main/AndroidManifest.xml",
         r'android:label="[^"]* Input"',
         f'android:label="{xml_escape(name)} Input"'),
        ("flutter/android/app/src/main/res/values/ic_launcher_background.xml",
         r'(<color name="ic_launcher_background">)[^<]*(</color>)',
         rf'\g<1>{cfg["ANDROID_ICON_BACKGROUND"]}\g<2>'),
        ("flutter/ios/Runner/Info.plist",
         r'(<key>CFBundleDisplayName</key>\s*<string>)[^<]*(</string>)',
         rf'\g<1>{xml_escape(name)}\g<2>'),
        ("flutter/ios/Runner/Info.plist",
         r'(<key>CFBundleName</key>\s*<string>)[^<]*(</string>)',
         rf'\g<1>{xml_escape(name)}\g<2>'),
        ("flutter/windows/runner/Runner.rc",
         r'VALUE "FileDescription", "[^"]*"',
         f'VALUE "FileDescription", "{name} Remote Desktop"'),
        ("flutter/windows/runner/Runner.rc",
         r'VALUE "ProductName", "[^"]*"',
         f'VALUE "ProductName", "{name}"'),
        # Only the first Name= (the [Desktop Entry] one), not the actions' names.
        ("res/rustdesk.desktop", r'\A(\[Desktop Entry\]\n)Name=[^\n]*', rf'\g<1>Name={name}'),
        ("res/rustdesk-link.desktop", r'\A(\[Desktop Entry\]\n)Name=[^\n]*', rf'\g<1>Name={name}'),
    ]


def apply_text(cfg, check):
    # Compute every patch before writing anything, so a mismatch never leaves
    # the tree half-branded.
    contents = {}
    for rel, pattern, repl in text_patches(cfg):
        if rel not in contents:
            contents[rel] = (ROOT / rel).read_text(encoding="utf-8")
        new, n = re.subn(pattern, repl, contents[rel])
        if n != 1:
            fail(f"{rel}: expected exactly one match for {pattern!r}, found {n} "
                 "(upstream changed? update branding/apply.py)")
        contents[rel] = new

    changed = []
    for rel, new in contents.items():
        path = ROOT / rel
        if path.read_text(encoding="utf-8") != new:
            changed.append(rel)
            if not check:
                path.write_text(new, encoding="utf-8")
    return changed


def icon_jobs():
    """(relative path, kind, size) for every raster icon replaced by the logo."""
    jobs = [
        ("res/32x32.png", "plain", 32),
        ("res/64x64.png", "plain", 64),
        ("res/128x128.png", "plain", 128),
        ("res/128x128@2x.png", "plain", 256),
        ("res/icon.png", "plain", 1024),
        ("res/mac-icon.png", "plain", 1024),
        ("res/mac-tray-dark-x2.png", "silhouette-white", 60),
        ("res/mac-tray-light-x2.png", "silhouette-black", 48),
        ("fastlane/metadata/android/en-US/images/icon.png", "plain", 256),
        ("res/icon.ico", "ico", (16, 24, 32, 48, 64, 128, 256)),
        ("res/tray-icon.ico", "ico", (16, 24, 32)),
        ("flutter/windows/runner/resources/app_icon.ico", "ico", (16, 24, 32, 48, 64, 128, 256)),
        ("flutter/macos/Runner/AppIcon.icns", "icns", 1024),
    ]
    for density, px in (("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)):
        base = f"flutter/android/app/src/main/res/mipmap-{density}"
        jobs += [
            (f"{base}/ic_launcher.png", "android-legacy", px),
            (f"{base}/ic_launcher_round.png", "round", px),
            (f"{base}/ic_launcher_foreground.png", "adaptive-fg", px * 108 // 48),
            (f"{base}/ic_stat_logo.png", "silhouette-white", px // 2),
        ]
    ios = ROOT / "flutter/ios/Runner/Assets.xcassets/AppIcon.appiconset"
    for f in sorted(ios.glob("Icon-App-*.png")):
        m = re.fullmatch(r"Icon-App-([\d.]+)x[\d.]+@(\d)x\.png", f.name)
        if m:
            jobs.append((str(f.relative_to(ROOT)), "opaque", round(float(m[1]) * int(m[2]))))
    return jobs


def render(logo, kind, size):
    from PIL import Image, ImageDraw

    def fit(img, box, canvas_size, bg=(0, 0, 0, 0)):
        canvas = Image.new("RGBA", (canvas_size, canvas_size), bg)
        scaled = img.resize((box, box), Image.LANCZOS)
        off = (canvas_size - box) // 2
        canvas.alpha_composite(scaled, (off, off))
        return canvas

    if kind == "plain":
        return fit(logo, size, size)
    if kind == "opaque":  # iOS rejects icons with transparency
        return fit(logo, size, size, (255, 255, 255, 255)).convert("RGB")
    if kind == "android-legacy":
        return fit(logo, round(size * 0.9), size)
    if kind == "round":
        img = fit(logo, round(size * 0.72), size, (255, 255, 255, 255))
        mask = Image.new("L", (size * 4, size * 4), 0)
        ImageDraw.Draw(mask).ellipse((0, 0, size * 4 - 1, size * 4 - 1), fill=255)
        img.putalpha(mask.resize((size, size), Image.LANCZOS))
        return img
    if kind == "adaptive-fg":  # 108dp canvas, content in the central 66dp safe zone
        return fit(logo, size * 66 // 108, size)
    if kind.startswith("silhouette"):
        rgb = (255, 255, 255) if kind.endswith("white") else (0, 0, 0)
        img = fit(logo, size, size)
        alpha = img.getchannel("A")
        hist = alpha.histogram()
        if sum(hist[128:]) > 0.6 * size * size:
            # Logo on an opaque plate: a plain alpha silhouette would be a solid
            # blob, so keep only what contrasts with the plate's dominant tone.
            from PIL import ImageChops

            lum = img.convert("L")
            inside = alpha.point(lambda a: 255 if a > 192 else 0)
            lum_hist = lum.histogram(mask=inside)
            half, acc, plate = sum(lum_hist) / 2, 0, 0
            for plate, count in enumerate(lum_hist):
                acc += count
                if acc >= half:
                    break
            contrast = lum.point(lambda v: 255 if abs(v - plate) > 64 else 0)
            alpha = ImageChops.multiply(contrast, inside)
        solid = Image.new("RGBA", img.size, rgb + (255,))
        solid.putalpha(alpha)
        return solid
    raise ValueError(kind)


def apply_icons(check):
    if check:
        return []
    from PIL import Image

    def load(path):
        img = Image.open(path).convert("RGBA")
        if img.width != img.height:
            side = max(img.size)
            sq = Image.new("RGBA", (side, side), (0, 0, 0, 0))
            sq.alpha_composite(img, ((side - img.width) // 2, (side - img.height) // 2))
            img = sq
        if img.width < 512:
            print(f"warning: {path.name} is {img.width}px; 1024px recommended", file=sys.stderr)
        return img

    logo = load(LOGO_FILE)
    small = load(LOGO_SMALL_FILE) if LOGO_SMALL_FILE.exists() else logo

    def pick(kind, size):
        return small if size <= SMALL_MAX or kind.startswith("silhouette") else logo

    written = []
    for rel, kind, size in icon_jobs():
        path = ROOT / rel
        if kind == "ico":
            frames = [render(pick("plain", s), "plain", s) for s in size]
            render(logo, "plain", 256).save(
                path, format="ICO", sizes=[(s, s) for s in size], append_images=frames
            )
        elif kind == "icns":
            render(logo, "plain", size).save(path, format="ICNS")
        else:
            render(pick(kind, size), kind, size).save(path, format="PNG", optimize=True)
        written.append(rel)

    # Vector logos: wrap the PNG so every consumer (Flutter UI, Linux desktop) shows the brand.
    buf = io.BytesIO()
    render(logo, "plain", 512).save(buf, format="PNG", optimize=True)
    data = base64.b64encode(buf.getvalue()).decode()
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
           'viewBox="0 0 512 512" width="512" height="512">'
           f'<image width="512" height="512" xlink:href="data:image/png;base64,{data}"/></svg>\n')
    for rel in ("flutter/assets/icon.svg", "res/logo.svg", "res/scalable.svg"):
        (ROOT / rel).write_text(svg, encoding="utf-8")
        written.append(rel)
    return written


def fingerprint():
    h = hashlib.sha256()
    h.update(ENV_FILE.read_bytes())
    h.update(LOGO_FILE.read_bytes())
    if LOGO_SMALL_FILE.exists():
        h.update(LOGO_SMALL_FILE.read_bytes())
    h.update(Path(__file__).read_bytes())
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="verify only, do not modify files")
    args = parser.parse_args()

    cfg = load_config()
    changed = apply_text(cfg, args.check)

    if args.check:
        stamp = STAMP_FILE.read_text().strip() if STAMP_FILE.exists() else ""
        if changed or stamp != fingerprint():
            stale = changed + ([] if stamp == fingerprint() else ["icons (logo.png or brand.env changed)"])
            fail("source tree is not branded with the current config; run "
                 "`python3 branding/apply.py` and commit. Out of date: " + ", ".join(stale))
        print(f"OK: tree is branded as {cfg['APP_NAME']} -> {cfg['RENDEZVOUS_SERVER']}")
        return

    icons = apply_icons(False)
    STAMP_FILE.write_text(fingerprint() + "\n")
    print(f"Branded as {cfg['APP_NAME']} (server {cfg['RENDEZVOUS_SERVER']}, API {cfg['API_SERVER']})")
    print(f"  {len(changed)} source file(s) patched, {len(icons)} icon(s) regenerated")


if __name__ == "__main__":
    main()
