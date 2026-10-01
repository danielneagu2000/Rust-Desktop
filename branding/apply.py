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
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRAND_DIR = ROOT / "branding"
ENV_FILE = BRAND_DIR / "brand.env"
LOGO_FILE = BRAND_DIR / "logo.png"
# Optional simplified mark for icons of SMALL_MAX px and below (tray, taskbar, notifications).
LOGO_SMALL_FILE = BRAND_DIR / "logo-small.png"
SMALL_MAX = 48
# Optional wide logo shown inside the app (main window header, max 300x60).
LOGO_APP_FILE = BRAND_DIR / "logo-app.png"
LOGO_APP_DARK_FILE = BRAND_DIR / "logo-app-dark.png"
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

    display = cfg.get("DISPLAY_NAME") or name
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .\-]{0,39}", display) or "  " in display:
        fail("DISPLAY_NAME may use letters, digits, single spaces, '.' and '-' (max 40)")
    cfg["DISPLAY_NAME"] = display.strip()

    company = cfg.get("COMPANY") or display
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .,&\-]{0,59}", company):
        fail("COMPANY may use letters, digits, spaces and . , & - (max 60)")
    cfg["COMPANY"] = company
    year = cfg.get("COPYRIGHT_YEAR") or time.strftime("%Y")
    if not re.fullmatch(r"\d{4}", year):
        fail("COPYRIGHT_YEAR must be a year, e.g. 2026")
    cfg["COPYRIGHT_YEAR"] = year

    url_re = r"https?://[A-Za-z0-9._~:/?#\[\]@!&()*+,;=%-]+"
    host = re.sub(r":\d+$", "", server).strip("[]")
    cfg["WEBSITE_URL"] = cfg.get("WEBSITE_URL") or f"https://{host}"
    cfg["PRIVACY_URL"] = cfg.get("PRIVACY_URL") or cfg["WEBSITE_URL"]
    cfg["SOURCE_URL"] = cfg.get("SOURCE_URL", "")
    if not cfg["SOURCE_URL"]:
        fail("SOURCE_URL is required: AGPL-3.0 obliges you to offer the source code to your users")
    for k in ("WEBSITE_URL", "PRIVACY_URL", "SOURCE_URL"):
        if not re.fullmatch(url_re, cfg[k]):
            fail(f"{k} must be an http(s) URL without quotes or spaces")
    email = cfg.get("SUPPORT_EMAIL", "")
    if email and not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", email):
        fail("SUPPORT_EMAIL is not a valid e-mail address")
    cfg["SUPPORT_EMAIL"] = email
    phone = cfg.get("SUPPORT_PHONE", "")
    if phone and not re.fullmatch(r"\+?[0-9 ()./-]{6,20}", phone):
        fail("SUPPORT_PHONE may contain digits, spaces and + ( ) . / -")
    cfg["SUPPORT_PHONE"] = phone

    if not LOGO_FILE.exists():
        fail(f"missing {LOGO_FILE.relative_to(ROOT)} (square PNG, ideally 1024x1024, transparent background)")
    return cfg


def xml_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# Each entry: (file, regex, replacement builder). The regex must match exactly
# once, both in pristine upstream sources and in already-branded sources.
def text_patches(cfg):
    name = cfg["APP_NAME"]
    # Shown by the OS (launcher, shortcuts, file properties); may contain spaces.
    display = cfg["DISPLAY_NAME"]
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
         rf'\g<1>{xml_escape(display)}\g<2>'),
        ("flutter/android/app/src/main/AndroidManifest.xml",
         r'android:label="[^"]* Input"',
         f'android:label="{xml_escape(display)} Input"'),
        ("flutter/android/app/src/main/res/values/ic_launcher_background.xml",
         r'(<color name="ic_launcher_background">)[^<]*(</color>)',
         rf'\g<1>{cfg["ANDROID_ICON_BACKGROUND"]}\g<2>'),
        ("flutter/ios/Runner/Info.plist",
         r'(<key>CFBundleDisplayName</key>\s*<string>)[^<]*(</string>)',
         rf'\g<1>{xml_escape(display)}\g<2>'),
        ("flutter/ios/Runner/Info.plist",
         r'(<key>CFBundleName</key>\s*<string>)[^<]*(</string>)',
         rf'\g<1>{xml_escape(display)}\g<2>'),
        ("flutter/windows/runner/Runner.rc",
         r'VALUE "FileDescription", "[^"]*"',
         f'VALUE "FileDescription", "{display}"'),
        ("flutter/windows/runner/Runner.rc",
         r'VALUE "ProductName", "[^"]*"',
         f'VALUE "ProductName", "{display}"'),
        # Only the first Name= (the [Desktop Entry] one), not the actions' names.
        ("res/rustdesk.desktop", r'\A(\[Desktop Entry\]\n)Name=[^\n]*', rf'\g<1>Name={display}'),
        ("res/rustdesk-link.desktop", r'\A(\[Desktop Entry\]\n)Name=[^\n]*', rf'\g<1>Name={display}'),
    ] + publisher_patches(cfg)


def publisher_patches(cfg):
    """Publisher metadata and in-app legal notices: the company replaces Purslane
    as publisher, while the RustDesk copyright and AGPL notice stay visible."""
    company, year, display = cfg["COMPANY"], cfg["COPYRIGHT_YEAR"], cfg["DISPLAY_NAME"]
    web, privacy, source = cfg["WEBSITE_URL"], cfg["PRIVACY_URL"], cfg["SOURCE_URL"]
    web_host = re.sub(r"^https?://", "", web).rstrip("/")
    legal = f"Copyright \u00a9 {year} {company}. Based on RustDesk, \u00a9 Purslane Tech Pte. Ltd., AGPL-3.0."
    vendor = f"{company} <{cfg['SUPPORT_EMAIL']}>" if cfg["SUPPORT_EMAIL"] else company
    const = lambda text: (lambda m: text)  # literal replacement, no backslash processing
    winres = (r'(\[package\.metadata\.winres\]\n)LegalCopyright = "[^"]*"\n(?:CompanyName = "[^"]*"\n)?',
              lambda m: f'{m.group(1)}LegalCopyright = "{legal}"\nCompanyName = "{company}"\n')
    dart_notice = (f"'Copyright \u00a9 ${{DateTime.now().toString().substring(0, 4)}} {company}\\n"
                   f"Based on RustDesk, Copyright \u00a9 Purslane Tech Pte. Ltd.\\n"
                   f"Licensed under AGPL-3.0. Source code: {source}\\n$license'")
    tis_notice = (f"Copyright &copy; {year} {company}<br />Based on RustDesk, Copyright &copy; "
                  f"Purslane Tech Pte. Ltd., AGPL-3.0<br />Source code: {source}")
    patches = [
        ("flutter/windows/runner/Runner.rc", r'VALUE "CompanyName", "[^"]*"', const(f'VALUE "CompanyName", "{company}"')),
        ("flutter/windows/runner/Runner.rc", r'VALUE "LegalCopyright", "[^"]*"', const(f'VALUE "LegalCopyright", "{legal}"')),
        ("Cargo.toml", *winres),
        ("Cargo.toml", r'(?m)^ProductName = "[^"]*"$', const(f'ProductName = "{display}"')),
        ("Cargo.toml", r'(?m)^FileDescription = "[^"]*"$', const(f'FileDescription = "{display}"')),
        ("libs/portable/Cargo.toml", *winres),
        ("libs/portable/Cargo.toml", r'(?m)^ProductName = "[^"]*"$', const(f'ProductName = "{display}"')),
        ("libs/portable/Cargo.toml", r'(?m)^FileDescription = "[^"]*"$', const(f'FileDescription = "{display}"')),
        ("flutter/macos/Runner/Configs/AppInfo.xcconfig", r'(?m)^PRODUCT_COPYRIGHT = .*$', const(f"PRODUCT_COPYRIGHT = {legal}")),
        ("res/msi/preprocess.py", r'("--manufacturer",\n\s*type=str,\n\s*default=)"[^"]*"',
         lambda m: f'{m.group(1)}"{company}"'),
        ("res/rpm.spec", r'(?m)^Vendor: .*$', const(f"Vendor:     {vendor}")),
        ("res/rpm-flutter.spec", r'(?m)^Vendor: .*$', const(f"Vendor:     {vendor}")),
        ("res/rpm-flutter-suse.spec", r'(?m)^Vendor: .*$', const(f"Vendor:     {vendor}")),
        # Desktop "About" page: links and the legal notice.
        ("flutter/lib/desktop/pages/desktop_setting_page.dart",
         r"(launchUrlString\(')[^']*('\);\n\s*\},\n\s*child: Text\(\n\s*translate\('Privacy Statement'\))",
         lambda m: f"{m.group(1)}{privacy}{m.group(2)}"),
        ("flutter/lib/desktop/pages/desktop_setting_page.dart",
         r"(launchUrlString\(')[^']*('\);\n\s*\},\n\s*child: Text\(\n\s*translate\('Website'\))",
         lambda m: f"{m.group(1)}{web}{m.group(2)}"),
        ("flutter/lib/desktop/pages/desktop_setting_page.dart",
         r"'Copyright \u00a9 \$\{DateTime\.now\(\)\.toString\(\)\.substring\(0, 4\)\}[^']*\$license'",
         const(dart_notice)),
        ("flutter/lib/desktop/pages/install_page.dart",
         r"(launchUrlString\(\n\s*')[^']*('\),\n\s*child: Tooltip\(\n\s*message: ')[^']*(',)",
         lambda m: f"{m.group(1)}{privacy}{m.group(2)}{privacy}{m.group(3)}"),
        # Mobile settings: website and privacy links.
        ("flutter/lib/mobile/pages/settings_page.dart", r"(?m)^const url = '[^']*';$", const(f"const url = '{web}/';")),
        ("flutter/lib/mobile/pages/settings_page.dart",
         r"(child: Text\(')[^']*(',\n\s*style: TextStyle\(\n\s*decoration: TextDecoration\.underline,)",
         lambda m: f"{m.group(1)}{web_host}{m.group(2)}", 2),
        ("flutter/lib/mobile/pages/settings_page.dart",
         r"(launchUrlString\(')[^']*('\),\n\s*leading: Icon\(Icons\.privacy_tip\))",
         lambda m: f"{m.group(1)}{privacy}{m.group(2)}"),
        ("flutter/lib/mobile/pages/settings_page.dart",
         r"(\n\s+const url = ')[^']*(';\n\s+await launchUrl)", lambda m: f"{m.group(1)}{web}/{m.group(2)}"),
        # Legacy Sciter UI (Windows 7 build).
        ("src/ui/index.tis", r"""(url=')[^']*('>" \+ translate\("Privacy Statement"\))""",
         lambda m: f"{m.group(1)}{privacy}{m.group(2)}"),
        ("src/ui/index.tis", r"""(url=')[^']*('>" \+ translate\("Website"\))""",
         lambda m: f"{m.group(1)}{web}{m.group(2)}"),
        ("src/ui/index.tis", r"(margin-top: 1em;'>)Copyright &copy; [^\n]*?(\\\n)",
         lambda m: f"{m.group(1)}{tis_notice}{m.group(2)}"),
        ("src/ui/install.tis", r'(event click \$\(#agreement\) \{\n\s*view\.open_url\(")[^"]*(")',
         lambda m: f"{m.group(1)}{privacy}{m.group(2)}"),
    ]
    if cfg["SUPPORT_EMAIL"]:
        patches.append(("build.py", r"(?m)^Maintainer: .*$", const(f"Maintainer: {vendor}")))
    # The MSI shows this as its license page; the whole file is ours.
    patches.append(("res/msi/Package/License.rtf", r"\A[\s\S]*\Z", const(msi_license_rtf(cfg))))
    return patches


def rtf_text(text):
    out = []
    for ch in text:
        if ch in "\\{}":
            out.append("\\" + ch)
        elif ord(ch) < 128:
            out.append(ch)
        else:
            out.append(f"\\u{ord(ch) if ord(ch) < 32768 else ord(ch) - 65536}?")
    # res/msi/preprocess.py rewrites "RustDesk" and "Purslane ... Ltd" to the app name;
    # an empty RTF group splits the words so the attribution survives that rewrite.
    return "".join(out).replace("RustDesk", "Rust{}Desk").replace("Purslane", "Purs{}lane")


def msi_license_rtf(cfg):
    company, display = cfg["COMPANY"], cfg["DISPLAY_NAME"]
    contact = ", ".join(x for x in (cfg["SUPPORT_EMAIL"], cfg["SUPPORT_PHONE"], cfg["WEBSITE_URL"]) if x)
    sections = [
        (None, f"{display}: licență și informații de utilizare"),
        ("1. Licența programului",
         f"{display} este software liber, bazat pe RustDesk (Copyright © Purslane Tech Pte. Ltd.) și distribuit "
         f"de {company} sub licența GNU Affero General Public License, versiunea 3 (AGPL-3.0). Poți folosi, copia, "
         f"modifica și redistribui programul în condițiile acestei licențe; nicio prevedere din acest document nu "
         f"restrânge drepturile pe care ți le dă AGPL-3.0. Codul sursă complet: {cfg['SOURCE_URL']}. "
         f"Textul integral al licenței: https://www.gnu.org/licenses/agpl-3.0.html"),
        ("2. Fără garanție",
         "Conform secțiunilor 15 și 16 din AGPL-3.0, programul este furnizat „ca atare”, fără nicio garanție, "
         "expresă sau implicită, în limita permisă de lege. Răspunderea pentru serviciile de asistență oferite "
         f"de {company} este cea stabilită prin contractul sau înțelegerea ta cu {company}."),
        ("3. Cum funcționează asistența la distanță",
         f"Programul se conectează la serverul {company}. Un tehnician se poate conecta la calculatorul tău "
         "numai cu ID-ul și parola afișate de program, pe care le comunici tu, sau, dacă ai convenit cu "
         f"{company} acces nesupravegheat, cu parola permanentă stabilită de comun acord. Conexiunea este criptată de la "
         "un capăt la altul. Vezi tot ce face tehnicianul și poți închide conexiunea oricând. Nu comunica ID-ul "
         "și parola persoanelor care te contactează nesolicitat."),
        ("4. Date personale",
         "Pentru funcționare și securitate, programul transmite serverului date tehnice: ID-ul dispozitivului, "
         "numele calculatorului și al utilizatorului, sistemul de operare, adresa IP și jurnalul conexiunilor. "
         f"Detalii despre ce date prelucrăm, cât timp le păstrăm și drepturile tale: {cfg['PRIVACY_URL']}"),
        ("5. Contact", f"{company}: {contact}"),
    ]
    body = []
    for title, text in sections:
        if title is None:
            body.append(f"{{\\b\\fs24 {rtf_text(text)}\\par}}\\par")
        else:
            body.append(f"{{\\b {rtf_text(title)}\\par}}{rtf_text(text)}\\par\\par")
    return ("{\\rtf1\\ansi\\ansicpg1252\\uc1\\deff0{\\fonttbl{\\f0\\fswiss\\fcharset0 Arial;}}"
            "\\f0\\fs18\n" + "\n".join(body) + "\n}\n")


def apply_text(cfg, check):
    # Compute every patch before writing anything, so a mismatch never leaves
    # the tree half-branded.
    contents = {}
    for rel, pattern, repl, *count in text_patches(cfg):
        expected = count[0] if count else 1
        if rel not in contents:
            contents[rel] = (ROOT / rel).read_text(encoding="utf-8")
        new, n = re.subn(pattern, repl, contents[rel])
        if n != expected:
            fail(f"{rel}: expected {expected} match(es) for {pattern!r}, found {n} "
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

    # Optional wide logo for the app's main window (shown at most 300x60); the dark-theme
    # copy turns dark strokes light so they stay readable on a dark background.
    if LOGO_APP_FILE.exists():
        app = Image.open(LOGO_APP_FILE).convert("RGBA")
        app = app.crop(app.getbbox())
        app.save(ROOT / "flutter/assets/logo.png", format="PNG", optimize=True)
        if LOGO_APP_DARK_FILE.exists():
            dark = Image.open(LOGO_APP_DARK_FILE).convert("RGBA").crop(app.getbbox())
        else:
            dark = app.copy()
            px = dark.load()
            for y in range(dark.height):
                for x in range(dark.width):
                    r_, g, b_, a_ = px[x, y]
                    if a_ and (r_ * 299 + g * 587 + b_ * 114) // 1000 < 70:
                        px[x, y] = (245, 238, 239, a_)
        dark.save(ROOT / "flutter/assets/logo_dark.png", format="PNG", optimize=True)
        written += ["flutter/assets/logo.png", "flutter/assets/logo_dark.png"]
    return written


def fingerprint():
    h = hashlib.sha256()
    h.update(ENV_FILE.read_bytes())
    h.update(LOGO_FILE.read_bytes())
    if LOGO_SMALL_FILE.exists():
        h.update(LOGO_SMALL_FILE.read_bytes())
    for extra in (LOGO_APP_FILE, LOGO_APP_DARK_FILE):
        if extra.exists():
            h.update(extra.read_bytes())
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
