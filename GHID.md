# Ghid: remote desktop propriu, bazat pe RustDesk

Acest repo este un fork al [RustDesk](https://github.com/rustdesk/rustdesk) 1.5.0, pregătit
pentru a fi folosit cu **numele tău, logo-ul tău și serverul tău**. Clienții compilați de aici
se conectează doar la serverul tău și nu au nevoie de nicio configurare la instalare.

| Ce | Unde |
| --- | --- |
| Setările de branding (nume, server, cheie) | [`branding/brand.env`](branding/brand.env) |
| Logo-ul | [`branding/logo.png`](branding/logo.png) |
| Scriptul care aplică branding-ul | [`branding/apply.py`](branding/apply.py) |
| Serverul (Docker) | [`server/`](server/) |
| Build pentru toate platformele | GitHub Actions → **Flutter Tag Build** |

Ordinea pașilor contează: **serverul primul**, pentru că el generează cheia pe care o
încorporezi în clienți.

---

## Pasul 1 — Pornește serverul

Ai nevoie de un server Linux cu IP public (un VPS de 1 vCPU / 1 GB RAM e suficient pentru
zeci de calculatoare; Ubuntu 22.04 sau 24.04). Ideal, un domeniu (ex. `remote.firma-mea.ro`)
care arată spre IP-ul lui — dacă schimbi vreodată IP-ul, schimbi doar DNS-ul, nu și clienții.

```bash
git clone https://github.com/danielneagu2000/Rust-Desktop.git
cd Rust-Desktop/server
sudo ./install.sh remote.firma-mea.ro
```

Scriptul instalează Docker (dacă lipsește), deschide porturile în `ufw`, pornește `hbbs` și
`hbbr` și la final afișează ceva de genul:

```
RENDEZVOUS_SERVER=remote.firma-mea.ro
RS_PUB_KEY=h5gYcaUJdmf0TSyIb296phdKvtJBhgY7a6SmrcQ280A=
```

Notează-le — îți trebuie la pasul 2.

**Porturi** (dacă ai și firewall la provider: AWS, Azure, Hetzner etc., deschide-le și acolo):
`21115-21117/tcp`, `21116/udp`, iar `21118-21119/tcp` doar dacă vrei clientul web.

**Backup obligatoriu:** `server/data/id_ed25519`. Este cheia privată a serverului. Dacă o
pierzi, trebuie să recompilezi și să reinstalezi toți clienții.

**Fără limite:** serverul open-source nu limitează numărul de calculatoare, durata sesiunilor
sau numărul de conexiuni simultane. Limitele implicite de viteză ale relay-ului sunt
dezactivate în `server/docker-compose.yml` (`TOTAL_BANDWIDTH`, `SINGLE_BANDWIDTH`,
`LIMIT_SPEED`), deci viteza depinde doar de rețeaua și procesorul serverului. Când cele două
calculatoare se pot conecta direct (P2P), traficul nici nu trece prin server. În aplicație,
la *Calitate imagine* poți alege „Cea mai bună” și FPS personalizat (până la 120).

Serverul acceptă doar clienți care au cheia lui (`-k _`), deci un RustDesk obișnuit sau
altcineva nu-ți poate folosi serverul.

## Pasul 2 — Configurează branding-ul

Direct pe GitHub (nu ai nevoie de nimic instalat):

1. Deschide `branding/brand.env` → iconița creion (Edit) și completează:
   - `APP_NAME` — numele aplicației, ex. `FirmaDesk` (doar litere și cifre, fără spații);
   - `RENDEZVOUS_SERVER` și `RS_PUB_KEY` — valorile de la pasul 1.
2. Opțional: înlocuiește `branding/logo.png` cu logo-ul tău (Add file → Upload files, același
   nume). PNG pătrat, ideal 1024×1024, **cu fundal transparent**.
3. Commit pe `master`.

Workflow-ul **Apply branding** pornește automat, rescrie sursele (nume, server, cheie,
toate iconițele pentru Windows/macOS/Linux/Android/iOS) și face singur un commit
„Apply branding from branding/brand.env”. Durează ~1 minut; urmărește-l în tab-ul
**Actions**.

Local, același lucru:

```bash
pip install pillow
python3 branding/apply.py          # aplică
python3 branding/apply.py --check  # verifică
```

## Pasul 3 — Compilează pentru toate platformele

În GitHub: **Releases → Draft a new release → Choose a tag**, scrie un tag nou de forma
`1.5.0-1` (apoi `1.5.0-2` la următoarea versiune etc.) și publică. Alternativ, din terminal:

```bash
git tag 1.5.0-1 && git push origin 1.5.0-1
```

Workflow-ul **Flutter Tag Build** verifică întâi că branding-ul e aplicat (refuză să
compileze un client nebranduit), apoi construiește tot și urcă fișierele în release-ul
cu același nume. Prima compilare durează **1–2 ore**. Repo-ul fiind public, minutele
GitHub Actions sunt gratuite.

Ce primești în release:

| Platformă | Fișiere |
| --- | --- |
| Windows (x64, ARM64, plus versiune x86 pentru Windows 7) | `.exe`, `.msi` |
| macOS (Intel și Apple Silicon) | `.dmg` |
| Linux | `.deb`, `.rpm`, `.AppImage`, Flatpak (x86_64 și ARM) |
| Android | `.apk` pe arhitecturi — **trebuie semnat**, vezi mai jos |
| iOS | nu se publică (necesită cont Apple Developer) — vezi mai jos |

## Pasul 4 — Instalează pe calculatoare

- **Calculatorul controlat:** instalează aplicația, apoi în Setări → Securitate setează o
  **parolă permanentă** pentru acces nesupravegheat. Pe Windows, instalarea completă
  (nu modul portabil) rulează ca serviciu și pornește odată cu sistemul.
- **Calculatorul tău (operator):** instalează aceeași aplicație și conectează-te cu ID-ul
  calculatorului controlat.
- Pe macOS trebuie acordate manual permisiunile *Screen Recording* și *Accessibility*.
- Pe Linux, controlul funcționează cel mai bine pe X11 (Wayland are limitări).

## Semnarea aplicațiilor (recomandat pentru producție)

Fără semnare, aplicațiile funcționează, dar apar avertismente:

- **Windows:** SmartScreen spune „editor necunoscut”. Rezolvare: certificat de code signing.
- **macOS:** Gatekeeper blochează aplicația la prima pornire (click dreapta → Open).
  Rezolvare: cont Apple Developer (99 $/an). Pune certificatul în secretele repo-ului
  (Settings → Secrets → Actions): `MACOS_P12_BASE64`, `MACOS_P12_PASSWORD`,
  `MACOS_CODESIGN_IDENTITY`, `MACOS_NOTARIZE_JSON`.
- **Android (obligatoriu):** un APK nesemnat nu se poate instala. Generează o singură dată
  o cheie și păstreaz-o (cu aceeași cheie se pot instala update-urile peste versiunea veche):

  ```bash
  keytool -genkeypair -v -keystore firma.jks -alias firma -keyalg RSA -keysize 4096 -validity 10000
  base64 -w0 firma.jks > firma.jks.b64
  ```

  Apoi, în Settings → Secrets and variables → Actions, adaugă: `ANDROID_SIGNING_KEY`
  (conținutul din `firma.jks.b64`), `ANDROID_ALIAS` (`firma`), `ANDROID_KEY_STORE_PASSWORD`
  și `ANDROID_KEY_PASSWORD` (parola aleasă). Fă backup la `firma.jks`.
- **iOS:** Apple nu permite instalarea fără semnare (cont Apple Developer + TestFlight sau
  distribuție enterprise). De reținut: **un iPhone/iPad poate doar controla alte
  dispozitive, nu poate fi controlat** — este o limitare a iOS, valabilă și pentru AnyDesk.

## Ce schimbă branding-ul și ce nu

Se schimbă: numele afișat (ferestre, meniuri, Android, iOS, Windows, Linux), serverul și
cheia încorporate, iconițele și logo-ul, adresa API implicită (nu mai trimite cereri la
rustdesk.com). Pentru că numele nu mai e „RustDesk”, verificarea automată de update-uri de
la RustDesk este dezactivată — update-urile le distribui tu.

Rămân ca în original, intenționat, ca scripturile oficiale de build să funcționeze:
numele fișierului executabil (`rustdesk.exe`, `rustdesk`), numele pachetului macOS
(`RustDesk.app`) și identificatorul pachetului Android.

## Actualizare la o versiune nouă RustDesk

```bash
git remote add upstream https://github.com/rustdesk/rustdesk.git
git fetch upstream --tags
# Copiază peste repo sursele noii versiuni (inclusiv libs/hbb_common), apoi:
python3 branding/apply.py
```

`apply.py` refuză să lucreze (fără să modifice nimic) dacă noua versiune a schimbat
fișierele pe care le modifică; atunci trebuie actualizat scriptul.

## Licență

RustDesk este licențiat **AGPL-3.0** (vezi `LICENCE`). Pe scurt: poți folosi și modifica
liber, inclusiv comercial, dar dacă distribui aplicația modificată (inclusiv clienților
tăi), codul sursă modificat trebuie să fie disponibil sub aceeași licență. Acest repo fiind
public, condiția este îndeplinită. Nu folosi numele și logo-ul „RustDesk” pentru produsul
tău — de aceea există `APP_NAME`.
