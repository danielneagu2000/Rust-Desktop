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
| Versiune nouă pentru toate platformele | GitHub Actions → **Publish new version** |

Ordinea pașilor contează: **serverul primul**, pentru că el generează cheia pe care o
încorporezi în clienți.

---

## Pasul 1 — Pornește serverul

Ai nevoie de un calculator Linux pornit permanent: un VPS (1 vCPU / 1 GB RAM e suficient
pentru zeci de calculatoare), serverul tău cu Virtualmin sau un mini PC. Merge pe AlmaLinux,
Rocky, RHEL, Ubuntu și Debian. Ideal, un domeniu (ex. `remote.firma-mea.ro`)
care arată spre IP-ul lui — dacă schimbi vreodată IP-ul, schimbi doar DNS-ul, nu și clienții.

```bash
git clone https://github.com/danielneagu2000/Rust-Desktop.git
cd Rust-Desktop/server
sudo ./install.sh remote.firma-mea.ro
```

Scriptul instalează Docker (dacă lipsește), deschide porturile în firewall (`firewalld` sau
`ufw`), pornește `hbbs`, `hbbr` și panoul de securitate și la final afișează ceva de genul:

```
RENDEZVOUS_SERVER=remote.firma-mea.ro
RS_PUB_KEY=h5gYcaUJdmf0TSyIb296phdKvtJBhgY7a6SmrcQ280A=
```

Notează-le — îți trebuie la pasul 2.

**Porturi** (dacă ai și firewall la provider: AWS, Azure, Hetzner etc., deschide-le și acolo):
`21114-21117/tcp`, `21116/udp`, iar `21118-21119/tcp` doar dacă vrei clientul web.

**Backup obligatoriu:** `server/data/id_ed25519`. Este cheia privată a serverului. Dacă o
pierzi, trebuie să recompilezi și să reinstalezi toți clienții.

**Fără limite:** serverul open-source nu limitează numărul de calculatoare, durata sesiunilor
sau numărul de conexiuni simultane. Limitele implicite de viteză ale relay-ului sunt
dezactivate în `server/docker-compose.yml` (`TOTAL_BANDWIDTH`, `SINGLE_BANDWIDTH`,
`LIMIT_SPEED`), deci viteza depinde doar de rețeaua și procesorul serverului. Când cele două
calculatoare se pot conecta direct (P2P), traficul nici nu trece prin server. În aplicație,
la *Calitate imagine* poți alege „Cea mai bună” și FPS personalizat (până la 120).

Serverul acceptă doar clienți care au cheia lui publică (`-k _`). Cheia publică nu e secretă
(e în aplicație și în repo), deci asta oprește folosirea întâmplătoare, nu un atacator hotărât;
secretul real e cheia privată `id_ed25519`.

### Pe un mini PC (acasă sau la birou)

Funcționează la fel, cu AlmaLinux sau altă distribuție de mai sus:

1. Dă-i mini PC-ului un **IP fix în rețeaua locală** (rezervare DHCP din router).
2. Pe router, fă **port forwarding** către mini PC pentru `21114-21117/tcp` și `21116/udp`
   (plus `21118-21119/tcp` doar pentru clientul web). **Nu** redirecționa `21120` (panoul).
3. Dacă nu ai IP public fix, folosește un **DDNS** (No-IP, DuckDNS sau DDNS-ul din router) și
   pune numele DDNS în `RENDEZVOUS_SERVER`. Dacă IP-ul de la operator e în spatele CG-NAT
   (nu ai IP public deloc), cere unul public de la operator sau folosește un VPS.
4. Instalează cu panoul accesibil din rețeaua locală:

   ```bash
   sudo dnf -y install git        # pe AlmaLinux
   git clone https://github.com/danielneagu2000/Rust-Desktop.git
   cd Rust-Desktop/server
   sudo PANEL_BIND=0.0.0.0 ./install.sh remote.domeniul-tau.ro
   ```

   Scriptul deschide portul panoului (21120) doar pentru rețelele locale (192.168.x.x, 10.x.x.x,
   172.16-31.x.x). SELinux poate rămâne activ: volumele sunt etichetate corect.
5. Setează mini PC-ul să nu intre în sleep și, din BIOS, să pornească singur după o pană de
   curent (*Restore on AC power loss → Power On*).

## Pagina de descărcare

`install.sh` pornește și o pagină web de unde clienții tăi descarcă aplicația, la
`https://remote.rdndata.ro/` (sau `http://IP-FIX/` dacă folosești doar IP). Pagina:

- detectează sistemul vizitatorului și îi arată butonul potrivit (Windows, macOS, Linux, Android);
- listează toate variantele, cu dimensiune și sumă de control SHA-256;
- explică pașii (ID + parolă) și avertizează împotriva înșelătoriilor telefonice.

**Fișierele se actualizează singure:** zilnic (și la pornire) serverul verifică release-urile
din GitHub și descarcă ultima versiune compilată în `server/web/files/`. Manual:
`sudo systemctl start rdn-update`. Până la primul release, pagina afișează „În curând”.

**Ce trebuie să faci:**

1. În DNS-ul domeniului `rdndata.ro`, creează un record **A**: `remote` → IP-ul public al
   serverului / al routerului de acasă.
2. Pe router redirecționează și **80/tcp** și **443/tcp** către mini PC (pentru certificatul
   HTTPS gratuit Let's Encrypt, obținut automat de Caddy).
3. Completează datele de contact în `server/web/site.json` (`phone`, `email`, `hours`);
   secțiunea Contact apare doar dacă le completezi.

Dacă pe server rulează deja Apache/Nginx (de exemplu Virtualmin), `install.sh` nu pornește
pagina ca să nu intre în conflict. În Virtualmin creează site-ul `remote.rdndata.ro` cu SSL
(Let's Encrypt din Virtualmin) și setează-i ca director rădăcină `.../Rust-Desktop/server/web`
(sau copiază acolo conținutul lui); `update_downloads.py` și folderul `files/` rămân la fel.

## Panoul de securitate

Rulează pe același server și primește automat jurnalele de la toate calculatoarele care
folosesc aplicația ta. Nu trebuie configurat nimic pe calculatoare: clienții trimit singuri
datele la `http://SERVER:21114`.

Ce arată:

- **Istoric conexiuni:** fiecare conexiune cu IP-ul sursă, calculatorul vizat, cine s-a
  conectat (ID și nume), tipul (control, transfer fișiere, terminal…), metoda de autentificare
  (parolă unică/permanentă, acceptare manuală, 2FA), durata și starea (activă, reușită, eșuată).
- **Brute-force pe IP:** pentru fiecare IP, din ultimele 30 de zile: încercări, reușite, eșuate,
  alarme și câte calculatoare a încercat; risc scăzut, mediu sau ridicat.
- **IP-uri blocate:** cele blocate automat de calculatoare (după 6 parole greșite într-un minut,
  după 30 în total) și lista ta de IP-uri blocate pe server, cu buton Blochează/Deblochează.
- **Alarme:** toate alarmele de securitate trimise de calculatoare.
- **Dispozitive:** ce calculatoare sunt online, nume, utilizator, sistem, IP public, și butonul
  **Deconectează** pentru a închide imediat o sesiune activă.

Acces: implicit panoul ascultă doar local pe server (port 21120). Utilizatorul și parola sunt
afișate de `install.sh` și salvate în `server/.env`.

- De pe calculatorul tău, prin tunel SSH: `ssh -L 21120:127.0.0.1:21120 root@SERVER`, apoi
  deschide `http://localhost:21120/`.
- Cu Virtualmin, prin HTTPS pe domeniul tău: în Virtualmin, la domeniul dorit,
  **Server Configuration → Edit Proxy Paths**, adaugă calea `/rustdesk-panel/` către
  `http://127.0.0.1:21120/`. Panoul e apoi la `https://domeniul-tau.ro/rustdesk-panel/`.
- Pe un mini PC în rețeaua locală: instalează cu `PANEL_BIND=0.0.0.0` (vezi mai sus).

Ce trebuie știut:

- „Blocat pe server” refuză conexiunile **prin relay** de la acel IP. Conexiunile directe P2P
  nu trec prin server; pe acelea le opresc protecțiile de pe calculatoare (blocare automată, 2FA,
  whitelist de IP).
- Calculatoarele raportează o tentativă eșuată per conexiune, nu fiecare parolă greșită;
  rafalele de parole greșite apar ca alarme.
- Jurnalele vin de la aplicații; cine are cheia publică ar putea trimite date false în panou,
  dar nu poate citi panoul și nu poate controla nimic. Datele se păstrează 180 de zile
  (`RETENTION_DAYS` în `server/.env`).

## Licențe

Cu `LICENSE_REQUIRED=Y` în `branding/brand.env`, aplicația **nu funcționează fără un cod de
licență valid**: nu se poate conecta la alte calculatoare și nu poate fi accesată. La prima
pornire afișează „Licență necesară” cu butonul **Activează licența**.

În panoul de securitate, tab-ul **Licențe**:

- **Licență nouă:** numele clientului, câte calculatoare acoperă, perioada (1, 3, 6, 12 luni sau
  nelimitată). Primești un cod de forma `RDN-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` (25 de caractere aleatorii), pe care îl trimiți clientului.
  Perioada începe la prima activare.
- **Prelungește** cu +1, +3, +6 sau +12 luni (de la data expirării, sau de azi dacă a expirat).
- **Revocă** sau **Reactivează** o licență; **Eliberează locul** unui calculator (tab-ul
  Dispozitive), de exemplu când clientul își schimbă calculatorul.
- Tab-ul **Dispozitive** arată pentru fiecare calculator licența și data expirării, plus cine e
  online fără licență validă.

Licența e necesară pe **toate** dispozitivele: și pe calculatoarele clienților, și pe ale
tehnicienilor. Pentru calculatoarele tale creează o licență „nelimitată” (de ex. „Intern RDN”).

Cum funcționează: serverul semnează licența cu cheia lui (`server/data/id_ed25519`), iar aplicația
o verifică cu cheia publică pe care o are compilată, deci nu poate fi falsificată. Serverul o
reîmprospătează la fiecare ~15 secunde; o licență revocată sau expirată blochează aplicația în
câteva secunde dacă e online, iar sesiunile deschise sunt închise. Un calculator care nu poate
contacta serverul rămâne funcțional cel mult 7 zile.

Limită: codul sursă e public (AGPL-3.0), deci un programator poate compila o versiune fără
verificarea licenței și o poate conecta la serverul tău (cheia publică a serverului nu e
secretă). Licența oprește utilizarea obișnuită, nu un programator hotărât.

Pentru a opri temporar închiderea sesiunilor dispozitivelor fără licență (de ex. la teste cu
aplicația RustDesk oficială): `LICENSE_REQUIRED=N` în `server/.env`, apoi `docker compose up -d`.

## Backup și restaurare

Un backup conține tot ce nu poate fi refăcut: **cheia serverului** (`id_ed25519`, de care depind
toate aplicațiile instalate), ID-urile înregistrate, **licențele**, istoricul conexiunilor,
IP-urile blocate și setările (`server/.env`).

- **Automat:** panoul face un backup pe zi în `server/data/backups/` și păstrează ultimele 14.
- **Manual:** panoul → tab-ul **Backup** → **Creează backup acum**, apoi **Descarcă**.
- **Important:** descarcă periodic (de ex. săptămânal) un backup pe alt dispozitiv (laptop,
  stick, cloud). Backup-urile de pe mini PC se pierd odată cu discul lui.
- Fișierul conține cheia privată a serverului și parola panoului: păstrează-l în siguranță.

**Restaurare din panou** (același server): tab-ul **Backup** → alegi fișierul → **Restaurează**.
Se restaurează licențele, istoricul, dispozitivele și IP-urile blocate; înainte se face automat
un backup al stării curente. Un backup de pe alt server (altă cheie) e refuzat aici.

**Restaurare completă** (mini PC nou, disc defect, cheie pierdută):

```bash
git clone https://github.com/danielneagu2000/Rust-Desktop.git
cd Rust-Desktop/server
sudo PANEL_BIND=0.0.0.0 ./install.sh remote.rdndata.ro     # instalează Docker și pornește
sudo ./restore.sh /cale/rdn-backup-....tar.gz            # pune la loc cheia, licențele, setările
```

După restaurare, cheia publică afișată trebuie să fie aceeași cu `RS_PUB_KEY` din
`branding/brand.env`: așa aplicațiile deja instalate se reconectează singure, fără reinstalare.

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

## Pasul 3 — Publică o versiune

În GitHub: **Actions → Publish new version → Run workflow**. Atât. Workflow-ul:

1. verifică întâi că branding-ul e aplicat (refuză să compileze un client nebranduit);
2. alege singur eticheta următoare: `1.5.0-1`, apoi `1.5.0-2` … `1.5.0-9`;
3. compilează pentru toate platformele (**1–2 ore**; minutele GitHub Actions sunt gratuite
   pentru repo-uri publice);
4. **numai dacă toate compilările au reușit**, publică release-ul ca „final” (adaugă
   `update-manifest.json`).

Un release nefinalizat (în lucru sau eșuat) nu ajunge niciodată la clienți sau pe server.

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

## Actualizări automate

După ce un release e final, totul merge singur, fără intervenția ta:

| Ce | Cum | Când |
| --- | --- | --- |
| Pagina de descărcare | serverul aduce noile kituri de pe GitHub | zilnic, ~04:00 |
| Serverul (panou, site, configurație) | serverul trece la codul release-ului (`auto_update.sh`) | zilnic, ~04:00 |
| Aplicația pe **Windows** | se descarcă și se instalează singură, când nu e nicio sesiune activă | la verificarea periodică a aplicației |
| Aplicația pe **macOS** | se actualizează prin serviciul de fundal (dacă aplicația e instalată) | la fel |
| Aplicația pe **Linux** și **Android** | apare mesajul „versiune nouă”, cu link spre pagina de descărcare | la fel |

Forțezi verificarea pe server cu `sudo systemctl start rdn-update` (jurnal:
`journalctl -u rdn-update`).

Siguranță: aplicația întreabă serverul tău care e ultima versiune, dar **descarcă doar din
release-urile acestui repo de pe GitHub** (lista permisă e compilată în aplicație), deci
nici un server compromis nu o poate face să instaleze altceva.

Reguli:

- Nu modifica fișiere din repo direct pe server (de ex. `server/web/site.json`): modifică-le
  în GitHub. Dacă găsește modificări locale, actualizarea serverului se oprește ca să nu le piardă.
- Actualizarea automată pe Windows/macOS e pornită implicit (`AUTO_UPDATE=Y` în
  `branding/brand.env`); utilizatorul o poate opri din setările aplicației.
- Încap 9 versiuni (`1.5.0-1` … `1.5.0-9`) peste aceeași versiune RustDesk; după aceea
  treci la o versiune RustDesk nouă (vezi mai jos).

## Ce schimbă branding-ul și ce nu

Se schimbă: numele afișat, serverul și cheia încorporate, iconițele și logo-ul, firma
care publică (metadate), textul de licență al instalatorului MSI, adresa de unde se verifică
actualizările.

Există două nume: `APP_NAME` (tehnic, fără spații, ex. `RDNRemote`), folosit în aplicație,
în foldere și în numele serviciilor, și `DISPLAY_NAME` (ex. `RDN Remote`), afișat de sistem
pe scurtături, pe ecranul telefonului și în proprietățile fișierului.

Pe sisteme:

- **Windows:** instalatorul redenumește executabilul în `RDNRemote.exe`.
- **macOS:** aplicația se numește `RDNRemote.app`.
- **Android:** identificator propriu (`ANDROID_APP_ID`, implicit `ro.rdndata.remote`), deci
  se instalează lângă un RustDesk existent. Nu-l schimba după prima distribuire.
- **Linux:** pachetul, executabilul și serviciul rămân `rustdesk` (procesul de build
  oficial); codul le caută sub acest nume. Pe un calculator cu RustDesk oficial instalat,
  pachetul RDN Remote îl înlocuiește.

## Actualizare la o versiune nouă RustDesk

Îmbunătățirile din RustDesk se preiau automat, dar intră în aplicație doar cu acordul tău:

1. În fiecare luni dimineața, workflow-ul **Sync RustDesk releases** verifică dacă RustDesk
   a publicat o versiune nouă. Se ia doar versiunea marcată de RustDesk ca stabilă
   („Latest” pe GitHub, ex. `1.5.1`), niciodată `nightly` sau „Pre-release”.
2. Dacă da, o importă și deschide un **pull request „Actualizare RustDesk X.Y.Z”** către
   `master`. Descrierea spune ce s-a schimbat, dacă se îmbină fără conflicte cu
   modificările RDN (branding, licențe, server) și dacă branding-ul se aplică în continuare.
3. Tu (sau eu, la cerere) apeși **Merge**. Branding-ul se reaplică singur după merge.
4. Rulezi **Publish new version**; clienții și serverul se actualizează ca de obicei.

Verificarea se poate porni și manual: Actions → **Sync RustDesk releases** → Run workflow
(opțional cu o versiune anume).

De știut:

- Dacă GitHub nu permite workflow-urilor să deschidă pull request-uri (setarea
  Settings → Actions → General → „Allow GitHub Actions to create and approve pull
  requests”), workflow-ul deschide în loc un **issue** cu link-ul spre pull request.
- Designul și datele RDN rămân ale tale: numele, logo-ul, iconițele și link-urile se
  reaplică după fiecare merge; panoul, site-ul, licențele și scripturile serverului sunt
  verificate la fiecare preluare să rămână neschimbate; datele (licențe, istoric, backup-uri,
  parole, cheia serverului) stau doar pe server, nu în repo, deci nu sunt atinse niciodată.
- Dacă descrierea anunță **conflicte**, **ATENȚIE: fișiere RDN** sau că **branding-ul nu
  se mai aplică**, nu face merge; cere-mi să le rezolv.
- Fișierele de compilare din `.github/` nu se preiau (sunt adaptate pentru RDN Remote);
  descrierea le listează pe cele pe care RustDesk le-a schimbat, ca să le portăm manual.
- Ramura `upstream-rustdesk` conține sursele RustDesk neschimbate, câte un commit pe
  versiune; nu lucra pe ea.

## Licență

RustDesk este licențiat **AGPL-3.0** (vezi `LICENCE`). Pe scurt: poți folosi și modifica
liber, inclusiv comercial, dar dacă distribui aplicația modificată (inclusiv clienților
tăi), codul sursă modificat trebuie să fie disponibil sub aceeași licență. Acest repo fiind
public, condiția este îndeplinită. Nu folosi numele și logo-ul „RustDesk” pentru produsul
tău — de aceea există `APP_NAME`.
