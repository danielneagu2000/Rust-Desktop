#!/usr/bin/env bash
# Instalează serverul (hbbs + hbbr + panoul de securitate) pe Linux:
# AlmaLinux, Rocky, RHEL, Ubuntu, Debian (merge și alături de Virtualmin).
#
#   sudo ./install.sh remote.firma-mea.ro      # domeniu sau IP public al serverului
#
# Pe un mini PC acasă/la birou, ca panoul să fie accesibil din rețeaua locală:
#   sudo PANEL_BIND=0.0.0.0 ./install.sh remote.firma-mea.ro
#
# La final afișează cheia publică pe care o pui în branding/brand.env (RS_PUB_KEY)
# și datele de acces la panoul de securitate.
set -euo pipefail

cd "$(dirname "$0")"

if [[ $EUID -ne 0 ]]; then
  echo "Rulează cu sudo: sudo $0 <domeniu-sau-ip>" >&2
  exit 1
fi

env_get() { [[ -f .env ]] && sed -n "s/^$1=//p" .env | tail -n 1 || true; }

HOST="${1:-$(env_get SERVER_HOST)}"
if [[ -z "$HOST" ]]; then
  echo "Folosire: sudo $0 <domeniu-sau-ip-public>" >&2
  exit 1
fi
if [[ ! "$HOST" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Adresă invalidă: $HOST (fără http://, fără port)" >&2
  exit 1
fi

PANEL_USER="$(env_get PANEL_USER)"; PANEL_USER="${PANEL_USER:-admin}"
PANEL_PASSWORD="$(env_get PANEL_PASSWORD)"
if [[ -z "$PANEL_PASSWORD" ]]; then
  PANEL_PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)"
fi
PANEL_BIND="${PANEL_BIND:-$(env_get PANEL_BIND)}"; PANEL_BIND="${PANEL_BIND:-127.0.0.1}"

. /etc/os-release
if ! command -v docker >/dev/null 2>&1; then
  echo "==> Instalez Docker"
  case " ${ID:-} ${ID_LIKE:-} " in
    *" almalinux "*|*" rocky "*|*" rhel "*|*" centos "*|*" fedora "*)
      dnf -y install dnf-plugins-core
      dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
      dnf -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin
      ;;
    *)
      curl -fsSL https://get.docker.com | sh
      ;;
  esac
fi
systemctl enable --now docker >/dev/null 2>&1 || true
if ! docker compose version >/dev/null 2>&1; then
  echo "Lipsește pluginul 'docker compose'. Instalează docker-compose-plugin și reîncearcă." >&2
  exit 1
fi

# Pagina de descărcare (server/web): pe domeniu cu HTTPS automat, pe IP fix doar HTTP.
# Se pornește doar dacă porturile 80/443 sunt libere (nu rulează deja Apache/Nginx/Virtualmin);
# forțezi cu WEB=1 sau dezactivezi cu WEB=0.
if [[ "$HOST" =~ ^[0-9.]+$ ]]; then WEB_ADDRESS=":80"; else WEB_ADDRESS="$HOST"; fi
if [[ -z "${WEB:-}" ]]; then
  WEB=1
  if ss -Hltn '( sport = :80 or sport = :443 )' 2>/dev/null | grep -q . \
     && ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx rustdesk-web; then
    WEB=0
  fi
fi

umask 077
cat > .env <<EOF
SERVER_HOST=$HOST
PANEL_USER=$PANEL_USER
PANEL_PASSWORD=$PANEL_PASSWORD
PANEL_BIND=$PANEL_BIND
WEB_ADDRESS=$WEB_ADDRESS
EOF
[[ "$WEB" == 1 ]] && echo "COMPOSE_PROFILES=web" >> .env
umask 022

PRIVATE_NETS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  echo "==> Deschid porturile în ufw"
  ufw allow 21114:21117/tcp
  ufw allow 21116/udp
  ufw allow 21118:21119/tcp
  [[ "$WEB" == 1 ]] && ufw allow 80,443/tcp
  if [[ "$PANEL_BIND" != "127.0.0.1" ]]; then
    for net in $PRIVATE_NETS; do ufw allow from "$net" to any port 21120 proto tcp; done
  fi
fi
# firewalld: implicit pe AlmaLinux/Rocky/RHEL, des întâlnit și pe serverele cu Virtualmin.
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  echo "==> Deschid porturile în firewalld"
  firewall-cmd --permanent --add-port=21114-21119/tcp
  firewall-cmd --permanent --add-port=21116/udp
  [[ "$WEB" == 1 ]] && firewall-cmd --permanent --add-service=http --add-service=https
  if [[ "$PANEL_BIND" != "127.0.0.1" ]]; then
    # Panoul doar din rețeaua locală, niciodată de pe internet.
    for net in $PRIVATE_NETS; do
      firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$net port port=21120 protocol=tcp accept"
    done
  fi
  firewall-cmd --reload
fi

echo "==> Pornesc serverul"
docker compose pull --ignore-buildable
docker compose up -d --build

for _ in $(seq 1 30); do
  [[ -s data/id_ed25519.pub ]] && break
  sleep 1
done
if [[ ! -s data/id_ed25519.pub ]]; then
  echo "Cheia nu a fost generată. Verifică: docker compose logs hbbs" >&2
  exit 1
fi
# Asigură-te că relay-ul folosește aceeași cheie ca hbbs.
docker compose restart hbbr >/dev/null
# Cheia privată și backup-urile: doar root.
chmod 700 data
chmod 600 data/id_ed25519

# Actualizare automată zilnică (auto_update.sh): kiturile de pe pagina de descărcare,
# versiunea anunțată clienților și serverul însuși, urmărind doar release-urile finalizate.
SERVER_DIR="$(pwd)"
for old in rdn-downloads.timer rdn-downloads.service; do
  systemctl disable --now "$old" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$old"
done
cat > /etc/systemd/system/rdn-update.service <<EOF
[Unit]
Description=RDN Remote: actualizare automată (kituri, versiune clienți, server)
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
# Prin bash: SELinux nu lasă systemd să execute direct un script din /root (203/EXEC).
ExecStart=/bin/bash $SERVER_DIR/auto_update.sh
EOF
cat > /etc/systemd/system/rdn-update.timer <<EOF
[Unit]
Description=RDN Remote: verificare zilnică a release-urilor noi

[Timer]
OnBootSec=5min
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now rdn-update.timer >/dev/null
echo "==> Verific release-urile publicate"
systemctl start rdn-update.service || echo "Atenție: actualizarea automată a eșuat; vezi: journalctl -u rdn-update" >&2

if [[ "$WEB" == 1 ]]; then
  if [[ "$WEB_ADDRESS" == ":80" ]]; then WEB_URL="http://$HOST/"; else WEB_URL="https://$HOST/"; fi
  WEB_HOW="$WEB_URL  (certificatul HTTPS se obține automat la prima accesare dacă domeniul
  arată spre acest server și porturile 80/443 sunt redirecționate)"
else
  WEB_HOW="nepornită: porturile 80/443 sunt ocupate (Apache/Nginx/Virtualmin).
  Copiază conținutul server/web/ în site-ul tău din Virtualmin (vezi GHID.md)."
fi

if [[ "$PANEL_BIND" == "127.0.0.1" ]]; then
  PANEL_HOW="Din calculatorul tău:  ssh -L 21120:127.0.0.1:21120 root@$HOST
  apoi deschide în browser  http://localhost:21120/"
else
  LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  PANEL_HOW="Din rețeaua locală:  http://${LAN_IP:-IP-ul-acestui-calculator}:21120/
  (NU face port forwarding pe router pentru 21120)"
fi

cat <<EOF

Server pornit pe $HOST.

Pune aceste valori în branding/brand.env:
  RENDEZVOUS_SERVER=$HOST
  RS_PUB_KEY=$(cat data/id_ed25519.pub)

Pagina de descărcare:
  $WEB_HOW

Panoul de securitate:
  $PANEL_HOW
  utilizator: $PANEL_USER
  parolă:     $PANEL_PASSWORD      (salvată în server/.env)

IMPORTANT: descarcă periodic un backup din panou (tab-ul Backup) pe alt dispozitiv;
conține cheia privată server/data/id_ed25519. Dacă o pierzi,
toți clienții trebuie recompilați cu cheia nouă.
Dacă serverul e în spatele unui router sau al unui firewall de la provider, deschide/redirecționează
porturile 21114-21119/tcp și 21116/udp (plus 80 și 443/tcp pentru pagina de descărcare)
către acest calculator.
EOF
