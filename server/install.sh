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

umask 077
cat > .env <<EOF
SERVER_HOST=$HOST
PANEL_USER=$PANEL_USER
PANEL_PASSWORD=$PANEL_PASSWORD
PANEL_BIND=$PANEL_BIND
EOF

PRIVATE_NETS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  echo "==> Deschid porturile în ufw"
  ufw allow 21114:21117/tcp
  ufw allow 21116/udp
  ufw allow 21118:21119/tcp
  if [[ "$PANEL_BIND" != "127.0.0.1" ]]; then
    for net in $PRIVATE_NETS; do ufw allow from "$net" to any port 21120 proto tcp; done
  fi
fi
# firewalld: implicit pe AlmaLinux/Rocky/RHEL, des întâlnit și pe serverele cu Virtualmin.
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  echo "==> Deschid porturile în firewalld"
  firewall-cmd --permanent --add-port=21114-21119/tcp
  firewall-cmd --permanent --add-port=21116/udp
  if [[ "$PANEL_BIND" != "127.0.0.1" ]]; then
    # Panoul doar din rețeaua locală, niciodată de pe internet.
    for net in $PRIVATE_NETS; do
      firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$net port port=21120 protocol=tcp accept"
    done
  fi
  firewall-cmd --reload
fi

echo "==> Pornesc serverul"
docker compose pull
docker compose up -d

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

Panoul de securitate:
  $PANEL_HOW
  utilizator: $PANEL_USER
  parolă:     $PANEL_PASSWORD      (salvată în server/.env)

IMPORTANT: fă backup la server/data/id_ed25519 (cheia privată). Dacă o pierzi,
toți clienții trebuie recompilați cu cheia nouă.
Dacă serverul e în spatele unui router sau al unui firewall de la provider, deschide/redirecționează
porturile 21114-21119/tcp și 21116/udp către acest calculator.
EOF
