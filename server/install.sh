#!/usr/bin/env bash
# Instalează serverul (hbbs + hbbr) pe un VPS Linux (Ubuntu/Debian testat).
#
#   sudo ./install.sh remote.firma-mea.ro      # domeniu sau IP public al serverului
#
# La final afișează cheia publică pe care o pui în branding/brand.env (RS_PUB_KEY).
set -euo pipefail

cd "$(dirname "$0")"

if [[ $EUID -ne 0 ]]; then
  echo "Rulează cu sudo: sudo $0 <domeniu-sau-ip>" >&2
  exit 1
fi

HOST="${1:-}"
if [[ -z "$HOST" ]]; then
  if [[ -f .env ]] && grep -q '^SERVER_HOST=' .env; then
    HOST="$(sed -n 's/^SERVER_HOST=//p' .env)"
  else
    echo "Folosire: sudo $0 <domeniu-sau-ip-public>" >&2
    exit 1
  fi
fi
if [[ ! "$HOST" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Adresă invalidă: $HOST (fără http://, fără port)" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "==> Instalez Docker"
  curl -fsSL https://get.docker.com | sh
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Lipsește pluginul 'docker compose'. Instalează docker-compose-plugin și reîncearcă." >&2
  exit 1
fi

echo "SERVER_HOST=$HOST" > .env

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  echo "==> Deschid porturile în ufw"
  ufw allow 21115:21117/tcp
  ufw allow 21116/udp
  ufw allow 21118:21119/tcp
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

cat <<EOF

Server pornit pe $HOST.

Pune aceste valori în branding/brand.env:
  RENDEZVOUS_SERVER=$HOST
  RS_PUB_KEY=$(cat data/id_ed25519.pub)

IMPORTANT: fă backup la server/data/id_ed25519 (cheia privată). Dacă o pierzi,
toți clienții trebuie recompilați cu cheia nouă.
Dacă serverul e într-un cloud (AWS, Hetzner, Azure...), deschide și în firewall-ul
providerului porturile 21115-21119/tcp și 21116/udp.
EOF
