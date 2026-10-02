#!/usr/bin/env bash
# Restaurare completă din backup: cheia serverului, ID-urile înregistrate, licențele,
# istoricul, IP-urile blocate și server/.env.
#
#   sudo ./restore.sh /cale/rdn-backup-AAAALLZZ-HHMMSS-....tar.gz
#
# Pe un calculator nou: clonează repo-ul, rulează întâi install.sh (instalează Docker și
# pornește serverul), apoi restore.sh cu backup-ul. Înainte de restaurare se face automat
# un backup al stării curente în data/backups/.
set -euo pipefail

cd "$(dirname "$0")"
if [[ $EUID -ne 0 ]]; then
  echo "Rulează cu sudo: sudo $0 <backup.tar.gz>" >&2
  exit 1
fi
if [[ $# -ne 1 || ! -f "$1" ]]; then
  echo "Folosire: sudo $0 <backup.tar.gz>" >&2
  exit 1
fi
ARCHIVE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
command -v docker >/dev/null 2>&1 || { echo "Docker lipsește: rulează întâi sudo ./install.sh <domeniu>" >&2; exit 1; }

py() {
  docker run --rm -v "$PWD/panel:/app:ro,z" -v "$PWD/data:/data:z" -v "$PWD:/server:z" \
    -v "$ARCHIVE:/backup.tar.gz:ro,z" python:3.12-alpine python /app/backup.py "$@"
}

mkdir -p data
if [[ -s data/id_ed25519 ]]; then
  echo "==> Backup al stării curente (pentru siguranță)"
  py create --data /data --env /server/.env --out /data/backups --label inainte-de-restaurare
fi

echo "==> Opresc serverul"
docker compose stop >/dev/null 2>&1 || true

echo "==> Restaurez"
py restore /backup.tar.gz --data /data --env /server/.env

echo "==> Pornesc serverul"
docker compose up -d
echo
echo "Gata. Cheia publică a serverului: $(cat data/id_ed25519.pub)"
echo "Trebuie să fie aceeași cu RS_PUB_KEY din branding/brand.env, altfel aplicațiile nu se mai conectează."
