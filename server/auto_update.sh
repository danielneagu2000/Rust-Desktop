#!/usr/bin/env bash
# Actualizare automată (rulată zilnic de rdn-update.timer, instalat de install.sh):
#   1. aduce pe pagina de descărcare ultimul release finalizat de pe GitHub și anunță
#      versiunea clienților (panoul răspunde la /version/latest);
#   2. aduce serverul (panou, site, configurație) la același release, dacă s-a schimbat.
# Serverul urmează doar release-urile finalizate, niciodată modificările nepublicate din master.
#
# Manual:  sudo systemctl start rdn-update    Jurnal:  journalctl -u rdn-update
set -euo pipefail

# Tot corpul e într-o funcție: bash citește scriptul din mers, iar git checkout îl poate
# înlocui chiar în timpul rulării.
main() {

SERVER_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SERVER_DIR")"
cd "$SERVER_DIR"
git_() { git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" "$@"; }

HOST="$(sed -n 's/^SERVER_HOST=//p' .env 2>/dev/null | tail -n 1)"
docker run --rm -e SERVER_HOST="$HOST" \
  -v "$SERVER_DIR/web:/w:z" -v "$SERVER_DIR/data:/data:z" \
  python:3.12-alpine python /w/update_downloads.py

TAG="$(sed -n 's/.*"tag": *"\([^"]*\)".*/\1/p' data/latest.json 2>/dev/null || true)"
if [[ -z "$TAG" ]]; then
  echo "Niciun release finalizat încă; serverul rămâne la versiunea curentă."
  exit 0
fi
if [[ ! "$TAG" =~ ^[0-9A-Za-z._-]+$ ]]; then
  echo "Etichetă invalidă în data/latest.json: $TAG" >&2
  exit 1
fi

git_ fetch --quiet --tags origin
TARGET="$(git_ rev-parse "refs/tags/$TAG^{commit}")"
CURRENT="$(git_ rev-parse HEAD)"
if [[ "$TARGET" == "$CURRENT" ]]; then
  echo "Serverul este deja la $TAG."
  exit 0
fi
if ! git_ diff --quiet || ! git_ diff --cached --quiet; then
  echo "Există modificări locale în $REPO_DIR; actualizarea serverului e oprită ca să nu le pierd." >&2
  echo "Fă modificările în GitHub (de ex. server/web/site.json), nu direct pe server." >&2
  git_ status --short >&2
  exit 1
fi

echo "Actualizez serverul de la ${CURRENT:0:12} la $TAG"
git_ checkout --quiet --detach "$TARGET"
docker compose pull --quiet --ignore-buildable
docker compose up -d --build --remove-orphans
# panel.py, pagina web și Caddyfile sunt montate din repo; le reîncarc explicit.
docker compose restart panel >/dev/null
if docker ps --format '{{.Names}}' | grep -qx rustdesk-web; then
  docker compose restart web >/dev/null
fi
echo "Server actualizat la $TAG."
}

main "$@"
