#!/usr/bin/env bash
# Actualizare automată (rulată zilnic de rdn-update.timer, instalat de install.sh):
#   1. aduce pe pagina de descărcare ultimul release finalizat de pe GitHub și anunță
#      versiunea clienților (panoul răspunde la /version/latest);
#   2. aduce serverul (panou, site, configurație) la același release, dacă s-a schimbat.
# Serverul urmează doar release-urile finalizate, niciodată modificările nepublicate din master,
# și nu coboară niciodată la un release mai vechi decât codul pe care îl are.
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
# Doar înainte: un release mai vechi decât codul de pe server (de ex. după un `git pull` pe
# master) nu readuce site-ul și panoul la o versiune anterioară.
if git_ merge-base --is-ancestor "$TARGET" "$CURRENT"; then
  echo "Serverul rulează cod mai nou decât $TAG; rămâne cum este."
  exit 0
fi
if ! git_ merge-base --is-ancestor "$CURRENT" "$TARGET"; then
  echo "$TAG nu continuă codul de pe server (${CURRENT:0:12}); nu schimb nimic. Verifică manual cu git log." >&2
  exit 0
fi
if ! git_ diff --quiet || ! git_ diff --cached --quiet; then
  echo "Există modificări locale în $REPO_DIR; actualizarea serverului e oprită ca să nu le pierd." >&2
  echo "Fă modificările în GitHub (de ex. server/web/site.json), nu direct pe server." >&2
  git_ status --short >&2
  exit 1
fi

if ! healthy; then
  echo "Atenție: serverul nu răspundea corect nici înainte de actualizare." >&2
fi
echo "Actualizez serverul de la ${CURRENT:0:12} la $TAG"
git_ checkout --quiet --detach "$TARGET"
if apply && wait_healthy; then
  echo "Server actualizat la $TAG."
  exit 0
fi
# Nu lăsa site-ul, panoul sau serverul RustDesk căzute: revino la codul de dinainte.
echo "După actualizarea la $TAG serverul nu răspunde corect; revin la ${CURRENT:0:12}." >&2
git_ checkout --quiet --detach "$CURRENT"
if apply && wait_healthy; then
  echo "Revenit la ${CURRENT:0:12}; actualizarea la $TAG trebuie verificată (journalctl -u rdn-update)." >&2
else
  echo "Nici după revenire serverul nu răspunde corect; verifică: docker compose ps, docker compose logs --tail=50" >&2
fi
exit 1
}

# Aduce containerele la codul din repo. Caddy își reîncarcă configurația fără să se oprească
# (o configurație greșită e refuzată și rămâne cea veche); panoul repornește în ~1 secundă.
apply() {
  docker compose pull --quiet --ignore-buildable || true
  docker compose up -d --build --remove-orphans
  docker compose restart panel >/dev/null
  if docker ps --format '{{.Names}}' | grep -qx rustdesk-web; then
    docker compose exec -T web caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
      || docker compose restart web >/dev/null
  fi
}

# 0 când rulează serverul RustDesk (hbbs, hbbr), panoul răspunde și, dacă e pornit, și site-ul.
healthy() {
  local ok=0 name web
  for name in hbbs hbbr rustdesk-panel; do
    if [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != true ]]; then
      echo "  $name nu rulează" >&2
      ok=1
    fi
  done
  curl -fsS -o /dev/null --max-time 10 http://127.0.0.1:21120/ 2>/dev/null || { echo "  panoul nu răspunde" >&2; ok=1; }
  if grep -qx 'COMPOSE_PROFILES=web' .env 2>/dev/null; then
    web="$(sed -n 's/^WEB_ADDRESS=//p' .env | tail -n 1)"
    if [[ -z "$web" || "$web" == :* ]]; then
      curl -fsS -o /dev/null --max-time 15 "http://127.0.0.1${web:-:80}/" 2>/dev/null || { echo "  site-ul nu răspunde" >&2; ok=1; }
    else
      curl -fsS -o /dev/null --max-time 15 --resolve "$web:443:127.0.0.1" "https://$web/" 2>/dev/null \
        || { echo "  site-ul https://$web/ nu răspunde" >&2; ok=1; }
    fi
  fi
  return $ok
}

wait_healthy() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if healthy 2>/dev/null; then
      return 0
    fi
    sleep 5
  done
  healthy
}

main "$@"
