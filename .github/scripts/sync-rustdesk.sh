#!/usr/bin/env bash
# Imports a RustDesk release into the `upstream-rustdesk` branch and prepares a
# `rustdesk-sync/<tag>` branch for a pull request into master.
#
#   sync-rustdesk.sh TAG SHA UPSTREAM_DIR REPORT_FILE
#
# UPSTREAM_DIR is a checkout of rustdesk/rustdesk at TAG with its submodules.
# `upstream-rustdesk` holds plain upstream trees, one commit per release, starting
# from the original import on master. Merging a sync branch into master is then an
# ordinary three-way merge against the previous release, so our changes are kept and
# only what RustDesk changed comes in. .github/ is never imported: our workflows
# differ from upstream's, and the workflow token may not push workflow files.
# Prints proposed=true|false to $GITHUB_OUTPUT (when set) and writes the PR body
# (Markdown) to REPORT_FILE.
set -euo pipefail

TAG="$1" SHA="$2" UP="$(cd "$3" && pwd)" REPORT="$4"
UPSTREAM_BRANCH=upstream-rustdesk
SYNC_BRANCH="rustdesk-sync/$TAG"
out() { [[ -n "${GITHUB_OUTPUT:-}" ]] && echo "$1" >> "$GITHUB_OUTPUT"; true; }
out proposed=false

if [[ ! "$TAG" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Unexpected upstream tag: $TAG" >&2
  exit 1
fi

if git ls-remote --exit-code --heads origin "$UPSTREAM_BRANCH" >/dev/null; then
  git fetch -q origin "$UPSTREAM_BRANCH"
  BASE="$(git rev-parse FETCH_HEAD)"
else
  BASE="$(git log --format=%H --grep='^Import RustDesk ' --reverse origin/master | head -n 1)"
fi
LAST="$(git log -1 --format=%s "$BASE" | sed -n 's/^Import RustDesk \([0-9.]*\).*/\1/p')"
if [[ -z "$LAST" ]]; then
  echo "Cannot find the previous RustDesk import (commit 'Import RustDesk <version> ...')" >&2
  exit 1
fi
if [[ "$(printf '%s\n%s\n' "$LAST" "$TAG" | sort -V | tail -n 1)" == "$LAST" ]]; then
  echo "Already at RustDesk $LAST (latest release: $TAG); nothing to do."
  exit 0
fi
if git ls-remote --exit-code --heads origin "$SYNC_BRANCH" >/dev/null; then
  echo "RustDesk $TAG was already proposed on branch $SYNC_BRANCH."
  exit 0
fi
echo "Importing RustDesk $TAG (previous import: $LAST)"

WT="$(mktemp -d)"
trap 'git worktree remove --force "$WT" >/dev/null 2>&1 || true' EXIT
git worktree add -q --detach "$WT" "$BASE"
(
  cd "$WT"
  find . -mindepth 1 -maxdepth 1 ! -name .git ! -name .github -exec rm -rf {} +
  tar -C "$UP" --exclude=.git --exclude=./.github --exclude=./.gitmodules -cf - . | tar -xf -
  git add -A
  git commit -q -m "Import RustDesk $TAG (upstream $SHA)"
)
NEW="$(git -C "$WT" rev-parse HEAD)"
git branch -f "$UPSTREAM_BRANCH" "$NEW"
git branch -f "$SYNC_BRANCH" "$NEW"

# Trial merge into master, never pushed: tells the reviewer what to expect.
git -C "$WT" checkout -q --detach origin/master
if git -C "$WT" merge -q --no-ff --no-edit "$NEW" >/dev/null 2>&1; then
  CONFLICTS=""
else
  CONFLICTS="$(git -C "$WT" diff --name-only --diff-filter=U)"
  git -C "$WT" merge --abort
fi
if [[ -n "$CONFLICTS" ]]; then
  BRANDING="Branding-ul se verifică după rezolvarea conflictelor (se reaplică automat după merge)."
elif grep -q '=CHANGE_ME' "$WT/branding/brand.env"; then
  BRANDING="Branding-ul nu e configurat încă (CHANGE_ME în branding/brand.env); nu l-am verificat."
else
  if LOG="$(cd "$WT" && python3 branding/apply.py 2>&1)"; then
    BRANDING="Branding-ul se aplică fără erori peste versiunea nouă (se reaplică automat după merge)."
  else
    BRANDING="**Branding-ul NU se mai aplică** peste versiunea nouă; trebuie adaptat branding/apply.py:"$'\n```\n'"$LOG"$'\n```'
  fi
fi
WORKFLOWS="$(gh api "repos/rustdesk/rustdesk/compare/$LAST...$TAG" --jq '.files[].filename' 2>/dev/null \
  | grep '^\.github/' || true)"

{
  echo "Versiune nouă RustDesk: **$TAG** (până acum: $LAST)."
  echo
  echo "- Note de lansare: https://github.com/rustdesk/rustdesk/releases/tag/$TAG"
  echo "- Toate modificările RustDesk: https://github.com/rustdesk/rustdesk/compare/$LAST...$TAG"
  echo
  if [[ -z "$CONFLICTS" ]]; then
    echo "**Se îmbină fără conflicte** cu modificările RDN (branding, licențe, server)."
  else
    echo "**Conflicte** între modificările RustDesk și cele RDN, de rezolvat înainte de merge:"
    echo
    sed 's/^/- `/; s/$/`/' <<< "$CONFLICTS"
  fi
  echo
  echo "$BRANDING"
  if [[ -n "$WORKFLOWS" ]]; then
    echo
    echo "RustDesk a modificat și fișiere de compilare din \`.github/\`. Acestea nu se preiau automat"
    echo "(sunt personalizate pentru RDN Remote); verifică dacă trebuie portate:"
    echo
    sed 's/^/- `/; s/$/`/' <<< "$WORKFLOWS"
  fi
  echo
  echo "După merge: Actions → **Publish new version** construiește și publică versiunea pentru clienți."
} > "$REPORT"
out proposed=true
out "conflicts=$([[ -n "$CONFLICTS" ]] && echo true || echo false)"
