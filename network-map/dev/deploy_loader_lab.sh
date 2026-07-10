#!/usr/bin/env bash
# Publish the loading-screen concept lab to demo.sfmix.org/loader-lab/ (behind
# the existing "SFMIX Demo" basic-auth). The lab iframes the ALREADY-DEPLOYED
# demo map at /network-map/ — run deploy_demo.sh first if that isn't up.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HOST="${PORTAL_HOST:-portal.sfmix.org}"
DEST="/var/www/demo.sfmix.org/loader-lab"

ssh "$HOST" "test -f /var/www/demo.sfmix.org/network-map/index.html" ||
  { echo "demo map missing at /network-map/ — run deploy_demo.sh first" >&2; exit 1; }

ssh "$HOST" "mkdir -p $DEST"
rsync -a --delete "$HERE/loader-lab/" "$HOST:$DEST/"
# ensure the demo index links it (idempotent)
ssh "$HOST" 'f=/var/www/demo.sfmix.org/index.html; test -f "$f" && { grep -q "loader-lab/" "$f" ||
  sed -i "s#</body>#<br><a href=\"loader-lab/\">Network Map loader lab (loading-screen concepts)</a>\n</body>#" "$f"; } || true'
echo "done -> https://demo.sfmix.org/loader-lab/  (behind SFMIX Demo basic-auth)"
