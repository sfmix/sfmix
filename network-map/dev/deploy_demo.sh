#!/usr/bin/env bash
# Build the NetBox-sourced map and publish it to the password-protected demo at
# demo.sfmix.org/network-map/ (behind the existing "SFMIX Demo" basic-auth).
#
# One command for the off-box iteration loop: it generates live fixtures from
# device eAPI-LLDP + NetBox (since sflow-rt/Prometheus aren't reachable here),
# builds --source=netbox, adds a SYNTHETIC traffic overlay, assembles a
# self-contained bundle from website/static/ (NOT the stale Hugo public/ build —
# that mismatch caused a cable.segments crash), and rsyncs to the portal host.
#
#   NetBox creds: NETBOX_API_ENDPOINT/NETBOX_API_TOKEN or scripts/.env
#   Device eAPI:  ~/.netrc entry for machine sfmix.org
#   Override host: PORTAL_HOST=portal.sfmix.org (default)
#
# NOTE: this is the DEMO path (static snapshot + synthetic traffic). Production is
# different — see network-map/DEPLOY.md (builder on metrics.sfo02 -> portal).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
STATIC="$REPO/website/static"
SCRIPTS="$REPO/scripts"
PORTAL="${PORTAL_HOST:-portal.sfmix.org}"
DEST="/var/www/demo.sfmix.org/network-map"
WORK="$(mktemp -d)"; BUNDLE="$WORK/bundle"
trap 'rm -rf "$WORK"' EXIT

# Locate scripts/.env — it's gitignored, so in a worktree it lives in the MAIN
# checkout (derive that from the shared git dir). Skip if creds already exported.
if [ -z "${NETBOX_API_ENDPOINT:-}" ]; then
  ENV_FILE="$SCRIPTS/.env"
  if [ ! -f "$ENV_FILE" ]; then
    MAIN="$(dirname "$(git -C "$REPO" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo /nonexistent/x)")"
    [ -f "$MAIN/scripts/.env" ] && ENV_FILE="$MAIN/scripts/.env"
  fi
  [ -f "$ENV_FILE" ] && export $(grep -vE '^#' "$ENV_FILE" | sed 's/ *= */=/' | xargs)
fi
: "${NETBOX_API_ENDPOINT:?set NETBOX_API_ENDPOINT (env or scripts/.env)}"
: "${NETBOX_API_TOKEN:?set NETBOX_API_TOKEN (env or scripts/.env)}"
export PYTHONWARNINGS=ignore

echo "[1/5] live fixtures (eAPI-LLDP topology + NetBox sites)"
python3 "$HERE/gen_live_fixtures.py" "$WORK"

echo "[2/5] build map.json (--source=netbox)"
echo '{}' > "$WORK/empty_eapi.json"
python3 "$SCRIPTS/gen_map_structure.py" \
  --topology-fixture "$WORK/topo_live.json" --sites-fixture "$WORK/sites_live.json" \
  --eapi-fixture "$WORK/empty_eapi.json" \
  --out "$WORK/map.json" --links-out "$WORK/links.json" --generation-seed demo

echo "[3/5] synthetic traffic overlay"
python3 "$HERE/gen_synth_traffic.py" "$WORK/map.json" "$WORK/traffic.json"

echo "[4/5] assemble self-contained bundle from website/static/"
mkdir -p "$BUNDLE/css" "$BUNDLE/js" "$BUNDLE/vendor/maplibre-gl" "$BUNDLE/map"
cp "$HERE/demo_index.html"            "$BUNDLE/index.html"
cp "$STATIC/js/network-map.js"        "$BUNDLE/js/"
cp "$STATIC/css/network-map.css"      "$BUNDLE/css/"
cp "$STATIC/vendor/maplibre-gl/"*     "$BUNDLE/vendor/maplibre-gl/"
cp -r "$STATIC/map/." "$BUNDLE/map/"
cp "$WORK/map.json" "$WORK/traffic.json" "$BUNDLE/"

echo "[5/5] publish to $PORTAL:$DEST"
ssh "$PORTAL" "mkdir -p $DEST"
rsync -a --delete "$BUNDLE/" "$PORTAL:$DEST/"
# ensure the demo index links it (idempotent)
ssh "$PORTAL" 'f=/var/www/demo.sfmix.org/index.html; cp -n "$f" "$f.bak";
  grep -q "network-map/" "$f" || sed -i "s#</body>#<a href=\"network-map/\">Network Map (live NetBox build)</a>\n</body>#" "$f"'
echo "done -> https://demo.sfmix.org/network-map/  (behind SFMIX Demo basic-auth)"
