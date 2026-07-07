#!/usr/bin/env bash
# Build the NetBox-sourced map and publish it to the password-protected demo at
# demo.sfmix.org/network-map/ (behind the existing "SFMIX Demo" basic-auth).
#
# One command for the off-box iteration loop: it builds the map straight from
# NetBox using the portal's self-contained builder (portal/mapbuild), adds a
# SYNTHETIC traffic overlay, assembles a self-contained bundle from
# website/static/ (NOT the stale Hugo public/ build — that mismatch caused a
# cable.segments crash), and rsyncs to the portal host.
#
#   NetBox creds: NETBOX_API_ENDPOINT/NETBOX_API_TOKEN or scripts/.env
#   Deps:         pip install pynetbox requests  (the builder's only runtime deps)
#   Override host: PORTAL_HOST=portal.sfmix.org (default)
#
# NOTE: this is the DEMO path (static snapshot + synthetic traffic). Production
# builds the same map in the portal on a schedule — see network-map/DEPLOY.md.
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

echo "[1/4] build map.json from NetBox (portal/mapbuild)"
PYTHONPATH="$REPO/portal" python3 - "$WORK/map.json" "$WORK/links.json" <<'PYEOF'
import sys
from mapbuild import builder
m, links, _drift = builder.build(generation_seed="demo")
builder.write_outputs(m, links, sys.argv[1], sys.argv[2])
print("  %d cables, %d sites, %d metros" % (len(m["cables"]), len(m["sites"]), len(m["metros"])))
PYEOF

echo "[2/4] synthetic traffic overlay"
python3 "$HERE/gen_synth_traffic.py" "$WORK/map.json" "$WORK/traffic.json"

echo "[3/4] assemble self-contained bundle from website/static/"
mkdir -p "$BUNDLE/css" "$BUNDLE/js" "$BUNDLE/vendor/maplibre-gl" "$BUNDLE/map"
cp "$HERE/demo_index.html"            "$BUNDLE/index.html"
cp "$STATIC/js/network-map.js"        "$BUNDLE/js/"
cp "$STATIC/css/network-map.css"      "$BUNDLE/css/"
cp "$STATIC/vendor/maplibre-gl/"*     "$BUNDLE/vendor/maplibre-gl/"
cp -r "$STATIC/map/." "$BUNDLE/map/"
cp "$WORK/map.json" "$WORK/traffic.json" "$BUNDLE/"

echo "[4/4] publish to $PORTAL:$DEST"
ssh "$PORTAL" "mkdir -p $DEST"
rsync -a --delete "$BUNDLE/" "$PORTAL:$DEST/"
# ensure the demo index links it (idempotent)
ssh "$PORTAL" 'f=/var/www/demo.sfmix.org/index.html; cp -n "$f" "$f.bak";
  grep -q "network-map/" "$f" || sed -i "s#</body>#<a href=\"network-map/\">Network Map (live NetBox build)</a>\n</body>#" "$f"'
echo "done -> https://demo.sfmix.org/network-map/  (behind SFMIX Demo basic-auth)"
