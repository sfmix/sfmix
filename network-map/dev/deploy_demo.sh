#!/usr/bin/env bash
# Publish the network-map FRONTEND to the password-protected demo at
# demo.sfmix.org/network-map/ (behind the existing "SFMIX Demo" basic-auth),
# pointed at the LIVE portal data endpoints. This is a faithful end-to-end
# preview of what the public site will show: the real frontend + committed
# basemap served privately, fetching the live NetBox-built map.json + live
# traffic from portal.sfmix.org (both CORS-enabled). No local build — the portal
# (mapbuild + Django-Q2) is the source of truth. See network-map/DEPLOY.md.
#
#   Override host: PORTAL_HOST=portal.sfmix.org (default)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
STATIC="$REPO/website/static"
PORTAL="${PORTAL_HOST:-portal.sfmix.org}"
DEST="/var/www/demo.sfmix.org/network-map"
WORK="$(mktemp -d)"; BUNDLE="$WORK/bundle"
trap 'rm -rf "$WORK"' EXIT

echo "[1/2] assemble frontend bundle from website/static/ (data is fetched live from the portal)"
mkdir -p "$BUNDLE/css" "$BUNDLE/js" "$BUNDLE/vendor/maplibre-gl" "$BUNDLE/map"
cp "$HERE/demo_index.html"            "$BUNDLE/index.html"
cp "$STATIC/js/network-map.js"        "$BUNDLE/js/"
cp "$STATIC/css/network-map.css"      "$BUNDLE/css/"
cp "$STATIC/vendor/maplibre-gl/"*     "$BUNDLE/vendor/maplibre-gl/"
cp -r "$STATIC/map/." "$BUNDLE/map/"

echo "[2/2] publish to $PORTAL:$DEST"
ssh "$PORTAL" "mkdir -p $DEST"
rsync -a --delete "$BUNDLE/" "$PORTAL:$DEST/"
# ensure the demo index links it (idempotent)
ssh "$PORTAL" 'f=/var/www/demo.sfmix.org/index.html; cp -n "$f" "$f.bak";
  grep -q "network-map/" "$f" || sed -i "s#</body>#<a href=\"network-map/\">Network Map (live NetBox build)</a>\n</body>#" "$f"'
echo "done -> https://demo.sfmix.org/network-map/  (behind SFMIX Demo basic-auth)"
