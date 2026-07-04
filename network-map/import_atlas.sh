#!/usr/bin/env bash
# Batch KMZ -> coarsened atlas importer. Run on a laptop where the NDA'd KMZs
# live; commit only the resulting network-map/atlas/*.geojson (coarsened, safe).
#
#   KMZ_DIR=~/Downloads/sfmix ./network-map/import_atlas.sh
#
# Each line: the provider KMZ (found by basename under KMZ_DIR), the placemark
# substring identifying the route, the A/Z site codes, and match tokens (the
# {…}/(…) tokens as they appear in the live interface descriptions). Paths are
# Douglas-Peucker + rounding coarsened by map_trace_path.py so the committed
# shape only approximates the corridor. Circuits with no usable KMZ (Hurricane
# HE #4757047 / HE#4490766, DRT #285322) are intentionally absent — the builder
# draws them as dashed auto-arcs until someone hand-draws them (see README).
set -euo pipefail
KMZ_DIR="${KMZ_DIR:-$HOME/Downloads/sfmix}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/atlas"
TRACE="$HERE/../scripts/map_trace_path.py"

find_kmz() { find "$KMZ_DIR" -name "$1" -print -quit; }

# id | kmz basename | placemark substr | a | z | match tokens (comma) | merge?
emit() {
  local id="$1" kmz="$2" pm="$3" a="$4" z="$5" match="$6" merge="${7:-}"
  local f; f="$(find_kmz "$kmz")"
  if [ -z "$f" ]; then echo "SKIP $id: KMZ '$kmz' not found under $KMZ_DIR" >&2; return; fi
  local args=(--circuit-id "$id" --a-site "$a" --z-site "$z" --match "$match" --snap --provider "BIG Fiber")
  if [ -n "$merge" ]; then args+=(--merge); else args+=(--placemark "$pm"); fi
  python3 "$TRACE" "$f" "${args[@]}" > "$OUT/$id.geojson"
  echo "OK   $id  ($a<->$z)"
}

# --- Zayo (single-route KMZs: merge all segments) ---
ZAYO_FBDK="$(find_kmz 'Service 576058*FBDK-1721530*.kmz')"
python3 "$TRACE" "$ZAYO_FBDK" --merge --circuit-id FBDK-1721530 --provider Zayo \
  --a-site fmt01 --z-site sjc01 --match 'FBDK/1721530//ZFS,FBDK-1721530' --snap > "$OUT/FBDK-1721530.geojson"; echo "OK   FBDK-1721530"
ZAYO_F22M="$(find_kmz 'Service 701967*FBDK-2172250*.kmz')"
python3 "$TRACE" "$ZAYO_F22M" --merge --circuit-id F22M-0204477 --provider Zayo \
  --a-site sfo01 --z-site sfo02 --match 'F22M-0204477' --snap > "$OUT/F22M-0204477.geojson"; echo "OK   F22M-0204477"

# --- Boldyn (single-route order KMZ: merge the 3 Fiber Path segments) ---
BOLDYN="$(find_kmz '*55 S Market To 2805 Lafayette.kmz')"
python3 "$TRACE" "$BOLDYN" --merge --circuit-id DF-231-4_sjc02-scl05 --provider Boldyn \
  --a-site sjc02 --z-site scl05 --match 'DF-231-4-1,DF-231-4-2,00000231-0000' --snap > "$OUT/DF-231-4_sjc02-scl05.geojson"; echo "OK   DF-231-4 (sjc02<->scl05)"

# --- BIG Fiber (named routes inside multi-route KMZs) ---
SVROUTES='Coresite to 2805 Lafayette - Final 3-27-25.kmz'
RING='BIG-SFMIX Proposed 6 Node Bay Ring and Single P2P_10112023.kmz'
QTS='BIG-SFMIX Proposed QTS 2807-OpenColo 3223 Single Custom Path_362025 (1).kmz'

emit FID-2023-0409 "$SVROUTES" "FID-2023-0409"                                 sfo02 fmt01 "FID-2023-0409"
emit FID-2025-0740 "$SVROUTES" "CoreSite SV4 2972 Stender Way-DRT SJC31 2805"  scl02 scl05 "FID-2025-0740"
emit FID-2025-0741 "$SVROUTES" "OpenColo 3223 Kenneth St.-DRT SJC31 2805"      scl04 scl05 "FID-2025-0741"
emit FID-2023-0407 "$SVROUTES" "FID-2023-0407"                                 fmt01 sjc01 "FID-2023-0407"
emit FID-2021-0106 "$RING"     "Equinix SV11 5GO Blvd.-Coresite SV4"           sjc01 scl02 "FID-2021-0106"
emit FID-2025-0762 "$QTS"      "QTS SC2"                                       scl01 scl04 "FID-2025-0762"

echo "done -> $OUT"
