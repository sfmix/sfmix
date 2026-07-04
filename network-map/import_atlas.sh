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

# --- Boldyn: fiber rides BART rights-of-way. Two kinds of source: ---
# (a) a dedicated single-order KMZ (merge its Fiber Path segments); this one is
#     the 55 S Market<->2805 Lafayette order (sjc02<->scl05). Match by the order
#     number only (NOT the DF-231-4 tokens, which are the fmt01<->sjc02 link).
BOLDYN_ORDER="$(find_kmz '*55 S Market To 2805 Lafayette.kmz')"
python3 "$TRACE" "$BOLDYN_ORDER" --merge --circuit-id Boldyn-00000231-0000 --provider Boldyn \
  --a-site sjc02 --z-site scl05 --match '00000231-0000' --snap > "$OUT/Boldyn-00000231-0000.geojson"
echo "OK   Boldyn 00000231-0000 (sjc02<->scl05)"
# (b) the customer-facing BART-network KMZ, chained via graph routing between
#     datacenters. DF-231-4 is the fmt01<->sjc02 core link.
BOLDYN_NET="$(find_kmz 'Customer Facing Boldyn Fiber Network 11.13.25.kmz')"
ROUTE="$HERE/../scripts/map_boldyn_route.py"
python3 "$ROUTE" "$BOLDYN_NET" --a-site fmt01 --z-site sjc02 \
  --circuit-id DF-231-4 --match 'DF-231-4-1,DF-231-4-2' > "$OUT/DF-231-4.geojson"
echo "OK   DF-231-4 (fmt01<->sjc02, BART-routed)"
rm -f "$OUT/DF-231-4_sjc02-scl05.geojson"  # superseded by the two entries above

# Santa Clara intra-metro hops via the Boldyn DC ring callouts. The CoreSite /
# OpenColo / DRT cluster is one loop; a larger --stitch joins its ring fragments.
python3 "$ROUTE" "$BOLDYN_NET" --a-site scl02 --z-site scl04 --stitch 300 \
  --provider "BIG Fiber" --circuit-id FID-2023-0408 --match 'FID-2023-0408' > "$OUT/FID-2023-0408.geojson"
echo "OK   FID-2023-0408 (scl02<->scl04, ring-routed)"
# scl01 (QTS, Mission College) is NOT on the Boldyn ring, so QTS<->CoreSite is the
# real corridor QTS<->OpenColo (FID-2025-0762) chained with OpenColo<->CoreSite
# (the ring hop above), joined at OpenColo (scl04).
python3 - "$OUT" <<'PY'
import json, sys, math
OUT = sys.argv[1]
def load(p):
    d = json.load(open(f"{OUT}/{p}"))
    return [c for f in d["features"] for c in f["geometry"]["coordinates"]]
qo = load("FID-2025-0762.geojson")   # scl01(QTS) <-> scl04(OpenColo)
oc = load("FID-2023-0408.geojson")   # scl02(CoreSite) <-> scl04(OpenColo)
def d(a, b): return math.hypot(a[0]-b[0], a[1]-b[1])
# orient qo as scl01 -> scl04 (join end near oc's scl04 end), oc as scl04 -> scl02
join = oc[-1] if d(oc[-1], qo[-1]) < d(oc[0], qo[-1]) else oc[0]
if d(qo[0], join) < d(qo[-1], join): qo = qo[::-1]      # end qo at the join (scl04)
if d(oc[0], qo[-1]) > d(oc[-1], qo[-1]): oc = oc[::-1]   # start oc at the join
coords = qo + [c for c in oc if c != qo[-1]]
fc = {"type": "FeatureCollection",
      "circuit": {"circuit_id": "FID-2025-0763", "provider": "BIG Fiber",
                  "a_site": "scl01", "z_site": "scl02", "status": "active",
                  "geometry": "chained", "match": ["FID-2025-0763"]},
      "features": [{"type": "Feature", "properties": {"seq": 0, "medium": "underground"},
                    "geometry": {"type": "LineString", "coordinates": coords}}]}
json.dump(fc, open(f"{OUT}/FID-2025-0763.geojson", "w"), indent=2)
print("OK   FID-2025-0763 (scl01<->scl02, chained QTS->OpenColo->CoreSite: %d pts)" % len(coords))
PY

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
# sfo02<->scl02: the SF<->Santa-Clara CoreSite long-haul. The "Proposed
# Replacement" route (200 Paul -> CoreSite SV7 3020 Coronado) is the real
# corridor; --snap ties its ends to sfo02/scl02 (SV7 and SV4 are ~500m apart on
# the same CoreSite campus).
emit FID-2025-0742 "$SVROUTES" "Proposed Replacement"                          sfo02 scl02 "FID-2025-0742"

echo "done -> $OUT"
