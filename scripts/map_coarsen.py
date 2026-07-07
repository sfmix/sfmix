#!/usr/bin/env python3
"""Tier 2: coarsen an EXACT mined path (network-map/atlas_precise/, gitignored)
into a committable, published-safe atlas file (network-map/atlas/).

This is the one-way privacy gate: Douglas-Peucker generalization + coordinate
rounding (map_kmz.coarsen) turns the exact NDA path into a "roughly this
corridor" shape. It is the ONLY sanctioned way to derive a committed geometry
from a mined one. Input coordinates never appear in the output at full fidelity.

    # coarsen every mined path into the committed atlas:
    scripts/map_coarsen.py

    # one circuit:
    scripts/map_coarsen.py --cid FID-2023-0409
"""
import argparse
import glob
import json
import os
import sys

import map_kmz as K

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRECISE_DIR = os.path.join(ROOT, "network-map", "atlas_precise")
ATLAS_DIR = os.path.join(ROOT, "portal", "mapbuild", "data", "atlas")


def coarsen_fc(precise_fc):
    """Return a new FeatureCollection with every feature's coordinates coarsened
    and the geometry tag downgraded exact-kmz -> approx-kmz."""
    c = precise_fc.get("circuit", {})
    out = {
        "type": "FeatureCollection",
        "circuit": {**c, "geometry": "approx-kmz"},
        "features": [],
    }
    for feat in precise_fc.get("features", []):
        pts = [(x[0], x[1]) for x in feat["geometry"]["coordinates"]]
        out["features"].append({
            "type": "Feature",
            "properties": feat.get("properties", {"seq": 0, "medium": "underground"}),
            "geometry": {"type": "LineString", "coordinates": K.coarsen(pts)},
        })
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cid", action="append", help="limit to these circuit id(s)")
    ap.add_argument("--precise-dir", default=PRECISE_DIR)
    ap.add_argument("--atlas-dir", default=ATLAS_DIR)
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.precise_dir, "*.geojson")))
    if not files:
        sys.exit("no precise paths in %s (run map_kmz_mine.py first)" % args.precise_dir)
    os.makedirs(args.atlas_dir, exist_ok=True)
    n = 0
    for f in files:
        fc = json.load(open(f))
        cid = fc.get("circuit", {}).get("circuit_id") or os.path.basename(f)[:-8]
        if args.cid and cid not in args.cid:
            continue
        coarse = coarsen_fc(fc)
        before = sum(len(ft["geometry"]["coordinates"]) for ft in fc["features"])
        after = sum(len(ft["geometry"]["coordinates"]) for ft in coarse["features"])
        # reuse the precise file's (already slash-sanitized) basename; the real
        # circuit_id (which may contain '/') stays intact inside the FeatureCollection
        out = os.path.join(args.atlas_dir, os.path.basename(f))
        json.dump(coarse, open(out, "w"), indent=2)
        print("COARSENED %-22s %d -> %d pts -> %s" % (cid, before, after, out))
        n += 1
    print("\n%d atlas file(s) written (committable)." % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
