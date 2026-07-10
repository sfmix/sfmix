#!/usr/bin/env python3
"""Quantize the committed terrarium DEM tiles to whole-meter precision.

Raw Mapzen terrarium tiles spend a full PNG channel (B) on 1/256-meter
elevation fractions — visually meaningless noise at this map's gentle
1.3x exaggeration, but it roughly doubles the PNG size. Zeroing the B
channel (and optionally coarsening the meter channel) makes the tiles
compress to about half the bytes, and DEM tiles are ~80% of the map's
initial network payload.

Idempotent: re-running on already-quantized tiles is a no-op. Run after
fetch_dem.py whenever the pyramid is refreshed:

    python3 network-map/basemap/fetch_dem.py
    python3 network-map/basemap/quantize_dem.py [--step METERS]

Requires Pillow.
"""
import argparse
import os

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
DEM = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir,
                                   "website", "static", "map", "dem"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--step", type=int, default=1,
                    help="elevation quantum in meters (default 1 = just drop "
                         "the fractional-meter channel)")
    args = ap.parse_args()
    before = after = n = 0
    for root, _, files in os.walk(DEM):
        for f in sorted(files):
            if not f.endswith(".png"):
                continue
            p = os.path.join(root, f)
            before += os.path.getsize(p)
            im = Image.open(p).convert("RGB")
            r, g, b = im.split()
            b = b.point(lambda _: 0)
            if args.step > 1:
                g = g.point(lambda v: (v // args.step) * args.step)
            Image.merge("RGB", (r, g, b)).save(p, "PNG", optimize=True)
            after += os.path.getsize(p)
            n += 1
    print("%d tiles: %.1fMB -> %.1fMB (%.0f%%)" %
          (n, before / 1e6, after / 1e6, 100.0 * after / before))


if __name__ == "__main__":
    main()
