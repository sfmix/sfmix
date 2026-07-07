#!/usr/bin/env python3
"""Fetch the committed DEM tile pyramid for hillshade/terrain.

Downloads Mapzen terrarium-encoded elevation PNGs (public, hosted by AWS Open
Data: https://registry.opendata.aws/terrain-tiles/) for the basemap BBOX at
z8-z10 into website/static/map/dem/{z}/{x}/{y}.png. ~150 small tiles; the map
serves them as a raster-dem source (256px tiles are fetched at map-zoom+1, and
the source overzooms past z10, so z10 is plenty for hillshade + gentle 3D).

    python3 network-map/basemap/fetch_dem.py
"""
import math
import os
import urllib.request

from fetch_basemap import BBOX

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir,
                                   "website", "static", "map", "dem"))
URL = "https://s3.amazonaws.com/elevation-tiles-prod/terrarium/{z}/{x}/{y}.png"
ZOOMS = (8, 9, 10)


def tile_range(z):
    n = 2 ** z

    def xt(lon):
        return int((lon + 180.0) / 360.0 * n)

    def yt(lat):
        r = math.radians(lat)
        return int((1.0 - math.asinh(math.tan(r)) / math.pi) / 2.0 * n)

    return (xt(BBOX[0]), xt(BBOX[2]), yt(BBOX[3]), yt(BBOX[1]))


def main():
    total = 0
    for z in ZOOMS:
        x0, x1, y0, y1 = tile_range(z)
        for x in range(x0, x1 + 1):
            for y in range(y0, y1 + 1):
                dest = os.path.join(OUT, str(z), str(x), "%d.png" % y)
                if os.path.exists(dest):
                    continue
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                urllib.request.urlretrieve(URL.format(z=z, x=x, y=y), dest)
                total += 1
        print("z%d: tiles x %d..%d y %d..%d" % (z, x0, x1, y0, y1))
    print("downloaded %d tiles -> %s" % (total, OUT))


if __name__ == "__main__":
    main()
