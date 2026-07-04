#!/usr/bin/env python3
"""Regenerate the committed all-vector basemap (water / land / roads).

Run on a laptop with internet + GDAL (ogr2ogr). Writes into
website/static/map/basemap-{water,land,roads}.json. See basemap/README.md.

    python3 network-map/basemap/fetch_basemap.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile

BBOX = [-122.75, 37.15, -121.6, 38.05]  # minlon, minlat, maxlon, maxlat
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir, "website", "static", "map"))
# Full-resolution assembled coastline->water polygons (~900 MB) — gives a smooth,
# detailed shoreline. The "simplified-" variant is too jagged for close zoom.
WATER_ZIP = "https://osmdata.openstreetmap.de/download/water-polygons-split-3857.zip"
# overpass-api.de rate-limits/406s aggressively; try mirrors in order.
OVERPASS_ENDPOINTS = [
    "https://overpass.private.coffee/api/interpreter",
    "https://overpass-api.de/api/interpreter",
    "https://overpass.osm.jp/api/interpreter",
]


def _round(coords, nd=5):
    if isinstance(coords[0], (int, float)):
        return [round(coords[0], nd), round(coords[1], nd)]
    return [_round(c, nd) for c in coords]


def build_land():
    x0, y0, x1, y1 = BBOX
    rect = [[x0, y0], [x1, y0], [x1, y1], [x0, y1], [x0, y0]]
    fc = {"type": "FeatureCollection", "features": [
        {"type": "Feature", "properties": {}, "geometry": {"type": "Polygon", "coordinates": [rect]}}]}
    with open(os.path.join(OUT, "basemap-land.json"), "w") as fh:
        json.dump(fc, fh)
    print("wrote basemap-land.json")


def build_water(tmp):
    zp = os.path.join(tmp, "water.zip")
    print("downloading water polygons (~24 MB)…")
    urllib.request.urlretrieve(WATER_ZIP, zp)
    with zipfile.ZipFile(zp) as z:
        z.extractall(tmp)
    shp = None
    for root, _, files in os.walk(tmp):
        for f in files:
            if f.endswith(".shp"):
                shp = os.path.join(root, f)
    if not shp:
        sys.exit("no .shp found in water zip")
    # Clip first (fast), THEN simplify the small result — simplifying the 900 MB
    # source directly is far too slow.
    clipped = os.path.join(tmp, "water_clip.json")
    subprocess.run(["ogr2ogr", "-f", "GeoJSON", "-t_srs", "EPSG:4326",
                    "-clipdst", str(BBOX[0]), str(BBOX[1]), str(BBOX[2]), str(BBOX[3]),
                    clipped, shp], check=True)
    simp = os.path.join(tmp, "water.json")
    subprocess.run(["ogr2ogr", "-f", "GeoJSON", "-simplify", "0.00003", simp, clipped], check=True)
    d = json.load(open(simp))
    for feat in d["features"]:
        feat["geometry"]["coordinates"] = _round(feat["geometry"]["coordinates"])
        feat["properties"] = {}
    with open(os.path.join(OUT, "basemap-water.json"), "w") as fh:
        json.dump(d, fh)
    print("wrote basemap-water.json (%d features)" % len(d["features"]))


def _overpass(q):
    data = urllib.parse.urlencode({"data": q}).encode()
    last = None
    for ep in OVERPASS_ENDPOINTS:
        try:
            return json.load(urllib.request.urlopen(urllib.request.Request(ep, data=data), timeout=180))
        except Exception as e:  # 406/timeout/etc — try the next mirror
            last = e
            print("  overpass %s failed (%s), trying next…" % (ep, e))
    raise last


def build_roads(tmp):
    # All freeways (motorway) + major state-route trunks, so bridges (I-80 Bay
    # Bridge, I-580 Richmond, CA-92 San Mateo, CA-84 Dumbarton) all appear.
    q = ('[out:json][timeout:120];('
         'way["highway"="motorway"](%f,%f,%f,%f);'
         'way["highway"="trunk"](%f,%f,%f,%f););out geom;'
         % (BBOX[1], BBOX[0], BBOX[3], BBOX[2], BBOX[1], BBOX[0], BBOX[3], BBOX[2]))
    print("querying Overpass for freeways…")
    raw = _overpass(q)
    feats = []
    for e in raw.get("elements", []):
        if e.get("type") != "way" or "geometry" not in e:
            continue
        coords = [[p["lon"], p["lat"]] for p in e["geometry"]]
        if len(coords) < 2:
            continue
        tags = e.get("tags", {})
        ref = (tags.get("ref", "") or "").split(";")[0].strip()
        cls = "motorway" if tags.get("highway") == "motorway" else "trunk"
        # keep all motorways; for trunk keep only interstate/US/state routes
        if cls == "trunk" and not re.match(r"^(I|US|CA)\s", ref):
            continue
        feats.append({"type": "Feature",
                      "properties": {"ref": ref, "class": cls},
                      "geometry": {"type": "LineString", "coordinates": coords}})
    src = os.path.join(tmp, "roads_raw.json")
    json.dump({"type": "FeatureCollection", "features": feats}, open(src, "w"))
    simp = os.path.join(tmp, "roads.json")
    subprocess.run(["ogr2ogr", "-f", "GeoJSON", "-simplify", "0.00015", simp, src], check=True)
    d = json.load(open(simp))
    out = []
    for feat in d["features"]:
        g = feat["geometry"]
        if g["type"] != "LineString" or len(g["coordinates"]) < 2:
            continue
        g["coordinates"] = _round(g["coordinates"])
        out.append({"type": "Feature",
                    "properties": {"ref": feat["properties"].get("ref", ""),
                                   "class": feat["properties"].get("class", "trunk")},
                    "geometry": g})
    with open(os.path.join(OUT, "basemap-roads.json"), "w") as fh:
        json.dump({"type": "FeatureCollection", "features": out}, fh)
    print("wrote basemap-roads.json (%d segments)" % len(out))


def main():
    os.makedirs(OUT, exist_ok=True)
    build_land()
    with tempfile.TemporaryDirectory() as tmp:
        build_water(tmp)
        build_roads(tmp)


if __name__ == "__main__":
    main()
