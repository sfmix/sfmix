#!/usr/bin/env python3
"""Fetch rail + pipeline rights-of-way for BUILD-TIME infra routing.

Fibre follows these corridors (rail especially — Caltrain/UP/BART), so
gen_map_structure.infra_route routes KMZ-less links over them together with the
basemap highways. This is a routing INPUT only — it is NOT served to the frontend
or drawn on the map (it lives here in network-map/basemap/, not website/static/map/).
Committed (public OSM). Run on a laptop with internet + GDAL (ogr2ogr):

    python3 network-map/basemap/fetch_rights_of_way.py
"""
import json
import os
import subprocess
import tempfile
import urllib.parse
import urllib.request

BBOX = [-122.75, 37.15, -121.6, 38.05]  # minlon, minlat, maxlon, maxlat (Bay Area)
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir, "portal", "mapbuild", "data", "rights-of-way.json"))
OVERPASS_ENDPOINTS = [
    "https://maps.mail.ru/osm/tools/overpass/api/interpreter",
    "https://overpass.private.coffee/api/interpreter",
    "https://overpass-api.de/api/interpreter",
]


def _round(coords, nd=5):
    if isinstance(coords[0], (int, float)):
        return [round(coords[0], nd), round(coords[1], nd)]
    return [_round(c, nd) for c in coords]


def _overpass(q):
    data = urllib.parse.urlencode({"data": q}).encode()
    last = None
    for ep in OVERPASS_ENDPOINTS:
        try:
            return json.load(urllib.request.urlopen(urllib.request.Request(ep, data=data), timeout=180))
        except Exception as e:
            last = e
            print("  overpass %s failed (%s), trying next…" % (ep, e))
    raise last


def main():
    b = BBOX
    q = ('[out:json][timeout:180];('
         'way["railway"~"^(rail|light_rail|subway|narrow_gauge)$"]["service"!~"."](%f,%f,%f,%f);'
         'way["man_made"="pipeline"](%f,%f,%f,%f););out geom;'
         % (b[1], b[0], b[3], b[2], b[1], b[0], b[3], b[2]))
    print("querying Overpass for rail + pipeline rights-of-way…")
    raw = _overpass(q)
    feats = []
    for e in raw.get("elements", []):
        if e.get("type") != "way" or "geometry" not in e:
            continue
        coords = [[p["lon"], p["lat"]] for p in e["geometry"]]
        if len(coords) < 2:
            continue
        cls = "pipeline" if e.get("tags", {}).get("man_made") == "pipeline" else "railway"
        feats.append({"type": "Feature", "properties": {"class": cls},
                      "geometry": {"type": "LineString", "coordinates": coords}})
    print("fetched %d raw segments" % len(feats))
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "row.json")
        json.dump({"type": "FeatureCollection", "features": feats}, open(src, "w"))
        simp = os.path.join(tmp, "row_s.json")
        subprocess.run(["ogr2ogr", "-f", "GeoJSON", "-simplify", "0.00015", simp, src], check=True)
        d = json.load(open(simp))
    out = []
    for f in d["features"]:
        g = f["geometry"]
        if g["type"] != "LineString" or len(g["coordinates"]) < 2:
            continue
        g["coordinates"] = _round(g["coordinates"])
        out.append({"type": "Feature",
                    "properties": {"class": f["properties"].get("class", "railway")},
                    "geometry": g})
    json.dump({"type": "FeatureCollection", "features": out}, open(OUT, "w"))
    n_rail = sum(1 for f in out if f["properties"]["class"] == "railway")
    print("wrote %s (%d segments: %d rail, %d pipeline)"
          % (OUT, len(out), n_rail, len(out) - n_rail))


if __name__ == "__main__":
    main()
