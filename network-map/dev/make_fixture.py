#!/usr/bin/env python3
"""Generate a synthetic fixtures/map.json for local development.

This is DEV-ONLY scaffolding. It uses the real (public) site coordinates but
invents cable shapes, device layouts, and opaque ids — it never touches the
NDA'd KMZ atlas. The dev harness (dev/serve.py) serves the result and fabricates
matching live traffic, so the whole frontend can be built and demoed offline.

The real production equivalent is scripts/gen_map_structure.py, which joins live
eAPI/topology/atlas data; this file only mirrors that JSON *shape*.
"""
import json
import math
import os
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, os.pardir, "fixtures", "map.json")
ATLAS_DIR = os.path.join(HERE, os.pardir, "atlas")
WATER_JSON = os.path.join(HERE, os.pardir, os.pardir, "website", "static", "map", "basemap-water.json")


def _water_rings():
    """All exterior/interior rings of the basemap water polygons, for classifying
    which cable spans cross open water (-> submarine treatment)."""
    rings = []
    try:
        d = json.load(open(WATER_JSON))
    except Exception:
        return rings
    for f in d.get("features", []):
        g = f.get("geometry", {})
        polys = g["coordinates"] if g.get("type") == "MultiPolygon" else [g.get("coordinates", [])]
        for poly in polys:
            for ring in poly:
                rings.append(ring)
    return rings


_WATER = _water_rings()


def _in_water(pt):
    """Even-odd ray cast across all water rings (islands as holes cancel out)."""
    x, y = pt
    inside = False
    for ring in _WATER:
        n = len(ring)
        j = n - 1
        for i in range(n):
            xi, yi = ring[i][0], ring[i][1]
            xj, yj = ring[j][0], ring[j][1]
            if ((yi > y) != (yj > y)) and (x < (xj - xi) * (y - yi) / (yj - yi) + xi):
                inside = not inside
            j = i
    return inside


def reseg_by_water(coords):
    """Re-segment a coord list into underground / submarine runs by water crossing."""
    if not coords:
        return []
    out, cur, cur_m = [], [coords[0]], ("submarine" if _in_water(coords[0]) else "underground")
    for p in coords[1:]:
        m = "submarine" if _in_water(p) else "underground"
        cur.append(p)
        if m != cur_m:
            out.append({"medium": cur_m, "coordinates": cur[:]})
            cur, cur_m = [p], m
    out.append({"medium": cur_m, "coordinates": cur})
    return out


def load_atlas():
    """Map frozenset({a_site,z_site}) -> atlas segments, so the dev map shows the
    real coarsened routes where we have them (geometry is public; traffic stays
    synthetic)."""
    import glob
    out = {}
    for path in glob.glob(os.path.join(ATLAS_DIR, "*.geojson")):
        if os.path.basename(path).startswith("_"):
            continue
        try:
            d = json.load(open(path))
            c = d.get("circuit", {})
            key = frozenset([c.get("a_site"), c.get("z_site")])
            segs = [{"medium": f["properties"].get("medium", "underground"),
                     "coordinates": f["geometry"]["coordinates"]} for f in d["features"]]
            if None not in key and segs:
                out[key] = segs
        except Exception:
            pass
    return out

# Real, public site coordinates (from NetBox / website/content/locations.md).
SITES = {
    "sfo01": (37.788971, -122.390168, "San Francisco", "365 Main", "Digital Realty"),
    "sfo02": (37.723214, -122.398125, "San Francisco", "200 Paul", "Digital Realty"),
    "fmt01": (37.471810, -121.920111, "Fremont", "Hurricane Electric FMT2", "Hurricane Electric"),
    "sjc01": (37.242351, -121.782426, "San Jose", "Equinix SV1", "Equinix"),
    "sjc02": (37.334147, -121.891649, "San Jose", "55 S Market", "CoreSite"),
    "scl01": (37.393803, -121.978378, "Santa Clara", "QTS SC2", "QTS"),
    "scl02": (37.376301, -121.970597, "Santa Clara", "CoreSite SV4", "CoreSite"),
    "scl04": (37.378800, -121.955940, "Santa Clara", "OpenColo SV1", "OpenColo"),
    "scl05": (37.372597, -121.947955, "Santa Clara", "Digital Realty SJC31", "Digital Realty"),
}

# Devices per site (exercises the zoom-in "site expands to devices" view).
DEVICES = {
    "sfo01": ["switch01.sfo01"],
    "sfo02": ["switch01.sfo02", "switch02.sfo02"],
    "fmt01": ["switch01.fmt01", "switch03.fmt01"],
    "sjc01": ["switch01.sjc01"],
    "sjc02": ["switch01.sjc02"],
    "scl01": ["switch01.scl01"],
    "scl02": ["switch01.scl02"],
    "scl04": ["switch01.scl04"],
    "scl05": ["switch01.scl05"],
}

# Inter-site cables: (a_site, z_site, capacity_bps, status, approximate, member_count,
# [(medium, [via-waypoints])]). Waypoints are SYNTHETIC — invented gentle detours,
# not real fiber routes. Coordinates are (lon, lat) to match GeoJSON.
CABLES = [
    ("sfo02", "fmt01", 400e9, "up", False, 1, [
        ("underground", [(-122.30, 37.70), (-122.10, 37.60)]),
        ("bridge",      [(-122.05, 37.56), (-121.98, 37.52)]),
        ("underground", [(-121.95, 37.49)]),
    ]),
    ("sfo01", "sfo02", 100e9, "up", False, 1, [
        ("underground", [(-122.395, 37.755)]),
    ]),
    ("fmt01", "sjc01", 400e9, "up", False, 1, [
        ("underground", [(-121.88, 37.40), (-121.83, 37.32)]),
    ]),
    ("scl02", "scl01", 100e9, "up", False, 1, [
        ("underground", [(-121.975, 37.385)]),
    ]),
    ("scl02", "scl04", 100e9, "up", False, 2, [
        ("underground", [(-121.963, 37.377)]),
    ]),
    ("scl02", "scl05", 100e9, "down", False, 2, [
        ("underground", [(-121.959, 37.374)]),
    ]),
    # sfo02<->scl02 carries TWO circuits: a hot 400G (FID-2025-0742) and an older
    # 100G standby (FID-2022-0145). Same pair -> drawn as adjacent parallel lines.
    ("scl02", "sfo02", 400e9, "up", False, 1, [
        ("underground", [(-121.99, 37.50), (-122.20, 37.62)]),
        ("bridge",      [(-122.30, 37.66)]),
        ("underground", [(-122.38, 37.70)]),
    ]),
    ("scl02", "sfo02", 100e9, "up", False, 1, [
        ("underground", [(-121.99, 37.50), (-122.20, 37.62)]),
        ("bridge",      [(-122.30, 37.66)]),
        ("underground", [(-122.38, 37.70)]),
    ]),
    ("scl02", "sjc01", 400e9, "up", False, 1, [
        ("underground", [(-121.90, 37.32)]),
    ]),
    ("fmt01", "sfo02", 10e9, "up", True, 1, []),  # approximate (auto arc, no atlas)
    ("fmt01", "sjc02", 100e9, "up", False, 1, []),  # Boldyn DF-231-4 (BART-routed atlas)
    ("scl05", "sjc02", 100e9, "up", False, 1, [
        ("underground", [(-121.92, 37.35)]),
    ]),
]

NS = uuid.UUID("5f1e9d0c-0000-4000-8000-5f6d6978aabb")
GENERATION = "dev-fixture-g1"


def building_rect(lat, lon):
    """Stylized building footprint (~210x200 m — deliberately larger than the real
    footprint so the box + switches inside are readable when zoomed in)."""
    dx, dy = 0.00130, 0.00090
    return [[round(lon - dx, 6), round(lat - dy, 6)], [round(lon + dx, 6), round(lat - dy, 6)],
            [round(lon + dx, 6), round(lat + dy, 6)], [round(lon - dx, 6), round(lat + dy, 6)],
            [round(lon - dx, 6), round(lat - dy, 6)]]


def device_offsets(n):
    """Grid of positions INSIDE the building footprint, spaced so dots, labels,
    and intra-links don't overlap."""
    if n == 1:
        return [(0.0, 0.0)]
    cols = min(n, 3 if n <= 6 else 4)
    rows = math.ceil(n / cols)
    sx, sy = 0.00095, 0.00060
    out = []
    for i in range(n):
        r, c = divmod(i, cols)
        x = 0.0 if cols == 1 else (-sx + 2 * sx * c / (cols - 1))
        y = 0.0 if rows == 1 else (sy - 2 * sy * r / (rows - 1))
        out.append((x, y))
    return out


def bezier_arc(p0, p1, bulge=0.12, steps=16):
    """Quadratic-bezier arc between two lon/lat points (for approximate links)."""
    mx, my = (p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2
    dx, dy = p1[0] - p0[0], p1[1] - p0[1]
    cx, cy = mx - dy * bulge, my + dx * bulge  # perpendicular offset
    pts = []
    for i in range(steps + 1):
        t = i / steps
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * cx + t ** 2 * p1[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * cy + t ** 2 * p1[1]
        pts.append([round(x, 5), round(y, 5)])
    return pts


def build():
    sites = {}
    for code, (lat, lon, metro, name, op) in SITES.items():
        offs = device_offsets(len(DEVICES[code]))
        sites[code] = {
            "lat": lat, "lon": lon, "metro": metro, "name": name, "operator": op,
            "address": "(synthetic dev fixture)",
            "building": building_rect(lat, lon),
            "devices": [
                {"id": d, "dlat": round(lat + oy, 6), "dlon": round(lon + ox, 6)}
                for d, (ox, oy) in zip(DEVICES[code], offs)
            ],
        }

    atlas = load_atlas()
    cables = []
    for a, z, cap, status, approx, members, segs in CABLES:
        a_ll = (SITES[a][1], SITES[a][0])
        z_ll = (SITES[z][1], SITES[z][0])
        cid = str(uuid.uuid5(NS, "%s|%s|%s|%s" % (GENERATION, a, z, cap)))
        atlas_segs = atlas.get(frozenset([a, z]))
        if atlas_segs and not approx:
            segments = atlas_segs
            cables.append({
                "id": cid, "scope": "inter", "a_site": a, "z_site": z,
                "a_device": DEVICES[a][0], "z_device": DEVICES[z][0],
                "capacity_bps": cap, "status": status, "approximate": False,
                "members": members, "segments": segments,
            })
            continue
        if approx or not segs:
            segments = [{"medium": "underground", "coordinates": bezier_arc(a_ll, z_ll)}]
        else:
            # stitch: a_site -> segment waypoints... -> z_site, splitting media
            segments = []
            cursor = [round(a_ll[0], 5), round(a_ll[1], 5)]
            flat = [(m, [round(x, 5) for x in [wx, wy]]) for m, wps in segs for wx, wy in wps]
            # group consecutive waypoints by medium into segments
            i = 0
            prev_pt = cursor
            for m, wps in segs:
                coords = [prev_pt] + [[round(wx, 5), round(wy, 5)] for wx, wy in wps]
                segments.append({"medium": m, "coordinates": coords})
                prev_pt = coords[-1]
            # final leg into z
            segments.append({"medium": segs[-1][0], "coordinates": [prev_pt, [round(z_ll[0], 5), round(z_ll[1], 5)]]})
        cables.append({
            "id": cid, "scope": "inter",
            "a_site": a, "z_site": z,
            "a_device": DEVICES[a][0], "z_device": DEVICES[z][0],
            "capacity_bps": cap, "status": status, "approximate": approx,
            "members": members,
            "segments": segments,
        })

    # A couple of intra-site links (only visible zoomed in).
    for code in ("sfo02", "fmt01"):
        devs = DEVICES[code]
        if len(devs) < 2:
            continue
        s = sites[code]
        d0, d1 = s["devices"][0], s["devices"][1]
        cid = str(uuid.uuid5(NS, "%s|intra|%s" % (GENERATION, code)))
        cables.append({
            "id": cid, "scope": "intra",
            "a_site": code, "z_site": code,
            "a_device": d0["id"], "z_device": d1["id"],
            "capacity_bps": 800e9, "status": "up", "approximate": False, "members": 2,
            "segments": [{"medium": "building", "coordinates": [
                [d0["dlon"], d0["dlat"]], [d1["dlon"], d1["dlat"]]]}],
        })

    # tag water-crossing spans as submarine (blue + wave treatment) by testing
    # each vertex against the basemap water polygons
    for c in cables:
        if c["scope"] != "inter":
            continue
        coords = []
        for seg in c["segments"]:
            for p in seg["coordinates"]:
                if not coords or coords[-1] != p:
                    coords.append(p)
        resegged = reseg_by_water(coords)
        if any(s["medium"] == "submarine" for s in resegged):
            c["segments"] = resegged

    return {
        "generation": GENERATION,
        "generated_at": "2026-07-04T00:00:00Z",
        "sites": sites,
        "cables": cables,
    }


if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as fh:
        json.dump(build(), fh, indent=2)
    print("wrote", os.path.relpath(OUT))
