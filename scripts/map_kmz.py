#!/usr/bin/env python3
"""Shared KMZ/geometry primitives for the cable-atlas pipeline.

This is the common library behind the three-tier atlas flow:

  Tier 1  map_kmz_mine.py   KMZ + NetBox hints -> EXACT per-circuit path
                            (network-map/atlas_precise/<CID>.geojson, GITIGNORED)
  Tier 2  map_coarsen.py    exact path -> COARSENED atlas (DP + rounding)
                            (network-map/atlas/<CID>.geojson, committed, NDA-safe)
  Tier 3  gen_map_structure builder reads the coarse atlas by CID

Nothing here reveals NDA data on its own; the coarsening in `coarsen()` is the
one-way privacy gate and must be the only path from an exact point to a
committed one. Regex-based KML parsing (not XML): provider KMLs use undeclared
namespace prefixes that a strict parser rejects.
"""
import math
import re
import zipfile

# Coarsening tolerances (Tier 2) — ~80 m Douglas-Peucker + ~11 m grid. Enough to
# keep a route recognizably following its corridor while generalizing away exact
# conduit positions. Only `coarsen()` may be used to derive committed geometry.
DP_TOLERANCE_DEG = 0.0008
ROUND_DECIMALS = 4


# ---------------------------------------------------------------------------
# KML / KMZ reading
# ---------------------------------------------------------------------------
def read_kml(path: str) -> str:
    if path.lower().endswith(".kmz"):
        with zipfile.ZipFile(path) as z:
            name = next((n for n in z.namelist() if n.lower().endswith(".kml")), None)
            if not name:
                raise ValueError("no .kml inside %s" % path)
            return z.read(name).decode("utf-8", "replace")
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


_PM_RE = re.compile(r"<Placemark\b.*?</Placemark>", re.S | re.I)
_NAME_RE = re.compile(r"<name>(.*?)</name>", re.S | re.I)
_DESC_RE = re.compile(r"<description>(.*?)</description>", re.S | re.I)
_LS_RE = re.compile(r"<LineString\b.*?</LineString>", re.S | re.I)
_PT_RE = re.compile(r"<Point\b.*?</Point>", re.S | re.I)
_COORD_RE = re.compile(r"<coordinates>(.*?)</coordinates>", re.S | re.I)


def _strip_tags(s: str) -> str:
    return re.sub(r"<.*?>", "", s or "").strip()


def _parse_coords(text: str):
    pts = []
    for tok in text.split():
        parts = tok.split(",")
        if len(parts) >= 2:
            try:
                pts.append((float(parts[0]), float(parts[1])))
            except ValueError:
                pass
    return pts


def linestrings(kml: str):
    """[(name, description, [(lon,lat), ...]), ...] for every LineString placemark."""
    out = []
    for pm in _PM_RE.findall(kml):
        m = _NAME_RE.search(pm)
        name = _strip_tags(m.group(1)) if m else "(unnamed)"
        dm = _DESC_RE.search(pm)
        desc = _strip_tags(dm.group(1)) if dm else ""
        for ls in _LS_RE.findall(pm):
            cm = _COORD_RE.search(ls)
            if not cm:
                continue
            pts = _parse_coords(cm.group(1))
            if len(pts) >= 2:
                out.append((name, desc, pts))
    return out


def points(kml: str):
    """[(name, description, (lon,lat)), ...] for every Point placemark.

    Provider KMZs mark datacenters / handoff sites as Points; matching these to
    NetBox site coordinates is how the miner anchors a circuit's endpoints.
    """
    out = []
    for pm in _PM_RE.findall(kml):
        m = _NAME_RE.search(pm)
        name = _strip_tags(m.group(1)) if m else "(unnamed)"
        dm = _DESC_RE.search(pm)
        desc = _strip_tags(dm.group(1)) if dm else ""
        for pt in _PT_RE.findall(pm):
            cm = _COORD_RE.search(pt)
            if not cm:
                continue
            cs = _parse_coords(cm.group(1))
            if cs:
                out.append((name, desc, cs[0]))
    return out


# ---------------------------------------------------------------------------
# Geometry
# ---------------------------------------------------------------------------
def dist(a, b) -> float:
    return math.hypot(a[0] - b[0], a[1] - b[1])


# Rough deg->meter at Bay Area latitude (~37.5N); good enough for snap/stitch
# thresholds and reporting. 1 deg lat ~111.2 km; 1 deg lon ~88.3 km.
_M_PER_DEG_LAT = 111_200.0
_M_PER_DEG_LON = 88_300.0


def meters_between(a, b) -> float:
    dx = (a[0] - b[0]) * _M_PER_DEG_LON
    dy = (a[1] - b[1]) * _M_PER_DEG_LAT
    return math.hypot(dx, dy)


def chain_segments(segs):
    """Greedily order+orient LineString segments into one connected path by
    joining nearest endpoints. Grows from BOTH ends of the path, so the starting
    segment can be a middle piece — extending only the tail (as a naive chain does)
    folds the route back on itself when the KMZ lists segments out of path order.
    Approximate but connected."""
    segs = [s[:] for s in segs if len(s) >= 2]
    if not segs:
        return []
    path = segs.pop(0)
    while segs:
        head, tail = path[0], path[-1]
        best = None  # (dist, index, where, oriented_segment)
        for i, s in enumerate(segs):
            for d, where, seg in (
                (dist(tail, s[0]), "tail", s),
                (dist(tail, s[-1]), "tail", s[::-1]),
                (dist(head, s[-1]), "head", s),
                (dist(head, s[0]), "head", s[::-1]),
            ):
                if best is None or d < best[0]:
                    best = (d, i, where, seg)
        _, i, where, seg = best
        segs.pop(i)
        path = (path + seg) if where == "tail" else (seg + path)
    return path


def orient_a_to_z(pts, a_ll, z_ll):
    """Reverse pts if it starts nearer the z end than the a end."""
    if a_ll and pts and dist(pts[0], a_ll) > dist(pts[-1], a_ll):
        return pts[::-1]
    if not a_ll and z_ll and pts and dist(pts[0], z_ll) < dist(pts[-1], z_ll):
        return pts[::-1]
    return pts


def _perp_dist(p, a, b):
    if a == b:
        return math.hypot(p[0] - a[0], p[1] - a[1])
    dx, dy = b[0] - a[0], b[1] - a[1]
    t = ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (dx * dx + dy * dy)
    t = max(0.0, min(1.0, t))
    px, py = a[0] + t * dx, a[1] + t * dy
    return math.hypot(p[0] - px, p[1] - py)


def douglas_peucker(pts, tol):
    if len(pts) < 3:
        return pts[:]
    dmax, idx = 0.0, 0
    for i in range(1, len(pts) - 1):
        d = _perp_dist(pts[i], pts[0], pts[-1])
        if d > dmax:
            dmax, idx = d, i
    if dmax > tol:
        left = douglas_peucker(pts[:idx + 1], tol)
        right = douglas_peucker(pts[idx:], tol)
        return left[:-1] + right
    return [pts[0], pts[-1]]


def coarsen(pts, tol=DP_TOLERANCE_DEG, decimals=ROUND_DECIMALS):
    """The privacy gate: Douglas-Peucker generalize + coordinate rounding.
    Consecutive duplicates after rounding are dropped."""
    pts = douglas_peucker(pts, tol)
    out = []
    for lon, lat in pts:
        c = [round(lon, decimals), round(lat, decimals)]
        if not out or out[-1] != c:
            out.append(c)
    return out


# ---------------------------------------------------------------------------
# Atlas FeatureCollection (both precise and coarse use this shape)
# ---------------------------------------------------------------------------
def atlas_fc(circuit_id, provider, a_site, z_site, coords,
             match=None, status="active", geometry="approx-kmz",
             medium="underground"):
    return {
        "type": "FeatureCollection",
        "circuit": {
            "circuit_id": circuit_id, "provider": provider,
            "a_site": a_site, "z_site": z_site, "status": status,
            "geometry": geometry,
            "match": match or ([circuit_id] if circuit_id else []),
        },
        "features": [{
            "type": "Feature",
            "properties": {"seq": 0, "medium": medium},
            "geometry": {"type": "LineString", "coordinates": coords},
        }],
    }
