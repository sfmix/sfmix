#!/usr/bin/env python3
"""Turn an NDA'd provider KMZ into a committable, COARSENED cable-atlas GeoJSON.

The provider KMZ files are shared under NDA and must never enter the repo, nor
may their exact path points be revealed. This tool reads a local KMZ and emits a
deliberately generalized approximation — Douglas–Peucker at a coarse tolerance
plus coordinate rounding — so the committed shape reads as "roughly this
corridor", not the engineering route. Run it only on a laptop where the KMZ
lives; commit only the output under network-map/atlas/.

Usage:
  # See the LineString placemarks in a KMZ (multi-route master files have many):
  scripts/map_trace_path.py "Some Provider Map.kmz" --list

  # Convert one route to an atlas file:
  scripts/map_trace_path.py "Some.kmz" --placemark "A to B" \
      --circuit-id FID-2023-0409 --provider "BIG Fiber" \
      --a-site sfo02 --z-site fmt01 > network-map/atlas/FID-2023-0409.geojson

If --placemark is omitted and the KMZ has exactly one LineString, that one is
used; otherwise the longest is used and a note is printed to stderr.

See network-map/README.md for the atlas format and the hand-draw workflow for
circuits that have no KMZ (Hurricane Electric, Digital Realty).
"""
import argparse
import math
import re
import sys
import zipfile

# Coarsening — the privacy-preserving core. ~300 m Douglas–Peucker + ~11 m grid.
DP_TOLERANCE_DEG = 0.003
ROUND_DECIMALS = 4

# Public site coordinates (lon, lat) — for orienting merged paths A->Z and
# snapping the first/last vertex onto the datacenter. Same values as sites.json.
SITE_COORDS = {
    "sfo01": (-122.390168, 37.788971), "sfo02": (-122.398125, 37.723214),
    "fmt01": (-121.920111, 37.471810), "sjc01": (-121.782426, 37.242351),
    "sjc02": (-121.891649, 37.334147), "scl01": (-121.978378, 37.393803),
    "scl02": (-121.970597, 37.376301), "scl04": (-121.955940, 37.378800),
    "scl05": (-121.947955, 37.372597),
}


def _dist(a, b):
    return math.hypot(a[0] - b[0], a[1] - b[1])


def chain_segments(segs):
    """Greedily order+orient LineString segments into one connected path by
    joining nearest endpoints. Approximate — fine for a coarsened atlas."""
    segs = [s[:] for s in segs if len(s) >= 2]
    if not segs:
        return []
    path = segs.pop(0)
    while segs:
        tail = path[-1]
        best_i, best_rev, best_d = 0, False, float("inf")
        for i, s in enumerate(segs):
            for rev, end in ((False, s[0]), (True, s[-1])):
                d = _dist(tail, end)
                if d < best_d:
                    best_i, best_rev, best_d = i, rev, d
        nxt = segs.pop(best_i)
        if best_rev:
            nxt = nxt[::-1]
        path.extend(nxt)
    return path


def read_kml(path):
    if path.lower().endswith(".kmz"):
        with zipfile.ZipFile(path) as z:
            name = next((n for n in z.namelist() if n.lower().endswith(".kml")), None)
            if not name:
                sys.exit("no .kml inside %s" % path)
            return z.read(name).decode("utf-8", "replace")
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


_PM_RE = re.compile(r"<Placemark\b.*?</Placemark>", re.S | re.I)
_NAME_RE = re.compile(r"<name>(.*?)</name>", re.S | re.I)
_LS_RE = re.compile(r"<LineString\b.*?</LineString>", re.S | re.I)
_COORD_RE = re.compile(r"<coordinates>(.*?)</coordinates>", re.S | re.I)


def _parse_coords(text):
    pts = []
    for tok in text.split():
        parts = tok.split(",")
        if len(parts) >= 2:
            try:
                pts.append((float(parts[0]), float(parts[1])))
            except ValueError:
                pass
    return pts


def linestrings(kml):
    """Return [(name, [(lon,lat), ...]), ...] for every LineString placemark.

    Regex-based, not XML — these provider KMLs use undeclared namespace prefixes
    that a strict parser rejects.
    """
    out = []
    for pm in _PM_RE.findall(kml):
        m = _NAME_RE.search(pm)
        name = re.sub(r"<.*?>", "", m.group(1)).strip() if m else "(unnamed)"
        for ls in _LS_RE.findall(pm):
            cm = _COORD_RE.search(ls)
            if not cm:
                continue
            pts = _parse_coords(cm.group(1))
            if len(pts) >= 2:
                out.append((name, pts))
    return out


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


def coarsen(pts):
    pts = douglas_peucker(pts, DP_TOLERANCE_DEG)
    out = []
    for lon, lat in pts:
        c = [round(lon, ROUND_DECIMALS), round(lat, ROUND_DECIMALS)]
        if not out or out[-1] != c:
            out.append(c)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kmz")
    ap.add_argument("--list", action="store_true", help="list LineString placemarks and exit")
    ap.add_argument("--placemark", help="name (substring, case-insensitive) of the route to use")
    ap.add_argument("--merge", action="store_true",
                    help="concatenate ALL LineStrings into one path (single-circuit KMZs)")
    ap.add_argument("--match", help="comma-separated match tokens (default: circuit-id)")
    ap.add_argument("--snap", action="store_true",
                    help="snap path ends onto the a-site/z-site coordinates")
    ap.add_argument("--circuit-id", default="REPLACE-ME")
    ap.add_argument("--provider", default="REPLACE-ME")
    ap.add_argument("--a-site", default="")
    ap.add_argument("--z-site", default="")
    ap.add_argument("--status", default="active", choices=["active", "retired"])
    ap.add_argument("--medium", default="underground",
                    help="default medium for the single emitted segment; split/tag by hand after")
    args = ap.parse_args()

    lss = linestrings(read_kml(args.kmz))
    if not lss:
        sys.exit("no LineStrings found in %s" % args.kmz)

    if args.list:
        for i, (name, pts) in enumerate(lss):
            print("%2d  %-48s %d pts" % (i, name[:48], len(pts)))
        return 0

    if args.merge:
        segs = [p for _, p in lss]
        pts = chain_segments(segs)
        print("merged %d segments into one path (%d pts)" % (len(segs), len(pts)), file=sys.stderr)
    elif args.placemark:
        q = args.placemark.lower()
        cand = [(n, p) for n, p in lss if q in n.lower()]
        if not cand:
            sys.exit("no placemark matching %r; use --list" % args.placemark)
        if len(cand) > 1:
            print("warning: %d placemarks match %r; using the longest"
                  % (len(cand), args.placemark), file=sys.stderr)
        name, pts = max(cand, key=lambda np: len(np[1]))
    elif len(lss) == 1:
        name, pts = lss[0]
    else:
        name, pts = max(lss, key=lambda np: len(np[1]))
        print("note: %d LineStrings; using the longest. Use --merge, or --list/--placemark."
              % len(lss), file=sys.stderr)

    # orient A->Z using site coords (nearest end to the a-site becomes the start)
    a_ll = SITE_COORDS.get(args.a_site)
    z_ll = SITE_COORDS.get(args.z_site)
    if a_ll and _dist(pts[0], a_ll) > _dist(pts[-1], a_ll):
        pts = pts[::-1]

    coords = coarsen(pts)
    if args.snap:
        if a_ll:
            coords[0] = [round(a_ll[0], ROUND_DECIMALS), round(a_ll[1], ROUND_DECIMALS)]
        if z_ll:
            coords[-1] = [round(z_ll[0], ROUND_DECIMALS), round(z_ll[1], ROUND_DECIMALS)]
    print("kept %d points after coarsening" % len(coords), file=sys.stderr)

    match = ([m.strip() for m in args.match.split(",")] if args.match
             else ([args.circuit_id] if args.circuit_id != "REPLACE-ME" else []))

    fc = {
        "type": "FeatureCollection",
        "circuit": {
            "circuit_id": args.circuit_id, "provider": args.provider,
            "a_site": args.a_site, "z_site": args.z_site, "status": args.status,
            "geometry": "approx-kmz",
            "match": match,
        },
        "features": [{
            "type": "Feature",
            "properties": {"seq": 0, "medium": args.medium},
            "geometry": {"type": "LineString", "coordinates": coords},
        }],
    }
    import json
    print(json.dumps(fc, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
