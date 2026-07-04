#!/usr/bin/env python3
"""Chain a Boldyn BART-right-of-way path into a coarsened cable-atlas GeoJSON.

Boldyn's fiber rides BART (and other) rights-of-way, so their KMZ is not one path
per circuit — it's a network of segments named by BART line (RTE100xxx /
"BART R-Line") plus short "Lateral to <DC>" spurs and datacenter Points. A given
SFMIX circuit is the *chain of segments* between two datacenters. This tool:

  1. builds a graph from every segment vertex (snapped to a ~20 m grid, so
     segments that touch share a node) and stitches near-miss nodes (<=STITCH m)
     to bridge laterals that join a line mid-span;
  2. Dijkstra-routes between the graph nodes nearest the two datacenters;
  3. coarsens the chained polyline (shared map_trace_path coarsening — NDA-safe)
     and emits the same atlas format as map_trace_path.py.

The KMZ is NDA; only the coarsened output is committable.

Usage:
  scripts/map_boldyn_route.py "Customer Facing Boldyn Fiber Network 11.13.25.kmz" \
      --a-site fmt01 --z-site sjc02 --circuit-id DF-231-4 --match DF-231-4-1,DF-231-4-2 \
      > network-map/atlas/DF-231-4.geojson

  # list the datacenter Points in the KMZ (to pick --a-name/--z-name):
  scripts/map_boldyn_route.py "…Boldyn….kmz" --list
"""
import argparse
import heapq
import json
import math
import os
import re
import sys
import xml.etree.ElementTree as ET

import map_trace_path as mtp  # shared KMZ read + coarsen (same scripts/ dir)

GRID_DEG = 0.0002      # ~22 m vertex-snap grid
STITCH_M = 70.0        # bridge laterals/gaps within this many metres
LAT = 37.6             # bay-area reference latitude for the metric approximation

# SFMIX site code -> the datacenter Point name as it appears in Boldyn KMZs.
SITE_DC_NAME = {
    "sfo01": "365 Main", "sfo02": "200 Paul", "fmt01": "48233 Warm Springs",
    "sjc02": "55 South Market", "scl05": "2805 Lafayette", "sjc01": "11 Great Oaks",
    "scl04": "3223 Kenneth", "scl01": "2807",  # best-effort
}


def meters(a, b):
    dx = (a[0] - b[0]) * math.cos(math.radians(LAT)) * 111320.0
    dy = (a[1] - b[1]) * 111320.0
    return math.hypot(dx, dy)


def _localname(t):
    return t.rsplit("}", 1)[-1]


def _folder_medium_status(folders):
    """Map a placemark's folder-path names to (medium, built).

    Boldyn organizes the built network under CONSTRUCTION COMPLETE with
    Underground / Aerial / Elevated Bart sub-layers, and proposed routes under
    IN PROGRESS. We route preferentially over built fiber and tag segments by
    their real medium."""
    joined = " / ".join(folders).lower()
    built = "construction complete" in joined
    if "elevated bart" in joined or "aerial" in joined:
        medium = "aerial"
    elif "underground" in joined:
        medium = "underground"
    else:
        medium = "underground"
    return medium, built


def parse_kml(kml):
    """Folder-aware parse. Returns (segments, points) where segments is a list of
    (coords, medium, built) and points is {name_lower: (lon,lat)}.

    Uses ElementTree with namespace prefixes stripped (these KMLs declare gx:/etc
    inconsistently), so we can read the Folder hierarchy for medium/status."""
    raw = re.sub(r"<(/?)(\w+):", r"<\1", kml)  # drop namespace prefixes
    root = ET.fromstring(raw)
    segments, points = [], {}

    def walk(el, folders):
        for ch in el:
            tag = _localname(ch.tag)
            if tag in ("Folder", "Document"):
                nm = ""
                for c in ch:
                    if _localname(c.tag) == "name":
                        nm = (c.text or "").strip()
                walk(ch, folders + ([nm] if tag == "Folder" and nm else []))
            elif tag == "Placemark":
                nm = ""
                for c in ch:
                    if _localname(c.tag) == "name":
                        nm = (c.text or "").strip()
                for g in ch.iter():
                    gt = _localname(g.tag)
                    if gt == "LineString":
                        for cc in g.iter():
                            if _localname(cc.tag) == "coordinates":
                                pts = mtp._parse_coords(cc.text or "")
                                if len(pts) >= 2:
                                    medium, built = _folder_medium_status(folders)
                                    segments.append((pts, medium, built))
                    elif gt == "Point":
                        for cc in g.iter():
                            if _localname(cc.tag) == "coordinates":
                                pts = mtp._parse_coords(cc.text or "")
                                if pts and nm:
                                    points[nm.lower()] = pts[0]
            else:
                walk(ch, folders)

    walk(root, [])
    return segments, points


PLANNED_PENALTY = 4.0  # prefer built fiber; use in-progress only to bridge


def build_graph(segments):
    def snap(p):
        return (round(p[0] / GRID_DEG), round(p[1] / GRID_DEG))
    node_xy, adj, emeta = {}, {}, {}

    def add(u, v, medium, built):
        adj.setdefault(u, {})
        dm = meters(node_xy[u], node_xy[v])
        cost = dm * (1.0 if built else PLANNED_PENALTY)
        if v not in adj[u] or cost < adj[u][v]:
            adj[u][v] = cost
            emeta[(u, v)] = {"m": dm, "medium": medium, "built": built}
    for seg, medium, built in segments:
        prev = None
        for p in seg:
            s = snap(p)
            node_xy[s] = p
            if prev is not None and s != prev:
                add(prev, s, medium, built)
                add(s, prev, medium, built)
            prev = s
    # stitch near nodes (bucketed by ~STITCH cells) to bridge mid-span joins;
    # a stitch inherits "built" so it doesn't distort the built/planned choice
    cx_deg = STITCH_M / (111320.0 * math.cos(math.radians(LAT)))
    cy_deg = STITCH_M / 111320.0
    buck = {}
    for s, xy in node_xy.items():
        buck.setdefault((int(xy[0] / cx_deg), int(xy[1] / cy_deg)), []).append(s)
    for s, xy in node_xy.items():
        bx, by = int(xy[0] / cx_deg), int(xy[1] / cy_deg)
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                for t in buck.get((bx + dx, by + dy), []):
                    if t <= s:
                        continue
                    d = meters(xy, node_xy[t])
                    if 0 < d <= STITCH_M:
                        add(s, t, "underground", True)
                        add(t, s, "underground", True)
    return node_xy, adj, emeta


def nearest_node(node_xy, coord):
    best, bd = None, 1e18
    for s, xy in node_xy.items():
        d = meters(xy, coord)
        if d < bd:
            bd, best = d, s
    return best, bd


def dijkstra(adj, src, dst):
    dist = {src: 0.0}; prev = {}; pq = [(0.0, src)]
    while pq:
        d, u = heapq.heappop(pq)
        if u == dst:
            break
        if d > dist.get(u, 1e18):
            continue
        for v, w in adj.get(u, {}).items():
            nd = d + w
            if nd < dist.get(v, 1e18):
                dist[v] = nd; prev[v] = u; heapq.heappush(pq, (nd, v))
    if dst not in dist:
        return None, None
    path = [dst]
    while path[-1] != src:
        path.append(prev[path[-1]])
    path.reverse()
    return path, dist[dst]


def resolve_dc(points, site, name):
    """Find the datacenter coord: explicit --a-name/--z-name substring, else the
    site code's known Boldyn DC name."""
    key = (name or SITE_DC_NAME.get(site, "")).lower()
    if not key:
        return None
    if key in points:
        return points[key]
    for nm, c in points.items():  # substring match
        if key in nm:
            return c
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kmz")
    ap.add_argument("--list", action="store_true", help="list datacenter Points and exit")
    ap.add_argument("--a-site", default="")
    ap.add_argument("--z-site", default="")
    ap.add_argument("--a-name", help="datacenter Point name (substring) if not derivable from --a-site")
    ap.add_argument("--z-name", help="datacenter Point name (substring)")
    ap.add_argument("--circuit-id", default="REPLACE-ME")
    ap.add_argument("--provider", default="Boldyn")
    ap.add_argument("--match", help="comma-separated match tokens (default: circuit-id)")
    ap.add_argument("--status", default="active", choices=["active", "retired"])
    args = ap.parse_args()

    kml = mtp.read_kml(args.kmz)
    segments, points = parse_kml(kml)

    if args.list:
        for nm in sorted(points):
            print("  %-28s %s" % (nm, points[nm]))
        return 0

    a = resolve_dc(points, args.a_site, args.a_name)
    z = resolve_dc(points, args.z_site, args.z_name)
    if not a or not z:
        sys.exit("could not resolve endpoints; use --list then --a-name/--z-name")

    node_xy, adj, emeta = build_graph(segments)
    sa, da = nearest_node(node_xy, a)
    sz, dz = nearest_node(node_xy, z)
    print("nearest-node offsets: a=%.0fm z=%.0fm" % (da, dz), file=sys.stderr)
    path, cost = dijkstra(adj, sa, sz)
    if not path:
        sys.exit("no BART-corridor path between endpoints (disconnected in this KMZ); "
                 "try a different Boldyn KMZ or a larger STITCH_M")

    # walk the path edges, grouping consecutive same-medium runs into segments,
    # bracketed by the short connectors from the datacenter points to the graph
    verts = [a, node_xy[sa]]
    edge_medium = ["underground"]  # a -> first graph node connector
    real_m = 0.0
    for i in range(len(path) - 1):
        e = emeta.get((path[i], path[i + 1]), {})
        verts.append(node_xy[path[i + 1]])
        edge_medium.append(e.get("medium", "underground"))
        real_m += e.get("m", 0.0)
    verts.append(z)
    edge_medium.append(edge_medium[-1])  # last graph node -> z connector

    straight = meters(a, z)
    print("routed %.1f km over %d hops (straight %.1f km)"
          % (real_m / 1000, len(path), straight / 1000), file=sys.stderr)

    features, seq = [], 0
    run_start = 0
    for i in range(1, len(edge_medium) + 1):
        if i == len(edge_medium) or edge_medium[i] != edge_medium[run_start]:
            run = verts[run_start:i + 1]
            coords = mtp.coarsen(run)
            if len(coords) >= 2:
                features.append({"type": "Feature",
                                 "properties": {"seq": seq, "medium": edge_medium[run_start]},
                                 "geometry": {"type": "LineString", "coordinates": coords}})
                seq += 1
            run_start = i
    match = ([m.strip() for m in args.match.split(",")] if args.match
             else ([args.circuit_id] if args.circuit_id != "REPLACE-ME" else []))
    fc = {
        "type": "FeatureCollection",
        "circuit": {"circuit_id": args.circuit_id, "provider": args.provider,
                    "a_site": args.a_site, "z_site": args.z_site, "status": args.status,
                    "geometry": "approx-bart", "match": match},
        "features": features,
    }
    print(json.dumps(fc, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
