"""Infrastructure-following routing for inter-site links that have no mined KMZ
geometry. Fibre follows rights-of-way, so instead of flying a straight arc we
route over the basemap's transport network (Dijkstra) preferring, by class:
rail, bridge, pipeline, then highways.

Self-contained: the committed corridor inputs live under this package's data/
(``basemap-roads.json`` + ``rights-of-way.json``) so the portal image needs no
repo checkout. The offline pipeline that produces those inputs stays in the repo
(see network-map/ARCHITECTURE.md); this module only consumes them.
"""
import json
import math
import os
import heapq

from . import geometry as mg

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# Douglas–Peucker coarsening (same tolerances the offline coarsener uses, so a
# routed path reads at the same fidelity as a mined one).
DP_TOLERANCE_DEG = 0.0008
ROUND_DECIMALS = 4

# Cost multiplier by corridor class (lower = preferred): fibre follows rail.
# Only motorway/trunk exist in the basemap-roads layer today; rail/bridge/
# pipeline come from rights-of-way.json.
_INFRA_CLASS_COST = {"railway": 0.7, "bridge": 0.75, "pipeline": 0.8,
                     "motorway": 1.0, "trunk": 1.4}
_ROAD_GRID = 0.0015  # ~150 m vertex-snap (highways are long; keeps the graph small)
_ROAD_GRAPH = {}


def _perp_dist(p, a, b):
    if a == b:
        return math.hypot(p[0] - a[0], p[1] - a[1])
    dx, dy = b[0] - a[0], b[1] - a[1]
    t = ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (dx * dx + dy * dy)
    t = max(0.0, min(1.0, t))
    px, py = a[0] + t * dx, a[1] + t * dy
    return math.hypot(p[0] - px, p[1] - py)


def _douglas_peucker(pts, tol):
    if len(pts) < 3:
        return pts[:]
    dmax, idx = 0.0, 0
    for i in range(1, len(pts) - 1):
        d = _perp_dist(pts[i], pts[0], pts[-1])
        if d > dmax:
            dmax, idx = d, i
    if dmax > tol:
        return _douglas_peucker(pts[:idx + 1], tol)[:-1] + _douglas_peucker(pts[idx:], tol)
    return [pts[0], pts[-1]]


def _coarsen(pts):
    out = []
    for lon, lat in _douglas_peucker(pts, DP_TOLERANCE_DEG):
        c = [round(lon, ROUND_DECIMALS), round(lat, ROUND_DECIMALS)]
        if not out or out[-1] != c:
            out.append(c)
    return out


def _nearest_node(node_xy, coord):
    best, bd = None, 1e18
    for s, xy in node_xy.items():
        d = mg.meters(xy, coord)
        if d < bd:
            bd, best = d, s
    return best, bd


def _dijkstra(adj, src, dst):
    dist = {src: 0.0}
    prev = {}
    pq = [(0.0, src)]
    while pq:
        d, u = heapq.heappop(pq)
        if u == dst:
            break
        if d > dist.get(u, 1e18):
            continue
        for v, w in adj.get(u, {}).items():
            nd = d + w
            if nd < dist.get(v, 1e18):
                dist[v] = nd
                prev[v] = u
                heapq.heappush(pq, (nd, v))
    if dst not in dist:
        return None, None
    path = [dst]
    while path[-1] != src:
        path.append(prev[path[-1]])
    path.reverse()
    return path, dist[dst]


def _road_graph():
    if _ROAD_GRAPH:
        return _ROAD_GRAPH
    node_xy, adj = {}, {}

    def snap(p):
        return (round(p[0] / _ROAD_GRID), round(p[1] / _ROAD_GRID))

    def add(u, v, w):
        d = adj.setdefault(u, {})
        if v not in d or w < d[v]:
            d[v] = w
    for fn in (os.path.join(DATA_DIR, "basemap-roads.json"),
               os.path.join(DATA_DIR, "rights-of-way.json")):
        try:
            feats = json.load(open(fn)).get("features", [])
        except (OSError, ValueError):
            continue
        for f in feats:
            mult = _INFRA_CLASS_COST.get((f.get("properties") or {}).get("class"), 2.0)
            prev = None
            for p in f["geometry"]["coordinates"]:
                s = snap(p)
                node_xy[s] = p
                if prev is not None and s != prev:
                    dm = mg.meters(node_xy[prev], node_xy[s]) * mult
                    add(prev, s, dm)
                    add(s, prev, dm)
                prev = s
    _ROAD_GRAPH.update({"xy": node_xy, "adj": adj})
    return _ROAD_GRAPH


def infra_route(a_ll, z_ll, max_off_m=4000.0):
    """Route a_ll->z_ll over the basemap transport network; None if neither
    endpoint is near it or the graph is disconnected (caller falls back to a
    straight arc)."""
    g = _road_graph()
    if not g.get("adj"):
        return None
    sa, da = _nearest_node(g["xy"], a_ll)
    sz, dz = _nearest_node(g["xy"], z_ll)
    if da > max_off_m or dz > max_off_m:
        return None
    path, _cost = _dijkstra(g["adj"], sa, sz)
    if not path or len(path) < 2:
        return None
    return _coarsen([a_ll] + [g["xy"][s] for s in path] + [z_ll])
