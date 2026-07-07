#!/usr/bin/env python3
"""Render-geometry engine for the network map — pure, IXP-agnostic.

The frontend (website/static/js/network-map.js) is intentionally dumb: it styles
and lays out whatever geometry it is handed. ALL geometry *construction* happens
here, on the backend, so map.json ships ready to draw and any consumer (this map,
a future one, another IXP) gets the same clean geometry. Nothing in this module
knows anything SFMIX-specific — it operates on lon/lat coordinate lists, site
centre points, building-box rings, and water polygons passed in by the caller.

Pipeline for one inter-site cable (see build_cable_geometry):
  raw segments -> concat+dedupe -> per-segment Chaikin smoothing -> orient a->z
  -> de-loop (drop small self-intersections) -> clip each end to the building-box
  edge on its true approach side (dropping the near-site coarsening jog) -> re-loop
  clean. Then: water spans for the submarine treatment, and the fine "drop" lines
  from each box-edge entry to the specific device.

Everything here mirrors the algorithms that used to live in network-map.js; the
frontend now just consumes the output.
"""
import math

# Tunables (geometry, not styling). Metres.
LOOP_MAX_M = 1800.0     # only excise self-intersections smaller than this
APPROACH_M = 350.0      # ignore near-site jogs within this radius when picking the entry side
CHAIKIN_ITERS = 2       # corner-cutting passes for smoothing


def meters(a, b):
    dx = (a[0] - b[0]) * 111320.0 * math.cos(math.radians(a[1]))
    dy = (a[1] - b[1]) * 110540.0
    return math.hypot(dx, dy)


# --- smoothing -------------------------------------------------------------
def chaikin(pts, iters=CHAIKIN_ITERS):
    """Chaikin corner-cutting. Endpoints are preserved so segment joins stay put."""
    for _ in range(iters):
        if len(pts) < 3:
            break
        out = [pts[0]]
        for i in range(len(pts) - 1):
            p, q = pts[i], pts[i + 1]
            out.append([p[0] * 0.75 + q[0] * 0.25, p[1] * 0.75 + q[1] * 0.25])
            out.append([p[0] * 0.25 + q[0] * 0.75, p[1] * 0.25 + q[1] * 0.75])
        out.append(pts[-1])
        pts = out
    return pts


def dedupe(coords):
    out = []
    for p in coords:
        if not out or out[-1][0] != p[0] or out[-1][1] != p[1]:
            out.append([p[0], p[1]])
    return out


# --- de-loop (remove small self-intersections) -----------------------------
def _seg_int(p1, p2, p3, p4):
    d = (p2[0] - p1[0]) * (p4[1] - p3[1]) - (p2[1] - p1[1]) * (p4[0] - p3[0])
    if abs(d) < 1e-14:
        return None
    t = ((p3[0] - p1[0]) * (p4[1] - p3[1]) - (p3[1] - p1[1]) * (p4[0] - p3[0])) / d
    u = ((p3[0] - p1[0]) * (p2[1] - p1[1]) - (p3[1] - p1[1]) * (p2[0] - p1[0])) / d
    if 0 < t < 1 and 0 < u < 1:
        return [p1[0] + t * (p2[0] - p1[0]), p1[1] + t * (p2[1] - p1[1])]
    return None


def deloop(pts, max_loop_m=LOOP_MAX_M):
    """Splice out small self-intersections (coarsening knots near sites). Capped by
    span so a long route that merely crosses itself once isn't collapsed to a line."""
    pts = [list(p) for p in pts]
    for _ in range(40):
        cut = False
        n = len(pts)
        for i in range(n - 1):
            for j in range(i + 2, n - 1):
                x = _seg_int(pts[i], pts[i + 1], pts[j], pts[j + 1])
                if x is None:
                    continue
                span = sum(meters(pts[k], pts[k + 1]) for k in range(i, j))
                if span > max_loop_m:
                    continue
                pts = pts[:i + 1] + [x] + pts[j + 1:]
                cut = True
                break
            if cut:
                break
        if not cut:
            break
    return pts


# --- building-box clipping --------------------------------------------------
def rect_bounds(ring):
    xs = [p[0] for p in ring]
    ys = [p[1] for p in ring]
    return {"minX": min(xs), "maxX": max(xs), "minY": min(ys), "maxY": max(ys)}


def _inside_rect(p, b):
    return b["minX"] < p[0] < b["maxX"] and b["minY"] < p[1] < b["maxY"]


def _rect_exit(center, toward, b):
    """Point where the ray from center (inside the box) toward `toward` exits the rect."""
    dx, dy = toward[0] - center[0], toward[1] - center[1]
    if dx == 0 and dy == 0:
        return [center[0], b["maxY"]]
    t = math.inf
    if dx > 0:
        t = min(t, (b["maxX"] - center[0]) / dx)
    elif dx < 0:
        t = min(t, (b["minX"] - center[0]) / dx)
    if dy > 0:
        t = min(t, (b["maxY"] - center[1]) / dy)
    elif dy < 0:
        t = min(t, (b["minY"] - center[1]) / dy)
    return [center[0] + t * dx, center[1] + t * dy]


def clip_to_boxes(coords, center_a, box_a, center_z, box_z, approach_m=APPROACH_M):
    """Clip a trunk so each end lands on its site's box EDGE, entering on the side
    the cable GENERALLY approaches from (skipping the near-site coarsening jog).
    Returns (line, entry_a, entry_z)."""
    mid = [p for p in coords
           if not (box_a and _inside_rect(p, box_a)) and not (box_z and _inside_rect(p, box_z))]
    if not mid:
        mid = [list(center_a), list(center_z)]
    i_a = 0
    while i_a < len(mid) - 1 and meters(mid[i_a], center_a) < approach_m:
        i_a += 1
    i_z = len(mid) - 1
    while i_z > 0 and meters(mid[i_z], center_z) < approach_m:
        i_z -= 1
    if i_z <= i_a:
        i_a, i_z = 0, len(mid) - 1
    core = mid[i_a:i_z + 1]
    entry_a = _rect_exit(center_a, core[0], box_a) if box_a else list(coords[0])
    entry_z = _rect_exit(center_z, core[-1], box_z) if box_z else list(coords[-1])
    return [entry_a] + core + [entry_z], entry_a, entry_z


# --- orientation ------------------------------------------------------------
def orient_a_to_z(coords, a_ll, z_ll):
    """Reverse the polyline if it starts nearer z than a, so it always runs a->z
    (atlas paths are stored in their own A/Z order; downstream clipping keys off it)."""
    if len(coords) < 2:
        return coords
    d_a = math.hypot(coords[0][0] - a_ll[0], coords[0][1] - a_ll[1])
    d_z = math.hypot(coords[0][0] - z_ll[0], coords[0][1] - z_ll[1])
    return coords[::-1] if d_a > d_z else coords


# --- water crossings (submarine treatment) ----------------------------------
def point_in_rings(pt, rings):
    """Even-odd ray cast across all water rings (island holes cancel out)."""
    x, y = pt[0], pt[1]
    inside = False
    for ring in rings:
        n = len(ring)
        j = n - 1
        for i in range(n):
            xi, yi = ring[i][0], ring[i][1]
            xj, yj = ring[j][0], ring[j][1]
            if ((yi > y) != (yj > y)) and (x < (xj - xi) * (y - yi) / (yj - yi) + xi):
                inside = not inside
            j = i
    return inside


def water_spans(coords, water_rings):
    """Sub-spans of `coords` that cross open water — emitted as `media` so the
    frontend lays the submerged/ripple treatment exactly over the cable (aligned,
    since these ARE sub-spans of the drawn path). Generic: any water basemap."""
    if not water_rings or len(coords) < 2:
        return []
    spans, cur = [], None
    for p in coords:
        wet = point_in_rings(p, water_rings)
        if wet:
            if cur is None:
                cur = [p]
            else:
                cur.append(p)
        else:
            if cur is not None and len(cur) >= 2:
                spans.append(cur)
            cur = None
    if cur is not None and len(cur) >= 2:
        spans.append(cur)
    return [{"medium": "submarine", "coordinates": s} for s in spans]


# --- top-level assembly -----------------------------------------------------
def concat_segments(segments):
    coords = []
    for seg in segments:
        coords += seg.get("coordinates", [])
    return dedupe(coords)


def build_inter_geometry(segments, a_ll, z_ll, box_a, box_z, water_rings,
                         a_dev_ll=None, z_dev_ll=None):
    """Full render geometry for an inter-site cable. Returns a dict with:
      path   final smoothed/oriented/de-looped/box-clipped polyline (the trunk)
      media  water-crossing sub-spans of path (submarine treatment)
      drops  fine [entry_edge -> device] lines (a end, z end) when devices known
    """
    # per-segment Chaikin (preserves segment joins), then concat
    smooth = dedupe([p for seg in segments for p in chaikin(seg.get("coordinates", []))])
    smooth = orient_a_to_z(smooth, a_ll, z_ll)
    smooth = deloop(smooth)
    line, entry_a, entry_z = clip_to_boxes(smooth, a_ll, box_a, z_ll, box_z)
    line = deloop(line)  # the box-edge entry segment can re-cross
    drops = []
    if a_dev_ll is not None:
        drops.append([entry_a, list(a_dev_ll)])
    if z_dev_ll is not None:
        drops.append([entry_z, list(z_dev_ll)])
    return {"path": [[round(p[0], 5), round(p[1], 5)] for p in line],
            "media": [{"medium": m["medium"],
                       "coordinates": [[round(p[0], 5), round(p[1], 5)] for p in m["coordinates"]]}
                      for m in water_spans(line, water_rings)],
            "drops": [[[round(a[0], 5), round(a[1], 5)], [round(b[0], 5), round(b[1], 5)]]
                      for a, b in drops]}


def assign_lanes(cables):
    """Assign each inter cable a parallel-lane ordinal among the DISTINCT circuits
    on its unordered site pair, so the frontend can offset them into adjacent
    strands. Sets c['lane'] and c['lane_count'] in place. (Ordinals only — the
    px spacing is a rendering choice the frontend makes.)"""
    order = {}
    for c in cables:
        if c.get("scope") != "inter":
            continue
        key = tuple(sorted([c["a_site"], c["z_site"]]))
        order.setdefault(key, []).append(c)
    for key, group in order.items():
        n = len(group)
        for i, c in enumerate(group):
            c["lane"] = i
            c["lane_count"] = n


def metro_aggregate(cables, sites, metro_of, metro_centroid):
    """Collapse inter-metro cables into one trunk per metro pair, traced along the
    richest real member (prefer non-approx, then most points) so it follows a real
    corridor. Returns a list of metro-cable dicts with pre-built `path`."""
    groups = {}
    for c in cables:
        if c.get("scope") != "inter":
            continue
        ma, mz = metro_of.get(c["a_site"]), metro_of.get(c["z_site"])
        if not ma or not mz or ma == mz:
            continue
        key = tuple(sorted([ma, mz]))
        g = groups.setdefault(key, {"a": ma, "z": mz, "cap": 0, "ids": [],
                                    "any_up": False, "all_approx": True})
        g["cap"] += c.get("capacity_bps", 0)
        g["ids"].append(c["id"])
        if c.get("status") != "down":
            g["any_up"] = True
        if not c.get("approximate"):
            g["all_approx"] = False
    by_id = {c["id"]: c for c in cables}
    out = []
    for key, g in groups.items():
        ca, cz = metro_centroid[g["a"]], metro_centroid[g["z"]]
        best = None
        for cid in g["ids"]:
            path = by_id[cid].get("path") or []
            if len(path) < 3:
                continue
            approx = by_id[cid].get("approximate", False)
            if (best is None or (best[0] and not approx)
                    or (best[0] == approx and len(path) > len(best[1]))):
                best = (approx, path)
        if best:
            pts = list(best[1])
            if math.hypot(pts[0][0] - ca[0], pts[0][1] - ca[1]) > \
               math.hypot(pts[-1][0] - ca[0], pts[-1][1] - ca[1]):
                pts = pts[::-1]
            line = [ca] + pts + [cz]
            real = not best[0]
        else:
            mx, my = (ca[0] + cz[0]) / 2, (ca[1] + cz[1]) / 2
            dx, dy = cz[0] - ca[0], cz[1] - ca[1]
            line = chaikin([ca, [mx - dy * 0.08, my + dx * 0.08], cz])
            real = False
        out.append({"id": "metro:%s~%s" % key, "a_metro": g["a"], "z_metro": g["z"],
                    "capacity_bps": g["cap"], "status": "up" if g["any_up"] else "down",
                    "approximate": not real, "members": len(g["ids"]), "member_ids": g["ids"],
                    "path": [[round(p[0], 5), round(p[1], 5)] for p in line]})
    return out
