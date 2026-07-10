"""Derive the public weathermap structure from the built map.json.

The weathermap is the same backbone graph the geographic map draws, rendered
schematically: switches as boxes clustered by metro, links as straight strands
coloured by utilization (the classic network-weathermap look the old Grafana
dashboard provided). Rather than re-query NetBox, this is a pure function of
the already-built map.json — the cable ids stay identical, so the frontend
colours links from the SAME /statistics/map/traffic feed the geographic map
polls, and no second build pass or traffic endpoint exists.

Layout (ideas ported from scripts/weathermap_layouts.py, sans graphviz),
optimised for clarity over geography: metro anchors sit on a ring, ordered so
the most-connected metro pairs are ring-adjacent (brute-forced — metro counts
are tiny) — inter-metro trunks then run along the ring's edges instead of
overlapping diagonals through the middle. The ring is rotated so the
northernmost metro sits at the top and mirrored so the westernmost sits on
the left, keeping a loose geographic feel. Within a metro, nodes sit on a
circle whose radius grows with the node count, each seated at the slot
nearest the direction of its external neighbours (so inter-metro links leave
the cluster on the side they travel, instead of slicing through it); finally
an iterative push-apart pass guarantees no two node label boxes overlap and a
normalize step stretches the graph to fill the viewbox. A passive site with
no switches (splice/patch building) that terminates a drawn span becomes a
small junction node so chained circuits stay connected.
"""

VIEW_W, VIEW_H = 2200.0, 1400.0  # roomy: the frontend is a pan/zoom viewport
PAD = 360.0          # horizontal anchor inset: largest cluster radius + box
PAD_Y = 280.0        # vertical inset can run tighter (boxes are wide, not tall)
# nominal node label-box footprint for the collision pass (frontend draws
# ~6.8px/char + padding at 22px tall; keep these comfortably larger)
NODE_W, NODE_H = 150.0, 34.0


def _ring_order(metros, pair_weight):
    """Metro names in the ring order that keeps heavily-linked metro pairs
    adjacent: minimise sum(weight * (ring_distance - 1)^2) over linked pairs.
    Brute force — a handful of metros, and fixing the first element kills the
    rotational symmetry. Deterministic: sorted base order, first improvement
    wins ties."""
    import itertools
    names = sorted(metros)
    if len(names) <= 3:
        return names
    n = len(names)
    best, best_cost = names, None
    for perm in itertools.permutations(names[1:]):
        order = [names[0]] + list(perm)
        idx = {m: i for i, m in enumerate(order)}
        cost = 0
        for (a, b), w in pair_weight.items():
            d = abs(idx[a] - idx[b])
            d = min(d, n - d)
            cost += w * (d - 1) ** 2
        if best_cost is None or cost < best_cost:
            best, best_cost = order, cost
    return best


def _metro_anchors(metros, pair_weight, counts):
    """Metro name -> (x, y) on an ellipse, in connectivity ring order, each
    metro given arc room proportional to its cluster radius (a 7-switch metro
    needs more clearance than a lone junction); rotated so the northernmost
    metro is at the top and mirrored so the westernmost falls on the left
    half — clarity first, with a loose geographic feel."""
    import math
    names = sorted(metros)
    if not names:
        return {}
    if len(names) == 1:
        return {names[0]: (VIEW_W / 2, VIEW_H / 2)}
    order = _ring_order(metros, pair_weight)
    n = len(order)
    top = max(names, key=lambda m: metros[m]["lat"])
    west = min(names, key=lambda m: metros[m]["lon"])
    cx, cy = VIEW_W / 2, VIEW_H / 2
    rx, ry = VIEW_W / 2 - PAD, VIEW_H / 2 - PAD_Y

    def seats(seq):
        # arc share per metro ~ its clearance need; a seat sits at the middle
        # of its arc, and the whole ring is rotated so `top` lands at -pi/2
        need = {m: _circle_radius(counts.get(m, 1)) + 200.0 for m in seq}
        total = sum(need.values())
        ang, acc = {}, 0.0
        for m in seq:
            ang[m] = 2 * math.pi * (acc + need[m] / 2) / total
            acc += need[m]
        off = -math.pi / 2 - ang[top]
        return {m: a + off for m, a in ang.items()}

    a = seats(order)
    if math.cos(a[west]) > 0:  # westernmost landed on the right: mirror the ring
        a = seats(order[::-1])
    return {m: (cx + rx * math.cos(a[m]), cy + ry * math.sin(a[m])) for m in names}


def _circle_radius(count):
    """Radius where neighbouring slots sit at least a label box apart."""
    import math
    if count <= 1:
        return 0.0
    # 1.2 chord factor: a whole label box plus clearance between neighbouring
    # nodes — the canvas is a zoomable viewport now, so space is cheap
    return max(110.0, (NODE_W * 1.2) / (2 * math.sin(math.pi / count)))


def _seat_on_circle(anchor, occ, prefer):
    """Assign each occupant the circle slot nearest its preferred angle.
    Occupants are ordered by preferred angle, slots are evenly spaced with the
    phase chosen so the first occupant lands on its preference."""
    import math
    ax, ay = anchor
    n = len(occ)
    if n == 1:
        return {occ[0]: (ax, ay)}
    r = _circle_radius(n)
    ordered = sorted(occ, key=lambda o: prefer[o])
    phase = prefer[ordered[0]]
    out = {}
    for i, o in enumerate(ordered):
        a = phase + 2 * math.pi * i / n
        out[o] = (ax + r * math.cos(a), ay + r * math.sin(a))
    return out


def _push_apart(pos, iters=300, pad=26.0):
    """Iterative pairwise push so no two node boxes overlap (port of the
    Grafana layout lab's remove_overlaps). Deterministic: fixed order/iters."""
    names = sorted(pos)
    P = {n: [pos[n][0], pos[n][1]] for n in names}
    m = 24.0  # viewbox margin for box edges

    def clamp(p):
        p[0] = min(max(p[0], m + NODE_W / 2), VIEW_W - m - NODE_W / 2)
        p[1] = min(max(p[1], m + NODE_H / 2), VIEW_H - m - NODE_H / 2)

    for _ in range(iters):
        moved = False
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                a, b = names[i], names[j]
                ox = (NODE_W + pad) - abs(P[a][0] - P[b][0])
                oy = (NODE_H + pad) - abs(P[a][1] - P[b][1])
                if ox > 0 and oy > 0:  # boxes overlap: push along the smaller axis
                    moved = True
                    if ox < oy:
                        s = ox / 2 * (1 if P[a][0] >= P[b][0] else -1)
                        P[a][0] += s
                        P[b][0] -= s
                    else:
                        s = oy / 2 * (1 if P[a][1] >= P[b][1] else -1)
                        P[a][1] += s
                        P[b][1] -= s
                    # clamp inside the loop so an edge-pinned node keeps
                    # displacing its neighbour instead of un-clamping later
                    clamp(P[a])
                    clamp(P[b])
        if not moved:
            break
    return {n: (P[n][0], P[n][1]) for n in names}


def _fill_view(pos, margin=160.0):
    """Stretch the laid-out graph to fill the padded viewbox (the Grafana
    lab's normalize step). Expansion only — scales below 1 would compress
    node spacing and could reintroduce the overlaps _push_apart removed."""
    if not pos:
        return pos
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
    sx = max(1.0, min((VIEW_W - 2 * margin) / ((maxx - minx) or 1), 2.0))
    sy = max(1.0, min((VIEW_H - 2 * margin) / ((maxy - miny) or 1), 2.0))
    ox = (VIEW_W - (maxx - minx) * sx) / 2
    oy = (VIEW_H - (maxy - miny) * sy) / 2
    return {n: (ox + (x - minx) * sx, oy + (y - miny) * sy)
            for n, (x, y) in pos.items()}


def weathermap_from_map(mapjson):
    """map.json dict -> weathermap.json dict (same generation + cable ids)."""
    import math
    sites = mapjson.get("sites", {})
    metros = mapjson.get("metros", {})
    metro_of = {code: name for name, m in metros.items() for code in m.get("codes", [])}

    # links first: they decide which passive sites need a junction node.
    # crossconnect "cables" are geographic drawing artifacts (a through-patch
    # inside a passive building) — the junction node already tells that story.
    links, endpoints = [], set()
    for c in mapjson.get("cables", []):
        if c.get("scope") not in ("inter", "intra"):
            continue
        a = c.get("a_device") or "site:" + c["a_site"]
        z = c.get("z_device") or "site:" + c["z_site"]
        if a == z:
            continue
        links.append({
            "id": c["id"], "a": a, "z": z, "scope": c["scope"],
            "status": c.get("status", "up"),
            "capacity_bps": c.get("capacity_bps") or 0,
            "members": c.get("members") or 1,
        })
        endpoints.update([a, z])

    # occupants per metro: every switch, plus a junction per referenced
    # passive site — placed on the same circle so the metro reads as one group
    node_meta, occupants = {}, {}
    for code, s in sites.items():
        metro = metro_of.get(code, s.get("metro") or code)
        for d in s.get("devices", []):
            node_meta[d["id"]] = {
                "id": d["id"], "kind": "switch", "site": code,
                "site_name": s.get("name") or code, "metro": metro,
                "label": d["id"]}
            occupants.setdefault(metro, []).append(d["id"])
        if not s.get("devices") and ("site:" + code) in endpoints:
            nid = "site:" + code
            node_meta[nid] = {
                "id": nid, "kind": "junction", "site": code,
                "site_name": s.get("name") or code, "metro": metro,
                "label": s.get("name") or code}
            occupants.setdefault(metro, []).append(nid)

    # ring the metros by connectivity: pair weight = physical strand count
    pair_weight = {}
    for l in links:
        ma = node_meta.get(l["a"], {}).get("metro")
        mz = node_meta.get(l["z"], {}).get("metro")
        if ma and mz and ma != mz:
            k = (min(ma, mz), max(ma, mz))
            pair_weight[k] = pair_weight.get(k, 0) + (l["members"] or 1)
    anchors = _metro_anchors(metros, pair_weight,
                             {m: len(o) for m, o in occupants.items()})

    # preferred angle per node: the direction of its external neighbours'
    # metro anchors — a node connected toward Fremont faces Fremont
    neighbours = {}
    for l in links:
        neighbours.setdefault(l["a"], []).append(l["z"])
        neighbours.setdefault(l["z"], []).append(l["a"])
    cx, cy = VIEW_W / 2, VIEW_H / 2
    prefer = {}
    for metro, occ in occupants.items():
        ax, ay = anchors.get(metro, (cx, cy))
        for nid in occ:
            vx = vy = 0.0
            for nb in neighbours.get(nid, []):
                nb_metro = node_meta.get(nb, {}).get("metro")
                if not nb_metro or nb_metro == metro:
                    continue
                bx, by = anchors.get(nb_metro, (cx, cy))
                d = math.hypot(bx - ax, by - ay) or 1.0
                vx += (bx - ax) / d
                vy += (by - ay) / d
            if vx or vy:
                prefer[nid] = math.atan2(vy, vx)
            else:  # intra-only nodes face away from the canvas centre
                prefer[nid] = math.atan2(ay - cy, ax - cx) if (ax, ay) != (cx, cy) else -math.pi / 2

    pos = {}
    for metro, occ in sorted(occupants.items()):
        pos.update(_seat_on_circle(anchors.get(metro, (cx, cy)), sorted(occ), prefer))
    pos = _push_apart(pos)
    pos = _fill_view(pos)

    nodes = []
    for nid in sorted(node_meta):
        if nid not in pos:
            continue
        n = dict(node_meta[nid])
        n["x"], n["y"] = round(pos[nid][0], 1), round(pos[nid][1], 1)
        nodes.append(n)

    # a link whose endpoint never materialised (site absent from map.json,
    # e.g. missing coordinates) can't be drawn — drop it rather than dangle
    have = {n["id"] for n in nodes}
    links = [l for l in links if l["a"] in have and l["z"] in have]

    metros_out = {
        name: {"x": round(anchors[name][0], 1), "y": round(anchors[name][1], 1),
               "codes": m.get("codes", [])}
        for name, m in metros.items() if name in anchors
    }
    return {
        "generation": mapjson.get("generation"),
        "generated_at": mapjson.get("generated_at"),
        "view": {"width": VIEW_W, "height": VIEW_H},
        "metros": metros_out,
        "nodes": nodes,
        "links": links,
    }
