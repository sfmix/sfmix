"""Derive the public weathermap structure from the built map.json.

The weathermap is the same backbone graph the geographic map draws, rendered
schematically: switches as boxes clustered by metro, links as straight strands
coloured by utilization (the classic network-weathermap look the old Grafana
dashboard provided). Rather than re-query NetBox, this is a pure function of
the already-built map.json — the cable ids stay identical, so the frontend
colours links from the SAME /statistics/map/traffic feed the geographic map
polls, and no second build pass or traffic endpoint exists.

Layout is deterministic and geography-flavoured: metro anchors are placed by
their lon/lat *rank* (equal spacing — rank, not raw coordinates, so nearby
metros never collide), and each metro's switches sit on a circle around its
anchor, grouped by site. A passive site with no switches (splice/patch
building) that terminates a drawn span becomes a small junction node so
chained circuits stay visually connected.
"""

VIEW_W, VIEW_H = 1000.0, 760.0
PAD = 170.0      # anchor inset: circle radius + node label box must fit inside
MAX_RADIUS = 96.0  # per-metro circle; PAD - MAX_RADIUS leaves label headroom


def _metro_anchors(metros):
    """Metro name -> (x, y): lon rank spaces metros across, lat rank down."""
    names = sorted(metros)
    if not names:
        return {}
    by_lon = sorted(names, key=lambda n: metros[n]["lon"])
    by_lat = sorted(names, key=lambda n: -metros[n]["lat"])  # north at the top
    span = max(len(names) - 1, 1)
    anchors = {}
    for n in names:
        fx = by_lon.index(n) / span if len(names) > 1 else 0.5
        fy = by_lat.index(n) / span if len(names) > 1 else 0.5
        anchors[n] = (PAD + fx * (VIEW_W - 2 * PAD), PAD + fy * (VIEW_H - 2 * PAD))
    return anchors


def _place_around(anchor, count, outward):
    """`count` positions on a circle around `anchor`, first slot facing away
    from the viewport centre (`outward`, radians) so labels tend to clear the
    inter-metro link corridor through the middle of the canvas."""
    import math
    ax, ay = anchor
    if count <= 1:
        return [(ax, ay)]
    r = min(46.0 + 18.0 * count, MAX_RADIUS)
    return [(ax + r * math.cos(outward + 2 * math.pi * i / count),
             ay + r * math.sin(outward + 2 * math.pi * i / count))
            for i in range(count)]


def weathermap_from_map(mapjson):
    """map.json dict -> weathermap.json dict (same generation + cable ids)."""
    import math
    sites = mapjson.get("sites", {})
    metros = mapjson.get("metros", {})
    anchors = _metro_anchors(metros)
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
    occupants = {}  # metro name -> [(sort_key, node dict), ...]
    for code, s in sites.items():
        metro = metro_of.get(code, s.get("metro") or code)
        for d in s.get("devices", []):
            occupants.setdefault(metro, []).append((
                (code, d["id"]),
                {"id": d["id"], "kind": "switch", "site": code,
                 "site_name": s.get("name") or code, "metro": metro,
                 "label": d["id"]}))
        if not s.get("devices") and ("site:" + code) in endpoints:
            occupants.setdefault(metro, []).append((
                (code, ""),
                {"id": "site:" + code, "kind": "junction", "site": code,
                 "site_name": s.get("name") or code, "metro": metro,
                 "label": s.get("name") or code}))

    cx, cy = VIEW_W / 2, VIEW_H / 2
    nodes = []
    for metro, occ in sorted(occupants.items()):
        ax, ay = anchors.get(metro, (cx, cy))
        outward = math.atan2(ay - cy, ax - cx) if (ax, ay) != (cx, cy) else -math.pi / 2
        occ.sort()
        for (_k, node), (x, y) in zip(occ, _place_around((ax, ay), len(occ), outward)):
            node["x"], node["y"] = round(x, 1), round(y, 1)
            nodes.append(node)

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
