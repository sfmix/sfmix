#!/usr/bin/env python3
# SFMIX weathermap layout lab. Computes readable, overlap-free node layouts for
# the tamirsuliman-weathermap-panel from the live LLDP topology (sflow-rt
# /topology/json) and pushes them as Grafana dashboards.
#
# Requires: graphviz (dot/neato/sfdp/fdp) locally; optional inkscape for the
# offline SVG->PNG previews. Reads a topo.json snapshot if present, else fetches
# live via SFLOW_URL / PROM_URL env (default localhost:8008 / :9090).
#
# Usage:
#   python3 weathermap_layouts.py                # score + preview all layouts
#   python3 weathermap_layouts.py emit           # write dashboard JSON per layout
# Layouts: metro_ring (grouped by POP, ring-ordered), sfdp/neato (force-directed).

import json
import math
import os
import subprocess
import sys
from collections import defaultdict, Counter

HERE = os.path.dirname(os.path.abspath(__file__))
TOPO = os.path.join(HERE, "topo.json")

# node bounding box in weathermap px (icon + label under it)
NW, NH = 140, 66
ICON_W, ICON_H = 46, 40

SITE_METRO = {"sfo01": "SF", "sfo02": "SF", "fmt01": "FMT",
              "scl01": "SCL", "scl02": "SCL", "scl04": "SCL", "scl05": "SCL",
              "sjc01": "SJC", "sjc02": "SJC"}
# geographic-ish ring order (secondary hint)
METRO_ORDER = ["SF", "FMT", "SJC", "SCL"]
METRO_NAME = {"SF": "San Francisco", "FMT": "Fremont",
              "SCL": "Santa Clara", "SJC": "San Jose"}
SPEED_W = {"1G": 2, "10G": 3, "25G": 3, "40G": 4, "100G": 5, "400G": 8, "800G": 10}
SPEED_BITS = {"1G": 1e9, "10G": 10e9, "25G": 25e9, "40G": 40e9,
              "100G": 100e9, "400G": 400e9, "800G": 800e9}
PROM_DS_UID = "y22GmBEVk"
# local, plugin-bundled icon (renders in headless renderer + browsers; the external
# sfmix.org SVG breaks in the image-renderer's chromium)
SWITCH_ICON = "public/plugins/tamirsuliman-weathermap-panel/icons/networking/switch.svg"
BLANK_ICON = "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="


def short(n):
    return ".".join(n.split(".")[:2])


def metro(n):
    return SITE_METRO.get(n.split(".")[1], "?")


def load_live():
    """Fetch topology live from sflow-rt + speeds from Prometheus (env URLs)."""
    import urllib.request
    sflow = os.environ.get("SFLOW_URL", "http://127.0.0.1:8008")
    prom = os.environ.get("PROM_URL", "http://127.0.0.1:9090")
    def g(u):
        with urllib.request.urlopen(u, timeout=30) as r:
            return json.load(r)
    import urllib.parse
    t = g(f"{sflow}/topology/json")
    # instant query returns only LIVE series (avoids stale label-sets, e.g. a
    # lingering ifspeed=1G from a past flap on a port that is really 100G).
    res = g(f"{prom}/api/v1/query?query="
            + urllib.parse.quote("sflow_ifoutoctets"))["data"]["result"]
    _rank = {"1G": 1, "10G": 10, "25G": 25, "40G": 40, "100G": 100, "400G": 400, "800G": 800}
    sp = {}
    for r in res:
        m = r["metric"]; k = (m.get("host"), m.get("ifname")); v = m.get("ifspeed")
        if k not in sp or _rank.get(v, 0) > _rank.get(sp[k], 0):
            sp[k] = v  # keep the highest live speed if duplicates
    links = [{"name": n, "node1": l["node1"], "port1": l["port1"],
              "node2": l["node2"], "port2": l["port2"],
              "speed1": sp.get((l["node1"], l["port1"])),
              "speed2": sp.get((l["node2"], l["port2"]))}
             for n, l in t["links"].items()]
    return {"nodes": sorted(t["nodes"].keys()), "links": links}


def load():
    t = json.load(open(TOPO)) if os.path.exists(TOPO) else load_live()
    nodes = sorted(short(n) for n in t["nodes"])
    edges = []
    for l in t["links"]:
        a, b = short(l["node1"]), short(l["node2"])
        sp = l.get("speed1") or l.get("speed2") or "100G"
        # nominal capacity = max of both ends
        cap = max(SPEED_W.get(l.get("speed1"), 5), SPEED_W.get(l.get("speed2"), 5))
        bits = max(SPEED_BITS.get(l.get("speed1"), 100e9),
                   SPEED_BITS.get(l.get("speed2"), 100e9))
        edges.append({"a": a, "b": b, "cap": cap, "bits": int(bits), "name": l["name"],
                      "q1": f'{l["node1"]}-{l["port1"]}',
                      "q2": f'{l["node2"]}-{l["port2"]}',
                      "n1": l["node1"], "p1": l["port1"],
                      "n2": l["node2"], "p2": l["port2"]})
    return nodes, edges


# ---------------------------------------------------------------------------
# graphviz layouts -> {node: (x,y)} in px
# ---------------------------------------------------------------------------
def _run_gv(dot, engine, extra=None):
    cmd = [engine, "-Tjson"] + (extra or [])
    out = subprocess.run(cmd, input=dot, capture_output=True, text=True, check=True).stdout
    j = json.loads(out)
    pos = {}
    for o in j.get("objects", []):
        if "pos" in o and "name" in o:
            x, y = o["pos"].split(",")
            pos[o["name"]] = (float(x), float(y))
    return pos


def _node_stanza():
    w_in, h_in = NW / 72.0, NH / 72.0
    return f'node [shape=box, fixedsize=true, width={w_in:.3f}, height={h_in:.3f}];\n'


def layout_plain(nodes, edges, engine, extra=None):
    dot = ["graph G {", _node_stanza()]
    for n in nodes:
        dot.append(f'"{n}";')
    for e in edges:
        dot.append(f'"{e["a"]}" -- "{e["b"]}";')
    dot.append("}")
    return _run_gv("\n".join(dot), engine, extra)


def layout_clustered(nodes, edges, engine, extra=None):
    """Metros as graphviz clusters (fdp/dot honor clusters)."""
    by_metro = defaultdict(list)
    for n in nodes:
        by_metro[metro(n)].append(n)
    dot = ["graph G {", _node_stanza(), "compound=true;"]
    for mi, m in enumerate(METRO_ORDER):
        dot.append(f'subgraph cluster_{m} {{')
        dot.append(f'label="{METRO_NAME[m]}"; fontsize=28; fontcolor="#8899aa"; '
                   f'style=rounded; color="#33404d";')
        for n in sorted(by_metro.get(m, [])):
            dot.append(f'"{n}";')
        dot.append("}")
    for e in edges:
        dot.append(f'"{e["a"]}" -- "{e["b"]}";')
    dot.append("}")
    return _run_gv("\n".join(dot), engine, extra)


def _cluster_layout(mem, sub_edges, cell_w, cell_h):
    """Lay out a metro's switches inside a cell, guaranteeing spacing."""
    if len(mem) == 1:
        return {mem[0]: (0.0, 0.0)}
    dot = ["graph G {", _node_stanza(), 'overlap=false; sep="+40,50";']
    for n in mem:
        dot.append(f'"{n}";')
    for e in sub_edges:
        dot.append(f'"{e["a"]}" -- "{e["b"]}";')
    dot.append("}")
    sp = _run_gv("\n".join(dot), "neato", ["-Goverlap=false", "-Gsep=+40,50"]) \
        or {n: (i * (NW + 60), 0.0) for i, n in enumerate(mem)}
    # scale sub-layout to fill the cell (keeps intra-cluster gaps generous)
    xs = [p[0] for p in sp.values()]; ys = [p[1] for p in sp.values()]
    sw = (max(xs) - min(xs)) or 1; sh = (max(ys) - min(ys)) or 1
    sx = cell_w / sw; sy = cell_h / sh
    mx, my = (min(xs) + max(xs)) / 2, (min(ys) + max(ys)) / 2
    return {n: ((x - mx) * sx, (y - my) * sy) for n, (x, y) in sp.items()}


def layout_metro_regions(nodes, edges):
    """Metros in ring order at 4 corners (topology: inter-metro links become the
    4 rectangle edges, no diagonals; also ~matches Bay geography). Each metro's
    switches are laid out internally with neato and scaled for clear spacing."""
    by_metro = defaultdict(list)
    for n in nodes:
        by_metro[metro(n)].append(n)
    # ring order SF-FMT-SJC-SCL-SF -> corners so adjacent metros are adjacent
    REG = {"SF": (0, 1150), "FMT": (1900, 1150), "SJC": (1900, 0), "SCL": (0, 0)}
    # cell size scaled to node count so dense metros (SCL/SJC) get more room
    pos = {}
    for m, (cx, cy) in REG.items():
        mem = sorted(by_metro.get(m, []))
        sub_edges = [e for e in edges if e["a"] in mem and e["b"] in mem]
        span = 260 + 150 * (len(mem) - 1)
        sp = _cluster_layout(mem, sub_edges, min(span, 620), min(span, 520))
        for n, (x, y) in sp.items():
            pos[n] = (cx + x, cy + y)
    return pos


def remove_overlaps(pos, pad=26, iters=400):
    """Iterative push-apart so no two node bboxes overlap. Guarantees clean map."""
    names = list(pos)
    P = {n: [pos[n][0], pos[n][1]] for n in names}
    for _ in range(iters):
        moved = False
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                a, b = names[i], names[j]
                ax, ay = P[a]; bx, by = P[b]
                ox = (NW + pad) - abs(ax - bx)
                oy = (NH + pad) - abs(ay - by)
                if ox > 0 and oy > 0:  # overlapping -> push along smaller axis
                    moved = True
                    if ox < oy:
                        s = ox / 2 * (1 if ax >= bx else -1)
                        P[a][0] += s; P[b][0] -= s
                    else:
                        s = oy / 2 * (1 if ay >= by else -1)
                        P[a][1] += s; P[b][1] -= s
        if not moved:
            break
    return {n: (P[n][0], P[n][1]) for n in names}


# ---------------------------------------------------------------------------
# normalize + metrics
# ---------------------------------------------------------------------------
def normalize(pos, margin=90, target_w=1600):
    if not pos:
        return pos
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
    w = (maxx - minx) or 1
    scale = (target_w - 2 * margin) / w
    scale = min(scale, 3.0)  # don't over-inflate small graphs
    out = {}
    for n, (x, y) in pos.items():
        out[n] = ((x - minx) * scale + margin, (maxy - y) * scale + margin)  # flip y
    return out


def bbox(p):
    x, y = p
    return (x - NW / 2, y - NH / 2, x + NW / 2, y + NH / 2)


def rects_overlap(r1, r2, pad=0):
    return not (r1[2] + pad <= r2[0] or r2[2] + pad <= r1[0] or
                r1[3] + pad <= r2[1] or r2[3] + pad <= r1[1])


def seg_intersect(p1, p2, p3, p4):
    def ccw(a, b, c):
        return (c[1] - a[1]) * (b[0] - a[0]) - (b[1] - a[1]) * (c[0] - a[0])
    d1 = ccw(p3, p4, p1); d2 = ccw(p3, p4, p2)
    d3 = ccw(p1, p2, p3); d4 = ccw(p1, p2, p4)
    if ((d1 > 0) != (d2 > 0)) and ((d3 > 0) != (d4 > 0)):
        return True
    return False


def seg_hits_rect(p1, p2, r):
    # any of rect's 4 edges intersect segment, or segment endpoint inside
    corners = [(r[0], r[1]), (r[2], r[1]), (r[2], r[3]), (r[0], r[3])]
    for i in range(4):
        if seg_intersect(p1, p2, corners[i], corners[(i + 1) % 4]):
            return True
    return False


def metrics(pos, edges):
    ns = list(pos)
    node_ov = 0
    min_gap = 1e9
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            r1, r2 = bbox(pos[ns[i]]), bbox(pos[ns[j]])
            if rects_overlap(r1, r2):
                node_ov += 1
            # gap
            dx = max(0, max(r1[0] - r2[2], r2[0] - r1[2]))
            dy = max(0, max(r1[1] - r2[3], r2[1] - r1[3]))
            min_gap = min(min_gap, math.hypot(dx, dy) if (dx or dy) else 0)
    # edge crossings
    segs = [(pos[e["a"]], pos[e["b"]], e) for e in edges if e["a"] in pos and e["b"] in pos]
    cross = 0
    for i in range(len(segs)):
        for j in range(i + 1, len(segs)):
            a1, a2, e1 = segs[i]; b1, b2, e2 = segs[j]
            if {e1["a"], e1["b"]} & {e2["a"], e2["b"]}:
                continue  # share a node
            if seg_intersect(a1, a2, b1, b2):
                cross += 1
    # edge passes through a non-endpoint node box
    edge_node = 0
    for a1, a2, e in segs:
        for n in ns:
            if n in (e["a"], e["b"]):
                continue
            if seg_hits_rect(a1, a2, bbox(pos[n])):
                edge_node += 1
    total_len = sum(math.hypot(a2[0] - a1[0], a2[1] - a1[1]) for a1, a2, _ in segs)
    xs = [p[0] for p in pos.values()]; ys = [p[1] for p in pos.values()]
    w = max(xs) - min(xs) or 1; h = max(ys) - min(ys) or 1
    aspect = max(w, h) / min(w, h)
    score = (node_ov * 1000 + edge_node * 300 + cross * 25 +
             total_len / 1000 + max(0, aspect - 2.2) * 40)
    return {"node_overlaps": node_ov, "edge_node": edge_node, "crossings": cross,
            "min_gap": round(min_gap, 1), "edge_len": round(total_len),
            "aspect": round(aspect, 2), "SCORE": round(score, 1)}


# ---------------------------------------------------------------------------
# SVG preview (faithful-ish to the weathermap panel) + PNG via inkscape
# ---------------------------------------------------------------------------
def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_svg(pos, edges, path, title=""):
    xs = [p[0] for p in pos.values()]; ys = [p[1] for p in pos.values()]
    W = int(max(xs) + NW); H = int(max(ys) + NH + 40)
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
         f'viewBox="0 0 {W} {H}">']
    s.append(f'<rect width="{W}" height="{H}" fill="#181b1f"/>')
    if title:
        s.append(f'<text x="20" y="30" fill="#c8c8dc" font-family="sans-serif" '
                 f'font-size="22" font-weight="bold">{esc(title)}</text>')
    # metro labels at centroid of each metro's nodes
    by_metro = defaultdict(list)
    for n in pos:
        by_metro[metro(n)].append(pos[n])
    for m, pts in by_metro.items():
        cx = sum(p[0] for p in pts) / len(pts)
        top = max(28, min(p[1] for p in pts) - NH / 2 - 16)
        s.append(f'<text x="{cx:.0f}" y="{top:.0f}" fill="#5b6b7d" '
                 f'font-family="sans-serif" font-size="26" font-weight="bold" '
                 f'text-anchor="middle" opacity="0.6">{esc(METRO_NAME.get(m,m))}</text>')
    # edges
    for e in edges:
        if e["a"] not in pos or e["b"] not in pos:
            continue
        (x1, y1), (x2, y2) = pos[e["a"]], pos[e["b"]]
        w = e["cap"]
        s.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
                 f'stroke="#6f7f90" stroke-width="{w}" stroke-opacity="0.75"/>')
        # endpoint throughput label placeholders (to expose label crowding)
        for (nx, ny), (ox, oy) in ((pos[e["a"]], (x2, y2)), (pos[e["b"]], (x1, y1))):
            t = 0.30
            lx = nx + (ox - nx) * t; ly = ny + (oy - ny) * t
            s.append(f'<rect x="{lx-16:.0f}" y="{ly-8:.0f}" width="32" height="14" '
                     f'rx="3" fill="#2a2f37" fill-opacity="0.7"/>')
    # nodes
    for n, (x, y) in pos.items():
        ix, iy = x - ICON_W / 2, y - ICON_H / 2 - 6
        s.append(f'<rect x="{ix:.0f}" y="{iy:.0f}" width="{ICON_W}" height="{ICON_H}" '
                 f'rx="5" fill="#20779c" stroke="#3fa7d6" stroke-width="1.5"/>')
        s.append(f'<text x="{x:.0f}" y="{y+ICON_H/2+12:.0f}" fill="#d8d8e0" '
                 f'font-family="sans-serif" font-size="15" text-anchor="middle">{esc(n)}</text>')
    s.append("</svg>")
    open(path, "w").write("\n".join(s))
    png = path.replace(".svg", ".png")
    subprocess.run(["inkscape", path, "--export-type=png", f"--export-filename={png}",
                    "--export-background=#181b1f"], capture_output=True)
    return png


LAYOUTS = {
    "neato": lambda n, e: layout_plain(n, e, "neato", ["-Goverlap=false", "-Gsep=+30,30"]),
    "sfdp": lambda n, e: layout_plain(n, e, "sfdp", ["-Goverlap=prism", "-GK=1.2"]),
    "fdp": lambda n, e: layout_plain(n, e, "fdp", ["-Goverlap=false", "-Gsep=+30,30"]),
    "dot": lambda n, e: layout_plain(n, e, "dot"),
    "twopi": lambda n, e: layout_plain(n, e, "twopi", ["-Goverlap=false"]),
    "circo": lambda n, e: layout_plain(n, e, "circo", ["-Goverlap=false"]),
    "clustered_fdp": lambda n, e: layout_clustered(n, e, "fdp", ["-Goverlap=false", "-Gsep=+30,30"]),
    "clustered_dot": lambda n, e: layout_clustered(n, e, "dot"),
    "metro_ring": lambda n, e: layout_metro_regions(n, e),
}


# ---------------------------------------------------------------------------
# Real Grafana weathermap dashboard from computed positions
# ---------------------------------------------------------------------------
import uuid
NS = uuid.UUID("5f1e9d0c-0000-4000-8000-5f6d6978aabb")


def uid5(*p):
    return str(uuid.uuid5(NS, "|".join(p)))


def _colors():
    return {"background": "rgba(204,204,220,0.10)", "border": "rgba(204,204,220,0.08)",
            "font": "rgb(204,204,220)", "statusDown": "#ff0000"}


def _anchors():
    return {str(i): {"numFilledLinks": 0, "numLinks": 0} for i in range(5)}


def _node(label, x, y, is_label=False):
    return {"anchors": _anchors(), "colors": _colors(), "compactVerticalLinks": False,
            "id": uid5("node", label), "isConnection": False, "label": label,
            "nodeIcon": {"drawInside": not is_label, "name": "n",
                         "padding": {"horizontal": 0, "vertical": 1},
                         "size": {"height": 1, "width": 1} if is_label
                                 else {"height": 44, "width": 44},
                         "src": BLANK_ICON if is_label else SWITCH_ICON},
            "padding": {"horizontal": 2, "vertical": 2}, "position": [round(x), round(y)],
            "useConstantSpacing": False}


def stroke_for(bits):
    """Link line width by capacity — gentle (~sqrt) so 400G reads thicker than
    100G without dwarfing it."""
    g = bits / 1e9
    if g >= 800: return 16
    if g >= 400: return 12
    if g >= 100: return 6
    if g >= 40: return 5
    if g >= 25: return 4
    if g >= 10: return 3
    return 2


def build_weathermap(pos, edges, with_metro_labels):
    nodes = {n: _node(n, x, y) for n, (x, y) in pos.items()}
    labels = []
    if with_metro_labels:
        by = defaultdict(list)
        for n in pos:
            by[metro(n)].append(pos[n])
        for m, pts in by.items():
            cx = sum(p[0] for p in pts) / len(pts)
            top = min(p[1] for p in pts) - 60
            labels.append(_node(METRO_NAME.get(m, m), cx, top, is_label=True))
    # Group edges by unordered node pair so parallel links (e.g. a 100G + a 400G
    # between the same two switches) can be given DISTINCT anchors — otherwise
    # both route on anchor 0 (auto) between the same points and overlap, hiding
    # one. Single links keep anchor 0 (clean auto-routing toward the peer).
    ANCHOR_CYCLE = [1, 2, 3, 4]
    by_pair = defaultdict(list)
    for e in edges:
        if e["a"] in nodes and e["b"] in nodes:
            by_pair[frozenset([e["a"], e["b"]])].append(e)
    links = []
    per_anchor = defaultdict(lambda: Counter())  # node -> {anchorIdx: count}
    for pair, es in by_pair.items():
        for i, e in enumerate(es):
            anc = 0 if len(es) == 1 else ANCHOR_CYCLE[i % len(ANCHOR_CYCLE)]
            per_anchor[e["a"]][anc] += 1
            per_anchor[e["b"]][anc] += 1
            links.append({
                "arrows": {"height": 10, "offset": 2, "width": 8},
                "id": uid5("link", *sorted([e["q1"], e["q2"]])),
                "nodes": [nodes[e["a"]], nodes[e["b"]]],
                "showThroughputPercentage": True,
                "sides": {"A": {"anchor": anc, "bandwidth": e["bits"], "dashboardLink": "",
                                "labelOffset": 60, "query": e["q1"]},
                          "Z": {"anchor": anc, "bandwidth": e["bits"], "dashboardLink": "",
                                "labelOffset": 60, "query": e["q2"]}},
                "stroke": stroke_for(e["bits"])})
    for n, nd in nodes.items():
        for anc, cnt in per_anchor.get(n, {}).items():
            nd["anchors"][str(anc)]["numLinks"] = cnt
    allpos = list(pos.values()) + [(l["position"][0], l["position"][1]) for l in labels]
    maxx = max(p[0] for p in allpos) + 120
    maxy = max(p[1] for p in allpos) + 90
    # scale.position is a PERCENT of canvas; park legend in whitespace
    # (ring: centre; force-directed: top-left corner)
    scx, scy = (43, 40) if with_metro_labels else (1, 3)
    return {"id": uid5("wm", "x"), "links": links,
            "nodes": list(nodes.values()) + labels,
            "scale": [{"color": "#5794F2", "percent": 0}, {"color": "#73BF69", "percent": 20},
                      {"color": "#FADE2A", "percent": 40}, {"color": "#FF9830", "percent": 60},
                      {"color": "#F2495C", "percent": 80}],
            "settings": {"fontSizing": {"link": 12, "node": 14},
                         "link": {"label": {"background": "rgba(204,204,220,0.10)",
                                            "border": "rgba(204,204,220,0.08)",
                                            "font": "rgb(204,204,220)"},
                                  "showAllWithPercentage": False,
                                  "spacing": {"horizontal": 13, "vertical": 30},
                                  "stroke": {"color": "rgba(204,204,220,0.10)"}},
                         "panel": {"backgroundColor": "#181b1f",
                                   "grid": {"enabled": False, "guidesEnabled": False, "size": 16},
                                   "offset": {"x": 0, "y": 0},
                                   "panelSize": {"height": round(maxy), "width": round(maxx)},
                                   "showTimestamp": True, "zoomScale": 0},
                         "scale": {"fontSizing": {"threshold": 10, "title": 14},
                                   "position": {"x": scx, "y": scy},
                                   "size": {"height": 150, "width": 55}, "title": "% of link"},
                         "tooltip": {"backgroundColor": "black", "fontSize": 14,
                                     "inboundColor": "#00cf00", "outboundColor": "#fade2a",
                                     "scaleToBandwidth": False, "textColor": "white"}},
            "version": 1}


def build_dashboard(pos, edges, uid, title, with_metro_labels):
    wm = build_weathermap(pos, edges, with_metro_labels)
    panel = {"id": 1, "type": "tamirsuliman-weathermap-panel", "title": "",
             "datasource": {"type": "prometheus", "uid": PROM_DS_UID},
             "gridPos": {"h": 24, "w": 24, "x": 0, "y": 0},
             "targets": [{"datasource": {"type": "prometheus", "uid": PROM_DS_UID},
                          "editorMode": "builder", "expr": "sflow_ifoutoctets * 8",
                          "instant": False, "legendFormat": "{{host}}-{{ifname}}",
                          "range": True, "refId": "A"}],
             "fieldConfig": {"defaults": {}, "overrides": []},
             "options": {"weathermap": wm}}
    return {"dashboard": {"uid": uid, "title": title, "tags": ["network", "auto-generated", "proto"],
                          "timezone": "browser", "schemaVersion": 39, "refresh": "30s",
                          "time": {"from": "now-1h", "to": "now"}, "panels": [panel]},
            "folderUid": "", "overwrite": True, "message": "layout prototype"}


# uid, title, layout, metro-labels
EMIT = [
    ("wm-proto-ring", "Weathermap · Metro Ring (proto)", "metro_ring", True),
    ("wm-proto-sfdp", "Weathermap · Force-Directed (proto)", "sfdp", False),
    ("wm-proto-neato", "Weathermap · Spring/neato (proto)", "neato", False),
]


def emit():
    nodes, edges = load()
    for uid, title, lay, mlab in EMIT:
        pos = remove_overlaps(normalize(LAYOUTS[lay](nodes, edges), target_w=1800))
        dash = build_dashboard(pos, edges, uid, title, mlab)
        path = os.path.join(HERE, "previews", f"{uid}.dash.json")
        json.dump(dash, open(path, "w"))
        print("wrote", path, f"({len(pos)} nodes, {len(edges)} links)")


def emit_one(uid, title, folder_uid, layout="metro_ring", mlab=True):
    nodes, edges = load()
    pos = remove_overlaps(normalize(LAYOUTS[layout](nodes, edges), target_w=1800))
    dash = build_dashboard(pos, edges, uid, title, mlab)
    dash["folderUid"] = folder_uid
    path = os.path.join(HERE, "previews", f"{uid}.dash.json")
    json.dump(dash, open(path, "w"))
    print("wrote", path, f"({len(pos)} nodes, {len(edges)} links, layout={layout})")


def push_dashboard(dash):
    """POST a dashboard to Grafana. Bearer GRAFANA_TOKEN (service account) or
    basic GRAFANA_USER/GRAFANA_PASS. GRAFANA_URL default localhost:3000."""
    import urllib.request
    url = os.environ.get("GRAFANA_URL", "http://127.0.0.1:3000")
    headers = {"Content-Type": "application/json"}
    tok = os.environ.get("GRAFANA_TOKEN")
    if tok:
        headers["Authorization"] = "Bearer " + tok
    else:
        import base64
        u = os.environ.get("GRAFANA_USER", "admin")
        p = os.environ.get("GRAFANA_PASS", "")
        headers["Authorization"] = "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()
    req = urllib.request.Request(url + "/api/dashboards/db",
                                 data=json.dumps(dash).encode(), method="POST",
                                 headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def refresh(uid, title, folder_uid, layout="metro_ring"):
    """Rebuild the weathermap from live topology and push it to Grafana."""
    nodes, edges = load()
    pos = remove_overlaps(normalize(LAYOUTS[layout](nodes, edges), target_w=1800))
    dash = build_dashboard(pos, edges, uid, title, layout == "metro_ring")
    dash["folderUid"] = folder_uid
    res = push_dashboard(dash)
    print("weathermap refresh: status=%s uid=%s version=%s (%d nodes, %d links, %s)"
          % (res.get("status"), res.get("uid"), res.get("version"),
             len(pos), len(edges), layout))
    return 0 if res.get("status") == "success" else 1


def main():
    if sys.argv[1:2] == ["refresh"]:
        # refresh <uid> <title> <folderUid> [layout]
        return refresh(sys.argv[2], sys.argv[3], sys.argv[4],
                       sys.argv[5] if len(sys.argv) > 5 else "metro_ring")
    if sys.argv[1:2] == ["emit"]:
        return emit()
    if sys.argv[1:2] == ["emit-one"]:
        # emit-one <uid> <title> <folderUid> [layout]
        return emit_one(sys.argv[2], sys.argv[3], sys.argv[4],
                        sys.argv[5] if len(sys.argv) > 5 else "metro_ring")
    which = sys.argv[1:] or [k for k in LAYOUTS]
    nodes, edges = load()
    results = []
    for name in which:
        if name not in LAYOUTS:
            continue
        try:
            pos = normalize(LAYOUTS[name](nodes, edges), target_w=1800)
            pos = remove_overlaps(pos)
        except Exception as ex:
            print(f"{name}: FAILED {ex}")
            continue
        if len(pos) != len(nodes):
            print(f"{name}: only placed {len(pos)}/{len(nodes)} nodes")
        m = metrics(pos, edges)
        png = render_svg(pos, edges, os.path.join(HERE, "previews", f"{name}.svg"),
                         title=f"{name}  score={m['SCORE']}")
        json.dump({"layout": name, "pos": pos, "metrics": m},
                  open(os.path.join(HERE, "previews", f"{name}.json"), "w"))
        results.append((m["SCORE"], name, m))
    results.sort()
    print(f"\n{'layout':16} {'score':>8} {'nOv':>4} {'e-node':>6} {'cross':>5} "
          f"{'minGap':>6} {'aspect':>6}")
    for sc, name, m in results:
        print(f"{name:16} {m['SCORE']:8.1f} {m['node_overlaps']:4} {m['edge_node']:6} "
              f"{m['crossings']:5} {m['min_gap']:6} {m['aspect']:6}")


if __name__ == "__main__":
    main()
