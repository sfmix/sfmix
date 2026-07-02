#!/usr/bin/env python3
"""Generate / verify the SFMIX Grafana weathermap from live LLDP topology.

The physical topology is discovered from LLDP by roles/sflow_rt/templates/
topology.py.j2 (eAPI `show lldp neighbors`, refreshed every 12h) and pushed to
sflow-rt's /topology/json.  sflow-rt is therefore an LLDP-derived, metric-aligned
source of truth: every link it knows about has a matching `sflow_ifoutoctets`
series keyed `{host}-{ifname}` (the weathermap panel's legend format).

This tool reads that topology, enriches per-interface link speed / oper-status
from Prometheus, and emits the `tamirsuliman-weathermap-panel` options model.

Modes:
  --check      Diff the current weathermap(s) against live topology; report
               missing / stale nodes & links. Exit 1 if drift is found.
  --generate   Build the weathermap and POST it to Grafana as a NEW dashboard
               (default uid: weathermap-auto) — non-destructive.
  --dry-run    With --generate, print the dashboard JSON instead of POSTing.

Endpoints/creds via env (sensible localhost defaults for metrics.sfo02):
  SFLOW_URL   (http://127.0.0.1:8008)
  PROM_URL    (http://127.0.0.1:9090)
  GRAFANA_URL (http://127.0.0.1:3000)
  GRAFANA_USER / GRAFANA_PASS   (required for --generate and --check)
"""
import argparse
import base64
import json
import os
import sys
import urllib.request
import uuid
from collections import defaultdict

SFLOW_URL = os.environ.get("SFLOW_URL", "http://127.0.0.1:8008")
PROM_URL = os.environ.get("PROM_URL", "http://127.0.0.1:9090")
GRAFANA_URL = os.environ.get("GRAFANA_URL", "http://127.0.0.1:3000")
GRAFANA_USER = os.environ.get("GRAFANA_USER", "admin")
GRAFANA_PASS = os.environ.get("GRAFANA_PASS", "")

# Deterministic UUIDs so re-runs are stable (idempotent updates, stable link ids)
NS = uuid.UUID("5f1e9d0c-0000-4000-8000-5f6d6978aabb")

PROM_DS_UID = os.environ.get("PROM_DS_UID", "y22GmBEVk")
SWITCH_ICON = "https://sfmix.org/wp-content/uploads/2024/07/Arista_DCS-7280SR2-48YC6.svg"
# 1x1 transparent gif — label-only nodes (metro headers) carry no visible icon
BLANK_ICON = "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="

# Geographic left->right ordering of metros and the site codes in each.
METROS = [
    ("San Francisco", ["sfo01", "sfo02"]),
    ("Fremont", ["fmt01"]),
    ("Santa Clara", ["scl01", "scl02", "scl04", "scl05"]),
    ("San Jose", ["sjc01", "sjc02"]),
]
COL_W = 280   # horizontal spacing between metro columns
ROW_H = 110   # vertical spacing between switches in a column

SPEED_BITS = {"1G": 1e9, "10G": 10e9, "25G": 25e9, "40G": 40e9,
              "100G": 100e9, "400G": 400e9, "800G": 800e9}


def _get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def _auth_header():
    tok = base64.b64encode(f"{GRAFANA_USER}:{GRAFANA_PASS}".encode()).decode()
    return {"Authorization": "Basic " + tok}


def _grafana(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(GRAFANA_URL + path, data=data, method=method,
                                 headers={**_auth_header(),
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def uid5(*parts):
    return str(uuid.uuid5(NS, "|".join(parts)))


def site_of(node):
    # switch01.fmt01.sfmix.org -> fmt01
    return node.split(".")[1]


def short(node):
    # switch01.fmt01.sfmix.org -> switch01.fmt01
    return ".".join(node.split(".")[:2])


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------
def fetch_topology():
    t = _get(f"{SFLOW_URL}/topology/json")
    return t.get("nodes", {}), t.get("links", {})


def fetch_iface_facts():
    """Return {(host, ifname): {'speed': '100G', 'oper': 'up'}} from Prometheus."""
    q = "%7B__name__%3D%22sflow_ifoutoctets%22%7D"  # {__name__="sflow_ifoutoctets"}
    d = _get(f"{PROM_URL}/api/v1/series?match[]={q}")["data"]
    facts = {}
    for s in d:
        facts[(s.get("host"), s.get("ifname"))] = {
            "speed": s.get("ifspeed"), "oper": s.get("ifoperstatus")}
    return facts


def bandwidth(facts, host, ifname):
    sp = (facts.get((host, ifname)) or {}).get("speed")
    return int(SPEED_BITS.get(sp, 100e9))


# ---------------------------------------------------------------------------
# Weathermap model construction
# ---------------------------------------------------------------------------
def node_colors():
    return {"background": "rgba(204, 204, 220, 0.10)",
            "border": "rgba(204, 204, 220, 0.08)",
            "font": "rgb(204, 204, 220)", "statusDown": "#ff0000"}


def empty_anchors():
    return {str(i): {"numFilledLinks": 0, "numLinks": 0} for i in range(5)}


def make_node(label, x, y, is_label=False):
    return {
        "anchors": empty_anchors(),
        "colors": node_colors(),
        "compactVerticalLinks": False,
        "id": uid5("node", label),
        "isConnection": False,
        "label": label,
        "nodeIcon": {
            "drawInside": not is_label,
            "name": "sfmix-label" if is_label else "arista",
            "padding": {"horizontal": 0, "vertical": 1},
            "size": {"height": 1, "width": 1} if is_label
                    else {"height": 25, "width": 150},
            "src": BLANK_ICON if is_label else SWITCH_ICON,
        },
        "padding": {"horizontal": 2, "vertical": 2},
        "position": [x, y],
        "useConstantSpacing": False,
    }


def layout_nodes(topo_nodes):
    """Cluster switches into metro columns; return {short_name: node} plus labels."""
    by_site = defaultdict(list)
    for n in topo_nodes:
        by_site[site_of(n)].append(short(n))

    nodes = {}
    label_nodes = []
    for col, (metro, sites) in enumerate(METROS):
        members = []
        for site in sites:
            members += sorted(by_site.get(site, []))
        if not members:
            continue
        x = col * COL_W
        # vertically center the column around y=0
        y0 = -((len(members) - 1) * ROW_H) // 2
        for row, name in enumerate(members):
            nodes[name] = make_node(name, x, y0 + row * ROW_H)
        label_nodes.append(make_node(metro, x, y0 - ROW_H, is_label=True))

    # any switch whose site isn't in METROS: park it in an "Other" column
    placed = set(nodes)
    leftover = sorted(short(n) for n in topo_nodes if short(n) not in placed)
    if leftover:
        x = len(METROS) * COL_W
        y0 = -((len(leftover) - 1) * ROW_H) // 2
        for row, name in enumerate(leftover):
            nodes[name] = make_node(name, x, y0 + row * ROW_H)
        label_nodes.append(make_node("Other", x, y0 - ROW_H, is_label=True))

    return nodes, label_nodes


def make_link(topo_link, nodes, facts):
    n1, p1 = topo_link["node1"], topo_link["port1"]
    n2, p2 = topo_link["node2"], topo_link["port2"]
    a_node = nodes.get(short(n1))
    z_node = nodes.get(short(n2))
    if not a_node or not z_node:
        return None  # endpoint not laid out (shouldn't happen)
    # A fabric link is symmetric; use the higher of the two ends as the nominal
    # capacity so a single mis-negotiated/mislabelled end doesn't skew the %.
    link_bw = max(bandwidth(facts, n1, p1), bandwidth(facts, n2, p2))
    return {
        "arrows": {"height": 10, "offset": 2, "width": 8},
        "id": uid5("link", *sorted([f"{n1}-{p1}", f"{n2}-{p2}"])),
        "nodes": [a_node, z_node],
        "showThroughputPercentage": True,
        "sides": {
            "A": {"anchor": 0, "bandwidth": link_bw,
                  "dashboardLink": "", "labelOffset": 60,
                  "query": f"{n1}-{p1}"},
            "Z": {"anchor": 0, "bandwidth": link_bw,
                  "dashboardLink": "", "labelOffset": 60,
                  "query": f"{n2}-{p2}"},
        },
        "stroke": 8,
    }


def count_anchors(nodes, links):
    """Populate anchor 0 numLinks with each node's degree (auto-routing)."""
    deg = defaultdict(int)
    # degree by node label from embedded endpoints
    for l in links:
        for nd in l["nodes"]:
            deg[nd["label"]] += 1
    for name, node in nodes.items():
        node["anchors"]["0"]["numLinks"] = deg.get(name, 0)


def build_weathermap(topo_nodes, topo_links, facts):
    nodes, label_nodes = layout_nodes(topo_nodes)
    links = []
    for name, tl in sorted(topo_links.items()):
        lk = make_link(tl, nodes, facts)
        if lk:
            links.append(lk)
    count_anchors(nodes, links)
    all_nodes = list(nodes.values()) + label_nodes
    return {
        "id": uid5("weathermap", "sfmix-auto"),
        "links": links,
        "nodes": all_nodes,
        "scale": [
            {"color": "#5794F2", "percent": 0},
            {"color": "#73BF69", "percent": 20},
            {"color": "#FADE2A", "percent": 40},
            {"color": "#FF9830", "percent": 60},
            {"color": "#F2495C", "percent": 80},
        ],
        "settings": {
            "fontSizing": {"link": 14, "node": 14},
            "link": {"label": {"background": "rgba(204, 204, 220, 0.10)",
                               "border": "rgba(204, 204, 220, 0.08)",
                               "font": "rgb(204, 204, 220)"},
                     "showAllWithPercentage": False,
                     "spacing": {"horizontal": 13, "vertical": 30},
                     "stroke": {"color": "rgba(204, 204, 220, 0.10)"}},
            "panel": {"backgroundColor": "#181b1f",
                      "grid": {"enabled": True, "guidesEnabled": False, "size": 16},
                      "offset": {"x": 0, "y": 0},
                      "panelSize": {"height": 700, "width": 1200},
                      "showTimestamp": True, "zoomScale": 0},
            "scale": {"fontSizing": {"threshold": 10, "title": 14},
                      "position": {"x": 49, "y": 0},
                      "size": {"height": 150, "width": 55}, "title": "bps % of link"},
            "tooltip": {"backgroundColor": "black", "fontSize": 14,
                        "inboundColor": "#00cf00", "outboundColor": "#fade2a",
                        "scaleToBandwidth": False, "textColor": "white"},
        },
        "version": 1,
    }


def build_dashboard(weathermap, uid, title):
    panel = {
        "id": 1,
        "type": "tamirsuliman-weathermap-panel",
        "title": "",
        "datasource": {"type": "prometheus", "uid": PROM_DS_UID},
        "gridPos": {"h": 22, "w": 24, "x": 0, "y": 0},
        "targets": [{"datasource": {"type": "prometheus", "uid": PROM_DS_UID},
                     "editorMode": "builder", "expr": "sflow_ifoutoctets * 8",
                     "instant": False, "legendFormat": "{{host}}-{{ifname}}",
                     "range": True, "refId": "A"}],
        "fieldConfig": {"defaults": {}, "overrides": []},
        "options": {"weathermap": weathermap},
    }
    return {
        "dashboard": {
            "uid": uid, "title": title, "tags": ["network", "auto-generated"],
            "timezone": "browser", "schemaVersion": 39,
            "refresh": "30s", "time": {"from": "now-1h", "to": "now"},
            "panels": [panel],
        },
        "folderUid": "", "overwrite": True,
        "message": "auto-generated from sflow-rt LLDP topology",
    }


# ---------------------------------------------------------------------------
# Verify / diff
# ---------------------------------------------------------------------------
def _walk(panels):
    for p in panels:
        yield p
        yield from _walk(p.get("panels", []))


def current_weathermap_links():
    """Return {frozenset({'host-if','host-if'})} across all existing weathermaps."""
    links, nodes = set(), set()
    for it in _grafana("GET", "/api/search?type=dash-db&limit=5000"):
        d = _grafana("GET", "/api/dashboards/uid/" + it["uid"])["dashboard"]
        for p in _walk(d.get("panels", [])):
            if p.get("type", "").endswith("weathermap-panel"):
                w = p.get("options", {}).get("weathermap", {})
                for n in w.get("nodes", []):
                    if not n.get("isConnection"):
                        nodes.add(n.get("label"))
                for l in w.get("links", []):
                    a = l.get("sides", {}).get("A", {}).get("query")
                    z = l.get("sides", {}).get("Z", {}).get("query")
                    if a and z:
                        links.add(frozenset([a, z]))
    return nodes, links


def do_check():
    topo_nodes, topo_links = fetch_topology()
    tp_nodes = {short(n) for n in topo_nodes}
    tp_links = {frozenset([f"{l['node1']}-{l['port1']}", f"{l['node2']}-{l['port2']}"])
                for l in topo_links.values()}
    cur_nodes, cur_links = current_weathermap_links()

    missing_nodes = sorted(tp_nodes - cur_nodes)
    stale_nodes = sorted(n for n in (cur_nodes - tp_nodes)
                         if n and n.startswith("switch"))
    missing_links = tp_links - cur_links
    stale_links = cur_links - tp_links

    print(f"live topology: {len(tp_nodes)} switches, {len(tp_links)} links")
    print(f"weathermap:    {len(cur_nodes)} nodes,    {len(cur_links)} links")
    print(f"\nMISSING switches (in topology, not on map): {missing_nodes or 'none'}")
    print(f"STALE switches (on map, not in topology):   {stale_nodes or 'none'}")
    print(f"\nMISSING links ({len(missing_links)}):")
    for l in sorted(map(sorted, missing_links)):
        print("   ", " <-> ".join(l))
    print(f"\nSTALE links ({len(stale_links)}):")
    for l in sorted(map(sorted, stale_links)):
        print("   ", " <-> ".join(l))

    drift = bool(missing_nodes or stale_nodes or missing_links or stale_links)
    print("\n" + ("DRIFT DETECTED" if drift else "weathermap is in sync"))
    return 1 if drift else 0


def do_generate(uid, title, dry_run):
    topo_nodes, topo_links = fetch_topology()
    facts = fetch_iface_facts()
    wm = build_weathermap(topo_nodes, topo_links, facts)
    dash = build_dashboard(wm, uid, title)
    print(f"built weathermap: {len([n for n in wm['nodes'] if not n['nodeIcon']['src'].startswith('data:')])} "
          f"switches, {len(wm['links'])} links", file=sys.stderr)
    if dry_run:
        print(json.dumps(dash, indent=2))
        return 0
    res = _grafana("POST", "/api/dashboards/db", dash)
    print(f"saved: status={res.get('status')} uid={res.get('uid')} "
          f"version={res.get('version')} url={GRAFANA_URL}{res.get('url','')}",
          file=sys.stderr)
    return 0 if res.get("status") == "success" else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true", help="diff map vs live topology")
    g.add_argument("--generate", action="store_true", help="build + POST dashboard")
    ap.add_argument("--dry-run", action="store_true", help="with --generate, print JSON")
    ap.add_argument("--uid", default="weathermap-auto")
    ap.add_argument("--title", default="Weathermap (auto-generated)")
    args = ap.parse_args()

    if args.check:
        return do_check()
    return do_generate(args.uid, args.title, args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
