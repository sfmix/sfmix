#!/usr/bin/env python3
"""Generate and push the SFMIX NMS Grafana dashboards.

Builds, from live NetBox + Prometheus data:
  * "Participant Traffic" — the participant-ASN-enriched SNMP series
    (sfmix:participant_bps:* / sfmix:participant_if_bps:*).
  * One "digital twin" dashboard per peering switch — a canvas faceplate of
    the front panel (ports colored by link state, laid out per hardware
    model) with health panels (CPU, memory, temps, fans, PSU, optics DOM,
    traffic, errors) below it.

Dashboards are pushed via the Grafana HTTP API into the "SFMIX NMS" folder
and are fully regenerated each run (ports/devices track NetBox + live SNMP).

Pure stdlib. Environment:
  NETBOX_API_ENDPOINT, NETBOX_API_TOKEN   — device list + models
  PROMETHEUS_URL     (default http://localhost:9090)
  GRAFANA_URL        (default http://localhost:3000)
  GRAFANA_TOKEN_FILE (default /home/sfmix/.grafana_weathermap_token)
"""
import json
import logging
import os
import re
import sys
import urllib.parse
import urllib.request

log = logging.getLogger("nms-dashboards")
logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")

DOMAIN = "sfmix.org"
FOLDER_TITLE = "SFMIX NMS"
DASH_TAGS = ["sfmix-nms", "generated"]
DATASOURCE = {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}

# Status colors (state, not identity — reserved semantics; every port cell
# also carries a text label and the faceplate has a swatch legend, so state
# is never encoded by color alone).
C_UP = "#3d9950"        # link up
C_DOWN = "#e0226e"      # link down (magenta-red: distinct from green under CVD)
C_ADMIN = "#565b64"     # administratively down
C_OTHER = "#c8821f"     # anything else (testing/dormant/lowerLayerDown/...)
C_EMPTY = "#2c2f36"     # notPresent — an empty cage, not an alarm
C_TEXT = "#e6e8ea"
C_CAGE = "#22252b"

# ifOperStatus + 10*(ifAdminStatus==2): 1=up 2=down 6=notPresent 11+=disabled
STATE_MAPPINGS = [
    {"type": "value", "options": {
        "1": {"color": C_UP, "text": "up", "index": 0},
        "2": {"color": C_DOWN, "text": "down", "index": 1},
        "6": {"color": C_EMPTY, "text": "empty", "index": 2},
    }},
    {"type": "range", "options": {
        "from": 11, "to": 18,
        "result": {"color": C_ADMIN, "text": "admin down", "index": 3}}},
    {"type": "range", "options": {
        "from": 3, "to": 8,
        "result": {"color": C_OTHER, "text": "other", "index": 4}}},
]

# ── HTTP helpers ─────────────────────────────────────────────────────


def _get_json(url, headers=None, timeout=90):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def _post_json(url, payload, headers, timeout=90):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def netbox_devices():
    base = os.environ["NETBOX_API_ENDPOINT"].rstrip("/")
    hdrs = {"Authorization": f"Token {os.environ['NETBOX_API_TOKEN']}"}
    url = (f"{base}/api/dcim/devices/?"
           + urllib.parse.urlencode({"role": "peering_switch",
                                     "status": "active", "limit": 100}))
    devices = []
    while url:
        page = _get_json(url, hdrs)
        devices.extend(page["results"])
        url = page.get("next")
    return [{
        "name": d["name"].strip(),
        "fqdn": d["name"].strip() + "." + DOMAIN,
        "site": (d.get("site") or {}).get("slug") or "",
        "model": d["device_type"]["model"],
        "manufacturer": d["device_type"]["manufacturer"]["name"],
    } for d in devices]


def prom_instant(expr):
    url = (os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
           + "/api/v1/query?" + urllib.parse.urlencode({"query": expr}))
    out = _get_json(url)
    if out.get("status") != "success":
        raise RuntimeError(f"prometheus query failed: {expr}")
    return out["data"]["result"]


def live_ifnames(fqdn):
    res = prom_instant(f'count by (ifname) (ifOperStatus{{host="{fqdn}"}})')
    return sorted(r["metric"]["ifname"] for r in res if r["metric"].get("ifname"))


# ── Faceplate layout ─────────────────────────────────────────────────
#
# A faceplate is a list of cages; each cage has a grid position (col, row)
# and the list of interface names (lanes) that live in it. Breakout lanes
# subdivide the cage vertically.

ETH_RE = re.compile(r"^Ethernet(\d+)(?:/(\d+))?$")


def group_eos_ports(ifnames):
    """{base_port_number: [ifname, ...]} for front-panel EthernetN(/L)."""
    cages = {}
    for ifn in ifnames:
        m = ETH_RE.match(ifn)
        if not m:
            continue
        cages.setdefault(int(m.group(1)), []).append(ifn)
    for lanes in cages.values():
        lanes.sort(key=lambda s: [int(x) for x in re.findall(r"\d+", s)])
    return cages


# Cage geometry: SFP cages are square; QSFP/QSFP-DD cages carry the wider
# aspect ratio of the physical connector. Cells are (label, lanes, x_px,
# row, w_px); layouts compute pixel x so blocks/gaps mirror the real
# faceplate.
SFP_W, QSFP_W, CAGE_H, GAP = 30, 52, 30, 5
BLOCK_GAP = 26          # visual gap between port blocks


def _zigzag_block(cages, x0, w):
    """Place ports odd-on-top/even-below starting at x0; returns cells."""
    cells = []
    for i, (n, lanes) in enumerate(sorted(cages.items())):
        col, row = i // 2, i % 2
        cells.append((str(n), lanes, x0 + col * (w + GAP), row, w))
    return cells


def layout_eos(model, ifnames):
    """Vendor/model-specific faceplate mirroring Arista's physical layouts."""
    cages = group_eos_ports(ifnames)
    if "7280SR-48C6" in model:
        # two blocks of 24x SFP with the 2x3 QSFP block in the middle
        sfp_l = {n: v for n, v in cages.items() if n <= 24}
        qsfp = {n: v for n, v in cages.items() if n >= 49}
        sfp_r = {n: v for n, v in cages.items() if 25 <= n <= 48}
        x = 0
        cells = _zigzag_block(sfp_l, x, SFP_W)
        x += 12 * (SFP_W + GAP) - GAP + BLOCK_GAP
        cells += _zigzag_block(qsfp, x, QSFP_W)
        x += 3 * (QSFP_W + GAP) - GAP + BLOCK_GAP
        cells += _zigzag_block(sfp_r, x, SFP_W)
        return cells
    if "7280CR3-36S" in model:
        # 36x QSFP, equally spaced, 2 rows of 18
        return _zigzag_block(cages, 0, QSFP_W)
    # generic EOS: zigzag, QSFP-width when the port has breakout lanes
    w = QSFP_W if any(len(v) > 1 for v in cages.values()) else SFP_W
    return _zigzag_block(cages, 0, w)


NOKIA_RE = re.compile(r"^\d+/\d+/c(\d+)(?:/(\d+))?$")


def layout_generic(ifnames):
    """Non-EOS gear: physical-looking grid of whatever IF-MIB reports.

    Keeps only physical ports: Juniper ge-/xe-/et- (no logical .subunits),
    Nokia connectors N/N/cN (QSFP-DD-wide cages; lanes share the
    connector's cage like EOS breakouts).
    """
    juniper = [i for i in ifnames
               if re.match(r"^(ge-|xe-|et-)\d", i) and "." not in i]
    nokia = {}
    for i in ifnames:
        m = NOKIA_RE.match(i)
        if m:
            nokia.setdefault(int(m.group(1)), []).append(i)

    if nokia:
        for lanes in nokia.values():
            lanes.sort(key=lambda s: [int(x) for x in re.findall(r"\d+", s)])
        return _zigzag_block(nokia, 0, QSFP_W)

    phys = juniper or [i for i in ifnames if "." not in i][:48]
    cells = []
    for idx, ifn in enumerate(sorted(
            phys, key=lambda s: [int(x) for x in re.findall(r"\d+", s)])):
        label = re.sub(r"^(ge-|xe-|et-)0/0/", "", ifn)
        cells.append((label, [ifn], (idx // 2) * (SFP_W + GAP), idx % 2,
                      SFP_W))
    return cells


# ── Canvas faceplate panel ───────────────────────────────────────────

FP_TOP = 34   # room for the model label + legend swatches


def canvas_element(name, field, text, x, y, w, h, bg_field=True, fixed_bg=None,
                   text_size=11, text_color=C_TEXT):
    bg = {"field": field} if bg_field else {"fixed": fixed_bg or C_CAGE}
    return {
        "type": "rectangle",
        "name": name,
        "background": {"color": bg},
        "border": {"color": {"fixed": C_CAGE}, "width": 1},
        "config": {
            "align": "center", "valign": "middle",
            "color": {"fixed": text_color},
            "size": text_size,
            "text": {"mode": "fixed", "fixed": text},
        },
        "constraint": {"horizontal": "left", "vertical": "top"},
        "placement": {"left": x, "top": y, "width": w, "height": h},
    }


def faceplate_panel(dev, ifnames, grid_y):
    if dev["manufacturer"].lower() == "arista":
        cells = layout_eos(dev["model"], ifnames)
    else:
        cells = layout_generic(ifnames)

    elements = []
    # model tag + state legend swatches (state never color-alone)
    elements.append(canvas_element(
        "model", None, f'{dev["manufacturer"]} {dev["model"]}',
        0, 2, 300, 22, bg_field=False, fixed_bg="rgba(0,0,0,0)", text_size=13))
    for i, (color, lbl) in enumerate(
            [(C_UP, "up"), (C_DOWN, "down"), (C_ADMIN, "admin down"),
             (C_EMPTY, "empty"), (C_OTHER, "other")]):
        elements.append(canvas_element(
            f"legend-{lbl}", None, lbl, 330 + i * 105, 4, 96, 18,
            bg_field=False, fixed_bg=color, text_size=10))

    for label, lanes, x, row, cage_w in sorted(cells,
                                               key=lambda c: (c[3], c[2])):
        y = FP_TOP + row * (CAGE_H + GAP)
        # breakout lanes stack as full-width slices so the cage keeps the
        # connector's real footprint instead of squishing into slivers
        lane_h = CAGE_H // max(1, len(lanes))
        for li, lane in enumerate(lanes):
            txt = label if li == 0 else ""
            elements.append(canvas_element(
                lane, lane, txt, x, y + li * lane_h, cage_w,
                lane_h if li < len(lanes) - 1 else CAGE_H - li * lane_h,
                text_size=11 if len(lanes) == 1 else 8))

    height_px = FP_TOP + 2 * (CAGE_H + GAP)
    grid_h = max(4, -(-height_px // 30) + 1)   # ~30px per grid row

    return {
        "type": "canvas",
        "title": f"Front panel — {dev['name']}",
        "gridPos": {"h": grid_h, "w": 24, "x": 0, "y": grid_y},
        "datasource": DATASOURCE,
        "fieldConfig": {"defaults": {
            "color": {"mode": "thresholds"},
            "thresholds": {"mode": "absolute",
                           "steps": [{"color": C_OTHER, "value": None}]},
            "mappings": STATE_MAPPINGS,
        }, "overrides": []},
        "options": {
            "inlineEditing": False,
            "showAdvancedTypes": False,
            "panZoom": False,
            "infinitePan": False,
            "root": {
                "type": "frame", "name": "root",
                "background": {"color": {"fixed": "transparent"}},
                "border": {"color": {"fixed": "transparent"}},
                "constraint": {"horizontal": "left", "vertical": "top"},
                "placement": {"left": 0, "top": 0, "width": 1400,
                              "height": height_px},
                "elements": elements,
            },
        },
        "targets": [{
            "refId": "A",
            "datasource": DATASOURCE,
            "instant": True, "range": False,
            "expr": (f'ifOperStatus{{host="{dev["fqdn"]}"}}'
                     f' + 10 * (ifAdminStatus{{host="{dev["fqdn"]}"}} == bool 2)'),
            "legendFormat": "{{ifname}}",
        }],
    }


# ── Generic panel builders ───────────────────────────────────────────


def target(expr, legend="", refid="A", instant=False):
    t = {"refId": refid, "datasource": DATASOURCE, "expr": expr,
         "legendFormat": legend}
    if instant:
        t.update(instant=True, range=False, format="table")
    return t


def timeseries(title, targets, grid, unit="none", stack=False, min_val=None,
               legend_calcs=None, description=""):
    custom = {"lineWidth": 2, "fillOpacity": 8, "pointSize": 4,
              "showPoints": "never", "spanNulls": True}
    if stack:
        custom["stacking"] = {"mode": "normal", "group": "A"}
    defaults = {"unit": unit, "custom": custom,
                "color": {"mode": "palette-classic"}}
    if min_val is not None:
        defaults["min"] = min_val
    return {
        "type": "timeseries", "title": title, "description": description,
        "gridPos": grid, "datasource": DATASOURCE, "targets": targets,
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"legend": {"displayMode": "table", "placement": "bottom",
                               "calcs": legend_calcs or ["lastNotNull", "max"]},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    }


def stat(title, expr, grid, unit="none", decimals=None, thresholds=None,
         mappings=None, description=""):
    steps = thresholds or [{"color": "#3d9950", "value": None}]
    d = {"unit": unit, "color": {"mode": "thresholds"},
         "thresholds": {"mode": "absolute", "steps": steps},
         "mappings": mappings or []}
    if decimals is not None:
        d["decimals"] = decimals
    return {
        "type": "stat", "title": title, "description": description,
        "gridPos": grid, "datasource": DATASOURCE,
        "targets": [{"refId": "A", "datasource": DATASOURCE, "expr": expr,
                     "legendFormat": ""}],
        "fieldConfig": {"defaults": d, "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]},
                    "graphMode": "area", "colorMode": "value"},
    }


def row(title, grid_y):
    return {"type": "row", "title": title, "collapsed": False,
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": grid_y}}


def dashboard(uid, title, panels, templating=None, description=""):
    return {
        "uid": uid, "title": title, "tags": DASH_TAGS, "timezone": "browser",
        "description": description,
        "schemaVersion": 39, "refresh": "1m", "editable": True,
        "time": {"from": "now-6h", "to": "now"},
        "templating": {"list": templating or []},
        "panels": panels,
    }


# ── Switch View dashboard (single, $switch-variable-driven) ──────────

TEMP_JOIN = ('* on (entPhysicalIndex, host) group_left () '
             'entPhySensorType_info{{entPhySensorType="{t}", host="{h}"}}')


def switch_view_dashboard():
    # Grafana interpolates ${switch} (the bare NetBox device name) before
    # the query reaches Prometheus; host labels are <device>.<DOMAIN>.
    h = "${switch}." + DOMAIN
    p = []
    y = 0

    # ── headline stats
    s = [
        ("Uptime", f'sysUpTime{{host="{h}"}} / 100', "s", 1, None, None),
        ("CPU", f'avg(hrProcessorLoad{{host="{h}"}})', "percent", 0,
         [{"color": "#3d9950", "value": None}, {"color": "#e8a33d", "value": 70},
          {"color": "#e0226e", "value": 90}], None),
        ("Memory", f'100 * hrStorageUsed{{host="{h}", hrStorageDescr="RAM"}}'
                   f' / hrStorageSize{{host="{h}", hrStorageDescr="RAM"}}',
         "percent", 0,
         [{"color": "#3d9950", "value": None}, {"color": "#e8a33d", "value": 80},
          {"color": "#e0226e", "value": 92}], None),
        ("Hottest sensor",
         f'max((entPhySensorValue{{host="{h}"}} / 10) '
         + TEMP_JOIN.format(t="celsius", h=h) + ')', "celsius", 1,
         [{"color": "#3d9950", "value": None}, {"color": "#e8a33d", "value": 65},
          {"color": "#e0226e", "value": 85}], None),
        ("Slowest fan",
         f'min(entPhySensorValue{{host="{h}"}} '
         + TEMP_JOIN.format(t="rpm", h=h) + ')', "rotrpm", 0,
         [{"color": "#e0226e", "value": None}, {"color": "#3d9950", "value": 1500}],
         None),
        ("Ports up",
         f'count(ifOperStatus{{host="{h}", ifname=~"Ethernet.*|ge-.*|xe-.*|et-.*|\\\\d+/.*"}} == 1) or vector(0)',
         "none", 0, None, None),
        ("Throughput (in)",
         f'sum(rate(ifHCInOctets{{host="{h}"}}[3m])) * 8', "bps", None, None, None),
        ("Throughput (out)",
         f'sum(rate(ifHCOutOctets{{host="{h}"}}[3m])) * 8', "bps", None, None, None),
    ]
    for i, (t, e, u, dec, thr, mp) in enumerate(s):
        p.append(stat(t, e, {"h": 4, "w": 3, "x": 3 * i, "y": y}, unit=u,
                      decimals=dec, thresholds=thr, mappings=mp))
    y += 4

    # ── per-port link state over time (the variable-friendly counterpart
    #    of the Front Panels faceplate; that dashboard links here)
    # physical ports only — no LAGs/subinterfaces/mgmt in the timeline
    phys_re = r"Ethernet[0-9/]+|(ge-|xe-|et-)[0-9/]+|[0-9]+/[0-9]+/c[0-9/]+"
    p.append({
        "type": "state-timeline",
        "title": "Port link state",
        "gridPos": {"h": 18, "w": 24, "x": 0, "y": y},
        "datasource": DATASOURCE,
        "targets": [target(
            f'ifOperStatus{{host="{h}", ifname=~"{phys_re}"}}'
            f' + 10 * (ifAdminStatus{{host="{h}", ifname=~"{phys_re}"}} == bool 2)',
            "{{ifname}}")],
        # colors come from the value mappings alone — an explicit thresholds
        # base paints every state with it on this panel type
        "fieldConfig": {"defaults": {
            "mappings": STATE_MAPPINGS,
            "custom": {"fillOpacity": 82, "lineWidth": 0},
        }, "overrides": []},
        "options": {"showValue": "never", "rowHeight": 0.72,
                    "mergeValues": True,
                    "legend": {"displayMode": "list", "placement": "bottom"},
                    "tooltip": {"mode": "single"}},
    })
    y += 18

    # ── traffic
    p.append(row("Traffic", y)); y += 1
    p.append(timeseries(
        "Switch throughput", [
            target(f'sum(rate(ifHCInOctets{{host="{h}"}}[3m])) * 8', "in", "A"),
            target(f'sum(rate(ifHCOutOctets{{host="{h}"}}[3m])) * 8', "out", "B"),
        ], {"h": 8, "w": 12, "x": 0, "y": y}, unit="bps"))
    p.append(timeseries(
        "Busiest ports (in)",
        [target(f'topk(10, rate(ifHCInOctets{{host="{h}"}}[3m]) * 8)',
                "{{ifname}}")],
        {"h": 8, "w": 12, "x": 12, "y": y}, unit="bps"))
    y += 8
    p.append(timeseries(
        "Errors", [
            target(f'rate(ifInErrors{{host="{h}"}}[5m]) > 0',
                   "{{ifname}} in", "A"),
            target(f'rate(ifOutErrors{{host="{h}"}}[5m]) > 0',
                   "{{ifname}} out", "B"),
        ], {"h": 7, "w": 12, "x": 0, "y": y}, unit="pps",
        description="Only ports with a non-zero error rate appear."))
    p.append(timeseries(
        "Discards", [
            target(f'rate(ifInDiscards{{host="{h}"}}[5m]) > 0',
                   "{{ifname}} in", "A"),
            target(f'rate(ifOutDiscards{{host="{h}"}}[5m]) > 0',
                   "{{ifname}} out", "B"),
        ], {"h": 7, "w": 12, "x": 12, "y": y}, unit="pps",
        description="Only ports with a non-zero discard rate appear."))
    y += 7

    # ── environment
    p.append(row("Environment", y)); y += 1
    p.append(timeseries(
        "Chassis temperatures",
        [target(f'(entPhySensorValue{{host="{h}", entPhysicalName!~"DOM.*"}} / 10) '
                + TEMP_JOIN.format(t="celsius", h=h), "{{entPhysicalName}}")],
        {"h": 8, "w": 8, "x": 0, "y": y}, unit="celsius"))
    p.append(timeseries(
        "Fans",
        [target(f'entPhySensorValue{{host="{h}"}} '
                + TEMP_JOIN.format(t="rpm", h=h), "{{entPhysicalName}}")],
        {"h": 8, "w": 8, "x": 8, "y": y}, unit="rotrpm", min_val=0))
    p.append(timeseries(
        "Power supplies", [
            target(f'(entPhySensorValue{{host="{h}", entPhysicalName=~".*[Vv]oltage.*"}} / 100) '
                   + TEMP_JOIN.format(t="voltsAC", h=h), "{{entPhysicalName}} (AC)", "A"),
            target(f'(entPhySensorValue{{host="{h}", entPhysicalName=~".*[Vv]oltage.*"}} / 100) '
                   + TEMP_JOIN.format(t="voltsDC", h=h), "{{entPhysicalName}} (DC)", "B"),
        ], {"h": 8, "w": 8, "x": 16, "y": y}, unit="volt",
        description="PSU input/output voltage sensors."))
    y += 8

    # ── optics
    p.append(row("Optics (DOM)", y)); y += 1
    for i, (dirn, refid) in enumerate([("RX", "A"), ("TX", "B")]):
        p.append(timeseries(
            f"Optic {dirn} power",
            [target(
                'label_replace(10 * log10((entPhySensorValue{host="%s", '
                'entPhysicalName=~"DOM %s Power Sensor for .*"} > 0) / 10000), '
                '"port", "$1", "entPhysicalName", "DOM %s Power Sensor for (.*)")'
                % (h, dirn, dirn), "{{port}}", refid)],
            {"h": 8, "w": 8, "x": 8 * i, "y": y}, unit="dBm",
            description="Dark/unlit lanes are omitted (sentinel filtered)."))
    p.append(timeseries(
        "Optic temperatures",
        [target(
            'label_replace(entPhySensorValue{host="%s", '
            'entPhysicalName=~"DOM Temperature Sensor for .*"} / 10, '
            '"port", "$1", "entPhysicalName", "DOM Temperature Sensor for (.*)")'
            % h, "{{port}}")],
        {"h": 8, "w": 8, "x": 16, "y": y}, unit="celsius"))
    y += 8

    # ── ports table
    p.append(row("Ports", y)); y += 1
    tbl = {
        "type": "table", "title": "Port inventory",
        "gridPos": {"h": 12, "w": 24, "x": 0, "y": y},
        "datasource": DATASOURCE,
        "targets": [
            target(f'ifOperStatus{{host="{h}"}}', refid="A", instant=True),
            target(f'ifHighSpeed{{host="{h}"}}', refid="B", instant=True),
            target(f'rate(ifHCInOctets{{host="{h}"}}[3m]) * 8', refid="C",
                   instant=True),
            target(f'rate(ifHCOutOctets{{host="{h}"}}[3m]) * 8', refid="D",
                   instant=True),
            target(f'max by (ifname, participant, asn) '
                   f'(sfmix_peering_port_info{{host="{h}"}})', refid="E",
                   instant=True),
        ],
        "transformations": [
            {"id": "joinByField", "options": {"byField": "ifname",
                                              "mode": "outer"}},
            {"id": "organize", "options": {
                "excludeByName": {"Time": True, "Time 1": True, "Time 2": True,
                                  "Time 3": True, "Time 4": True,
                                  "Time 5": True, "__name__": True,
                                  "__name__ 1": True, "__name__ 2": True,
                                  "__name__ 3": True, "__name__ 4": True,
                                  "__name__ 5": True,
                                  "host": True, "host 1": True,
                                  "host 2": True, "host 3": True,
                                  "host 4": True, "instance": True,
                                  "instance 1": True, "instance 2": True,
                                  "instance 3": True, "instance 4": True,
                                  "job": True, "job 1": True, "job 2": True,
                                  "job 3": True, "job 4": True,
                                  "device": True, "device 1": True,
                                  "device 2": True, "device 3": True,
                                  "device 4": True, "site": True,
                                  "site 1": True, "site 2": True,
                                  "site 3": True, "site 4": True,
                                  "ifIndex": True, "ifIndex 1": True,
                                  "ifIndex 2": True, "ifIndex 3": True,
                                  "ifDescr": True, "ifDescr 1": True,
                                  "ifDescr 2": True, "ifDescr 3": True,
                                  "ifAlias 1": True, "ifAlias 2": True,
                                  "ifAlias 3": True, "Value #E": True},
                "renameByName": {"ifname": "port", "ifAlias": "description",
                                 "Value #A": "oper", "Value #B": "speed",
                                 "Value #C": "in bps", "Value #D": "out bps",
                                 "participant": "participant", "asn": "ASN"},
            }},
        ],
        "fieldConfig": {"defaults": {"custom": {"filterable": True}},
                        "overrides": [
            {"matcher": {"id": "byName", "options": "oper"},
             "properties": [
                 {"id": "mappings", "value": [
                     {"type": "value", "options": {
                         "1": {"color": C_UP, "text": "up"},
                         "2": {"color": C_DOWN, "text": "down"}}}]},
                 {"id": "custom.cellOptions",
                  "value": {"type": "color-text"}}]},
            {"matcher": {"id": "byName", "options": "speed"},
             "properties": [{"id": "unit", "value": "Mbits"}]},
            {"matcher": {"id": "byName", "options": "in bps"},
             "properties": [{"id": "unit", "value": "bps"}]},
            {"matcher": {"id": "byName", "options": "out bps"},
             "properties": [{"id": "unit", "value": "bps"}]},
        ]},
        "options": {"sortBy": [{"displayName": "in bps", "desc": True}]},
    }
    p.append(tbl)

    templ = [{
        "name": "switch", "label": "Switch", "type": "query",
        "datasource": DATASOURCE,
        "query": {"query": 'label_values(up{job="snmp-eos"}, device)',
                  "refId": "switch"},
        "refresh": 2, "sort": 1, "multi": False, "includeAll": False,
    }]
    d = dashboard(
        "sfmix-switch-view", "Switch View", p, templating=templ,
        description="Per-switch health: traffic, environment, optics, port "
                    "state. Pick the switch with the variable; the Front "
                    "Panels dashboard shows every faceplate at a glance. "
                    "Generated by gen_nms_dashboards.py — edits will be "
                    "overwritten.")
    d["links"] = [{"title": "Front Panels", "type": "link", "icon": "bolt",
                   "url": "/d/sfmix-front-panels/front-panels",
                   "keepTime": True}]
    return d


# ── Front Panels dashboard (all faceplates, links into Switch View) ──


def front_panels_dashboard(devices_ifnames):
    p = []
    y = 0
    for dev, ifnames in devices_ifnames:
        fp = faceplate_panel(dev, ifnames, y)
        fp["title"] = dev["name"]
        fp["links"] = [{
            "title": f"Switch View — {dev['name']}",
            "url": (f"/d/sfmix-switch-view/switch-view"
                    f"?var-switch={dev['name']}"),
        }]
        p.append(fp)
        y += fp["gridPos"]["h"]
    d = dashboard(
        "sfmix-front-panels", "Front Panels", p,
        description="Live faceplate of every peering switch — port cells "
                    "colored by link state, laid out per hardware model. "
                    "Panel title links open the Switch View for that device. "
                    "Generated by gen_nms_dashboards.py — edits will be "
                    "overwritten.")
    d["links"] = [{"title": "Switch View", "type": "link", "icon": "bolt",
                   "url": "/d/sfmix-switch-view/switch-view",
                   "keepTime": True}]
    return d


# ── Participant traffic dashboard ────────────────────────────────────


def participant_dashboard():
    p = []
    y = 0

    p.append(row("Exchange overview", y)); y += 1
    p.append(timeseries(
        "Top participants (in)",
        [target('topk(10, sfmix:participant_bps:in)', "{{participant}}")],
        {"h": 9, "w": 12, "x": 0, "y": y}, unit="bps"))
    p.append(timeseries(
        "Top participants (out)",
        [target('topk(10, sfmix:participant_bps:out)', "{{participant}}")],
        {"h": 9, "w": 12, "x": 12, "y": y}, unit="bps"))
    y += 9

    p.append(row("Participant: $participant", y)); y += 1
    p.append(timeseries(
        "Aggregate traffic — $participant", [
            target('sfmix:participant_bps:in{participant=~"$participant"}',
                   "{{participant}} in", "A"),
            target('sfmix:participant_bps:out{participant=~"$participant"}',
                   "{{participant}} out", "B"),
        ], {"h": 8, "w": 24, "x": 0, "y": y}, unit="bps",
        description="Port-independent series — continuous across port moves."))
    y += 8
    p.append(timeseries(
        "Per-port (in)",
        [target('sfmix:participant_if_bps:in{participant=~"$participant"}',
                "{{host}} {{ifname}}")],
        {"h": 8, "w": 12, "x": 0, "y": y}, unit="bps"))
    p.append(timeseries(
        "Per-port (out)",
        [target('sfmix:participant_if_bps:out{participant=~"$participant"}',
                "{{host}} {{ifname}}")],
        {"h": 8, "w": 12, "x": 12, "y": y}, unit="bps"))
    y += 8

    tbl = {
        "type": "table", "title": "Ports — $participant",
        "gridPos": {"h": 9, "w": 24, "x": 0, "y": y},
        "datasource": DATASOURCE,
        "targets": [target(
            'max by (host, ifname, asn, participant, port_role, ipv4, ipv6) '
            '(sfmix_peering_port_info{participant=~"$participant"})',
            refid="A", instant=True)],
        "transformations": [
            {"id": "organize", "options": {
                "excludeByName": {"Time": True, "Value": True},
                "renameByName": {"host": "switch", "ifname": "port",
                                 "port_role": "role"},
                "indexByName": {"participant": 0, "asn": 1, "switch": 2,
                                "port": 3, "role": 4, "ipv4": 5, "ipv6": 6},
            }},
        ],
        "fieldConfig": {"defaults": {"custom": {"filterable": True}},
                        "overrides": []},
        "options": {},
    }
    p.append(tbl)

    templ = [{
        "name": "participant", "label": "Participant", "type": "query",
        "datasource": DATASOURCE,
        "query": {"query": 'label_values(sfmix_peering_port_info, participant)',
                  "refId": "participant"},
        "refresh": 2, "sort": 1, "multi": False, "includeAll": True,
        "allValue": ".*", "current": {"text": "All", "value": "$__all"},
    }]
    return dashboard(
        "sfmix-participant-traffic", "Participant Traffic", p,
        templating=templ,
        description="SNMP counter-accurate participant traffic, enriched with "
                    "ASN/port attribution from NetBox. Generated by "
                    "gen_nms_dashboards.py — edits will be overwritten.")


# ── Grafana push ─────────────────────────────────────────────────────


def grafana_headers():
    tok = open(os.environ.get("GRAFANA_TOKEN_FILE",
                              "/home/sfmix/.grafana_weathermap_token")
               ).read().strip()
    return {"Authorization": f"Bearer {tok}"}


def prometheus_ds_uid(gurl, hdrs):
    for ds in _get_json(f"{gurl}/api/datasources", hdrs):
        if ds["type"] == "prometheus":
            return ds["uid"]
    raise RuntimeError("no prometheus datasource in Grafana")


def ensure_folder(gurl, hdrs):
    for f in _get_json(f"{gurl}/api/folders", hdrs):
        if f["title"] == FOLDER_TITLE:
            return f["uid"]
    out = _post_json(f"{gurl}/api/folders", {"title": FOLDER_TITLE}, hdrs)
    return out["uid"]


def push(gurl, hdrs, folder_uid, dash, ds_uid):
    blob = json.dumps(dash)
    blob = blob.replace("${DS_PROMETHEUS}", ds_uid)
    payload = {"dashboard": json.loads(blob), "folderUid": folder_uid,
               "overwrite": True,
               "message": "generated by gen_nms_dashboards.py"}
    out = _post_json(f"{gurl}/api/dashboards/db", payload, hdrs)
    log.info("pushed %s -> %s", dash["title"], out.get("url"))


def cleanup_stale(gurl, hdrs, keep_uids):
    """Delete previously-generated dashboards that are no longer produced."""
    url = f"{gurl}/api/search?" + urllib.parse.urlencode(
        {"tag": DASH_TAGS[0], "limit": 200})
    for hit in _get_json(url, hdrs):
        uid = hit.get("uid")
        if uid and uid not in keep_uids:
            req = urllib.request.Request(
                f"{gurl}/api/dashboards/uid/{uid}", method="DELETE",
                headers=hdrs)
            with urllib.request.urlopen(req, timeout=30):
                pass
            log.info("deleted stale dashboard %s (%s)", hit.get("title"), uid)


def main():
    gurl = os.environ.get("GRAFANA_URL", "http://localhost:3000")
    hdrs = grafana_headers()
    ds_uid = prometheus_ds_uid(gurl, hdrs)
    folder = ensure_folder(gurl, hdrs)

    devices_ifnames = []
    for dev in sorted(netbox_devices(), key=lambda d: d["name"]):
        ifnames = live_ifnames(dev["fqdn"])
        if not ifnames:
            log.warning("%s: no live interface series — skipped", dev["fqdn"])
            continue
        devices_ifnames.append((dev, ifnames))

    dashboards = [participant_dashboard(), switch_view_dashboard(),
                  front_panels_dashboard(devices_ifnames)]
    for d in dashboards:
        push(gurl, hdrs, folder, d, ds_uid)
    cleanup_stale(gurl, hdrs, {d["uid"] for d in dashboards})
    return 0


if __name__ == "__main__":
    sys.exit(main())
