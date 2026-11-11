"""Peering Traffic dashboard for the SFMIX NMS folder.

  Peering Traffic   /d/sfmix-peering-traffic   who exchanges how much across
                    the peering LAN, from sflow-rt's ixp-metrics app. Replaces
                    the hand-built "Overall Traffic Breakdown" dashboard.

Design: every panel follows the time picker, from a 5s close-up to a year.
Per-member series come from recording rules (rules/sflow.rules.yml,
sflow:ixp_peering_bps:sum_by_{src,dst}, ~80 series per direction), not from
summing the top-1000 pair matrix at query time, so long ranges stay inside
the Thanos query limits (doc 012 "Query guard rails"). Lines are per-interval
means (avg_over_time over $__interval) rather than point samples, so a
zoomed-out view never aliases; the exchange total adds a min/max band so the
peaks averaging hides are still visible.

Data sources:
  sflow:ixp_peering_bps:sum_by_src / _dst   rules/sflow.rules.yml (5s); history
                                            before 2026-11-11 is a backfill with
                                            external label backfill="sflow-members",
                                            so always sum by (src_name)/(dst_name)
  sflow_ixp_peering_bps                     src x dst pair matrix, top 1000 (drill-down)
  sflow_ixp_bps_total / _bps / _pktdist     ixp-metrics exchange totals
  sfmix:participant_if_bps:{in,out}         SNMP per-port rates (rules/sfmix.rules.yml)

Imported by gen_nms_dashboards.py, which pushes it alongside the SNMP
dashboards and substitutes the real datasource uid.
"""

DS_PROM = {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}
DS_DASH = {"type": "datasource", "uid": "-- Dashboard --"}
UID = "sfmix-peering-traffic"
SENT, RECV = "#5794f2", "#ff9830"       # blue / orange: distinct under CVD
OTHERS = "#7b8087"                      # "All others": context, not a member
GHOST = "#9aa0a6"                       # last week's line
GREEN, AMBER, RED = "#3d9950", "#e8a33d", "#e0226e"
NEUTRAL = [{"color": "#c8ccd1", "value": None}]
TOP_N = 10
MULTIPLES = 24

SRC_RULE = "sflow:ixp_peering_bps:sum_by_src"
DST_RULE = "sflow:ixp_peering_bps:sum_by_dst"
TOTAL = 'sflow_ixp_bps_total{direction="in"}'


def side(rule, by, window="$__interval", sel="", at_end=False):
    """Per-member mean over `window`.

    The live and backfilled streams differ only by the backfill label and never
    overlap in time, but a window spanning the handover holds samples of both:
    collapse them with max (not sum) first, or that window double-counts.
    """
    at = " @ end()" if at_end else ""
    return (f"sum by ({by}) (max without (backfill) "
            f"(avg_over_time({rule}{sel}[{window}]{at})))")


def top_and_others(rule, by, n=TOP_N, sel=""):
    """(top-n by mean over the whole visible range, everything else summed).

    Ranking with `@ end()` over $__range keeps one stable set of series for the
    whole window instead of a per-step topk that reshuffles the legend.
    """
    rank = f"topk({n}, {side(rule, by, '$__range', sel, at_end=True)})"
    series = side(rule, by, sel=sel)
    return (f"{series} and on ({by}) {rank}",
            f"sum({series} unless on ({by}) {rank})")


def member(expr, name_label, asn_label):
    """Rename src_/dst_ labels to member/asn so sent and received rows merge."""
    return (f'sum by (member, asn) (label_replace(label_replace({expr}, '
            f'"member", "$1", "{name_label}", "(.*)"), "asn", "$1", "{asn_label}", "(.*)"))')


# ── panel helpers ────────────────────────────────────────────────────

class Ids:
    def __init__(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        return self.n


def _t(expr, legend="", refid="A", instant=False, fmt=None):
    t = {"refId": refid, "datasource": DS_PROM, "expr": expr, "legendFormat": legend}
    if instant:
        t.update(instant=True, range=False, format=fmt or "table")
    return t


def _ts(pid, title, targets, grid, unit="bps", description="", stack=False,
        overrides=None, color=None, legend=False, interval="5s", fill=10,
        axis_label="", extra=None):
    custom = {"lineWidth": 1, "fillOpacity": fill, "showPoints": "never",
              "spanNulls": 60000, "drawStyle": "line", "gradientMode": "none",
              "axisLabel": axis_label, "axisBorderShow": False,
              "axisCenteredZero": False}
    if stack:
        custom["stacking"] = {"mode": "normal", "group": "A"}
    p = {
        "id": pid, "type": "timeseries", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_PROM, "targets": targets,
        "interval": interval,
        "fieldConfig": {"defaults": {"unit": unit, "custom": custom,
                                     "color": color or {"mode": "palette-classic-by-name"}},
                        "overrides": overrides or []},
        "options": {"legend": {"showLegend": legend, "displayMode": "list",
                               "placement": "bottom", "calcs": []},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    }
    if extra:
        p.update(extra)
    return p


def _fixed(name, color, match="byName"):
    return {"matcher": {"id": match, "options": name},
            "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}]}


def _negative(refid, group="rx"):
    """Draw below the axis but keep positive values in tooltips."""
    return {"matcher": {"id": "byFrameRefID", "options": refid},
            "properties": [{"id": "custom.transform", "value": "negative-Y"},
                           {"id": "custom.stacking", "value": {"mode": "normal", "group": group}}]}


def _stat(pid, title, expr, grid, unit="bps", description="", steps=None,
          spark=True, decimals=None):
    d = {"unit": unit, "color": {"mode": "thresholds"},
         "thresholds": {"mode": "absolute", "steps": steps or NEUTRAL}}
    if decimals is not None:
        d["decimals"] = decimals
    t = _t(expr) if spark else _t(expr, instant=True, fmt="time_series")
    return {
        "id": pid, "type": "stat", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_PROM, "targets": [t],
        "interval": "1m", "maxDataPoints": 200,
        "fieldConfig": {"defaults": d, "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]},
                    "graphMode": "area" if spark else "none",
                    "colorMode": "value", "textMode": "value", "justifyMode": "center"},
    }


def _row(pid, title, y, repeat=None):
    r = {"id": pid, "type": "row", "title": title, "collapsed": False, "panels": [],
         "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}}
    if repeat:
        r["repeat"] = repeat
    return r


# ── dashboard ────────────────────────────────────────────────────────

def peering_dashboard():
    nid = Ids()
    p, y = [], 0

    # ── The exchange ──
    p.append(_row(nid(), "The exchange", y)); y += 1
    stats = [
        ("Peering traffic now", TOTAL, "bps", None, True,
         "Bits/s entering the peering LAN from members (sflow-rt ixp-metrics). "
         "Sparkline: the visible range."),
        ("Peak in range", f"max_over_time({TOTAL}[$__range])", "bps", None, False,
         "Highest 5s sample in the visible range."),
        ("vs. one week earlier",
         f"avg_over_time({TOTAL}[1h]) / avg_over_time({TOTAL}[1h] offset 1w) - 1",
         "percentunit", None, True,
         "Last hour's mean against the same hour one week earlier."),
        ("IPv6 share",
         'sflow_ixp_bps{ethtype="IPv6"} / ignoring (ethtype) '
         'sum without (ethtype) (sflow_ixp_bps{ethtype=~"IPv4|IPv6"})',
         "percentunit", None, True, "IPv6 bits as a share of IPv4 + IPv6."),
        ("Members > 1 Mb/s", f"count({side(SRC_RULE, 'src_name', '5m')} > 1e6)",
         "none", 0, True, "Members whose 5-minute mean sent rate exceeds 1 Mb/s."),
        ("Pairs > 1 Mb/s", "count(sflow_ixp_peering_bps > 1e6)", "none", 0, True,
         "Source-destination member pairs exchanging more than 1 Mb/s "
         "(from sflow-rt's top-1000 pair list)."),
    ]
    for i, (title, expr, unit, dec, spark, desc) in enumerate(stats):
        p.append(_stat(nid(), title, expr, {"h": 4, "w": 4, "x": 4 * i, "y": y},
                       unit=unit, description=desc, spark=spark, decimals=dec))
    y += 4

    p.append(_ts(
        nid(), "Exchange traffic, with the same time one week earlier",
        [_t(f"avg_over_time({TOTAL}[$__interval])", "mean", "A"),
         _t(f"max_over_time({TOTAL}[$__interval])", "max", "B"),
         _t(f"min_over_time({TOTAL}[$__interval])", "min", "C"),
         _t(f"avg_over_time({TOTAL}[$__interval] offset 1w)", "one week earlier", "D")],
        {"h": 9, "w": 24, "x": 0, "y": y},
        description="Solid: mean bits/s per interval. Band: the min-max of the 5s "
                    "samples inside each interval, so zoomed-out peaks stay visible. "
                    "Dashed: the same interval one week earlier.",
        color={"mode": "fixed", "fixedColor": SENT}, fill=0, legend=True,
        overrides=[
            {"matcher": {"id": "byName", "options": "max"},
             "properties": [{"id": "custom.fillBelowTo", "value": "min"},
                            {"id": "custom.lineWidth", "value": 0},
                            {"id": "custom.fillOpacity", "value": 18},
                            {"id": "custom.hideFrom",
                             "value": {"legend": True, "tooltip": False, "viz": False}}]},
            {"matcher": {"id": "byName", "options": "min"},
             "properties": [{"id": "custom.lineWidth", "value": 0},
                            {"id": "custom.hideFrom",
                             "value": {"legend": True, "tooltip": False, "viz": False}}]},
            {"matcher": {"id": "byName", "options": "mean"},
             "properties": [{"id": "custom.lineWidth", "value": 2}]},
            _fixed("one week earlier", GHOST),
            {"matcher": {"id": "byName", "options": "one week earlier"},
             "properties": [{"id": "custom.lineStyle",
                             "value": {"fill": "dash", "dash": [6, 6]}}]},
        ]))
    y += 9

    # ── Who sends, who receives ──
    p.append(_row(nid(), "Who sends, who receives", y)); y += 1
    tx_top, tx_rest = top_and_others(SRC_RULE, "src_name")
    rx_top, rx_rest = top_and_others(DST_RULE, "dst_name")
    p.append(_ts(
        nid(), f"Sent ↑ and received ↓ by member: top {TOP_N} each way, the rest as "
               "\"All others\"",
        [_t(tx_top, "{{src_name}}", "A"), _t(tx_rest, "All others", "B"),
         _t(rx_top, "{{dst_name}}", "C"), _t(rx_rest, "All others", "D")],
        {"h": 14, "w": 24, "x": 0, "y": y}, stack=True, fill=70,
        axis_label="received ↓   sent ↑",
        description="Above the axis: traffic members send into the exchange. Below: "
                    "traffic delivered to them. Same member, same colour on both "
                    "sides. Members ranked by their mean over the visible range.",
        overrides=[_negative("C"), _negative("D"), _fixed("All others", OTHERS)]))
    y += 14

    # Member table (also the data source for the two balance charts).
    table_id = nid()
    cols = [
        ("Sent", member(side(SRC_RULE, "src_name, src_asn", "$__range"), "src_name", "src_asn")),
        ("Received", member(side(DST_RULE, "dst_name, dst_asn", "$__range"), "dst_name", "dst_asn")),
        ("Peak sent", member("sum by (src_name, src_asn) (max without (backfill) (max_over_time("
                             f"{SRC_RULE}[$__range])))", "src_name", "src_asn")),
        ("Peak received", member("sum by (dst_name, dst_asn) (max without (backfill) (max_over_time("
                                 f"{DST_RULE}[$__range])))", "dst_name", "dst_asn")),
    ]
    targets = [_t(e, refid=chr(ord("A") + i), instant=True) for i, (_, e) in enumerate(cols)]
    rename = {f"Value #{chr(ord('A') + i)}": c for i, (c, _) in enumerate(cols)}
    bar = [{"id": "custom.cellOptions",
            "value": {"type": "gauge", "mode": "basic", "valueDisplayMode": "text"}},
           {"id": "min", "value": 0}, {"id": "fieldMinMax", "value": True}]
    overrides = [
        {"matcher": {"id": "byName", "options": "Sent"},
         "properties": bar + [{"id": "color", "value": {"mode": "fixed", "fixedColor": SENT}}]},
        {"matcher": {"id": "byName", "options": "Received"},
         "properties": bar + [{"id": "color", "value": {"mode": "fixed", "fixedColor": RECV}}]},
        {"matcher": {"id": "byRegexp", "options": "Peak.*"},
         "properties": [{"id": "custom.width", "value": 128}]},
        {"matcher": {"id": "byName", "options": "Sent ÷ received"},
         "properties": [{"id": "unit", "value": "none"}, {"id": "decimals", "value": 2},
                        {"id": "displayName", "value": "Sent ÷ rcvd"},
                        {"id": "custom.width", "value": 92}]},
        {"matcher": {"id": "byName", "options": "member"},
         "properties": [{"id": "displayName", "value": "Member"},
                        {"id": "custom.width", "value": 180},
                        {"id": "links", "value": [{
                            "title": "Drill down to ${__value.raw}",
                            "url": f"/d/{UID}/peering-traffic?var-member=${{__value.raw}}"
                                   "&${__url_time_range}"}]}]},
        {"matcher": {"id": "byName", "options": "asn"},
         "properties": [{"id": "displayName", "value": "ASN"},
                        {"id": "unit", "value": "string"},
                        {"id": "custom.width", "value": 64},
                        {"id": "links", "value": [{
                            "title": "Participant Traffic (SNMP) for AS${__value.raw}",
                            "url": "/d/sfmix-participant-traffic/participant-traffic"
                                   "?var-participant=AS${__value.raw}&${__url_time_range}"}]}]},
    ]
    p.append({
        "id": table_id, "type": "table",
        "title": "Members: mean and peak over the visible range",
        "description": "Bars are each column's share of its maximum. Sent ÷ received "
                       "above 1: a net sender (content, CDN); below 1: a net receiver "
                       "(access, eyeball). Click a member to drill down, an ASN for "
                       "its SNMP port view.",
        "gridPos": {"h": 16, "w": 24, "x": 0, "y": y}, "datasource": DS_PROM,
        "targets": targets,
        "transformations": [
            {"id": "merge", "options": {}},
            {"id": "organize", "options": {
                "excludeByName": {"Time": True},
                "indexByName": {"member": 0, "asn": 1},
                "renameByName": rename}},
            {"id": "calculateField", "options": {
                "mode": "binary", "alias": "Sent ÷ received",
                "binary": {"left": "Sent", "operator": "/", "right": "Received"},
                "replaceFields": False}},
            {"id": "sortBy", "options": {"sort": [{"field": "Sent", "desc": True}]}},
        ],
        "fieldConfig": {"defaults": {"unit": "bps", "decimals": 1,
                                     "custom": {"align": "auto", "filterable": True}},
                        "overrides": overrides},
        "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
    })

    def balance(title, left, right, color, gy, desc):
        return {
            "id": nid(), "type": "barchart", "title": title, "description": desc,
            "gridPos": {"h": 9, "w": 24, "x": 0, "y": gy}, "datasource": DS_DASH,
            "targets": [{"refId": "A", "datasource": DS_DASH, "panelId": table_id,
                         "withTransforms": True}],
            "transformations": [
                {"id": "calculateField", "options": {
                    "mode": "binary", "alias": "net",
                    "binary": {"left": left, "operator": "-", "right": right},
                    "replaceFields": False}},
                {"id": "sortBy", "options": {"sort": [{"field": "net", "desc": True}]}},
                {"id": "limit", "options": {"limitField": 12}},
                {"id": "organize", "options": {
                    "excludeByName": {k: True for k in (
                        "asn", "Sent", "Received", "Peak sent", "Peak received",
                        "Sent ÷ received")}}},
            ],
            "fieldConfig": {"defaults": {
                "unit": "bps", "min": 0,
                "color": {"mode": "fixed", "fixedColor": color},
                "custom": {"fillOpacity": 80, "lineWidth": 0, "axisPlacement": "auto"}},
                "overrides": []},
            "options": {"orientation": "horizontal", "xField": "member",
                        "showValue": "always", "barWidth": 0.7, "groupWidth": 0.7,
                        "legend": {"showLegend": False}, "tooltip": {"mode": "single"},
                        "xTickLabelMaxLength": 40, "stacking": "none"},
        }

    y += 16
    p.append(balance("Biggest net senders (sent − received)", "Sent", "Received", SENT, y,
                     "Mean sent minus mean received over the visible range."))
    y += 9
    p.append(balance("Biggest net receivers (received − sent)", "Received", "Sent", RECV,
                     y, "Mean received minus mean sent over the visible range."))
    y += 9

    # ── Small multiples ──
    p.append(_row(nid(), f"Top {MULTIPLES} members at a glance (sent ↑, received ↓; "
                         "each panel on its own scale)", y)); y += 1
    p.append(_ts(
        nid(), "$top",
        [_t(side(SRC_RULE, "src_name", sel='{src_name="$top"}'), "sent", "A"),
         _t(side(DST_RULE, "dst_name", sel='{dst_name="$top"}'), "received", "B")],
        {"h": 5, "w": 4, "x": 0, "y": y}, fill=35,
        description="Shape over scale: each panel has its own y axis, so daily rhythm, "
                    "outages and shifts stand out even for small members.",
        color={"mode": "fixed", "fixedColor": SENT},
        overrides=[_fixed("received", RECV),
                   {"matcher": {"id": "byFrameRefID", "options": "B"},
                    "properties": [{"id": "custom.transform", "value": "negative-Y"}]}],
        extra={"repeat": "top", "repeatDirection": "h", "maxPerRow": 6,
               "maxDataPoints": 300,
               "links": [{"title": "Drill down", "url": f"/d/{UID}/peering-traffic"
                          "?var-member=$top&${__url_time_range}"}]}))
    y += 5

    # ── Drill-down ──
    p.append(_row(nid(), "Drill-down: $member", y)); y += 1
    for i, (title, rule, mine, other, color_desc) in enumerate((
            ("$member sends to", "sflow_ixp_peering_bps", "src_name", "dst_name",
             "Who receives what $member sends."),
            ("$member receives from", "sflow_ixp_peering_bps", "dst_name", "src_name",
             "Who sends what $member receives."))):
        top, rest = top_and_others(rule, other, n=10, sel=f'{{{mine}="$member"}}')
        p.append(_ts(
            nid(), title, [_t(top, "{{" + other + "}}", "A"), _t(rest, "All others", "B")],
            {"h": 12, "w": 24, "x": 0, "y": y + 12 * i}, stack=True, fill=70, legend=True,
            description=color_desc + " Top 10 peers over the visible range, from "
                        "sflow-rt's top-1000 pair matrix.",
            overrides=[_fixed("All others", OTHERS)],
            extra={"options": {
                "legend": {"showLegend": True, "displayMode": "table",
                           "placement": "right", "calcs": ["mean", "max"],
                           "sortBy": "Mean", "sortDesc": True},
                "tooltip": {"mode": "multi", "sort": "desc"}}}))
    y += 24

    # ── Character of the traffic ──
    p.append(_row(nid(), "Character of the traffic", y)); y += 1
    p.append(_ts(
        nid(), "IPv4 / IPv6 mix",
        [_t('sum by (ethtype) (avg_over_time(sflow_ixp_bps{ethtype=~"IPv4|IPv6"}'
            '[$__interval]))', "{{ethtype}}", "A")],
        {"h": 8, "w": 12, "x": 0, "y": y}, unit="percentunit", fill=60, legend=True,
        description="Share of peering bits by IP version.",
        color={"mode": "fixed", "fixedColor": SENT},
        overrides=[_fixed("IPv6", "#73bf69")],
        extra={"fieldConfig": {"defaults": {
            "unit": "percentunit", "min": 0, "max": 1,
            "color": {"mode": "fixed", "fixedColor": SENT},
            "custom": {"lineWidth": 0, "fillOpacity": 60, "showPoints": "never",
                       "spanNulls": 60000, "drawStyle": "line",
                       "stacking": {"mode": "percent", "group": "A"}}},
            "overrides": [_fixed("IPv6", "#73bf69")]}}))
    p.append({
        "id": nid(), "type": "barchart", "title": "Packet sizes (share of packets)",
        "description": "Mean share of sampled packets per frame-size bin over the "
                       "visible range. The 1518 bin is full-size Ethernet; 1519+ are "
                       "jumbo or VLAN-tagged frames.",
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": y}, "datasource": DS_PROM,
        "targets": [_t("avg by (bin, size) (avg_over_time(sflow_ixp_pktdist[$__range]))",
                       refid="A", instant=True)],
        "transformations": [
            {"id": "convertFieldType", "options": {"conversions": [
                {"targetField": "bin", "destinationType": "number"}]}},
            {"id": "sortBy", "options": {"sort": [{"field": "bin", "desc": False}]}},
            {"id": "organize", "options": {"excludeByName": {"Time": True, "bin": True},
                                           "renameByName": {"Value": "share"}}},
        ],
        "fieldConfig": {"defaults": {"unit": "percent", "decimals": 1, "min": 0,
                                     "color": {"mode": "fixed", "fixedColor": SENT},
                                     "custom": {"fillOpacity": 80, "lineWidth": 0}},
                        "overrides": []},
        "options": {"orientation": "vertical", "xField": "size", "showValue": "always",
                    "barWidth": 0.8, "legend": {"showLegend": False},
                    "tooltip": {"mode": "single"}, "stacking": "none"},
    })
    y += 8

    # ── Capacity ──
    p.append(_row(nid(), "Capacity", y)); y += 1
    names = ('label_replace(max by (src_asn, src_name) (last_over_time('
             f'{SRC_RULE}[1d])) * 0 + 1, "asn", "$1", "src_asn", "(.*)")')
    # max_over_time drops __name__, so tag one side before collapsing in/out.
    peak_util = ('max by (asn, participant, host, ifname) ('
                 'max_over_time(sfmix:participant_if_bps:in[$__range]) or '
                 'label_replace(max_over_time(sfmix:participant_if_bps:out[$__range]), '
                 '"dir", "out", "", "")) '
                 '/ on (host, ifname) group_left () '
                 'max by (host, ifname) (ifHighSpeed{job="snmp-eos"} * 1e6)')
    p.append({
        "id": nid(), "type": "bargauge",
        "title": "Busiest participant ports: peak utilisation in the visible range",
        "description": "Highest SNMP 2-minute rate (either direction) on each "
                       "participant's peering port, as a share of its speed. "
                       "Source: sfmix:participant_if_bps × ifHighSpeed.",
        "gridPos": {"h": 10, "w": 24, "x": 0, "y": y}, "datasource": DS_PROM,
        "targets": [_t(f"sort_desc(topk(16, ({peak_util}) * on (asn) group_left (src_name) "
                       f"topk by (asn) (1, max by (asn, src_name) ({names})) "
                       f"or on (asn, host, ifname) ({peak_util})))",
                       "{{src_name}} {{participant}} · {{host}} {{ifname}}", "A",
                       instant=True, fmt="time_series")],
        "fieldConfig": {"defaults": {
            "unit": "percentunit", "min": 0, "max": 1, "decimals": 0,
            "color": {"mode": "thresholds"},
            "thresholds": {"mode": "absolute", "steps": [
                {"color": GREEN, "value": None}, {"color": AMBER, "value": 0.6},
                {"color": RED, "value": 0.8}]}}, "overrides": []},
        "options": {"orientation": "horizontal", "displayMode": "basic",
                    "showUnfilled": True, "valueMode": "text", "namePlacement": "left",
                    "sizing": "manual", "minVizHeight": 14, "maxVizHeight": 18,
                    "reduceOptions": {"calcs": ["lastNotNull"], "values": False}},
    })
    y += 10

    # ── The long view ──
    p.append(_row(nid(), "The long view", y)); y += 1
    p.append(_ts(
        nid(), "Daily peak and daily mean, last 365 days",
        [_t(f"max_over_time({TOTAL}[1d])", "daily peak", "A"),
         _t(f"avg_over_time({TOTAL}[1d])", "daily mean", "B")],
        {"h": 8, "w": 24, "x": 0, "y": y}, interval="1d", fill=0, legend=True,
        description="Fixed to the last year regardless of the time picker. sFlow "
                    "history in Prometheus/Thanos starts 2026-03; LibreNMS holds the "
                    "multi-year record.",
        color={"mode": "fixed", "fixedColor": SENT},
        overrides=[_fixed("daily mean", GHOST)],
        extra={"timeFrom": "365d", "hideTimeOverride": False,
               "fieldConfig": {"defaults": {
                   "unit": "bps", "min": 0, "color": {"mode": "fixed", "fixedColor": SENT},
                   "custom": {"lineWidth": 1, "fillOpacity": 0, "showPoints": "never",
                              "spanNulls": False, "drawStyle": "line"}},
                   "overrides": [_fixed("daily mean", GHOST)]}}))
    y += 8

    templating = [
        {"name": "member", "label": "Member", "type": "query", "datasource": DS_PROM,
         "query": {"query": f"label_values({SRC_RULE}, src_name)", "refId": "member"},
         "refresh": 1, "sort": 5, "multi": False, "includeAll": False,
         "current": {"text": "Cloudflare", "value": "Cloudflare"}},
        {"name": "top", "label": "Top members", "type": "query", "datasource": DS_PROM,
         "hide": 2,
         "query": {"query": f"query_result(sort_desc(topk({MULTIPLES}, "
                            f"{side(SRC_RULE, 'src_name', '$__range')})))",
                   "refId": "top"},
         "regex": '/src_name="([^"]+)"/', "refresh": 2, "sort": 0,
         "multi": True, "includeAll": True,
         "current": {"text": "All", "value": "$__all"}},
    ]
    return {
        "uid": UID, "title": "Peering Traffic",
        "tags": ["sfmix-nms", "generated", "sflow"], "timezone": "browser",
        "description": "Who exchanges how much across the peering LAN (sflow-rt "
                       "ixp-metrics). Generated by gen_nms_dashboards.py / "
                       "nms_peering_dashboards.py — edits will be overwritten.",
        "schemaVersion": 39, "refresh": "", "editable": True,
        "graphTooltip": 1,   # shared crosshair across panels
        "time": {"from": "now-24h", "to": "now"},
        "templating": {"list": templating},
        "links": [{"title": "Participant Traffic (SNMP)", "type": "link",
                   "icon": "dashboard", "keepTime": True,
                   "url": "/d/sfmix-participant-traffic/participant-traffic"}],
        "panels": p,
    }


def peering_dashboards():
    return [peering_dashboard()]
