"""Site environment (temperature/humidity) dashboard for the SFMIX NMS folder.

  Site Temperatures   /d/sfmix-site-temps   ?var-site=   every temperature
                      sensor SFMIX owns at one site, on one page

Sources, best air signal first:
  * PDU environmental probes  pdu:env_temp_celsius / pdu:env_humidity_pct
                              (pdu.rules; true rack-air readings, but only
                              where a probe is plugged in)
  * room air sensor           mqtt2prometheus-air-sensor `temperature`
                              (sensor label = site; sfo02 only today)
  * Arista "Inlet" sensors    ENTITY-SENSOR, one per switch, every site.
                              Reads a few degrees above room air (it sits in
                              the chassis intake path), so it trends well but
                              runs warm in absolute terms.
  * component temps           switch chassis sensors, optic DOM temps, PVE
                              host hwmon — load-dependent, shown as context.

Site-level for now: NetBox has no rack assignment we can join on yet. When it
does, add a $rack variable and filter the same queries on it.

Imported by gen_nms_dashboards.py, which pushes it alongside the SNMP
dashboards and substitutes the real datasource uid for ${DS_PROMETHEUS}.
"""

DS_PROM = {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}
GREEN, AMBER, RED = "#3d9950", "#e8a33d", "#e0226e"
UID = "sfmix-site-temps"

SITE = 'site=~"$site"'

# Thresholds. Rack air follows ASHRAE A1: 27 °C is the top of the recommended
# envelope, 32 °C the top of the allowable one. Switch inlet sensors read warm
# (self-heating in the intake path), so they get their own, looser, steps.
T_AIR = [{"color": GREEN, "value": None}, {"color": AMBER, "value": 27},
         {"color": RED, "value": 32}]
T_INLET = [{"color": GREEN, "value": None}, {"color": AMBER, "value": 35},
           {"color": RED, "value": 40}]
T_OPTIC = [{"color": GREEN, "value": None}, {"color": AMBER, "value": 60},
           {"color": RED, "value": 70}]       # commercial optics: 0-70 °C case
T_CHASSIS = [{"color": GREEN, "value": None}, {"color": AMBER, "value": 65},
             {"color": RED, "value": 85}]     # matches Switch View
T_RH = [{"color": AMBER, "value": None}, {"color": GREEN, "value": 20},
        {"color": AMBER, "value": 60}, {"color": RED, "value": 80}]
T_DELTA = [{"color": GREEN, "value": None}, {"color": AMBER, "value": 1.5},
           {"color": RED, "value": 3}]

SWITCH_VIEW = ("/d/sfmix-switch-view/switch-view?var-switch=${__field.labels.device}"
               "&${__url_time_range}")
SWITCH_VIEW_TABLE = ("/d/sfmix-switch-view/switch-view?var-switch="
                     "${__data.fields.device}&${__url_time_range}")


# ── PromQL builders ──────────────────────────────────────────────────

def sw_temp(sel="", site=SITE, offset=""):
    """Every celsius-typed ENTITY-SENSOR reading on the switches, in °C.

    Scaled per sensor by 10^entPhySensorPrecision (nearly all are tenths, a
    couple are hundredths). job/instance are collapsed away on both sides
    (see SENSOR in gen_nms_dashboards.py for why). Keeps site/device/host/
    entPhysicalName. `offset` (e.g. " offset 7d") applies to every selector.
    """
    return (
        f'max by (site, device, host, entPhysicalIndex, entPhysicalName) '
        f'(entPhySensorValue{{{site}{sel}}}{offset}) '
        f'/ on (host, entPhysicalIndex) group_left () '
        f'(10 ^ max by (host, entPhysicalIndex) '
        f'(entPhySensorPrecision{{{site}}}{offset})) '
        f'* on (host, entPhysicalIndex) group_left () '
        f'max by (host, entPhysicalIndex) '
        f'(entPhySensorType_info{{{site}, entPhySensorType="celsius"}}{offset})')


INLET_SEL = ', entPhysicalName="Inlet"'


def inlet(site=SITE, offset=""):
    return f'max by (site, device) ({sw_temp(INLET_SEL, site, offset)})'


OPTIC_SEL = ', entPhysicalName=~"DOM Temperature Sensor for .*"'
CHASSIS_SEL = ', entPhysicalName!~"DOM .*"'


def fans(site=SITE):
    return (f'max by (site, device, host, entPhysicalIndex) (entPhySensorValue{{{site}}}) '
            f'* on (host, entPhysicalIndex) group_left () '
            f'max by (host, entPhysicalIndex) '
            f'(entPhySensorType_info{{{site}, entPhySensorType="rpm"}})')


def pdu_temp(site=SITE):
    return f'pdu:env_temp_celsius{{{site}}}'


def pdu_rh(site=SITE):
    return f'pdu:env_humidity_pct{{{site}}}'


def room(metric, sensor='sensor=~"$site"'):
    """The MQTT air sensor(s): the `sensor` label carries the site name."""
    return (f'label_replace({metric}{{job="mqtt2prometheus-air-sensor", '
            f'{sensor}}}, "site", "$1", "sensor", "(.+)")')


# node_exporter series carry no site label; derive it from the inventory
# hostname (<name>.<site>.sfmix.org), plus the two pre-convention PVE names.
_HOST_SITE = (
    'label_replace(label_replace(label_replace({expr}, '
    '"site", "$1", "host", "[^.]+\\\\.([a-z]+[0-9]+)\\\\.sfmix\\\\.org"), '
    '"site", "sfo02", "host", ".*-paulave200-sfo\\\\..*"), '
    '"site", "fmt01", "host", ".*-warmspringsblvd48233-fmt\\\\..*")')


def hwmon_by_host(site=SITE):
    expr = _HOST_SITE.format(expr='max by (host) (node_hwmon_temp_celsius)')
    # Filter on the derived label by intersecting with any series that has a
    # real `site` (every site has a polled switch).
    return (f'({expr}) and on (site) '
            f'group by (site) (up{{job="snmp-eos-health", {site}}})')


# ── panel helpers (same shapes as the other nms_* modules) ───────────

def _t(expr, legend="", refid="A", instant=False, table=False):
    t = {"refId": refid, "datasource": DS_PROM, "expr": expr,
         "legendFormat": legend}
    if instant:
        t.update(instant=True, range=False)
    if table:
        t["format"] = "table"
    return t


def _ts(title, targets, grid, unit="celsius", thresholds=None, description="",
        links=None, min_val=None, decimals=1, legend_calcs=None):
    custom = {"lineWidth": 2, "fillOpacity": 0, "pointSize": 3,
              "showPoints": "never", "spanNulls": True}
    defaults = {"unit": unit, "decimals": decimals, "custom": custom,
                "color": {"mode": "palette-classic"}, "links": links or []}
    if thresholds:
        # draw the steps as dashed reference lines, not a colour scheme
        custom["thresholdsStyle"] = {"mode": "dashed"}
        defaults["thresholds"] = {"mode": "absolute", "steps": thresholds}
    if min_val is not None:
        defaults["min"] = min_val
    return {
        "type": "timeseries", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_PROM, "targets": targets,
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"legend": {"displayMode": "table", "placement": "bottom",
                               "calcs": legend_calcs or ["lastNotNull", "mean", "max"],
                               "sortBy": "Last *", "sortDesc": True},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    }


def _stat(title, expr, grid, thresholds, unit="celsius", decimals=1,
          description="", no_value="—"):
    return {
        "type": "stat", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_PROM, "targets": [_t(expr)],
        "fieldConfig": {"defaults": {
            "unit": unit, "decimals": decimals, "noValue": no_value,
            "color": {"mode": "thresholds"},
            "thresholds": {"mode": "absolute", "steps": thresholds}},
            "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]},
                    "graphMode": "area", "colorMode": "value",
                    "textMode": "value"},
    }


def _row(title, y):
    return {"type": "row", "title": title, "collapsed": False,
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}}


# ── dashboard ────────────────────────────────────────────────────────

def site_temps_dashboard():
    p, y = [], 0

    # ── headline numbers for the selected site
    p.append(_row("$site — now", y)); y += 1
    stats = [
        ("Hottest switch inlet", f'max({inlet()})', T_INLET, "celsius",
         "Highest Arista 'Inlet' sensor in the site. These sit in the chassis "
         "intake and read a few °C above room air — compare against other "
         "switches and other sites rather than ASHRAE numbers."),
        ("Mean switch inlet", f'avg({inlet()})', T_INLET, "celsius",
         "Average of every switch inlet sensor in the site."),
        ("Inlet vs. 7 days ago",
         f'avg({inlet()}) - avg({inlet(offset=" offset 7d")})', T_DELTA, "celsius",
         "Mean switch inlet now minus the same mean exactly one week ago "
         "(same time of day, so daily HVAC cycles cancel out). Positive = "
         "the site is running warmer than last week."),
        ("Rack air (PDU probe)", f'max({pdu_temp()})', T_AIR, "celsius",
         "Hottest PDU temperature probe in the site — a real air reading. "
         "ASHRAE A1: ≤27 °C recommended, ≤32 °C allowable. '—' = no probe "
         "plugged into any PDU here."),
        ("Rack humidity", f'max({pdu_rh()})', T_RH, "humidity",
         "Relative humidity from the PDU probe(s). Below ~20% raises ESD "
         "risk; above 60% condensation risk."),
        ("Hottest optic", f'max({sw_temp(OPTIC_SEL)})', T_OPTIC, "celsius",
         "Hottest transceiver module (DOM case temperature). Commercial-grade "
         "optics are rated 0–70 °C; they are also the first thing to suffer "
         "when inlet air climbs."),
    ]
    for i, (title, expr, th, unit, desc) in enumerate(stats):
        p.append(_stat(title, expr, {"h": 4, "w": 4, "x": 4 * i, "y": y}, th,
                       unit=unit, description=desc,
                       decimals=0 if unit == "humidity" else 1))
    y += 4

    # Every air-ish reading in the site as one sorted bar list.
    everything_now = (
        'sort_desc('
        f'label_replace({inlet()}, "name", "$1  inlet", "device", "(.+)") '
        f'or label_join({pdu_temp()}, "name", "  ", "device", "probe") '
        f'or label_replace({room("temperature")}, "name", "room air sensor", "", "")'
        ')')
    p.append({
        "type": "bargauge", "title": "Inlet & rack air now",
        "description": "Every switch inlet sensor, PDU probe and room sensor "
                       "in the site, hottest first. Inlet bars use the "
                       "switch-inlet scale, so read the colours loosely.",
        "gridPos": {"h": 10, "w": 10, "x": 0, "y": y},
        "datasource": DS_PROM,
        "targets": [_t(everything_now, "{{name}}", instant=True)],
        "fieldConfig": {"defaults": {
            "unit": "celsius", "decimals": 1, "min": 15, "max": 50,
            "color": {"mode": "thresholds"},
            "thresholds": {"mode": "absolute", "steps": T_INLET}},
            "overrides": []},
        "options": {"orientation": "horizontal", "displayMode": "gradient",
                    "showUnfilled": True, "valueMode": "color",
                    "namePlacement": "top", "sizing": "auto",
                    "text": {"titleSize": 13, "valueSize": 16},
                    "reduceOptions": {"calcs": ["lastNotNull"]}},
    })

    hottest = f'topk(15, {sw_temp()})'
    p.append({
        "type": "table", "title": "Hottest sensors in the site",
        "description": "Top 15 temperature sensors across every switch in the "
                       "site — chassis, ASIC, PSU and optic DOM. Click a "
                       "device for Switch View.",
        "gridPos": {"h": 10, "w": 14, "x": 10, "y": y},
        "datasource": DS_PROM,
        "targets": [_t(hottest, instant=True, table=True)],
        "transformations": [
            {"id": "organize", "options": {
                "excludeByName": {"Time": True, "host": True, "site": True,
                                  "entPhysicalIndex": True},
                "indexByName": {"device": 0, "entPhysicalName": 1, "Value": 2},
                "renameByName": {"entPhysicalName": "Sensor", "Value": "°C",
                                 "device": "Device"}}},
            {"id": "sortBy", "options": {"sort": [{"field": "°C", "desc": True}]}},
        ],
        "fieldConfig": {"defaults": {"custom": {"align": "auto"}},
                        "overrides": [
            {"matcher": {"id": "byName", "options": "°C"}, "properties": [
                {"id": "unit", "value": "celsius"},
                {"id": "decimals", "value": 1},
                {"id": "custom.cellOptions",
                 "value": {"type": "color-background", "mode": "basic"}},
                {"id": "thresholds", "value": {"mode": "absolute",
                                               "steps": T_CHASSIS}},
                {"id": "custom.width", "value": 90}]},
            {"matcher": {"id": "byName", "options": "Device"}, "properties": [
                {"id": "links", "value": [{"title": "Switch View",
                                           "url": SWITCH_VIEW_TABLE}]}]},
        ]},
        "options": {"showHeader": True, "cellHeight": "sm"},
    })
    y += 10

    # ── trends for the selected site
    p.append(_row("$site — trends", y)); y += 1
    p.append(_ts(
        "Switch inlet temperature",
        [_t(inlet(), "{{device}}")],
        {"h": 9, "w": 12, "x": 0, "y": y}, thresholds=T_INLET,
        links=[{"title": "Switch View", "url": SWITCH_VIEW}],
        description="Arista 'Inlet' sensor per switch. Watch for a step "
                    "change, one switch diverging from its neighbours "
                    "(blocked intake, reversed airflow, hot-aisle "
                    "recirculation), or the whole site drifting together "
                    "(room HVAC)."))
    p.append(_ts(
        "Rack air — PDU probes & room sensor",
        [_t(pdu_temp(), "{{device}} {{probe}}", "A"),
         _t(room("temperature"), "room air sensor", "B")],
        {"h": 9, "w": 12, "x": 12, "y": y}, thresholds=T_AIR,
        description="True air temperature: probes hanging off the PDUs and "
                    "the standalone room sensor. Dashed lines: ASHRAE A1 "
                    "recommended (27 °C) and allowable (32 °C) maxima. "
                    "PDU probe history starts 2026-11-17."))
    y += 9
    p.append(_ts(
        "Fan speed (mean per switch)",
        [_t(f'avg by (device) ({fans()})', "{{device}}")],
        {"h": 8, "w": 8, "x": 0, "y": y}, unit="rotrpm", decimals=0,
        links=[{"title": "Switch View", "url": SWITCH_VIEW}],
        description="Fans ramp with internal temperature, so a rise here "
                    "corroborates warmer intake air."))
    p.append(_ts(
        "Hottest chassis sensor per switch",
        [_t(f'max by (device) ({sw_temp(CHASSIS_SEL)})', "{{device}}")],
        {"h": 8, "w": 8, "x": 8, "y": y}, thresholds=T_CHASSIS,
        links=[{"title": "Switch View", "url": SWITCH_VIEW}],
        description="Highest non-optic sensor (ASIC, CPU, VRMs, PSU) on each "
                    "switch — load-dependent, but tracks inlet air."))
    p.append(_ts(
        "Optic temperature per switch (hottest / mean)",
        [_t(f'max by (device) ({sw_temp(OPTIC_SEL)})', "{{device}} max", "A"),
         _t(f'avg by (device) ({sw_temp(OPTIC_SEL)})', "{{device}} mean", "B")],
        {"h": 8, "w": 8, "x": 16, "y": y}, thresholds=T_OPTIC,
        links=[{"title": "Switch View", "url": SWITCH_VIEW}],
        description="Transceiver DOM case temperature. Optic power readings "
                    "drift with temperature, so check here before blaming a "
                    "fibre."))
    y += 8
    p.append(_ts(
        "Humidity",
        [_t(pdu_rh(), "{{device}} {{probe}}", "A"),
         _t(room("humidity"), "room air sensor", "B")],
        {"h": 8, "w": 12, "x": 0, "y": y}, unit="humidity", decimals=0,
        thresholds=[{"color": AMBER, "value": None},
                    {"color": GREEN, "value": 20}, {"color": AMBER, "value": 60}],
        description="Relative humidity from PDU probes and the room sensor."))
    p.append(_ts(
        "Servers — hottest hwmon sensor per host",
        [_t(hwmon_by_host(), "{{host}}")],
        {"h": 8, "w": 12, "x": 12, "y": y},
        description="Hypervisor hardware sensors (CPU package/cores, NICs) "
                    "from node_exporter. Load-dependent — useful as a "
                    "cross-check, not as an air reading."))
    y += 8

    # ── all sites, for comparison
    p.append(_row("All sites — is it just this one?", y)); y += 1
    all_sites, any_sensor = 'site=~".+"', 'sensor=~".+"'
    p.append(_ts(
        "Switch inlet by site (mean)",
        [_t(f'avg by (site) ({inlet(all_sites)})', "{{site}}")],
        {"h": 9, "w": 12, "x": 0, "y": y}, thresholds=T_INLET,
        description="Mean switch inlet temperature per site. Different "
                    "switch models read differently, so compare a site to "
                    "its own history more than to its neighbours."))
    p.append(_ts(
        "Rack air by site (hottest probe)",
        [_t(f'max by (site) ({pdu_temp(all_sites)})', "{{site}}", "A"),
         _t(f'max by (site) ({room("temperature", any_sensor)})',
            "{{site}} (room sensor)", "B")],
        {"h": 9, "w": 12, "x": 12, "y": y}, thresholds=T_AIR,
        description="Hottest PDU probe per site (only sites with a probe "
                    "plugged in), plus the room sensor(s)."))
    y += 9

    q = 'label_values(up{job="snmp-eos-health"}, site)'
    templ = [{"name": "site", "label": "Site", "type": "query",
              "datasource": DS_PROM, "definition": q,
              "query": {"query": q, "refId": "site"},
              "refresh": 2, "sort": 1, "multi": False, "includeAll": False}]
    links = [("Switch View", "/d/sfmix-switch-view/switch-view"),
             ("PDU Power", "/d/sfmix-pdu-power/pdu-power")]
    return {
        "uid": UID, "title": "Site Temperatures",
        "tags": ["sfmix-nms", "generated", "environment"],
        "timezone": "browser",
        "description": "Every SFMIX temperature/humidity sensor at one site: "
                       "switch inlets, PDU env probes, room sensor, chassis, "
                       "optics and servers. Site-level until NetBox carries "
                       "rack positions.",
        "schemaVersion": 39, "refresh": "5m", "editable": True,
        "time": {"from": "now-7d", "to": "now"},
        "templating": {"list": templ},
        "links": [{"title": t, "type": "link", "icon": "dashboard", "url": u,
                   "keepTime": True, "targetBlank": False} for t, u in links],
        "panels": p,
    }


def environment_dashboards():
    return [site_temps_dashboard()]
