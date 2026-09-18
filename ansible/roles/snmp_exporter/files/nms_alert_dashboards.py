"""Alert-context dashboards for the SFMIX NMS folder.

Every alert rule (Prometheus and Loki ruler) carries a `dashboard` annotation
that Alertmanager turns into the Slack "Dashboard" button. These are the
landing pages those links point at, built so one dashboard serves a whole
family of alerts by pre-filling variables from the URL:

  Host Logs            /d/sfmix-host-logs        ?var-host=&var-unit=&var-search=
  Container Logs       /d/sfmix-container-logs   ?var-host=&var-container=&var-search=
  Network Device Logs  /d/sfmix-device-logs      ?var-host=&var-severity=&var-search=
  Log Pipeline         /d/sfmix-log-pipeline     (no variables: fleet ingest view)
  TLS Certificates     /d/sfmix-tls              ?var-instance=

`$search` is a free-text RE2 regex applied with `|~` so an alert can land you
on exactly the lines that fired it (e.g. var-search=Out%20of%20memory).

Imported by gen_nms_dashboards.py, which pushes these alongside the SNMP
dashboards. Loki panels reference the datasource as ${DS_LOKI}; the pusher
substitutes the real uid the same way it does ${DS_PROMETHEUS}.
"""

DS_LOKI = {"type": "loki", "uid": "${DS_LOKI}"}
DS_PROM = {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}

# Same "something went wrong" regex the Loki rules use for error-ish counts.
ERRORISH = r'(?i)(error|crit|emerg|fail|panic|oom|segfault|denied)'

GREEN, AMBER, RED = "#3d9950", "#e8a33d", "#e0226e"


# ── panel helpers (Loki flavoured; mirror the shapes in gen_nms_dashboards) ──

def _ltarget(expr, legend="", refid="A", instant=False):
    t = {"refId": refid, "datasource": DS_LOKI, "expr": expr,
         "legendFormat": legend, "queryType": "instant" if instant else "range"}
    return t


def _lts(title, targets, grid, unit="short", stack=False, description="",
         legend_calcs=None):
    custom = {"lineWidth": 1, "fillOpacity": 25 if stack else 8,
              "pointSize": 3, "showPoints": "never", "spanNulls": False}
    if stack:
        custom["stacking"] = {"mode": "normal", "group": "A"}
    return {
        "type": "timeseries", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_LOKI, "targets": targets,
        "fieldConfig": {"defaults": {"unit": unit, "min": 0, "custom": custom,
                                     "color": {"mode": "palette-classic"}},
                        "overrides": []},
        "options": {"legend": {"displayMode": "table", "placement": "right",
                               "calcs": legend_calcs or ["lastNotNull", "max"]},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    }


def _lstat(title, expr, grid, thresholds=None, unit="short", description="",
           ds=None):
    ds = ds or DS_LOKI
    steps = thresholds or [{"color": GREEN, "value": None}]
    return {
        "type": "stat", "title": title, "description": description,
        "gridPos": grid, "datasource": ds,
        "targets": [{"refId": "A", "datasource": ds, "expr": expr,
                     "legendFormat": "", "queryType": "instant",
                     "instant": True, "range": False}],
        "fieldConfig": {"defaults": {"unit": unit, "decimals": 0,
                                     "color": {"mode": "thresholds"},
                                     "thresholds": {"mode": "absolute",
                                                    "steps": steps}},
                        "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]},
                    "graphMode": "none", "colorMode": "value",
                    "textMode": "value"},
    }


def _ltable(title, expr, grid, value_name="lines", sort_desc=True,
            description="", unit="short", ds=None):
    """Instant metric query rendered as a table: one row per label set."""
    ds = ds or DS_LOKI
    return {
        "type": "table", "title": title, "description": description,
        "gridPos": grid, "datasource": ds,
        "targets": [{"refId": "A", "datasource": ds, "expr": expr,
                     "legendFormat": "", "queryType": "instant",
                     "instant": True, "range": False, "format": "table"}],
        "transformations": [
            {"id": "organize", "options": {
                "excludeByName": {"Time": True},
                "renameByName": {"Value #A": value_name, "Value": value_name}}},
        ],
        "fieldConfig": {"defaults": {"unit": unit, "decimals": 0,
                                     "custom": {"align": "auto",
                                                "cellOptions": {"type": "auto"}}},
                        "overrides": [
                            {"matcher": {"id": "byName", "options": value_name},
                             "properties": [{"id": "custom.cellOptions",
                                             "value": {"type": "gauge",
                                                       "mode": "basic"}},
                                            {"id": "color",
                                             "value": {"mode": "continuous-BlYlRd"}}]}]},
        "options": {"sortBy": [{"displayName": value_name, "desc": sort_desc}],
                    "showHeader": True, "cellHeight": "sm"},
    }


def _logs(title, expr, grid, description=""):
    return {
        "type": "logs", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_LOKI,
        "targets": [{"refId": "A", "datasource": DS_LOKI, "expr": expr,
                     "queryType": "range", "maxLines": 1000}],
        "options": {"showTime": True, "showLabels": False,
                    "showCommonLabels": False, "wrapLogMessage": True,
                    "prettifyLogMessage": False, "enableLogDetails": True,
                    "dedupStrategy": "none", "sortOrder": "Descending"},
    }


def _row(title, y):
    return {"type": "row", "title": title, "collapsed": False,
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}}


def _text(md, grid):
    return {"type": "text", "title": "", "gridPos": grid,
            "options": {"mode": "markdown", "content": md}}


# ── variables ────────────────────────────────────────────────────────

def _loki_label_var(name, label, stream, label_name, multi=False,
                    include_all=False, default=None):
    v = {
        "name": name, "label": label, "type": "query", "datasource": DS_LOKI,
        "definition": f"label_values({stream}, {label_name})",
        "query": {"label": label_name, "stream": stream, "type": 1,
                  "refId": "LokiVariableQueryEditor-VariableQuery"},
        "refresh": 2, "sort": 1, "multi": multi, "includeAll": include_all,
    }
    if include_all:
        # Loki needs a real regex for "all"; the default (a|b|c) join would
        # miss label values that appear after the variable was resolved.
        v["allValue"] = ".+"
        v["current"] = {"text": "All", "value": "$__all"}
    if default is not None:
        v["current"] = {"text": default, "value": default}
    return v


def _textbox_var(name, label, default=""):
    return {"name": name, "label": label, "type": "textbox", "query": default,
            "current": {"text": default, "value": default},
            "description": "RE2 regex applied to the log line with |~ "
                           "(empty = everything). Alert links pre-fill this."}


def _prom_label_var(name, label, query, multi=True, include_all=True):
    v = {"name": name, "label": label, "type": "query", "datasource": DS_PROM,
         "definition": query,
         "query": {"query": query, "refId": name},
         "refresh": 2, "sort": 1, "multi": multi, "includeAll": include_all}
    if include_all:
        v["current"] = {"text": "All", "value": "$__all"}
    return v


def _dash(uid, title, panels, templating, description, links=(), time_from="now-6h"):
    return {
        "uid": uid, "title": title, "tags": ["sfmix-nms", "generated", "alerts"],
        "timezone": "browser", "description": description,
        "schemaVersion": 39, "refresh": "1m", "editable": True,
        "time": {"from": time_from, "to": "now"},
        "templating": {"list": templating},
        "links": [{"title": t, "type": "link", "icon": "dashboard", "url": u,
                   "keepTime": True, "targetBlank": False}
                  for t, u in links],
        "panels": panels,
    }


# ── Host Logs ────────────────────────────────────────────────────────

def host_logs_dashboard():
    """Everything one Linux host (VM or hypervisor) says: journald by unit,
    plus its containers and file logs. Landing page for LogSenderSilent,
    LogVolumeSpike, KernelOomKill, ProcessCrash, SystemdUnitFailed,
    SmartAttributeFailing, ZfsPoolUnhealthy, CertbotRenewFailed,
    UnattendedUpgradesError, SshBruteForce, ProxmoxBackupFailed,
    LookingGlassBackendWaiting (and TeleportBackendSlow, currently disabled)."""
    H = 'host="$host"'
    J = f'{{{H}, job="journal", unit=~"$unit"}}'
    ALL = f'{{{H}}}'
    p, y = [], 0

    p.append(_row("Overview — $host", y)); y += 1
    stats = [
        ("Lines in range", f'sum(count_over_time({ALL}[$__range]))', None),
        ("Error-ish lines", f'sum(count_over_time({ALL} |~ "{ERRORISH}" [$__range]))',
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 50},
          {"color": RED, "value": 500}]),
        ("OOM kills", f'sum(count_over_time({ALL} |= "Out of memory: Killed process" [$__range])) or vector(0)',
         [{"color": GREEN, "value": None}, {"color": RED, "value": 1}]),
        ("Units entered failed state",
         f'sum(count_over_time({{{H}, job="journal", unit="init.scope"}} |= "entered failed state" [$__range])) or vector(0)',
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 1}]),
        ("Failed SSH passwords",
         f'sum(count_over_time({ALL} |= "Failed password for" [$__range])) or vector(0)',
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 100},
          {"color": RED, "value": 1000}]),
        ("Lines matching $search",
         f'sum(count_over_time({ALL} |~ "$search" [$__range])) or vector(0)', None),
    ]
    for i, (t, e, th) in enumerate(stats):
        p.append(_lstat(t, e, {"h": 4, "w": 4, "x": 4 * i, "y": y}, thresholds=th))
    y += 4

    p.append(_lts("journald lines/min by unit",
                  [_ltarget(f'sum by (unit) (rate({J}[5m])) * 60', "{{unit}}")],
                  {"h": 9, "w": 16, "x": 0, "y": y}, stack=True, unit="short",
                  description="Filtered by $unit. A unit that suddenly dominates "
                              "is usually the story."))
    p.append(_ltable("Top units in range",
                     f'topk(15, sum by (unit) (count_over_time({J}[$__range])))',
                     {"h": 9, "w": 8, "x": 16, "y": y}))
    y += 9
    p.append(_lts("Error-ish lines/min by unit",
                  [_ltarget(f'sum by (unit) (rate({J} |~ "{ERRORISH}" [5m])) * 60', "{{unit}}")],
                  {"h": 8, "w": 12, "x": 0, "y": y}))
    p.append(_lts("Other sources on this host (containers, file logs) lines/min",
                  [_ltarget(f'sum by (job, container) (rate({{{H}, job!="journal"}}[5m])) * 60',
                            "{{job}} {{container}}")],
                  {"h": 8, "w": 12, "x": 12, "y": y},
                  description="job=docker per container and job=unattended-upgrades. "
                              "Container detail lives on the Container Logs dashboard."))
    y += 8

    p.append(_row("Logs", y)); y += 1
    p.append(_logs("journald — $unit, matching $search",
                   f'{J} |~ "$search"',
                   {"h": 16, "w": 24, "x": 0, "y": y}))
    y += 16
    p.append(_logs("Containers & file logs on $host, matching $search",
                   f'{{{H}, job!="journal"}} |~ "$search"',
                   {"h": 10, "w": 24, "x": 0, "y": y},
                   description="job=docker and job=unattended-upgrades streams."))
    y += 10

    templ = [
        # syslog is included so OpenBSD hosts (lg, rs-openbsd) land here too:
        # their lines show in the "other sources" panels, journald ones stay empty.
        _loki_label_var("host", "Host", '{job=~"journal|docker|unattended-upgrades|syslog"}', "host"),
        _loki_label_var("unit", "Unit", '{host="$host", job="journal"}', "unit",
                        multi=True, include_all=True),
        _textbox_var("search", "Search (regex)"),
    ]
    return _dash(
        "sfmix-host-logs", "Host Logs", p, templ,
        "One Linux host's logs from Loki: journald by unit, containers and "
        "file logs, with a regex filter. Alert Slack buttons deep-link here "
        "with host/unit/search pre-filled. Generated by gen_nms_dashboards.py "
        "— edits will be overwritten.",
        links=[("Container Logs (this host)",
                "/d/sfmix-container-logs/container-logs?var-host=${host}"),
               ("Log Pipeline", "/d/sfmix-log-pipeline/log-pipeline")])


# ── Container Logs ───────────────────────────────────────────────────

def container_logs_dashboard():
    """Docker container stdout per host/container (job=docker). Landing page
    for ContainerErrorBurst and container-flavoured LogStreamFlood."""
    C = '{host="$host", job="docker", container=~"$container"}'
    p, y = [], 0

    p.append(_row("Overview — $host", y)); y += 1
    stats = [
        ("Containers seen", f'count(sum by (container) (count_over_time({C}[$__range])))', None),
        ("Lines in range", f'sum(count_over_time({C}[$__range]))', None),
        ("Error-ish lines",
         f'sum(count_over_time({C} |~ "(?i)(traceback|exception|\\\\berror\\\\b|\\\\bfatal\\\\b)" [$__range])) or vector(0)',
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 100},
          {"color": RED, "value": 1000}]),
        ("Lines matching $search",
         f'sum(count_over_time({C} |~ "$search" [$__range])) or vector(0)', None),
    ]
    for i, (t, e, th) in enumerate(stats):
        p.append(_lstat(t, e, {"h": 4, "w": 6, "x": 6 * i, "y": y}, thresholds=th))
    y += 4
    p.append(_lts("Lines/min by container",
                  [_ltarget(f'sum by (container) (rate({C}[5m])) * 60', "{{container}}")],
                  {"h": 9, "w": 16, "x": 0, "y": y}, stack=True,
                  description="What Loki receives AFTER Alloy's per-container rate "
                              "limit (20/s) and known-noise drops. A flat line at "
                              "~1200/min means the limiter is clipping that container."))
    p.append(_ltable("Top containers in range",
                     f'topk(15, sum by (container) (count_over_time({C}[$__range])))',
                     {"h": 9, "w": 8, "x": 16, "y": y}))
    y += 9
    p.append(_lts("Error-ish lines/min by container",
                  [_ltarget(f'sum by (container) (rate({C} |~ "(?i)(traceback|exception|\\\\berror\\\\b|\\\\bfatal\\\\b)" [5m])) * 60',
                            "{{container}}")],
                  {"h": 8, "w": 24, "x": 0, "y": y}))
    y += 8
    p.append(_row("Logs", y)); y += 1
    p.append(_logs("$container on $host, matching $search", f'{C} |~ "$search"',
                   {"h": 18, "w": 24, "x": 0, "y": y}))
    y += 18

    templ = [
        _loki_label_var("host", "Host", '{job="docker"}', "host"),
        _loki_label_var("container", "Container", '{host="$host", job="docker"}',
                        "container", multi=True, include_all=True),
        _textbox_var("search", "Search (regex)"),
    ]
    return _dash(
        "sfmix-container-logs", "Container Logs", p, templ,
        "Docker container stdout shipped by Alloy (job=docker), per host and "
        "container, with a regex filter. Generated by gen_nms_dashboards.py — "
        "edits will be overwritten.",
        links=[("Host Logs (this host)", "/d/sfmix-host-logs/host-logs?var-host=${host}"),
               ("Log Pipeline", "/d/sfmix-log-pipeline/log-pipeline")])


# ── Network Device Logs ──────────────────────────────────────────────

def device_logs_dashboard():
    """Appliance syslog (switches, routers, mgmt-gws, OpenBSD) received by
    syslog-ng. Landing page for BgpUnconfiguredPeerOpens and any future
    syslog-pattern alert."""
    S = '{job="syslog", host=~"$host", severity=~"$severity"}'
    p, y = [], 0

    p.append(_row("Overview — $host", y)); y += 1
    stats = [
        ("Devices heard", f'count(sum by (host) (count_over_time({S}[$__range])))', None),
        ("Lines in range", f'sum(count_over_time({S}[$__range]))', None),
        ("err+ severity lines",
         f'sum(count_over_time({{job="syslog", host=~"$host", severity=~"emerg|alert|crit|err"}}[$__range])) or vector(0)',
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 10},
          {"color": RED, "value": 100}]),
        ("BGP-tagged lines",
         f'sum(count_over_time({S} |~ "BGP" [$__range])) or vector(0)',
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 50},
          {"color": RED, "value": 500}]),
        ("Lines matching $search",
         f'sum(count_over_time({S} |~ "$search" [$__range])) or vector(0)', None),
    ]
    w = 24 // len(stats)
    for i, (t, e, th) in enumerate(stats):
        p.append(_lstat(t, e, {"h": 4, "w": w, "x": w * i, "y": y}, thresholds=th))
    y += 4
    p.append(_lts("Lines/min by device",
                  [_ltarget(f'sum by (host) (rate({S}[5m])) * 60', "{{host}}")],
                  {"h": 9, "w": 16, "x": 0, "y": y}, stack=True))
    p.append(_ltable("Top devices in range",
                     f'topk(20, sum by (host) (count_over_time({S}[$__range])))',
                     {"h": 9, "w": 8, "x": 16, "y": y}))
    y += 9
    p.append(_lts("Lines/min by severity",
                  [_ltarget(f'sum by (severity) (rate({S}[5m])) * 60', "{{severity}}")],
                  {"h": 8, "w": 12, "x": 0, "y": y}, stack=True))
    p.append(_lts("Lines/min matching $search, by device",
                  [_ltarget(f'sum by (host) (rate({S} |~ "$search" [5m])) * 60', "{{host}}")],
                  {"h": 8, "w": 12, "x": 12, "y": y}))
    y += 8
    p.append(_row("Logs", y)); y += 1
    p.append(_logs("syslog — $host / $severity, matching $search", f'{S} |~ "$search"',
                   {"h": 18, "w": 24, "x": 0, "y": y}))
    y += 18

    templ = [
        _loki_label_var("host", "Device", '{job="syslog"}', "host",
                        multi=True, include_all=True),
        _loki_label_var("severity", "Severity", '{job="syslog"}', "severity",
                        multi=True, include_all=True),
        _textbox_var("search", "Search (regex)"),
    ]
    return _dash(
        "sfmix-device-logs", "Network Device Logs", p, templ,
        "Appliance syslog (Arista/Nokia/VyOS/OpenBSD) as received by syslog-ng "
        "on metrics, by device and severity, with a regex filter. Generated by "
        "gen_nms_dashboards.py — edits will be overwritten.",
        links=[("Log Pipeline", "/d/sfmix-log-pipeline/log-pipeline"),
               ("Switch View", "/d/sfmix-switch-view/switch-view")])


# ── Log Pipeline ─────────────────────────────────────────────────────

def log_pipeline_dashboard():
    """Fleet-wide ingest health: who is sending, how much, and what Loki is
    rejecting. Landing page for SyslogReceiverSilent and the fleet view for
    LogSenderSilent / LogStreamFlood / LogVolumeSpike."""
    A = '{job=~".+"}'
    p, y = [], 0

    p.append(_row("Ingest", y)); y += 1
    stats = [
        ("Lines/s (5m)", f'sum(rate({A}[5m]))', None),
        ("Bytes/s (5m)", f'sum(bytes_rate({A}[5m]))', None),
        ("journald hosts heard (1h)",
         f'count(sum by (host) (count_over_time({{job="journal"}}[1h])))', None),
        ("Docker hosts heard (1h)",
         f'count(sum by (host) (count_over_time({{job="docker"}}[1h]))) or vector(0)', None),
        ("Appliances heard (1h)",
         f'count(sum by (host) (count_over_time({{job="syslog"}}[1h]))) or vector(0)',
         [{"color": RED, "value": None}, {"color": GREEN, "value": 1}]),
        ("Loki write rejections (1h)",
         f'sum(count_over_time({{job="docker", container="loki"}} |= "write operation failed" [1h])) or vector(0)',
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 1},
          {"color": RED, "value": 100}]),
    ]
    for i, (t, e, th) in enumerate(stats):
        u = "Bps" if "Bytes" in t else "short"
        p.append(_lstat(t, e, {"h": 4, "w": 4, "x": 4 * i, "y": y}, thresholds=th, unit=u))
    # bytes stat wants decimals; the helper pins 0, override for that one
    p[-5]["fieldConfig"]["defaults"]["decimals"] = 1
    y += 4
    p.append(_lts("Lines/s by job", [_ltarget(f'sum by (job) (rate({A}[5m]))', "{{job}}")],
                  {"h": 8, "w": 12, "x": 0, "y": y}, stack=True))
    p.append(_lts("Bytes/s by job", [_ltarget(f'sum by (job) (bytes_rate({A}[5m]))', "{{job}}")],
                  {"h": 8, "w": 12, "x": 12, "y": y}, stack=True, unit="Bps",
                  description="Disk write pressure on metrics is proportional to this."))
    y += 8
    p.append(_lts("Top 10 senders, lines/s",
                  [_ltarget(f'topk(10, sum by (host) (rate({A}[5m])))', "{{host}}")],
                  {"h": 9, "w": 12, "x": 0, "y": y}))
    p.append(_ltable("Hottest streams now (lines/s, 5m) — LogStreamFlood fires at 30",
                     f'topk(15, sum by (host, job, unit, container) (rate({A}[5m])))',
                     {"h": 9, "w": 12, "x": 12, "y": y}, value_name="lines/s"))
    y += 9

    p.append(_row("Senders", y)); y += 1
    p.append(_ltable("journald hosts — lines in range (a missing row is a silent sender)",
                     f'sum by (host) (count_over_time({{job="journal"}}[$__range]))',
                     {"h": 12, "w": 8, "x": 0, "y": y}, sort_desc=False))
    p.append(_ltable("Docker hosts — lines in range",
                     f'sum by (host) (count_over_time({{job="docker"}}[$__range]))',
                     {"h": 12, "w": 8, "x": 8, "y": y}, sort_desc=False))
    p.append(_ltable("Appliances — lines in range",
                     f'sum by (host) (count_over_time({{job="syslog"}}[$__range]))',
                     {"h": 12, "w": 8, "x": 16, "y": y}, sort_desc=False))
    y += 12
    p.append(_lts("Appliance syslog lines/min (SyslogReceiverSilent watches 30m of this)",
                  [_ltarget('sum(rate({job="syslog"}[5m])) * 60', "syslog")],
                  {"h": 7, "w": 12, "x": 0, "y": y}))
    p.append(_lts("Loki write rejections/min (from the loki container's own log)",
                  [_ltarget('sum(rate({job="docker", container="loki"} |= "write operation failed" [5m])) * 60',
                            "rejections")],
                  {"h": 7, "w": 12, "x": 12, "y": y},
                  description="Mostly 'timestamp too old' when a new docker source "
                              "replays its json-file history; sustained non-zero "
                              "means a sender's clock or an out-of-order stream."))
    y += 7
    # ── Prometheus-side internals: Alloy self-metrics (remote_write) + Loki
    p.append(_row("Agents & Loki internals (Prometheus)", y)); y += 1

    def pts(title, expr, grid, unit="short", legend="{{host}}", stack=False, desc=""):
        t = _lts(title, [{"refId": "A", "datasource": DS_PROM, "expr": expr,
                          "legendFormat": legend}], grid, unit=unit, stack=stack,
                 description=desc)
        t["datasource"] = DS_PROM
        return t
    p.append(_lstat("Alloy agents reporting",
                    'count(alloy_build_info)',
                    {"h": 4, "w": 6, "x": 0, "y": y}, ds=DS_PROM,
                    description="Distinct hosts remote-writing alloy_build_info. "
                                "AlloyAgentDown fires per missing log_agent host."))
    p.append(_lstat("Loki up", 'up{job="loki"}', {"h": 4, "w": 6, "x": 6, "y": y},
                    thresholds=[{"color": RED, "value": None}, {"color": GREEN, "value": 1}],
                    ds=DS_PROM))
    p.append(_lstat("Loki lines received/s",
                    'sum(rate(loki_distributor_lines_received_total[5m]))',
                    {"h": 4, "w": 6, "x": 12, "y": y}, ds=DS_PROM))
    p.append(_lstat("Loki active streams", 'sum(loki_ingester_memory_streams)',
                    {"h": 4, "w": 6, "x": 18, "y": y}, ds=DS_PROM,
                    description="Label cardinality in one number. Grows with "
                                "hosts x units x containers; a jump means a "
                                "new high-cardinality label."))
    y += 4
    p.append(pts("Alloy: lines dropped/s by host & reason",
                 'sum by (host, reason) (rate(loki_process_dropped_lines_total[5m]))',
                 {"h": 8, "w": 12, "x": 0, "y": y}, legend="{{host}} {{reason}}", stack=True,
                 desc="known_noise = grafana_alloy_docker_drop_patterns (intended); "
                      "ratelimit_drop_stage = a container over 20/s (investigate); "
                      "line_too_long = >16KB lines."))
    p.append(pts("Alloy: entries sent to Loki/s by host",
                 'sum by (host) (rate(loki_write_sent_entries_total[5m]))',
                 {"h": 8, "w": 12, "x": 12, "y": y}, stack=True))
    y += 8
    p.append(pts("Alloy: write failures/s (dropped entries, by host & reason)",
                 'sum by (host, reason) (rate(loki_write_dropped_entries_total[5m]))',
                 {"h": 8, "w": 12, "x": 0, "y": y}, legend="{{host}} {{reason}}"))
    p.append(pts("Loki: discarded samples/s by reason",
                 'sum by (reason) (rate(loki_discarded_samples_total[5m]))',
                 {"h": 8, "w": 12, "x": 12, "y": y}, legend="{{reason}}",
                 desc="timestamp too old = a source replaying old history (one-off); "
                      "sustained = sender clock / out-of-order stream."))
    y += 8
    p.append(pts("Loki: request latency p99 by route (s)",
                 'histogram_quantile(0.99, sum by (le, route) (rate(loki_request_duration_seconds_bucket{route=~"loki_api_v1_(push|query|query_range)"}[5m])))',
                 {"h": 8, "w": 12, "x": 0, "y": y}, unit="s", legend="{{route}}"))
    p.append(pts("Loki: process memory & chunks flushed/s",
                 'process_resident_memory_bytes{job="loki"}',
                 {"h": 8, "w": 12, "x": 12, "y": y}, unit="bytes", legend="RSS"))
    p[-1]["targets"].append({"refId": "B", "datasource": DS_PROM,
                             "expr": 'sum(rate(loki_ingester_chunks_flushed_total[5m]))',
                             "legendFormat": "chunks flushed/s"})
    p[-1]["fieldConfig"]["overrides"] = [
        {"matcher": {"id": "byName", "options": "chunks flushed/s"},
         "properties": [{"id": "unit", "value": "short"},
                        {"id": "custom.axisPlacement", "value": "right"}]}]
    y += 8

    p.append(_text(
        "**Retention:** 90d default, `job=docker` 30d. **Sender-side limits:** "
        "Alloy drops container lines over 20/s (burst 400) per container and "
        "known-noise patterns (roles/grafana_alloy defaults). **Audit:** "
        "`ansible/loki_sender_audit.py` compares inventory to the senders here.",
        {"h": 3, "w": 24, "x": 0, "y": y}))
    y += 3

    return _dash(
        "sfmix-log-pipeline", "Log Pipeline", p, [],
        "Fleet-wide Loki ingest: rates by job/host, hottest streams, sender "
        "inventory and Loki's own write rejections. Generated by "
        "gen_nms_dashboards.py — edits will be overwritten.",
        links=[("Host Logs", "/d/sfmix-host-logs/host-logs"),
               ("Container Logs", "/d/sfmix-container-logs/container-logs"),
               ("Network Device Logs", "/d/sfmix-device-logs/network-device-logs")],
        time_from="now-24h")


# ── TLS Certificates ─────────────────────────────────────────────────

def tls_dashboard():
    """Served-certificate expiry and probe health from blackbox_exporter.
    Landing page for TLSCertExpiringSoon/Critical, TLSCertExpired,
    TLSProbeFailing."""
    I = 'instance=~"$instance"'
    days = f'(probe_ssl_earliest_cert_expiry{{{I}}} - time()) / 86400'
    p, y = [], 0

    p.append(_row("Fleet", y)); y += 1
    stats = [
        ("Endpoints probed", f'count(probe_success{{job=~"blackbox-tls.*", {I}}})', None),
        ("Probes failing", f'count(probe_success{{job=~"blackbox-tls.*", {I}}} == 0) or vector(0)',
         [{"color": GREEN, "value": None}, {"color": RED, "value": 1}]),
        ("Certs < 21 days", f'count({days} < 21) or vector(0)',
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 1}]),
        ("Certs < 7 days", f'count({days} < 7) or vector(0)',
         [{"color": GREEN, "value": None}, {"color": RED, "value": 1}]),
        ("Soonest expiry (days)", f'min({days})',
         [{"color": RED, "value": None}, {"color": AMBER, "value": 7},
          {"color": GREEN, "value": 21}]),
    ]
    w = 24 // len(stats)
    for i, (t, e, th) in enumerate(stats):
        p.append(_lstat(t, e, {"h": 4, "w": w, "x": w * i, "y": y}, thresholds=th, ds=DS_PROM))
    y += 4

    tbl = _ltable("Served certificates — days to expiry", days,
                  {"h": 12, "w": 12, "x": 0, "y": y}, value_name="days",
                  sort_desc=False, unit="d", ds=DS_PROM)
    tbl["transformations"][0]["options"]["excludeByName"].update(
        {"__name__": True, "job": True})
    tbl["fieldConfig"]["overrides"][0]["properties"] = [
        {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
        {"id": "thresholds", "value": {"mode": "absolute", "steps": [
            {"color": RED, "value": None}, {"color": AMBER, "value": 7},
            {"color": GREEN, "value": 21}]}},
        {"id": "color", "value": {"mode": "thresholds"}}]
    p.append(tbl)
    prob = _ltable("Probe status (1 = handshake OK)",
                   f'probe_success{{job=~"blackbox-tls.*", {I}}}',
                   {"h": 12, "w": 12, "x": 12, "y": y}, value_name="up",
                   sort_desc=False, ds=DS_PROM)
    prob["transformations"][0]["options"]["excludeByName"].update({"__name__": True})
    prob["fieldConfig"]["overrides"][0]["properties"] = [
        {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
        {"id": "thresholds", "value": {"mode": "absolute", "steps": [
            {"color": RED, "value": None}, {"color": GREEN, "value": 1}]}},
        {"id": "color", "value": {"mode": "thresholds"}}]
    p.append(prob)
    y += 12

    p.append(_row("Trend — $instance", y)); y += 1

    def pts(title, expr, grid, unit="short", legend="{{instance}}"):
        t = _lts(title, [{"refId": "A", "datasource": DS_PROM, "expr": expr,
                          "legendFormat": legend}], grid, unit=unit)
        t["datasource"] = DS_PROM
        return t
    p.append(pts("Days to expiry (a renewal shows as a step up to ~90)", days,
                 {"h": 9, "w": 12, "x": 0, "y": y}, unit="d"))
    p.append(pts("Probe success", f'probe_success{{job=~"blackbox-tls.*", {I}}}',
                 {"h": 9, "w": 12, "x": 12, "y": y}))
    y += 9
    p.append(pts("Probe duration", f'probe_duration_seconds{{job=~"blackbox-tls.*", {I}}}',
                 {"h": 8, "w": 12, "x": 0, "y": y}, unit="s"))
    p.append(pts("TLS version negotiated", f'probe_tls_version_info{{{I}}}',
                 {"h": 8, "w": 12, "x": 12, "y": y}, legend="{{instance}} {{version}}"))
    y += 8

    templ = [_prom_label_var("instance", "Endpoint",
                             'label_values(probe_success{job=~"blackbox-tls.*"}, instance)')]
    return _dash(
        "sfmix-tls", "TLS Certificates", p, templ,
        "What each public endpoint actually serves on the wire (blackbox_exporter "
        "TLS probes): days to expiry, probe health, trends. A cert on disk that "
        "nginx never reloaded shows up here and nowhere else. Generated by "
        "gen_nms_dashboards.py — edits will be overwritten.",
        time_from="now-7d")


def alert_dashboards():
    return [host_logs_dashboard(), container_logs_dashboard(),
            device_logs_dashboard(), log_pipeline_dashboard(), tls_dashboard()]
