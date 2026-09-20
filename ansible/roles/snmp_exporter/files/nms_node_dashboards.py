"""Linux host dashboards (node_exporter) for the SFMIX NMS folder.

Every server and Proxmox hypervisor runs upstream node_exporter
(roles/sfmix_server, tasks/node_exporter.yml), scraped by Prometheus as
job="node" with instance=host=<inventory_hostname>.

  Linux Hosts   /d/sfmix-linux-hosts   fleet table + per-host trend lines
  Host View     /d/sfmix-host-view     ?var-host=   one host, node_exporter
                                       in full: CPU, memory, PSI, disks,
                                       filesystems, network, kernel, time

Imported by gen_nms_dashboards.py, which pushes these alongside the SNMP
dashboards and substitutes the real datasource uid for ${DS_PROMETHEUS}.
"""

DS_PROM = {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}
GREEN, AMBER, RED = "#3d9950", "#e8a33d", "#e0226e"

# Utilisation thresholds shared by every percentage stat/column.
PCT_STEPS = [{"color": GREEN, "value": None}, {"color": AMBER, "value": 70},
             {"color": RED, "value": 90}]
NEUTRAL = [{"color": "#c8ccd1", "value": None}]   # a value, not a verdict

# Pseudo/virtual filesystems and block devices that never mean anything for
# capacity or I/O (loop snaps, ramdisks, optical, ZFS zvols on the PVE hosts).
FS_SEL = 'fstype!~"tmpfs|squashfs|overlay|nsfs|autofs|fuse.*"'
DISK_SEL = 'device!~"^(loop|ram|sr|fd|zd).*"'

# ── panel helpers (Prometheus flavoured; mirror the shapes in gen_nms_dashboards) ──


def _t(expr, legend="", refid="A", instant=False):
    t = {"refId": refid, "datasource": DS_PROM, "expr": expr,
         "legendFormat": legend}
    if instant:
        t.update(instant=True, range=False, format="table")
    return t


def _ts(title, targets, grid, unit="short", stack=False, min_val=0,
        max_val=None, description="", legend_calcs=None, legend_right=False,
        overrides=None):
    custom = {"lineWidth": 1, "fillOpacity": 22 if stack else 8,
              "pointSize": 3, "showPoints": "never", "spanNulls": True}
    if stack:
        custom["stacking"] = {"mode": "normal", "group": "A"}
    defaults = {"unit": unit, "custom": custom,
                "color": {"mode": "palette-classic"}}
    if min_val is not None:
        defaults["min"] = min_val
    if max_val is not None:
        defaults["max"] = max_val
    return {
        "type": "timeseries", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_PROM, "targets": targets,
        "fieldConfig": {"defaults": defaults, "overrides": overrides or []},
        "options": {"legend": {"displayMode": "table",
                               "placement": "right" if legend_right else "bottom",
                               "calcs": legend_calcs or ["lastNotNull", "max"]},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    }


def _stat(title, expr, grid, unit="short", decimals=None, thresholds=None,
          description="", legend="", text_mode=None, graph=True):
    d = {"unit": unit, "color": {"mode": "thresholds"},
         "thresholds": {"mode": "absolute",
                        "steps": thresholds or [{"color": GREEN, "value": None}]},
         "mappings": []}
    if decimals is not None:
        d["decimals"] = decimals
    opts = {"reduceOptions": {"calcs": ["lastNotNull"]},
            "graphMode": "area" if graph else "none", "colorMode": "value"}
    if text_mode:
        opts["textMode"] = text_mode
        opts["colorMode"] = "none"
    return {
        "type": "stat", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_PROM,
        "targets": [_t(expr, legend)],
        "fieldConfig": {"defaults": d, "overrides": []},
        "options": opts,
    }


def _row(title, y):
    return {"type": "row", "title": title, "collapsed": False,
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}}


def _text(md, grid):
    return {"type": "text", "title": "", "gridPos": grid,
            "options": {"mode": "markdown", "content": md}}


def _host_var():
    q = "label_values(node_uname_info, host)"
    return {"name": "host", "label": "Host", "type": "query",
            "datasource": DS_PROM, "definition": q,
            "query": {"query": q, "refId": "host"},
            "refresh": 2, "sort": 1, "multi": False, "includeAll": False}


def _dash(uid, title, panels, templating, description, links=(),
          time_from="now-6h"):
    return {
        "uid": uid, "title": title, "tags": ["sfmix-nms", "generated", "hosts"],
        "timezone": "browser", "description": description,
        "schemaVersion": 39, "refresh": "1m", "editable": True,
        "time": {"from": time_from, "to": "now"},
        "templating": {"list": templating},
        "links": [{"title": t, "type": "link", "icon": "dashboard", "url": u,
                   "keepTime": True, "targetBlank": False}
                  for t, u in links],
        "panels": panels,
    }


# ── shared PromQL ────────────────────────────────────────────────────

def _cpu_pct(by="host", sel=""):
    return f'100 * (1 - avg by ({by}) (rate(node_cpu_seconds_total{{mode="idle"{sel}}}[5m])))'


def _mem_pct(sel=""):
    return (f'100 * (1 - node_memory_MemAvailable_bytes{{{sel}}} '
            f'/ node_memory_MemTotal_bytes{{{sel}}})')


def _fs_pct(sel):
    return (f'100 * (1 - node_filesystem_avail_bytes{{{sel}}} '
            f'/ node_filesystem_size_bytes{{{sel}}})')


HOST_VIEW_LINK = "/d/sfmix-host-view/host-view?var-host=${__data.fields.host}"


# ── Linux Hosts (fleet) ──────────────────────────────────────────────

def linux_hosts_dashboard():
    """Every host on one page: a sortable table of the headline numbers
    (click a row for Host View) and fleet trend lines below it."""
    p, y = [], 0

    p.append(_row("Fleet", y)); y += 1
    stats = [
        ("Hosts reporting", 'count(up{job="node"} == 1)', "short", NEUTRAL,
         "node_exporter targets Prometheus scraped successfully just now."),
        ("Targets down", 'count(up{job="node"} == 0) or vector(0)',
         "short", [{"color": GREEN, "value": None}, {"color": RED, "value": 1}],
         "Scrape targets Prometheus cannot reach (NodeExporterDown fires "
         "after 10m): host down, exporter stopped, bind/firewall/auth changed."),
        ("Hosts CPU > 80%",
         f'count({_cpu_pct()} > 80) or vector(0)', "short",
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 1}], ""),
        ("Hosts memory > 90%",
         f'count({_mem_pct("")} > 90) or vector(0)', "short",
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 1}], ""),
        ("Filesystems > 85%",
         f'count({_fs_pct(FS_SEL)} > 85) or vector(0)', "short",
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 1},
          {"color": RED, "value": 3}], "Any mountpoint on any host, tmpfs excluded."),
        ("Clock offset > 100 ms",
         'count(abs(node_timex_offset_seconds) > 0.1) or vector(0)', "short",
         [{"color": GREEN, "value": None}, {"color": RED, "value": 1}],
         "Hosts whose kernel time offset from their NTP source exceeds 100 ms."),
    ]
    for i, (t, e, u, th, d) in enumerate(stats):
        p.append(_stat(t, e, {"h": 4, "w": 4, "x": 4 * i, "y": y}, unit=u,
                       thresholds=th, description=d, graph=False))
    y += 4

    # Fleet table: one instant query per column, merged on `host`.
    cols = [
        ("Uptime", 'time() - node_boot_time_seconds', "dtdurations", None),
        ("Cores", 'count by (host) (node_cpu_seconds_total{mode="idle"})', "short", None),
        ("Load 1m / core",
         'node_load1 / count by (host) (node_cpu_seconds_total{mode="idle"})',
         "short", [{"color": GREEN, "value": None}, {"color": AMBER, "value": 0.7},
                   {"color": RED, "value": 1}]),
        ("CPU %", _cpu_pct(), "percent", PCT_STEPS),
        ("IO wait %",
         '100 * avg by (host) (rate(node_cpu_seconds_total{mode="iowait"}[5m]))',
         "percent", [{"color": GREEN, "value": None}, {"color": AMBER, "value": 10},
                     {"color": RED, "value": 25}]),
        ("Memory %", _mem_pct(""), "percent", PCT_STEPS),
        ("Swap %",
         '100 * (1 - node_memory_SwapFree_bytes / (node_memory_SwapTotal_bytes > 0))',
         "percent", [{"color": GREEN, "value": None}, {"color": AMBER, "value": 25},
                     {"color": RED, "value": 60}]),
        ("Fullest FS %", f'max by (host) ({_fs_pct(FS_SEL)})', "percent",
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 75},
          {"color": RED, "value": 85}]),
        ("Disk busy %",
         f'100 * max by (host) (rate(node_disk_io_time_seconds_total{{{DISK_SEL}}}[5m]))',
         "percent", PCT_STEPS),
        ("Net RX",
         'sum by (host) (rate(node_network_receive_bytes_total[5m])) * 8', "bps", None),
        ("Net TX",
         'sum by (host) (rate(node_network_transmit_bytes_total[5m])) * 8', "bps", None),
    ]
    targets = [_t(e, refid=chr(ord("A") + i), instant=True)
               for i, (_, e, _, _) in enumerate(cols)]
    # node_exporter version: a label on an info series, so it rides through
    # the merge as a plain column rather than a value.
    targets.append(_t('node_exporter_build_info', refid="V", instant=True))
    rename = {f"Value #{chr(ord('A') + i)}": name for i, (name, *_ ) in enumerate(cols)}
    overrides = [{"matcher": {"id": "byName", "options": "host"},
                  "properties": [{"id": "links", "value": [
                      {"title": "Host View", "url": HOST_VIEW_LINK}]},
                                 {"id": "custom.width", "value": 260}]}]
    for name, _, unit, steps in cols:
        props = [{"id": "unit", "value": unit}, {"id": "decimals", "value": 1}]
        if steps:
            props += [{"id": "thresholds", "value": {"mode": "absolute", "steps": steps}},
                      {"id": "custom.cellOptions", "value": {"type": "color-text"}}]
        if unit == "short" and name != "Load 1m / core":
            props[1] = {"id": "decimals", "value": 0}
        overrides.append({"matcher": {"id": "byName", "options": name},
                          "properties": props})
    p.append({
        "type": "table", "title": "Hosts — now (click a host for Host View)",
        "description": "One row per host reporting node_exporter. Percentages "
                       "are the last 5m averages; Fullest FS / Disk busy are the "
                       "worst mountpoint / block device on that host.",
        "gridPos": {"h": 14, "w": 24, "x": 0, "y": y}, "datasource": DS_PROM,
        "targets": targets,
        "transformations": [
            {"id": "merge", "options": {}},
            {"id": "organize", "options": {
                "excludeByName": {"Time": True, "instance": True, "job": True,
                                  "Value #V": True, "branch": True, "goarch": True,
                                  "goos": True, "goversion": True, "revision": True,
                                  "tags": True},
                "indexByName": {"host": 0, "version": 1},
                "renameByName": {**rename, "version": "Version"}}},
            {"id": "sortBy", "options": {"sort": [{"field": "host", "desc": False}]}},
        ],
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": overrides},
        "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
    })
    y += 14

    p.append(_row("Trends (per host)", y)); y += 1
    p.append(_ts("CPU %", [_t(_cpu_pct(), "{{host}}")],
                 {"h": 8, "w": 12, "x": 0, "y": y}, unit="percent", max_val=100))
    p.append(_ts("Memory % (1 - MemAvailable/MemTotal)", [_t(_mem_pct(""), "{{host}}")],
                 {"h": 8, "w": 12, "x": 12, "y": y}, unit="percent", max_val=100))
    y += 8
    p.append(_ts("Load 1m per core", [_t(
        'node_load1 / count by (host) (node_cpu_seconds_total{mode="idle"})', "{{host}}")],
        {"h": 8, "w": 12, "x": 0, "y": y},
        description="> 1 means runnable threads are queuing for a CPU."))
    p.append(_ts("IO pressure (PSI: % of time some task stalled on I/O)", [_t(
        '100 * rate(node_pressure_io_waiting_seconds_total[5m])', "{{host}}")],
        {"h": 8, "w": 12, "x": 12, "y": y}, unit="percent",
        description="Kernel PSI. Sustained double digits is the fsync/iowait "
                    "squeeze seen on the PVE hosts; see Host View for per-disk."))
    y += 8
    p.append(_ts("Fullest filesystem %", [_t(f'max by (host) ({_fs_pct(FS_SEL)})', "{{host}}")],
                 {"h": 8, "w": 12, "x": 0, "y": y}, unit="percent", max_val=100))
    p.append(_ts("Disk busy % (busiest device)", [_t(
        f'100 * max by (host) (rate(node_disk_io_time_seconds_total{{{DISK_SEL}}}[5m]))', "{{host}}")],
        {"h": 8, "w": 12, "x": 12, "y": y}, unit="percent", max_val=100))
    y += 8
    p.append(_ts("Network RX bits/s", [_t(
        'sum by (host) (rate(node_network_receive_bytes_total[5m])) * 8', "{{host}}")],
        {"h": 8, "w": 12, "x": 0, "y": y}, unit="bps"))
    p.append(_ts("Network TX bits/s", [_t(
        'sum by (host) (rate(node_network_transmit_bytes_total[5m])) * 8', "{{host}}")],
        {"h": 8, "w": 12, "x": 12, "y": y}, unit="bps"))
    y += 8
    p.append(_ts("Clock offset vs NTP source", [_t('node_timex_offset_seconds', "{{host}}")],
                 {"h": 7, "w": 12, "x": 0, "y": y}, unit="s", min_val=None))
    p.append(_ts("Root filesystem free", [_t(
        'node_filesystem_avail_bytes{mountpoint="/"}', "{{host}}")],
        {"h": 7, "w": 12, "x": 12, "y": y}, unit="bytes"))
    y += 7

    p.append(_text(
        "**Source:** upstream node_exporter on every server and hypervisor "
        "(roles/sfmix_server), scraped every 30s by Prometheus as `job=\"node\"`. "
        "Virtual NICs (veth/docker/tap/fw*) are excluded at collection "
        "(`sfmix_node_exporter_netdev_exclude`); tmpfs/overlay and loop/zvol "
        "devices are filtered in the queries. Generated by "
        "gen_nms_dashboards.py — edits will be overwritten.",
        {"h": 3, "w": 24, "x": 0, "y": y}))
    y += 3

    return _dash(
        "sfmix-linux-hosts", "Linux Hosts", p, [],
        "Fleet view of every Linux host's node_exporter metrics: a sortable "
        "table of current utilisation plus per-host trend lines. Generated by "
        "gen_nms_dashboards.py — edits will be overwritten.",
        links=[("Host View", "/d/sfmix-host-view/host-view"),
               ("Host Logs", "/d/sfmix-host-logs/host-logs"),
               ("Log Pipeline", "/d/sfmix-log-pipeline/log-pipeline")],
        time_from="now-24h")


# ── Host View ($host) ────────────────────────────────────────────────

def host_view_dashboard():
    """node_exporter in full for one host."""
    H = 'host="$host"'
    p, y = [], 0

    # ── headline
    p.append(_row("$host", y)); y += 1
    p.append(_stat("OS", f'node_os_info{{{H}}}', {"h": 3, "w": 6, "x": 0, "y": y},
                   legend="{{pretty_name}}", text_mode="name", graph=False))
    p.append(_stat("Kernel", f'node_uname_info{{{H}}}', {"h": 3, "w": 6, "x": 6, "y": y},
                   legend="{{release}}", text_mode="name", graph=False))
    p.append(_stat("Uptime", f'time() - node_boot_time_seconds{{{H}}}',
                   {"h": 3, "w": 4, "x": 12, "y": y}, unit="dtdurations",
                   thresholds=NEUTRAL, graph=False))
    p.append(_stat("Cores", f'count(node_cpu_seconds_total{{{H}, mode="idle"}})',
                   {"h": 3, "w": 2, "x": 16, "y": y}, thresholds=NEUTRAL, graph=False))
    p.append(_stat("Memory", f'node_memory_MemTotal_bytes{{{H}}}',
                   {"h": 3, "w": 3, "x": 18, "y": y}, unit="bytes", decimals=1,
                   thresholds=NEUTRAL, graph=False))
    p.append(_stat("Swap", f'node_memory_SwapTotal_bytes{{{H}}}',
                   {"h": 3, "w": 3, "x": 21, "y": y}, unit="bytes", decimals=1,
                   thresholds=NEUTRAL, graph=False))
    y += 3
    head = [
        ("CPU %", _cpu_pct(sel=", " + H), "percent", PCT_STEPS),
        ("Load 1m / core",
         f'node_load1{{{H}}} / count(node_cpu_seconds_total{{{H}, mode="idle"}})',
         "short", [{"color": GREEN, "value": None}, {"color": AMBER, "value": 0.7},
                   {"color": RED, "value": 1}]),
        ("Memory %", _mem_pct(H), "percent", PCT_STEPS),
        ("Root FS %", _fs_pct(f'{H}, mountpoint="/"'), "percent",
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 75},
          {"color": RED, "value": 85}]),
        ("Disk busy % (max)",
         f'100 * max(rate(node_disk_io_time_seconds_total{{{H}, {DISK_SEL}}}[5m]))',
         "percent", PCT_STEPS),
        ("Clock offset", f'node_timex_offset_seconds{{{H}}}', "s",
         [{"color": GREEN, "value": None}, {"color": RED, "value": 0.1}]),
    ]
    for i, (t, e, u, th) in enumerate(head):
        p.append(_stat(t, e, {"h": 4, "w": 4, "x": 4 * i, "y": y}, unit=u,
                       decimals=1 if u != "s" else 4, thresholds=th))
    y += 4

    # ── CPU
    p.append(_row("CPU", y)); y += 1
    p.append(_ts("CPU % by mode", [_t(
        f'100 * avg by (mode) (rate(node_cpu_seconds_total{{{H}, mode!="idle"}}[5m]))', "{{mode}}")],
        {"h": 8, "w": 12, "x": 0, "y": y}, unit="percent", stack=True, max_val=100,
        legend_right=True, description="Averaged over all cores; steal is the "
                                       "hypervisor taking cycles from a VM."))
    p.append(_ts("Load average", [
        _t(f'node_load1{{{H}}}', "1m"), _t(f'node_load5{{{H}}}', "5m", "B"),
        _t(f'node_load15{{{H}}}', "15m", "C"),
        _t(f'count(node_cpu_seconds_total{{{H}, mode="idle"}})', "cores", "D")],
        {"h": 8, "w": 12, "x": 12, "y": y}, overrides=[
            {"matcher": {"id": "byName", "options": "cores"},
             "properties": [{"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [10, 10]}},
                            {"id": "color", "value": {"mode": "fixed", "fixedColor": "#8a8f98"}},
                            {"id": "custom.fillOpacity", "value": 0}]}]))
    y += 8
    p.append(_ts("Pressure stall (PSI): % of wall time some task waited", [
        _t(f'100 * rate(node_pressure_cpu_waiting_seconds_total{{{H}}}[5m])', "cpu"),
        _t(f'100 * rate(node_pressure_memory_waiting_seconds_total{{{H}}}[5m])', "memory", "B"),
        _t(f'100 * rate(node_pressure_io_waiting_seconds_total{{{H}}}[5m])', "io", "C")],
        {"h": 8, "w": 12, "x": 0, "y": y}, unit="percent",
        description="Kernel pressure-stall information. Unlike load, this says "
                    "how much time was actually lost waiting for each resource."))
    p.append(_ts("Context switches & forks /s", [
        _t(f'rate(node_context_switches_total{{{H}}}[5m])', "context switches"),
        _t(f'rate(node_forks_total{{{H}}}[5m])', "forks", "B")],
        {"h": 8, "w": 12, "x": 12, "y": y}, overrides=[
            {"matcher": {"id": "byName", "options": "forks"},
             "properties": [{"id": "custom.axisPlacement", "value": "right"}]}]))
    y += 8

    # ── Memory
    p.append(_row("Memory", y)); y += 1
    p.append(_ts("Memory breakdown", [
        _t(f'node_memory_MemTotal_bytes{{{H}}} - node_memory_MemFree_bytes{{{H}}} '
           f'- node_memory_Buffers_bytes{{{H}}} - node_memory_Cached_bytes{{{H}}} '
           f'- node_memory_SReclaimable_bytes{{{H}}}', "used"),
        _t(f'node_memory_Cached_bytes{{{H}}} + node_memory_SReclaimable_bytes{{{H}}}', "cache", "B"),
        _t(f'node_memory_Buffers_bytes{{{H}}}', "buffers", "C"),
        _t(f'node_memory_MemFree_bytes{{{H}}}', "free", "D")],
        {"h": 8, "w": 12, "x": 0, "y": y}, unit="bytes", stack=True, legend_right=True,
        description="cache = page cache + reclaimable slab; both are given back "
                    "under pressure, so 'used' is what applications hold."))
    p.append(_ts("Swap & memory pressure", [
        _t(f'node_memory_SwapTotal_bytes{{{H}}} - node_memory_SwapFree_bytes{{{H}}}', "swap used"),
        _t(f'rate(node_vmstat_pswpin{{{H}}}[5m]) * 4096', "swap in B/s", "B"),
        _t(f'rate(node_vmstat_pswpout{{{H}}}[5m]) * 4096', "swap out B/s", "C"),
        _t(f'rate(node_vmstat_oom_kill{{{H}}}[5m]) * 300', "OOM kills (5m)", "D")],
        {"h": 8, "w": 12, "x": 12, "y": y}, unit="bytes", overrides=[
            {"matcher": {"id": "byRegexp", "options": "swap (in|out).*"},
             "properties": [{"id": "unit", "value": "Bps"},
                            {"id": "custom.axisPlacement", "value": "right"}]},
            {"matcher": {"id": "byName", "options": "OOM kills (5m)"},
             "properties": [{"id": "unit", "value": "short"},
                            {"id": "custom.axisPlacement", "value": "right"},
                            {"id": "color", "value": {"mode": "fixed", "fixedColor": RED}},
                            {"id": "custom.drawStyle", "value": "bars"}]}],
        description="Steady swap-in/out means the working set no longer fits. "
                    "OOM kills are the kernel's own counter (node_vmstat_oom_kill)."))
    y += 8

    # ── Storage
    p.append(_row("Storage", y)); y += 1
    p.append(_ts("Filesystem used % by mountpoint", [_t(
        _fs_pct(f'{H}, {FS_SEL}'), "{{mountpoint}} ({{device}})")],
        {"h": 8, "w": 12, "x": 0, "y": y}, unit="percent", max_val=100, legend_right=True))
    p.append(_ts("Inodes used % by mountpoint", [_t(
        f'100 * (1 - node_filesystem_files_free{{{H}, {FS_SEL}}} '
        f'/ node_filesystem_files{{{H}, {FS_SEL}}})', "{{mountpoint}}")],
        {"h": 8, "w": 12, "x": 12, "y": y}, unit="percent", max_val=100, legend_right=True,
        description="ZFS reports inodes dynamically so these stay near zero there; "
                    "ext4 runs out for real (many small files)."))
    y += 8
    p.append(_ts("Disk throughput", [
        _t(f'rate(node_disk_read_bytes_total{{{H}, {DISK_SEL}}}[5m])', "{{device}} read"),
        _t(f'-rate(node_disk_written_bytes_total{{{H}, {DISK_SEL}}}[5m])', "{{device}} write", "B")],
        {"h": 8, "w": 8, "x": 0, "y": y}, unit="Bps", min_val=None, legend_right=False,
        description="Reads above the axis, writes below."))
    p.append(_ts("Disk IOPS", [
        _t(f'rate(node_disk_reads_completed_total{{{H}, {DISK_SEL}}}[5m])', "{{device}} read"),
        _t(f'-rate(node_disk_writes_completed_total{{{H}, {DISK_SEL}}}[5m])', "{{device}} write", "B")],
        {"h": 8, "w": 8, "x": 8, "y": y}, unit="iops", min_val=None,
        description="Reads above the axis, writes below."))
    p.append(_ts("Disk busy % & queue", [
        _t(f'100 * rate(node_disk_io_time_seconds_total{{{H}, {DISK_SEL}}}[5m])', "{{device}} busy"),
        _t(f'rate(node_disk_io_time_weighted_seconds_total{{{H}, {DISK_SEL}}}[5m])', "{{device}} queue", "B")],
        {"h": 8, "w": 8, "x": 16, "y": y}, unit="percent", overrides=[
            {"matcher": {"id": "byRegexp", "options": ".* queue"},
             "properties": [{"id": "unit", "value": "short"},
                            {"id": "custom.axisPlacement", "value": "right"},
                            {"id": "custom.lineStyle", "value": {"fill": "dot", "dash": [2, 4]}}]}],
        description="busy = % of time the device had a request in flight; "
                    "queue = average requests in flight (weighted io time)."))
    y += 8
    p.append(_ts("Disk latency (avg per op)", [
        _t(f'rate(node_disk_read_time_seconds_total{{{H}, {DISK_SEL}}}[5m]) '
           f'/ rate(node_disk_reads_completed_total{{{H}, {DISK_SEL}}}[5m])', "{{device}} read"),
        _t(f'rate(node_disk_write_time_seconds_total{{{H}, {DISK_SEL}}}[5m]) '
           f'/ rate(node_disk_writes_completed_total{{{H}, {DISK_SEL}}}[5m])', "{{device}} write", "B")],
        {"h": 8, "w": 12, "x": 0, "y": y}, unit="s",
        description="Average time a completed request spent in the device, "
                    "queueing included. Tens of ms on SSD = the untrimmed-QVO fsync problem."))
    p.append(_ts("Filesystem free (absolute)", [_t(
        f'node_filesystem_avail_bytes{{{H}, {FS_SEL}}}', "{{mountpoint}}")],
        {"h": 8, "w": 12, "x": 12, "y": y}, unit="bytes", legend_right=True))
    y += 8

    # ── Network
    p.append(_row("Network", y)); y += 1
    p.append(_ts("Traffic by interface", [
        _t(f'rate(node_network_receive_bytes_total{{{H}}}[5m]) * 8', "{{device}} rx"),
        _t(f'-rate(node_network_transmit_bytes_total{{{H}}}[5m]) * 8', "{{device}} tx", "B")],
        {"h": 8, "w": 12, "x": 0, "y": y}, unit="bps", min_val=None,
        description="RX above the axis, TX below. veth/docker/tap/fw* interfaces "
                    "are excluded at collection (roles/sfmix_server)."))
    p.append(_ts("Errors & drops /s", [
        _t(f'rate(node_network_receive_errs_total{{{H}}}[5m])', "{{device}} rx errs"),
        _t(f'rate(node_network_transmit_errs_total{{{H}}}[5m])', "{{device}} tx errs", "B"),
        _t(f'rate(node_network_receive_drop_total{{{H}}}[5m])', "{{device}} rx drop", "C"),
        _t(f'rate(node_network_transmit_drop_total{{{H}}}[5m])', "{{device}} tx drop", "D")],
        {"h": 8, "w": 12, "x": 12, "y": y}, legend_right=True))
    y += 8
    p.append(_ts("Packets/s by interface", [
        _t(f'rate(node_network_receive_packets_total{{{H}}}[5m])', "{{device}} rx"),
        _t(f'-rate(node_network_transmit_packets_total{{{H}}}[5m])', "{{device}} tx", "B")],
        {"h": 7, "w": 8, "x": 0, "y": y}, unit="pps", min_val=None))
    p.append(_ts("TCP sockets", [
        _t(f'node_netstat_Tcp_CurrEstab{{{H}}}', "established"),
        _t(f'node_sockstat_TCP_tw{{{H}}}', "time-wait", "B"),
        _t(f'node_sockstat_TCP_alloc{{{H}}}', "allocated", "C")],
        {"h": 7, "w": 8, "x": 8, "y": y}))
    p.append(_ts("conntrack table", [
        _t(f'node_nf_conntrack_entries{{{H}}}', "entries"),
        _t(f'node_nf_conntrack_entries_limit{{{H}}}', "limit", "B")],
        {"h": 7, "w": 8, "x": 16, "y": y}, overrides=[
            {"matcher": {"id": "byName", "options": "limit"},
             "properties": [{"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [10, 10]}},
                            {"id": "color", "value": {"mode": "fixed", "fixedColor": "#8a8f98"}},
                            {"id": "custom.fillOpacity", "value": 0}]}],
        description="Empty on hosts without nf_conntrack loaded (no NAT/stateful "
                    "firewall); at the limit new connections are dropped."))
    y += 7

    # ── System
    p.append(_row("System", y)); y += 1
    p.append(_ts("Processes", [
        _t(f'node_procs_running{{{H}}}', "running"),
        _t(f'node_procs_blocked{{{H}}}', "blocked on I/O", "B")],
        {"h": 7, "w": 8, "x": 0, "y": y}))
    p.append(_ts("File descriptors", [
        _t(f'node_filefd_allocated{{{H}}}', "allocated"),
        _t(f'node_filefd_maximum{{{H}}}', "maximum", "B")],
        {"h": 7, "w": 8, "x": 8, "y": y}, overrides=[
            {"matcher": {"id": "byName", "options": "maximum"},
             "properties": [{"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [10, 10]}},
                            {"id": "color", "value": {"mode": "fixed", "fixedColor": "#8a8f98"}},
                            {"id": "custom.fillOpacity", "value": 0}]}]))
    p.append(_ts("Time sync (timex)", [
        _t(f'node_timex_offset_seconds{{{H}}}', "offset"),
        _t(f'node_timex_estimated_error_seconds{{{H}}}', "estimated error", "B"),
        _t(f'node_timex_sync_status{{{H}}}', "synced (1/0)", "C")],
        {"h": 7, "w": 8, "x": 16, "y": y}, unit="s", min_val=None, overrides=[
            {"matcher": {"id": "byName", "options": "synced (1/0)"},
             "properties": [{"id": "unit", "value": "short"},
                            {"id": "custom.axisPlacement", "value": "right"},
                            {"id": "custom.drawStyle", "value": "line"},
                            {"id": "custom.lineInterpolation", "value": "stepAfter"}]}]))
    y += 7
    p.append(_ts("Hardware temperatures", [_t(
        f'node_hwmon_temp_celsius{{{H}}}', "{{chip}} {{sensor}}")],
        {"h": 8, "w": 12, "x": 0, "y": y}, unit="celsius", min_val=None, legend_right=True,
        description="Physical hosts only (hwmon). Empty on VMs."))
    p.append(_ts("Entropy & interrupts", [
        _t(f'node_entropy_available_bits{{{H}}}', "entropy bits"),
        _t(f'rate(node_intr_total{{{H}}}[5m])', "interrupts/s", "B")],
        {"h": 8, "w": 12, "x": 12, "y": y}, overrides=[
            {"matcher": {"id": "byName", "options": "interrupts/s"},
             "properties": [{"id": "custom.axisPlacement", "value": "right"}]}]))
    y += 8

    p.append(_text(
        "**Source:** upstream node_exporter on this host (roles/sfmix_server, "
        "tasks/node_exporter.yml), scraped every 30s by Prometheus as "
        "`job=\"node\"`. OpenBSD hosts have no PSI/timex/vmstat rows. Logs for the "
        "same host: use the **Host Logs** link above (pre-filled). Generated by "
        "gen_nms_dashboards.py — edits will be overwritten.",
        {"h": 3, "w": 24, "x": 0, "y": y}))
    y += 3

    return _dash(
        "sfmix-host-view", "Host View", p, [_host_var()],
        "Everything node_exporter knows about one Linux host: CPU, load, PSI, "
        "memory, swap, filesystems, disk I/O and latency, network, sockets, "
        "processes, time sync, temperatures. Generated by gen_nms_dashboards.py "
        "— edits will be overwritten.",
        links=[("Linux Hosts", "/d/sfmix-linux-hosts/linux-hosts"),
               ("Host Logs", "/d/sfmix-host-logs/host-logs?var-host=${host}"),
               ("Container Logs", "/d/sfmix-container-logs/container-logs?var-host=${host}")])


def node_dashboards():
    return [linux_hosts_dashboard(), host_view_dashboard()]
