"""Backups dashboard for the SFMIX NMS folder (design doc 013).

  Backups   /d/sfmix-backups   per-app freshness, sizes and integrity from the
                               backup target's textfile metrics, plus the
                               health of the storage underneath: backup01's
                               volume, the Thanos/Garage long-term tier
                               (doc 012) and the hypervisor ZFS pools.

Data sources:
  sfmix_backup_*                 roles/backup_target seal + verify jobs
                                 (node_exporter textfile collector, backup01)
  sfmix:backup_max_age_seconds   rules/backup.rules.yml: each client's
                                 freshness window, one series per backup_push
                                 host, so a client that never reported still
                                 gets a row
  node_* / garage / thanos       node_exporter, Garage admin API, Thanos

Imported by gen_nms_dashboards.py, which pushes it alongside the SNMP
dashboards and substitutes the real datasource uids.
"""

DS_PROM = {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}
DS_LOKI = {"type": "loki", "uid": "${DS_LOKI}"}
GREEN, AMBER, RED = "#3d9950", "#e8a33d", "#e0226e"
NEUTRAL = [{"color": "#c8ccd1", "value": None}]
ZERO_GOOD = [{"color": GREEN, "value": None}, {"color": RED, "value": 1}]
PCT_STEPS = [{"color": GREEN, "value": None}, {"color": AMBER, "value": 75},
             {"color": RED, "value": 90}]
# Fraction of the client's alert window used: BackupStale fires at 1.0.
WINDOW_STEPS = [{"color": GREEN, "value": None}, {"color": AMBER, "value": 0.75},
                {"color": RED, "value": 1}]

BACKUP_HOST = "backup01.scl04.sfmix.org"
BACKUP_FS = f'host="{BACKUP_HOST}", mountpoint="/srv/backup"'
TELEMETRY_FS = 'host=~"metrics01\\\\..*", mountpoint="/srv/telemetry"'

# ── shared PromQL ────────────────────────────────────────────────────

LAST = "max by (client) (sfmix_backup_last_timestamp_seconds)"
WINDOW = "max by (client) (sfmix:backup_max_age_seconds)"
# Age / window. A client with a window but no sealed bundle at all reads 99
# (mapped to "never"), so it sorts to the top and shows red.
WINDOW_USED = (f"((time() - {LAST}) / on (client) {WINDOW})"
               f" or on (client) ({WINDOW} * 0 + 99)")
NEVER_MAP = [{"type": "range", "options": {
    "from": 50, "to": 1e9, "result": {"text": "never", "color": RED, "index": 0}}}]

# ── panel helpers (mirror the shapes in nms_node_dashboards) ─────────


def _t(expr, legend="", refid="A", instant=False, ds=DS_PROM):
    t = {"refId": refid, "datasource": ds, "expr": expr, "legendFormat": legend}
    if instant:
        t.update(instant=True, range=False, format="table")
    return t


def _ts(title, targets, grid, unit="short", stack=False, min_val=0, max_val=None,
        description="", steps=None, log_scale=False, draw="line", calcs=None):
    custom = {"lineWidth": 1, "fillOpacity": 22 if stack else 8, "pointSize": 3,
              "showPoints": "never", "spanNulls": True, "drawStyle": draw}
    if stack:
        custom["stacking"] = {"mode": "normal", "group": "A"}
    if log_scale:
        custom["scaleDistribution"] = {"type": "log", "log": 10}
    defaults = {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}}
    if steps:
        custom["thresholdsStyle"] = {"mode": "dashed"}
        defaults["thresholds"] = {"mode": "absolute", "steps": steps}
    if min_val is not None and not log_scale:
        defaults["min"] = min_val
    if max_val is not None:
        defaults["max"] = max_val
    return {
        "type": "timeseries", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_PROM, "targets": targets,
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"legend": {"displayMode": "table", "placement": "right",
                               "calcs": calcs or ["lastNotNull", "max"]},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    }


def _stat(title, expr, grid, unit="short", decimals=None, steps=None,
          description="", mappings=None, no_value=None, legend=""):
    d = {"unit": unit, "color": {"mode": "thresholds"},
         "thresholds": {"mode": "absolute", "steps": steps or NEUTRAL},
         "mappings": mappings or []}
    if decimals is not None:
        d["decimals"] = decimals
    if no_value is not None:
        d["noValue"] = no_value
    return {
        "type": "stat", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_PROM, "targets": [_t(expr, legend)],
        "fieldConfig": {"defaults": d, "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]},
                    "graphMode": "none", "colorMode": "value",
                    "textMode": "value_and_name" if legend else "value"},
    }


def _row(title, y):
    return {"type": "row", "title": title, "collapsed": False,
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}}


def _text(md, grid):
    return {"type": "text", "title": "", "gridPos": grid,
            "options": {"mode": "markdown", "content": md}}


def _merged_table(title, cols, key, grid, description="", extra_targets=(),
                  exclude=(), first=(), key_links=None):
    """One instant query per column, merged on the shared label(s)."""
    targets = [_t(e, refid=chr(ord("A") + i), instant=True)
               for i, (_, e, *_) in enumerate(cols)]
    targets += list(extra_targets)
    rename = {f"Value #{chr(ord('A') + i)}": c[0] for i, c in enumerate(cols)}
    overrides = []
    if key_links:
        overrides.append({"matcher": {"id": "byName", "options": key},
                          "properties": [{"id": "links", "value": key_links}]})
    for name, _, unit, steps, *rest in cols:
        props = [{"id": "unit", "value": unit}]
        if unit in ("short", "none"):
            props.append({"id": "decimals", "value": 0})
        if steps:
            props += [{"id": "thresholds", "value": {"mode": "absolute", "steps": steps}},
                      {"id": "custom.cellOptions", "value": {"type": "color-text"}}]
        if rest and rest[0]:
            props.append({"id": "mappings", "value": rest[0]})
        overrides.append({"matcher": {"id": "byName", "options": name},
                          "properties": props})
    return {
        "type": "table", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_PROM, "targets": targets,
        "transformations": [
            {"id": "merge", "options": {}},
            {"id": "organize", "options": {
                "excludeByName": {"Time": True, **{e: True for e in exclude}},
                "indexByName": {k: i for i, k in enumerate((key, *first))},
                "renameByName": rename}},
            {"id": "sortBy", "options": {"sort": [{"field": key, "desc": False}]}},
        ],
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": overrides},
        "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
    }


# ── Backups ──────────────────────────────────────────────────────────

def backups_dashboard():
    p, y = [], 0

    # ── Overview ──
    p.append(_row("Overview", y)); y += 1
    stats = [
        ("Backup alerts firing",
         'count(ALERTS{component="backups", alertstate="firing"}) or vector(0)',
         "short", ZERO_GOOD, None,
         "BackupStale / SealerStale / VerifyStale / Quarantined / ArchiveCorrupt "
         "currently firing. Rules: roles/prometheus rules/backup.rules.yml."),
        ("Apps backed up", f"count({WINDOW})", "short", NEUTRAL, None,
         "Hosts in the backup_push inventory group (one freshness window each)."),
        ("Apps overdue", f"count(({WINDOW_USED}) >= 1) or vector(0)",
         "short", ZERO_GOOD, None,
         "Apps whose newest sealed bundle is older than their window, or that "
         "have never delivered one."),
        ("Worst window used", f"max({WINDOW_USED})", "percentunit", WINDOW_STEPS,
         NEVER_MAP,
         "The stalest app's age as a fraction of its alert window. "
         "BackupStale fires at 100% (after 30m)."),
        ("Quarantined uploads", "sum(sfmix_backup_quarantined_files) or vector(0)",
         "short", ZERO_GOOD, None,
         "Uploads that failed zstd -t on arrival, held in <client>/quarantine/."),
        ("Corrupt sealed bundles", "sum(sfmix_backup_verify_failed_files) or vector(0)",
         "short", ZERO_GOOD, None,
         "Archived bundles failing the weekly re-verify: corruption at rest."),
    ]
    for i, (t, e, u, st, mp, d) in enumerate(stats):
        p.append(_stat(t, e, {"h": 4, "w": 4, "x": 4 * i, "y": y}, unit=u,
                       steps=st, mappings=mp, description=d, decimals=0 if u == "short" else None))
    y += 4
    stats2 = [
        ("Archive held", "sum(sfmix_backup_archive_bytes)", "bytes", NEUTRAL,
         "Bytes of sealed bundles across all apps (30d retention, newest 10 always kept)."),
        ("Bundles held", "sum(sfmix_backup_archive_files)", "short", NEUTRAL, ""),
        ("Seal job last ran", "time() - max(sfmix_backup_seal_last_run_timestamp_seconds)",
         "dtdurations", [{"color": GREEN, "value": None}, {"color": AMBER, "value": 1800},
                         {"color": RED, "value": 3600}],
         "sfmix-backup-seal.timer runs every 10 min; uploads stay in client-writable "
         "incoming/ until it does."),
        ("Verify last ran", "time() - max(sfmix_backup_verify_last_run_timestamp_seconds)",
         "dtdurations", [{"color": GREEN, "value": None}, {"color": AMBER, "value": 7.5 * 86400},
                         {"color": RED, "value": 8 * 86400}],
         "Weekly zstd re-check of every sealed bundle."),
        ("/srv/backup used",
         f"1 - node_filesystem_avail_bytes{{{BACKUP_FS}}} / node_filesystem_size_bytes{{{BACKUP_FS}}}",
         "percentunit", [{"color": GREEN, "value": None}, {"color": AMBER, "value": 0.75},
                         {"color": RED, "value": 0.9}],
         "Grow with `qm resize 109 scsi1 +NG` on pve01.scl04, then resize2fs."),
        ("/srv/backup full in",
         f"node_filesystem_avail_bytes{{{BACKUP_FS}}} "
         f"/ (-deriv(node_filesystem_avail_bytes{{{BACKUP_FS}}}[7d]) > 0)",
         "s", [{"color": RED, "value": None}, {"color": AMBER, "value": 30 * 86400},
               {"color": GREEN, "value": 90 * 86400}],
         "Linear projection of free space over the last 7 days. Blank = not filling."),
    ]
    for i, (t, e, u, st, d) in enumerate(stats2):
        s = _stat(t, e, {"h": 4, "w": 4, "x": 4 * i, "y": y}, unit=u, steps=st,
                  description=d, decimals=1 if u in ("percentunit",) else None,
                  no_value="not filling" if "full in" in t else None)
        p.append(s)
    y += 4

    # ── Per app ──
    p.append(_row("Per app", y)); y += 1
    cols = [
        ("Last sealed", f"{LAST} * 1000", "dateTimeFromNow", None),
        ("Age", f"time() - {LAST}", "dtdurations", None),
        ("Window", WINDOW, "dtdurations", None),
        ("Window used", WINDOW_USED, "percentunit", WINDOW_STEPS, NEVER_MAP),
        ("Last bundle", "max by (client) (sfmix_backup_last_size_bytes)", "bytes", None),
        ("Bundles held", "max by (client) (sfmix_backup_archive_files)", "short", None),
        ("Archive held", "max by (client) (sfmix_backup_archive_bytes)", "bytes", None),
        ("Quarantined", "max by (client) (sfmix_backup_quarantined_files)", "short", ZERO_GOOD),
        ("Verified", "max by (client) (sfmix_backup_verify_checked_files)", "short", None),
        ("Verify failed", "max by (client) (sfmix_backup_verify_failed_files)", "short", ZERO_GOOD),
    ]
    push_host = _t("max by (client, push_host) (sfmix:backup_max_age_seconds)",
                   refid="H", instant=True)
    p.append(_merged_table(
        "Apps — now (click the push host for its backup-push journal)", cols, "client",
        {"h": 9, "w": 24, "x": 0, "y": y},
        description="One row per backup_push host. Window = BackupStale threshold "
                    "(backup_push_max_age_hours). Verified / Verify failed come "
                    "from the last weekly verify run (blank until it has run "
                    "once for that app).",
        extra_targets=[push_host], exclude=("Value #H",), first=("push_host",),
        key_links=None))
    # push_host links to the Host Logs dashboard filtered to the push unit.
    p[-1]["fieldConfig"]["overrides"].append(
        {"matcher": {"id": "byName", "options": "push_host"},
         "properties": [{"id": "displayName", "value": "Push host"},
                        {"id": "links", "value": [{
                            "title": "backup-push journal",
                            "url": "/d/sfmix-host-logs/host-logs?var-host=${__value.raw}"
                                   "&var-unit=sfmix-backup-push.service&from=now-2d&to=now"}]}]})
    y += 9

    p.append(_ts("Window used (age ÷ alert window)",
                 [_t(f"(time() - {LAST}) / on (client) {WINDOW}", "{{client}}")],
                 {"h": 8, "w": 12, "x": 0, "y": y}, unit="percentunit",
                 steps=[{"color": "transparent", "value": None},
                        {"color": AMBER, "value": 0.75}, {"color": RED, "value": 1}],
                 description="Sawtooth: climbs between pushes, drops to ~0 when a "
                             "bundle is sealed. Crossing the red line = BackupStale."))
    p.append(_ts("Last bundle size",
                 [_t("max by (client) (sfmix_backup_last_size_bytes)", "{{client}}")],
                 {"h": 8, "w": 12, "x": 12, "y": y}, unit="bytes", log_scale=True,
                 description="Size of the newest sealed bundle. A sudden drop "
                             "usually means a dump step silently produced less."))
    y += 8
    p.append(_ts("Archive held per app",
                 [_t("max by (client) (sfmix_backup_archive_bytes)", "{{client}}")],
                 {"h": 8, "w": 12, "x": 0, "y": y}, unit="bytes", stack=True,
                 calcs=["lastNotNull"]))
    p.append(_ts("Bundles held per app",
                 [_t("max by (client) (sfmix_backup_archive_files)", "{{client}}")],
                 {"h": 8, "w": 12, "x": 12, "y": y}, unit="short",
                 calcs=["lastNotNull"],
                 description="Retention: 30 days, but the newest 10 are always kept."))
    y += 8

    # ── backup01 ──
    p.append(_row(f"Backup target — {BACKUP_HOST} (VM 109 on pve01.scl04 tank)", y)); y += 1
    sel = f'host="{BACKUP_HOST}"'
    tstats = [
        ("node_exporter", f'max(up{{job="node", {sel}}})', "none",
         [{"color": RED, "value": None}, {"color": GREEN, "value": 1}],
         [{"type": "value", "options": {"0": {"text": "DOWN"}, "1": {"text": "up"}}}]),
        ("/srv/backup free", f"node_filesystem_avail_bytes{{{BACKUP_FS}}}", "bytes", NEUTRAL, None),
        ("/srv/backup size", f"node_filesystem_size_bytes{{{BACKUP_FS}}}", "bytes", NEUTRAL, None),
        ("Root FS used",
         f'1 - node_filesystem_avail_bytes{{{sel}, mountpoint="/"}} '
         f'/ node_filesystem_size_bytes{{{sel}, mountpoint="/"}}', "percentunit",
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 0.75},
          {"color": RED, "value": 0.9}], None),
        ("Memory used",
         f"1 - node_memory_MemAvailable_bytes{{{sel}}} / node_memory_MemTotal_bytes{{{sel}}}",
         "percentunit", [{"color": GREEN, "value": None}, {"color": AMBER, "value": 0.8},
                         {"color": RED, "value": 0.95}], None),
        ("Uptime", f"time() - node_boot_time_seconds{{{sel}}}", "dtdurations", NEUTRAL, None),
    ]
    for i, (t, e, u, st, mp) in enumerate(tstats):
        p.append(_stat(t, e, {"h": 4, "w": 4, "x": 4 * i, "y": y}, unit=u, steps=st,
                       mappings=mp, decimals=1 if u == "percentunit" else None))
    y += 4
    p.append(_ts("/srv/backup used vs size",
                 [_t(f"node_filesystem_size_bytes{{{BACKUP_FS}}} - "
                     f"node_filesystem_avail_bytes{{{BACKUP_FS}}}", "used"),
                  _t(f"node_filesystem_size_bytes{{{BACKUP_FS}}}", "size", refid="B")],
                 {"h": 8, "w": 8, "x": 0, "y": y}, unit="bytes",
                 calcs=["lastNotNull"]))
    p.append(_ts("Data disk throughput",
                 [_t(f'rate(node_disk_written_bytes_total{{{sel}, device="sda"}}[5m])', "write"),
                  _t(f'rate(node_disk_read_bytes_total{{{sel}, device="sda"}}[5m])', "read",
                     refid="B")],
                 {"h": 8, "w": 8, "x": 8, "y": y}, unit="Bps",
                 description="sda = the /srv/backup zvol. Device letters can shuffle "
                             "across reboots (the FS is mounted by label)."))
    p.append(_ts("Network in (pushes arriving)",
                 [_t(f'sum(rate(node_network_receive_bytes_total{{{sel}, device!="lo"}}[5m])) * 8',
                     "rx")],
                 {"h": 8, "w": 8, "x": 16, "y": y}, unit="bps", calcs=["lastNotNull", "max"]))
    y += 8

    # ── Long-term telemetry storage ──
    p.append(_row("Long-term telemetry storage — Thanos bucket on Garage (doc 012)", y)); y += 1
    gstats = [
        ("Garage cluster healthy", "min(cluster_healthy)", "none",
         [{"color": RED, "value": None}, {"color": GREEN, "value": 1}],
         [{"type": "value", "options": {"0": {"text": "NO"}, "1": {"text": "yes"}}}],
         "All storage nodes connected and every partition has quorum."),
        ("Storage nodes OK", "min(cluster_storage_nodes_ok) / max(cluster_storage_nodes)",
         "percentunit", [{"color": RED, "value": None}, {"color": AMBER, "value": 0.5},
                         {"color": GREEN, "value": 1}], None,
         "Replication 2 across metrics01.scl04 + metrics01.sfo02."),
        ("Resync errored blocks", "sum(block_resync_errored_blocks) or vector(0)", "short",
         ZERO_GOOD, None, "Blocks Garage failed to repair to their replica."),
        ("Resync queue", "sum(block_resync_queue_length)", "short",
         [{"color": GREEN, "value": None}, {"color": AMBER, "value": 1000}], None,
         "Blocks waiting to be re-replicated; non-zero after a node outage is normal."),
        ("Compactor halted", "max(thanos_compact_halted) or vector(0)", "short",
         ZERO_GOOD, None, "thanos compact stops on overlapping/corrupt blocks."),
        ("Sidecar last block upload",
         'time() - max(thanos_objstore_bucket_last_successful_upload_time{host="metrics.sfo02.sfmix.org"})',
         "dtdurations", [{"color": GREEN, "value": None}, {"color": AMBER, "value": 3 * 3600},
                         {"color": RED, "value": 6 * 3600}], None,
         "The sidecar ships a 2h TSDB block from metrics.sfo02 every ~2h."),
    ]
    for i, (t, e, u, st, mp, d) in enumerate(gstats):
        p.append(_stat(t, e, {"h": 4, "w": 4, "x": 4 * i, "y": y}, unit=u, steps=st,
                       mappings=mp, description=d,
                       decimals=0 if u in ("short", "percentunit") else None))
    y += 4
    p.append(_ts("/srv/telemetry used",
                 [_t(f"1 - node_filesystem_avail_bytes{{{TELEMETRY_FS}}} "
                     f"/ node_filesystem_size_bytes{{{TELEMETRY_FS}}}", "{{host}}")],
                 {"h": 8, "w": 12, "x": 0, "y": y}, unit="percentunit", max_val=1,
                 steps=[{"color": "transparent", "value": None},
                        {"color": AMBER, "value": 0.75}, {"color": RED, "value": 0.9}],
                 calcs=["lastNotNull"]))
    p.append(_ts("Garage data volume free",
                 [_t('garage_local_disk_avail{volume="data"}', "{{host}}")],
                 {"h": 8, "w": 12, "x": 12, "y": y}, unit="bytes", calcs=["lastNotNull"]))
    y += 8

    # ── Hypervisor pools ──
    p.append(_row("Hypervisor ZFS pools (VM disks, incl. backup01's zvol on pve01.scl04 tank)", y))
    y += 1
    p.append(_stat("Pools not ONLINE",
                   'count(node_zfs_zpool_state{state!="online"} == 1) or vector(0)',
                   {"h": 8, "w": 4, "x": 0, "y": y}, steps=ZERO_GOOD, decimals=0,
                   description="Any pool DEGRADED / FAULTED / SUSPENDED / UNAVAIL "
                               "on any Proxmox node."))
    p.append({
        "type": "table", "title": "Pool state", "gridPos": {"h": 8, "w": 8, "x": 4, "y": y},
        "datasource": DS_PROM,
        "targets": [_t("max by (host, zpool, state) (node_zfs_zpool_state) == 1",
                       instant=True)],
        "transformations": [
            {"id": "organize", "options": {
                "excludeByName": {"Time": True, "Value": True},
                "indexByName": {"host": 0, "zpool": 1, "state": 2}}},
            {"id": "sortBy", "options": {"sort": [{"field": "host"}]}}],
        "fieldConfig": {"defaults": {"custom": {"align": "auto"}}, "overrides": [
            {"matcher": {"id": "byName", "options": "state"}, "properties": [
                {"id": "mappings", "value": [
                    {"type": "value", "options": {"online": {"color": GREEN, "index": 0}}},
                    {"type": "regex", "options": {"pattern": ".*",
                                                  "result": {"color": RED, "index": 1}}}]},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}}]}]},
        "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
    })
    p.append(_ts("pve01.scl04 disk busy (per device; tank = the 8 HDDs)",
                 [_t('100 * rate(node_disk_io_time_seconds_total'
                     '{host="pve01.scl04.sfmix.org", device=~"sd[a-z]+"}[5m])', "{{device}}")],
                 {"h": 8, "w": 12, "x": 12, "y": y}, unit="percent", max_val=100,
                 description="8 aged ST4000DM000 in raidz2. One disk persistently "
                             "busier than its peers is an early sign of a failing drive."))
    y += 8
    p.append(_text(
        "**Not yet monitored:** zpool capacity / fragmentation, last scrub age and "
        "error counts, and SMART health of the tank drives. node_exporter only "
        "exports pool *state*. See doc 013 *Limits*.",
        {"h": 2, "w": 24, "x": 0, "y": y}))
    y += 2

    # ── Logs ──
    p.append(_row("Activity (journald via Loki)", y)); y += 1
    p.append({
        "type": "logs", "title": "Backup push / seal / verify",
        "description": "sfmix-backup-push on each app host; sfmix-backup-seal and "
                       "-verify on the target.",
        "gridPos": {"h": 12, "w": 24, "x": 0, "y": y}, "datasource": DS_LOKI,
        "targets": [{"refId": "A", "datasource": DS_LOKI,
                     "expr": '{unit=~"sfmix-backup-(push|seal|verify)\\\\.service"} '
                             '!= "pam_unix"'}],
        "options": {"showTime": True, "wrapLogMessage": True, "sortOrder": "Descending",
                    "enableLogDetails": True, "showLabels": False,
                    "showCommonLabels": False, "prettifyLogMessage": False,
                    "dedupStrategy": "none"},
    })
    y += 12

    return {
        "uid": "sfmix-backups", "title": "Backups",
        "tags": ["sfmix-nms", "generated", "backups"], "timezone": "browser",
        "description": "Fleet backups (doc 013) and the storage under them. "
                       "Generated by gen_nms_dashboards.py / nms_backup_dashboards.py "
                       "— edits will be overwritten.",
        "schemaVersion": 39, "refresh": "1m", "editable": True,
        "time": {"from": "now-2d", "to": "now"},
        "templating": {"list": []},
        "links": [
            {"title": "backup01 Host View", "type": "link", "icon": "dashboard",
             "url": f"/d/sfmix-host-view/host-view?var-host={BACKUP_HOST}",
             "keepTime": True},
            {"title": "pve01.scl04 Host View", "type": "link", "icon": "dashboard",
             "url": "/d/sfmix-host-view/host-view?var-host=pve01.scl04.sfmix.org",
             "keepTime": True},
        ],
        "panels": p,
    }


def backup_dashboards():
    return [backups_dashboard()]
