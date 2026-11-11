"""Long-term metrics (Thanos + Garage) dashboard for the SFMIX NMS folder.

  Long-term Metrics   /d/sfmix-longterm-metrics   (no variables)

Shows the mechanics of design doc 012 end to end: Prometheus keeps 30 days
locally, the thanos sidecar ships every 2h block to the Garage bucket
(metrics01.scl04 + metrics01.sfo02, two copies), thanos compact downsamples
(raw 30d / 5m 1y / 1h forever), and Grafana reads both tiers through thanos
query. Bucket coverage per resolution comes from the thanos-bucket-coverage
textfile exporter on metrics01.scl04 (roles/metrics_archive).

Imported by gen_nms_dashboards.py, which substitutes the real datasource uid
for ${DS_PROMETHEUS}.
"""

DS_PROM = {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}
GREEN, AMBER, RED = "#3d9950", "#e8a33d", "#e0226e"
NEUTRAL = [{"color": "#c8ccd1", "value": None}]
DOC_URL = ("https://github.com/sfmix/sfmix/blob/main/documentation/"
           "design_docs/012-long-term-telemetry-storage.md")


def _res(expr):
    """Map Thanos resolution millis to raw / 5m / 1h in a `res` label."""
    return ('label_replace(label_replace(label_replace({e}, "res", "raw", "resolution", "0"),'
            ' "res", "5m", "resolution", "300000"), "res", "1h", "resolution", "3600000")'
            ).format(e=expr)


# ── panel helpers (mirror the shapes in nms_node_dashboards) ──────────

def _t(expr, legend="", refid="A", instant=False):
    t = {"refId": refid, "datasource": DS_PROM, "expr": expr,
         "legendFormat": legend}
    if instant:
        t.update(instant=True, range=False, format="table")
    return t


def _ts(title, targets, grid, unit="short", stack=False, description="",
        min_val=0, legend_right=True):
    custom = {"lineWidth": 1, "fillOpacity": 22 if stack else 8,
              "pointSize": 3, "showPoints": "never", "spanNulls": True}
    if stack:
        custom["stacking"] = {"mode": "normal", "group": "A"}
    defaults = {"unit": unit, "custom": custom,
                "color": {"mode": "palette-classic"}}
    if min_val is not None:
        defaults["min"] = min_val
    return {
        "type": "timeseries", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_PROM, "targets": targets,
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"legend": {"displayMode": "table",
                               "placement": "right" if legend_right else "bottom",
                               "calcs": ["lastNotNull", "max"]},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    }


def _stat(title, expr, grid, unit="short", steps=None, description="",
          mappings=None, decimals=0):
    return {
        "type": "stat", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_PROM,
        "targets": [{"refId": "A", "datasource": DS_PROM, "expr": expr,
                     "instant": True, "range": False}],
        "fieldConfig": {"defaults": {
            "unit": unit, "decimals": decimals, "mappings": mappings or [],
            "color": {"mode": "thresholds"},
            "thresholds": {"mode": "absolute", "steps": steps or NEUTRAL}},
            "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]},
                    "graphMode": "none", "colorMode": "background",
                    "textMode": "value"},
    }


def _ok_map(ok_val, ok_text, bad_text):
    return [{"type": "value", "options": {
        str(ok_val): {"text": ok_text, "color": GREEN}}},
        {"type": "range", "options": {"from": -1e18, "to": 1e18,
                                      "result": {"text": bad_text, "color": RED}}}]


def _row(title, y):
    return {"type": "row", "title": title, "collapsed": False,
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}}


def _text(md, grid):
    return {"type": "text", "title": "", "gridPos": grid,
            "options": {"mode": "markdown", "content": md}}


def _g(x, y, w, h):
    return {"x": x, "y": y, "w": w, "h": h}


# ── the dashboard ──────────────────────────────────────────────────────

HOW = f"""
**How long-term metrics work** ([design doc 012]({DOC_URL}))

1. **Prometheus** on metrics.sfo02 scrapes and alerts, keeping **30 days** on its SSD
   in 2-hour blocks (local compaction off).
2. The **thanos sidecar** uploads every finished 2h block to the **Garage S3 bucket**,
   which keeps **two copies**: metrics01.scl04 (HDD) and metrics01.sfo02 (SSD).
3. **thanos compact** (metrics01.scl04) merges blocks and **downsamples**: raw is kept
   **30 days**, 5-minute averages **1 year**, 1-hour averages **forever**.
4. **Grafana** reads through **thanos query**, which merges recent raw data (sidecar) with
   history (thanos store), picking the coarsest resolution that fits the graph.
"""


# ── retention runway (forever tier vs fixed disks) ─────────────────────
#
# Everything is per copy: Garage replication 2 on 2 nodes = every node holds
# the whole bucket, so the smaller node's volume is the limit. Bucket figures
# are block bytes before Garage compression ("logical"); disk figures are
# physical. K converts between them.

FILL = 0.90                 # planning ceiling: keep 10% of the usable volume free
YEAR = 31557600             # seconds
MULTIPLIERS = [1, 2, 3, 5, 10]
_MP = 'mountpoint="/srv/telemetry", job="node"'

# Usable = size minus ext4's root reserve (free - avail), times the fill target.
CEILING = (f"min({FILL} * (node_filesystem_size_bytes{{{_MP}}}"
           f" - node_filesystem_free_bytes{{{_MP}}} + node_filesystem_avail_bytes{{{_MP}}}))")
USED = f"max(node_filesystem_size_bytes{{{_MP}}} - node_filesystem_free_bytes{{{_MP}}})"
# Physical bytes stored per logical block byte (zstd + Garage metadata).
K = (f"({USED} / (sum(thanos_bucket_size_bytes)"
     " + sum(thanos_bucket_pending_delete_bytes)))")


def _rate(res):
    return f'sum(thanos_bucket_growth_bytes_per_second{{resolution="{res}"}})'


def _ret(res):
    return f'sum(thanos_compact_retention_seconds{{resolution="{res}"}})'


# Logical size raw + 5m settle at once full: growth rate x retention.
FIXED = f'({_rate("raw")} * {_ret("raw")} + {_rate("5m")} * {_ret("5m")})'
FOREVER_NOW = 'sum(thanos_bucket_size_bytes{resolution="1h"})'


def _runway(m=1):
    """Years until the 1h tier fills the ceiling, ingestion x m from now on."""
    room = f"({CEILING} / {K} - {m} * {FIXED} - {FOREVER_NOW})"
    return f"{room} / ({m} * {_rate('1h')} * {YEAR})"


RUNWAY_STEPS = [{"color": RED, "value": None}, {"color": AMBER, "value": 5},
                {"color": GREEN, "value": 15}]

RUNWAY_HOW = f"""
**How the runway is estimated**

- **Ceiling** — the smaller Garage data volume (each node holds a full copy), minus
  ext4's root reserve, × {FILL:.0%}. The volumes are fixed 1 TiB VM disks: more
  room means a bigger disk, not a setting.
- **Growth** — block bytes per day of data in the newest 30 days of each resolution
  (thanos-bucket-coverage), i.e. today's series count, not the lifetime average.
- **raw** (30d) and **5m** (1y) stop growing once full: rate × retention.
  **1h** never ages out, so it gets whatever is left.
- **Runway** = (ceiling ÷ compression − raw − 5m − 1h so far) ÷ 1h growth per year.

The 1h rate trails by ~3 weeks (1h blocks need a compacted 10d+ source).
If ingestion jumps, the multiplier bars show what that does.
"""


def _bargauge(title, targets, grid, unit, description="", steps=None, decimals=None):
    defaults = {"unit": unit, "min": 0, "color": {"mode": "thresholds"},
                "thresholds": {"mode": "absolute", "steps": steps or NEUTRAL}}
    if decimals is not None:
        defaults["decimals"] = decimals
    for t in targets:
        t.update(instant=True, range=False)
    return {
        "type": "bargauge", "title": title, "description": description,
        "gridPos": grid, "datasource": DS_PROM, "targets": targets,
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"orientation": "horizontal", "displayMode": "basic",
                    "showUnfilled": True, "valueMode": "color", "namePlacement": "left",
                    "reduceOptions": {"calcs": ["lastNotNull"]}},
    }


def runway_panels(y):
    yr = "suffix: yr"
    p = [
        _stat("Ceiling per copy", CEILING, _g(0, y, 3, 4), unit="bytes", decimals=1,
              description=f"Smaller Garage volume minus ext4 reserve, × {FILL:.0%} fill target."),
        _stat("Ceiling used", f"{USED} / {CEILING}", _g(3, y, 3, 4), unit="percentunit",
              decimals=1,
              steps=[{"color": GREEN, "value": None}, {"color": AMBER, "value": 0.75},
                     {"color": RED, "value": 0.9}],
              description="Fuller node's disk use (blocks + Garage metadata) against the ceiling."),
        _stat("Stored per bucket byte", K, _g(6, y, 3, 4), decimals=2,
              description="Physical disk used ÷ block bytes in the bucket (incl. blocks "
                          "pending deletion): Garage zstd compression plus metadata."),
        _stat("raw + 5m when full", f"{FIXED} * {K}", _g(9, y, 3, 4), unit="bytes",
              decimals=1,
              description="On disk once raw (30d) and 5m (1y) have filled their retention "
                          "at today's growth. They stop growing there."),
        _stat("1h growth / year", f"{_rate('1h')} * {YEAR} * {K}", _g(12, y, 3, 4),
              unit="bytes", decimals=1,
              description="On disk per year added to the forever tier at today's ingestion."),
        _stat("Forever runway", _runway(), _g(15, y, 3, 4), unit=yr, decimals=0,
              steps=RUNWAY_STEPS,
              description="Years until the 1h tier fills the ceiling at today's ingestion."),
        _stat("Ceiling reached", f"1970 + (time() + {_runway()} * {YEAR}) / {YEAR}",
              _g(18, y, 3, 4), unit="none", decimals=0,
              description="Calendar year the ceiling is reached at today's ingestion."),
        _stat("1h history at full",
              f'(time() - min(thanos_bucket_min_time_seconds{{resolution="1h"}})) / {YEAR}'
              f" + {_runway()}", _g(21, y, 3, 4), unit=yr, decimals=0,
              description="How far back the 1h tier reaches when the ceiling is hit."),
    ]
    y += 4
    p += [
        _bargauge("Forever runway if ingestion grows", [
            _t(f"clamp_min({_runway(m)}, 0)", "today" if m == 1 else f"{m}× today",
               refid=chr(65 + i))
            for i, m in enumerate(MULTIPLIERS)], _g(0, y, 8, 9), unit=yr, decimals=1,
            steps=RUNWAY_STEPS,
            description="Series count (and so every tier's growth) × N from now on. "
                        "0 = raw + 5m alone would not fit."),
        _bargauge("Ceiling at steady state (per copy)", [
            _t(f'{_rate("raw")} * {_ret("raw")} * {K}', "raw · 30d"),
            _t(f'{_rate("5m")} * {_ret("5m")} * {K}', "5m · 1y", "B"),
            _t(f"{FOREVER_NOW} * {K}", "1h · stored so far", "C"),
            _t(f"{CEILING} - ({FIXED} + {FOREVER_NOW}) * {K}", "1h · room left", "D")],
            _g(8, y, 8, 9), unit="bytes", decimals=1,
            description="How the ceiling divides once raw and 5m are full, "
                        "at today's growth."),
        _text(RUNWAY_HOW, _g(16, y, 8, 9)),
    ]
    y += 9
    p += [
        _ts("Growth per day of data, by resolution", [
            _t("sum by (resolution) (thanos_bucket_growth_bytes_per_second) * 86400",
               "{{resolution}}")], _g(0, y, 8, 8), unit="bytes",
            description="Block bytes per day of data, newest 30 days of each resolution "
                        "(before Garage compression)."),
        _ts("Ingestion: active series and samples/s", [
            _t("max(prometheus_tsdb_head_series)", "active series"),
            _t("sum(rate(prometheus_tsdb_head_samples_appended_total[1h]))", "samples/s", "B")],
            _g(8, y, 8, 8),
            description="What drives the growth rates. A lasting step here shows up in "
                        "raw growth at once and in 1h growth ~3 weeks later."),
        _ts("Forever runway estimate", [
            _t(_runway(), "today's ingestion"),
            _t(_runway(2), "2× today", "B")], _g(16, y, 8, 8), unit=yr,
            description="The estimate over time: falling means ingestion is growing faster "
                        "than the disk is filling."),
    ]
    return p


def longterm_metrics_dashboard():
    p = [_text(HOW, _g(0, 0, 24, 6))]

    # ── Health ──
    p.append(_row("Health", 6))
    y = 7
    p += [
        _stat("Sidecar", "min(thanos_sidecar_prometheus_up)", _g(0, y, 3, 4),
              mappings=_ok_map(1, "OK", "DOWN"),
              description="The sidecar can reach Prometheus (needed to ship blocks)."),
        _stat("Last upload", 'time() - (max(thanos_objstore_bucket_last_successful_upload_time{thanos_component="sidecar"}) > 0)',
              _g(3, y, 3, 4), unit="s",
              steps=[{"color": GREEN, "value": None}, {"color": AMBER, "value": 3 * 3600},
                     {"color": RED, "value": 6 * 3600}],
              description="A 2h block is cut every 2h, so this should stay under ~2.5h."),
        _stat("Upload fails 24h", "sum(increase(thanos_shipper_upload_failures_total[24h]))",
              _g(6, y, 3, 4), steps=[{"color": GREEN, "value": None}, {"color": RED, "value": 1}]),
        _stat("Compactor", "max(thanos_compact_halted)", _g(9, y, 3, 4),
              mappings=_ok_map(0, "running", "HALTED"),
              description="Halts on a bad block; nothing compacts, downsamples or ages out until fixed."),
        _stat("To downsample", "sum(thanos_compact_todo_downsample_blocks)", _g(12, y, 3, 4),
              description="Blocks waiting to be downsampled (0 = caught up)."),
        _stat("Garage nodes", "min(cluster_storage_nodes_ok)", _g(15, y, 3, 4),
              steps=[{"color": RED, "value": None}, {"color": AMBER, "value": 1},
                     {"color": GREEN, "value": 2}],
              description="Both copies need both nodes. One down = bucket read-only (uploads wait)."),
        _stat("Resync queue", "sum(block_resync_queue_length)", _g(18, y, 3, 4),
              description="Blocks a node still has to fetch or check to hold its copy."),
        _stat("Resync errors", "sum(block_resync_errored_blocks)", _g(21, y, 3, 4),
              steps=[{"color": GREEN, "value": None}, {"color": RED, "value": 1}]),
    ]
    y += 4
    p += [
        _stat("Local TSDB", "max(prometheus_tsdb_storage_blocks_bytes)", _g(0, y, 3, 4),
              unit="bytes", decimals=1),
        _stat("Local span", "time() - min(prometheus_tsdb_lowest_timestamp_seconds)",
              _g(3, y, 3, 4), unit="s", description="How far back Prometheus itself reaches."),
        _stat("Bucket size", "sum(thanos_bucket_size_bytes)", _g(6, y, 3, 4),
              unit="bytes", decimals=1,
              description="Live blocks, all resolutions, before Garage compression; "
                          "Garage stores this twice. Blocks marked for deletion "
                          "(gone within 48h) are not counted."),
        _stat("Bucket span", "time() - min(thanos_bucket_min_time_seconds)", _g(9, y, 3, 4),
              unit="s", description="Oldest data at any resolution."),
        _stat("Store blocks", "sum(thanos_bucket_store_blocks_loaded)", _g(12, y, 3, 4)),
        _stat("Query stores", "sum(thanos_store_nodes_grpc_connections)", _g(15, y, 3, 4),
              steps=[{"color": RED, "value": None}, {"color": AMBER, "value": 1},
                     {"color": GREEN, "value": 2}],
              description="thanos query should see 2 StoreAPIs: the sidecar and the store gateway."),
        _stat("Replicated", "min(cluster_partitions_all_ok) / max(cluster_partitions)",
              _g(18, y, 3, 4), unit="percentunit", decimals=1,
              steps=[{"color": RED, "value": None}, {"color": GREEN, "value": 1}]),
        _stat("Coverage", "min(thanos_bucket_coverage_success)", _g(21, y, 3, 4),
              mappings=_ok_map(1, "OK", "FAILING"),
              description="thanos-bucket-coverage.timer on metrics01.scl04 (every 15 min)."),
    ]

    # ── Where the data is ──
    y += 4
    p.append(_row("Where the data is", y))
    y += 1
    tier_bucket = 'label_replace(max by (resolution) ({m}), "tier", "bucket · $1", "resolution", "(.*)")'
    tier_local = 'label_replace({e}, "tier", "local · raw (metrics.sfo02)", "", "")'

    def tier_q(bucket_metric, local_expr, ref):
        return _t(f"max by (tier) ({tier_bucket.format(m=bucket_metric)}) or "
                  f"max by (tier) ({tier_local.format(e=local_expr)})", refid=ref, instant=True)

    table = {
        "type": "table", "title": "Tiers: what is kept where",
        "gridPos": _g(0, y, 14, 9), "datasource": DS_PROM,
        "description": "Bucket figures from the coverage exporter (15 min); local from Prometheus itself.",
        "targets": [
            tier_q("thanos_bucket_min_time_seconds * 1000", "min(prometheus_tsdb_lowest_timestamp_seconds) * 1000", "A"),
            tier_q("thanos_bucket_max_time_seconds * 1000", "max(prometheus_tsdb_head_max_time_seconds) * 1000", "B"),
            tier_q("thanos_bucket_size_bytes", "max(prometheus_tsdb_storage_blocks_bytes)", "C"),
            tier_q("thanos_bucket_blocks", "max(prometheus_tsdb_blocks_loaded)", "D"),
        ],
        "transformations": [
            {"id": "merge", "options": {}},
            {"id": "organize", "options": {
                "excludeByName": {"Time": True},
                "renameByName": {"tier": "Tier", "Value #A": "Oldest", "Value #B": "Newest",
                                 "Value #C": "Size", "Value #D": "Blocks"}}},
            {"id": "sortBy", "options": {"sort": [{"field": "Tier"}]}},
        ],
        "fieldConfig": {"defaults": {}, "overrides": [
            {"matcher": {"id": "byName", "options": "Oldest"},
             "properties": [{"id": "unit", "value": "dateTimeAsIso"}]},
            {"matcher": {"id": "byName", "options": "Newest"},
             "properties": [{"id": "unit", "value": "dateTimeAsIso"}]},
            {"matcher": {"id": "byName", "options": "Size"},
             "properties": [{"id": "unit", "value": "bytes"}, {"id": "decimals", "value": 1}]},
        ]},
        "options": {"showHeader": True},
    }
    p.append(table)
    p.append(_text("""
**Retention by tier**

| Tier | Kept |
|---|---|
| local · raw (metrics.sfo02 SSD) | 30 days (60 GB cap) |
| bucket · raw | 30 days |
| bucket · 5m | 1 year |
| bucket · 1h | forever |

Bucket = Garage, two copies (scl04 HDD + sfo02 SSD).
Raw older than 30 days is deleted only after its 5m/1h blocks exist.
""", _g(14, y, 10, 9)))
    y += 9
    p += [
        _ts("Bucket size by resolution", [
            _t('sum by (resolution) (thanos_bucket_size_bytes)', "bucket {{resolution}}"),
            _t('max(prometheus_tsdb_storage_blocks_bytes)', "local TSDB (metrics.sfo02)", "B")],
            _g(0, y, 12, 8), unit="bytes"),
        _ts("Data age reached, by tier", [
            _t('time() - min by (resolution) (thanos_bucket_min_time_seconds)', "bucket {{resolution}}"),
            _t('time() - min(prometheus_tsdb_lowest_timestamp_seconds)', "local raw", "B")],
            _g(12, y, 12, 8), unit="s",
            description="Age of the oldest sample in each tier: flat lines at the retention limits once steady."),
    ]

    # ── Runway ──
    y += 8
    p.append(_row("Retention runway: how long \"forever\" lasts on the disks we have", y))
    y += 1
    p += runway_panels(y)
    y += 21

    # ── Shipping ──
    p.append(_row("Shipping: metrics.sfo02 → bucket (thanos sidecar)", y))
    y += 1
    p += [
        _ts("Blocks shipped / failed per hour", [
            _t("sum(increase(thanos_shipper_uploads_total[1h]))", "uploaded"),
            _t("sum(increase(thanos_shipper_upload_failures_total[1h]))", "failed", "B")],
            _g(0, y, 8, 8)),
        _ts("Upload throughput", [
            _t('sum by (thanos_component) (rate(thanos_objstore_bucket_operation_transferred_bytes_sum{operation="upload"}[5m]))',
               "{{thanos_component}}")], _g(8, y, 8, 8), unit="Bps",
            description="Sidecar shipping plus the compactor writing compacted/downsampled blocks."),
        _ts("Time since last shipped block", [
            _t('time() - (max(thanos_objstore_bucket_last_successful_upload_time{thanos_component="sidecar"}) > 0)',
               "since last upload")], _g(16, y, 8, 8), unit="s"),
    ]

    # ── Compaction ──
    y += 8
    p.append(_row("Compaction & downsampling (thanos compact, metrics01.scl04)", y))
    y += 1
    p += [
        _ts("Compactor backlog", [
            _t("sum(thanos_compact_todo_compactions)", "compactions to do"),
            _t("sum(thanos_compact_todo_compaction_blocks)", "blocks to compact", "B"),
            _t("sum(thanos_compact_todo_downsample_blocks)", "blocks to downsample", "C"),
            _t("sum(thanos_compact_todo_deletion_blocks)", "blocks to delete (retention)", "D")],
            _g(0, y, 8, 8)),
        _ts("Work done per hour", [
            _t(_res("sum by (resolution) (increase(thanos_compact_group_compactions_total[1h]))"),
               "compactions @ {{res}}"),
            _t(_res("sum by (resolution) (increase(thanos_compact_downsample_total[1h]))"),
               "downsampled from {{res}}", "B"),
            _t("sum(increase(thanos_compact_blocks_cleaned_total[1h]))", "blocks deleted", "C")],
            _g(8, y, 8, 8)),
        _ts("Compactor bucket I/O", [
            _t('sum by (operation) (rate(thanos_objstore_bucket_operation_transferred_bytes_sum{thanos_component="compact"}[5m]))',
               "{{operation}}")], _g(16, y, 8, 8), unit="Bps"),
    ]

    # ── Queries ──
    y += 8
    p.append(_row("Queries: Grafana → thanos query → sidecar + store", y))
    y += 1
    p += [
        _ts("Query rate by API", [
            _t('sum by (handler) (rate(http_request_duration_seconds_count{thanos_component="query"}[5m]))',
               "{{handler}}")], _g(0, y, 6, 8), unit="reqps"),
        _ts("Range query latency", [
            _t('histogram_quantile(0.5, sum by (le) (rate(http_request_duration_seconds_bucket{thanos_component="query",handler="query_range"}[15m])))', "p50"),
            _t('histogram_quantile(0.9, sum by (le) (rate(http_request_duration_seconds_bucket{thanos_component="query",handler="query_range"}[15m])))', "p90", "B")],
            _g(6, y, 6, 8), unit="s"),
        _ts("History reads (store gateway)", [
            _t("sum(rate(thanos_bucket_store_series_blocks_queried_count[5m]))", "series requests/s"),
            _t("histogram_quantile(0.9, sum by (le) (rate(thanos_bucket_store_series_blocks_queried_bucket[30m])))",
               "blocks touched p90", "B")],
            _g(12, y, 6, 8),
            description="How often queries reach past the sidecar into the bucket, and how many blocks each touches."),
        _ts("Store gateway reads from bucket", [
            _t('sum by (operation) (rate(thanos_objstore_bucket_operation_transferred_bytes_sum{thanos_component="store"}[5m]))',
               "{{operation}}")], _g(18, y, 6, 8), unit="Bps"),
    ]

    # ── Garage ──
    y += 8
    p.append(_row("Garage: the bucket, two copies (metrics01.scl04 + metrics01.sfo02)", y))
    y += 1
    p += [
        _ts("Resync queue per node", [
            _t("max by (host) (block_resync_queue_length)", "{{host}}")], _g(0, y, 8, 8),
            description="Blocks a node still has to fetch/verify. Drains to ~0 when both copies are complete."),
        _ts("Disk written / read per node", [
            _t("sum by (host) (rate(block_bytes_written[5m]))", "write {{host}}"),
            _t("sum by (host) (rate(block_bytes_read[5m]))", "read {{host}}", "B")],
            _g(8, y, 8, 8), unit="Bps"),
        _ts("Data disk free per node", [
            _t('max by (host) (garage_local_disk_avail{volume="data"})', "{{host}}")],
            _g(16, y, 8, 8), unit="bytes", min_val=None),
    ]
    y += 8
    p += [
        _ts("S3 requests by API", [
            _t("sum by (api_endpoint) (rate(api_s3_request_counter[5m]))", "{{api_endpoint}}")],
            _g(0, y, 12, 8), unit="reqps", stack=True),
        _ts("S3 errors by status", [
            _t("sum by (status_code, api_endpoint) (rate(api_s3_error_counter[5m]))",
               "{{status_code}} {{api_endpoint}}")],
            _g(12, y, 12, 8), unit="reqps",
            description="404 GetObject is normal: Thanos probes optional marker files "
                        "(deletion-mark.json etc.) on every sync. 403/5xx are not."),
    ]

    return {
        "uid": "sfmix-longterm-metrics", "title": "Long-term Metrics",
        "tags": ["sfmix-nms", "generated", "thanos"], "timezone": "browser",
        "description": "Thanos + Garage long-term metrics: shipping, downsampling, "
                       "coverage and the two-copy bucket (design doc 012).",
        "schemaVersion": 39, "refresh": "1m", "editable": True,
        "time": {"from": "now-24h", "to": "now"},
        "templating": {"list": []},
        "links": [
            {"title": "Design doc 012", "type": "link", "icon": "doc", "url": DOC_URL,
             "targetBlank": True},
            {"title": "Host View", "type": "link", "icon": "dashboard",
             "url": "/d/sfmix-host-view/host-view?var-host=metrics01.scl04.sfmix.org",
             "keepTime": True},
        ],
        "panels": p,
    }


def telemetry_dashboards():
    return [longterm_metrics_dashboard()]
