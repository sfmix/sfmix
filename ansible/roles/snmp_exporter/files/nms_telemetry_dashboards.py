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


def longterm_metrics_dashboard():
    p = [_text(HOW, _g(0, 0, 24, 6))]

    # ── Health ──
    p.append(_row("Health", 6))
    y = 7
    p += [
        _stat("Prometheus ↔ sidecar", "min(thanos_sidecar_prometheus_up)", _g(0, y, 3, 4),
              mappings=_ok_map(1, "OK", "DOWN"),
              description="The sidecar can reach Prometheus (needed to ship blocks)."),
        _stat("Last block shipped", 'time() - max(thanos_objstore_bucket_last_successful_upload_time{thanos_component="sidecar"})',
              _g(3, y, 3, 4), unit="s",
              steps=[{"color": GREEN, "value": None}, {"color": AMBER, "value": 3 * 3600},
                     {"color": RED, "value": 6 * 3600}],
              description="A 2h block is cut every 2h, so this should stay under ~2.5h."),
        _stat("Upload failures (24h)", "sum(increase(thanos_shipper_upload_failures_total[24h]))",
              _g(6, y, 3, 4), steps=[{"color": GREEN, "value": None}, {"color": RED, "value": 1}]),
        _stat("Compactor", "max(thanos_compact_halted)", _g(9, y, 3, 4),
              mappings=_ok_map(0, "running", "HALTED"),
              description="Halts on a bad block; nothing compacts, downsamples or ages out until fixed."),
        _stat("Downsample backlog", "sum(thanos_compact_todo_downsample_blocks)", _g(12, y, 3, 4),
              description="Blocks waiting to be downsampled (0 = caught up)."),
        _stat("Garage storage nodes OK", "min(cluster_storage_nodes_ok)", _g(15, y, 3, 4),
              steps=[{"color": RED, "value": None}, {"color": AMBER, "value": 1},
                     {"color": GREEN, "value": 2}],
              description="Both copies need both nodes. One down = bucket read-only (uploads wait)."),
        _stat("Garage resync backlog", "sum(block_resync_queue_length)", _g(18, y, 3, 4),
              description="Blocks a node still has to fetch or check to hold its copy."),
        _stat("Resync errored blocks", "sum(block_resync_errored_blocks)", _g(21, y, 3, 4),
              steps=[{"color": GREEN, "value": None}, {"color": RED, "value": 1}]),
    ]
    y += 4
    p += [
        _stat("Local TSDB", "max(prometheus_tsdb_storage_blocks_bytes)", _g(0, y, 3, 4),
              unit="bytes", decimals=1),
        _stat("Local span", "time() - min(prometheus_tsdb_lowest_timestamp_seconds)",
              _g(3, y, 3, 4), unit="s", description="How far back Prometheus itself reaches."),
        _stat("Bucket size", "sum(thanos_bucket_size_bytes)", _g(6, y, 3, 4),
              unit="bytes", decimals=1, description="All resolutions; Garage stores this twice."),
        _stat("Bucket span", "time() - min(thanos_bucket_min_time_seconds)", _g(9, y, 3, 4),
              unit="s", description="Oldest data at any resolution."),
        _stat("Store gateway blocks", "sum(thanos_bucket_store_blocks_loaded)", _g(12, y, 3, 4)),
        _stat("Query → stores", "sum(thanos_store_nodes_grpc_connections)", _g(15, y, 3, 4),
              steps=[{"color": RED, "value": None}, {"color": AMBER, "value": 1},
                     {"color": GREEN, "value": 2}],
              description="thanos query should see 2 StoreAPIs: the sidecar and the store gateway."),
        _stat("Partitions fully replicated", "min(cluster_partitions_all_ok) / max(cluster_partitions)",
              _g(18, y, 3, 4), unit="percentunit", decimals=1,
              steps=[{"color": RED, "value": None}, {"color": GREEN, "value": 1}]),
        _stat("Coverage exporter", "min(thanos_bucket_coverage_success)", _g(21, y, 3, 4),
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
        "gridPos": _g(0, y, 14, 7), "datasource": DS_PROM,
        "description": "Bucket figures from the coverage exporter (15 min); local from Prometheus itself.",
        "targets": [
            tier_q("thanos_bucket_min_time_seconds", "min(prometheus_tsdb_lowest_timestamp_seconds)", "A"),
            tier_q("thanos_bucket_max_time_seconds", "max(prometheus_tsdb_head_max_time_seconds)", "B"),
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
""", _g(14, y, 10, 7)))
    y += 7
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

    # ── Shipping ──
    y += 8
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
            _t('time() - max(thanos_objstore_bucket_last_successful_upload_time{thanos_component="sidecar"})',
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
        _ts("How far back queries reach", [
            _t('histogram_quantile(0.5, sum by (le) (rate(thanos_query_range_requested_timespan_duration_seconds_bucket[1h])))', "p50"),
            _t('histogram_quantile(0.99, sum by (le) (rate(thanos_query_range_requested_timespan_duration_seconds_bucket[1h])))', "p99", "B")],
            _g(12, y, 6, 8), unit="s",
            description="Requested time span of range queries: beyond 30 days is served from the bucket."),
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
