# 012 — Long-term metrics: Thanos with a downsampled bucket on spinning disk

Status: deployed 2026-11-10 (see Rollout for the two deferred retention flips).

## Why

Everything lives on metrics.sfo02: one 160 GB VM disk on the paulave nodes'
Samsung 870 QVO (QLC SSD) ZFS mirror. Measured 2026-11-09:

| | On disk | Growth | Retention |
|---|---|---|---|
| Prometheus | 78 GB, 20 blocks back to 2026-03-01 | ~0.5 GB/day at 133k head series (was ~15-20k in March) | `retention.size=80GB` — **full**; already deleting March |
| Loki | 2.7 GB chunks | ~8 MB/day stored (~270 MB/day ingested) | 90d (`job="docker"` 30d) |

Prometheus history is shrinking as series grow (~5 months at today's rate),
and there is no long-term metrics story at all.

pve01.scl04 has a 29 TB raidz2 of spinning disk (`tank`, ~20 TB free), and
on these hosts the HDD pool actually beats the QVO SSDs on fsync latency
(p50 ~10 ms vs 90-150 ms, see the PVE QVO notes).

Logs don't need a tier: at ~3 GB/year, Loki keeps **2 years** on
metrics.sfo02's SSD as a single instance with one Grafana datasource. (An
archive Loki on scl04 fed by an ingest tee was considered and dropped: two
Lokis and two log datasources for data this small isn't worth it.)

## Shape

Solid arrows carry data in (writes); dotted arrows are queries.

**Hosts and network path.** Only metrics.sfo02 talks to the cold tier, over
the management network. The bucket lives on two Garage nodes in two sites;
every object is on both.

```mermaid
flowchart LR
  subgraph SFO["sfo02"]
    M1["metrics.sfo02<br/>VM on paulave PVE<br/>160 GB QVO SSD<br/>public 192.33.255.10<br/>oob 10.1.1.14"]
    GWS["mgmt-gw.sfo02"]
    M3["metrics01.sfo02<br/>VM 100 on pve01.sfo02<br/>1 TB tank SSD<br/>SFO02-MGMT 10.1.1.25 only"]
  end
  subgraph SCL["scl04"]
    GWC["mgmt-gw.scl04"]
    M2["metrics01.scl04<br/>VM 110 on pve01.scl04<br/>1 TB tank raidz2 HDD<br/>SCL04-MGMT 10.6.1.34 only"]
  end
  USERS(["Operators, portal"]) -- "HTTPS (public)" --> M1
  M1 -- "oob" --> GWS -- "VLAN 200 mgmt fabric, ~2 ms" --> GWC --> M2
  M3 <-- "Garage replication (RPC :3901)" --> M2
```

**Metrics.** Prometheus keeps 30 days on SSD; the sidecar ships every 2h
block to the bucket; the compactor downsamples; Grafana reads both tiers
through Thanos Query.

```mermaid
flowchart LR
  TGT["Scrape targets<br/>SNMP, node_exporter, blackbox,<br/>sflow-rt, bird, LG, portal"]
  AGENTS["Alloy agents<br/>(self-metrics)"]
  subgraph HOT["metrics.sfo02 (SSD)"]
    PROM["Prometheus :9090<br/>30 days, alert rules"]
    SC["thanos sidecar"]
    TQ["thanos query :10904"]
    GRAF["Grafana"]
    AM["Alertmanager"]
  end
  subgraph COLD["metrics01.scl04 (HDD)"]
    GAR[("Garage S3<br/>bucket thanos")]
    TC["thanos compact<br/>raw 30d, 5m 1y, 1h forever"]
    TS["thanos store"]
  end
  subgraph REP["metrics01.sfo02 (SSD)"]
    GAR2[("Garage<br/>second copy")]
  end
  GAR <-- "every object on both" --> GAR2
  TGT -- "scraped (pull)" --> PROM
  AGENTS -- "remote_write" --> PROM
  PROM --> SC
  SC -- "2h blocks" --> GAR
  TC <-- "downsample" --> GAR
  TS -. "reads" .-> GAR
  GRAF -. "Prometheus datasource" .-> TQ
  TQ -. "last 30d, raw" .-> SC
  TQ -. "history, downsampled" .-> TS
  PORTAL(["Portal charts"]) -. "PromQL" .-> PROM
  PROM -- "alerts" --> AM --> SLACK(["Slack"])
```

**Logs.** Unchanged path, single Loki, retention raised to 2 years.

```mermaid
flowchart LR
  LNX["Linux servers + PVE nodes<br/>Alloy: journald, docker"]
  APP["Network gear, mgmt-gws,<br/>OpenBSD hosts"]
  subgraph HOT["metrics.sfo02 (SSD)"]
    SNG["syslog-ng :514"] --> PTL["promtail"]
    LOKI["Loki :3100<br/>2 years, log alerts"]
    GRAF["Grafana"]
  end
  LNX -- "push" --> LOKI
  APP -- "syslog" --> SNG
  PTL --> LOKI
  GRAF -. "Loki datasource" .-> LOKI
  LOKI -- "log alerts" --> AM(["Alertmanager"])
```

| Host | Where | Network | Storage | Runs |
|---|---|---|---|---|
| metrics.sfo02 | VM on paulave PVE (sfo02) | public 192.33.255.10 + oob 10.1.1.14 | 160 GB, QVO SSD mirror | Prometheus, thanos sidecar + query, Loki, syslog-ng, promtail, Alertmanager, Grafana, exporters, sflow-rt |
| metrics01.scl04 | VM 110 on pve01.scl04 | SCL04-MGMT 10.6.1.34 only | 32 GB OS + 1 TB data, tank raidz2 HDD | Garage, thanos store + compact |
| metrics01.sfo02 | VM 100 on pve01.sfo02 (DL360) | SFO02-MGMT 10.1.1.25 only | 32 GB OS + 1 TB data, tank SSD | Garage (second copy) |

## Prometheus → Thanos

- **Prometheus** keeps scraping and evaluating every alert, with local
  retention cut to 30 days (60 GB ceiling). Local compaction is turned off
  (`min/max-block-duration=2h`) so the sidecar can ship each 2h block, and
  `external_labels: {prometheus: metrics.sfo02.sfmix.org}` labels the blocks.
- **thanos sidecar** (metrics.sfo02) uploads blocks to the bucket. Uploads
  retry, so a WAN or scl04 outage only delays shipping (blocks stay local for
  30 days).
- **Garage** (metrics01.scl04) is the S3 store: single node,
  `replication_factor = 1`, data on raidz2 (the redundancy is ZFS's). Chosen
  over MinIO because MinIO's community edition stopped shipping binaries and
  images and went into maintenance mode in 2025.
- **thanos compact** (metrics01.scl04) compacts and **downsamples**: 5-minute
  aggregates for blocks older than 40 hours, 1-hour aggregates for blocks
  older than 10 days. Retention per resolution: **raw 30d, 5m 1y, 1h
  forever**. Long-term data is low-resolution by design; raw is only kept as
  long as Prometheus keeps it locally.
- **thanos store** (metrics01.scl04) serves the bucket over gRPC.
- **thanos query** (metrics.sfo02) fans out to the sidecar (recent) and the
  store gateway (history) with `--query.auto-downsampling`, so a 2-year graph
  reads 1h data rather than raw. The existing Grafana "Prometheus"
  datasource (same uid) now points at it, so every dashboard spans both tiers
  without edits. If scl04 is unreachable, queries return partial results
  from the sidecar with a warning instead of failing. The portal still
  queries Prometheus :9090 directly (its charts are short-range).

The compactor and store gateway sit next to the bucket because they move the
most data; the querier sits next to Grafana. metrics.sfo02 has 2 vCPU / 7 GB
and only gains the two light components.

Rejected: VictoriaMetrics (OSS has no downsampling — needed: long-term data
is low-resolution by design); Mimir (far too big for one Prometheus).

## Two copies: second Garage node at sfo02

pve01.scl04's `tank` is eight 8.5-year-old ST4000DM000s, one with a latched
SMART error, and the host has no backup job. raidz2 is not enough on its own
for the only copy of the long-term history, so the bucket is a two-node
Garage cluster, **replication_factor 2**, one node per site (zone = site):
metrics01.scl04 and metrics01.sfo02 (VM 100 on the DL360 pve01.sfo02, its
1.8 TB SSD `tank`). Every object, raw and downsampled, is on both.

- Thanos store + compact stay on scl04 only (one compactor per bucket); the
  sfo02 node is Garage-only. Thanos talks to scl04's S3 endpoint.
- With two nodes and the default `consistent` mode, either node down makes
  the bucket read-only: sidecar uploads and compaction retry and catch up
  (blocks wait on metrics.sfo02 for 30 days); reads keep working.
- Changing the replication factor of a cluster that holds data is officially
  unsupported. Done once, 2026-11-10, with every raw block still on
  metrics.sfo02 as the fallback: stop thanos-compact/store and garage on
  scl04, back up `meta/` (kept as `/srv/telemetry/garage-meta-backup-rf1-*`),
  move `meta/cluster_layout` aside, deploy RF 2 to both nodes, assign both,
  apply layout v1. Keys, bucket and all 296 objects (102.2 GB) came through;
  sfo02 pulled every block in the background. A node learns of blocks via
  metadata sync and schedules each fetch 2x rpc_timeout later (restarting
  Garage pushes that out again); `garage repair blocks` cannot pull queued
  entries earlier. Speed it with `garage worker set -a resync-worker-count 4`
  and `resync-tranquility 0`.
- Garage's API logger is at warn: Thanos probes every block for optional
  marker files (`deletion-mark.json`, `no-compact-mark.json`,
  `no-downsample-mark.json`) on every sync, and each absent one is a 404 that
  Garage logs at info (~2k lines/h, all benign).

## metrics01.scl04

- PVE VM 110 on pve01.scl04 (NetBox VM 21), Debian 13 cloud image,
  4 vCPU / 8 GB.
- **Management network only**: SCL04-MGMT (`vmbr0`, VLAN 701)
  10.6.1.34/24, gw 10.6.1.1, IPv4 only (scl04's OOB has no working IPv6).
  It hosts no public frontend and no ingestion endpoint that public hosts
  need — only metrics.sfo02 talks to it, over oob (10.1.1.14 → 10.6.1.0/24
  via mgmt-gw.sfo02, ~2 ms). S3 and Thanos gRPC are unauthenticated, so they
  belong off public addresses anyway. UFW's admin allow (10/8) covers
  metrics.sfo02.
- Ansible reaches it via `ProxyJump shell.sfmix.org`; role `metrics_archive`
  (`push_servers -t metrics_archive`).
- Disks: 32G OS + **1T thin data disk** (scsi1, ext4 `LABEL=telemetry` on
  `/srv/telemetry`), both on `tank-vms`. Grow with `qm resize 110 scsi1 +NG`
  then `resize2fs`.
- Not backup01.scl04: that VM keeps a public IP to receive backups from
  public-only hosts, and is a backup target, not a query service.

Expected steady state: raw 30d ~15 GB, 5m for a year ~50-100 GB, 1h ~10
GB/yr. The 1T disk is years of headroom.

## Rollout (no data loss)

The existing 78 GB of history is uploaded once, and nothing is allowed to age
out anywhere until it is verified in the bucket:

1. Compactor runs with `-e metrics_archive_thanos_retention_raw=0d` (keep all
   raw) during the backfill.
2. Prometheus deploy with `-e prometheus_retention_time=
   -e prometheus_retention_size=95GB -e thanos_sidecar_upload_compacted=true`:
   no time retention, a size ceiling above today's 80 GB so the oldest blocks
   stop being deleted, and the sidecar uploads the already-compacted history.
   This is the one container restart (TSDB/WAL replay, a short scrape gap).
3. Verify: every local block ULID is in the bucket (`thanos.shipper.json` vs
   `thanos tools bucket ls`), then redeploy Prometheus with the defaults
   (30d / 60GB, no upload-compacted).
4. Verify 5m and 1h blocks cover the whole history, then redeploy the
   compactor with the default raw retention (30d).
5. Grafana "Prometheus" datasource → Thanos Query; Loki retention → 2y
   (`-t datasources,loki`).

Done 2026-11-10: the Prometheus restart cost one 94 s scrape gap (06:07:03 →
06:08:37 UTC, WAL replay 21 s). Backfill 06:08 → 07:22 UTC (~15 MB/s over
the mgmt path); all 20 local blocks verified in the bucket with identical
time ranges, sample and series counts (39.4 B samples, 2026-03-01 →
2026-11-10). Thanos Query returns identical results to Prometheus over the
overlapping range. The sidecar's upload-compacted flag is off again.

Deferred, deliberately:
- **Local 30d / 60GB** is the committed default but is only applied by the
  next Prometheus restart (each restart is a ~90 s scrape gap, so bundle it
  with the overdue 2.43 → current upgrade). Until then the running flags are
  no time limit / 95GB; anything that ceiling trims is already in the bucket.
- ~~Bucket raw 30d~~ done 2026-11-10: 5m coverage passed the 30-day line
  (08:22Z) and the second copy was verified, then raw retention went to 30d.

Second copy, 2026-11-10: sfo02 pulled every block 08:48 → 10:35Z (~66 GB on
disk after Garage compression, 0 errored blocks). Verified: both nodes hold
98,436 block files totalling 70,175,989,361 bytes against 98,435 block
references, and a full `garage repair --all-nodes blocks` afterwards found
nothing missing on either node.

## Alerts

`thanos.rules.yml`: any Thanos component or Garage down, sidecar upload
failures, no block shipped in 6h, compactor halted, compactor not completing
runs.
