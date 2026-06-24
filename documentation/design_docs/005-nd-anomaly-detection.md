# 005 - Neighbor-Discovery Anomaly Detection & Evidence Capture

## Status: Implemented & deployed (2026-06-24)

## Overview

A system that passively watches ARP/NDP on the SFMIX peering fabric, records
**neighbor-discovery anomalies** as durable, queryable events, captures a
focused pcap of the offending traffic for each one, and surfaces them in the
participant portal. It also ages the live "discovered neighbors" view so that
resolved conditions (e.g. a member migrating to new hardware) stop reading as
active.

It spans three codebases:

- **`looking-glass/lg-neighborhood-watch`** — the passive sensor on the route
  server (Rust).
- **`looking-glass`** (lib + `lg-server` + `lg-http` + `lg-client`) — detection,
  the durable event store, evidence orchestration, and the RPC/REST API.
- **`portal`** — the admin "ND Events" page and participant-detail integration
  (Django).

Deployment is driven by the `sfmix_route_server_linux`, `looking_glass`, and
`ixp_portal` Ansible roles.

## Background & motivation

The looking glass already accumulated ARP/NDP neighbors heard on the fabric and
flagged an IP with more than one MAC as a conflict ("⚠ multiple MACs"). That
flag had **no aging**: once a second MAC was ever recorded for an IP, the
warning latched forever. Two everyday situations turned this into permanent
false positives:

- **Legitimate migrations** — a member swaps router hardware (old MAC → new
  MAC). Both MACs linger; the conflict never clears.
- **Transient bursts** — a short-lived event (e.g. one member's MAC briefly
  attributed to ~30 other IPs over a 46-minute window) latched and stayed.

An ad-hoc `nd-watch.py` + `dumpcap` ring buffer had been running on rs-linux to
investigate these by hand. This system productizes that capability and retires
the ad-hoc tooling.

### Goals

1. Durable, queryable record of each anomaly, with rollup so a storm of activity
   collapses into one event rather than thousands.
2. Targeted pcap evidence per event (only the relevant frames), browsable and
   downloadable.
3. Age the live view so resolved conflicts (esp. migrations) auto-close while the
   historical record is preserved.
4. Catch the **one-MAC-many-IP** case (proxy-ARP / impersonation / sweep) that
   the per-IP model misses entirely.
5. **The sensor never transmits on L2.** All neighbor solicitation goes through
   the Linux kernel (ICMP echo → kernel ARP/NDP). Capture is receive-only.

### Non-goals

- Full-fabric packet capture or a general forensics platform (see Arkime/Malcolm
  if that is ever wanted). The ring buffer holds only ARP/NDP frames, briefly.
- Active mitigation. This system observes and records; it does not block or
  quarantine.

## Architecture

```
  peering VLAN (ens19 on rs-linux)
        │ ARP / NDP (passive)
        ▼
┌─────────────────────────────────────────────┐
│ lg-neighborhood-watch (rs-linux)             │   receive-only; CAP_NET_RAW only
│  capture.rs   AF_PACKET RX ──┬─► store.rs    │   /neighbors  (heard ip→mac, aged)
│  (promisc off)               │   (sensor_ttl)│   /healthz /metrics
│                              └─► ringbuf.rs  │   rolling pcap of ARP/NDP frames
│  solicit.rs  kernel ICMP echo (no L2 TX)     │   evidence.rs ── /evidence/snapshot
│                                              │              ── /evidence/{id}
└───────────────┬──────────────────────────────┘
                │ poll GET /neighbors (60s)         ▲ POST /evidence/snapshot (on new event)
                │                                   │ GET /evidence/{id}        (pcap stream)
                ▼                                   │
┌─────────────────────────────────────────────┐    │
│ lg-server (alice)                            │────┘
│  discovered.rs  fold polls vs NetBox assigns │
│    • detect new_mac_on_ip / mac_claims_many  │
│    • mac_ttl staleness in snapshot()         │
│    • trigger evidence snapshot on new events │
│  anomaly.rs     SQLite event store (WAL)     │   nd-anomalies.sqlite
│  rpc_server.rs  /rpc/v1/nd-events[/{id}[/pcap]]
└───────────────┬──────────────────────────────┘
                │ RPC (X-RPC-Secret)
                ▼
┌─────────────────────────────────────────────┐
│ lg-http (alice, 127.0.0.1:8080)              │   /api/v1/nd-events[/{id}[/pcap]]
└───────────────┬──────────────────────────────┘   (streams pcap, never buffers)
                │ HTTPS (OIDC bearer)
                ▼
┌─────────────────────────────────────────────┐
│ portal (portal.sfmix.org, Django)            │   Admin ▸ ND Events
│  dashboard/views.py  nd_events / nd_event_pcap│  participant_detail: stale MACs,
│  templates/dashboard/nd_events.html          │  "N events · history" badges
└─────────────────────────────────────────────┘
```

Data flow for one anomaly:

1. The sensor hears ARP/NDP and publishes the current `(ip, mac)` set at
   `/neighbors` (entries decay after `sensor_ttl_secs`).
2. lg-server polls `/neighbors` every `poll_interval_secs`, folds it against the
   current NetBox IP assignments, and detects anomalies.
3. On a **newly opened** event, lg-server POSTs the conflicting MACs + a time
   window to the sensor's `/evidence/snapshot`; the sensor extracts a filtered
   pcap from its ring buffer and returns an `evidence_id`, which lg-server links
   onto the event.
4. The portal lists events via lg-http and streams the pcap on demand through the
   proxy chain portal → lg-http → lg-server → sensor.

## Components

### Sensor — `lg-neighborhood-watch` (rs-linux)

- **`capture.rs`** — one blocking AF_PACKET capture thread per interface (pnet),
  **promiscuous OFF**. Parses ARP (sender fields) and IPv6 ICMPv6 NDP
  (NA target / NS source) into `(ip, family, mac)` observations. Every ARP/NDP
  frame's raw bytes + capture timestamp are also teed to the ring buffer.
- **`solicit.rs`** — to stimulate neighbors it sends ordinary **ICMP/ICMPv6 echo
  requests** via a raw ICMP socket and lets the *kernel* issue the ARP request /
  Neighbor Solicitation. It never crafts or transmits L2 ARP/NDP frames — this is
  the safety guarantee against polluting the IX.
- **`store.rs`** — single writer task owns `ip → (family, mac → Entry)` and
  republishes a lock-free snapshot for `/neighbors`. Bounded at
  `MAX_MACS_PER_IP = 100`. With `sensor_ttl_secs` set, entries not re-heard within
  the TTL decay out (so a gone-away MAC stops being re-reported downstream).
- **`ringbuf.rs`** — rolling on-disk classic-libpcap ring buffer (LinkType
  Ethernet) of raw ARP/NDP frames. Size/age-rotated chunk files
  (`chunk-<ts>-<seq>.pcap`), pruned by `ring_buffer_secs` (mtime) then a byte cap.
  Hand-rolled minimal pcap reader/writer (no extra deps); readers tolerate a
  truncated trailing record. Runs on a dedicated OS thread fed by a bounded
  channel from capture (drops on backpressure — best-effort).
- **`evidence.rs`** — `EvidenceStore`: filtered extraction + serving. See
  [Evidence capture](#evidence-capture).
- **`http.rs`** — `/neighbors`, `/healthz`, `/metrics`, and the evidence
  endpoints. Bound internally (mgmt IP).

### lg-server (alice)

- **`discovered.rs`** — `DiscoveredNeighborStore` folds each `/neighbors` poll
  against NetBox assignments (`ip → {asn, tenant, mac → first/last seen}`). A
  tenant change wipes an IP's MAC history (it is effectively a new IP);
  unassigned IPs are retained (bounded, `MAX_UNASSIGNED_IPS = 256`, 24 h TTL) and
  flagged. It performs detection (below), drives the staleness computation in
  `snapshot()`, and returns the events opened this poll so the poll loop can
  trigger evidence.
- **`anomaly.rs`** — `AnomalyStore`, the durable SQLite (WAL) event store and
  rollup engine. See [Detection semantics](#detection-semantics) and
  [Data model](#data-model).
- **`rpc_server.rs`** — internal RPC: `GET /rpc/v1/nd-events`,
  `/rpc/v1/nd-events/{id}`, and `/rpc/v1/nd-events/{id}/pcap` (resolves the
  event's `evidence_id` and streams the pcap from the sensor).
- **Poll loop / snapshot worker** (`spawn_poll_loop`, `spawn_snapshot_worker`) —
  after `update()`, newly-opened events are handed to a **single serialized
  worker** that POSTs `/evidence/snapshot` (120 s timeout) and links the returned
  `evidence_id`. Serializing matches the sensor's one-at-a-time extraction and
  avoids a 503 storm on bursts.

### lg-http (alice) & portal

- **lg-http** proxies `/api/v1/nd-events[/{id}[/pcap]]` to lg-server. The pcap
  path streams (via `lg-client::get_raw` → `Body::from_stream`), never buffering.
- **portal** — admin-only `nd_events` list view (IP/ASN filters, paging, both
  event kinds, streaming `nd_event_pcap` download) and participant-detail
  integration: conflict IPs show a "N events · history" badge, and stale MACs
  render dimmed and are excluded from the conflict flag.

## Detection semantics

### `new_mac_on_ip` — conflict rollup & hysteresis

When folding a poll, a MAC arriving on an IP that already has other MAC(s) and is
not already recorded is a conflict. `AnomalyStore::record_conflict` applies a
per-IP cooldown (`anomaly_cooldown_secs`, default 600):

- **First occurrence** → open a new event (`flap_count = 1`).
- **Another within the window** → fold in (increment `flap_count`, advance the
  `last_seen` window end). A thousand flaps in a minute → one event,
  `flap_count = 1000`.
- The in-memory open-event map is seeded from un-expired open rows on startup, so
  a restart keeps folding rather than duplicating.

**Liveness / why migrations close.** Whether a conflict is still "live" is keyed
on **distinct MACs heard fresh in the *current* poll**, not on the un-aged
record. Each poll, lg-server extends (`touch_conflict`) an open event only if ≥2
distinct MACs for the IP were heard within the freshness window
(`mac_ttl_secs`, else the cooldown). Once a migrated-away MAC ages out of the
window, the conflict is no longer live, touches stop, and the event **closes**
about one cooldown later. `closed` is computed at read time (`now - last_seen >
cooldown`, or explicitly superseded), so events reflect reality without a writer
re-touching every row. This is what fixes the original latching problem.

### `mac_claims_many_ips` — one-MAC-many-IP (proxy-ARP / sweep)

Built in the same fold from `mac → {fresh IPs claimed}`. Two triggers
(`AnomalyStore::record_mac_sweep`, keyed on the MAC so a growing sweep is one
rolling event with an accumulating `claimed_ips` set, capped at 256):

- **Cross-tenant** — the MAC claims IPs assigned to **≥2 distinct ASNs**. A
  member's own IPv4 + IPv6 is one ASN, so this is the low-false-positive smoking
  gun for impersonation/proxy-ARP.
- **Cardinality** — the MAC claims more than `max_ips_per_mac` (default 8)
  *unassigned* IPs — blanket proxy-ARP over idle space where there is no owner.

A member's own MAC on its own assigned addresses trips neither.

### Aging (Phase 3) — the three knobs

| Window | Where | Default (deployed) | Effect |
|--------|-------|--------------------|--------|
| `sensor_ttl_secs` | sensor `store.rs` | 1800 | drop `(ip,mac)` not re-heard this long from `/neighbors`; stops feeding stale MACs downstream; bounds sensor memory |
| `mac_ttl_secs` | lg-server `snapshot()` + liveness | 1800 | MAC unheard this long is `stale`, excluded from the `conflict` flag and from event liveness |
| `anomaly_cooldown_secs` | `anomaly.rs` rollup | 600 | flap-rollup window and the read-time `closed` threshold |

**Never-miss guards.** Detection is never gated on aging: `record_conflict` /
`record_mac_sweep` fire on the transition regardless of TTL, and events are
written durably at first detection. `sensor_ttl_secs ≫ poll_interval_secs`
(1800 vs 60) guarantees even a brief conflict appears in many polls before it
ages out. Aging only ever changes whether something reads as *currently active*,
never whether it was *recorded*.

## Evidence capture

The old approach copied the whole ring buffer — mostly irrelevant traffic.
Instead, lg-server sends the conflict's MACs + a time window (`opened_at` ±5 min)
and the sensor extracts a **filtered** pcap (`evidence.rs`) keeping only:

- frames where `eth.src`/`eth.dst` matches any conflicting MAC,
- **all L2 broadcast** (`ff:ff:ff:ff:ff:ff`) — ARP requests showing who asked,
- **all IPv6 multicast** (`33:33:*`) — NDP solicitations/advertisements,
- within the time window.

Extraction is expensive (scans the ring), so it is guarded:

- **Idempotent by `event_id`** — an existing snapshot returns immediately (200).
- **In-flight de-dup** — a duplicate while extracting returns 409.
- **Concurrency limit** — `tokio::Semaphore`, `MAX_CONCURRENT_EXTRACTIONS = 1`;
  over-limit returns 503 + `Retry-After`.
- **Deadline** — `EXTRACTION_DEADLINE = 90 s`; partial output is discarded.
- **Bounded storage** — `evidence_max_bytes` (default 500 MiB), oldest pruned.
- **Path-traversal-safe ids** for the download handler.

The result is small (typically a few MB) and valid classic libpcap, openable in
Wireshark/tshark.

## Data model

`nd_events` (SQLite, WAL), one row per event:

```sql
CREATE TABLE nd_events (
    id          TEXT PRIMARY KEY,   -- UUID v4
    ip          TEXT NOT NULL,      -- conflicted IP; "" for sweeps
    family      TEXT NOT NULL,      -- IPv4 / IPv6
    asn         INTEGER,
    tenant      TEXT,
    old_macs    TEXT NOT NULL,      -- JSON array
    new_mac     TEXT NOT NULL,      -- new / offending MAC
    opened_at   TEXT NOT NULL,      -- RFC3339, window start (immutable)
    last_seen   TEXT NOT NULL,      -- RFC3339, window end (advances)
    flap_count  INTEGER NOT NULL DEFAULT 1,
    evidence_id TEXT,               -- links to sensor pcap
    closed      INTEGER NOT NULL DEFAULT 0,
    kind        TEXT NOT NULL DEFAULT 'new_mac_on_ip',  -- | 'mac_claims_many_ips'
    claimed_ips TEXT                -- JSON array (sweeps), capped 256
);
-- indexes: ip, asn, opened_at, kind
```

`closed` is recomputed at read time. The serialized `AnomalyEvent`
(`lg-types/structured.rs`) mirrors these fields; `DiscoveredMac` gained
`stale: bool` (`#[serde(default)]` so old on-disk caches deserialize).

## API surface

| Endpoint | Auth | Purpose |
|----------|------|---------|
| sensor `GET /neighbors` | internal | current heard `(ip, mac)` rows |
| sensor `POST /evidence/snapshot` | internal | extract filtered pcap → `{evidence_id, frame_count, size_bytes}` |
| sensor `GET /evidence/{id}` | internal | stream pcap (`application/vnd.tcpdump.pcap`) |
| sensor `GET /evidence` | internal | list snapshots |
| lg-server `GET /rpc/v1/nd-events` | X-RPC-Secret | list (`?asn`, `?ip`, `?limit`, `?offset`) |
| lg-server `GET /rpc/v1/nd-events/{id}[/pcap]` | X-RPC-Secret | one event / stream its pcap |
| lg-http `GET /api/v1/nd-events[/{id}[/pcap]]` | OIDC bearer | portal-facing proxy |
| portal `/admin/nd-events/[{id}/pcap/]` | session (IX admin) | UI + download |

## Configuration reference

`DiscoveredNeighborsConfig` (lg-server, under `discovered:`):

| Key | Default | Notes |
|-----|---------|-------|
| `sensor_url` | — | sensor base URL |
| `poll_interval_secs` | 60 | 0 disables |
| `state_file` | — | discovered-neighbor persistence |
| `anomaly_db` | — (unset = off) | SQLite path; enables recording |
| `anomaly_cooldown_secs` | 600 | rollup / close window |
| `mac_ttl_secs` | — (unset = no aging) | staleness + liveness window |
| `max_ips_per_mac` | 8 | sweep cardinality threshold |

Sensor (`lg-neighborhood-watch`):

| Key | Default | Notes |
|-----|---------|-------|
| `sensor_ttl_secs` | — (unset = no decay) | `(ip,mac)` decay; must be ≫ poll interval |
| `evidence_dir` | — (unset = off) | enables ring buffer + `/evidence*` |
| `ring_buffer_secs` | 1800 | ring retention |
| `ring_buffer_max_bytes` | 100 MiB | ring byte cap |
| `evidence_max_bytes` | 500 MiB | saved-pcap byte cap |

Code defaults keep both aging and evidence **off** (opt-in); the deployed config
turns them on (see below).

## Deployment

Binaries are built **off-host** as static musl artifacts and copied — never built
on rs-linux (a sensitive route server). See design doc 004 and the deploy roles.

| Component | Host | Role | Notes |
|-----------|------|------|-------|
| sensor | rs-linux | `sfmix_route_server_linux` (`lg_neighborhood_watch` tag) | captures `ens19`; HTTP bound to mgmt `10.1.1.18:29185`; `CAP_NET_RAW` only; evidence under systemd `StateDirectory=/var/lib/lg-neighborhood-watch`; `sensor_ttl_secs=1800` |
| lg-server/lg-http/lg-cli | alice | `looking_glass` | RPC `10.2.1.26:9090`; lg-http `127.0.0.1:8080` behind nginx; `anomaly_db=/var/lib/looking-glass/nd-anomalies.sqlite`, `mac_ttl_secs=1800`, `max_ips_per_mac=8` |
| portal | portal.sfmix.org | `ixp_portal` | rsync + docker rebuild (regenerates Tailwind) |

Deployed values live in `ansible/inventory/group_vars/rs_linux.yml` and
`looking_glass_rust.yml` so deploys stay idempotent.

## Security & safety

- **Receive-only at L2**, enforced by design and verifiable at runtime: the
  service runs with `CAP_NET_RAW` and nothing else (`CapEff/CapBnd = cap_net_raw`).
  It can open AF_PACKET RX + a raw ICMP socket for kernel-mediated solicitation;
  it cannot transmit crafted L2.
- **Bounded everywhere** — per-IP MAC cap, unassigned-IP cap, ring/evidence byte
  caps, extraction concurrency + deadline, `MemoryMax` on the unit (OOM victim
  before BIRD).
- **pcap parsing.** Evidence frames are attacker-influenced (off the wire). The
  ring/extraction code is a tiny hand-rolled ARP/NDP-only path with no
  general-dissector attack surface. Any future inline pcap *viewer* should prefer
  a minimal ARP/NDP dissector (or a sandboxed/updated tshark) for the same reason.

## Operations

- **Verify the chain:** sensor `GET /healthz` + `/neighbors`; lg-http
  `GET /api/v1/nd-events` → `{"events":[]}` when quiet; `discovered-neighbors`
  reports stale-MAC counts when aging is active.
- **Trigger a test detection (safely):** from rs-linux, emit gratuitous ARP for a
  **verified-dark** unused IP (not assigned, not in `/neighbors`, no ping reply)
  from one MAC, wait one poll, then from a second MAC → a `new_mac_on_ip` event +
  auto-captured pcap. It auto-closes ~30 min after you stop (demonstrating
  aging). A single MAC ARPing >8 dark IPs triggers a `mac_claims_many_ips` sweep.
- **Delete a test event:** remove its row from `nd-anomalies.sqlite` and its
  `<id>.pcap` from the sensor's `evidence/snapshots/`. (lg-server's in-memory
  open-event entry only issues no-op UPDATEs afterward and clears on restart.)
- **Known benign behavior:** lg-http has a bounded "wait for lg-server" startup
  loop; a simultaneous lg-server+lg-http restart can flap lg-http a few times
  until lg-server's RPC binds, then it settles.

## Verification / testing

Unit + integration tests cover: cooldown rollup (flap-within vs flap-after,
1000-flaps→1-event); migration opens-then-**closes** (the headline regression);
brief-conflict-recorded-durably (don't-miss); MAC staleness + conflict exclusion;
sweep cross-tenant / cardinality / no-false-positive / rolling; ring-buffer →
filtered-extraction round trip + idempotency; sensor decay. End-to-end was
validated in production with a synthetic conflict on a dark IP (event recorded,
valid filtered pcap containing the conflict MACs, visible on the portal,
auto-closed afterward).

## Future work

- **Inline web pcap viewer** on the ND Events detail page (the pcap proxy already
  exists). Preferred: a small purpose-built ARP/NDP dissector (safe, tailored),
  with the Wireshark download retained for deep dives. Heavier alternatives:
  self-hosted Arkime/Malcolm; commercial CloudShark.
- Cross-linking per-IP conflicts to an active `mac_claims_many_ips` sweep.

## Source map

- Sensor: `looking-glass/lg-neighborhood-watch/src/{capture,solicit,store,ringbuf,evidence,http,config}.rs`
- lg-server: `looking-glass/src/{anomaly,discovered,config,service}.rs`, `looking-glass/lg-server/src/rpc_server.rs`
- Types/proxy: `looking-glass/lg-types/src/structured.rs`, `looking-glass/lg-http/src/rest.rs`, `looking-glass/lg-client/src/client.rs`
- Portal: `portal/dashboard/{views,urls,lg_client}.py`, `portal/templates/dashboard/nd_events.html`, `portal/templates/base.html`, `portal/templates/dashboard/participant_detail.html`
- Deploy: `ansible/roles/sfmix_route_server_linux/`, `ansible/roles/looking_glass/`, `ansible/inventory/group_vars/{rs_linux,looking_glass_rust}.yml`
