# 008 - LAN Hygiene: BUM-Traffic Misbehavior Detection

## Status: Implemented, rollout pending (2026-09-02)

## Overview

A companion to the neighbor-discovery sensor of [Design Doc 005](005-nd-anomaly-detection.md)
that watches the **broadcast / unknown-multicast (BUM)** traffic on the SFMIX peering LAN and
records, per source MAC, every protocol heard that has no business on an exchange: IPv6 router
advertisements, DHCP, OSPF/IS-IS/EIGRP hellos, VRRP/HSRP, spanning tree, CDP/LLDP, MikroTik
discovery, mDNS, and so on. Detections become durable **LAN events** in lg-server, attributed to
the owning participant via our own switch MAC tables, with a small evidence pcap, and are shown
publicly on the participant's portal page together with a remediation hint.

It reuses the three codebases of doc 005 (sensor, lg-server/lg-http, portal) plus the Prometheus
role, and renames the user-facing surface from "ND events" to **LAN events** since the one store
and page now hold both ND anomalies and hygiene detections.

### Background

An exchange is one big broadcast domain, so a member's misconfiguration — a router advertising
itself as the default gateway, a DHCP server, an IGP speaking hello to strangers — reaches every
other member. In 2026 roughly a dozen SFMIX members were sending IPv6 router advertisements into
the LAN without anyone noticing. We already run a passive sensor on the route server VM
(`rs-linux`, `ens19`) for ARP/NDP; extending it costs one classifier and a membership change on
the capture socket. The constraint that shaped every decision below: the sensor shares a host
with BIRD, so it must stay receive-only, bounded, and cheap under a flood.

### Goals

1. Detect the common offenders on a peering LAN (see [Detection catalog](#detection-catalog)).
2. Attribute each detection to a participant using the switch MAC tables + NetBox port map,
   falling back to the MAC's own ARP/NDP sightings on assigned IPs.
3. Durable events with a two-hour liveness window, a bounded set of sanitized sample details
   (advertised prefix, MikroTik identity, …), and the first frames as evidence.
4. Public participant-page banners with the fix and a public event log with filters (evidence
   pcaps stay admin-only); Prometheus metrics for the sensor and detections.
5. Host sympathy: in-kernel prefilter, bounded tables, per-second rate sampling, drop counters,
   and an alert when the kernel starts dropping frames.

### Non-goals

- Mitigation. The sensor never transmits and nothing here filters or quarantines.
- Inspecting unknown-unicast payloads. In promiscuous mode unknown unicast is *counted* per
  source for the flood heuristic, never classified or stored.
- Perfect coverage of link-local protocols (STP, LLDP, LACP are often consumed at the
  participant's switch port and never reach the route server). Best-effort by design.

## Architecture

```
 peering VLAN (ens19 on rs-linux)
       │  every frame the kernel prefilter passes
       ▼
┌────────────────────────────────────────────────────────────────┐
│ lg-neighborhood-watch (rs-linux)          CAP_NET_RAW only      │
│  afpacket.rs  AF_PACKET + PACKET_MR_PROMISC + cBPF prefilter   │
│               (drops this host's own unicast IP in-kernel)     │
│  capture.rs   ─► parse_frame (ARP/NDP)  ─► store.rs /neighbors │  (doc 005, unchanged)
│               ─► ringbuf tee (ARP/NDP)                         │
│               ─► bum::classify(frame)   ─► bum.rs table        │  /bum
│               ─► per-src rate counts (1 s) ─► flood rows       │  /bum/{mac}/{proto}/pcap
│                                                                │  /metrics (+ bum counters)
└──────────────┬─────────────────────────────────────────────────┘
               │ GET /bum (each poll, 60 s)          ▲ GET /bum/{mac}/{proto}/pcap (new event)
               ▼                                     │
┌────────────────────────────────────────────────────┴───────────┐
│ lg-server (alice)                                              │
│  discovered.rs  attribute_mac: mac_table → PortMap → ASN,      │
│                 else owner_of_mac (ND sightings); infra → skip │
│  anomaly.rs     record_bum (kind bum_protocol, 2 h window),    │
│                 evidence_pcap BLOB, EventFilter                 │   nd-anomalies.sqlite
│  rpc_server.rs  /rpc/v1/lan-events[/{id}[/pcap]]               │
└──────────────┬─────────────────────────────────────────────────┘
               │ RPC (X-RPC-Secret)
               ▼
┌────────────────────────────────────────────────────────────────┐
│ lg-http (alice)  /api/v1/lan-events[/{id}[/pcap]]              │
└──────────────┬─────────────────────────────────────────────────┘
               │ HTTPS (OIDC bearer; listing is also anonymous-safe)
               ▼
┌────────────────────────────────────────────────────────────────┐
│ portal   LAN Events, public (kind/protocol/MAC/active filters)  │
│          participant page: public hygiene banners + fix        │
│          participants list: ⚠ LAN badge per network            │
└────────────────────────────────────────────────────────────────┘
 Prometheus (metrics.sfo02) scrapes 10.1.1.18:29185 → lan-hygiene.rules.yml
   → Alertmanager → #networkalerts (sensor health only; detection alerting is commented out)
```

## Components

### Sensor — `lg-neighborhood-watch`

- **`afpacket.rs`** (new). A hand-rolled AF_PACKET receive socket, replacing pnet's datalink
  channel (pnet's packet *parsers* are still used). It binds to the interface, joins a per-socket
  membership (`PACKET_MR_PROMISC` by default; `allmulti` / `unicast` selectable via
  `capture_mode`), attaches a classic-BPF prefilter, sets a 2 MiB receive buffer and a 1 s receive
  timeout, and exposes `PACKET_STATISTICS` (kernel-side frames/drops). All of this needs only
  `CAP_NET_RAW`: memberships are socket-scoped, unlike `SIOCSIFFLAGS`. The prefilter accepts
  broadcast/multicast, ARP, 802.1Q/802.1ad, IPv6 ICMPv6 and (promiscuous only) unicast whose
  destination is not our own MAC; **it drops the route server's own unicast IP traffic — BGP and
  management — before it reaches userspace**. The filter is unit-tested with a small cBPF
  interpreter.
- **`bum.rs`** (new). `classify(frame, ctx) -> Option<Detection>` is one bounded decode
  (Ethernet → optional 802.1Q → LLC/SNAP | ARP | IPv4 | IPv6 with up to two extension headers →
  UDP/ICMPv6/IGMP) followed by a match against the catalog. Normal IX traffic (ARP for in-prefix
  addresses, NS/NA, MLD/IGMP *reports*) decodes to `None`. Frames from the interface's own MAC or
  any `ignore_src_macs` entry are skipped before classification. Sample details are extracted only
  for a handful of trivially-safe fields (RA prefix/lifetime/flags, MNDP identity/platform/version,
  CDP device-id, LLDP system name, DHCP hostname, OSPF router-id/area, VRRP vrid/prio, STP root,
  VID, hex EtherType) through `sanitize()` (printable ASCII else `?`, ≤ 64 bytes); every TLV walk
  is slice-bounded and capped at 32 iterations. The aggregate `Table` folds detections into one row
  per `(src_mac, protocol)` with first/last seen, count, ≤ 8 distinct details and the first ≤ 8
  frames (≤ 512 B each) as evidence; rows decay after `bum_ttl_secs` and the table is capped at
  2048 keys (oldest evicted). Capture threads also send one `RateSample` per second per interface
  (per-source broadcast/multicast and unknown-unicast counts); a 60 s window over
  `bum_flood_pps` synthesizes the `bum_flood` / `unknown_unicast_flood` rows.
- **`capture.rs`** — now opens the `RawSocket`, fans each frame out to the ND parser, the ring tee,
  the classifier and the rate counters (all non-blocking with drop counters), and flushes rate
  samples + kernel stats once a second.
- **`lgpoll.rs`** — additionally fetches `/rpc/v1/peering-vlans` and publishes the IX prefixes into
  the `ClassifyCtx` (atomic swap). Until the first sync the prefix list is empty and the
  `foreign_*` heuristics stay off — no cold-start false positives.
- **`http.rs`** — `GET /bum` (rows), `GET /bum/{mac}/{protocol}/pcap` (in-memory classic pcap of the
  stored frames; MAC syntax and catalog key validated first), `/healthz` gains `capture_mode` and
  `bum_rows`, `/metrics` gains the counters below.

### lg-types — the catalog

`lg_types::structured::BUM_CATALOG` is the single source of truth: `key`, `label`, `severity`,
`why`, `remediation` per protocol. The sensor classifies into it, lg-server stores the key and
severity, and fills `label`/`why`/`remediation` onto the event at read time so the CLI and the
portal never carry a copy. `EVENT_KIND_BUM_PROTOCOL = "bum_protocol"`.

### lg-server

- **`anomaly.rs`** — same SQLite store and `nd_events` table (name kept; it is internal), with
  additive columns `protocol`, `severity`, `detail` (JSON array), `evidence_pcap` (BLOB ≤ 16 KiB)
  and indexes on `last_seen` and `(new_mac, protocol)`. `record_bum(mac, protocol, severity, asn,
  tenant, details, count, now)` rolls up on `(mac, protocol)` within `bum_active_secs` (default
  7200): advances `last_seen`, takes the sensor's cumulative count as `flap_count`, unions details,
  COALESCEs attribution; otherwise closes the stale event and opens a new one. Open BUM events are
  re-seeded on restart. `list_events(&EventFilter, now)` replaces the positional signature and adds
  `mac`, `kind`, `protocol` and `active_only` (a per-kind `last_seen >` cutoff evaluated in SQL, so
  "what does ASN X have open" is one indexed query). `closed` is computed at read time with the
  ND cooldown for ND kinds and the 2 h window for hygiene.
- **`discovered.rs`** — `fetch_bum()`; `attribute_mac()` walks the device-state cache's MAC tables
  and classifies the learning port through the NetBox `PortMap`: a **participant** port attributes,
  an **admin-only** port marks the MAC as infrastructure (detection suppressed), a **core** port
  says nothing (the MAC is behind another switch), and the fallback is
  `DiscoveredNeighborStore::owner_of_mac` (clean sightings on assigned IPs). The poll loop, after
  the ND fold and when `bum_enabled`, records each `/bum` row and queues newly-opened events to the
  existing serialized snapshot worker, which for hygiene events fetches the sensor's tiny pcap and
  stores it inline (`set_evidence_pcap`, write-once).
- **`rpc_server.rs`** — `/rpc/v1/lan-events[?asn&ip&mac&kind&protocol&active&limit&offset]`,
  `/rpc/v1/lan-events/{id}`, `/rpc/v1/lan-events/{id}/pcap` (inline BLOB for hygiene events, sensor
  stream for ND events). **`lg-http`** proxies the same paths under `/api/v1/`, passing only
  token-safe filter values through.
- **CLI** — `show lan-events [<asn>|ip <ip>|detail <uuid>|evidence]` (was `show nd-events`);
  hygiene rows show `protocol (severity)` as the subject and detail prints why/remediation.

### Portal

- **LAN Events** (`/lan-events/`, public, née the admin ND Events page): kind, protocol, IP, MAC,
  ASN and "active only" filters carried through paging; hygiene rows show a severity-toned protocol
  badge, the catalog label, sample details and the fix as one line per vendor. The evidence pcap
  column and download (`/lan-events/{id}/pcap/`) render only for IX admins. Public so a participant
  can follow the banner on their own page to the full record.
- **Participant page** (public): one banner per active protocol, ordered critical → warning →
  info, with why-it-matters, sample details, the remediation as code, source MAC(s), last heard and
  frame count; a sticky-bar chip counts the issues. Visible to anyone.
- **Participants list**: a ⚠ LAN badge per network with an active detection (worst severity),
  from one anonymous `active=1&kind=bum_protocol` call.

## Detection catalog

Severity: **critical** protocols can redirect other members' traffic, merge routing tables or
disrupt the port and page to Slack; **warning** is information leakage / misconfiguration shown on
the portal; **info** is chatter worth telling the participant about.

| key | match | sev | what to tell the participant |
|---|---|---|---|
| `ipv6_ra` | ICMPv6 134 (detail: lifetime, M/O flags, first PIO prefix) | critical | Arista `ipv6 nd ra disabled all`; Cisco `ipv6 nd ra suppress all`; Junos delete `protocols router-advertisement interface`; RouterOS `/ipv6 nd set [find] disabled=yes`; Linux stop radvd |
| `dhcpv4` | UDP dst 67 (client) / 68 (server) (detail: hostname opt 12) | critical | `no ip address dhcp`, no DHCP server on the IX interface |
| `dhcpv6` | UDP dst 546 / 547 | critical | `no ipv6 dhcp client|server` |
| `ospf` | IP proto 89 (detail: version, router-id, area) | critical | `passive-interface` / `ip ospf passive` |
| `isis` | LLC DSAP/SSAP 0xfe | critical | `isis passive` |
| `eigrp` | IP proto 88 | critical | `passive-interface` |
| `rip` | UDP 520 / 521 | critical | `no router rip` / passive |
| `ldp` | UDP 646 | critical | `no mpls ldp` on the interface |
| `pim` | IP proto 103 | critical | `no ip pim` / `no ipv6 pim` |
| `vrrp` | IP proto 112 (detail: vrid, prio) | critical | remove the VRRP group from the IX interface |
| `hsrp` | UDP 1985 / 2029 (detail: group, prio) | critical | `no standby <grp>` |
| `glbp` | UDP 3222 | critical | `no glbp <grp>` |
| `stp` | LLC 0x42 to 01:80:c2:00:00:00, or PVST+ SNAP PID 0x010b (detail: BPDU type, root id) | critical | `spanning-tree bpdufilter enable` / disable STP on the port |
| `cdp` | SNAP OUI 00000c PID 0x2000 (detail: device id) | warning | `no cdp enable` |
| `cisco_l2` | SNAP OUI 00000c PID 0x2003 VTP / 0x2004 DTP / 0x0104 PAgP / 0x0111 UDLD | warning | `switchport nonegotiate`, no VTP/UDLD/channel-group towards the IX |
| `lldp` | EtherType 0x88cc (detail: system name) | warning | `no lldp transmit` |
| `mndp` | UDP dst 5678 (detail: identity, platform, version) | warning | RouterOS `/ip neighbor discovery-settings set discover-interface-list=none` |
| `romon` | EtherType 0x88bf | warning | RouterOS `/tool romon set enabled=no` |
| `mac_telnet` | UDP dst 20561 | warning | RouterOS `/tool mac-server set allowed-interface-list=none` (+ mac-winbox) |
| `mdns` | UDP 5353 | warning | disable avahi/Bonjour on the IX interface |
| `llmnr` | UDP 5355 | warning | Windows GPO "Turn off multicast name resolution" |
| `ssdp` | UDP 1900 | warning | disable UPnP/SSDP |
| `netbios` | UDP 137 / 138 | warning | disable NetBIOS over TCP/IP |
| `igmp_query` | IP proto 2, IGMP type 0x11 (reports are normal) | warning | `no ip igmp`, no snooping querier towards the IX |
| `mld_query` | ICMPv6 130 (reports are normal; hop-by-hop header handled) | warning | `no ipv6 mld` |
| `ntp_broadcast` | UDP 123 to a broadcast/multicast destination | warning | `no ntp broadcast` |
| `dot1q_tagged` | EtherType 0x8100 / 0x88a8 on the untagged port (detail: VID) | warning | fix the VLAN/subinterface facing the IX |
| `foreign_arp` | ARP sender IP outside the IX prefixes and ≠ 0.0.0.0 (detail: sender) | warning | VLAN leak / wrong subnet on the IX interface |
| `foreign_ipv4_broadcast` | IPv4 to ff:ff:… with source outside the IX prefixes, otherwise unmatched (detail: source) | warning | same |
| `bum_flood` | synthetic: one source > `bum_flood_pps` broadcast/multicast frames/s over 60 s | warning | loop / storm / misbehaving host; storm-control |
| `ipv6_rs` | ICMPv6 133 | info | `accept_ra=0`, no autoconf on the IX interface |
| `lacp` | EtherType 0x8809 from a non-infrastructure MAC | info | no channel-group towards the IX unless agreed |
| `dns_broadcast` | UDP 53 to a broadcast/multicast destination | info | fix the resolver configuration |
| `icmpv6_echo_allnodes` | ICMPv6 128 to ff02::1 | info | known SONiC neighbor-refresh behaviour |
| `dec_mop` | EtherType 0x6001 / 0x6002 | info | Cisco `no mop enabled` |
| `loop_detect` | EtherType 0x9000 / 0x8899 | info | `no keepalive` / `loop-detect disable` |
| `unknown_ethertype` | any other EtherType / LLC / SNAP to a broadcast/multicast MAC (detail: hex) | info | identify + disable vendor L2 chatter |
| `unknown_unicast_flood` | synthetic (promiscuous only): unicast to ≠ own MAC > `bum_flood_pps` from one source | info | destination MAC aged out / flapping; informational |

Adding a protocol = one `BUM_CATALOG` row (lg-types), one match arm in `bum::classify`, one
hand-built-frame test in `bum.rs`, and the key in the portal's `_BUM_PROTOCOLS` dropdown list.

## Data model

`nd_events` (SQLite, WAL) — doc 005's table plus additive columns; a `bum_protocol` row uses
`ip = ''`, `family = ''`, `old_macs = '[]'`, `new_mac = <source MAC, lowercase>` and
`flap_count = <sensor's cumulative count>`.

```sql
ALTER TABLE nd_events ADD COLUMN protocol TEXT;        -- BUM_CATALOG key
ALTER TABLE nd_events ADD COLUMN severity TEXT;        -- critical | warning | info
ALTER TABLE nd_events ADD COLUMN detail TEXT;          -- JSON array of sanitized strings (≤ 8)
ALTER TABLE nd_events ADD COLUMN evidence_pcap BLOB;   -- ≤ 16 KiB classic pcap, write-once
CREATE INDEX IF NOT EXISTS idx_nd_events_last_seen ON nd_events(last_seen);
CREATE INDEX IF NOT EXISTS idx_nd_events_mac_proto ON nd_events(new_mac, protocol);
```

`AnomalyEvent` (lg-types) gains `protocol`, `severity`, `detail`, `has_evidence`, and the
read-time `label` / `why` / `remediation`; all `#[serde(default)]` so existing rows and payloads
deserialize unchanged. Example:

```json
{"id":"7e1c…","kind":"bum_protocol","protocol":"ipv6_ra","severity":"critical",
 "label":"IPv6 Router Advertisement","ip":"","family":"","asn":64496,"tenant":"Example Net",
 "old_macs":[],"new_mac":"00:11:22:33:44:55","claimed_ips":[],
 "detail":["lifetime 1800s M prefix 2001:db8:beef::/64"],
 "why":"Advertises this router as a default gateway …","remediation":"Arista: ipv6 nd ra disabled all; …",
 "opened_at":"2026-09-02T18:00:00Z","last_seen":"2026-09-02T19:12:00Z","flap_count":437,
 "evidence_id":null,"has_evidence":true,"closed":false,"classification":null}
```

## API surface

| Endpoint | Auth | Purpose |
|---|---|---|
| sensor `GET /bum` | internal | current `(src_mac, protocol)` rows |
| sensor `GET /bum/{mac}/{protocol}/pcap` | internal | stored frames as a tiny pcap |
| sensor `GET /metrics` | internal (scraped) | `neighwatch_bum_frames_total{protocol,severity,src_mac}`, `neighwatch_bum_frames_by_protocol_total{protocol,severity}`, `neighwatch_bum_sources{protocol,severity}`, `neighwatch_bum_observations_total`, `neighwatch_bum_dropped_observations_total`, `neighwatch_capture_frames_total`, `neighwatch_capture_kernel_drops_total` |
| lg-server `GET /rpc/v1/lan-events` | X-RPC-Secret | list; `?asn ?ip ?mac ?kind ?protocol ?active=1 ?limit ?offset` |
| lg-server `GET /rpc/v1/lan-events/{id}[/pcap]` | X-RPC-Secret | one event / its pcap |
| lg-http `GET /api/v1/lan-events[/{id}[/pcap]]` | OIDC bearer | portal-facing proxy |
| portal `/lan-events/` | public | UI; `/lan-events/{id}/pcap/` download is IX-admin only |
| portal `/participants/<asn>/`, `/participants/` | public | hygiene banners / badges |

## Configuration reference

Sensor (`lg-neighborhood-watch`, in addition to doc 005):

| Key | Default | Notes |
|---|---|---|
| `capture_mode` | `promisc` | `promisc` \| `allmulti` \| `unicast`; the cBPF prefilter applies in every mode |
| `bum_ttl_secs` | 7200 | row expiry after last heard |
| `bum_flood_pps` | 50 | per-source rate (60 s average) for the two synthetic flood rows |
| `ignore_src_macs` | `[]` | infrastructure MACs; the interface's own MAC is always ignored |

lg-server (`discovered:`):

| Key | Default | Notes |
|---|---|---|
| `bum_enabled` | true | poll `/bum` into durable events (false = sensor dry-run) |
| `bum_active_secs` | 7200 | hygiene rollup / read-time `closed` window |

Ansible: `sfmix_route_server_linux_lg_neighborhood_watch_{capture_mode,bum_ttl_secs,bum_flood_pps,ignore_src_macs}`
(role defaults + `group_vars/rs_linux.yml`), `looking_glass_discovered_{bum_enabled,bum_active_secs}`
(`group_vars/looking_glass_rust.yml`, **currently `bum_enabled: false`** for the dry run),
Prometheus job `lg-neighborhood-watch` + `rules/lan-hygiene.rules.yml.j2`. The per-detection
alert (`IxLanCriticalProtocolSeen`) is **commented out**: with a dozen-plus RA senders at any time
it is a standing condition, not an incident, and paged too much; only the sensor-health alerts
(`NeighwatchCaptureDrops`, `NeighwatchDown`) are active.

## Deployment & rollout

Same model as doc 005: static musl binaries built off-host and copied; never build on rs-linux.
The `lan-events` rename spans lg-server, lg-http and the portal, so deploy the `looking_glass`
role first, then the portal (the portal 404s on the old path only for that window).

Staged, deliberately slow:

1. **Sensor first, hygiene events off** (`looking_glass_discovered_bum_enabled: false` as
   committed). Deploy the sensor with `capture_mode: promisc`; watch `neighwatch_capture_*`, the
   unit's CPU/RSS, and `neighwatch_bum_dropped_observations_total`. Fall back to `allmulti` if
   the host shows strain.
2. **Dry-run week.** Read `GET /bum` on the sensor (or `neighwatch_bum_sources` in Prometheus).
   Expect SFMIX's own switches (LLDP, LACP, IGMP/MLD querier, possibly STP) and the sibling route
   server to appear; collect those MACs into `ignore_src_macs`. Sanity-check the RA sender set
   against a manual tcpdump on the sensor host.
3. **Enable.** Deploy Prometheus (scrape + rules), flip `bum_enabled: true`, deploy lg-server,
   then the portal. Events and banners go live together; re-enable the detection alert only once
   the fabric is clean enough that a new critical source is worth a page.

## Security & safety

- Still **receive-only** and **`CAP_NET_RAW` only**: promiscuous membership is socket-scoped and
  released when the process exits; nothing here can transmit.
- The cBPF prefilter means the route server's BGP sessions are never copied to userspace, in any
  capture mode.
- **Everything in a frame is attacker-controlled.** The classifier is a bounded, allocation-light
  decode with slice-checked reads and iteration-capped TLV walks; sample details are `sanitize()`d
  to printable ASCII (≤ 64 bytes) before they are stored, exported as metrics, or rendered (Django
  escapes them again). Malformed/truncated inputs are unit-tested to never panic.
- **Bounded everywhere:** ≤ 2048 rows, ≤ 8 frames × 512 B per row (≈ 8 MiB worst case under the
  unit's `MemoryMax=128M`), ≤ 8 details, per-thread rate map cleared beyond 2048 sources, ≤ 16 KiB
  evidence per event in SQLite, bounded channels with drop counters.
- Public exposure of a network's hygiene issues is an explicit product decision: what a network
  leaks onto the shared LAN is already visible to every other member. Only the catalog text, the
  source MAC, sanitized details and counts are shown.

## Operations

- **Is it working?** Sensor `/healthz` shows `capture_mode` and `bum_rows`; `/bum` lists rows;
  Prometheus `neighwatch_bum_sources`; `show lan-events` on the LG; the portal LAN Events page with
  kind = LAN hygiene (public page).
- **A detection is SFMIX infrastructure.** Add the MAC to
  `sfmix_route_server_linux_lg_neighborhood_watch_ignore_src_macs`, redeploy the sensor. MACs
  learned on NetBox admin-only ports are already suppressed by `attribute_mac`.
- **Host under load** (`NeighwatchCaptureDrops`): switch `capture_mode` to `allmulti`; the flood
  rows on the sensor name the storm source.
- **Delete a test event:** remove the row from `nd-anomalies.sqlite` (the BLOB goes with it).

## Verification

- `cargo test --workspace` (sensor: classifier per catalog row, negatives, malformed input,
  table fold/cap/prune, flood synthesis, cBPF encoding; lg-server: BUM rollup vs ND cooldown,
  `EventFilter`, evidence write-once, restart re-seed, schema migration, `owner_of_mac`) and
  `cargo clippy --workspace --all-targets` — clean.
- `python manage.py test dashboard` — LAN Events rendering, filter validation, admin gating,
  hygiene issue grouping/ordering, list badges.
- **Lab only — never inject on the production IX.** veth pair on a dev box, sensor on one end in
  `promisc`, `tcpreplay`/scapy on the other with RA, DHCP Discover, OSPF Hello, MNDP, CDP
  (Dot3/LLC/SNAP), 802.1Q-tagged and RoMON frames. Check `/bum`, open the `/pcap` in Wireshark,
  scrape `/metrics`, watch lg-server open `bum_protocol` events with inline evidence, load the
  participant page.

## Future work

- Per-switch-port attribution via sFlow or a port mirror, for link-local protocols the route
  server never sees.
- A `lan_hygiene` public JSON feed (IX-F style) for members who want to poll their own status.
- Historical trending of `neighwatch_bum_frames_by_protocol_total` in Grafana.

## Source map

- Sensor: `looking-glass/lg-neighborhood-watch/src/{afpacket,bum,capture,config,http,lgpoll,main}.rs`
- Catalog/types: `looking-glass/lg-types/src/structured.rs` (`BUM_CATALOG`, `EVENT_KIND_BUM_PROTOCOL`, `AnomalyEvent`)
- lg-server: `looking-glass/src/{anomaly,discovered,config,service,format,policy}.rs`, `looking-glass/config/grammar.yml`, `looking-glass/lg-server/src/rpc_server.rs`
- lg-http: `looking-glass/lg-http/src/rest.rs`
- Portal: `portal/dashboard/{views,urls,lg_client}.py`, `portal/templates/dashboard/{lan_events,participant_detail,participants_list}.html`, `portal/templates/base.html`, `portal/tailwind.input.css`, `portal/dashboard/devmock/fixtures/lg/lan-events.json`
- Deploy: `ansible/roles/sfmix_route_server_linux/{defaults/main.yml,templates/lg-neighborhood-watch.yml.j2}`, `ansible/inventory/group_vars/{rs_linux,looking_glass_rust}.yml`, `ansible/roles/looking_glass/templates/lg-server.yml.j2`, `ansible/roles/prometheus/{templates/prometheus.yaml.j2,templates/rules/lan-hygiene.rules.yml.j2,tasks/main.yml}`
