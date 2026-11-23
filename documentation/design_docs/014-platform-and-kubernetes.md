# 014 — Platform strata and Kubernetes

Status: exploratory (2026-11-22). Nothing is built. Names, numbers and
address ranges below are proposals; the ranges and VLAN 203 were unallocated
in NetBox on 2026-11-16.

## Why

Two problems with one answer.

Every new service today gets its own hand-built VM. That is a lot of kernels
to patch, a lot of per-service Ansible, and a lot of overhead for workloads
that are mostly a container and a port. The donated DL360 Gen9s are the first
hosts with real headroom (64 threads each, fast local SSD), so a small
Kubernetes cluster can hold the stateless services, with rolling deploys and
replicas spread across sites.

But "put it on Kubernetes" is only safe if it is equally clear what may *not*
go there. An IXP's route servers must not depend on a cluster whose control
plane depends on the exchange network. So this document defines the layers
and their dependency rules first, and the cluster second.

We are an IXP, so the cluster is addressed the way we address everything
else: with dynamic routing. That removes the usual problem of a multi-site
cluster (no shared L2 for ARP-based virtual IPs) and makes pod and service
addresses ordinary routed prefixes.

## Principles

- **Dependencies point down.** A service may depend only on strata strictly
  below it. An arrow pointing up is a bug, not a trade-off.
- **Simple and discoverable beats clever.** A volunteer network engineer
  should be able to read the repo and the routing table and understand what
  is happening. This rules out designs whose debugging requires specialist
  tooling.
- **Bulk and public traffic never crosses a mgmt-gw.** The mgmt-gws are small
  CPU routers. Public services, pod internet egress and node-to-node traffic
  ride a fabric VLAN on the node hosts' fabric links — 10G where available,
  2x1G at scl04 until its FlexLOM is cabled.
- **The mgmt side carries only internal, low-volume traffic:** admin access,
  the API, scraping, logs.
- **Same pattern everywhere:** the two core sites (sfo02, fmt01) are hubs that
  accept BGP clients from a `bgp listen range`; every client lists just the
  two hubs. Adding a node or a site never touches existing config.
- **One private ASN per site.** No iBGP anywhere.
- **Plain Linux routing on the nodes:** FRR plus k3s's built-in flannel in
  `host-gw` mode. No overlay, no CNI-specific BGP layer.

## Infrastructure strata

```
┌─ S4  pods ────────────────────────────────────────────────────┐
│  portal · lg-http · obscreen · exporters · bots               │
│  identity: SPIFFE ID from namespace/ServiceAccount            │
└──────────────────────────┬────────────────────────────────────┘
┌─ S3  kubernetes nodes (VMs) ─────────────────────────────────┐
│  k8s01.sfo02 · k8s01.fmt01 (witness) · k8s01.scl04            │
│  identity: SPIFFE ID per node                                 │
└──────────────────────────┬────────────────────────────────────┘
┌─ S2  platform VMs ───────────────────────────────────────────┐
│  see sublayers below                                          │
│  identity: SPIFFE ID per VM, registered from NetBox           │
└──────────────────────────┬────────────────────────────────────┘
┌─ S1  hypervisors (bare metal) ───────────────────────────────┐
│  pve01.sfo02 · pve02.scl04 · pve0{1,2}-{sfo,fmt} · pve01.scl04│
│  identity: SPIFFE ID per host                                 │
└──────────────────────────┬────────────────────────────────────┘
┌─ S0  physical + network ─────────────────────────────────────┐
│  edge-gw · mgmt-gw · switches · PDUs · iLO/BMC · VLAN 203     │
│  time (NTP from the site mgmt-gw)                             │
│  identity: device credentials, configured directly on the gear│
└───────────────────────────────────────────────────────────────┘
```

The diagram is not exhaustive; it names enough of each stratum to place the
rest by analogy.

### S2 in detail

A single flat S2 hides the dependency cycles that matter, so it has an
internal order of its own:

| sub | layer | contents | may depend on |
|---|---|---|---|
| **S2.0** | Naming | `ns1` authoritative DNS | S1/S0 only |
| **S2.1** | Identity | SPIRE server | S2.0 |
| **S2.2** | Durable state | Garage object store, `backup01.scl04` | S2.0 |
| **S2.3** | Secrets & artifacts | OpenBao, container registry | S2.0–S2.2 |
| **S2.4** | Record & human access | NetBox, authentik, Teleport, Prometheus/Loki/Thanos | S2.0–S2.2 |

Two rules fall out of this ordering:

- **SPIRE sits below OpenBao, never beside it.** Making OpenBao's PKI engine
  the SPIRE upstream CA while OpenBao authenticates workloads by SPIFFE ID is
  a deadlock on cold start. SPIRE is self-rooted and never calls OpenBao.
- **The exchange plane is pinned to S2.0.** `rs-linux`, `rs-openbsd` and
  `rpki-linux` may hold no runtime dependency above naming. They are
  structurally S2 but pinned to the bottom of it by policy.

NetBox sits at S2.4, above most of what it configures. That is not an
inversion, because of the next section.

### The operator path is outside the strata

Ansible run from an operator's workstation, direct SSH, ProxyJump via
`shell.sfmix.org`, and the iLO/console path are **not** a stratum. They are
the out-of-band construction and repair path.

This is why `rs-linux` can be *configured from* NetBox without *depending on*
NetBox: the dependency is build-time and mediated by an operator, not a
runtime call. The same applies to SPIRE registration entries derived from
NetBox — NetBox being down stops new registrations, not the issuance of SVIDs
for anything already registered.

It is also the bootstrap answer: the whole stack is constructible from a
laptop plus GitHub.

Two corollaries:

- **The break-glass path must never route through the strata.** Ansible uses
  direct SSH, not Teleport, and that must stay true. Teleport is an S2.4
  convenience, not the repair path.
- **Monitoring is inherently inverted** (S2.4 watching S2.0). Accept it, but
  the alert egress path must not traverse Kubernetes.

### Never on Kubernetes

These stay on dedicated VMs permanently. The moment the exchange's control
plane depends on a cluster whose control plane depends on the exchange
network, a routine partition becomes an unrecoverable one.

- Route servers (`rs-linux`, `rs-openbsd`)
- `ns1` authoritative DNS
- RPKI validators
- SPIRE server, OpenBao, the container registry
- `backup01.scl04` and the Garage nodes
- Teleport

Kubernetes gets *workloads*: portal, lg-http, obscreen, exporters, bots,
sensor and DAS processing.

## Threat model

In scope: credential sprawl across hosts and the repo, one compromised
workload reading another's secrets, accidental disclosure in git or logs, and
auditability of secret access.

Out of scope: physical theft of a powered-off disk or host. SFMIX hosts have
no full-disk encryption, and OpenBao's unseal key is stored on the host it
unseals, so possession of a host — or root on its hypervisor — yields every
secret that host holds. Equipment is in access-controlled colocation
facilities, and the operational cost of the alternative (no unattended
reboots) is judged higher than the benefit.

`backup01.scl04` aggregates every service's secrets into one place and is
therefore the highest-value single target under this model. It stays
mgmt-only with tight access rather than encrypted.

## Identity: SPIRE

One trust domain, `spiffe://sfmix.org`, spanning bare metal, VMs and pods.
The payoff is that a service running on a VM and the same service running in
a pod hold comparable identities, so moving it is a policy edit rather than a
re-plumb.

| stratum | attestation | notes |
|---|---|---|
| S1 hypervisors, S2/S3 VMs | `x509pop` | per-host cert issued by Ansible from a small internal CA |
| S4 pods | `k8s_psat` + `spire-controller-manager` | `ClusterSPIFFEID` maps namespace/ServiceAccount to SPIFFE ID; SVIDs mounted by the SPIFFE CSI driver |

- **SPIRE has its own self-signed root.** `KeyManager = "disk"` on
  `/var/lib/spire`. Not `memory`, which regenerates the CA on every restart
  and invalidates the trust bundle every agent holds.
- **NetBox is the registrar.** A reconciler syncs NetBox VM and device records
  into SPIRE registration entries, in the same idiom as the existing
  NetBox-driven syncers. Proxmox VMID and host appear as selectors.
- There is no Proxmox node attestor upstream; `x509pop` with Ansible-issued
  certs is the substitute. `join_token` works but is a bearer secret.

## Secrets: OpenBao

OpenBao (Apache-2.0; Vault is BUSL) on three VMs across three sites, Raft
storage. Its value here is per-workload policy, rotatable credentials, an
audit trail and one place to revoke — not encryption at rest, which the
threat model above explicitly forgoes.

- **Auto-unseal at boot.** A systemd unit reads the unseal shares from a
  root-only file and posts them. Authoritative copy in 1Password, matching how
  the Ansible vault password is already handled. (Check whether the OpenBao
  version in use has since gained a native static seal that removes the
  wrapper.)
- **Raft storage has the same fsync profile as etcd.** See the fsync table
  below; the same Optane fix applies, and `pve01-fmt`'s empty M.2 slot is
  therefore load-bearing for two Raft systems.
- **No component may require OpenBao at boot.** A seal is then a degraded
  state, not an outage.

### Human access

- **Native `oidc` auth against `login.sfmix.org`**, with `ui = true`. Not the
  authentik outpost proxy: OpenBao must know which human is calling in order
  to select a policy and write a meaningful audit entry, and behind
  forward-auth every request looks like one identity.
- **authentik groups map to OpenBao policies** via `groups_claim`, so group
  membership is the whole access-control surface. The authentik provider needs
  its group scope mapping.
- Verify the redirect-URI paths against the deployed OpenBao version; the UI
  routes inherit Vault's naming.
- **Break-glass needs no standing credential.** Revoke the initial root token
  once OIDC works; the unseal keys in 1Password can regenerate one with
  `operator generate-root`.

### Machine access

Workloads authenticate by SPIFFE JWT-SVID (AppRole before SPIRE exists),
**never through authentik**. If machine auth ever routes through SSO, an
authentik outage becomes a fleet outage.

### Audit

- **Enable two audit devices**, `file` and `syslog`. OpenBao inherits Vault's
  fail-closed behavior: if every audit device fails to write, it stops serving
  requests. A full disk must not be able to wedge the secrets store.
- The audit log HMACs sensitive values, so it is safe to ship off-box through
  the existing journald → Alloy → Loki path on metrics.sfo02. Mind the 200M
  journald cap if the syslog device goes through journald.

### Policies as code

A static service listing in the monorepo is the source of truth, rendering
OpenBao policies, SPIRE registration entries and the authentik group for each
service from one entry. Paths stay flat and greppable (`secret/<service>/...`,
one policy per service); no Vault-style namespaces.

## Container images

Two independence requirements that are easy to confuse:

- **GitHub/ghcr.io unavailable** → the internal registry serves. Daily
  operational independence.
- **Internal compute destroyed** → rebuild from GitHub and public registries.
  Bootstrap path.

Which gives one invariant: **every image exists in at least two of
{ghcr.io, internal registry, upstream origin}**, and everything in the
internal registry is reproducible from the monorepo.

- Build in public on GitHub Actions, push to ghcr.io.
- **Internal registry** (Distribution `registry:2`) with its S3 backend
  pointed at the existing Garage cluster, one frontend per core site over one
  bucket. Authoritative for what Kubernetes pulls.
- **Mirror everything**, third-party images included (postgres, openbao,
  registry itself). "Independent of GitHub" is worthless if it leaves a
  dependency on Docker Hub.
- **Promotion by digest**: `skopeo copy` from ghcr.io, digests pinned in the
  repo, so a deploy or a pod restart never needs the public internet.
- **containerd mirror fallback** in `/etc/rancher/k3s/registries.yaml`:
  local-site registry → other-site registry → ghcr.io. A dead cache degrades
  to a slow pull, not an outage.
- **Bootstrap trap:** the registry's own image comes from an Ansible-placed
  tarball (`podman load`), never a pull.

## The cluster

### Shape

```
                       internet
                          │
          edge-gw.sfo02 ──┴── edge-gw.fmt01        AS 12276, fabric hubs
               │   listen range on VLAN 203   │
 ══════════════╧══ VLAN 203 K8S-FABRIC (stretched, 10G) ═╧══════════════
      │                         │                         │
 k8s01.sfo02               k8s01.fmt01               k8s01.scl04
 AS 65201                  AS 65202 (etcd witness)   AS 65206
      │                         │                         │
 K8S-NODES (site VLAN)     K8S-NODES                 K8S-NODES
      │                         │                         │
 mgmt-gw.sfo02 ◄─────────► mgmt-gw.fmt01             mgmt-gw.scl04
 AS 65101   hub            AS 65102   hub            AS 65106  spoke
      ▲                         ▲                         │
      └──── route-server hubs; every spoke peers with both ┘
```

### Nodes

| node | host | role | vCPU | RAM | disk |
|---|---|---|---|---|---|
| k8s01.sfo02 | pve01.sfo02 (DL360) | server + workloads | 32–48 | ~20 GiB | 200 GiB on `tank-vms` |
| k8s01.scl04 | pve02.scl04 (DL360) | server + workloads | 32–48 | ~24 GiB | 200 GiB on `tank-vms` |
| k8s01.fmt01 | pve01-fmt (Atom) | etcd only, no workloads | 2 | 4 GiB | 32 GiB on `local-zfs` |

Each node VM has two NICs:

- **fabric leg** on the host's fabric bridge: pve01.sfo02 and pve02.scl04
  `vmbr2` (bond2, FlexLOM 10G to the fabric switches, today
  `allowed vlan none`); pve01-fmt `vmbr2` (eno4 trunk, already carries fabric
  VLANs 100/101/997/998). pve02.scl04 has no in-band 10G for now: its fabric
  leg is `vmbr1` (bond1, 2x1G to mgmt-switch.scl04) rather than `vmbr2`
  (bond2, FlexLOM, uncabled) — see below.
- **mgmt leg** on the site's new `K8S-NODES` VLAN.

Sizing notes:

- **RAM is the constraint, not CPU.** Each DL360 has 31–32 GiB. pve01.sfo02
  already runs metrics01 (4 GiB) and teleport (2 GiB). Leave 4–5 GiB per host
  for Proxmox and the ZFS ARC. More DDR4 RDIMMs is the cheapest upgrade.
- **`tank-vms` is a single consumer 2 TB SSD** on both DL360s. Losing it
  means rebuilding that node from the cluster: fine for stateless workloads
  and etcd, not for local persistent volumes. Keep state off the cluster at
  first.

**Why not pve02-fmt** for any member: its Samsung 870 QVO pair was at ~90%
endurance used on 2026-09-20, burning ~0.9 P/E cycles per day — roughly five
months of life left at that rate. Both drives have taken identical writes
over identical hours, so the mirror protects against an independent failure,
not the correlated one that is actually coming. It also runs librenms.
pve01-fmt's QVOs are at 40–41% and it has 42 of 62 GiB free.

### etcd and the fmt01 witness

etcd fsyncs its log on every write and wants p99 fsync under 10 ms. Measured
2026-11-15, 200 × `fdatasync` of 2.3 KB (similar to an etcd log write):

| pool | p50 | p99 |
|---|---|---|
| pve01-fmt `rpool` (Samsung 870 QVO mirror) | 98 ms | 231 ms |
| pve02-fmt `rpool` (Samsung 870 QVO mirror) | 103 ms | 224 ms |
| pve01.sfo02 `tank` | 1.0 ms | 1.5 ms |
| pve02.scl04 `tank` | 1.0 ms | 1.5 ms |

A write commits once the leader and one follower have it on disk. So the slow
fmt01 member:

- **does not matter** while both DL360 members are up and one of them leads;
- **slows every write to ~100–250 ms** while a DL360 member is down (the API
  keeps working; heartbeat 100 ms / election 1 s means no election storms);
- **slows every write while it is the leader.** etcd has no leader priority;
  move leadership with `etcdctl move-leader` if it ever wins.

Fix: pve01-fmt (Supermicro A2SDi-TP8F) has an **empty M.2 PCIe slot**. A
small power-loss-protected device (Intel Optane P1600X 58 GB, ~$40–60) as a
dedicated pool for this VM takes fsync under 1 ms. Used instead as a `log`
vdev for `rpool`, it also helps alice. Do it before relying on the cluster.

etcd does not split-brain. On a partition the majority side keeps a leader and
keeps serving; the minority side has no leader and refuses writes *and* reads,
because normal etcd reads are linearizable and need a quorum round-trip. The
failure mode is unavailability, never divergence.

What that means for workloads: **kubelet is autonomous.** Pods already running
keep running, container restarts keep working, and FRR keeps advertising from
its existing state. A partitioned site keeps serving traffic; it just cannot
schedule, scale or self-heal. The hazard is the majority side rescheduling a
partitioned node's pods after the eviction timeout while the originals still
run — harmless for stateless HTTP, which is one more reason stateful
singletons stay off the cluster.

Rules for the witness VM:

- **Exclude it from pvesr replication** on the FMT01-01 cluster. Replication
  freezes the guest filesystem every 15 minutes, which stalls etcd, and a
  copied etcd member is useless anyway.
- No vzdump either (snapshot mode freezes the guest the same way). Back up
  etcd with its own snapshots (k3s `etcd-snapshot`), pushed to backup01.scl04
  like doc 013.

### Third site

The third DL360 (NetBox 216, `incoming-dl360g9-3`, status `inventory`) would
go to **fmt01**, but that rack is busy; **scl02** is the fallback. Latency is
fine either way:

| from | to mgmt-gw.fmt01 | to mgmt-gw.scl02 |
|---|---|---|
| pve01.sfo02 | 1.8 ms | 1.7 ms |
| pve02.scl04 | 2.9 ms | 1.2 ms |

Measured site-to-site RTT is 2.1–3.1 ms, far inside etcd's defaults.

When it is racked it becomes a full member and the witness retires. **Add
the new member first, then remove the witness** (four members briefly,
quorum 3, still tolerates one failure).

**Not pve01.scl04** for any member: same site as pve02.scl04, so one site
outage would take two of three members.

### Addressing

N is the site's management number (`10.N.0.0/16`): sfo02 1, fmt01 2,
scl02 5, scl04 6.

| what | IPv4 | IPv6 | routed where |
|---|---|---|---|
| fabric VLAN 203 `K8S-FABRIC` | `192.33.255.144/28` | `2620:11a:b000:203::/64` | connected on edges |
| — edge-gw.sfo02 / .fmt01 | `.145` / `.146` | `::1` / `::2` | |
| — nodes | `.150` up | `::150` up | |
| pods | `10.42.0.0/16` (k3s default), `/24` per node | `2620:11a:b000:a00::/56`, `/64` per node | v6: edges + mgmt-gws; v4: mgmt-gws only |
| public service VIPs | `192.33.255.128/28` | `2620:11a:b000:120::/64` | edges |
| internal service VIPs | `10.255.20.0/24` | `2620:11a:b00f:ff20::/64` | mgmt-gws |
| API VIP | `10.255.20.1` | `2620:11a:b00f:ff20::1` | mgmt-gws, name `api.k8s.sfmix.org` (internal) |
| mgmt leg `K8S-NODES` | `10.N.10.0/24` | `2620:11a:b00f:N10::/64` | connected on the site mgmt-gw |
| ClusterIP services | `10.43.0.0/16` (k3s default) | `fd00:43::/112` | not routed |

- **Pod IPv6 is public GUA** from the publicly routed `2620:11a:b000::/48`,
  inside the `/44` we already announce. Edges are stateless, so return
  traffic arriving at either edge just follows the node's `/64`. No NAT.
- **Pod IPv4 is private** and masqueraded by the node to its own fabric
  address on the way to the internet (flannel's default), so the mgmt-gws
  never translate it.
- **Public VIPs and pod `/64`s are tagged `no-export`** on the edges. The
  outside world keeps seeing only the `/24` and `/44`.

### Cluster DNS domain

`--cluster-domain=k8s.sfmix.org`, not `cluster.local`. Services resolve as
`<svc>.<ns>.svc.k8s.sfmix.org`.

- This must be set at cluster creation; changing it later is a rebuild.
- A minority of Helm charts and operators hardcode `cluster.local` and need
  patching per chart.
- For resolution from outside the cluster, the internal recursors forward
  `k8s.sfmix.org` to the CoreDNS service VIP. Forwarding rather than NS
  delegation, because it degrades more gracefully.

### Fabric leg: data plane, public

VLAN 203 is a new Exchange Fabric VLAN, stretched to every site with a node,
like VLANs 200 and 201. Both edges get `eth4.203`, as they have `eth4.10x`
for hosted networks today.

#### scl04's interim fabric path

pve02.scl04's FlexLOM is not cabled, and will not be for a while. Until it is,
scl04 reaches VLAN 203 through **mgmt-switch.scl04 over a 2x1G LAG**, which
trunks the fabric VLAN up to the site fabric. Functionally this is identical —
same stretched L2, same `host-gw` routes, same edge sessions — with three
consequences:

Observed 2026-11-23: the path already exists end to end. mgmt-switch.scl04 is
an **EX3400-48P** (Junos 23.4R2-S5.8). pve02.scl04's four 1G NICs are already
bonded into two LAGs — `ae0` (gige0/1) access on `SCL04-MGMT` as the mgmt leg,
and `ae1` (gige2/3) described as *"Trunk: pve02.scl04 bond1 frontend/WAN"*,
LACP-up with `periodic fast` and parked on VLAN `PARKING` (3999). On the host
these are `vmbr0` and `vmbr1`, the latter VLAN-aware with `bridge-vids 2-4094`.
The switch's uplink `xe-0/2/0` is already a 10G LR trunk to switch01.scl04,
carrying VLANs 200 and 106. So enabling the interim path is purely a matter of
adding VLAN 203 to `ae1` and `xe-0/2/0`.

- **2 Gbit aggregate, 1 Gbit per flow.** LACP hashes per flow, so any single
  image pull, etcd stream or participant-facing transfer tops out at 1 Gbit.
- **etcd shares the link with bulk egress.** This is the combination most
  likely to make the cluster flaky: a saturated LAG adds latency to etcd
  heartbeats (100 ms heartbeat, 1 s election), and scl04 is the compute-heavy
  site. Prioritise etcd and API traffic on the LAG, and watch
  `etcd_network_peer_round_trip_time_seconds` against link utilisation.
- **mgmt-switch.scl04 becomes a single point of failure for that node**, which
  now has both legs behind it. The failure is at least clean — both sessions
  drop, BFD withdraws in about a second, etcd falls to 2/3 — but the two legs
  are no longer independent, and the mgmt switches have no remote syslog
  today.

Note that public traffic now crosses a management switch, which the "never
across a mgmt-gw" principle does not forbid (that is about the small CPU
routers) but is against its spirit. Cabling the FlexLOM removes all of this
and is the first follow-up once parts and hands are available.

**A cheaper shortcut exists.** The EX3400's PIC 2 has four SFP+ ports with only
two populated (`xe-0/2/0` the 10G uplink, `ge-0/2/2` a 1G LX to mgmt-gw.scl04),
leaving `xe-0/2/1` and `xe-0/2/3` free, plus both 40G QSFP ports. pve02.scl04's
FlexLOM could therefore go straight into a spare SFP+ on this same switch — one
optic or DAC and an in-rack patch — instead of waiting for a cross-connect to
switch01.scl04. The uplink is already 10G, so this removes the per-flow cap and
the etcd contention without any new fibre run.

#### East-west: flannel host-gw

All nodes share one L2 segment, so k3s's built-in flannel in `host-gw` mode
installs a plain kernel route per remote node (`10.42.X.0/24 via <node>`,
same for IPv6). Node-to-node traffic goes switch to switch over the fabric,
never through a router. k3s node IP = the fabric address, so etcd and kubelet
traffic use the 10G path too. (Verify dual-stack `host-gw` on the k3s
version we pick.)

#### North-south: edges as hubs

- **Edges:** `bgp listen range` for `192.33.255.144/28` and
  `2620:11a:b000:203::/64` into peer-group `K8S`, `remote-as external`, BFD,
  session password. A new node needs no edge change.
- **Import:** public VIPs (`192.33.255.128/28 le 32`,
  `2620:11a:b000:120::/64 le 128`) and pod `/64`s
  (`2620:11a:b000:a00::/56 ge 64 le 64`) only, tagged `no-export`.
  Max-prefix. Nothing else; never IPv4 pod space.
- **Export to nodes:** `0.0.0.0/0` and `::/0` only, conditional on the edge
  having upstream routes (same `default-originate` + route-map as doc 011).
  Nodes' default route is therefore the fabric; they can ECMP across both
  edges.
- **Long-lived graceful restart works here as intended:** every node peers
  directly with both edges, so each edge compares all announcers of a VIP
  itself. A stale path is least preferred and loses to any healthy one.

Not needed now, but available: with `route-server-client` on the `K8S`
peer-group the edges could also hand pod routes between nodes (next hop
unchanged on the shared VLAN), replacing flannel's routes. We don't, to keep
east-west independent of the edges.

### Mgmt leg: internal only

#### Node ↔ its site's mgmt-gw

- mgmt-gw: `bgp listen range` for the site's `K8S-NODES` subnet into
  peer-group `K8S`, `remote-as external`, BFD.
- **Node announces:** internal VIPs, its pod IPv4 `/24`, its pod IPv6 `/64`
  (so internal clients reach pods directly and replies come back the same
  way).
- **Node receives nothing.** Internal destinations (`10.0.0.0/8`,
  `2620:11a:b00f::/48`) are static routes on the node via the mgmt-gw; the
  default stays on the fabric.
- **mgmt-gw import:** exactly those ranges at those lengths, max-prefix.

#### Between mgmt-gws: route-server hubs

Why BGP between mgmt-gws rather than redistributing into OSPF: OSPF has no
notion of "stale, least preferred", and a mgmt-gw's own BGP route
(distance 20) beats OSPF (110). A site whose node is dead but still held by
graceful restart would keep forwarding an anycast VIP into it, even with
healthy announcers elsewhere. In BGP, every mgmt-gw sees every announcer.

A full mesh grows with every site, so instead the core sites are hubs:

- **Hubs: mgmt-gw.sfo02 (AS 65101) and mgmt-gw.fmt01 (AS 65102)**, matching
  the fabric's dual-star core. Each has `bgp listen range 10.0.0.0/11`
  (spoke loopbacks `10.N.0.0`) into peer-group `MGMT-SPOKES`,
  `remote-as external`, `ebgp-multihop`, `update-source lo`,
  **`route-server-client`**, and an explicit session to the other hub.
- **Spokes: every other mgmt-gw lists only the two hub loopbacks.** Spoke
  config is identical at every site except its own ASN; a new site needs no
  hub change.
- `route-server-client` means hubs don't prepend their AS or change the next
  hop. A spoke learns `10.42.6.0/24 via 10.6.0.0` (scl04's loopback) and
  forwards along OSPF straight to scl04, not through the hub. Hubs carry
  control plane only.
- Sessions run between loopbacks, which OSPF reaches over VLAN 200 or the
  WireGuard mesh, so they survive either path failing.
- **Path choice at a mgmt-gw:** its own site's node (AS path `65200+N`) beats
  a remote one (`65100+M 65200+M`). Among remote paths BGP falls through to
  IGP cost to the next hop, so it picks the closest site.
  `bestpath as-path multipath-relax` + `maximum-paths` gives ECMP instead.
- One hub down: the other carries everything. Both down: each site keeps its
  local node's routes; cross-site internal reachability to k8s is lost (the
  fabric leg and public services are unaffected).
- Overlapping listen ranges on a hub (`10.0.0.0/11` for spokes and its own
  `10.N.10.0/24` for local nodes): FRR should pick the longest match. Verify,
  or give spoke loopbacks their own range.

These mgmt-gw BGP sessions use the doc 011 ASNs (`65100 + N`) and live in
the same BGP instance, but do not depend on doc 011 being built.

### The node is an originator, never a transit router

Each node is dual-homed between the DFZ and the management network, which is
the classic shape of an accidental bridge. Two independent defences:

- **In BGP:** the node only ever redistributes connected routes from `vip0`
  and `cni0`. Nothing learned on one leg can be exported to the other. Enforce
  it twice — outbound prefix-lists matching only the owned ranges per
  neighbor, independent of the `redistribute` route-map.
- **In the forwarding plane:** `ip_forward` is necessarily on for pods, so a
  packet arriving on the fabric leg destined for `10.0.0.0/8` would otherwise
  be forwarded out the mgmt leg. An explicit nftables `forward` drop for
  fabric↔mgmt-leg transit, separate from the pod policy rules, is required.
  Do not pin `ip_forward` in sysctl; it is dockerd-owned.

`rp_filter` strict will misfire given ECMP across two edges and anycast VIPs;
use loose or off and let the forward policy do the work.

### QoS and MTU

#### MTU: provision for jumbo, run 1500

The two legs have different MTU characteristics, which resolves most of the
tension:

- **Fabric leg (VLAN 203)** carries pod east-west, etcd and kubelet, and rides
  the exchange fabric only. A stretched L2 VLAN has no WireGuard fallback: if
  the fabric partitions, VLAN 203 partitions. Its MTU is therefore stable, and
  it is the path that would benefit from jumbo frames.
- **Mgmt leg** carries internal VIPs, pod IPv4 to internal destinations,
  scraping and admin, and is the only path that can fail over to the mgmt-gw
  WireGuard mesh. Low volume, mostly short-lived HTTP.

So the traffic that wants jumbo never touches the tunnel, and the traffic that
touches the tunnel does not want jumbo.

**Decision: provision the underlay for jumbo** (switch ports at 9216 on
VLAN 203 and the scl04 LAG) **but run node interfaces and pod MTU at 1500.**
Raising it later is then a host config change rather than a re-cabling
conversation. Revisit once pve02.scl04's FlexLOM is cabled.

**ICMP PTB must be permitted** in the node nftables rules and the mgmt-gw
firewall zones. This is a hard requirement, not a nicety:

- TCP MSS is fixed in the SYN/SYN-ACK and never renegotiated, so MSS clamping
  on the tunnel only helps flows whose SYN crossed the tunnel. A flow
  established over the fabric and then failed over mid-stream was never
  clamped, and clamping cannot fix it retroactively.
- Such flows depend entirely on PMTUD: ICMP "fragmentation needed" or
  ICMPv6 Packet Too Big shrinking the sender's cached path MTU for that
  destination.
- WireGuard's MTU is ~1420, so this applies at 1500 just as at 9000. Running
  1500 makes the mid-flow step smaller, not absent.

#### DSCP marking

| traffic | mark | why |
|---|---|---|
| etcd peer and client (2380/2379) | CS6 | infrastructure control, same tier as routing |
| BGP and BFD from FRR | CS6/CS7 | already marked by FRR |
| API server (6443) | AF31 | latency-sensitive, not control |
| image pulls, pod egress, bulk | CS0 | should yield |

etcd cannot set socket DSCP itself, so mark it with an nftables output rule
(`ip dscp set cs6` on tcp dport 2379/2380) rather than looking for a k3s flag.

**Marking without a scheduler is decoration.** The only congestion point in
this design is the scl04 2x1G LAG, so that is where the work is:

- **mgmt-switch.scl04 (Junos):** an L2 trunk takes the `ieee-802.1` classifier
  by default, which reads PCP, not DSCP. A Linux host sending on a VLAN
  subinterface emits **PCP 0 regardless of DSCP** — 802.1p comes from
  `skb->priority` via the VLAN interface's `egress-qos-map`, which is not
  populated from DSCP. The default path therefore puts CS6 etcd traffic in the
  same best-effort class as bulk image pulls. Configure a DSCP classifier on
  the `ae` interface **and** an explicit scheduler-map giving the control class
  a real share. Optionally also set `egress-qos-map` on the nodes' VLAN
  interfaces so PCP mirrors DSCP.
  **Confirmed on the box 2026-11-23:** `show class-of-service interface ae1`
  reports `Scheduler map: <default>` and classifier `ieee8021p-default` on
  `ae1.0`, with 12 usable queues and 8 in use (best-effort, expedited-
  forwarding, assured-forwarding, network-control plus multicast variants).
  DSCP is ignored on this path today exactly as described.
- The default Junos scheduler is best-effort heavy: expedited- and
  assured-forwarding classes typically get no guaranteed share, so marking into
  them *without* a scheduler-map can be worse than leaving traffic
  best-effort.
- **Arista fabric:** interfaces default to trusted, and that path is 10G and
  uncongested, so no scheduling work is needed. The concern there is
  preservation, not trust — the 7280CR3 VXLAN decap bug zeroed DSCP and ECN
  until the fleet-wide fix in `e460473`. Any newly added CR3 needs the same
  config or marking disappears at that site.

Verify on the device rather than trusting platform defaults:
`show class-of-service interface ae0`, `show class-of-service classifier`, and
`show interfaces queue ae0` under load, to see which queue etcd lands in and
whether anything is tail-dropping.

### Failure detection

The aim behind "long hold times" is that routes should survive a BGP speaker
or agent restart while the node keeps forwarding. A long hold timer cannot
tell that from a dead node: for an anycast VIP, a dead node keeps attracting
its share of traffic into a blackhole for the whole hold time. Instead:

| mechanism | handles | effect |
|---|---|---|
| **BFD** (FRR `bfdd`, e.g. 300 ms × 3) | node or link dead | withdrawn in about a second |
| **Graceful restart**, restart time ~120 s | FRR restart, datapath still forwarding | routes kept while FRR comes back |
| **Long-lived graceful restart** (RFC 9494), stale time hours | longer control-plane outages | routes kept but least preferred; healthy announcers win, single-announcer prefixes (a node's pod `/64`) keep working |

FRR on the nodes supports all three as the restarting side. To verify:
whether VyOS 1.4 (FRR 9.1.1 underneath, LLGR since FRR 8.2) exposes LLGR in
its configuration, and how FRR treats BFD-down during GR
(`bfd check-control-plane-failure`).

#### Announce only when healthy

- **One dummy interface, `vip0`, per node.** Anything the node should announce
  is an address there; FRR `redistribute connected` with a route-map matching
  the VIP ranges. Pods' `/24` and `/64` come the same way from flannel's
  `cni0` bridge. FRR needs no Kubernetes integration.
- **API VIP:** a systemd timer on each server node checks
  `https://127.0.0.1:6443/readyz` and adds or removes `10.255.20.1` /
  `2620:11a:b00f:ff20::1` on `vip0`. It does not depend on Kubernetes being
  healthy to withdraw. The witness never announces it.
- **Service VIPs:** kube-vip-cloud-provider assigns `LoadBalancer` IPs from
  the two VIP pools; something puts each IP on `vip0` only on nodes with a
  ready local endpoint (`externalTrafficPolicy: Local`). Candidates:
  kube-vip's routing-table mode (writes VIPs into a kernel table; FRR
  `ip import-table`, verify IPv6) or a ~100-line controller. Open item.
- **Planned maintenance:** cordon, drain, then graceful-shutdown community
  (RFC 8326) or shut the sessions, then reboot.

The same `vip0` + FRR pattern is not Kubernetes-specific. The registry and
OpenBao VMs should use it too, for anycast service addresses with BFD
withdrawal.

### Node software

- **k3s with embedded etcd**, three servers. Witness:
  `--disable-apiserver --disable-controller-manager --disable-scheduler`.
  `--flannel-backend=host-gw`, dual-stack `--cluster-cidr` and
  `--service-cidr` from the table, `--cluster-domain=k8s.sfmix.org`,
  `--flannel-ipv6-masq` off (pods are public), servicelb and traefik
  disabled, k3s's built-in network policy controller kept. `--tls-san` for the
  API VIP and `api.k8s.sfmix.org`. Per-node IPv6 sizing goes through
  `--kube-controller-manager-arg=node-cidr-mask-size-ipv6=64`.
- **FRR** from Debian packages, managed by Ansible (`sfmix_server` plus a k8s
  role), `frr defaults datacenter`. Sketch for k8s01.sfo02 (not tested):

```
router bgp 65201
 bgp router-id 192.33.255.150
 bgp graceful-restart
 bgp long-lived-graceful-restart stale-time 21600
 neighbor EDGES peer-group
 neighbor EDGES remote-as 12276
 neighbor EDGES bfd
 neighbor 192.33.255.145 peer-group EDGES
 neighbor 192.33.255.146 peer-group EDGES
 neighbor 2620:11a:b000:203::1 peer-group EDGES
 neighbor 2620:11a:b000:203::2 peer-group EDGES
 neighbor MGMT peer-group
 neighbor MGMT remote-as 65101
 neighbor MGMT bfd
 neighbor 10.1.10.1 peer-group MGMT
 neighbor 2620:11a:b00f:110::1 peer-group MGMT
 address-family ipv4 unicast
  redistribute connected route-map ANNOUNCE   ! vip0 + cni0 only
  neighbor EDGES route-map EDGES-OUT out      ! public VIPs
  neighbor EDGES route-map DEFAULT-ONLY in
  neighbor MGMT route-map MGMT-OUT out        ! internal VIPs, pod /24
  neighbor MGMT route-map DENY-ALL in
 address-family ipv6 unicast
  (same shape; pod /64 to both EDGES and MGMT)
```

**Validated 2026-11-23** on a throwaway single-node VM (`k8s-scratch`, VM 130
on pve02.scl04, mgmt leg only) running **k3s v1.37.2+k3s1**:

- **Dual-stack `host-gw` works.** The node was allocated
  `["10.42.0.0/24","2620:11a:b000:a00::/64"]` and `cni0` came up with both
  `10.42.0.1/24` and `2620:11a:b000:a00::1/64`. The log shows
  `Starting flannel with backend host-gw` and that it selected the node's IPv6
  address. Cross-node route programming still needs a second node to prove.
- **`--cluster-domain=k8s.sfmix.org` works end to end.** A pod's `resolv.conf`
  search list is `default.svc.k8s.sfmix.org svc.k8s.sfmix.org k8s.sfmix.org
  sfmix.org`, and `kubernetes.default.svc.k8s.sfmix.org` resolves to the
  ClusterIP.
- **IPv6 pod egress is not masqueraded** — no flannel v6 POSTROUTING
  masquerade, only kube-proxy's service rules — matching the public-pod
  design. IPv4 is masqueraded as intended. `FLANNEL_MTU=1500`.
- traefik and servicelb are absent as requested. `local-path-provisioner` and
  `metrics-server` remain as k3s defaults and should be reviewed before
  production.
- **Gotcha: `--node-cidr-mask-size-ipv6` is not a k3s server flag.** Passing it
  directly makes k3s exit with `flag provided but not defined`; it must go
  through `--kube-controller-manager-arg`.

- **Why not Calico or Cilium:** both can route natively without an overlay
  (Calico is BIRD underneath), but each brings its own control plane, CRDs
  and BGP configuration model on top. With the stretched VLAN, flannel
  `host-gw` already gives overlay-free pod routing, and FRR is the same
  routing stack the mgmt-gws and edges run — which matters when the operators
  are volunteer network engineers.

### Security

- **Nodes are on the internet** (public fabric addresses). Host nftables:
  BGP and BFD only from the edges and the mgmt-gw; etcd, kubelet and API
  ports only from the fabric `/28` and the `K8S-NODES` / admin ranges; plus
  the fabric↔mgmt forward drop above.
- **Pods have public IPv6.** Default-deny `NetworkPolicy` per namespace, and
  a host forward rule that only lets new inbound connections reach service
  VIP ports.
- **mgmt-gw:** `K8S-NODES` in its own interface group. Allowed from k8s:
  DNS on the mgmt-gw, NetBox API, Loki, Prometheus as needed. Admin and
  metrics to k8s: allowed. Internet egress does not go this way at all.
- **API authentication** via OIDC against `login.sfmix.org`, giving volunteers
  SSO'd `kubectl` with real RBAC, on the same group mapping as OpenBao.

### Failure behavior

| failure | etcd | API (internal) | public services |
|---|---|---|---|
| none | 3/3 | VIP → nearest healthy DL360 node | nearest healthy announcer, either edge |
| one DL360 node or its site down | 2/3; writes wait on fmt01 disk until the Optane is in | other DL360 node | BFD withdraws in ~1 s; other node serves |
| fmt01 witness down | 2/3, fast | unaffected | unaffected |
| two members down | no quorum; no changes possible | down | running pods keep serving |
| one edge-gw down | unaffected | unaffected | the other edge |
| one mgmt-gw hub down | unaffected | the other hub carries routes | unaffected |
| a spoke mgmt-gw down | unaffected (etcd rides the fabric) | that site's node unreachable internally | unaffected |
| mgmt-switch.scl04 down (interim path) | 2/3 | scl04 node unreachable on both legs | BFD withdraws in ~1 s; sfo02 node serves |
| FRR restart on a node | unaffected | GR holds routes | GR holds routes |
| OpenBao sealed or down | unaffected | unaffected | running workloads keep their delivered secrets |

## Rollout

Platform first only where it gates the cluster. Of the S2 layers, DNS already
exists and the registry is the only true prerequisite; SPIRE and OpenBao are
parallel work, because swapping Ansible-rendered Secrets for SPIFFE-authenticated
OpenBao is a producer change, not an architecture change.

1. NetBox: VLAN 203, prefixes above, `K8S-NODES` per site, ASNs
   65201/65202/65206 (65200 + N).
2. **Registry**: Garage-backed Distribution, one frontend per core site,
   promotion job from ghcr.io, mirrors of third-party images.
3. Fabric: VLAN 203 to both edge ports and the node hosts' fabric ports. At
   scl04, trunk VLAN 203 to mgmt-switch.scl04 and build the 2x1G LAG to
   pve02.scl04; confirm MTU end to end. Cabling the FlexLOM is a follow-up,
   not a blocker.
4. Witness: k8s01.fmt01 on pve01-fmt, out of pvesr. Optane when bought.
5. VMs on pve01.sfo02 and pve02.scl04; FRR; k3s with flannel `host-gw`.
   Verify pod-to-pod across sites over VLAN 203.
6. Edges: `eth4.203`, `K8S` listen range, filters, conditional defaults.
   `commit-confirm`. Nodes take their default from the edges.
7. mgmt-gws: `K8S-NODES` VLAN and `K8S` listen range at the three sites;
   hub/spoke sessions (hubs first). `commit-confirm` each.
8. API VIP health check; test BFD pull, FRR restart, node drain against the
   failure table. Verify the fabric↔mgmt forward drop.
9. Service VIPs (kube-vip or controller), firewall zone, first workload —
   stateless web services only (portal, lg-http, obscreen).
10. SPIRE: trust domain, internal CA, NetBox reconciler, `x509pop` for VMs,
    PSAT and controller-manager for pods.
11. OpenBao: three VMs, auto-unseal, OIDC against login.sfmix.org, two audit
    devices shipping to Loki, policies rendered from the service listing.
12. Move workloads from Ansible-rendered Secrets to JWT-SVID auth; retire
    static credentials.
13. Third DL360 racked: add member, remove witness.

## Open items

- How service VIPs get onto `vip0` (kube-vip routing-table mode vs a small
  controller).
- VyOS 1.4: LLGR configuration, BFD control-plane-failure handling,
  overlapping listen ranges.
- Edge forwarding headroom for k8s egress (the edges are software routers
  too, but they already carry all transit).
- RAM upgrade for both DL360s; Optane for pve01-fmt.
- Whether WireGuard copies inner DSCP to the outer header on the mgmt-gw mesh.
- Whether to pin etcd to the mgmt leg at scl04 while the interim path is in
  use, at the cost of node homogeneity.
- Cabling pve02.scl04's FlexLOM, which retires the interim path.
- Whether the deployed OpenBao has a native static seal, and its exact OIDC
  redirect-URI paths.
- Which charts in the first workload set hardcode `cluster.local`.
- Garage capacity and replication factor once registry blobs share the
  cluster with Thanos (doc 012).
