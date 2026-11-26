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
- **The management domain is the primary path for everything internal.**
  etcd, kubelet, pod-to-pod, internal VIPs and pod internet egress all route
  via the site mgmt-gw. This trades throughput for reliability deliberately —
  see "Why the management domain is the primary path".
- **The fabric carries public service traffic only.** VLAN 203 gives nodes at
  sites without an edge router an address-efficient path into AS 12276 space.
  Nothing internal depends on it.
- **Same pattern everywhere:** the two core sites (sfo02, fmt01) are hubs that
  accept BGP clients from a `bgp listen range`; every client lists just the
  two hubs. Adding a node or a site never touches existing config.
- **One private ASN per site.** No iBGP anywhere.
- **Plain Linux routing on the nodes:** FRR does all routing; the CNI does
  only local bridging and IPAM. No overlay, no stretched-L2 dependency, no
  CNI-specific BGP layer.

## Why the management domain is the primary path

Decided 2026-11-26. Reliability is the paramount property, and the mgmt-gw is
the only device at each site with **two independent underlays**: the inband
path (OSPF over VLAN 200, across the exchange fabric) and the OOB WireGuard
mesh over commodity transit. Those fail independently — an SFMIX fabric fault
and an internet fault are not the same event — so routing internal traffic
through the management domain means a partition needs both down at once.

That matters more than it first appears, because **etcd cannot split-brain**:
Raft makes the minority side unavailable, never divergent. The residual
hazards are a partitioned node's pods being rescheduled while the originals
keep running, and anycast VIP divergence. Both get rarer in direct proportion
to how rare partitions are — so a dual-underlay path beats a fast single one.

A stretched L2 has exactly one path. If the stretch breaks the segment is
simply gone, and `host-gw`'s kernel routes do not withdraw when the L2
disappears; they blackhole rather than reroute. Relying on L2 stretching also
does not scale. The exchange is built on L3 routing and the cluster's
internals should be too.

**The accepted cost: the mgmt-gws are all-CPU and top out around 200 Mbit.**
Every internal flow, including cross-site pod-to-pod, passes through one. That
is acceptable for this workload set — stateless web services, exporters and
bots — and the ceiling is a known, documented limit rather than a surprise.

**The future fast path.** When it earns its complexity, nodes can route L3 over
the fabric directly and prefer that path, falling back to the management
domain when it is unavailable. That is additive — a second BGP relationship
and a route preference — not a rebuild, and deliberately not day-one work.

**A degraded path is not a partition, and can be worse.** When the inband path
drops and traffic shifts to a tunnel, etcd keeps exchanging heartbeats over a
far slower link. If that tunnel congests, latency can cross the election
timeout and the cluster flaps leaders instead of failing cleanly. Mark etcd and
API traffic and schedule it ahead of bulk at every congestion point — the scl04
LAG and the tunnel path both qualify. See "QoS and MTU".

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

**Never — circular dependency.** The moment the exchange's control plane
depends on a cluster whose control plane depends on the exchange network, a
routine partition becomes an unrecoverable one.

- Route servers (`rs-linux`, `rs-openbsd`)
- `ns1` authoritative DNS
- RPKI validators
- SPIRE server, OpenBao, the container registry
- `backup01.scl04` and the Garage nodes

**Never — observability rule.** *Whatever tells you the cluster is broken must
not run on the cluster.* That covers Prometheus and Alertmanager (the alerting
path) and Loki (where you look to diagnose a break). The Thanos query and store
layer is the historical read path and could move, for little gain. Independent
of the rule, metrics.sfo02 is a memory-hungry, carefully tuned workload with a
30d local TSDB, which would become a node-pinned local-path volume on a single
consumer SSD.

**Not yet, but no structural objection.** Teleport. It is stateful, and losing
it during a cluster incident costs a convenience rather than a recovery path,
because Ansible reaches hosts over direct SSH and ProxyJump rather than through
it. Sequence it late.

Note that migrating a VM into the cluster *on the same hypervisor* does not
free memory there — it reclaims a kernel and some slack and improves
bin-packing. The consolidation win is operational, not capacity.

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
| k8s01.sfo02 | pve01.sfo02 (DL360) | server + workloads | 32–48 | balance of the node (16 GiB today) | 200 GiB on `tank-vms` |
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

- **RAM is the constraint, not CPU.** The node VM gets whatever the host has
  left over; there is no target figure. Measured on pve01.sfo02 2026-11-23:
  31 GiB total, less 3.1 GiB ARC max, ~2 GiB for Proxmox and 6 GiB of existing
  guests (metrics01 4 GiB, teleport 2 GiB), leaves ~20 GiB assignable — so
  16 GiB for the node with slack for spikes. pve02.scl04 is empty and can take
  24 GiB. More DDR4 RDIMMs is the cheapest upgrade and the only real fix.
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
| ClusterIP services | `10.43.0.0/16` (k3s default) | `2620:11a:b000:43::/112` | not routed |

- **Pod IPv6 is public GUA** from the publicly routed `2620:11a:b000::/48`,
  inside the `/44` we already announce. Edges are stateless, so return
  traffic arriving at either edge just follows the node's `/64`. No NAT.
- **Pod IPv4 is private** and masqueraded by the node to its own fabric
  address on the way to the internet (flannel's default), so the mgmt-gws
  never translate it.
- **ClusterIP IPv6 comes from our own GUA, not a ULA.** These addresses never
  appear on the wire outside a node — kube-proxy rewrites them — so ULA versus
  GUA makes no reachability difference, and taking a slice of
  `2620:11a:b000::/48` keeps every SFMIX address identifiable on sight instead
  of leaving one unexplained `fd00::` range in the logs. Kubernetes caps an
  IPv6 service CIDR at /108, so /112 is comfortably inside the limit. The edge
  import filters accept only the fabric, VIP and pod ranges, so a leaked
  ClusterIP would not be carried anywhere regardless.
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
routers) but is against its spirit. **Treat 2x1G as the design point, not a stopgap.** scl04 is roughly a two-hour
drive and the optics are not on hand, so the cluster must work properly over
this path for the foreseeable future. Size and test accordingly.

Recorded for whenever a trip and the hardware coincide: the EX3400's PIC 2 has
four SFP+ ports with only two populated (`xe-0/2/0` the 10G uplink, `ge-0/2/2`
a 1G LX to mgmt-gw.scl04), leaving `xe-0/2/1` and `xe-0/2/3` free, plus both
40G QSFP ports. pve02.scl04's FlexLOM could patch straight into a spare SFP+
on this same switch rather than waiting for a cross-connect to switch01.scl04,
which would remove the per-flow cap, the etcd contention and the shared failure
domain in one step.

#### East-west does not ride the fabric

**Superseded 2026-11-26.** East-west — etcd, kubelet and pod-to-pod — routes
through the management domain, not this VLAN. The fabric leg exists so that a
node at a site without an edge router can reach AS 12276 space efficiently; it
carries public service traffic and nothing internal.

This removes the stretched-L2 dependency entirely. `host-gw` required all nodes
to share one segment, and was validated working on 2026-11-23 (see the bootstrap
runbook) before the architecture changed — those findings are kept because the
`--flannel-iface` lesson still applies to any flannel deployment, but `host-gw`
is no longer the chosen path.

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

### Mgmt leg: internal everything

#### Node ↔ its site's mgmt-gw

- mgmt-gw: `bgp listen range` for the site's `K8S-NODES` subnet into
  peer-group `K8S`, `remote-as external`, BFD.
- **Node announces:** internal VIPs, its pod IPv4 `/24`, its pod IPv6 `/64`.
  Since 2026-11-26 these are also how **east-west** works: a node reaches
  another node's pods by the route its mgmt-gw learned, not over a shared
  segment. Internal clients reach pods directly and replies return the same
  way.
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
  `--flannel-backend=none` with the stock `bridge` + `host-local` CNI plugins
  doing only local bridging and IPAM (FRR advertises the resulting `cni0`
  connected route), dual-stack `--cluster-cidr` and
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
  and BGP configuration model on top. Here FRR already does all the routing
  and the CNI does nothing clever — `bridge` + `host-local` allocate from the
  node's podCIDR onto `cni0` and stop there. FRR is the same routing stack the
  mgmt-gws and edges run, which matters when the operators are volunteer
  network engineers. That is *more* in the plain-Linux spirit than flannel
  was, not less.

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
| a spoke mgmt-gw down | that site's member unreachable; 2/3 remains | that site's node unreachable | unaffected (fabric is independent) |
| fabric (VLAN 200/203) down, tunnels up | degraded: control plane rides tunnels, needs DSCP priority | works, slowly | public VIP path down |
| mgmt-switch.scl04 down (interim path) | 2/3 | scl04 node unreachable on both legs | BFD withdraws in ~1 s; sfo02 node serves |
| FRR restart on a node | unaffected | GR holds routes | GR holds routes |
| OpenBao sealed or down | unaffected | unaffected | running workloads keep their delivered secrets |

## Bootstrap runbook

> **Historical record, partly superseded.** This section documents the
> 2026-11-23 bring-up as it actually happened, including the `host-gw`
> validation. The architecture changed on 2026-11-26: east-west now routes
> through the management domain, so a rebuild uses `--flannel-backend=none`
> with `bridge` + `host-local`, and `--node-ip` on the **mgmt** leg rather
> than the fabric. The `--flannel-iface` and witness-taint lessons below still
> apply. Steps 1 and 2 (trunk ports, layer-2 proof) are unaffected.

State as of 2026-11-23. VLAN 203 and `vxlan vlan 203 vni 203` are configured
and verified on 14 of 15 peering switches; `switch01.sjc01` does not resolve in
DNS and appears decommissioned after the sjc01 cabinet migration to
switch03/04. Both node VMs exist and boot. What remains before the cluster can
form is three trunk ports.

### 0. What exists

| | |
|---|---|
| k8s01.sfo02 | VM 120 on pve01.sfo02 — 16 GiB, 16 vCPU, 200 GiB `tank-vms` |
| | `eth0` 10.1.1.41/24 (mgmt, vmbr0); `eth1` 192.33.255.150/28 + `2620:11a:b000:203::150/64` (vmbr2 tag 203) |
| k8s01.scl04 | VM 121 on pve02.scl04 — 24 GiB, 16 vCPU, 200 GiB `tank-vms` |
| | `eth0` 10.6.1.41/24 (mgmt, vmbr0); `eth1` 192.33.255.151/28 + `2620:11a:b000:203::151/64` (vmbr1 tag 203) |
| k8s01.fmt01 | VM 122 on pve01-fmt — 4 GiB, 2 vCPU, 32 GiB `local-zfs`, etcd only |
| | `eth0` 10.2.1.41/24 (mgmt, vmbr0); `eth1` 192.33.255.152/28 + `2620:11a:b000:203::152/64` (vmbr2 tag 203) |

The k8s-scratch VM (130) was destroyed on 2026-11-23 once k3s v1.37.2+k3s1 had
been validated on it.

Both hypervisors' fabric bridges are already VLAN-aware (`bridge-vids
2-4094`), so the tag rides on the VM NIC and no host-side VLAN interface is
needed. pve01.sfo02 reaches the fabric over bond2 (FlexLOM, two 10G legs,
active-backup: `sfpp0` to switch02.sfo02 Et15/4 and `sfpp1` to switch01.sfo02
Et33). pve02.scl04 reaches it over bond1/ae1, the 2x1G LAG to
mgmt-switch.scl04.

Until the edges exist, each node's default route stays on the mgmt leg. That
is a deliberate deviation from the steady-state design, where the default
comes from the edges over the fabric.

### 1. Trunk ports — done 2026-11-23

Applied via EOS `configure session` with `commit timer 00:05:00`, verified,
then confirmed. Resulting state:

| switch | port | allowed VLANs |
|---|---|---|
| switch01.sfo02 | Ethernet33 | `203` |
| switch02.sfo02 | Ethernet15/4 | `203` |
| switch01.scl04 | Ethernet9/1 | `106,200,203` |
| switch01.fmt01 | Ethernet47 | `100-101,203,997-998` |

The commands were:

    ! switch01.sfo02
    interface Ethernet33
       switchport trunk allowed vlan 203

    ! switch02.sfo02
    interface Ethernet15/4
       switchport trunk allowed vlan 203

    ! switch01.scl04 -- note "add": this port already carries 106,200
    interface Ethernet9/1
       switchport trunk allowed vlan add 203

**The `add` on switch01.scl04 Et9/1 is not optional.** That port is the trunk
to mgmt-switch.scl04 and currently allows `106,200`; writing `switchport trunk
allowed vlan 203` without `add` would drop both and break the scl04 mgmt
peering trunk. The two sfo02 ports are `allowed vlan none` today, so there is
nothing to preserve.

switch01.fmt01 Et47 (`pve01.fmt01-Trunk`, the pve01-fmt `eno4` trunk) took
`switchport trunk allowed vlan add 203` for the same reason.

The mgmt-switch.scl04 side was already done — `K8S-FABRIC` is a member of `ae1`
and `xe-0/2/0`.

Note that pve01-fmt's `vmbr2` is **not** VLAN-aware (it uses explicit
`vmbr2.100` / `vmbr2.101` subinterfaces), unlike the two DL360s. Proxmox still
honours a `tag=` on the VM NIC there by creating the dynamic bridge itself, so
no host change was needed — but do not assume the bridges are uniform across
hypervisors.

Both pve01.sfo02 ports carry `switchport port-security mac-address maximum 5`.
That is ample: the node VM presents one MAC on VLAN 203, and pods never appear
as MACs because `host-gw` routes rather than bridges them.

### 2. Prove layer 2 before touching Kubernetes — verified 2026-11-23

Measured between the node fabric addresses: sfo02 <-> scl04 1.6 ms v4 and
1.5-3.1 ms v6; fmt01 <-> sfo02 1.5-3.0 ms; fmt01 <-> scl04 2.3-4.6 ms. Full
1500-byte frames pass with DF set, and 1600-byte frames correctly fail, so the
path MTU is genuinely 1500 rather than something larger that happens to work.

MAC learning confirms the path: mgmt-switch.scl04 shows the scl04 node on
`ae1.0` and the sfo02 node on `xe-0/2/0.0` in `K8S-FABRIC`.

ARP and ND take a moment to settle after the trunk ports are committed; a ping
that fails immediately afterwards is not necessarily a misconfiguration.

From k8s01.sfo02:

    ping -c3 192.33.255.151
    ping -c3 2620:11a:b000:203::151
    ping -c3 -M do -s 1472 192.33.255.151   # full 1500-byte path, no fragmentation

If the 1472-byte ping fails while small ones succeed, the VXLAN underlay is
not carrying the full frame — fix that before going further, because it will
later look like an application bug.

### 3. First server, on k8s01.sfo02

    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server \
      --cluster-init \
      --flannel-backend=host-gw \
      --flannel-iface=eth1 \
      --cluster-cidr=10.42.0.0/16,2620:11a:b000:a00::/56 \
      --service-cidr=10.43.0.0/16,2620:11a:b000:43::/112 \
      --cluster-domain=k8s.sfmix.org \
      --node-ip=192.33.255.150,2620:11a:b000:203::150 \
      --kube-controller-manager-arg=node-cidr-mask-size-ipv6=64 \
      --disable=traefik --disable=servicelb \
      --tls-san=api.k8s.sfmix.org --tls-san=10.255.20.1 \
      --write-kubeconfig-mode=0644" sh -

`--node-ip` is the fabric address, so etcd and kubelet use the fabric rather
than the mgmt leg. The service and cluster CIDRs cannot be changed after this
command without rebuilding the cluster.

### 4. Join the other two as servers

With the fmt01 witness built, all three nodes are servers and etcd reaches
three members. Take the token from
`/var/lib/rancher/k3s/server/node-token` on k8s01.sfo02.

On **k8s01.scl04** (server with workloads):

    curl -sfL https://get.k3s.io | K3S_TOKEN=<token> INSTALL_K3S_EXEC="server \
      --server https://192.33.255.150:6443 \
      --flannel-backend=host-gw \
      --flannel-iface=eth1 \
      --cluster-domain=k8s.sfmix.org \
      --node-ip=192.33.255.151,2620:11a:b000:203::151 \
      --disable=traefik --disable=servicelb \
      --write-kubeconfig-mode=0644" sh -

On **k8s01.fmt01** (etcd only, no workloads):

    curl -sfL https://get.k3s.io | K3S_TOKEN=<token> INSTALL_K3S_EXEC="server \
      --server https://192.33.255.150:6443 \
      --disable-apiserver --disable-controller-manager --disable-scheduler \
      --flannel-backend=host-gw \
      --flannel-iface=eth1 \
      --node-taint node-role.kubernetes.io/etcd=true:NoExecute \
      --cluster-domain=k8s.sfmix.org \
      --node-ip=192.33.255.152,2620:11a:b000:203::152 \
      --disable=traefik --disable=servicelb" sh -

**Do not stop at two servers.** A two-member etcd has a quorum of two, so
*either* node failing stops the cluster — strictly worse than the single member
you started with. Joining goes 1 -> 2 -> 3, so pass through two quickly and do
not leave the cluster sitting there.

**The fmt01 member must stay out of both pvesr and vzdump.** VM 122 has no
replication job, but the FMT01-01 cluster runs a daily `vzdump` job with
`all 1` in **snapshot mode**, which would have included it automatically and
frozen the guest filesystem — stalling etcd — every night. VM 122 was added to
that job's `exclude` list on 2026-11-23. Any future etcd member on that cluster
needs the same treatment. Back etcd up with k3s `etcd-snapshot` to
backup01.scl04 instead, per doc 013.

Remember that pve01-fmt's pool is the slow one (p99 fsync 231 ms). While both
DL360 members are healthy and one of them leads, this does not matter; it
becomes visible the moment a DL360 is down or fmt01 wins an election. The
Optane P1600X for its empty M.2 slot is still unbought.

### 4a. Two k3s settings that are not optional

Both were found the hard way during the 2026-11-23 bring-up.

**`--flannel-iface=eth1`.** `--node-ip` sets the *Kubernetes* node address, but
flannel selects its own interface independently, defaulting to whichever holds
the default route. Until the edges exist that is the **mgmt leg**, so flannel
annotated every node with its mgmt address and a **link-local** IPv6:

    k8s01-sfo02  10.1.1.41  fe80::be24:11ff:fe9e:e57b
    k8s01-scl04  10.6.1.41  fe80::be24:11ff:fee9:beee
    k8s01-fmt01  10.2.1.41  fe80::be24:11ff:feb1:1b17

`host-gw` then installed **no** cross-node routes at all, because each node's
advertised next hop sat in a different per-site subnet and was not on-link, and
the IPv6 next hops were link-local and useless. Pinning the fabric leg fixes it
immediately:

    k8s01-sfo02  192.33.255.150  2620:11a:b000:203::150
    k8s01-scl04  192.33.255.151  2620:11a:b000:203::151
    k8s01-fmt01  192.33.255.152  2620:11a:b000:203::152

Note this stays necessary even once the edges supply the default route over the
fabric. Relying on the default-route interface to pick the right leg is exactly
the kind of implicit coupling that breaks silently later, so pin it explicitly.

**The witness needs a taint.** `--disable-apiserver
--disable-controller-manager --disable-scheduler` stops the *control plane*
components but does **not** stop the node accepting pods — kubelet still
registers it as schedulable, and during bring-up workloads landed on it. It is
a 4 GiB, 2 vCPU VM on the slow QVO pool, so that must not happen:

    node-taint: node-role.kubernetes.io/etcd=true:NoExecute

Gotcha: `node-taint` in `/etc/rancher/k3s/config.yaml` is applied at node
**registration** only. Restarting k3s on an already-registered node does not
apply it; use `kubectl taint` once for the running node and keep it in the
config file so a rebuild inherits it.

Both settings live in `/etc/rancher/k3s/config.yaml` on each node, with a
comment explaining why.

### 5. Verify what a single node could not

    k3s kubectl get nodes -o wide
    k3s kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.podCIDRs}{"\n"}{end}'

Expect non-overlapping `/24` and `/64` per node. Then on each node confirm
`host-gw` installed a route to the *other* node's pod ranges with the other
node's fabric address as next hop:

    ip route | grep 10.42
    ip -6 route | grep 2620:11a:b000:a00

Then the real test — a pod on each node, talking both families:

    k3s kubectl create deployment netcheck --image=busybox:1.36 --replicas=2 \
      -- sh -c 'sleep 86400'
    k3s kubectl get pods -o wide            # confirm one pod per node
    k3s kubectl exec <pod-on-sfo02> -- ping -c3 <pod-ip-v4-on-scl04>
    k3s kubectl exec <pod-on-sfo02> -- ping -c3 <pod-ip-v6-on-scl04>

This is the open item the single scratch node could not answer: whether
dual-stack `host-gw` programs cross-node routes correctly.

**Result, 2026-11-23: it does, once `--flannel-iface` is set.** Routes on
k8s01.sfo02:

    10.42.1.0/24 via 192.33.255.151 dev eth1
    10.42.2.0/24 via 192.33.255.152 dev eth1
    2620:11a:b000:a01::/64 via 2620:11a:b000:203::151 dev eth1
    2620:11a:b000:a02::/64 via 2620:11a:b000:203::152 dev eth1

Pod-to-pod sfo02 -> scl04 measured 1.8 ms on IPv4 and 1.9 ms on IPv6, matching
the node-to-node fabric RTT — confirming the traffic goes switch to switch over
VLAN 203 rather than through a router. Pods carry public GUA IPv6 from
`2620:11a:b000:a0X::/64`.

### 6. FRR on the nodes — done 2026-11-23

FRR 10.3 (Debian 13 package) on all three nodes, `bgpd` and `bfdd` enabled,
config in `/etc/frr/frr.conf`. **No router has been touched**, so every session
is deliberately `Idle`; the node side is staged and waiting.

Per node: ASN `65200+N` (sfo02 65201, fmt01 65202, scl04 65206), router-id =
the node's fabric IPv4 address, `bgp graceful-restart`,
`bgp long-lived-graceful-restart stale-time 21600`, `no bgp default
ipv4-unicast` with explicit per-address-family activation, and BFD on every
peer-group.

Peer-groups staged: `EDGES` / `EDGES6` to `192.33.255.145-.146` and
`2620:11a:b000:203::1-::2` (AS 12276), and `MGMT` to the site mgmt-gw with
AS `65100+N`.

`vip0` is a dummy interface on each node, created live and persisted with a
systemd-networkd `.netdev` + `.network` pair. It was created with `ip link add`
rather than by restarting networkd, to avoid blipping a live node. It carries
no addresses yet — the API VIP health-check timer and service VIPs come later.

**Verified originate policy.** With the route-maps in place, k8s01.sfo02
originates exactly:

    *>  10.42.0.0/24              0.0.0.0(k8s01-sfo02)
    *>  2620:11a:b000:a00::/64    ::(k8s01-sfo02)

and nothing else. The node's own mgmt subnet (`10.1.1.0/24`) and the fabric
`/28` (`192.33.255.144/28`) are both correctly excluded by `ANNOUNCE-V4` /
`ANNOUNCE-V6`. Confirming this *before* any router peers is the point: the node
is an originator, never a transit router, and the filters are what enforce it.

**Pod-CIDR announcements are self-gating.** `cni0` only comes up once a pod is
scheduled on the node. With no pods, it is `DOWN`, contributes no connected
route, and the node announces nothing — which is why scl04 and fmt01 originate
zero prefixes today while sfo02 (running the kube-system pods) originates two.
This is desirable, not a fault: a node advertises its pod range only when it
can actually carry pod traffic. The tainted fmt01 witness will never announce a
pod CIDR, which is correct.

### Mgmt-leg IPv6 — added 2026-11-23

The nodes initially had **IPv4 only** on the mgmt leg. That was not a network
gap: every site's management LAN already carries IPv6 exactly as doc 001
specifies (`2620:11a:b00f:N01::1/64` on the mgmt-gw — verified at sfo02, fmt01
and scl04). The cause was that cloud-init was given only `ip=` for net0, and
SLAAC could not fill the gap because **SFMIX servers run `accept_ra=0`
fleet-wide** — `pve01.sfo02` on the same LAN is likewise link-local only.

Addresses assigned to match each node's v4 `.41`, reserved in NetBox:

| node | mgmt IPv6 | gateway |
|---|---|---|
| k8s01.sfo02 | `2620:11a:b00f:101::41/64` | `…:101::1` |
| k8s01.fmt01 | `2620:11a:b00f:201::41/64` | `…:201::1` |
| k8s01.scl04 | `2620:11a:b00f:601::41/64` | `…:601::1` |

Applied live and persisted in each VM's `ipconfig0` so they survive a rebuild.
No IPv6 default route was added — the v6 default is to come from the edges over
the fabric, per the design; the mgmt leg carries internal traffic only.

Each node now also stages a `MGMT6` peer-group to its local mgmt-gw v6 address,
with `MGMT-OUT-V6` (pod `/64` plus internal v6 VIPs) outbound and `DENY-ALL`
inbound — six staged neighbors per node in total.

Note for whoever builds the mgmt-gw side: the nodes sit on each site's existing
management LAN, **not** the `K8S-NODES` VLAN the addressing table describes
(`10.N.10.0/24` + `2620:11a:b00f:N10::/64`). Whether to build that VLAN later or
keep the nodes on the site mgmt LAN is still open, and it determines which
subnet the mgmt-gw `bgp listen range` must cover.

### Serving cluster names to the rest of SFMIX

The design calls for the internal recursors to **forward** `k8s.sfmix.org` to
CoreDNS rather than NS-delegating it, so that CoreDNS being unreachable costs
you cluster-internal names rather than the zone. Findings from 2026-11-23:

**TTL needs no work.** Measured against CoreDNS directly, cluster records are
already served with **TTL 5**, and the negative-cache SOA minimum is also 5:

    kubernetes.default.svc.k8s.sfmix.org. 5 IN A 10.43.0.1
    k8s.sfmix.org. 5 IN SOA ns.dns.k8s.sfmix.org. ... 5

BIND honours the TTL it is given, so a forwarded answer inherits that 5 s and
service changes propagate almost immediately. No CoreDNS tuning is required.

**The blocker is reachability, not configuration.** `kube-dns` is a plain
**ClusterIP** (`10.43.0.10`, `2620:11a:b000:43::a`), which is not routed outside
the cluster — ns1 cannot reach it today. CoreDNS must first be exposed on an
internal service VIP, reserved for this purpose:

| | |
|---|---|
| CoreDNS VIP | `10.255.20.2`, `2620:11a:b00f:ff20::2` |
| API VIP | `10.255.20.1`, `2620:11a:b00f:ff20::1` |

So the dependency order is: service-VIP mechanism -> mgmt-gw BGP sessions up ->
expose CoreDNS as a `LoadBalancer` on that VIP with
`externalTrafficPolicy: Local` (so only nodes with a ready CoreDNS endpoint
announce it) -> then, and only then, point ns1 at it.

**On ns1** (BIND, `192.33.255.3` / `2620:11a:b000::3`, recursion already enabled
for the `sfmix` ACL) the stanza is a forward-only zone:

    zone "k8s.sfmix.org" {
        type forward;
        forward only;
        forwarders { 10.255.20.2; 2620:11a:b00f:ff20::2; };
    };

Note `roles/sfmix_dns/templates/sfmix_zones.conf.j2` currently emits only
`type master` zones, from the `sfmix_forward_zones` / `sfmix_reverse_zones`
lists. Adding a forward zone means a new variable and template block, not just
another list entry.

**CoreDNS customisation goes through the ConfigMap, not the Corefile.** The
Corefile is written by k3s and marked `DO NOT EDIT`, but it ends with
`import /etc/coredns/custom/*.override` and `*.server`, so changes belong in
the `coredns-custom` ConfigMap and survive k3s upgrades.

### NAT: where it still happens, and why that is wrong

Measured on the live cluster 2026-11-23.

**IPv6 is already completely NAT-free.** There is no `FLANNEL-POSTRTG` chain in
`ip6tables` at all. Pods hold public GUA addresses and reach everything, inside
and outside, with their own source address. This is the design working as
intended.

**IPv4 pod-to-pod is NAT-free**, via explicit `RETURN` rules for traffic
between pod CIDRs.

**IPv4 pod-to-anything-else is masqueraded**, which is broader than this
document intends. The operative rule is:

    -A FLANNEL-POSTRTG -s 10.42.0.0/16 ! -d 224.0.0.0/4 -j MASQUERADE --random-fully

"Not another pod and not multicast" includes **every internal destination** —
NetBox, Loki, Prometheus, the mgmt-gws, every other SFMIX VM. Confirmed by
counter: a pod on k8s01.sfo02 pinging `10.1.1.1` incremented that rule.

This defeats the premise. The point of announcing each node's pod `/24` to the
mgmt-gws is that internal clients and pods reach each other **directly, both
directions**. Today inbound is direct but outbound is translated, so internal
services see node addresses instead of pod addresses: no per-workload ACLs, no
meaningful source identity in audit logs, and the pod `/24` advertisement only
does half its job. The text elsewhere in this document says masquerade happens
"on the way to the internet" — flannel's default is simply broader than that.

kube-proxy is *not* a contributor: `--masquerade-all` is off and
`KUBE-SERVICES` carries no masquerade marks. The remaining structural case is
an off-cluster client reaching a **ClusterIP**, which needs SNAT so replies
return via the same node — and that case disappears for real consumers once
services are exposed on LoadBalancer VIPs with `externalTrafficPolicy: Local`,
which preserves the client address.

**Decision (user, 2026-11-23): no NAT in Kubernetes at all.** Pods egress the
cluster as their pod addresses, and the site's mgmt-gw performs SNAT for IPv4
internet egress — the box that already does exactly this for the rest of the
management domain (doc 011). IPv6 needs no translation anywhere, as it already
does not get any.

This is cheaper than it looks: `mgmt-gw.sfo02`'s source NAT is a single
**source-agnostic** rule —

    nat source rule 1  outbound-interface eth2.31  translation address masquerade

— so it masquerades anything leaving the WAN interface regardless of source.
Once the mgmt-gw has a route to the pod `/24`s, pod IPv4 internet egress is
covered with **no NAT rule change on the router**.

**Resulting routing shape: both families egress via the mgmt domain.**

Egress path follows the **workload's domain, not its address family**. A
mgmt-domain pod reaches the internet through its site's mgmt-gw for IPv4 *and*
IPv6; it does not peel off onto the fabric merely because a flow is v6. One
path per workload means one set of firewall and policy decisions, and traffic
that is reasoned about once rather than twice.

| leg | carries |
|---|---|
| mgmt leg -> site mgmt-gw | node management, internal VIPs, **pod internet egress, both families** |
| fabric leg -> edges | east-west pod/etcd/kubelet, **public service VIP ingress** |

IPv4 is SNATed by the mgmt-gw; IPv6 is routed unchanged, since pods already
hold public GUA and need no translation anywhere.

**Consequence: pod `/64`s should stop being announced to the edges.** If pod
egress leaves via the mgmt domain, announcing the pod `/64`s to the edges would
pull *return* traffic back in over the fabric — egress one way, ingress the
other. That asymmetry is tolerable for stateless forwarding but defeats any
stateful policy on the egress path, and it is simply harder to reason about.

Dropping pod `/64`s from the edge export makes the picture symmetric and has a
second benefit: pods stop being directly reachable from the internet at all.
Public consumers reach services through the public VIPs
(`192.33.255.128/28`, `2620:11a:b000:120::/64`), never through pod addresses,
so nothing is lost — and the "pods have public IPv6, so default-deny hard"
exposure concern elsewhere in this document largely evaporates, because the
exposure stops being routed rather than merely filtered.

This requires editing `EDGES-OUT-V6` on each node, which currently permits the
pod `/56` alongside the public VIP range.

**The real cost, stated plainly.** This makes a mgmt-gw the egress path for
*all* pod internet traffic, including IPv6, which was meant to be the
high-volume family on the 10G fabric. That is in direct tension with this
document's own principle that bulk and public traffic never cross a mgmt-gw,
and the mgmt-gws are small CPU routers. The trade is deliberate — coherent
policy and one reasoning path, bought with egress throughput — but it means
egress bandwidth is now a mgmt-gw property, and a traffic-heavy workload is the
signal to revisit rather than something to discover from a saturated APU.

Also worth confirming before relying on it: the management domain's own IPv6
internet path has known weak points from the doc 011 work (notably the fmt01
`::/0`-into-OSPF blackhole), so mgmt-domain v6 egress should be verified at
each site rather than assumed.

**Ordering matters, and getting it backwards breaks the cluster.** Flannel's
IPv4 masquerade must be disabled **only after** the mgmt-gws have BGP sessions
up and have learned the pod `/24`s. Disable it first and pod IPv4 egress stops
working immediately — including CoreDNS's upstream forwarding to `ns1`
(`192.33.255.3`), because ns1 would have no route back to `10.42.0.0/16`. The
correct sequence is:

1. mgmt-gw BGP sessions up; mgmt-gws learn each node's pod `/24`.
2. Confirm internal reachability to a pod address from off-cluster.
3. Disable flannel IPv4 masquerade on the nodes (custom flannel conf —
   flannel owns and rewrites `FLANNEL-POSTRTG`, so editing that chain is not
   durable).
4. Re-verify pod egress and CoreDNS upstream resolution.

**One tension to keep an eye on.** This routes pod IPv4 internet traffic across
a mgmt-gw, which the "bulk and public traffic never crosses a mgmt-gw"
principle warns against. It is acceptable because the high-volume path is meant
to be IPv6 via the edges, and IPv4 egress should be modest — but a v4-heavy
workload would violate the principle, and that is the signal to revisit.

### 7. Teardown

    /usr/local/bin/k3s-uninstall.sh        # on a server
    /usr/local/bin/k3s-agent-uninstall.sh  # on an agent

and `qm destroy 130` for the scratch VM once it has served its purpose.

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
