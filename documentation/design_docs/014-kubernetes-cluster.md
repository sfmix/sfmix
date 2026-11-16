# 014 — Kubernetes across three sites, addressed by BGP

Status: exploratory (2026-11-15). Nothing is built. Names, numbers and
address ranges below are proposals; the ranges were unallocated in NetBox on
2026-11-15.

## Why

The donated DL360 Gen9s are the first hosts with real headroom (64 threads
each, fast local SSD), and today each new service gets its own hand-built VM.
A small Kubernetes cluster would give us one place to run stateless services,
with rolling deploys and replicas spread across sites.

We are an IXP, so the cluster should be addressed the way we address
everything else: with dynamic routing. That removes the usual problem of a
multi-site cluster (no shared L2, so no ARP-based virtual IPs) and makes pod
and service addresses ordinary routed prefixes that metrics, LibreNMS and
admins can reach directly.

## Shape

```
   ┌──────────── eBGP mesh between mgmt-gw loopbacks ─────────────┐
   │        (k8s prefixes only; OSPF stays the IGP)               │
   │                                                              │
 mgmt-gw.sfo02            mgmt-gw.fmt01               mgmt-gw.scl04
 AS 65101                 AS 65102                    AS 65106
   │                        │                            │
   │ eBGP + BFD, listen range on each site's K8S-NODES VLAN
   │                        │                            │
 k8s01.sfo02              k8s01.fmt01                 k8s01.scl04
 on pve01.sfo02           on pve01-fmt                on pve02.scl04
 server + workloads       etcd-only witness           server + workloads
 AS 65200                 AS 65200                    AS 65200
```

- Three etcd members, one per site, so losing any one site keeps quorum.
- Each node peers BGP **only with its own site's mgmt-gw** and announces its
  pod prefixes plus any service addresses it is serving.
- The mgmt-gws carry those prefixes between sites in BGP. They are not
  redistributed into OSPF (why: see "Between mgmt-gws").

## Nodes

| node | host | role | vCPU | RAM | disk |
|---|---|---|---|---|---|
| k8s01.sfo02 | pve01.sfo02 (DL360) | server + workloads | 32–48 | ~20 GiB | 200 GiB on `tank-vms` |
| k8s01.scl04 | pve02.scl04 (DL360) | server + workloads | 32–48 | ~24 GiB | 200 GiB on `tank-vms` |
| k8s01.fmt01 | pve01-fmt (Atom) | etcd only, no workloads | 2 | 4 GiB | 32 GiB on `local-zfs` |

- **RAM is the constraint, not CPU.** Each DL360 has 31–32 GiB. pve01.sfo02
  already runs metrics01 (4 GiB) and teleport (2 GiB). Leave 4–5 GiB per host
  for Proxmox and the ZFS ARC. More DDR4 RDIMMs is the cheapest upgrade.
- **`tank-vms` is a single consumer 2 TB SSD** on both DL360s (no
  redundancy). Losing it means rebuilding that node from the cluster, which
  is fine for stateless workloads and for etcd (two others hold the data),
  but not for local persistent volumes. Keep state off the cluster at first.
- **pve01-fmt** has 42 of 62 GiB free (2026-11-15). Its guests are alice and
  quarantine-lg. pve02-fmt is not a candidate: worn QVOs (about 14% endurance
  left) and librenms.

## etcd and the fmt01 witness

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
  keeps working, just sluggishly; heartbeat 100 ms / election 1 s means no
  election storms);
- **slows every write while it is the leader.** etcd has no leader priority;
  move leadership with `etcdctl move-leader` if it ever wins.

Fix: pve01-fmt (Supermicro A2SDi-TP8F) has an **empty M.2 PCIe slot**. A
small power-loss-protected device (Intel Optane P1600X 58 GB, ~$40–60) as a
dedicated pool for this VM takes fsync under 1 ms. Used instead as a `log`
vdev for `rpool`, it also helps alice. Not required to start, but do it
before relying on the cluster.

Rules for the witness VM:

- **Exclude it from pvesr replication** on the FMT01-01 cluster. Replication
  freezes the guest filesystem every 15 minutes (`guest-fsfreeze`), which
  stalls etcd, and a copied etcd member is useless anyway.
- No vzdump either (snapshot mode freezes the guest the same way). Back up
  etcd with its own snapshots (k3s: `etcd-snapshot`), pushed to
  backup01.scl04 like doc 013.

## Third site

The third DL360 (NetBox 216, `incoming-dl360g9-3`, status `inventory`) would
go to **fmt01**, but that rack is busy; **scl02** is the fallback. Either
works for latency:

| from | to mgmt-gw.fmt01 | to mgmt-gw.scl02 |
|---|---|---|
| pve01.sfo02 | 1.8 ms | 1.7 ms |
| pve02.scl04 | 2.9 ms | 1.2 ms |

(Host to host, sfo02↔scl04 is 2.2 ms and scl04↔fmt01 3.1 ms.) scl02 and
scl04 are different buildings in the same metro, which is acceptable for
quorum.

When it is racked, it becomes a full member (`k8s01.<site>`) and the witness
retires. **Add the new member first, then remove the witness** (four members
briefly, quorum 3, still tolerates one failure). Removing first would leave
two members, where any failure stops writes.

**Not pve01.scl04** for any member: same site as pve02.scl04, so one site
outage would take two of three members.

## Addressing

N is the site's management number (`10.N.0.0/16`, as in doc 011): sfo02 1,
fmt01 2, scl02 5, scl04 6.

| what | IPv4 | IPv6 | scope | routed? |
|---|---|---|---|---|
| node subnet | `10.N.10.0/24` | `2620:11a:b00f:N10::/64` | per site, new site-local VLAN `K8S-NODES` | yes (connected on mgmt-gw) |
| pod pool | `10.N.64.0/18` | `2620:11a:b00f:N80::/57` | per site; one block per node | yes, BGP from nodes |
| internal service VIPs (anycast) | `10.255.20.0/24` | `2620:11a:b00f:ff20::/64` | cluster-wide | yes, BGP from nodes |
| API server VIP | `10.255.20.1` | `2620:11a:b00f:ff20::1` | cluster-wide, name `api.k8s.sfmix.org` (internal) | yes |
| public service VIPs (later) | `192.33.255.128/28` | `2620:11a:b000:120::/64` | cluster-wide | yes, via edges (doc 011) |
| ClusterIP services | `10.43.0.0/16` (k3s default) | `fd00:43::/112` | inside the cluster | **no** |

Why the pod pools are **per site** rather than one cluster-wide pool:

- **IPv6 egress just works.** Each site's pods fall inside that site's `/56`,
  which doc 011 already announces from that site's mgmt-gw to the edges.
  Replies come back to the same mgmt-gw that holds the connection state. A
  cluster-wide pod `/56` would be announced from several mgmt-gws, replies
  could return to the wrong one, and its stateful firewall would drop them.
- **IPv4 egress** is masqueraded by the site's mgmt-gw like any other
  management host (the NAT rule's source match must cover the new ranges).
- Each mgmt-gw could announce one aggregate per site if we ever want fewer
  routes. With three nodes it does not matter.

The CNI must be able to give nodes pod blocks from a pool chosen by node
label (Calico `IPPool` with `nodeSelector` does; Cilium multi-pool IPAM is
the equivalent there, check its maturity in the version we pick).

Plain management LAN (`10.N.1.0/24`) for nodes is a possible shortcut if a new
VLAN is awkward at a site, but it puts workloads with host networking on the
management LAN. Prefer `K8S-NODES`.

## Routing

### Nodes ↔ their mgmt-gw

Same pattern as doc 011's edge-gw side, so a new or rebuilt node needs no
router change:

- mgmt-gw: `bgp listen range` for the site's `K8S-NODES` subnet (v4 and v6)
  into peer-group `K8S`, `remote-as external`, BFD, session password.
- Nodes: one private ASN for the whole cluster, **AS 65200**. mgmt-gws keep
  doc 011's `65100 + N`.
- **Import, strict:** only prefixes inside that site's pod pool (exact block
  size), the internal VIP range (`/32`, `/128` only) and the public VIP range
  (`/32`, `/128` only). Max-prefix limit. Never a default.
- **Export to nodes: nothing.** Nodes have a static default to the mgmt-gw.
- mgmt-gw firewall: BGP (tcp/179) and BFD (udp/3784-3785) from `K8S-NODES`
  only.

### Between mgmt-gws

The obvious move, redistributing BGP into OSPF, is wrong for anycast. OSPF
carries no notion of "stale" or "less preferred", and a mgmt-gw's own BGP
route (distance 20) beats OSPF (110) in its RIB. If a node dies and its
mgmt-gw is still holding the route (graceful restart, long-lived graceful
restart, or a slow hold timer), that whole site keeps forwarding the VIP into
the dead node even though two healthy announcers exist elsewhere.

So the mgmt-gws carry k8s prefixes **in BGP**, where best-path selection sees
every announcer:

- **eBGP between mgmt-gw loopbacks** (`10.N.0.0`), multihop, using doc 011's
  per-site ASNs. Loopbacks are already in OSPF, so sessions survive VLAN 200
  or WireGuard path changes. Neighbors are templated from
  `group_vars/management_router.yml` (every mgmt-gw, 36 sessions for 9 sites).
  Only k8s ranges are accepted or sent on these sessions.
- **Path choice:** a mgmt-gw prefers its own site's node (AS path `65200`)
  over a remote one (`65NNN 65200`). Among remote paths, BGP falls through to
  IGP cost to the next hop, so it picks the closest site.
  `bestpath as-path multipath-relax` + `maximum-paths` gives ECMP instead if
  we want it.
- **Alternative:** one management AS (`65100`) with route reflectors on
  mgmt-gw.sfo02 and mgmt-gw.fmt01, iBGP between loopbacks. Cleaner policy,
  but it changes doc 011's ASN table. Decide before doc 011 is built.

### Failure detection: graceful restart instead of long hold timers

The aim behind "long hold times" is right: routes should not disappear just
because a BGP speaker or CNI agent restarts while the node keeps forwarding.
But a long hold timer cannot tell a restart from a dead node. For an anycast
VIP, a dead node keeps attracting its share of traffic, into a blackhole, for
the whole hold time.

What we use instead:

| mechanism | handles | effect |
|---|---|---|
| **BFD** (e.g. 300 ms × 3) | node or link actually dead | session down in about a second, routes withdrawn |
| **Graceful restart**, restart time ~120 s | BGP speaker or agent restart, datapath still forwarding | mgmt-gw keeps routes while the speaker comes back |
| **Long-lived graceful restart** (RFC 9494), stale time hours | longer control-plane outages | routes kept but tagged `LLGR_STALE` and least preferred, so any healthy announcer wins; single-announcer prefixes (a node's own pod block) keep working |

LLGR is the version of "long hold" that does the right thing, and it works
only because the mgmt-gws compare paths in BGP (previous section).

Caveats to verify:

- FRR 9.1.1 (mgmt-gws) implements LLGR (since FRR 8.2). Whether the VyOS 1.4
  configuration commands expose it is unchecked.
- The node's BGP speaker must advertise GR/LLGR capability. Check the chosen
  CNI (BIRD in Calico, GoBGP in Cilium) or run FRR on the node.
- If BFD runs inside the same agent as BGP, an agent restart also drops BFD
  and the routes are withdrawn, defeating GR. FRR's
  `bfd check-control-plane-failure` (BFD C-bit) is the knob to get right.

### Announce only when healthy

- Service VIPs are announced only from nodes with a ready local endpoint
  (`externalTrafficPolicy: Local` or the CNI's equivalent), so a VIP follows
  its pods.
- The API VIP is announced only by nodes whose local API server passes its
  health check. The fmt01 witness (no API server) never announces it.
- Before planned maintenance on a node, withdraw first: cordon and drain,
  then shut its BGP sessions (graceful shutdown community, RFC 8326), then
  reboot. Same rule as BGP maintenance elsewhere: take the neighbor down
  before dropping sockets.

### Public services (later)

Once doc 011 is built, each mgmt-gw already has eBGP to both edges over
VLAN 202.

- Edges: widen the `MGMT-GWS` import filter to accept `192.33.255.128/28`
  `le 32` and `2620:11a:b000:120::/64` `le 128`, tagged `no-export`. They are
  inside the `/24` and `/44` we already announce, so nothing new appears in
  the global table.
- mgmt-gws export to the edges **only public VIPs learned from their own
  site's nodes**, never ones learned over the mgmt-gw mesh. Otherwise
  traffic can enter at site A, cross to a node at site B, and reply out B's
  mgmt-gw, where the stateful firewall has no session.
- mgmt-gw forward chain: allow inbound to the public VIP range on the
  service's ports.

## Software

- **k3s with embedded etcd**, three servers. The fmt01 witness runs
  `--disable-apiserver --disable-controller-manager --disable-scheduler`
  (etcd only). Disable the bundled flannel, servicelb and traefik.
  `--tls-san` for the API VIP and `api.k8s.sfmix.org`. k3s agents (if we add
  any) balance across API servers on their own, so the VIP matters mostly
  for humans and tooling.
- **CNI: Calico or Cilium**, chosen on these requirements:

| requirement | why |
|---|---|
| native routing, no overlay | pods are routed prefixes |
| per-node-label pod pools | per-site pools (Addressing) |
| BGP to an external peer with GR, ideally LLGR | Routing |
| BFD, or room to run FRR alongside | failure detection |
| announce LoadBalancer IPs only from nodes with ready endpoints | anycast VIPs |
| dual-stack | IPv6 everywhere |

- Ansible: VMs provisioned like other servers (`sfmix_server`), k3s by a new
  role; mgmt-gw BGP in the VyOS templates next to `firewall.j2`.

## Security

Today `firewall.j2` filters only the WAN side of each mgmt-gw; every other
interface is trusted. Routed pod addresses mean a compromised pod could reach
the management LANs directly. Before running anything internet-facing:

- `K8S-NODES` goes into its own interface group on the mgmt-gw.
- Forward policy: k8s → internet (NAT) allowed; k8s → management only to
  named services (DNS on the mgmt-gw, NetBox API, Loki, Prometheus remote
  write as needed); admin and metrics → k8s allowed.
- Pod and VIP ranges count as `K8S` sources wherever they appear (including
  the mgmt-gw mesh).

## Failure behavior

| failure | etcd | API | services |
|---|---|---|---|
| none | 3/3 | VIP → nearest healthy DL360 node | nearest announcer |
| one DL360 node or its site down | 2/3, writes wait on fmt01 disk (slow until Optane) | other DL360 node | BFD withdraws in ~1 s; other site serves |
| fmt01 witness down | 2/3, fast | unaffected | unaffected |
| two members down | no quorum, API read-only/stuck | down | running pods keep forwarding; no changes possible |
| a site's mgmt-gw down | that site's node isolated | other site | other site |
| CNI agent restart on a node | unaffected | unaffected | GR keeps routes while the datapath forwards |

## Rollout

1. NetBox: prefixes above, `K8S-NODES` VLAN per site, ASN 65200.
2. Witness first: k8s01.fmt01 on pve01-fmt, out of pvesr. Optane when bought.
3. VMs on pve01.sfo02 and pve02.scl04; k3s cluster on node addresses only.
4. mgmt-gw BGP: `K8S` peer-group and filters at sfo02, scl04, fmt01; then the
   mgmt-gw mesh. `commit-confirm` each.
5. CNI with native routing; verify pod prefixes from metrics.sfo02 and the
   failure table above (BFD pull, agent restart, node drain).
6. API VIP and internal service VIPs.
7. Firewall zone for `K8S-NODES`, then the first real workload.
8. Third DL360 racked: add member, remove witness.
9. Public VIPs after doc 011 is live.

## Open items

- Calico or Cilium (or FRR on the nodes) — decides GR/LLGR/BFD support.
- eBGP mesh with per-site ASNs vs one management AS with route reflectors
  (affects doc 011).
- Does VyOS 1.4 expose LLGR and BFD C-bit handling?
- mgmt-gw forwarding capacity for cross-site pod traffic. The DL360s have
  unused 10G links into the fabric switches (bond2, `allowed vlan none`); a
  k8s VLAN on the fabric with nodes peering there would keep east-west
  traffic off the mgmt-gws.
- What moves first. Stateless candidates only (no persistent volumes at
  first).
- RAM upgrade for both DL360s.
