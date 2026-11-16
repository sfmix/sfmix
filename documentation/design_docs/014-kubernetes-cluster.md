# 014 — Kubernetes across three sites, addressed by BGP

Status: exploratory (2026-11-16). Nothing is built. Names, numbers and
address ranges below are proposals; the ranges and VLAN 203 were unallocated
in NetBox on 2026-11-16.

## Why

The donated DL360 Gen9s are the first hosts with real headroom (64 threads
each, fast local SSD), and today each new service gets its own hand-built VM.
A small Kubernetes cluster would give us one place to run stateless services,
with rolling deploys and replicas spread across sites.

We are an IXP, so the cluster is addressed the way we address everything
else: with dynamic routing. That removes the usual problem of a multi-site
cluster (no shared L2 for ARP-based virtual IPs) and makes pod and service
addresses ordinary routed prefixes.

## Principles

- **Bulk and public traffic never crosses a mgmt-gw.** The mgmt-gws are small
  CPU routers. Public services, pod internet egress and node-to-node traffic
  ride a fabric VLAN on the DL360s' 10G links.
- **The mgmt side carries only internal, low-volume traffic:** admin access,
  the API, scraping, logs.
- **Same pattern everywhere:** the two core sites (sfo02, fmt01) are hubs that
  accept BGP clients from a `bgp listen range`; every client lists just the
  two hubs. Adding a node or a site never touches existing config.
- **One private ASN per site.** No iBGP anywhere.
- **Plain Linux routing on the nodes:** FRR plus k3s's built-in flannel in
  `host-gw` mode. No overlay, no CNI-specific BGP layer.

## Shape

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

## Nodes

| node | host | role | vCPU | RAM | disk |
|---|---|---|---|---|---|
| k8s01.sfo02 | pve01.sfo02 (DL360) | server + workloads | 32–48 | ~20 GiB | 200 GiB on `tank-vms` |
| k8s01.scl04 | pve02.scl04 (DL360) | server + workloads | 32–48 | ~24 GiB | 200 GiB on `tank-vms` |
| k8s01.fmt01 | pve01-fmt (Atom) | etcd only, no workloads | 2 | 4 GiB | 32 GiB on `local-zfs` |

Each node VM has two NICs:

- **fabric leg** on the host's fabric bridge: pve01.sfo02 and pve02.scl04
  `vmbr2` (bond2, FlexLOM 10G to the fabric switches, today
  `allowed vlan none`); pve01-fmt `vmbr2` (eno4 trunk, already carries fabric
  VLANs 100/101/997/998). pve02.scl04's FlexLOM is not cabled yet.
- **mgmt leg** on the site's new `K8S-NODES` VLAN.

Sizing notes:

- **RAM is the constraint, not CPU.** Each DL360 has 31–32 GiB. pve01.sfo02
  already runs metrics01 (4 GiB) and teleport (2 GiB). Leave 4–5 GiB per host
  for Proxmox and the ZFS ARC. More DDR4 RDIMMs is the cheapest upgrade.
- **`tank-vms` is a single consumer 2 TB SSD** on both DL360s. Losing it
  means rebuilding that node from the cluster: fine for stateless workloads
  and etcd, not for local persistent volumes. Keep state off the cluster at
  first.
- **pve01-fmt** has 42 of 62 GiB free (2026-11-15). pve02-fmt is not a
  candidate (worn QVOs, about 14% endurance left; librenms).

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
  keeps working; heartbeat 100 ms / election 1 s means no election storms);
- **slows every write while it is the leader.** etcd has no leader priority;
  move leadership with `etcdctl move-leader` if it ever wins.

Fix: pve01-fmt (Supermicro A2SDi-TP8F) has an **empty M.2 PCIe slot**. A
small power-loss-protected device (Intel Optane P1600X 58 GB, ~$40–60) as a
dedicated pool for this VM takes fsync under 1 ms. Used instead as a `log`
vdev for `rpool`, it also helps alice. Do it before relying on the cluster.

Rules for the witness VM:

- **Exclude it from pvesr replication** on the FMT01-01 cluster. Replication
  freezes the guest filesystem every 15 minutes, which stalls etcd, and a
  copied etcd member is useless anyway.
- No vzdump either (snapshot mode freezes the guest the same way). Back up
  etcd with its own snapshots (k3s `etcd-snapshot`), pushed to backup01.scl04
  like doc 013.

## Third site

The third DL360 (NetBox 216, `incoming-dl360g9-3`, status `inventory`) would
go to **fmt01**, but that rack is busy; **scl02** is the fallback. Latency is
fine either way:

| from | to mgmt-gw.fmt01 | to mgmt-gw.scl02 |
|---|---|---|
| pve01.sfo02 | 1.8 ms | 1.7 ms |
| pve02.scl04 | 2.9 ms | 1.2 ms |

When it is racked it becomes a full member and the witness retires. **Add
the new member first, then remove the witness** (four members briefly,
quorum 3, still tolerates one failure).

**Not pve01.scl04** for any member: same site as pve02.scl04, so one site
outage would take two of three members.

## Addressing

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

## Fabric leg: data plane, public

VLAN 203 is a new Exchange Fabric VLAN, stretched to every site with a node,
like VLANs 200 and 201. Both edges get `eth4.203`, as they have `eth4.10x`
for hosted networks today.

### East-west: flannel host-gw

All nodes share one L2 segment, so k3s's built-in flannel in `host-gw` mode
installs a plain kernel route per remote node (`10.42.X.0/24 via <node>`,
same for IPv6). Node-to-node traffic goes switch to switch over the fabric,
never through a router. k3s node IP = the fabric address, so etcd and kubelet
traffic use the 10G path too. (Verify dual-stack `host-gw` on the k3s
version we pick.)

### North-south: edges as hubs

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

## Mgmt leg: internal only

### Node ↔ its site's mgmt-gw

- mgmt-gw: `bgp listen range` for the site's `K8S-NODES` subnet into
  peer-group `K8S`, `remote-as external`, BFD.
- **Node announces:** internal VIPs, its pod IPv4 `/24`, its pod IPv6 `/64`
  (so internal clients reach pods directly and replies come back the same
  way).
- **Node receives nothing.** Internal destinations (`10.0.0.0/8`,
  `2620:11a:b00f::/48`) are static routes on the node via the mgmt-gw; the
  default stays on the fabric.
- **mgmt-gw import:** exactly those ranges at those lengths, max-prefix.

### Between mgmt-gws: route-server hubs

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

## Failure detection

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

### Announce only when healthy

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

## Node software

- **k3s with embedded etcd**, three servers. Witness:
  `--disable-apiserver --disable-controller-manager --disable-scheduler`.
  `--flannel-backend=host-gw`, dual-stack `--cluster-cidr` and
  `--service-cidr` from the table, `--flannel-ipv6-masq` off (pods are
  public), servicelb and traefik disabled, k3s's built-in network policy
  controller kept. `--tls-san` for the API VIP and `api.k8s.sfmix.org`.
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

- **Why not Calico or Cilium:** both can route natively without an overlay
  (Calico is BIRD underneath), but each brings its own control plane, CRDs
  and BGP configuration model on top. With the stretched VLAN, flannel
  `host-gw` already gives overlay-free pod routing, and FRR is the same
  routing stack the mgmt-gws and edges run.

## Security

- **Nodes are on the internet** (public fabric addresses). Host nftables:
  BGP and BFD only from the edges and the mgmt-gw; etcd, kubelet and API
  ports only from the fabric `/28` and the `K8S-NODES` / admin ranges.
- **Pods have public IPv6.** Default-deny `NetworkPolicy` per namespace, and
  a host forward rule that only lets new inbound connections reach service
  VIP ports.
- **mgmt-gw:** `K8S-NODES` in its own interface group. Allowed from k8s:
  DNS on the mgmt-gw, NetBox API, Loki, Prometheus as needed. Admin and
  metrics to k8s: allowed. Internet egress does not go this way at all.

## Failure behavior

| failure | etcd | API (internal) | public services |
|---|---|---|---|
| none | 3/3 | VIP → nearest healthy DL360 node | nearest healthy announcer, either edge |
| one DL360 node or its site down | 2/3; writes wait on fmt01 disk until the Optane is in | other DL360 node | BFD withdraws in ~1 s; other node serves |
| fmt01 witness down | 2/3, fast | unaffected | unaffected |
| two members down | no quorum; no changes possible | down | running pods keep serving |
| one edge-gw down | unaffected | unaffected | the other edge |
| one mgmt-gw hub down | unaffected | the other hub carries routes | unaffected |
| a spoke mgmt-gw down | unaffected (etcd rides the fabric) | that site's node unreachable internally | unaffected |
| FRR restart on a node | unaffected | GR holds routes | GR holds routes |

## Rollout

1. NetBox: VLAN 203, prefixes above, `K8S-NODES` per site, ASNs
   65201/65202/65206 (65200 + N).
2. Fabric: VLAN 203 to both edge ports and the node hosts' fabric ports;
   cable pve02.scl04's FlexLOM.
3. Witness: k8s01.fmt01 on pve01-fmt, out of pvesr. Optane when bought.
4. VMs on pve01.sfo02 and pve02.scl04; FRR; k3s with flannel `host-gw`.
   Verify pod-to-pod across sites over VLAN 203.
5. Edges: `eth4.203`, `K8S` listen range, filters, conditional defaults.
   `commit-confirm`. Nodes take their default from the edges.
6. mgmt-gws: `K8S-NODES` VLAN and `K8S` listen range at the three sites;
   hub/spoke sessions (hubs first). `commit-confirm` each.
7. API VIP health check; test BFD pull, FRR restart, node drain against the
   failure table.
8. Service VIPs (kube-vip or controller), firewall zone, first workload.
9. Third DL360 racked: add member, remove witness.

## Open items

- How service VIPs get onto `vip0` (kube-vip routing-table mode vs a small
  controller).
- VyOS 1.4: LLGR configuration, BFD control-plane-failure handling,
  overlapping listen ranges.
- Dual-stack flannel `host-gw` on the chosen k3s version.
- Edge forwarding headroom for k8s egress (the edges are software routers
  too, but they already carry all transit).
- What moves first: stateless services only at first.
- RAM upgrade for both DL360s.
