# 011 — Management internet access: central egress with per-site OOB fallback

Status: proposed (2026-11-09). Nothing below is built yet except the
2026-11-09 interim fix (no defaults in management OSPF).

## Why

Every site's management router (`mgmt-gw.<site>`) currently reaches the
internet only through its own out-of-band (OOB) circuit, with IPv4
masquerade and no working IPv6:

- **Slow.** sfo02's OOB path measured ~8 Mb/s (2026-11-08) while
  metrics.sfo02's public path did ~90 Mb/s. Installs and updates on
  management hosts crawl.
- **IPv6 was a blackhole.** mgmt-gw.fmt01 originated `::/0` into
  management OSPF while its own HE IPv6 uplink was dead (HE never answers
  neighbor solicitation). Every site followed that default, so the
  pdns-recursor on each mgmt-gw spent its query budget on IPv6 timeouts and
  returned SERVFAIL for any name with IPv6 nameservers. Fixed 2026-11-09 by
  removing `protocols ospfv3 default-information originate` on fmt01.
- **Not repeatable.** Each site's egress is hand-built, and the IPv6 story
  differs per site.

We want one pattern, deployed identically at every site, that uses the fast
central transit (the edge-gws at sfo02 and fmt01) when the fabric is up and
falls back to the site's own OOB circuit when it is not.

## Shape

```
                internet (HE, DRT, AS40271, IX peers)
                  │                         │
            edge-gw.sfo02             edge-gw.fmt01      internet domain:
                  │                         │            routing only, no NAT,
   ═══════════════╧═══ VLAN 202 MGMT-INTERNET ╧══════    no connection tracking
     │          │          │          │          │
  mgmt-gw    mgmt-gw    mgmt-gw    mgmt-gw    mgmt-gw    security appliances:
   sfo01      sfo02      fmt01       ...       sjc02     NAT44 / NAT66 + stateful
     │          │          │                     │       firewall on BOTH WAN ifaces
   OOB ISP    OOB ISP    OOB ISP               OOB ISP   (fallback egress)
```

- **VLAN 202 `MGMT-INTERNET`** is a new Exchange Fabric VLAN, next to
  200 `MGMT-PEERING` (mgmt-gw ↔ mgmt-gw OSPF only) and 201 `EDGE-PEERING`.
  It is part of the internet side, untrusted.
  - IPv4 `192.33.255.96/27`, IPv6 `2620:11a:b000:202::/64` (both were
    unallocated in NetBox; both sit inside the already announced
    `192.33.255.0/24` and `2620:11a:b000::/44`).
- **edge-gws stay internet-domain only.** They route; they do not translate
  or track connections.
- **mgmt-gws are the security appliances.** They own NAT and the stateful
  firewall, on both of their WAN interfaces.
- **VLAN 200 and the WireGuard mesh** keep carrying internal reachability
  (OSPF). **No router originates a default into management OSPF.**

## edge-gw side (configured once, identical on both)

1. `eth4.202` with `192.33.255.97` / `2620:11a:b000:202::1` (sfo02) and
   `192.33.255.98` / `2620:11a:b000:202::2` (fmt01).
2. BGP **dynamic neighbors**: `bgp listen range` for `192.33.255.96/27` and
   `2620:11a:b000:202::/64` into peer-group `MGMT-GWS` (`remote-as external`),
   BFD enabled. A new site needs **no edge-gw change**.
3. Export to `MGMT-GWS`: `0.0.0.0/0` and `::/0` only, via
   `default-originate` with a route-map that requires an upstream-learned
   route. An edge with no working transit stops offering a default.
4. Import from `MGMT-GWS`: only `/56`s inside `2620:11a:b00f::/48`
   (`ge 56 le 56`), tagged `no-export`. Nothing IPv4.
5. These `/56`s never leave AS12276. The external announcements stay the
   `/44` and the `/24` (`SFMIX-V6` / `SFMIX-OUT-V6` already match exact
   prefixes only; the `no-export` tag is a second guard). The existing
   `/44` and `/48` blackhole statics (distance 254) remain the catch-all.

Replies to a site's IPv6 space can enter at either edge (both announce the
`/44`). Both are on VLAN 202 and both learn every `/56`, so either one
delivers to the right mgmt-gw. That is why connection state lives on the
mgmt-gw and not on the edges.

## mgmt-gw side (one template, per-site variables)

1. `eth0.202` on VLAN 202 with the site's addresses (table below). It joins
   the existing `WAN` interface group next to the OOB uplink, so the
   current `firewall.j2` chains apply unchanged (replies only, admin
   allowlist, rate-limited ping). Add to `WAN4/6_LOCAL`: BGP (tcp/179) and
   BFD (udp/3784-3785) from the VLAN 202 subnet only.
2. eBGP to both edges, ASN `65100 + N` (N = the site's management number,
   as in `10.N.0.0/16`). Receive the defaults; send the site's IPv6 `/56`.
   BFD on, so a dead fabric link or edge withdraws the default in about a
   second. eBGP distance 20.
3. Fallback default routes via the OOB uplink at distance 210 (IPv4 always;
   IPv6 where the ISP provides it). Idle until BGP withdraws.
4. IPv4: masquerade on **both** WAN interfaces. Normally the site appears as
   its own `192.33.255.1NN` (via VLAN 202 → edges); on fallback as the OOB
   ISP's address.
5. IPv6: the site's `/56` is routed untranslated out `eth0.202`; the forward
   chain allows replies only. On fallback, NAT66 masquerade on the OOB
   uplink where the ISP has IPv6; elsewhere there is simply no IPv6 default
   during fallback, so IPv6 fails fast instead of timing out.
6. OSPF: unchanged for internal prefixes; no `default-information
   originate`.

## Failure behavior

| Failure | Outbound | Inbound to the site's IPv6 space |
|---|---|---|
| none | central edges | either edge, via the `/44` |
| one edge-gw down | the other edge | the other edge |
| site's fabric link down | local OOB, translated | lost (blocked anyway, except admins) |
| both edge-gws down | every site on its own OOB | lost |
| site's OOB circuit down | central edges, unaffected | unaffected |

Admin access over the WireGuard tunnels and IPv4 does not depend on any of
this.

## Per-site variables

N = management number (`10.N.0.0/16`, `lo` = `10.N.0.0`). OOB facts from
the 2026-11-09 probe (below).

| site | N | VLAN 202 v4 / v6 | site IPv6 /56 | ASN | OOB iface / ISP | OOB IPv6 → NAT66 fallback |
|---|---|---|---|---|---|---|
| sfo01 | 0 | .100 / ::100 | 2620:11a:b00f::/56 | 65100 | eth0.50 / Telx-DRT | none → v4-only |
| sfo02 | 1 | .101 / ::101 | 2620:11a:b00f:100::/56 | 65101 | eth2.31 / DRT-Telx DIA | DRT router present, unconfirmed → ask DRT |
| fmt01 | 2 | .102 / ::102 | 2620:11a:b00f:200::/56 | 65102 | eth1 / HE | configured but dead (HE ND) → v4-only until fixed |
| sjc01 | 3 | .103 / ::103 | 2620:11a:b00f:300::/56 | 65103 | eth1 / SoftCom | none → v4-only |
| scl01 | 4 | .104 / ::104 | 2620:11a:b00f:400::/56 | 65104 | eth1 / QTS | RAs present; take an address → NAT66 |
| scl02 | 5 | .105 / ::105 | 2620:11a:b00f:500::/56 | 65105 | eth1 / Comfluent (CoreSite) | working → NAT66 |
| scl04 | 6 | .106 / ::106 | 2620:11a:b00f:600::/56 | 65106 | eth1 / OpenColo | none → v4-only |
| sjc02 | 7 | .107 / ::107 | 2620:11a:b00f:700::/56 | 65107 | eth1 / CoreSite | working → NAT66 |
| scl05 | 8 | .108 / ::108 | 2620:11a:b00f:800::/56 | 65108 | eth0 / DRT-Telx | none → v4-only |

v4 addresses are in `192.33.255.96/27`, v6 in `2620:11a:b000:202::/64`.
scl02 and sjc02 currently carry their own static `::/0` at distance 1;
under this design it moves to distance 210.

## Why not local egress with AS12276 source addresses

An alternative is to send traffic out each site's fast-enough local OOB
circuit with AS12276 source addresses and let replies return via the edges
(no NAT anywhere). On 2026-11-09 we probed every OOB circuit with raw
frames sourced from `192.33.255.10N` / `2620:11a:b000:202::10N` and
captured replies on the edges:

- IPv4: **7 of 9 ISPs forward** AS12276-sourced packets; **SoftCom (sjc01)
  and OpenColo (scl04) filter** (BCP38).
- IPv6 (where present): QTS, Comfluent and CoreSite forward; DRT
  inconclusive.

It would not be uniform, it depends on providers never turning on source
filtering, and it splits each flow across two paths. The design above works
the same at every site regardless of ISP filtering. Probe script:
`~/.cache/sfmix-spoof-test/spooftest.py` (AF_PACKET, bypasses local NAT).

## Rollout

1. ~~Remove defaults from management OSPF~~ (done 2026-11-09, fmt01).
2. NetBox: VLAN 202 in "Exchange Fabric VLANs"; prefixes
   `192.33.255.96/27` and `2620:11a:b000:202::/64`; addresses per the table.
3. Fabric: carry VLAN 202 to every site's mgmt-gw port and both edge-gw
   ports (same way as VLAN 200).
4. edge-gws: interface, listen ranges, peer-group, filters, conditional
   defaults. Inert until a mgmt-gw peers. `commit-confirm`.
5. Pilot sfo02, then one site at a time (as the 2026-11-08 firewall
   rollout). Per site:
   - `compare saved` empty; session via an internal path
   - add `eth0.202`, `WAN` group membership, BGP/BFD, fallback statics,
     NAT rules; `commit-confirm`
   - verify: BGP Established to both edges, defaults installed, outbound
     v4 shows `192.33.255.1NN`, v6 from the site `/56` reaches the internet,
     inbound unsolicited connections are dropped
   - **forced fallback test**: shut the BGP neighbors; defaults move to the
     OOB within seconds, DNS/apt/NTP keep working; re-enable
   - confirm, save
6. Template it: add the per-site variables to
   `group_vars/management_router.yml` and the stanzas to the VyOS templates
   (alongside `firewall.j2`).

## Open items

- Alert when a site is on fallback (its BGP sessions to the edges are
  down), e.g. via SNMP BGP4-MIB on the edges.
- Ask DRT whether IPv6 is provisioned for the sfo02 OOB port; ask HE to fix
  fmt01's IPv6 neighbor discovery.
- fmt01 still has its own static `::/0` via HE, which blackholes fmt01's own
  IPv6 until HE is fixed; remove or replace when this design lands there.
- sjc01's VLAN 200 interface is down; it will run on fallback until its
  fabric connection is restored.
