# Underlay IP Fabric Addressing and Flow Export

## Status: Draft / Request for Comment

## Summary

As SFMIX expands from a pure Layer 2 exchange into offering IP routed services (transit via AS 40271), several related design questions have surfaced around IP addressing of the backbone underlay, flow telemetry export, and the relationship between the out-of-band management network and the in-band IP fabric. This document captures the current state, outlines the tensions, and proposes paths forward for group discussion.

## Background

### The OOB-only heritage

Historically, SFMIX has been a Layer 2 exchange. The only routed IP network we operated was the out-of-band (OOB) management network — originally numbered from 100.64.0.0/10 (CGNAT space), and now being renumbered to 10.0.0.0/8 per [Design Doc 001](001-management_ip_renumbering.md).

Because we weren't routing customer traffic through our own infrastructure, there was never a need for an "in-band" or "front-end" IP network with globally routable addresses on router loopbacks and point-to-point links.

### The new transit / IP fabric

With the introduction of the Nokia SR-series transit routers (cr1.sjc01, cr1.scl02, cr1.fmt01) running AS 40271, we now operate an MPLS/RSVP-TE backbone with OSPF/OSPFv3 as the IGP. This backbone carries L3VPN services (FREE and PAID VRFs) for transit customers.

Today, the underlay is addressed with a mix of:

- **Router loopbacks (system interfaces):** 149.112.115.0/24 space (e.g., cr1.sjc01 = 149.112.115.246, cr1.scl02 = 149.112.115.247)
- **Transit peering LAN:** 149.112.115.208/27 (VLAN 1407)
- **Core point-to-point links:** 100.64.50.0/24 remnants (e.g., lag-core-1-10 on cr1.scl02 = 100.64.50.105/31)

Note: this addressing only applies to the new Nokia SR-series transit routers. The existing Arista EOS peering fabric is entirely addressed from 100.64/10 space and does not yet use any globally routable underlay IPs. There is no IPv6 underlay deployed today.

On the Nokia routers, the loopbacks and peering LAN already use globally routable 149.112.115.0/24 ("SFMIX-TRANSIT" PI space), but some point-to-point core links still use 100.64/10 addresses.

## Problem Statement

### 1. Flow export needs in-band reachability

We want to export NetFlow/IPFIX from the transit routers to a flow collector (Akvorado). Flow export requires a source IP on each router that is reachable from the collector, and the collector needs to be able to correlate source IPs to router identities (via DNS, SNMP, etc.).

If the flow collector sits on the OOB management network (10.0.0.0/8), the transit routers would need interfaces in the management routing domain — mixing the OOB network with the in-band backbone. This is undesirable:

- It blurs the security boundary between management and production traffic.
- It creates routing complexity (leaking routes between domains, or maintaining static routes).
- It undermines the purpose of having a dedicated OOB network.

### 2. Traceroute visibility

Now that customer traffic traverses our backbone, traceroutes expose the underlay hop IPs. If those IPs are from 100.64/10 (non-globally-routable CGNAT space), they appear as dark/unresolvable hops. Using globally routable IPs with proper forward and reverse DNS makes traceroutes informative and professional.

### 3. Inconsistent underlay addressing

On the Nokia transit routers, the underlay uses 149.112.115.0/24 for loopbacks and the peering LAN, but still has 100.64/10 remnants on some core point-to-point links. The Arista EOS peering fabric is entirely on 100.64/10. Both should be cleaned up and converged onto a single addressing scheme regardless of which direction we go.

## Proposed Direction

### Keep the OOB management network separate

The 10.0.0.0/8 management network (per Design Doc 001) remains a dedicated OOB network for BMCs, PDUs, management ports, and administrative access. No changes here.

### Establish a "front-end" in-band IP network on the backbone

All transit router interfaces (loopbacks, point-to-points, peering LANs) should be numbered from globally routable PI space with proper forward/reverse DNS. The flow collector should sit in (or be reachable from) this in-band network.

### The addressing question: 149.112.115.0/24 vs. 192.33.255.0/24

This is the core design choice we need group input on.

#### Option A: 149.112.115.0/24 (SFMIX-TRANSIT block)

This is what the loopbacks and peering LAN already use today.

| Pros                                                                                                                    | Cons                                                                                        |
|-------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| Already in use on Nokia routers — but the Arista EOS fabric would still need to be renumbered into this block over time | Semantically "transit" space; using it for infrastructure feels like it muddies the purpose |
| /24 gives 254 usable addresses; room for growth                                                                         | Consumed from the block that could otherwise serve customer/service allocations             |
| Clear separation from the 192.33.255.0/24 "admin" identity                                                              | Requires carving out a well-defined infrastructure sub-allocation within the /24            |
| Naturally associated with AS 40271                                                                                      |                                                                                             |

Current allocations within 149.112.115.0/24:

| Range     | Use                 |
|-----------|---------------------|
| .22-.23   | Valve cache         |
| .160/27   | Apple cache         |
| .208/27   | Transit peering LAN |
| .244-.247 | Router loopbacks    |

#### Option B: 192.33.255.0/24 (SFMIX administrative PI space)

The classic SFMIX identity block, currently used for public services (web, DNS, route servers, hosted tenants).

| Pros                                                                                                | Cons                                                                             |
|-----------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| Feels "correct" — this is SFMIX's own infrastructure, and 192.33.255.0/24 is SFMIX's identity block | Only a /24 — shared with existing service allocations, very tight on space       |
| Router identities would live in the same block as other SFMIX infrastructure                        | Would need to reclaim deprecated/unused allocations to free up room              |
| Single block for all SFMIX-operated infrastructure simplifies policy and filtering                  | Mixing backbone underlay with public services in the same /24 could be confusing |
|                                                                                                     | No room for growth if the backbone expands significantly                         |

Current allocations within 192.33.255.0/24:

| Range  | Use                                            |
|--------|------------------------------------------------|
| .0/28  | SFMIX services (web, mailing list, monitoring) |
| .13    | OpenBSD route server                           |
| .20/30 | Unused (formerly PCH)                          |
| .24/30 | RIPE Atlas                                     |
| .28/30 | RouteViews                                     |
| .32/29 | Verisign DNS                                   |

Several addresses in the .0/28 services block are deprecated and reclaimable, but the total free space is still limited.

#### Option C: Hybrid approach

Use 149.112.115.0/24 for the backbone underlay (loopbacks, point-to-points) since it's already deployed there, and keep 192.33.255.0/24 for non-backbone SFMIX services. The flow collector could live in either block depending on where it's most naturally reachable.

This preserves a clean mental model:
- **10.0.0.0/8** — OOB management (not globally routed)
- **192.33.255.0/24** — SFMIX public services and admin infrastructure (AS 12276)
- **149.112.115.0/24** — SFMIX transit backbone and in-band infrastructure (AS 40271)

### IPv6 considerations

There is no IPv6 underlay deployed today. When IPv6 is added to the backbone, 2620:11a:b002::/48 (carved from the SFMIX-V6-MANAGEMENT /44, 2620:11a:b000::/44) is the natural candidate. The same "front-end vs. OOB" separation should apply: IPv6 underlay and flow export source addresses should come from this /48, not from the management 2620:11a:b00f::/48.

## Flow collector placement

Regardless of which IP block is chosen for the underlay, the flow collector (Akvorado) should:

1. **Listen on an in-band IP** reachable from the transit routers' loopback addresses (the natural flow export source).
2. **Not require routes to be leaked** between the OOB management network and the transit backbone.
3. Have its **ingress interface** on a network segment reachable from the backbone — either directly connected to the transit fabric, or via a server with a leg in both networks (with appropriate firewalling).

A practical deployment would place Akvorado on a host that has:
- An OOB management IP (10.x.x.x) for SSH access and administration
- An in-band IP (from whichever block is chosen) for receiving flow data and SNMP polling of routers

## Action items for discussion

1. **Which IPv4 block for the backbone underlay?** 149.112.115.0/24 (Option A), 192.33.255.0/24 (Option B), or hybrid (Option C)?
2. **Clean up 100.64/10 remnants** on core point-to-point links — renumber to the chosen block.
3. **Define a sub-allocation plan** within the chosen block for loopbacks, point-to-points, peering LANs, and infrastructure services (flow collector, etc.).
4. **Forward/reverse DNS** for all underlay IPs.
5. **Flow collector deployment**: confirm host placement and dual-homed (OOB + in-band) connectivity model.

## Author's leaning

Option C (hybrid) seems like the path of least resistance and clearest mental model. The 149.112.115.0/24 space is already deployed on the transit router loopbacks and peering LAN, it's associated with AS 40271, and it has room for the point-to-point renumbering plus a flow collector address. Keeping 192.33.255.0/24 for SFMIX's public-facing services (AS 12276) avoids overloading a small /24 with backbone infrastructure duties.

The key remaining work would be:
- Renumber the 100.64.50.x core point-to-point links into 149.112.115.0/24
- Assign a flow collector IP from 149.112.115.0/24
- Set up forward/reverse DNS for all underlay addresses
- Configure NetFlow/IPFIX export from the Nokia routers toward the collector
