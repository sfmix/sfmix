# Management Network: IP Renumbering

## Background

Historically, SFMIX has maintained an internal routed IP network for management of devices that make up SFMIX. 

With a single site, the topology was quite simple and all devices were connected to a single LAN, and utilized RFC 1918 space <sup>[citation needed]</sup>.

Over time, as additional sites were added, the need for connectivity between sites and from the outside was identified. As part of that multi-site transition (around 2013? 2014?), the then-relatively-new Carrier-grade NAT IP space (100.64.0.0/10, [RFC 6890](https://datatracker.ietf.org/doc/html/rfc6890)) was identified as a useful renumbering target, as it was very unlikely to conflict with home and office internal IP space (which could be problematic for the use case of directly connecting from the outside using a VPN).

Ever since, SFMIX has been growing to more and more locations and utilizing more and more portions of the 100.64.0.0/10 IP space.

## Current State

Currently, most access is mediated by SSH tunnels, Teleport, and in some cases a VPN client. As we have moved management router platforms over time, the support for various VPN technologies has been shifting, and we haven't maintained a consistent configuration that can be reliably used to reach all of the sites.

A growing internal desire and sentiment has been building with an eye towards re-enabling the remote-access VPN use case, as we have a handful of internal resources which are best connected to with a VPN. For example: Supermicro BMCs, ServerTech PDUs, and the Proxmox PVE administration interface.

No IPv6 space is in use in the management network.

## Proposed Solution

In order to make the VPN experience more consistent and without complex, per-user configuration overhead, we would like to enable the use of a modern software-defined overlay VPN network. A prime target of this desire is [Tailscale](https://tailscale.com/), as it seamlessly supports clients across all major platforms and enables a zero-configuration VPN experience.

However, the use of Tailscale conflicts with our existing IP numbering scheme and use of 100.64.0.0/10. Tailscale internally [claims the use of this entire /10 of IP space to enable unique addressing of participants in each Tailnet.](https://tailscale.com/kb/1015/100.x-addresses)

To enable the use of Tailscale, we would need to renumber our internal IP space to something else. While RFC 1918 space may still overlap with home networks, Tailscale has some helpful client-side support to enable remotely-routed subnets with conflicting IP space to still be routed correctly.

Since SFMIX now [assigns some numerical identifiers to sites and locations](https://sfmix.org/locations/), it seems like a natural fit that we could extend that mental model to the addressing of management IP space as well.
Since it enables the use of networks with the fewest number of network bits set, 10.0.0.0/8 seems like a natural fit.

Explicitly out-of-scope for this renumbering would be the "in-band" IP space used to internally build the exchange fabric. This also uses portions of 100.64.0.0/10, and leaving this addressing as-is will help to create a clear mnemonic separation between the routing domains. The "in-band" network IP space is not currently routed from the management network (and it is intended to keep this the case)

Additionally, we should assign some globally unique unicast IPv6 space, where appropriate. Of the existing `SFMIX-V6-MANAGEMENT` PI space (2620:11a:b000::/44), 2620:11a:b000::/48 is currently assigned to the public services and resources.

In order to leave some room for those public services to grow, we should number the internal management network from the end of the public PI space.

## Proposed Renumbering Plan

### IPv4

10.0.0.0/11 (10.0.0.0 - 10.31.255.255) will be assigned to the management network.

A /16 of space from the management network /11 will be assigned to each site, and a /24 of that site-specific /16 will be assigned to the management LAN.



| LAN   | Location ID number | Current IP Space | Proposed IP Space |
|-------|--------------------|------------------|-------------------|
| sfo01 | 0                  | 100.64.2.0/24    | 10.0.1.0/24       |
| sfo02 | 1                  | 100.64.0.0/24    | 10.1.1.0/24       |
| fmt01 | 2                  | 100.64.1.0/24    | 10.2.1.0/24       |
| sjc01 | 3                  | 100.64.5.0/24    | 10.3.1.0/24       |
| scl01 | 4                  | 100.64.4.0/24    | 10.4.1.0/24       |
| scl02 | 5                  | 100.64.6.0/24    | 10.5.1.0/24       |
| scl04 | 6                  | 100.64.7.0/24    | 10.6.1.0/24       |

### IPv6

2620:11a:b00f::/48 will be assigned to the management network. While we globally route the /44, this /48 should remain distinct and unrouted from the default-free zone / Internet.

A /56 of space from the management network /48 will be assigned to each site, and a /64 of that site-specific /56 will be assigned to the management LAN.

The site location numerical identifiers will be encoded in a decimalized form in 7th byte (bits 48-56), and then site-specific LAN /64s can be numbered in the 8th byte (bits 56-64).

| LAN   | Location ID number | Proposed IP Space       |
|-------|--------------------|-------------------------|
| sfo01 | 0                  | 2620:11a:b00f:0001::/64 |
| sfo02 | 1                  | 2620:11a:b00f:0101::/64 |
| fmt01 | 2                  | 2620:11a:b00f:0201::/64 |
| sjc01 | 3                  | 2620:11a:b00f:0301::/64 |
| scl01 | 4                  | 2620:11a:b00f:0401::/64 |
| scl02 | 5                  | 2620:11a:b00f:0501::/64 |
| scl04 | 6                  | 2620:11a:b00f:0601::/64 |

## Proposed Rollout Plan

The renumbering could happen in phases:

1. Configure IPv6 addressing on management LANs, and add OSPFv3 over the existing management paths to stitch the management network together with an IGP
1. Configure parallel IPv4 subnets on management routers, adjacent to existing 100.64.0.0/10 space. Ensure the IP space is routed over the existing OSPF IGP.
1. On a site-by-site basis, renumber devices using DHCP and static leases. Update DNS records as devices are renumbered.
