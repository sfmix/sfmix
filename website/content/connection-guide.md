---
title: "Connection Guide"
url: "/connection-guide/"
layout: "video-header"
video: "video/connection-guide-bg.mp4"
mobile_image: "img/mobile-fiber-cables.jpg"
---

<p class="lead">Want to connect to SFMIX? Here's how.</p>

## Overview

1. Review pricing and requirements below
2. Email [tech-c@sfmix.org](mailto:tech-c@sfmix.org) with your desired speed and [location](/locations/); we'll confirm port availability
3. Complete the [Membership Application](https://goo.gl/forms/fiqOIjCP7QHYUG3i1)
4. SFMIX issues an LOA/CFA for you to order a cross-connect with the datacenter operator
5. SFMIX allocates your IPv4 and IPv6 addresses
6. Your circuit is connected to a **Quarantine VLAN** — a safe environment to bring up your link and validate configuration before touching production
7. Once ready, SFMIX moves your port to the production peering VLAN
8. Start peering!

## Administrative Requirements

### Pricing

Annual membership fees (as of 2023):

- **$995/year** — 1Gbps port (prefer 10G with rate limit over multiple 1G ports)
- **$2,995/year** — 10Gbps port (up to 4 in a LAG)
- **$7,495/year** — 100Gbps port (no LAG limit)

Fee exemptions are considered case-by-case for non-profits contributing in-kind services (e.g., root DNS, ccTLD/gTLD, public measurement tools). Contact [tech-c@sfmix.org](mailto:tech-c@sfmix.org).

### Billing

- Annual billing (calendar year); no monthly option
- USD only
- Payment (preferred order): ACH, wire, check, credit card

## Logistical Requirements

- At least one representative must subscribe to the [sfmix-members mailing list](https://lists.sfmix.org/postorius/lists/sfmix-members.lists.sfmix.org/). Role accounts encouraged. Email [tech-c@sfmix.org](mailto:tech-c@sfmix.org) to subscribe.
- Mailing list discussions are confidential to participants, members, and sponsors.
- SFMIX is volunteer-run. All services are best-effort; no SLA is implied.
- Participants may peer at a single location only, regardless of port count. SFMIX is a peering fabric, not a transport network.
- No ARP/ICMPv6 spoofing or traffic sniffing.

## Technical Requirements

- **SMF only** — no copper or MMF.
- A public RIR-assigned ASN is required ([RFC 1930](https://datatracker.ietf.org/doc/html/rfc1930), [RFC 6996](https://datatracker.ietf.org/doc/html/rfc6996)). No private ASNs.
- A maintained [PeeringDB](https://peeringdb.org/) entry is required.
- **One MAC address per logical link.** Port security allows 2 MACs temporarily for router migrations, but only 1 long-term.
- **Allowed broadcast:** ARP and ICMPv6 ND only. No RAs, CDP, LLDP, DHCP, or STP.
- **BGP session with the [Looking Glass](/looking-glass/) is mandatory.** It is used only for debugging — no routes are redistributed, no traffic exchanged.
- Do not propagate SFMIX peering subnets (206.197.187.0/24, 2001:504:30::/64) beyond your edge router. Use ACLs if needed.
- No static or default routes toward other participants or SFMIX resources without permission.
- [Route server](/route-servers/) peering is encouraged but not required.
