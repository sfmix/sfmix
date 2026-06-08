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

   > **Tip:** Use subject "New Connection Request – [Your Org Name]" and include your PeeringDB URL, desired speed, and preferred location. We typically respond within 1–2 business days.

3. Complete the [Membership Application](https://goo.gl/forms/fiqOIjCP7QHYUG3i1)
4. SFMIX issues an LOA/CFA for you to order a cross-connect with the datacenter operator
5. SFMIX allocates your IPv4 and IPv6 addresses
6. Your circuit is connected to a **Quarantine VLAN** — a safe environment to bring up your link and validate configuration before touching production
7. Once ready, SFMIX moves your port to the production peering VLAN
8. Start peering!

## Administrative Requirements

### Pricing

Annual membership fees (as of 2023):

Fees are charged per capacity tier. Existing 1G ports remain supported.

- **$2,995/year** — 10Gbps capacity (up to 4 ports in a LAG)
- **$7,495/year** — 100Gbps capacity (no LAG limit)

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
- **Allowed broadcast:** ARP and ICMPv6 ND only. No RAs, CDP, DHCP, or STP.
- **LLDP:** SFMIX transmits LLDP on all participant ports, including optical receive power levels. Participants may transmit LLDP but are not required to.
- **BGP session with the [Looking Glass](/looking-glass/) is mandatory.** It is used only for debugging — no routes are redistributed, no traffic exchanged.
- Do not propagate SFMIX peering subnets (206.197.187.0/24, 2001:504:30::/64) beyond your edge router. Use ACLs if needed.
- No static or default routes toward other participants or SFMIX resources without permission.
- [Route server](/route-servers/) peering is encouraged but not required.

## LLDP & Optical Power Monitoring

SFMIX switches transmit [LLDP](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol) on every participant port. In addition to standard LLDP information (system name, port description), each frame includes the optical receive power measured by the SFMIX-side transceiver, encoded as an [LLDP-MED](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol#LLDP-MED) Inventory TLV.

This lets you see — from your own router — how well your transmit light is arriving at the SFMIX switch, without needing to engage us for support.

### What's advertised

The LLDP-MED Asset ID field carries the receive power in dBm:

- **Single-lane optics example:** `dBm:-2.05`
- **Multi-lane optics example:** `dBm:-7.60/-8.20/-6.79/-6.52` (one value per lane)

### Viewing the data

On **Arista EOS**:

```
switch# show lldp neighbors Ethernet1 detail | grep 'Asset ID'
  - LLDP-MED Inventory Asset ID TLV: "dBm:-2.05"
```

On **Linux** (lldpd):

```
$ lldpcli show neighbors
  LLDP-MED:
    Inventory:
      Asset ID:     dBm:-2.05
```

On **Juniper Junos**:

```
user@router> show lldp neighbors interface xe-0/0/0
```

On other platforms, look for LLDP-MED Inventory or organizationally-defined TLVs with OUI `00:12:BB`, subtype 11.

### Interpreting the values

The power values represent what the SFMIX transceiver is receiving from your side. If you see values dropping toward the transceiver's receiver sensitivity threshold (typically around −14 dBm for LR4, −22 dBm for ER4), your fiber plant may need attention. A value of `dBm:-40.00` or the absence of an Asset ID TLV means no light is detected.

Optical power via LLDP is currently supported on Arista edge ports only, which covers essentially all peering ports today. The agent that injects this data is open source: [LldpDomAgent on GitHub](https://github.com/sfmix/sfmix/blob/main/scripts/arista_eos/LldpDomAgent).
