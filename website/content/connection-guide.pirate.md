---
title: "Boardin' Guide"
layout: "video-header"
video: "video/connection-guide-bg.mp4"
mobile_image: "img/mobile-fiber-cables.jpg"
---

<p class="lead">Keen to climb aboard SFMIX? Here be how.</p>

## Overview

1. Review pricing an' requirements below
2. Email [tech-c@sfmix.org](mailto:tech-c@sfmix.org) with yer desired speed an' [location](/locations/); we'll confirm port availability

   > **Tip:** Use th' subject "New Connection Request – [Your Org Name]" an' include yer PeeringDB URL, desired speed, an' preferred location. We typically respond within 1–2 business days.

3. Complete th' [Membership Application](https://goo.gl/forms/fiqOIjCP7QHYUG3i1)
4. SFMIX issues an LOA/CFA for ye to order a cross-connect with th' datacenter operator
5. SFMIX allocates yer IPv4 an' IPv6 addresses
6. Yer circuit be connected to a **Quarantine VLAN** — a safe harbor to bring up yer link an' validate configuration before touchin' production
7. Once ready, SFMIX moves yer port to th' production peering VLAN
8. Start peering, ye scurvy dog!

## Administrative Requirements

### Pricing

{{< pricing >}}

### Billing

- Annual billing (calendar year); no monthly option
- USD only
- Payment (preferred order): ACH, wire, check, credit card

## Logistical Requirements

- At least one representative must subscribe to th' [sfmix-members mailing list](https://lists.sfmix.org/postorius/lists/sfmix-members.lists.sfmix.org/). Role accounts encouraged. Email [tech-c@sfmix.org](mailto:tech-c@sfmix.org) to subscribe.
- Mailing list discussions be confidential to mateys, members, an' sponsors.
- SFMIX be volunteer-run. All services be best-effort; no SLA be implied.
- Mateys may peer at a single location only, regardless o' port count. SFMIX be a peering fabric, not a transport network.
- No ARP/ICMPv6 spoofing nor traffic sniffing, ye scallywags.

## Technical Requirements

- **SMF only** — no copper or MMF.
- A public RIR-assigned ASN be required ([RFC 1930](https://datatracker.ietf.org/doc/html/rfc1930), [RFC 6996](https://datatracker.ietf.org/doc/html/rfc6996)). No private ASNs.
- A maintained [PeeringDB](https://peeringdb.org/) entry be required.
- **One MAC address per logical link.** Port security allows 2 MACs temporarily for router migrations, but only 1 long-term.
- **Allowed broadcast:** ARP an' ICMPv6 ND only. No RAs, CDP, DHCP, or STP.
- **LLDP:** SFMIX transmits LLDP on all matey ports, includin' optical receive power levels. Mateys may transmit LLDP but be not required to.
- **BGP session with th' [Looking Glass](/looking-glass/) be mandatory.** It be used only for debugging — no routes be redistributed, no traffic exchanged.
- Do not propagate SFMIX peering subnets (206.197.187.0/24, 2001:504:30::/64) beyond yer edge router. Use ACLs if needed.
- No static or default routes toward other mateys or SFMIX resources without permission.
- [Route server](/route-servers/) peering be encouraged but not required.

## LLDP & Optical Power Monitoring

SFMIX switches transmit [LLDP](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol) on every matey port. In addition to standard LLDP information (system name, port description), each frame includes th' optical receive power measured by th' SFMIX-side transceiver, encoded as an [LLDP-MED](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol#LLDP-MED) Inventory TLV.

This lets ye see — from yer own router — how well yer transmit light be arrivin' at th' SFMIX switch, without needin' to engage us for support.

### What's advertised

Th' LLDP-MED Asset ID field carries th' receive power in dBm:

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

Th' power values represent what th' SFMIX transceiver be receivin' from yer side. If ye see values droppin' toward th' transceiver's receiver sensitivity threshold (typically around −14 dBm for LR4, −22 dBm for ER4), yer fiber plant may need attention. A value o' `dBm:-40.00` or th' absence o' an Asset ID TLV means no light be detected.

Optical power via LLDP be currently supported on Arista edge ports only, which covers essentially all peering ports today. Th' agent that injects this data be open source: [LldpDomAgent on GitHub](https://github.com/sfmix/sfmix/blob/main/scripts/arista_eos/LldpDomAgent).
