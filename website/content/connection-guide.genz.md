---
title: "how to pull up 🔌"
layout: "video-header"
video: "video/connection-guide-bg.mp4"
mobile_image: "img/mobile-fiber-cables.jpg"
---

<p class="lead">wanna connect to SFMIX? say less, here's how. 🚀</p>

## overview

1. peep the pricing and requirements below 👀
2. email [tech-c@sfmix.org](mailto:tech-c@sfmix.org) with your desired speed and [location](/locations/); we'll confirm port availability

   > **tip:** use subject "New Connection Request – [Your Org Name]" and include your PeeringDB URL, desired speed, and preferred location. we usually hit you back within 1–2 business days. bet 🤝
3. fill out the [membership application](https://goo.gl/forms/fiqOIjCP7QHYUG3i1)
4. SFMIX issues an LOA/CFA for you to order a cross-connect with the datacenter operator
5. SFMIX hooks you up with your IPv4 and IPv6 addresses
6. your circuit gets connected to a **quarantine VLAN** — a safe spot to bring up your link and validate config before touching production (lowkey hella clutch 🧪)
7. once you're ready, SFMIX moves your port to the production peering VLAN
8. start peering! bet 🎉

## administrative requirements

### pricing 💸

{{< pricing >}}

### billing

- annual billing (calendar year); no monthly option
- USD only
- payment (preferred order): ACH, wire, check, credit card

## logistical requirements

- at least one rep has gotta subscribe to the [sfmix-members mailing list](https://lists.sfmix.org/postorius/lists/sfmix-members.lists.sfmix.org/). role accounts encouraged. email [tech-c@sfmix.org](mailto:tech-c@sfmix.org) to subscribe.
- mailing list discussions stay confidential to participants, members, and sponsors. don't be a snitch 🤐.
- SFMIX is volunteer-run. all services are best-effort; no SLA is implied. we do hella what we can fr.
- participants may peer at a single location only, regardless of port count. SFMIX is a peering fabric, not a transport network. stay in your lane 🛣️.
- no ARP/ICMPv6 spoofing or traffic sniffing. that's a red flag, don't do it 🚩.

## technical requirements

- **SMF only** — no copper or MMF. we don't do that here.
- a public RIR-assigned ASN is required ([RFC 1930](https://datatracker.ietf.org/doc/html/rfc1930), [RFC 6996](https://datatracker.ietf.org/doc/html/rfc6996)). no private ASNs.
- a maintained [PeeringDB](https://peeringdb.org/) entry is required. keep it fresh ✨.
- **one MAC address per logical link.** port security allows 2 MACs temporarily for router migrations, but only 1 long-term.
- **allowed broadcast:** ARP and ICMPv6 ND only. no RAs, CDP, DHCP, or STP.
- **LLDP:** SFMIX transmits LLDP on all participant ports, including optical receive power levels. participants may transmit LLDP but aren't required to.
- **BGP session with the [looking glass](/looking-glass/) is mandatory.** it's used only for debugging — no routes are redistributed, no traffic exchanged. non-negotiable, no cap 🔭.
- do not propagate SFMIX peering subnets (206.197.187.0/24, 2001:504:30::/64) beyond your edge router. use ACLs if needed.
- no static or default routes toward other participants or SFMIX resources without permission. ask first 🙏.
- [route server](/route-servers/) peering is encouraged but not required.

## LLDP & optical power monitoring 💡

SFMIX switches transmit [LLDP](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol) on every participant port. on top of standard LLDP info (system name, port description), each frame includes the optical receive power measured by the SFMIX-side transceiver, encoded as an [LLDP-MED](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol#LLDP-MED) Inventory TLV.

this lets you see — straight from your own router — how well your transmit light is landing at the SFMIX switch, without needing to ping us for support. self-service W 🏆.

### what's advertised

the LLDP-MED Asset ID field carries the receive power in dBm:

- **single-lane optics example:** `dBm:-2.05`
- **multi-lane optics example:** `dBm:-7.60/-8.20/-6.79/-6.52` (one value per lane)

### viewing the data

on **Arista EOS**:

```
switch# show lldp neighbors Ethernet1 detail | grep 'Asset ID'
  - LLDP-MED Inventory Asset ID TLV: "dBm:-2.05"
```

on **Linux** (lldpd):

```
$ lldpcli show neighbors
  LLDP-MED:
    Inventory:
      Asset ID:     dBm:-2.05
```

on **Juniper Junos**:

```
user@router> show lldp neighbors interface xe-0/0/0
```

on other platforms, look for LLDP-MED Inventory or organizationally-defined TLVs with OUI `00:12:BB`, subtype 11.

### interpreting the values

the power values represent what the SFMIX transceiver is receiving from your side. if you see values dropping toward the transceiver's receiver sensitivity threshold (typically around −14 dBm for LR4, −22 dBm for ER4), your fiber plant might need some attention. a value of `dBm:-40.00` or the absence of an Asset ID TLV means no light is detected — that's an L 💀, check your stuff.

optical power via LLDP is currently supported on Arista edge ports only, which covers basically all peering ports today. the agent that injects this data is open source: [LldpDomAgent on GitHub](https://github.com/sfmix/sfmix/blob/main/scripts/arista_eos/LldpDomAgent).
