---
title: "Tallies & Looking Glass"
aliases: ["/looking-glass/"]
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-sf-night.jpg"
---

## Live Tallies & Charts

SFMIX uses sFlow to sample th' exchange's traffic metadata, includin' peer-to-peer volume tallies. Packet payloads be never captured nor inspected, ye have me word. Th' traffic be gathered with sFlow-RT an' Prometheus, an' ye can survey it on our own live dashboards an' interactive charts.

<div class="stat-cta-grid">

{{< stat-card icon="📈" url="https://portal.sfmix.org/statistics/" title="Overall Traffic Dashboard" desc="All th' exchange's throughput, high tides, an' tallies o' voyages past." >}}

{{< stat-card icon="🗺️" url="/pirate/weathermap/" external="false" title="Traffic Weather Chart" desc="Th' classic weather chart, rebuilt: ev'ry line o' th' riggin' coloured by its live load. Pan about, zoom in, an' click any line fer its tallies an' a day's log." >}}

{{< stat-card icon="🚇" url="/pirate/network-map/" external="false" title="Interactive Chart o' th' Network" desc="A subway-style chart o' th' riggin', coloured by live traffic. Zoom from th' metros down to th' berths." >}}

</div>

## Looking Glass

All mateys be required to peer with th' SFMIX Looking Glass. It serves several purposes:

- Validate yer router configuration when ye first climb aboard
- Test configuration changes against a low-impact peer with a self-service view o' what th' LG spies from ye
- Public visibility into what prefixes be present at th' exchange
- Quick reachability check for th' SFMIX crew

## Quarantine VLAN

A parallel Looking Glass runs on th' Quarantine VLAN with th' same addresses as production. New mateys can test their Ethernet, IP, an' BGP configuration safely before joinin' th' production peering LAN.

## BGP Connection Information

| Parameter | Value |
|-----------|-------|
| ASN | 12276 |
| IPv4 | 206.197.187.1 |
| IPv6 | 2001:504:30::ba01:2276:1 |

## Route Browser

SFMIX runs [Alice LG](https://github.com/alice-lg/alice-lg) as a Route Browser — a single helm for Looking Glass an' Route Server routing information.

**[alice.sfmix.org](https://alice.sfmix.org/)**
