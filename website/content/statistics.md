---
title: "Statistics & Looking Glass"
url: "/statistics/"
aliases: ["/looking-glass/"]
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-sf-night.jpg"
---

## Live Statistics & Maps

SFMIX uses sFlow to sample exchange traffic metadata, including peer-to-peer volume metrics. Packet payloads are never captured or inspected. Traffic is collected with sFlow-RT and Prometheus, and you can explore it through our live dashboards and interactive maps.

<div class="stat-cta-grid">

{{< stat-card icon="📈" url="https://portal.sfmix.org/statistics/" title="Overall Traffic Dashboard" desc="Aggregate exchange throughput, peaks, and historical trends." >}}

{{< stat-card icon="🗺️" url="/weathermap/" external="false" title="Traffic Weathermap" desc="The classic weathermap, rebuilt: every backbone link coloured by live utilization. Pan, zoom, and click any link for rates and a 24-hour graph." >}}

{{< stat-card icon="🚇" url="/network-map/" external="false" title="Interactive Network Map" desc="A subway-style map of the fabric, coloured by live traffic. Zoom from metros to sites." >}}

</div>

## Looking Glass

All participants are required to peer with the SFMIX Looking Glass. It serves several purposes:

- Validate your router configuration when first connecting
- Test configuration changes against a low-impact peer with a self-service view of what the LG sees from you
- Public visibility into what prefixes are present at the exchange
- Quick reachability check for SFMIX operators

## Quarantine VLAN

A parallel Looking Glass runs on the Quarantine VLAN with the same addresses as production. New participants can test their Ethernet, IP, and BGP configuration safely before joining the production peering LAN.

## BGP Connection Information

| Parameter | Value |
|-----------|-------|
| ASN | 12276 |
| IPv4 | 206.197.187.1 |
| IPv6 | 2001:504:30::ba01:2276:1 |

## Route Browser

SFMIX runs [Alice LG](https://github.com/alice-lg/alice-lg) as a Route Browser — a single interface for Looking Glass and Route Server routing information.

**[alice.sfmix.org](https://alice.sfmix.org/)**
