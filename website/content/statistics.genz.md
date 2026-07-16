---
title: "stats & looking glass 📊🔭"
aliases: ["/looking-glass/"]
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-sf-night.jpg"
---

## live stats & maps 📊

SFMIX uses sFlow to sample exchange traffic metadata, including peer-to-peer volume metrics. packet payloads are never captured or inspected (we're not nosy 🤫). traffic gets collected with sFlow-RT and Prometheus, and you can vibe with it through our live dashboards and interactive maps.

<div class="stat-cta-grid">

{{< stat-card icon="📈" url="https://portal.sfmix.org/statistics/" title="overall traffic dashboard" desc="the exchange's total throughput, peaks, and history — no cap 📊" >}}

{{< stat-card icon="🗺️" url="/genz/weathermap/" external="false" title="traffic weathermap" desc="the classic weathermap but rebuilt: every backbone link color-coded by live usage. pan, zoom, tap any link for the rates + a 24h graph, it's giving realtime 🔥" >}}

{{< stat-card icon="🚇" url="/genz/network-map/" external="false" title="interactive network map 🚇" desc="a subway-style map of the fabric, colored by live traffic. zoom from metros all the way down to sites, fr 🔥" >}}

</div>

## looking glass 🔭

all participants gotta peer with the SFMIX looking glass. it pulls hella weight in a few ways:

- validate your router config when you first connect ✅
- test config changes against a low-impact peer with a self-service view of what the LG sees from you
- public visibility into what prefixes are present at the exchange (the receipts 🧾)
- quick reachability check for SFMIX operators

## quarantine VLAN 🧪

a parallel looking glass runs on the quarantine VLAN with the same addresses as production. new participants can test their ethernet, IP, and BGP config safely before joining the production peering LAN. no pressure, practice round.

## BGP connection info

| Parameter | Value |
|-----------|-------|
| ASN | 12276 |
| IPv4 | 206.197.187.1 |
| IPv6 | 2001:504:30::ba01:2276:1 |

## route browser 🗺️

SFMIX runs [Alice LG](https://github.com/alice-lg/alice-lg) as a route browser — one interface for looking glass and route server routing info. one-stop shop, bet 🤝.

**[alice.sfmix.org](https://alice.sfmix.org/)**
