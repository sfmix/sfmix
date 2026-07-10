---
title: "stats 📊"
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
