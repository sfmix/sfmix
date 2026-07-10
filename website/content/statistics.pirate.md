---
title: "Tallies"
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-sf-night.jpg"
---

## Public Grafana Dashboards

SFMIX uses sFlow to sample th' exchange's traffic metadata, includin' peer-to-peer volume tallies. Packet payloads be never captured nor inspected, ye have me word. Th' stack be sFlow-RT, Prometheus, an' [Grafana](https://grafana.com/).

<div class="stat-cta-grid">

{{< stat-card icon="📈" url="https://grafana.sfmix.org/public-dashboards/7dedd014679f4c798124748a24e9f5ef" title="Overall Traffic Dashboard" desc="All th' exchange's throughput, high tides, an' tallies o' voyages past." >}}

{{< stat-card icon="🗺️" url="/weathermap/" external="false" title="Traffic Weathermap" desc="Live load on ev'ry line across th' SFMIX riggin'." >}}

{{< stat-card icon="🚇" url="/pirate/network-map/" external="false" title="Interactive Chart o' th' Network" desc="A subway-style chart o' th' riggin', coloured by live traffic. Zoom from th' metros down to th' berths." >}}

</div>
