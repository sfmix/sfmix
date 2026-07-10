---
title: "Statistics"
url: "/statistics/"
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-sf-night.jpg"
---

## Public Grafana Dashboards

SFMIX uses sFlow to sample exchange traffic metadata, including peer-to-peer volume metrics. Packet payloads are never captured or inspected. The stack is sFlow-RT, Prometheus, and [Grafana](https://grafana.com/).

<div class="stat-cta-grid">

{{< stat-card icon="📈" url="https://grafana.sfmix.org/public-dashboards/7dedd014679f4c798124748a24e9f5ef" title="Overall Traffic Dashboard" desc="Aggregate exchange throughput, peaks, and historical trends." >}}

{{< stat-card icon="🗺️" url="/weathermap/" external="false" title="Traffic Weathermap" desc="Live per-link utilization across the SFMIX switch fabric." >}}

{{< stat-card icon="🚇" url="/network-map/" external="false" title="Interactive Network Map" desc="A subway-style map of the fabric, coloured by live traffic. Zoom from metros to sites." >}}

</div>
