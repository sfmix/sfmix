---
title: "Statistics"
url: "/statistics/"
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-sf-night.jpg"
---

## Live Statistics & Maps

SFMIX uses sFlow to sample exchange traffic metadata, including peer-to-peer volume metrics. Packet payloads are never captured or inspected. Traffic is collected with sFlow-RT and Prometheus, and you can explore it two ways: through our own interactive live maps, or through the public [Grafana](https://grafana.com/) dashboards.

<div class="stat-cta-grid">

{{< stat-card icon="📈" url="https://grafana.sfmix.org/public-dashboards/7dedd014679f4c798124748a24e9f5ef" title="Overall Traffic Dashboard" desc="Aggregate exchange throughput, peaks, and historical trends." >}}

{{< stat-card icon="🗺️" url="/weathermap/" external="false" title="Traffic Weathermap" desc="The classic weathermap, rebuilt: every backbone link coloured by live utilization. Pan, zoom, and click any link for rates and a 24-hour graph." >}}

{{< stat-card icon="🚇" url="/network-map/" external="false" title="Interactive Network Map" desc="A subway-style map of the fabric, coloured by live traffic. Zoom from metros to sites." >}}

</div>
