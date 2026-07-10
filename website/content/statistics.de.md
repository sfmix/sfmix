---
title: "Statistiken"
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-sf-night.jpg"
---

## Öffentliche Grafana-Dashboards

SFMIX verwendet sFlow, um Metadaten zum Datenverkehr des Internet-Knotens zu erfassen, einschließlich Volumenkennzahlen zwischen einzelnen Teilnehmern. Paketinhalte werden niemals erfasst oder inspiziert. Der Stack besteht aus sFlow-RT, Prometheus und [Grafana](https://grafana.com/).

<div class="stat-cta-grid">

{{< stat-card icon="📈" url="https://grafana.sfmix.org/public-dashboards/7dedd014679f4c798124748a24e9f5ef" title="Dashboard zum Gesamtverkehr" desc="Gesamtdurchsatz des Knotens, Spitzenwerte und historische Trends." >}}

{{< stat-card icon="🗺️" url="/weathermap/" external="false" title="Verkehrs-Weathermap" desc="Live-Auslastung je Verbindung im SFMIX-Switch-Fabric." >}}

{{< stat-card icon="🚇" url="/de/network-map/" external="false" title="Interaktive Netzwerkkarte" desc="Eine U-Bahn-artige Karte des Fabrics, eingefärbt nach Live-Datenverkehr. Zoomen Sie von Metropolregionen bis zu einzelnen Standorten." >}}

</div>
