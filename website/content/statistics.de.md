---
title: "Statistiken"
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-sf-night.jpg"
---

## Live-Statistiken & Karten

SFMIX verwendet sFlow, um Metadaten zum Datenverkehr des Internet-Knotens zu erfassen, einschließlich Volumenkennzahlen zwischen einzelnen Teilnehmern. Paketinhalte werden niemals erfasst oder inspiziert. Der Datenverkehr wird mit sFlow-RT und Prometheus gesammelt und lässt sich über unsere Live-Dashboards und interaktiven Karten erkunden.

<div class="stat-cta-grid">

{{< stat-card icon="📈" url="https://portal.sfmix.org/statistics/" title="Dashboard zum Gesamtverkehr" desc="Gesamtdurchsatz des Knotens, Spitzenwerte und historische Trends." >}}

{{< stat-card icon="🗺️" url="/de/weathermap/" external="false" title="Verkehrs-Wetterkarte" desc="Die klassische Wetterkarte, neu gebaut: jede Backbone-Verbindung nach Live-Auslastung eingefärbt. Verschieben, zoomen und jede Verbindung anklicken für Raten und einen 24-Stunden-Graphen." >}}

{{< stat-card icon="🚇" url="/de/network-map/" external="false" title="Interaktive Netzwerkkarte" desc="Eine U-Bahn-artige Karte des Fabrics, eingefärbt nach Live-Datenverkehr. Zoomen Sie von Metropolregionen bis zu einzelnen Standorten." >}}

</div>
