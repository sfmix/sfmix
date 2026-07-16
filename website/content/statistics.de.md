---
title: "Statistiken & Looking Glass"
aliases: ["/looking-glass/"]
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

## Looking Glass

Alle Teilnehmer sind verpflichtet, mit dem SFMIX Looking Glass zu peeren. Es erfüllt mehrere Zwecke:

- Überprüfung Ihrer Router-Konfiguration bei der ersten Verbindung
- Testen von Konfigurationsänderungen gegenüber einem risikoarmen Peer, mit einer Selbstbedienungsansicht dessen, was das LG von Ihnen sieht
- Öffentliche Einsicht in die am Internet-Knoten vorhandenen Präfixe
- Schnelle Erreichbarkeitsprüfung für SFMIX-Betreiber

## Quarantäne-VLAN

Ein paralleles Looking Glass läuft im Quarantäne-VLAN mit denselben Adressen wie in der Produktion. Neue Teilnehmer können ihre Ethernet-, IP- und BGP-Konfiguration sicher testen, bevor sie dem produktiven Peering-LAN beitreten.

## BGP-Verbindungsinformationen

| Parameter | Wert |
|-----------|-------|
| ASN | 12276 |
| IPv4 | 206.197.187.1 |
| IPv6 | 2001:504:30::ba01:2276:1 |

## Route-Browser

SFMIX betreibt [Alice LG](https://github.com/alice-lg/alice-lg) als Route-Browser — eine einheitliche Oberfläche für Routing-Informationen von Looking Glass und Route-Server.

**[alice.sfmix.org](https://alice.sfmix.org/)**
