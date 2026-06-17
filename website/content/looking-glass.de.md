---
title: "Looking Glass"
layout: "video-header"
video: "video/participants-bg.mp4"
mobile_image: "img/mobile-fiber-light.jpg"
---

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
