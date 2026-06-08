---
title: "Looking Glass"
url: "/looking-glass/"
layout: "video-header"
video: "video/participants-bg.mp4"
mobile_image: "img/mobile-fiber-light.jpg"
---

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
