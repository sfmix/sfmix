---
title: "Looking Glass"
layout: "video-header"
video: "video/participants-bg.mp4"
mobile_image: "img/mobile-fiber-light.jpg"
---

## Looking Glass

All mateys be required to peer with th' SFMIX Looking Glass. It serves several purposes:

- Validate yer router configuration when ye first climb aboard
- Test configuration changes against a low-impact peer with a self-service view o' what th' LG spies from ye
- Public visibility into what prefixes be present at th' exchange
- Quick reachability check for th' SFMIX crew

## Quarantine VLAN

A parallel Looking Glass runs on th' Quarantine VLAN with th' same addresses as production. New mateys can test their Ethernet, IP, an' BGP configuration safely before joinin' th' production peering LAN.

## BGP Connection Information

| Parameter | Value |
|-----------|-------|
| ASN | 12276 |
| IPv4 | 206.197.187.1 |
| IPv6 | 2001:504:30::ba01:2276:1 |

## Route Browser

SFMIX runs [Alice LG](https://github.com/alice-lg/alice-lg) as a Route Browser — a single helm for Looking Glass an' Route Server routing information.

**[alice.sfmix.org](https://alice.sfmix.org/)**
