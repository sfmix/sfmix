---
title: "looking glass 🔭"
layout: "video-header"
video: "video/participants-bg.mp4"
mobile_image: "img/mobile-fiber-light.jpg"
---

## looking glass 🔭

all participants gotta peer with the SFMIX looking glass. it pulls hella weight in a few ways:

- validate your router config when you first connect ✅
- test config changes against a low-impact peer with a self-service view of what the LG sees from you
- public visibility into what prefixes are present at the exchange (the receipts 🧾)
- quick reachability check for SFMIX operators

## quarantine VLAN 🧪

a parallel looking glass runs on the quarantine VLAN with the same addresses as production. new participants can test their ethernet, IP, and BGP config safely before joining the production peering LAN. no pressure, practice round.

## BGP connection info

| Parameter | Value |
|-----------|-------|
| ASN | 12276 |
| IPv4 | 206.197.187.1 |
| IPv6 | 2001:504:30::ba01:2276:1 |

## route browser 🗺️

SFMIX runs [Alice LG](https://github.com/alice-lg/alice-lg) as a route browser — one interface for looking glass and route server routing info. one-stop shop, bet 🤝.

**[alice.sfmix.org](https://alice.sfmix.org/)**
