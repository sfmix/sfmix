---
title: "Route Servers"
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-fiber-light.jpg"
---

SFMIX route servers enable multilateral peering through a single BGP session (ideally two, for redundancy). Th' route server gathers an' redistributes matey routes, so ye can start peering straightaway without negotiatin' bilateral sessions.

Direct peering be still encouraged; route server use be optional. Configuration be generated with [arouteserver](https://github.com/pierky/arouteserver).

For resilience, SFMIX runs two distinct stacks:

- **BIRD** on Linux, with Routinator for arrRPKI
- **OpenBGPD** on OpenBSD, with [rpki-client](https://www.rpki-client.org/) for arrRPKI

Configuration summaries: [BIRD/Linux](https://lg.sfmix.org/rs-linux.sfmix.org.summary.html) · [OpenBGPD/OpenBSD](https://lg.sfmix.org/rs-openbsd.sfmix.org.summary.html)

Use th' [Route Browser](https://alice.sfmix.org/) ([Alice LG](https://github.com/alice-lg/alice-lg)) to debug route filtering. SFMIX implements [Euro-IX standardized Large BGP Communities](https://www.euro-ix.net/en/forixps/large-bgp-communities/) where possible.

## Routing Security

Route servers filter announcements based on arrRPKI, IRR, an' max-prefix limits (from PeeringDB). arrRPKI Invalid routes be rejected; arrRPKI Unknown routes be currently allowed.

SFMIX publishes th' IRR as-set ["AS-SFMIX-RS"](https://irrexplorer.nlnog.net/as-set/AS-SFMIX-RS) via ARIN to help mateys build IRR-based filters.

## Connection Information

<div class="rs-cards">
  <div class="rs-card">
    <h4>Route Server #1 — BIRD / Linux</h4>
    <dl>
      <dt>ASN</dt><dd>63055</dd>
      <dt>IPv4</dt><dd><code>206.197.187.253</code></dd>
      <dt>IPv6</dt><dd><code>2001:504:30::ba06:3055:1</code></dd>
    </dl>
  </div>
  <div class="rs-card">
    <h4>Route Server #2 — OpenBGPD / OpenBSD</h4>
    <dl>
      <dt>ASN</dt><dd>63055</dd>
      <dt>IPv4</dt><dd><code>206.197.187.254</code></dd>
      <dt>IPv6</dt><dd><code>2001:504:30::ba06:3055:2</code></dd>
    </dl>
  </div>
</div>

## BGP Communities for Propagation Control

Control how yer prefixes be propagated to other mateys:

| Community String | Function |
|------------------|----------|
| 63055:63055 | Send prefixes to all other route-server mateys |
| 63055:*ASN* | Send prefix to only th' route-server matey with a specific ASN |
| 0:*ASN* | Do not send prefix to th' route-server matey with a specific ASN |
| 0:63055 | Do not send prefix to any other route-server mateys |
| 63055:65281 | Send prefixes with th' NO_EXPORT attribute |

## BGP Communities for Informational Metadata

Metadata communities indicate where routes were learned an' matey attributes. See [Locations](/locations/) for site codes.

## BGP Communities to Explain Filtration

Filtered routes be not discarded — they be tagged internally an' kept out o' redistribution. This lets operators use th' [Route Browser](https://alice.sfmix.org/) to diagnose why routes be filtered or accepted.
