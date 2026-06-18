---
title: "route servers 🖥️"
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-fiber-light.jpg"
---

SFMIX route servers let you do multilateral peering through a single BGP session (ideally two for redundancy). the route server aggregates and redistributes participant routes, so you can start peering immediately without negotiating hella bilateral sessions. say less, you're in 🚀.

direct peering is still encouraged; route server use is optional. config is generated with [arouteserver](https://github.com/pierky/arouteserver).

for resilience, SFMIX runs two distinct stacks:

- **BIRD** on Linux, with Routinator for RPKI
- **OpenBGPD** on OpenBSD, with [rpki-client](https://www.rpki-client.org/) for RPKI

config summaries: [BIRD/Linux](https://lg.sfmix.org/rs-linux.sfmix.org.summary.html) · [OpenBGPD/OpenBSD](https://lg.sfmix.org/rs-openbsd.sfmix.org.summary.html)

use the [route browser](https://alice.sfmix.org/) ([Alice LG](https://github.com/alice-lg/alice-lg)) to debug route filtering. SFMIX implements [Euro-IX standardized Large BGP Communities](https://www.euro-ix.net/en/forixps/large-bgp-communities/) where possible.

## routing security 🔒

route servers filter announcements based on RPKI, IRR, and max-prefix limits (from PeeringDB). RPKI Invalid routes get rejected (that's an L 💀); RPKI Unknown routes are currently allowed.

SFMIX publishes the IRR as-set ["AS-SFMIX-RS"](https://irrexplorer.nlnog.net/as-set/AS-SFMIX-RS) via ARIN to help participants build IRR-based filters.

## connection info

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

## BGP communities for propagation control 🎛️

control how your prefixes get propagated to other participants:

| Community String | Function |
|------------------|----------|
| 63055:63055 | Send prefixes to all other route-server participants |
| 63055:*ASN* | Send prefix to only route-server participant with specific ASN |
| 0:*ASN* | Do not send prefix to route-server participant with specific ASN |
| 0:63055 | Do not send prefix to any other route-server participants |
| 63055:65281 | Send prefixes with NO_EXPORT attribute |

## BGP communities for informational metadata

metadata communities indicate where routes were learned and participant attributes. see [locations](/locations/) for site codes.

## BGP communities to explain filtration

filtered routes don't get discarded — they're tagged internally and excluded from redistribution. this lets operators use the [route browser](https://alice.sfmix.org/) to diagnose why routes got filtered or accepted. receipts included 🧾.
