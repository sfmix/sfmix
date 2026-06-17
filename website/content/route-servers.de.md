---
title: "Route-Server"
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-fiber-light.jpg"
---

Die SFMIX-Route-Server ermöglichen multilaterales Peering über eine einzige BGP-Sitzung (idealerweise zwei zur Redundanz). Der Route-Server aggregiert und verteilt die Routen der Teilnehmer, sodass Sie sofort mit dem Peering beginnen können, ohne bilaterale Sitzungen aushandeln zu müssen.

Direktes Peering wird dennoch empfohlen; die Nutzung des Route-Servers ist optional. Die Konfiguration wird mit [arouteserver](https://github.com/pierky/arouteserver) generiert.

Zur Ausfallsicherheit betreibt SFMIX zwei voneinander getrennte Stacks:

- **BIRD** unter Linux, mit Routinator für RPKI
- **OpenBGPD** unter OpenBSD, mit [rpki-client](https://www.rpki-client.org/) für RPKI

Konfigurationsübersichten: [BIRD/Linux](https://lg.sfmix.org/rs-linux.sfmix.org.summary.html) · [OpenBGPD/OpenBSD](https://lg.sfmix.org/rs-openbsd.sfmix.org.summary.html)

Nutzen Sie den [Route-Browser](https://alice.sfmix.org/) ([Alice LG](https://github.com/alice-lg/alice-lg)), um die Routenfilterung zu debuggen. SFMIX implementiert nach Möglichkeit [von Euro-IX standardisierte Large BGP Communities](https://www.euro-ix.net/en/forixps/large-bgp-communities/).

## Routing-Sicherheit

Die Route-Server filtern Announcements anhand von RPKI, IRR und Max-Prefix-Limits (aus PeeringDB). Als RPKI Invalid eingestufte Routen werden abgelehnt; als RPKI Unknown eingestufte Routen werden derzeit zugelassen.

SFMIX veröffentlicht das IRR-as-set ["AS-SFMIX-RS"](https://irrexplorer.nlnog.net/as-set/AS-SFMIX-RS) über ARIN, um Teilnehmern beim Aufbau IRR-basierter Filter zu helfen.

## Verbindungsinformationen

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

## BGP-Communities zur Propagierungssteuerung

Steuern Sie, wie Ihre Präfixe an andere Teilnehmer propagiert werden:

| Community-String | Funktion |
|------------------|----------|
| 63055:63055 | Präfixe an alle anderen Route-Server-Teilnehmer senden |
| 63055:*ASN* | Präfix nur an Route-Server-Teilnehmer mit bestimmter ASN senden |
| 0:*ASN* | Präfix nicht an Route-Server-Teilnehmer mit bestimmter ASN senden |
| 0:63055 | Präfix an keinen anderen Route-Server-Teilnehmer senden |
| 63055:65281 | Präfixe mit dem Attribut NO_EXPORT senden |

## BGP-Communities für informative Metadaten

Metadaten-Communities geben an, wo Routen gelernt wurden, sowie Teilnehmerattribute. Siehe [Standorte](/locations/) für die Standortcodes.

## BGP-Communities zur Erläuterung der Filterung

Gefilterte Routen werden nicht verworfen — sie werden intern markiert und von der Weiterverteilung ausgenommen. Dies ermöglicht es Betreibern, den [Route-Browser](https://alice.sfmix.org/) zu nutzen, um zu diagnostizieren, warum Routen gefiltert oder akzeptiert werden.
