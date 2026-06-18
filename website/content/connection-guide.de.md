---
title: "Verbindungsanleitung"
layout: "video-header"
video: "video/connection-guide-bg.mp4"
mobile_image: "img/mobile-fiber-cables.jpg"
---

<p class="lead">Möchten Sie sich mit SFMIX verbinden? So geht's.</p>

## Überblick

1. Lesen Sie die Preise und Anforderungen weiter unten
2. Schreiben Sie eine E-Mail an [tech-c@sfmix.org](mailto:tech-c@sfmix.org) mit Ihrer gewünschten Geschwindigkeit und Ihrem [Standort](/locations/); wir bestätigen die Port-Verfügbarkeit

   > **Tipp:** Verwenden Sie den Betreff „New Connection Request – [Name Ihrer Organisation]" und geben Sie Ihre PeeringDB-URL, die gewünschte Geschwindigkeit und Ihren bevorzugten Standort an. Wir antworten in der Regel innerhalb von 1–2 Werktagen.

3. Füllen Sie den [Mitgliedsantrag](https://goo.gl/forms/fiqOIjCP7QHYUG3i1) aus
4. SFMIX stellt Ihnen ein LOA/CFA aus, damit Sie beim Rechenzentrumsbetreiber einen Cross-Connect bestellen können
5. SFMIX weist Ihnen Ihre IPv4- und IPv6-Adressen zu
6. Ihre Leitung wird mit einem **Quarantäne-VLAN** verbunden — einer sicheren Umgebung, um Ihre Verbindung aufzubauen und die Konfiguration zu validieren, bevor Sie die Produktion berühren
7. Sobald alles bereit ist, verschiebt SFMIX Ihren Port in das produktive Peering-VLAN
8. Beginnen Sie mit dem Peering!

## Administrative Anforderungen

### Preise

{{< pricing >}}

### Abrechnung

- Jährliche Abrechnung (Kalenderjahr); keine monatliche Option
- Nur USD
- Zahlung (bevorzugte Reihenfolge): ACH, Überweisung, Scheck, Kreditkarte

## Logistische Anforderungen

- Mindestens ein Vertreter muss die [Mailingliste sfmix-members](https://lists.sfmix.org/postorius/lists/sfmix-members.lists.sfmix.org/) abonnieren. Rollenkonten werden empfohlen. Schreiben Sie an [tech-c@sfmix.org](mailto:tech-c@sfmix.org), um sich anzumelden.
- Diskussionen auf der Mailingliste sind vertraulich und auf Teilnehmer, Mitglieder und Sponsoren beschränkt.
- SFMIX wird von Freiwilligen betrieben. Alle Dienste erfolgen nach bestem Bemühen; es wird kein SLA zugesichert.
- Teilnehmer dürfen unabhängig von der Anzahl ihrer Ports nur an einem einzigen Standort peeren. SFMIX ist eine Peering-Struktur, kein Transportnetz.
- Kein ARP/ICMPv6-Spoofing und kein Mitschneiden von Datenverkehr.

## Technische Anforderungen

- **Nur Singlemode-Faser** — kein Kupfer oder Multimode-Faser.
- Eine öffentliche, von einer RIR zugewiesene ASN ist erforderlich ([RFC 1930](https://datatracker.ietf.org/doc/html/rfc1930), [RFC 6996](https://datatracker.ietf.org/doc/html/rfc6996)). Keine privaten ASNs.
- Ein gepflegter [PeeringDB](https://peeringdb.org/)-Eintrag ist erforderlich.
- **Eine MAC-Adresse pro logischer Verbindung.** Die Port-Sicherheit erlaubt vorübergehend 2 MACs für Router-Migrationen, langfristig jedoch nur 1.
- **Erlaubter Broadcast:** nur ARP und ICMPv6 ND. Keine RAs, kein CDP, DHCP oder STP.
- **LLDP:** SFMIX überträgt LLDP auf allen Teilnehmer-Ports, einschließlich der optischen Empfangsleistungswerte. Teilnehmer dürfen LLDP übertragen, sind dazu aber nicht verpflichtet.
- **Eine BGP-Sitzung mit dem [Looking Glass](/looking-glass/) ist verpflichtend.** Sie dient ausschließlich dem Debugging — es werden keine Routen weiterverteilt und kein Datenverkehr ausgetauscht.
- Propagieren Sie die SFMIX-Peering-Subnetze (206.197.187.0/24, 2001:504:30::/64) nicht über Ihren Edge-Router hinaus. Verwenden Sie bei Bedarf ACLs.
- Keine statischen oder Standardrouten zu anderen Teilnehmern oder SFMIX-Ressourcen ohne Genehmigung.
- Peering mit dem [Route-Server](/route-servers/) wird empfohlen, ist aber nicht erforderlich.

## LLDP & Überwachung der optischen Leistung

SFMIX-Switches übertragen [LLDP](https://de.wikipedia.org/wiki/Link_Layer_Discovery_Protocol) auf jedem Teilnehmer-Port. Zusätzlich zu den standardmäßigen LLDP-Informationen (Systemname, Port-Beschreibung) enthält jeder Frame die vom SFMIX-seitigen Transceiver gemessene optische Empfangsleistung, kodiert als [LLDP-MED](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol#LLDP-MED) Inventory TLV.

Dies ermöglicht es Ihnen, von Ihrem eigenen Router aus zu sehen, wie gut Ihr Sendelicht am SFMIX-Switch ankommt, ohne dass Sie uns für den Support kontaktieren müssen.

### Was angekündigt wird

Das LLDP-MED-Feld „Asset ID" trägt die Empfangsleistung in dBm:

- **Beispiel für Single-Lane-Optiken:** `dBm:-2.05`
- **Beispiel für Multi-Lane-Optiken:** `dBm:-7.60/-8.20/-6.79/-6.52` (ein Wert pro Lane)

### Anzeigen der Daten

Unter **Arista EOS**:

```
switch# show lldp neighbors Ethernet1 detail | grep 'Asset ID'
  - LLDP-MED Inventory Asset ID TLV: "dBm:-2.05"
```

Unter **Linux** (lldpd):

```
$ lldpcli show neighbors
  LLDP-MED:
    Inventory:
      Asset ID:     dBm:-2.05
```

Unter **Juniper Junos**:

```
user@router> show lldp neighbors interface xe-0/0/0
```

Suchen Sie auf anderen Plattformen nach LLDP-MED Inventory oder organisationsspezifisch definierten TLVs mit der OUI `00:12:BB`, Subtyp 11.

### Interpretation der Werte

Die Leistungswerte geben an, was der SFMIX-Transceiver von Ihrer Seite empfängt. Wenn die Werte gegen die Empfindlichkeitsschwelle des Transceiver-Empfängers absinken (typischerweise etwa −14 dBm bei LR4, −22 dBm bei ER4), benötigt Ihre Glasfaserinfrastruktur möglicherweise Aufmerksamkeit. Ein Wert von `dBm:-40.00` oder das Fehlen eines Asset-ID-TLV bedeutet, dass kein Licht erkannt wird.

Optische Leistung über LLDP wird derzeit nur an Arista-Edge-Ports unterstützt, was im Wesentlichen alle heutigen Peering-Ports abdeckt. Der Agent, der diese Daten einspeist, ist Open Source: [LldpDomAgent auf GitHub](https://github.com/sfmix/sfmix/blob/main/scripts/arista_eos/LldpDomAgent).
