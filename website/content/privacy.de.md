---
title: "Datenschutzerklärung"
layout: "single"
---

SFMIX („San Francisco Metropolitan Internet eXchange") ist eine gemeinnützige Genossenschaft nach IRS 501(c)(12). Wir setzen uns für Transparenz darüber ein, welche begrenzten Daten wir erheben und wie wir sie verwenden.

## Was wir erheben

### Administrative Informationen der Teilnehmer

Wenn sich eine Organisation mit SFMIX verbindet, erheben wir grundlegende Kontakt- und Abrechnungsinformationen, die für den Betrieb des Internet-Knotens erforderlich sind:

- **Kontaktdaten** — Name, E-Mail-Adresse, Telefonnummer und Postanschrift der autorisierten betrieblichen und abrechnungsbezogenen Ansprechpartner.
- **Organisationsdaten** — Name der Organisation, ASN und PeeringDB-Eintrag.

Diese Informationen werden ausschließlich zur betrieblichen Koordination, Abrechnung und für Servicebenachrichtigungen verwendet. Wir verkaufen oder teilen die Kontaktinformationen von Teilnehmern nicht mit Dritten.

### Netzwerkverkehrsdaten

SFMIX betreibt eine gemeinsam genutzte Vermittlungsstruktur, die Pakete zwischen Teilnehmern weiterleitet. Wir inspizieren, speichern oder analysieren den Inhalt der den Internet-Knoten durchquerenden Pakete nicht.

Wir erheben die folgenden betrieblichen Daten:

- **Schnittstellenzähler** — aggregierte Paket- und Byte-Zähler an teilnehmerseitigen Netzwerkschnittstellen, die zur Kapazitätsplanung, Abrechnungsprüfung und betrieblichen Überwachung verwendet werden.
- **Flow-Stichproben** — statistische Flow-Stichproben, die mithilfe von Protokollen wie sFlow oder IPFIX von der Vermittlungsinfrastruktur erfasst werden und zur Erstellung aggregierter Verkehrsmatrizen zwischen Mitgliedern sowie knotenweiter Statistiken dienen. Diese Protokolle erfassen Paket-Header (typischerweise die ersten 128 Byte) mit einer festgelegten Stichprobenrate; sie erfassen keine vollständigen Paketnutzdaten.

Aus diesen Daten abgeleitete Verkehrsstatistiken können in aggregierter Form auf unserer [Statistik](/statistics/)-Seite angezeigt oder mit einzelnen Teilnehmern hinsichtlich ihres eigenen Datenverkehrs geteilt werden.

### Ihr Datenverkehr ist Ihre Sache

Lassen Sie es uns klar sagen: **Es ist uns gleichgültig, was Sie über den Internet-Knoten senden.** SFMIX ist eine offene Plattform zum Transport von Bits, kein moderiertes Forum. Unsere Aufgabe ist es, Ihre Pakete zur anderen Seite weiterzuleiten, nicht eine Meinung über sie zu haben.

Dennoch wenden wir einige sinnvolle Ordnungsmaßnahmen an, damit die gemeinsam genutzte Struktur reibungslos läuft:

- **Auf Layer 3 (IP)** — Unsere Route-Server-Plattformen validieren Routen mithilfe von IRR, RPKI und (künftig) ASPA, um Teilnehmern bei guten Routing-Entscheidungen zu helfen. Dies ist eine Filterung von *Routing-Informationen*, nicht des Datenverkehrs selbst.
- **Auf Layer 2 (Ethernet)** — Wir können Protokolle filtern, die an einem Internet-Knoten nichts zu suchen haben, wie etwa DHCP und diverse herstellerspezifische Discovery-Protokolle (CDP, MNDP usw.). LLDP ist an allen Ports aktiviert. Als IX möchten wir nur die L2-Protokolle aktivieren, die die IP-Kommunikation unterstützen — nämlich Neighbor-Discovery-Protokolle wie ARP und ICMPv6 Neighbor Discovery.

Keine dieser Filterungen beinhaltet die Inspektion des Inhalts oder der Nutzdaten Ihres Datenverkehrs. Wir sind eine Leitung, kein Türsteher.

### Website

Wir können Nutzungsanalyse-Tools wie Google Analytics oder PostHog einsetzen, um zu verstehen, wie Besucher diese Website nutzen. Diese Tools können Cookies setzen und anonymisierte Nutzungsdaten wie besuchte Seiten, Verweildauer und Verweisquelle erfassen. Server-Zugriffsprotokolle können für einen begrenzten Zeitraum zu betrieblichen und sicherheitsbezogenen Zwecken aufbewahrt werden.

## Datenaufbewahrung

- **Kontaktinformationen der Teilnehmer** werden für die Dauer der Verbindung des Teilnehmers mit dem Internet-Knoten und für einen angemessenen Zeitraum danach zu Abrechnungs- und rechtlichen Zwecken aufbewahrt.
- **Schnittstellenzähler** werden in unseren Überwachungssystemen aufbewahrt und gemäß den üblichen Aufbewahrungsrichtlinien ausgesondert (typischerweise bis zu zwei Jahre bei abnehmender Granularität).
- **Flow-Stichprobendaten** werden in aggregierter/zusammengefasster Form aufbewahrt. Rohstichproben werden nicht langfristig aufbewahrt.

## Datenweitergabe

Wir verkaufen, vermieten oder teilen persönliche oder organisatorische Informationen nicht mit Dritten, außer:

- wenn dies gesetzlich oder durch ein gültiges rechtliches Verfahren vorgeschrieben ist.
- mit Dienstleistern, die beim Betrieb des Internet-Knotens helfen (z. B. bei der Abrechnung) und an Vertraulichkeitsverpflichtungen gebunden sind.
- in Form aggregierter, anonymisierter Verkehrsstatistiken, die keine Rückschlüsse auf einzelne Teilnehmer oder deren Verkehrsmuster zulassen.

## Kontakt

Fragen zu dieser Richtlinie können an [tech-c@sfmix.org](mailto:tech-c@sfmix.org) gerichtet werden.

*Zuletzt aktualisiert: Mai 2026*
