---
title: "Privacy Code"
layout: "single"
---

SFMIX ("San Francisco Metropolitan Internet eXchange") be a nonprofit IRS 501(c)(12) cooperative. We be committed to bein' straight with ye about th' limited data we collect an' how we use it.

## What We Collect

### Participant Administrative Information

When a crew connects to SFMIX, we collect basic contact an' billing information needed to run th' exchange:

- **Contact details** — name, email address, phone number, an' mailing address for authorized operational an' billing contacts.
- **Organization details** — organization name, ASN, an' PeeringDB record.

This information be used solely for operational coordination, billing, an' service notifications. We do not sell nor share matey contact information with third parties.

### Network Traffic Data

SFMIX operates a shared switching fabric that forwards packets between mateys. We do not inspect, store, nor analyze th' content o' packets transitin' th' exchange.

We do collect th' followin' operational data:

- **Interface counters** — aggregate packet an' byte counts on matey-facing network interfaces, used for capacity planning, billing verification, an' operational monitoring.
- **Flow samples** — statistical flow samples collected from switching infrastructure usin' protocols such as sFlow or IPFIX, used to generate aggregate member-to-member traffic matrices an' exchange-wide statistics. These protocols capture packet headers (typically th' first 128 bytes) at a defined sampling rate; they do not capture full packet payloads.

Traffic statistics derived from this data may be displayed in aggregate form on our [Statistics](/statistics/) page or shared with individual mateys regarding their own traffic.

### Your Traffic Is Your Business

Let's be clear: **we don't care what ye send over th' exchange.** SFMIX be an open platform for haulin' bits, not a moderated forum. Our job be to forward yer packets to th' other side, not to have opinions about them.

That said, we do apply some sensible housekeeping to keep th' shared fabric runnin' smoothly:

- **At Layer 3 (IP)** — Our route server platforms validate routes usin' IRR, arrRPKI, an' (eventually) ASPA to help mateys make good routing decisions. This be filtering o' *routing information*, not o' traffic itself.
- **At Layer 2 (Ethernet)** — We may filter protocols that have no business on an Internet exchange fabric, such as DHCP an' various vendor-specific discovery protocols (CDP, MNDP, etc.). LLDP be enabled on all ports. As an IX, we aim to enable only th' L2 protocols that support IP communication — namely neighbor discovery protocols like ARP an' ICMPv6 Neighbor Discovery.

None o' this filtering involves inspectin' th' content or payload o' yer traffic. We be a pipe, not a gatekeeper.

### Website

We may utilize usage analytics tools such as Google Analytics or PostHog to understand how visitors use this website. These tools may set cookies an' collect anonymized usage data such as pages visited, time on site, an' referral source. Server access logs may be retained for a limited period for operational an' security purposes.

## Data Retention

- **Participant contact information** be retained for th' duration o' th' matey's connection to th' exchange an' for a reasonable period afterward for billing an' legal purposes.
- **Interface counters** be retained in our monitoring systems an' aged out accordin' to standard retention policies (typically up to two years at decreasing granularity).
- **Flow sample data** be retained in aggregate/summarized form. Raw samples be not retained long-term.

## Data Sharing

We do not sell, rent, nor share personal or organizational information with third parties, except:

- When required by law or valid legal process.
- With service providers who assist in operatin' th' exchange (e.g., billing), bound by confidentiality obligations.
- Aggregate, anonymized traffic statistics that cannot identify individual mateys or their traffic patterns.

## Contact

Questions about this code can be directed to [tech-c@sfmix.org](mailto:tech-c@sfmix.org).

*Last updated: May 2026*
