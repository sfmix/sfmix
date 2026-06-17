---
title: "Privacy Policy"
layout: "single"
---

SFMIX ("San Francisco Metropolitan Internet eXchange") is a nonprofit IRS 501(c)(12) cooperative. We're committed to being fully transparent about the limited data we collect and how we use it. No funny business.

## What We Collect

### Participant Administrative Information

When an org connects to SFMIX, we collect basic contact and billing info needed to run the exchange:

- **Contact details** — name, email address, phone number, and mailing address for authorized operational and billing contacts.
- **Organization details** — organization name, ASN, and PeeringDB record.

This info is used solely for operational coordination, billing, and service notifications. We do not sell or share participant contact info with third parties. Period.

### Network Traffic Data

SFMIX runs a shared switching fabric that forwards packets between participants. We do not inspect, store, or analyze the content of packets transiting the exchange. We're not nosy.

We do collect the following operational data:

- **Interface counters** — aggregate packet and byte counts on participant-facing network interfaces, used for capacity planning, billing verification, and operational monitoring.
- **Flow samples** — statistical flow samples collected from switching infrastructure using protocols such as sFlow or IPFIX, used to generate aggregate member-to-member traffic matrices and exchange-wide statistics. These protocols capture packet headers (typically the first 128 bytes) at a defined sampling rate; they do not capture full packet payloads.

Traffic stats derived from this data may be shown in aggregate form on our [Statistics](/statistics/) page or shared with individual participants about their own traffic.

### Your Traffic Is Your Business

Let's be clear: **we don't care what you send over the exchange.** SFMIX is an open platform for hauling bits, not a moderated forum. Our job is to forward your packets to the other side, not to have opinions about them. Mind our own, fr.

That said, we do apply some sensible housekeeping to keep the shared fabric running smoothly:

- **At Layer 3 (IP)** — Our route server platforms validate routes using IRR, RPKI, and (eventually) ASPA to help participants make good routing decisions. This is filtering of *routing information*, not of traffic itself.
- **At Layer 2 (Ethernet)** — We may filter protocols that have no business on an Internet exchange fabric, such as DHCP and various vendor-specific discovery protocols (CDP, MNDP, etc.). LLDP is enabled on all ports. As an IX, we aim to enable only the L2 protocols that support IP communication — namely neighbor discovery protocols like ARP and ICMPv6 Neighbor Discovery.

None of this filtering involves inspecting the content or payload of your traffic. We're a pipe, not a gatekeeper. Built to forward, not to judge.

### Website

We may use usage analytics tools such as Google Analytics or PostHog to understand how visitors use this website. These tools may set cookies and collect anonymized usage data such as pages visited, time on site, and referral source. Server access logs may be kept for a limited period for operational and security purposes.

## Data Retention

- **Participant contact information** is retained for the duration of the participant's connection to the exchange and for a reasonable period afterward for billing and legal purposes.
- **Interface counters** are kept in our monitoring systems and aged out according to standard retention policies (typically up to two years at decreasing granularity).
- **Flow sample data** is kept in aggregate/summarized form. Raw samples are not retained long-term.

## Data Sharing

We do not sell, rent, or share personal or organizational information with third parties, except:

- When required by law or valid legal process.
- With service providers who help operate the exchange (e.g., billing), bound by confidentiality obligations.
- Aggregate, anonymized traffic stats that can't identify individual participants or their traffic patterns.

## Contact

Questions about this policy? Slide them to [tech-c@sfmix.org](mailto:tech-c@sfmix.org).

*Last updated: May 2026*
