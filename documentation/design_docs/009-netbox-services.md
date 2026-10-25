# 009 - NetBox Services: a service layer over the physical model

## Status: Experiment, rehearsed against a prod copy (2026-10-25)

## Overview

NetBox describes what SFMIX *has*: devices, LAGs, cross-connect cables, VLANs, prefixes. It doesn't
describe what participants *buy*, such as "AS62809 peers over a 20G LAG at FMT01" or "a private VLAN
between AS32329 and AS46886". We add a **Service** record on top of the physical objects using the
[netbox-services](https://github.com/baldoarturo/netbox-services) plugin. Each record links to the
interfaces, devices, cables and VLANs it runs on and carries a port rate and a committed rate.

This is model-only. No consumer (switch templates, IX-F/website export, route servers, LG,
portal) reads Services. `rate_limit_bps` on interfaces stays the source of truth for shaping, and a
Service's commit only mirrors it.

## Plugin

We run the `sfmix` branch of our fork, [sfmix/netbox-services](https://github.com/sfmix/netbox-services):
upstream v0.2.0 plus four changes drafted as upstream PRs (not opened yet):

- **fix-tags**: upstream stored Service tags in taggit's own tables instead of NetBox's.
  Tagging a service created a shadow tag, and the API returned a 500 for every tagged service.
  Migration 0006 moves existing assignments onto NetBox tags.
- **writable-relations**: the API exposed relations (interfaces, VLANs, `depends_on`, ...)
  read-only, so automation couldn't populate them.
- **extensible-service-type**: lets `FIELD_CHOICES` add types. We add `peering_lan` (Peering
  LAN) and `peering` (Peering). The names are generic rather than "IX" so they also fit a
  peering LAN that isn't an Internet exchange.
- **multi-tenant**: a `tenants` M2M ("Parties") next to `tenant`. `tenant` remains the
  primary/billing tenant; a PVLAN lists both ends as parties.

Deployment is in [netbox.md](../netbox.md#plugins).

## Model

Everything is derived by `scripts/netbox_services_sync.py` from data already in NetBox. The sync
is idempotent and keyed on `service_id`. It tags what it creates `services_sync`. It never deletes:
a synced Service whose source is gone is reported as stale. It only writes the fields below;
lifecycle dates, SLA, attachments and a PVLAN's billing `tenant` are left to humans.

| Service | `service_id` | Type | Derived from |
| --- | --- | --- | --- |
| Peering LAN (one) | `SFMIX-PEERING` | `peering_lan` | VLANs 997/998/999, prefixes tagged `peering_lan` |
| Peering connection | `PEERING-AS<asn>-<device>-<interface>` | `peering` | each `peering_port` / `encapsulated_peering_port` interface with a `participant` |
| Private VLAN | the VLAN name, `PVLAN-AS<a>-AS<b>` | `l2vpn` | VLANs in `exchange_fabric_vlans` with that name |

Each participant connection is its own service, tied to the peering LAN by `depends_on`, so every
connection carries its own port rate and commit. It is per port rather than per participant: a
network present at two sites has two services, because speed and shaping are per port.

Peering connection fields:
- `tenant` and `tenants`: the participant.
- `interfaces`: the peering interface, its parent (for a `.998` sub-interface) and the LAG
  members.
- `cables`: the cables on those members.
- `vlans`: the interface's VLANs.
- `depends_on`: `SFMIX-PEERING`.
- `status`: `active` if enabled, `offline` if not, `deprovisioning` on a device that is being
  decommissioned.

PVLAN fields:
- `tenants`: tenants whose `as_number` appears in the name.
- `interfaces`/`devices`: every interface carrying the VLAN, on live devices.
- `bandwidth`: the slowest endpoint.
- `depends_on`: the peering service that shares an endpoint's parent LAG, if any.

### Commit rate

- `bandwidth` is the physical port rate in Mbps: the sum of the LAG members' speeds.
- `cir` is the committed rate in Mbps, i.e. what the `rate_limit_bps` shapers enforce. With no
  shaper, `cir = bandwidth`.
- So every sub-rate customer satisfies `cir < bandwidth`, e.g. a 10G port with 1G committed is
  `bandwidth=10000, cir=1000`.
- A shaper on the port itself, its parent or its LAG caps the whole service. Shapers on
  individual LAG members cap only that member, which mirrors how EOS shapes members.

If Services become authoritative later, the consumers (`eos/interface.j2` shaper, IX-F
`if_speed`, website table, LG `ixf.rs`) switch to `Service.cir` and `rate_limit_bps` goes away. We
won't keep two stores.

## Findings from the first run (prod copy, 2026-10-25)

The sync produced 118 services: 1 peering LAN, 115 peering connections and 2 PVLANs. Data issues surfaced:

- **Inconsistent participant on a shaped member.** switch01.fmt01 Ethernet11 is the only shaped
  interface (1G). It is a member of Port-Channel101 (VOLT BROADBAND, AS62809), but its own
  `participant` is AS399338. VOLT's peering service therefore computes as 20G physical / 11G committed.
- **Missing tenant.** No tenant has `as_number` 1299, so PVLAN-AS26073-AS1299 has only one party.
- **Endpoint on a decommissioning switch.** PVLAN-AS26073-AS1299 still has an endpoint on
  switch02.sjc01 (decommissioning). It is skipped, and the ports on that switch sync as
  `deprovisioning`.
- **Peering ports without a participant.** Three `peering_port` interfaces have none
  (pve trunks on fmt01, the scl04 PVE access LAG) and are skipped.

## Next steps

- Model AS40271 transit VLANs (`SFMIX-TRANSIT-*`) as `transit` services.
- Model remote-peering (reseller) sub-interfaces once they carry a `participant`. Today the one
  PacketFabric sub-interface has none.
- Decide whether to adopt Services as the source of truth, and if so, cut consumers over and
  retire `rate_limit_bps`.
