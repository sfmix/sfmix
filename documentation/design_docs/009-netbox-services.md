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
  LAN), `peering` (Peering) and `private_vlan` (Private VLAN). The names are generic rather than "IX" so they also fit a
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
| Private VLAN | the VLAN name, `PVLAN-AS<a>-AS<b>` | `private_vlan` | VLANs in `exchange_fabric_vlans` with that name |
| Private VLAN port | `PVLAN-AS<a>-AS<b>-<device>-<interface>` | `l2vpn` | each interface carrying the PVLAN, on live devices |

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

A PVLAN follows the same shape as peering. One `private_vlan` service is the shared VLAN and
lists both parties in `tenants`. Each side buys its own port into it, so every endpoint is its
own `l2vpn` service with its own bandwidth/commit, depending on the PVLAN. The sync never sets an
endpoint's billing `tenant`; that is entered by hand. The descriptions on the endpoints don't
reliably say who pays ("Arelion c/o Cofractal").

PVLAN fields:
- `tenants`: tenants whose `as_number` appears in the name.
- `interfaces`/`devices`: every interface carrying the VLAN, on live devices.
- `bandwidth`: the slowest endpoint.

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

## Import (prod, 2026-10-25)

The import ran as a one-off `services-import` user with scoped permissions and an expiring token,
deleted once the import was done. It created 122 services: 1 peering LAN, 115 peering connections, 2
private VLANs and 4 private VLAN ports. Fixes made along the way:

- **switch01.fmt01 Ethernet11.** It is a member of VOLT's (AS62809) Port-Channel101 but still had
  `participant` AS399338, the `ixp_participant` tag and a 1G `rate_limit_bps`. All three were left
  over from when it was Central Valley Internet's port; CVI now uses Port-Channel103, and the
  switch has no shaper on Ethernet11. All three were cleared, so VOLT is 20G/20G. No published
  output read them: IX-F and the website use `rate_limit_bps` only from `peering_port`
  interfaces. With that gone, no service has `cir < bandwidth`.
- **Arelion tenant.** `AS1299` (Arelion) was added as a non-participant tenant (no
  `ixp_participant` tag) so PVLAN 1411 names both parties. SFMIX is an Arelion customer/transport
  provider, not the reverse.
- **PVLAN billing.** Each side pays for its own port, so the endpoint services carry the payer
  as `tenant`. On 1411 Cofractal pays for both ports, since the Arelion end at sjc01 is part of
  a bundled transport service.

`scripts/netbox_ix_lint.py` now checks that a LAG member's `participant` matches its LAG, or a
peering sub-interface of it. The first run flagged 16 members, 14 of them on switch01.fmt01, with
member participants that look shifted relative to their LAGs.

The lint also checks that the services cover the ports:
- Each `peering_port` with a `participant` must be in exactly one `peering` service for that
  participant.
- Each port carrying a PVLAN on a live device must be in exactly one `l2vpn` service, and that
  service must have a billing `tenant`.

Ports are selected by `peering_port`, not `ixp_participant`. Discovery keeps `peering_port` in
step with VLAN 998 membership, and the LG and portal read it too. `ixp_participant` on an
interface is only ever added, never removed. On 2026-10-25 it was on 167 interfaces against 118
peering ports; the extra ones are LAG members, transit LAGs and ports left over from former
participants.

Skipped by the sync: three `peering_port` interfaces with no participant (PVE trunks on fmt01, the
scl04 PVE access LAG), and the PVLAN 1411 endpoint on decommissioning switch02.sjc01.

## Next steps

- Model AS40271 transit VLANs (`SFMIX-TRANSIT-*`) as `transit` services.
- Model remote-peering (reseller) sub-interfaces once they carry a `participant`. Today the one
  PacketFabric sub-interface has none.
- Decide whether to adopt Services as the source of truth, and if so, cut consumers over and
  retire `rate_limit_bps`.
