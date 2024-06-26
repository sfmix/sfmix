# SFMIX Netbox

SFMIX uses Netbox as a source-of-truth for intended network configurations.

Because we manage network resources that cross administrative domains (for example Participant IP addresses), we have a few special cases which are not supported natively in Netbox.
In order to handle these use cases, we make use of a mix of Netbox Tagging and Netbox Custom Fields to model some of our objects and their relationships.

## Deployment

We run Netbox in a VM, which is deployed with the ansible inside of `deploy/` of this repository.
We use PostgreSQL as a persistent database. We use Redis as a cache.

## Bootstrapping

Run the `Device-Type-Library-Import` script to populate the Manufacturer and Device database: https://github.com/netbox-community/Device-Type-Library-Import

Add the Peering VLANs and Prefixes.

Add IX-specific tags:

- IXP Infrastructure (Slug: "ixp_infrastructure")
- IXP Participant (Slug: "ixp_participant")
- Peering LAN (Slug: "peering_lan")
- Peering Port (Slug: "peering_port")
- Encapsulated Peering Port (Slug: "encapsulated_peering_port")
- Encapsulating Peering Port (Slug: "encapsulating_peering_port")
- Core Port (Slug: "core_port")

## SFMIX-Specific Objects and Relationships

### Participants as Netbox Tenants

In order to maintain a listing of participant networks, we use Netbox Tenant objects using a name and slug format like "AS[ AS Number ]" (e.g. "AS12276"). The name of the AS is treated as metadata (as opposed to a unique identifier). The implications of this are that if a participant wants to change their description, they should update PeeringDB, and if a participant wants to change their ASN, we should go through a full de-commissioning and re-commissioning workflow (even if they keep the same billing, cross-connects, and ports).

All IXP Infrastructure Participant-Tenants (like AS63055 / SFMIX Route Servers) are tagged with the Netbox Tag "IXP Infrastructure/ixp_infrastructure"

All "normal" IXP Participant-Tenants are tagged with the Netbox Tag "IXP Participant" (Slug: "ixp_participant").

*Relevant custom fields on Tenant objects*:

- `as_number`: The numeric AS number in decimal form
- `participant_type`: A selection choice field with options: Member, Exempt, and Infrastructure

### Physical Sites

We use Netbox Sites with our SFMIX-internal site code as the Name and Slug of the Netbox Site (e.g. "sfo02").

In order to facilitate consistent external references to our physical locations (like in the Euro-IX formatted participants.json), we set a Netbox Custom Field called `peeringdb_facility`, which contains a numerical ID of the facility from PeeringDB.

### Peering LANs and VLANs

VLANs used in the exchange fabric are tracked as Netbox VLANs.

Peering LANs are tagged with the Netbox Tag "Peering LAN" (Slug: "peering_lan")

### Peering Subnets

IP subnet prefixes are tracked as Netbox Prefixes, tagged with the Netbox Tag "Peering LAN" (Slug: "peering_lan")

### Participant Peering IPs

Participant Peering Subnet IP assignments are tracked as Netbox IP Addresses tagged with the Netbox Tag "IXP Participant".

The association to a Participant is made by setting the Participant's Tenant as the Netbox Tenant on the Netbox IP Address.

In order to facilitate mapping the address to a participant's logical/physical L2 interface, because a Netbox Interface does not have a field to set a Netbox Tenant, two Netbox Custom Fields are used:

- "Participant LAG" of type "Interface" points to the LAG or physical interface for that participant.
- "Participant MAC Address" of type String contains a lower-case, colon-delimited MAC address that we detect (via ARP or ICMPv6 Neighbor Discovery) the participant using.

### Encapsulating Peering Ports

Some interfaces go towards remote peering transport providers. In these cases, a single physical interface is shared by multiple participants, with an outer 802.1Q VLAN tag used to differentiate the participants on the port.

To differentiate these physical interfaces from other Peering Ports tagged as "Peering Port", these will have an additional tag applied: "Encapsulating Peering Port".

### Encapsulated Peering Ports

The child sub-interfaces of Encapsulating Peering Ports are called Encapsulated Peering Ports and have a Netbox Tag "Encapsulated Peering Port" applied to them.

Additionally, an optional custom field is defined on Netbox Interfaces called "dot1q_encapsulation_tag". This field is used by these child sub-interfaces of the parent physical interface to denote the outer encapsulation tag used for the participant.

### LACP Mode on Interfaces

As Netbox does not have a native way to model LACP mode on LAG member links, we add a Custom Field Choice Set and Custom Field on Interfaces to denote this desired mode.

The mode choices are: on, active, passive

The custom field is called LACP Mode (Slug: "lacp_mode")
