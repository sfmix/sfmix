# SFMIX Netbox

SFMIX uses Netbox as a source-of-truth for intended network configurations.

Because we manage network resources that cross administrative domains (for example Participant IP addresses), we have a few special cases which are not supported natively in Netbox.
In order to handle these use cases, we make use of a mix of Netbox Tagging and Netbox Custom Fields to model some of our objects and their relationships.

## Deployment

We run Netbox in a VM (`netbox.sfo02`, VMID 102 on `pve02-paulave200-sfo`, ZFS-backed), deployed by
`ansible/push_servers.playbook.yml --tags netbox` (`ixp_netbox` + `geerlingguy.postgresql` +
`DavidWittman.redis` + `lae.netbox`). We use PostgreSQL as a persistent database. We use Redis as a cache.

State that matters lives in two places: the `netbox` Postgres database and `/srv/netbox/shared/`
(`media/` images and attachments, `configuration.py`, `generated_secret_key`, and from 4.5 on
`generated_secret_pepper`, without which v2 API tokens cannot be verified). `requests.log` there is
multi-GB and disposable.

## Upgrading

Upgrade from a restored copy first. A `pg_dump -Fc` restored into a `postgres:16` container plus
the `netboxcommunity/netbox:vX.Y.Z` image running `manage.py migrate` rehearses the schema
migrations; running the old image next to it lets consumers be diffed between versions (the LG's
`netbox::fetch_port_map`, and the `netbox_data` role rendering the RS `clients.yml` and IX-F
templates).

### 4.4.8 → 4.7.2 (2026-10)

Platform: 4.5+ needs Python ≥ 3.12 and 4.7 needs PostgreSQL ≥ 15 (plus the `ltree` extension,
self-installed because the `netbox` role owns the DB). Ubuntu 22.04 has 3.10/14, so the VM moves to
24.04 (3.12/16). `lae.netbox` is pinned to an untagged master commit (Ubuntu 24 vars, `DATABASES`,
auto-generated `API_TOKEN_PEPPERS`), `geerlingguy.postgresql` to 4.1.0, and uWSGI goes in the
venv because 24.04 refuses system-wide pip installs.

API changes that hit us:

- Select custom fields (`participant_type`, `lacp_mode`) read as `{value, label}`. Writes still
  take the bare value, but a pynetbox `save()` after editing `custom_fields` resends the whole dict
  and is rejected; use `record.update({"custom_fields": {...}})`.
- GraphQL enum filters need a lookup (`status: {exact: STATUS_ACTIVE}`), and 4.4 rejects that
  form, so the LG filters status client-side.
- GraphQL lists without pagination are capped at `MAX_PAGE_SIZE` (1000). Nothing we query is near
  that today (476 IPs, 116 tenants), but `netbox_syslog_hostmap.py` will truncate silently past it.
- `SENTRY_DSN` is gone (NetBox refuses to start); the DSN lives under `SENTRY_CONFIG.dsn`.
- `manage.py housekeeping` is gone (runs as a system job); the play removes lae's cron for it.
- v1 (40-hex) tokens keep working until v5.0. Token plaintext can no longer be retrieved or
  chosen by the client, so new service tokens are v2 (`nbt_…`) and are shown once at creation.

Cutover, in order:

1. Deploy the LG (`deploy_looking_glass_rust.playbook.yml`). Its NetBox client works on both
   versions; a running lg-server keeps its last good NetBox data if a refresh fails.
2. Fresh backup to the control node (`pg_dump -Fc`, `pg_dumpall --globals-only`, tar of
   `/srv/netbox/shared` minus `requests.log`), into the gitignored `ansible/backups/`.
3. Stop `netbox`, `netbox-rqworker@1`, then snapshot: `qm snapshot 102 pre_netbox47` on
   pve02-paulave200. Rollback is `qm rollback 102 pre_netbox47`.
4. `apt full-upgrade`, reboot, then `do-release-upgrade` to 24.04 (in tmux; it opens a fallback
   sshd on 1022). Re-enable the grafana apt source it disables.
5. `pg_dropcluster 16 main --stop && pg_upgradecluster 14 main`, check, then
   `pg_dropcluster 14 main`.
6. `ansible-galaxy role install -r requirements.yml --force`, then
   `ansible-playbook push_servers.playbook.yml --tags netbox`.
7. Verify: UI, images, `/api/status/`, per-table row counts against the backup, the LG's
   "NetBox refresh: N participants" log line, and drop the snapshot once settled.

As run (2026-10-03/04): NetBox was down 23:57 → 05:57 UTC. Nearly all of that was the release
upgrade (~920 packages) and the dump/restore, both fsync-bound on pve02-paulave200's pool
(33-98 ms per write); the 4.7 migrations themselves take about a minute. Two surprises:

- 24.04 splits out a `systemd-resolved` package whose postinst replaces `/etc/resolv.conf` with
  the stub symlink, but our servers keep resolved masked (`sfmix_server` `dns` tag), so the VM came
  up with no DNS. Rerun `push_servers.playbook.yml --tags dns --limit <host>` after any 24.04
  release upgrade.
- This VM's `/etc/hosts` had no `localhost` line, so Postgres could not bind `localhost` at boot
  without DNS. Fixed by hand (the old file is `/etc/hosts.pre-localhost-fix`).

sshd is also down for a while mid-upgrade (24.04 moves it to `ssh.socket`); watch progress with
`qm guest exec 102 -- tail /var/log/dist-upgrade/apt-term.log` from the hypervisor instead.

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
