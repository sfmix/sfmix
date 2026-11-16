# 015 — mgmt-gw standard configuration (template-driven)

Status: templates and data written (2026-11-16); no gateway changed yet.
Precursor to doc 011 (management internet access): VLAN 202 should land on
gateways that already match one template.

## Goal

Every `mgmt-gw.<site>` (VyOS) is described by one set of templates plus a
short per-gateway data block. Operators may still change a box by hand;
`scripts/vyos_drift.py` shows what differs from the templates, so hand
changes are either folded into the templates or reverted.

## Where things live

- Data: `ansible/inventory/group_vars/management_router.yml`
  - `mgmt_gw.<host>`: the facts that are not derivable: site id `id`,
    fabric `trunk` port, `lan` and `wan` interfaces, uplink addresses and
    gateways, VyOS `release`, and a few per-site exceptions.
  - `mgmt_gw_wireguard_hubs`, `mgmt_gw_login_users`, `mgmt_gw_dns_forwarders`.
- Templates: `ansible/roles/sfmix_network_devices/templates/vyos/`, one file
  per part, in push order: `interfaces`, `wireguard`, `routing` (OSPF, static
  default, NAT), `firewall` (doc 010 plus global-options), `general`
  (system, NTP, DNS, LLDP, SSH, syslog, SNMP, accounts).
- Build: `ansible-playbook --vault-password-file ~/.sfmix_ansible_vault
  -i inventory/netbox.management_router.yml
  sfmix_network_devices.build.playbook.yml --tags management_router` →
  `ansible/sfmix_network_devices.configs/<host>/<part>.vyos_config.txt`
  (gitignored; contains secrets).
- Drift: `ssh <gw> 'vbash -ic "show configuration commands"' > live.txt;
  scripts/vyos_drift.py live.txt <configs>/<host>/*.vyos_config.txt`
  (pass the parts in push order). Empty output means the box matches.

## Ownership model

A template part either **owns** a subtree (emits `delete <subtree>` and then
the full desired content, which is a no-op in one commit when nothing
changed) or **owns only some leaves** inside a shared subtree.

| Owned subtree | Leaves only (rest left on the box) |
|---|---|
| `protocols ospf`, `protocols ospfv3` | `interfaces loopback lo address` |
| `protocols static route 0.0.0.0/0`, `route6 ::/0` | trunk `vif 200` address and description |
| `nat source` | LAN, WAN address and description |
| `firewall global-options`, the doc 010 chains and groups | WireGuard address, description, port, peer address and port (never keys) |
| `service ntp`, `dns forwarding`, `lldp`, `ssh`, `snmp`; `system syslog`, `system name-server` | `system login` for the listed users (keys, full name) |

Hand-managed (not templated): DHCP static mappings, console-server ports,
sfo02/fmt01 `br210`/`vxlan210`/VRRP, `nat66`, sfo02's sFlow static route and
route-map, and WireGuard keys. Interface speed, duplex and `hw-id` are left
alone too.

## The standard

Derived from `id` = N (NetBox `site_id`):

- loopback `10.N.0.0/32`, `2620:11a:b00f:0N00::/128`
- LAN `10.N.1.1/24`, `2620:11a:b00f:0N01::1/64` (plus the legacy 100.64 /24
  at sfo02 and fmt01)
- `<trunk>.200` `10.255.200.10N/24`, `2620:11a:b00f:fffe::10N/64`
- WireGuard: one tunnel to each hub (sfo02 = 1, fmt01 = 2): `wg<h><N>`,
  port `520<h><N>`, `10.255.<h>.(4N+1)` at the hub and `(4N+2)` at the
  spoke. The hub-to-hub tunnel uses sfo02's numbering at both ends (fmt01
  names it wg21).
- OSPF and OSPFv3 area 0, enabled per interface (no `network`
  statements), router-id `10.N.0.0`: lo and LAN passive, VLAN 200 cost 10,
  WireGuard cost 20. No defaults in OSPF (doc 011).
- Default route: static via the OOB uplink. NAT: `nat source rule 10`
  masquerade out the uplink.
- global-options as before, with `send-redirects disable`.
- NTP and SNMP as before; LLDP `interface all` with the LAN management
  address and SNMP; SSH `dynamic-protection` from
  `ixp_admin_source_subnets`; syslog over TCP to `metrics.oob.sfo02` (the
  sfmix-3 build spells `global`/`host` as `local`/`remote`).
- DNS: listen on `10.N.1.1` (and the legacy address), allow
  `10.0.0.0/8` and `2620:11a:b00f::/48` (and `100.64.0.0/10` where
  legacy), cache 10000, forward to `192.33.255.3`. Exceptions: sfo02
  recurses itself; sjc02 forwards to `4.2.2.2`/`9.9.9.9`, because
  192.33.255.3 refuses sjc02's source address (checked 2026-11-16).

## Findings (live state, 2026-11-16)

Fabric trunk per site (LLDP):

| site | trunk | peer | VLAN 200 OSPF |
|---|---|---|---|
| sfo01 | eth0 | switch01.sfo01:Ethernet4 (also carries the WAN, vif 50) | up |
| sfo02 | eth0 | switch02.sfo02:Ethernet7/1 | up |
| fmt01 | eth0 | switch03.fmt01:Ethernet5/1 | up |
| sjc01 | eth0 | was switch02.sjc01:Et11/1 (retired), **link down** | down |
| scl01 | eth0 | switch01.scl01:Ethernet48 | up |
| scl02 | eth0 | switch01.scl02:Et48 (no LLDP from the switch) | up |
| scl04 | eth0 | **mgmt-switch.scl04:ge-0/2/2**: VLAN 200 transits the mgmt-switch | up |
| sjc02 | eth0 | switch01.sjc02:Ethernet48 | up |
| scl05 | **eth1** | switch01.scl05, **link down** | down |

Config drift the templates remove:

- OSPF: two styles. sfo01, sjc01, scl01, scl02, scl04 and sjc02 used
  `network 10.0.0.0/11` + `10.255.0.0/16`; sfo02, fmt01 and scl05 used
  per-interface areas. sjc02 sets no router-id; none set an OSPFv3
  router-id (all run as `10.N.0.0` already).
- sjc02's tunnels (wg17, wg27) carry no OSPF, because sfo02 and fmt01 never
  enabled it on their ends. wg27's addresses were swapped (fmt01 .30,
  sjc02 .29).
- sfo01 does not advertise its IPv6 loopback (no OSPFv3 area on lo); sjc02
  does not advertise its IPv6 LAN; scl05 has no IPv6 LAN address and no
  OSPF on `eth1.200`.
- fmt01: wg23 and wg24 have no listen port; wg21 carries a stray
  `10.255.2.5/30`.
- sfo02 NAT is rule 1, everywhere else rule 10.
- scl01, sjc01 and sjc02 had no firewall global-options; the others had
  `send-redirects enable`.
- LLDP lists name long-gone interfaces (`vti1`, `wg0-2`, `switch0`).
- DNS: allow-from had public prefixes (the service listens only on
  internal addresses). Cache size was 150 at five sites; sfo01's recursor
  was serving a stale SERVFAIL for www.google.com (same as sfo02 on
  2026-11-09).
- sjc02 used three extra `time*.vyos.net` NTP servers and plain-UDP syslog.
  sjc01 used `1.1.1.1` as a system name-server.
- Descriptions were stale (e.g. sfo02 eth0 "switch01.oob.sfo02:Et35",
  fmt01 eth0 "switch01.fmt01:Eth13").

Not changed by the templates (decisions or physical work):

- Accounts: the boxes have admin, jof, pozar and oxidized, plus matt on
  scl01 and sjc02. `sfmix_admin_users` also lists xenith, igloo and
  richgibson. The template keeps today's set.
- The admin password is not templated unless `mgmt_gw_manage_admin_password`
  is true: on-box hashes are salted, so a diff cannot tell whether they
  match the vault.
- NetBox's mgmt-gw interfaces and IPs are stale (old WireGuard names, 100.64
  and old OpenColo addresses, no VLAN 200 at most sites), and
  `mgmt-gw-new.sjc01` is still an active device. NetBox does not drive these
  templates until it is reconciled.

## Rollout

Per gateway, the same procedure as the 2026-11-08 firewall rollout
(`reference_vyos_scripted_config`): `compare saved` empty → paste the
change set in `configure` → `compare` → `commit-confirm 10` → verify from
a fresh ssh → `confirm` → `save` → re-run the drift check (expect empty).

Risk order within a gateway, as separate commits:

1. **Cosmetic and services**: descriptions, LLDP, SNMP location, system,
   syslog, NTP, DNS allow-from and cache, SSH allow-list,
   global-options. Verify: DNS/NTP from a LAN host, syslog arriving in
   Loki.
2. **Routing**: OSPF restyle, router-ids, new interfaces in OSPF,
   WireGuard fixes, NAT renumber. Expect a brief adjacency flap. Verify:
   `show ip ospf neighbor`/`show ipv6 ospfv3 neighbor` Full on VLAN 200
   and the tunnels; LibreNMS/metrics still polling.

Order: sfo02 (closest to standard; adds wg17 OSPF), then fmt01 (wg27 and
port fixes, pairs with sjc02), sjc02, then sfo01, scl01, scl02, scl04, and
last sjc01 and scl05 (trunks down; they run on WireGuard).

After all nine show empty drift, the push playbook can carry future changes
(`sfmix_network_devices.push.playbook.yml --limit <gw>`). Until then it is
not the normal path.

## Follow-ups

- Physical: give sjc01 a trunk on switch03/04.sjc01; fix scl05's eth1 link
  to switch01.scl05. For doc 011, VLAN 202 must also be carried by
  mgmt-switch.scl04 and its uplink.
- doc 011: sfo01's WAN rides the same trunk as the fabric, so its OOB
  fallback is not independent of the fabric link.
- Decide accounts (matt everywhere? xenith/igloo/richgibson?) and the
  forwarder (keep 192.33.255.3 with sjc02 added to its ACL, or recurse
  everywhere like sfo02).
- Reconcile NetBox mgmt-gw interfaces, IPs and cables; retire
  `mgmt-gw-new.sjc01`.
- SSH `disable-password-authentication`, SNMP community rotation (doc 010
  leftovers).
