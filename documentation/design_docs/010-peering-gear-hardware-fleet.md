# 010 — peering-gear.sfmix.org: hardware fleet & donations

Status: phase 1 live (discovery → NetBox → admin-only web app). Schema
applied, first sync run, deployed to portal.sfmix.org 2026-11-05.

## Why

SFMIX runs on donated and second-hand hardware with **no spares**. We want one
place that shows the main fleet (peering switches, transit/core routers,
hypervisors) down to every slot and pluggable, makes the age/wear case
honestly from data the hardware reports, and shows **where a donation would
go** (empty DIMM slots, worn drives, missing redundant PSUs, empty optic
cages, aging chassis) and **where donations went** (donor → device → slot).

## Shape

```
devices ──(eAPI / NETCONF / SSH)──> scripts/hardware_inventory.py ──> NetBox ──> portal `gear` app
                                       (hwinv/ collectors + sync)       (SoT)     peering-gear.sfmix.org
```

NetBox is the only store; the app never talks to devices.

## NetBox model

| Thing | NetBox object | Notes |
|---|---|---|
| Slot (PSU bay, fan tray, optic cage, DIMM slot, drive bay, CPU socket, mainboard) | `dcim.modulebay` | `cf.slot_kind`, `cf.slot_accepts` (JSON: what fits), `label` (form factor / bus). Reuses device-type bays where names match (`PSU 1`, `PS1`, `Fan Tray 1`). |
| Installed part | `dcim.module` | `serial`, `status`, `cf.mfg_date`, `cf.power_on_hours`, `cf.endurance_used_pct`, `cf.donor`, `cf.donated_on` |
| Part number | `dcim.moduletype` | manufacturer + model, **module-type profile** + typed `attributes` (built-in CPU/Memory/Hard disk/Power supply/Fan; ours: Transceiver, Mainboard, Line card) |
| Chassis | `dcim.device` | `serial`, `cf.mfg_date`, `cf.hw_last_seen`, `cf.donor`, `cf.donated_on` |
| A wish / pledge | `planned` module in an empty bay | shows as a specific ask; `cf.donor` set = pledged |

Why modules + bays rather than inventory items: bays make **empty slots
first-class** (they are the donation opportunities), profiles give typed
attributes (DIMM size/class, drive type/size, PSU wattage) for upgrade
matching, and a `planned` module is a NetBox-native wishlist entry.
Interfaces are untouched (modules have no component templates, created with
`replicate_components=false`), so participant ports/cables/IPs are unaffected.

Schema lives in `ansible/netbox_schema.playbook.yml` (custom fields, the
`hw_slot_kind` choice set, `hwinv` tag, the three extra profiles).

## Discovery (`scripts/hardware_inventory.py`, `scripts/hwinv/`)

- `eos.py` — `show inventory` (chassis mfg date, PSUs, fan trays, every xcvr
  slot incl. empty), media/wavelength from `show interfaces transceiver
  hardware`, optic date codes from raw IDPROM.
- `sros.py` — Nokia NETCONF state: chassis/PSU/fan hardware-data, QSFP-DD
  cages; optic vendor via OUI table (SR-OS reports no vendor name).
- `junos.py` — MX150 chassis inventory; empty SFP cages from a fixed layout
  (Junos doesn't list them). Key/agent SSH auth (netrc password is refused).
- `linux.py` — Proxmox hosts over SSH (root, ProxyJump shell.sfmix.org): one
  stdlib-only remote script → DMI (board, BIOS, CPUs, all DIMM slots), SES
  enclosure slots / ATA ports / NVMe as drive bays, `smartctl --json` wear.
- `netbox_sync.py` — reconciles slots/parts. Rules: everything created is
  tagged `hwinv`; a vanished part is deleted only if hwinv-tagged *and* its
  kind is in the collector's `authoritative_kinds` (else warn); `planned`
  modules are never pruned, and when real hardware lands in a planned bay the
  donor fields carry over; bays are never deleted; no per-module "last seen"
  stamp (it would PATCH every module every run).

Run by hand: `make hardware_inventory` (dry run) / `make
hardware_inventory_apply` in `scripts/` with the write token from `scripts/.env`.

Nightly: `deploy_hardware_inventory.playbook.yml` (role `hardware_inventory`)
installs a systemd timer on netbox.sfo02 (10:30 UTC ± 20 min) running as an
unprivileged `hwinv` user, which reaches every device directly from inside the
network. Its credentials, least-privilege:

- devices: the shared read-only `oxidized` netrc login (already on every
  server via sfmix_server) for eAPI/NETCONF;
- Proxmox: its own ed25519 key (generated on the host) in root's
  `authorized_keys2` with `command="/usr/local/sbin/sfmix-hw-inventory",restrict`
  -- it can only run the read-only inventory script (`hwinv/remote_linux_inventory.py`);
  root's `authorized_keys` is the pmxcfs cluster symlink and is not touched;
- MX150s: the same public key on the `oxidized` login (class view-only),
  added by hand -- they refuse the shared password;
- Nokia cr1s: dedicated user `hwinv` (access netconf only, profile
  `hwinv-readonly` = read-only-all + NETCONF get/get-config/get-schema/
  close-session, the job's ECDSA key -- SR-OS takes no ed25519 user keys;
  random never-stored password because SR-OS requires one). Not `oxidized`:
  on SR-OS it has no NETCONF and its profile is `default-action permit-all`
  (i.e. not read-only) while its password sits in /home/sfmix/.netrc on every
  server -- worth tightening separately;
- NetBox: user `hardware-inventory` (view_all + write on module bays/modules/
  module types/manufacturers + change on devices), created by
  `scripts/hwinv/bootstrap_netbox_identity.py`, token vaulted in the role.

## App (`portal/gear/`)

Same Django project/container as the portal; `GearHostMiddleware` serves
`gear.urls` for `GEAR_HOSTS`. OIDC via the existing `portal` authentik
client (extra redirect URIs in terraform), gated on the `oidc_is_ix_admin`
session flag (IX Administrators) while we build it up. Pages: fleet, device
slot map, needs ("where donations could go", with spares table), donations
(ledger + sankey). Needs/severity/suggestions are computed in
`gear/analysis.py`; curated upgrade candidates live in `gear/catalog.py`
(vet before asking anyone).

Pages never wait on NetBox: a cold fetch pages through ~1k bays/modules
(~12 s), and hardware changes rarely, so each gunicorn worker runs a thread
that re-fetches a snapshot every 15 min (file-locked so one worker does it,
backoff on failure) into the shared cache with no expiry. Stale-but-fast beats
fresh-but-slow; the footer shows the snapshot's age and has "Refresh now". Dev: `GEAR_USE_FIXTURES=true DEV_AUTOLOGIN=admin
python manage.py runserver` → http://gear.localhost:8000/ (serial-scrubbed
fixture in `gear/devmock/fleet.json`).

## Deploy order

1. `netbox_schema.playbook.yml` (write token) — custom fields, tag, profiles.
2. `hardware_inventory.py` dry run, review, then apply.
3. Portal NetBox token needs view on dcim.modulebay/module/moduletype.
4. DNS: `peering-gear CNAME portal` (sfmix_dns), then terraform apply in
   `terraform/authentik` (redirect URIs).
5. `deploy_portal.playbook.yml` — vhost, cert, `.env` (`GEAR_HOSTS`).

## Findings from the first collection (2026-11-05)

- NetBox device types wrong: the four paulave/warmsprings hypervisors are
  **SYS-E300-9A** (A2SDi-TP8F, Atom C3858), not E300-8D; pve01.scl04 is an
  X10DRU-i+ (6028U-class, 2014 Haswell), not SYS-6029U.
- switch03.sjc01 / switch04.sjc01 serials are swapped in NetBox.
- pve02-warmsprings Samsung 870 QVO pair at **94%** endurance used.
- pve01.scl04: 64 GB in 8 of 24 DIMM slots (board takes 1.5 TB); 11 of 12
  data drives are desktop ST4000DM000 at up to 8.9 years powered on.
- cr1.scl02 runs on one PSU of three; cr1.sjc01 on two.
- switch01.sfo01 still carries 2005–2009 SFP+ optics.

## Incoming (not yet installed) hardware

Recorded by hand: device status `inventory` (the app's "Incoming" section),
site `unassigned` ("pending site planning"; no lat/lon or region so it stays
off the map, and never role `peering_switch` -- the IX-F export and
new_participant.py don't filter on status). Bays/modules entered manually
(no `hwinv` tag); a worn part without SMART data gets tag `hw-worn`, a dead
one module status `failed`. The nightly job only collects `active` devices, so
it never touches these; once a server is installed and active, discovery
creates its real bays -- delete the hand-made ones then.
First use: 3x HPE DL360 Gen9 (incoming-dl360g9-1..3), 2026-11-05; their
8x SFF drive bays are assumed, not confirmed.

## Later

- Track spares (e.g. a "spares shelf" device per site, modules `offline`).
- Collectors for edge-gw (Gowin R86S), mgmt switches/gateways, PDUs.
- Schedule discovery (systemd timer / Django-Q) once trusted.
- Public mode: drop the admin gate, hide serials, add donor opt-in.
