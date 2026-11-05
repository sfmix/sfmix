# 010 — peering-gear.sfmix.org: hardware fleet & donations

Status: phase 1 built (discovery → NetBox → admin-only web app). 2026-11-05.

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

Run: `make hardware_inventory` (dry run) / `make hardware_inventory_apply`
in `scripts/` with the write token from `scripts/.env`. Not scheduled yet.

## App (`portal/gear/`)

Same Django project/container as the portal; `GearHostMiddleware` serves
`gear.urls` for `GEAR_HOSTS`. OIDC via the existing `portal` authentik
client (extra redirect URIs in terraform), gated on the `oidc_is_ix_admin`
session flag (IX Administrators) while we build it up. Pages: fleet, device
slot map, needs ("where donations could go", with spares table), donations
(ledger + sankey). Needs/severity/suggestions are computed in
`gear/analysis.py`; curated upgrade candidates live in `gear/catalog.py`
(vet before asking anyone). Dev: `GEAR_USE_FIXTURES=true DEV_AUTOLOGIN=admin
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

## Later

- Track spares (e.g. a "spares shelf" device per site, modules `offline`).
- Collectors for edge-gw (Gowin R86S), mgmt switches/gateways, PDUs.
- Schedule discovery (systemd timer / Django-Q) once trusted.
- Public mode: drop the admin gate, hide serials, add donor opt-in.
