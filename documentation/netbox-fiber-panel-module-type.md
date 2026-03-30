# NetBox Fiber Panel Module Type Changes

**Date:** 2026-03-29

## Summary

Created a new NetBox module type for the Petabit Scale FHD MPO-LC cassettes used in the FCE4U fiber patch panel shelves. The key change is using NetBox's `{module}` template variable in port names so that cassettes can be installed in multiple module bays without name collisions.

## Problem

The original module type (ID 788) used static port names (e.g. `A1 (Port 01)`, `MPO A`). When installing the same module type into more than one module bay on a device, NetBox rejected the second installation due to duplicate front/rear port names.

## Changes

### New Module Type (ID 790)

- **Manufacturer:** Petabit Scale
- **Model:** `MPO-LC Cassette, 3xMPO-8 (Male)/3x6-core Shuttered LC Quad (Blue)`
- **Old module type 788** was removed/replaced.

### Port Naming with `{module}` Templating

All port template names use the `{module}-` prefix, which NetBox expands to the module bay **position** value upon installation. Module bay positions use the format `SlotX` (no space) to avoid ambiguity between the slot letter and the MPO group letter (e.g. `SlotB-B2-14` is clearly Slot B, MPO group B, pair 2, fiber 14).

**Rear port templates (3):**

| Template Name    | Type | Positions | Color  |
|------------------|------|-----------|--------|
| `{module}-MPO-A` | MPO  | 12        | Blue   |
| `{module}-MPO-B` | MPO  | 12        | Orange |
| `{module}-MPO-C` | MPO  | 12        | Green  |

**Front port templates (24):**

Each MPO has 4 LC duplex pairs (8 individual LC/UPC fiber ports), for 24 total front ports.

| Template Name    | Rear Port        | Positions |
|------------------|------------------|-----------|
| `{module}-A1-01` | `{module}-MPO-A` | 1         |
| `{module}-A1-02` | `{module}-MPO-A` | 2         |
| `{module}-A2-03` | `{module}-MPO-A` | 3         |
| `{module}-A2-04` | `{module}-MPO-A` | 4         |
| `{module}-A3-05` | `{module}-MPO-A` | 9         |
| `{module}-A3-06` | `{module}-MPO-A` | 10        |
| `{module}-A4-07` | `{module}-MPO-A` | 11        |
| `{module}-A4-08` | `{module}-MPO-A` | 12        |
| `{module}-B1-09` | `{module}-MPO-B` | 1         |
| `{module}-B1-10` | `{module}-MPO-B` | 2         |
| `{module}-B2-11` | `{module}-MPO-B` | 3         |
| `{module}-B2-12` | `{module}-MPO-B` | 4         |
| `{module}-B3-13` | `{module}-MPO-B` | 9         |
| `{module}-B3-14` | `{module}-MPO-B` | 10        |
| `{module}-B4-15` | `{module}-MPO-B` | 11        |
| `{module}-B4-16` | `{module}-MPO-B` | 12        |
| `{module}-C1-17` | `{module}-MPO-C` | 1         |
| `{module}-C1-18` | `{module}-MPO-C` | 2         |
| `{module}-C2-19` | `{module}-MPO-C` | 3         |
| `{module}-C2-20` | `{module}-MPO-C` | 4         |
| `{module}-C3-21` | `{module}-MPO-C` | 9         |
| `{module}-C3-22` | `{module}-MPO-C` | 10        |
| `{module}-C4-23` | `{module}-MPO-C` | 11        |
| `{module}-C4-24` | `{module}-MPO-C` | 12        |

MPO-8 polarity: fiber pairs map to MPO positions 1-2, 3-4, 9-10, 11-12 (positions 5-8 unused in 8-fiber MPO).

### Example: Installed in "Slot A"

When installed in module bay "Slot A" (position=`SlotA`), the ports render as:

- `SlotA-MPO-A`, `SlotA-MPO-B`, `SlotA-MPO-C` (rear)
- `SlotA-A1-01` through `SlotA-C4-24` (front)

Installing a second cassette in "Slot B" produces `SlotB-MPO-A`, `SlotB-A1-01`, etc. — no name collisions.

### Module Type: LC-LC Cassette (ID 791)

- **Manufacturer:** Petabit Scale
- **Model:** `LC-LC Cassette, 12x LC-LC Duplex Shuttered (Blue)`

A 1:1 passthrough cassette with 12 LC duplex connectors (24 individual fibers). Front and rear ports are both LC/UPC, blue, numbered 1–24.

**Rear port templates (24):** `{module}-01` through `{module}-24` (LC/UPC, blue, 1 position each)

**Front port templates (24):** `{module}-01` through `{module}-24` (LC/UPC, blue, each mapped 1:1 to corresponding rear port)

When installed in e.g. "Slot A", ports render as `SlotA-01` through `SlotA-24`.

---

### Device Type: FCE4U (ID 1062)

Updated all 12 module bay templates. The **name** and **label** remain human-readable (`Slot A`), while the **position** field uses `SlotX` (no space) since this is what `{module}` expands to in port names.

| Name   | Label  | Position |
|--------|--------|----------|
| Slot A | Slot A | SlotA    |
| Slot B | Slot B | SlotB    |
| ...    | ...    | ...      |
| Slot L | Slot L | SlotL    |

### Device: CP:0218:1406875 (ID 210)

Updated module bay positions on the device instance to match (`SlotA`–`SlotL`). Renamed all 162 existing instantiated ports (18 rear + 144 front across 6 populated slots) to use the `Slot` prefix.

## NetBox Links

- [Module Type 790 — MPO-LC Cassette](https://netbox.sfmix.org/dcim/module-types/790/)
- [Module Type 791 — LC-LC Cassette](https://netbox.sfmix.org/dcim/module-types/791/)
- [Device Type FCE4U](https://netbox.sfmix.org/dcim/device-types/1062/)
- [Device CP:0218:1406875](https://netbox.sfmix.org/dcim/devices/210/)
