# Firming up the transport data model: NetBox Circuits as source-of-truth

## Problem

Today the map's inter-site transport links are derived by **string-parsing interface
descriptions** (`Core: Transport <SITE> via <Provider> {<TOKEN>} [<Speed>]`) and
pulling speed/oper from Prometheus labels. That's fragile: a typo, a missing token,
or a re-described port silently drops or mis-places a backbone link, and there is no
authoritative record of what dark fibre actually interconnects the sites.

## Target model

Every inter-site transport span becomes a **NetBox `Circuit`** (the dark-fibre object),
and the map builder treats NetBox — not descriptions — as source-of-truth.

```
circuits.Provider        Zayo | Boldyn | BIG Fiber | Hurricane Electric | DRT
circuits.CircuitType     "Dark Fiber"
circuits.Circuit         cid = FID-2025-0742 (the carrier circuit id), provider, type,
                         status, custom_field: map_atlas_id (-> atlas/<id>.geojson)
circuits.CircuitTermination  A -> Site(sfo02), Z -> Site(scl02)   (A/Z by sorted slug)
        each termination is CABLED to the switch interface it lands on —
        directly, or through dcim FrontPort/RearPort patch panels.
```

- **The switch interface is the lit end**; the circuit termination is the demarc.
- **Which interface a circuit lands on** is resolved by the **cable-trace API**
  (`/api/dcim/interfaces/{id}/trace/`), which walks front/rear patch-panel ports to
  the far end. This is exactly the patch-panel case the request calls out.
- **Capacity (lit speed)** stays the switch interface's speed (NetBox `interface.speed`,
  set by `discover_hardware_interfaces`; Prometheus `ifspeed` as fallback). Dark fibre
  itself is unrated.
- **Live status** stays runtime (LLDP topology + oper) — NetBox holds intent, not the
  live weathermap state.
- **LAG / multi-strand**: a bundle is N circuits landing on the member interfaces of one
  switch port-channel. The map groups them by that LAG interface → `members = N`. Distinct
  circuits on the same site-pair (e.g. 400G hot + 100G standby) are separate `Circuit`s.
- **Geometry** still comes from the coarsened atlas; the match key is now the circuit's
  `map_atlas_id` / cid from NetBox instead of a parsed `{token}`.

## Phase 1 — Extend `discovery.py` to bootstrap circuits (dry-run first)

Add a `discover_transport_circuits()` capability that fits the existing plan/apply
pattern (`dry_run=True` logs "[DRY-RUN] Would …", `--apply` writes). It runs per device
or once globally, reconciling idempotently. Signals it fuses to bootstrap:

1. **`core_port`-tagged interfaces** (discovery already maintains this tag) + their
   descriptions → parse remote site, provider, circuit token, speed.
2. **LLDP topology** (sflow-rt) → confirm the far device:port, hence the far site, so
   we never invent a termination from a typo'd description alone.
3. **Existing NetBox cabling** → if the interface already traces to a CircuitTermination,
   VALIDATE/enrich (never clobber human-entered patch-panel cabling).

Reconciliation rules (idempotent):
- Ensure Provider + CircuitType exist.
- Ensure a `Circuit(cid)` exists with provider/type/`map_atlas_id`.
- Ensure two CircuitTerminations at the two confirmed sites (A/Z by sorted slug).
- Cabling: if the interface is **directly** cable-able to the termination (no patch
  panel), propose the cable; if a **patch-panel path** exists, only validate the trace
  resolves to this circuit and flag mismatches for a human (we can't invent physical
  patch cabling). Emit a clear "needs cabling" report for the gaps.

Everything is proposal-only until reviewed — this rides the existing discovery-bot
approve-to-apply flow.

## Phase 2 — Validation / audit tooling (read-only)

A `--audit-circuits` mode (in discovery.py or a small companion) that cross-checks the
three signals and reports, without writing:
- transport ports (by description/tag/LLDP) with **no** NetBox Circuit → to create;
- NetBox Circuits with **no cabling / trace** to a live interface → dangling;
- terminations whose **site disagrees** with LLDP's far end → data error;
- circuits present in the atlas but **not** in NetBox, and vice-versa;
- speed/provider mismatches between description and NetBox.

This is the tool we run repeatedly until the dataset is clean.

## Phase 3 — Rewrite the map builder to read NetBox

`gen_map_structure.py` gains a NetBox-circuits path (kept behind a flag during
migration so we can diff it against the description parser):
- Enumerate `circuits.circuits` of type Dark Fiber; for each, read A/Z terminations →
  sites, and **trace each termination to its switch interface** (through patch panels)
  → `a_device`/`z_device` + the member ports for the private traffic feed.
- Group by switch LAG interface → `members`; capacity = Σ member `interface.speed`.
- Geometry: atlas match by `map_atlas_id`/cid (exact, no token guessing).
- Live status/util: unchanged (LLDP + Prometheus by the traced member ports).
- The description parser (`parse_core_ports`) demotes to a **bootstrap-only** helper for
  `discovery.py`; the map no longer depends on it.

`--check` gains NetBox-vs-atlas and NetBox-vs-live drift (subsumes today's checks).

## Phase 4 — Discover & validate all existing spans

1. Run `--audit-circuits` → gap list.
2. Run circuit bootstrap in **dry-run**; review the proposed Circuits/terminations.
3. Apply (via the discovery-bot approve flow); hand-cable the patch-panel gaps the
   audit flagged.
4. Re-run audit until clean (0 dangling, 0 site disagreements, every transport port →
   a traced circuit, every atlas file → a circuit).
5. Flip the builder to NetBox mode; diff map.json against the description-mode output to
   confirm parity; then remove the description dependency.

## Safety / sequencing

- Read-only first (Phase 2 audit), then dry-run bootstrap, then apply — nothing writes
  to production NetBox without review, consistent with the discovery-bot model.
- Builder runs both modes during migration and diffs, so the public map can't regress.
- `map.json` stays byte-compatible (v2 geometry schema unchanged); only the *source* of
  the cable list changes.

## Open decisions (need your call)

1. **CircuitType name & a `map_atlas_id` custom field** — add the custom field on
   `Circuit`, or reuse the cid as the atlas key directly?
2. **LAG grouping key** — group map "cables" by the switch **port-channel** interface
   (cleanest), or by (site-pair + provider)? Affects how hot/standby vs LAG render.
3. **Patch-panel cabling ownership** — should bootstrap ever create interface↔termination
   cables when the path is unambiguous, or always leave physical cabling to humans and
   only validate?
4. **Provider granularity** — model the actual carrier (Zayo/Boldyn/…) as the NetBox
   Provider, keeping providers out of the public map.json (they already never leak).
