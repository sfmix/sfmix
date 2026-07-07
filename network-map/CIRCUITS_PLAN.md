# Firming up the transport data model: NetBox Circuits as source-of-truth

> **Status: SHIPPED (2026-07).** This plan is realized — the builder
> (`portal/mapbuild/builder.py`) is fully NetBox-sourced (devices, circuits,
> cabling, speeds); the interface-description string-parsing path described below
> is retired, and the builder runs in the portal (not metrics.sfo02). Kept for
> historical context / rationale. See `ARCHITECTURE.md` for the current design.

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

## Discovered reality (live NetBox, 2026-07-04)

A survey of production NetBox shows the model is **already substantially there** — this
is more "validate & complete + wire the builder" than "bootstrap from scratch":

- `circuits.CircuitType` **`dark-fiber` exists**; **19 dark-fibre circuits** across 5
  providers, **39 terminations**, with real lifecycle status (Active / Deprovisioning
  `FID-2023-0408` / Decommissioned `FBDK/1721530/ZFS` / Planned `SO-*` + `oak01`/`scl03`
  spans the map doesn't know yet). NetBox already models `DF-231-4` correctly as **two**
  circuits (`DF-00000231-0004-0001/0002`) — richer than the atlas's single file.
- The map-transport ports are the **`switch01.<site>` interfaces with
  `Core: Transport … {TOKEN}` descriptions** (36 of them). The `{TOKEN}` **equals the
  NetBox circuit CID** for the BIG `FID-*` circuits (exact match). Zayo/Boldyn need
  CID normalization (`FBDK-1721530` ↔ `FBDK/1721530/ZFS`, `DF-231-4` ↔ `DF-00000231-0004-*`).
- **17/36 transport interfaces are already cabled through patch panels.** A live trace,
  e.g. `switch01.scl02/Ethernet20/1 → front CAB.0126 → rear → IDF2.01 → front ODP.C/02C7 →
  (dead end)`, shows the ODF chain is built but **stops before the CircuitTermination**.
  So the concrete gap is the **last hop**: cabling each patch-panel demarc to its
  `CircuitTermination`, after which the interface traces cleanly to its circuit.
- The `core_port` **tag** is a *different* thing (it's on `ar1/cr1.*.transit` routers,
  empty descriptions) — do NOT use it to select map-transport ports. Use the
  `Core: Transport` description (bootstrap signal) → NetBox circuit (source of truth).
- `pynetbox` `CircuitTermination` has no `.trace()`; use the REST
  `/api/dcim/interfaces/{id}/trace/` (or `/circuit-terminations/{id}/trace/`).

This sharpens the phases below: Phase 1 is mostly **completing termination cabling**
(the last patch-panel hop) for circuits whose switch ports are already described/cabled;
Phase 2's audit is the work-list generator; Phase 3 keys the builder off the CID the
description already carries.

## Authoritative circuit-ID formats & fibre model (from the turn-up docs)

Confirmed against the carriers' service-order / LOA / OTDR files in the KMZ bundles:

- **BIG Fiber:** `FID-YYYY-NNNN` (e.g. `FID-2025-0742`). A 2-fibre **duplex** span is
  **one** circuit (docs are "2-F", bidirectional-OTDR). Already matches NetBox + atlas.
- **Zayo:** `F22M-0204477` (matches); `FBDK-1721530-ZFS` (folder) == NetBox
  `FBDK/1721530/ZFS` (slashes) — Decommissioned.
- **Boldyn:** service order **#00000231**; ordered sub-items are `SO-00000231-000X`
  (e.g. `SO-00000231-0000` = sjc02↔scl05). A turned-up duplex span exposes its **two
  cores** as separate circuits `DF-00000231-0004-0001` / `-0002` (fmt01↔sjc02).

**Fibre model — draw per LOGICAL LINK, don't collapse cores.** The unit the map draws
is a **logical link = a transceiver / switch interface with its own traffic counter**,
NOT a core and NOT a circuit. The physical fibre (cores) and NetBox circuits are the
*substrate* that supplies geometry and validates the path. The data model keeps both
link types and their terminations distinct:
- **BiDi** transceiver = one core = **one** logical link = one drawn strand.
- **Duplex** = two cores. Either:
  - used as **one** bidirectional link (one transceiver pair, one interface, one
    counter) → **one** drawn strand; or
  - lit with **two BiDi transceivers, one per core** → **two** independent links (two
    interfaces, two counters) → **two** distinct drawn strands.
  So a duplex span can be one or two strands depending on how it's lit — the map keys
  off interfaces/counters, not core count. NetBox already exposes cores as separate
  circuits (`…-0001/-0002`); which interface(s) terminate on them decides the strands.
- **LAG** = N logical links bonded on one port-channel → N strands, grouped, spaced
  (as today). Distinct links on the same span (2× BiDi, or hot+standby) are also
  separate spaced strands.
- **Passive-site spans:** a logical A↔Z can be **two spliced dark spans through a
  passive site** — e.g. Boldyn `-0002` (365 Main→720 2nd) + `-0003` (720 2nd→48233
  Warm Springs) build sfo01↔fmt01 via the passive **720 2nd (oak01)** site; `scl03` is
  similar. The builder chains the spliced spans into one drawn corridor for that link.

**Atlas alignment done** (this pass): renamed/keyed to the authoritative CIDs —
`DF-231-4`→`DF-00000231-0004` (match carries both cores + legacy tokens),
`Boldyn-00000231-0000`→`SO-00000231-0000`, `FBDK-1721530`→`FBDK-1721530-ZFS`. Audit now
shows **0 atlas files without a matching circuit**; the only active-circuit-without-atlas
is `FID-2022-0145` (scl02↔scl03 passive span, not yet drawn).

## Runtime `!!` interface comments = authoritative device→circuit link

The Arista EOS running-config carries `!!` comment lines on each transport interface that
are the **authoritative** device→dark-fibre linkage — richer and more reliable than the
`{token}` in the `description`:

```
interface Ethernet24/1
   !! PP ODP.A.SHELF.1.SLOT.A Ports 1 & 2 (1st cable bundle - cable id 7 & 8)
   !! SO:CAS-02800032 CID:FID-2022-0145
   description Core: Transport SFO02 via BandwidthIG+DRT {FID-2022-0145} [100Gbps]
```

- **Boldyn id convention (SFMIX = Boldyn customer `00000231`):** `SO-00000231-<order>` is
  the service **order**; `DF-00000231-<order>[-<core>]` is the dark-fibre **circuit** it
  turns up as (a duplex order yields cores `-0001`/`-0002`). **Circuit ids are `DF-`;**
  `SO-` is the order. NetBox today names the *turned-up* circuits `DF-…` (correct) but the
  *planned* ones `SO-…` — those circuit CIDs should be renamed to `DF-` (or kept `SO-`
  until turn-up — a policy call). The atlas keys on the `DF-` id and carries the `SO-` +
  bare-order forms in `match`, so it resolves whichever NetBox holds. `map_circuits --audit`
  flags `SO-`-named dark-fibre circuits as rename candidates.
- **`!! SO:<so> CID:<cid>`** — canonical service-order + **circuit id**. Match on THIS,
  not the `{token}`. The token is decorative and sometimes wrong (Eth24/1's description
  says `SFO02`, but `CID:FID-2022-0145` is scl02↔scl03 per NetBox — the CID wins).
- **`!! PP <panel> Port(s) N …`** — the patch-panel/ODF landing (14/32 ifaces have it).
  This is the switch→ODF hop that completes/validates the trace to the circuit termination
  — the exact info needed to cable the uncabled ports.
- **`BiDi #N` vs "Ports A & B / cable id X & Y"** — the fibre model per interface:
  - two `BiDi #1`/`#2` transceivers on one duplex fibre = **two independent links (two
    counters) = two drawn strands**; in NetBox that wants **one core-circuit per BiDi
    link**. This EXPLAINS the earlier "2 switch ports, 1 termination" ambiguity
    (`FID-2023-0408`, `-0740`, `-0741`, `-0763`).
  - a `duplex` single link (one transceiver pair, e.g. `FID-2022-0145`, `-0742`, `-0106`)
    = **one strand**. `-0742`/`-0106` are DWDM (`Ch 21`).
- **New gap surfaced:** `sfo01/Eth50` comment `CID:DF-00000231-0002-0001` (the sfo01↔oak01
  passive-site span) is NOT in NetBox (only the planned `SO-00000231-0002`) — add the
  turned-up circuit.

**Implication for the tool + builder:** read the runtime `!! CID` / `!! PP` (SSH
`show running-config`, direct — no PTY per the EOS exec-mode gotcha) as the authoritative
device→circuit signal and patch-target hint, alongside NetBox (the circuit/termination
source of truth). The description `{token}` demotes to a last-resort fallback.

## Phase 1 — Manual NetBox cleanup + a gap-detector that prompts a human (NOT auto-cabling)

Decision: **do NOT automate circuit/cable creation.** Circuit terminations change rarely,
and physical patching is human knowledge; automating it is complex and risky for little
benefit. Instead:

- **Humans manually clean up NetBox** — cable the terminations (through patch panels),
  add the missing circuit (`DF-231-2`), backfill empty `{…}` description tokens, mark
  lifecycle, etc. NetBox is the source of truth and is curated by hand.
- **The tool's only job is to DETECT clear gaps and prompt** — no `--apply`, no writes.
  It runs periodically (or in the discovery-bot) and surfaces, in human terms:
  - a transport interface whose cable **trace dead-ends** (patch chain incomplete), or
    has **no cable** at all → "patch `switch01.scl02/Eth20` through to its circuit";
  - a transport link between two sites/locations with **no corresponding dark-fibre
    circuit** in NetBox between them → "create/attach the circuit for this span";
  - a trace that reaches a **different** circuit than the description claims → data error.
  This is exactly `map_circuits.py --audit` (Phase 2) — it *is* the gap prompt. Optionally
  wire its output into the discovery-bot so new/edited patches get flagged for a human.

No `discover_transport_circuits()` write path is built. The audit stays strictly
read-only.

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
- Start from the **switch transport interfaces** (the logical links / traffic counters)
  and **trace each through patch panels to its dark-fibre circuit** (source of truth for
  the span it rides). One drawn strand per interface — so a duplex lit as one link is
  one strand, a duplex lit with two BiDi transceivers is two strands (two interfaces),
  and cores are never collapsed. `a_device`/`z_device` + member ports come from the
  interfaces at each end.
- Group strands by switch **port-channel** → LAG `members`; capacity = Σ member
  `interface.speed`. Non-bonded links on the same span (2× BiDi, hot+standby) render as
  separate spaced strands.
- Geometry: from the circuit/span the trace lands on, atlas-matched by cid (exact, no
  token guessing); chain passive-site spliced spans into one corridor.
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
