# NetBox transport-circuit cleanup — step-by-step

**Principle: device *link state* is authoritative.** A transport port whose
`show interfaces status` is **`connected`** (light present) means the dark-fibre circuit is
**delivered** → the NetBox circuit must be **Active** and its near-side termination **cabled**
to that interface. `notconnect` (no light) or `disabled` (shut) = **not delivered** → the
circuit is legitimately Planned / Deprovisioning / Decommissioned. The interface's `!! CID:`
comment is the canonical circuit id; `!! PP` is the ODF landing.

Built from live `show running-config` + `show interfaces status` on all 10 transport switches
(2026-07-04) cross-referenced with NetBox.

Legend: ✔=matches reality · ✎=change NetBox · ⚑=decision · 🖧=device-side fix.

---

## Step 0 — Status truth is already correct (no changes)

Link state confirms NetBox's status for every down circuit — **do NOT turn these up**:

| circuit | link state | NetBox | verdict |
|---|---|---|---|
| `DF-00000231-0002` (sfo01/Eth50) | `notconnect` | planned `SO-00000231-0002` | ✔ pending deployment — keep `SO-`, don't turn up |
| `FBDK/1721530/ZFS` (fmt01/Eth13, sjc01/Eth24) | `notconnect` | Decommissioned | ✔ down — leave (no conflict) |
| `FID-2023-0408` (scl02/Eth20,21) | `disabled` | Deprovisioning | ✔ shut — retire when physically removed |

All 10 delivered circuits below are already **Active** in NetBox — status needs no change; the
gap is only the **termination cabling**.

## Step 1 — Complete termination cabling for the DELIVERED (connected) circuits ✎

The real work. Each is `connected` and Active; cable the switch→ODF (per `!! PP`) →
`CircuitTermination`. Terminations are currently uncabled.

| circuit | delivered ends (connected) | ODF landing (`!! PP`) |
|---|---|---|
| `FID-2021-0106` | scl02/Eth35 | ODP.A.SHELF.1.SLOT.A Ports 3&4 (DWDM Ch21) |
| `FID-2022-0145` | scl02/Eth24 | ODP.A.SHELF.1.SLOT.A Ports 1&2 |
| `FID-2023-0407` | fmt01/Eth33, sjc01/Eth35 | 🖧 no PP comment on either end |
| `FID-2023-0409` | sfo02/sw02 Eth33, fmt01/sw03 Eth35 | sfo02: 303.02.07.64 Ports 3&4; fmt01: 🖧 none |
| `FID-2025-0742` | scl02/Eth33, sfo02/sw02 Eth35 | scl02: ODP.A.B Ports 5&6 (DWDM); sfo02: 303.01.06.36 Ports 21&22 |
| `F22M-0204477` | sfo01/Eth54 | (demarc D.04.05.08.44/14 via trace) |
| `FID-2025-0740` | scl02/Eth22+23, scl05/Eth53+54 | scl02: ODP.A.B P1&2; scl05: 110.02.01PNL01 P1&2 — **BiDi pair, Step 2** |
| `FID-2025-0741` | scl04/Eth31+32, scl05/Eth51+52 | scl05: 110.02.01PNL01 P3 — **BiDi pair, Step 2**; 🖧 scl04 no PP |
| `FID-2025-0762` | scl04/Eth29+30 | 🖧 scl04 no PP — **BiDi pair, Step 2**; ⚑ verify scl01 end |
| `FID-2025-0763` | scl02/Eth25+26 | ODP.A.B Ports 9&10 — **BiDi pair, Step 2** |

The 2 clean 1:1 duplex cases (`FID-2022-0145`@scl02, `F22M-0204477`@sfo01) are ready to cable
now (they're the `map_circuits --plan` proposals). The rest are gated on Step 2.

## Step 2 — Model BiDi-vs-duplex correctly ⚑ (decision, gates most of Step 1)

- **Duplex, one link** — one connected interface per side: `FID-2022-0145`, `-0742`, `-0106`,
  `-0409`, `F22M`. One circuit, one termination per side. ✔
- **Two BiDi links** — two connected interfaces per side on the two cores of one BIG circuit:
  `FID-2025-0740` (Eth22/23), `-0763` (Eth25/26), `-0741` (scl04 Eth31/32 + scl05 Eth51/52),
  `-0762` (scl04 Eth29/30). NetBox has one circuit / one termination per side but there are
  **two** delivered ports → recommend **one core-circuit per BiDi link** (its own termination,
  its own counter, two strands on the map). Decide before cabling these.

## Step 3 — Delivered transport NOT in NetBox ⚑

- **`HE #4757047`** (sfo02/Eth50) is `connected` = delivered, but has **no NetBox circuit** and
  is filtered from the map (retiring). Decide: add it as a circuit for completeness, or leave
  it out since it's being decommissioned. (No map impact either way.)

## Step 4 — Identify the delivered but undescribed ports 🖧 (device-side)

These are `connected` (delivered transport) but carry **no `!! CID` and no `{token}`**, so
nothing can tie them to a circuit:

- `switch02.sfo02/Eth21,22,23,24` (4 connected — likely LAG members of a delivered SF circuit)
- `switch01.sfo02/Eth52,54`
- `switch03.fmt01/Eth16/1`

Add the `description {CID}` + `!! CID`/`!! PP` on each so they resolve. (`switch02.fmt01/Eth3,5`
are `notconnect` — not delivered, ignore.) Also backfill `!! CID`/`!! PP` on
`switch01.scl04/Eth29–32` (delivered, token-only, no comments) and add missing `!! PP` on the
fmt01/sjc01 ends flagged in Step 1.

## Step 5 — Device-side description fix 🖧

`switch01.scl02/Eth24/1` reads "Transport **SFO02**" but `CID:FID-2022-0145` is scl02↔**scl03**
(NetBox is right). Fix the description's site token.

## Step 6 — SO → DF convention

No planned Boldyn order is delivered (all `SO-*` ports are down/absent), so **leave every `SO-`
as-is**; rename to `DF-<order>-<core>` only when its ports come up `connected`. The atlas already
matches both forms.

---

### Execution order
2 (decide BiDi model) → 1 (cable delivered circuits; start with the 2 clean duplex ones) →
4/5 (device-side identify/fix so the rest resolve) → 3 (HE decision). Steps 0 and 6 are
"leave as-is" confirmations. Re-run `map_circuits.py --audit --configs-dir …` after each batch;
success = every **connected** transport port resolves to its circuit termination.
