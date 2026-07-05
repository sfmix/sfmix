# NetBox transport-circuit cleanup — step-by-step

**Principle: the device state is authoritative.** If a switch transport port is *up*, its
dark-fibre circuit is *delivered* → the NetBox circuit must exist, be **Active**, and its
near-side termination must be **cabled** (through patch panels) to that switch interface.
The interface's `!! CID:` comment is the canonical circuit id; `!! PP` is the ODF landing.

Derived from the live running-configs of all transport switches (2026-07-04) cross-referenced
with NetBox. Note: `switch01.scl04`'s transport ports carry only the `{token}` in the
description — they lack the `!! CID`/`!! PP` comments the other sites use (device-side gap,
Step 6).

Legend: ✔=matches reality · ✎=change NetBox · ⚑=needs a decision · 🖧=device-side fix.

---

## Step 1 — Reconcile circuit status against device state

| circuit | device ports | NetBox status | action |
|---|---|---|---|
| `DF-00000231-0002-0001` | sfo01/Eth50/1 **up** | **MISSING** (only planned `SO-00000231-0002`) | ✎ **turn up** — see Step 2 |
| `FBDK/1721530/ZFS` | fmt01/Eth13/1 **up**, sjc01/Eth24/1 up | **Decommissioned** | ⚑ conflict: port is up but circuit decommissioned. Either shut the ports (truly retired) or set the circuit back to Active. Reconcile with ops. |
| `FID-2023-0408` | scl02/Eth20/1, /Eth21/1 **shutdown** | Deprovisioning | ✔ consistent — finish decommission (remove cabling + circuit when done). |
| all other `FID-*`, `F22M-0204477` | ≥1 port up | Active | ✔ status correct; complete cabling (Step 3). |

## Step 2 — Turn up the delivered Boldyn span `00000231-0002`

`sfo01/Eth50/1` is up with `CID:DF-00000231-0002-0001` (link=duplex), but NetBox only has the
planned order `SO-00000231-0002` (sfo01↔oak01).

1. ✎ Create dark-fibre circuit **`DF-00000231-0002-0001`** (and **`-0002`** for the 2nd core of
   the duplex), provider Boldyn Networks, status **Active**, referencing service order
   `SO-00000231-0002`. Either repurpose the existing `SO-00000231-0002` object (rename → `DF-…`)
   or create the `DF-…` circuits and keep `SO-…` as the order record — your convention call.
2. ✎ Terminations: **A = sfo01**, **Z = oak01** (720 2nd, the passive site).
3. ⚑ Passive-site chain: this span is the sfo01→oak01 leg; `SO-00000231-0003` is the oak01→fmt01
   leg. Confirm whether the *logical* link is sfo01↔fmt01 spliced through oak01, and whether the
   fmt01 far-end port exists (none was observed on fmt01). Turn up `-0003` similarly if delivered.

## Step 3 — Complete termination cabling for delivered circuits (use `!! PP`)

For each up port: ensure the switch→ODF patch exists (per `!! PP`), then cable the ODF demarc
to the circuit's near-side `CircuitTermination`. (9 already trace switch→ODF and only need the
last hop; the rest need the full patch entered from the PP.)

| circuit | side | switch iface | ODF landing (`!! PP`) | termination cabled? |
|---|---|---|---|---|
| `FID-2021-0106` | scl02 | Eth35/1 | ODP.A.SHELF.1.SLOT.A Ports 3 & 4 (DWDM Ch21) | ✎ cable |
| `FID-2022-0145` | scl02 | Eth24/1 | ODP.A.SHELF.1.SLOT.A Ports 1 & 2 | ✎ cable |
| `FID-2025-0742` | scl02 | Eth33/1 | ODP.A.SHELF.1.SLOT.B Ports 5 & 6 (DWDM Ch21) | ✎ cable |
| `FID-2025-0742` | sfo02 | switch02 Eth35/1 | 303.01.06.36 Ports 21 & 22 | ✎ cable |
| `FID-2023-0409` | sfo02 | switch02 Eth33/1 | 303.02.07.64 Ports 3 & 4 | ✎ cable |
| `FID-2023-0409` | fmt01 | switch03 Eth35/1 | (no PP in comment) | 🖧 add PP comment, then cable |
| `FID-2025-0740` | scl05 | Eth53/1, Eth54/1 | 110.02.01PNL01 Ports 1 & 2 | ✎ cable (2 BiDi — Step 4) |
| `FID-2025-0741` | scl05 | Eth51/1, Eth52/1 | 110.02.01PNL01 Port 3 (Eth52 missing PP) | ✎ cable; 🖧 add Eth52 PP |
| `FID-2025-0763` | scl02 | Eth25/1, Eth26/1 | ODP.A.SHELF.1.SLOT.B Ports 9 & 10 | ✎ cable (2 BiDi — Step 4) |
| `FID-2023-0407` | sjc01 | switch03 Eth35/1 | (no PP) | 🖧 add PP, then cable |
| `FID-2023-0407` | fmt01 | switch03 Eth33/1 | (no PP) | 🖧 add PP, then cable |
| `F22M-0204477` | sfo01 | Eth54/1 | (no PP; trace demarc D.04.05.08.44/14) | ✎ cable |
| `FID-2025-0762` | scl04 | Eth29/1, Eth30/1 (BiDi pair) | (no PP — comment missing) | 🖧 add PP, then cable (Step 4) |
| `FID-2025-0762` | scl01 | (scl01 has no observed port) | — | ⚑ verify scl01 end |
| `FID-2025-0741` | scl04 | Eth31/1, Eth32/1 (BiDi pair) | (no PP — comment missing) | 🖧 add PP, then cable (Step 4) |

## Step 4 — Model BiDi-vs-duplex correctly ⚑ (decision)

The `!! ` comments distinguish two lit patterns on a 2-fibre span:
- **Duplex, one link** (`FID-2022-0145`, `-0742`, `-0106`, `-0409`, `F22M`): one transceiver
  pair, one interface, one counter → one circuit, one termination per side. ✔ current model.
- **Two BiDi links** (`FID-2025-0740` #1/#2, `-0763` #1/#2, `-0741` scl04 Eth31/32,
  `-0762` scl04 Eth29/30, `FID-2023-0408` #1/#2):
  two BiDi transceivers, **two interfaces / two counters** on the two cores of one BIG circuit.
  NetBox has these as **one** circuit with **one** termination per side, but there are **two**
  switch ports per side. Decide the representation:
  - **(recommended)** one child/core circuit per BiDi link (e.g. `FID-2025-0740-1`, `-2`), each
    with its own termination cabled to its own switch port — matches "one counter per link" and
    lets the map draw two strands; or
  - keep one circuit and attach both switch ports to a LAG-style grouping (loses the per-core
    circuit identity).

  Until decided, these are the "2 ports, 1 termination" ambiguities the audit flags.

## Step 5 — SO → DF circuit-id convention

Boldyn customer `00000231`: `SO-<order>` = service order, `DF-<order>[-<core>]` = dark-fibre
circuit. Only `SO-00000231-0002` is shown *delivered* by device state (Step 2). The other
planned orders have **no up port** observed:

| order | sites | keep as-is |
|---|---|---|
| `SO-00000231-0000` | sjc02↔scl05 | ✔ leave `SO-` (planned; sjc02 switch not checked) |
| `SO-00000231-0001` | sfo01↔sfo02 | ✔ leave `SO-` (planned; not observed up) |
| `SO-00000231-0003` | oak01↔fmt01 | ⚑ leave `SO-` unless the passive chain (Step 2.3) is delivered |

Rename each to `DF-…` only when its ports come up. The atlas already matches both forms.

## Step 6 — Device-side fixes 🖧 (config, not NetBox — but part of "sync to reality")

- `switch01.scl02/Eth24/1` description says **SFO02** but `CID:FID-2022-0145` is scl02↔**scl03**.
  Fix the description's site token (the CID/NetBox are right).
- Backfill `!! CID:`/`description {token}` on the up transport ports that have **neither**:
  `switch02.sfo02/Eth21–24`, `switch01.sfo02/Eth52,54`, `switch02.fmt01/Eth3,5`,
  `switch03.fmt01/Eth16/1`, `switch04.sjc01/Eth24/1` (this one has the FBDK token but no CID).
  Until described, the map/audit can't tie them to a circuit. (Some may be intra-site or LAG
  member ports, not inter-site transport — confirm per port.)
- `switch01.scl04/Eth29–32` (FID-2025-0762, -0741): up and token-described but carry **no
  `!! CID`/`!! PP` comments** at all — add them so scl04 matches the other sites' annotation
  standard (and so PP-guided cabling is possible).
- Add missing `!! PP` comments where noted in Step 3 (fmt01/sjc01 ends, scl05/Eth52).

## Step 7 — Retirements

- `FID-2023-0408` (scl02↔scl04, ports shutdown, Deprovisioning): once cross-connects are pulled,
  delete the terminations + circuit (or leave Deprovisioning until physically removed).
- `FBDK/1721530/ZFS`: resolve the up-but-Decommissioned conflict from Step 1 first.

---

### Suggested execution order
1 (status truth) → 2 (turn up 0002) → 4 (decide BiDi model) → 3 (cable, honouring the Step-4
decision) → 6 (device descriptions/PPs) → 5 (SO→DF as ports come up) → 7 (retire). Re-run
`map_circuits.py --audit --configs-dir …` after each batch; success = every up transport port
resolves to its circuit termination (`resolved`), 0 `dead_end`/`uncabled` for delivered circuits.
