# Network map — architecture

The interactive subway-style map at `/network-map/` is built from two clearly
separated halves:

1. **A laptop/repo data pipeline** that turns private carrier KMZs and OSM data
   into *coarse, committed geometry artifacts*. This runs by hand on an
   operator's machine, never in production, and never touches the portal.
2. **A NetBox-sourced builder** that lives *inside the portal* and, on a
   schedule, joins those committed artifacts with live NetBox state to emit the
   public `map.json` (and the private `map-links.json`). This is the only part
   that runs in production.

The dividing line is deliberate: the sensitive/heavy geometry work (raw carrier
route KMZs, Overpass fetches, Douglas–Peucker coarsening) is done offline and
its *output* — small, reviewed GeoJSON — is committed. The portal only ever
consumes committed geometry + NetBox; it needs nothing but a public network.

```
  ┌─────────────────────── laptop / repo (offline, by hand) ──────────────────────┐
  │                                                                                │
  │  private KMZs ─┐                                                               │
  │  (gitignored)  │  scripts/map_kmz.py         (KMZ parse lib)                   │
  │                ├─▶ scripts/map_kmz_mine.py   Tier 1: mine precise geometry     │
  │  NetBox  ──────┘      │                      using NetBox circuit hints        │
  │  (circuit hints)      ▼                                                        │
  │                 network-map/atlas_precise/*.geojson   (GITIGNORED, precise)    │
  │                       │                                                        │
  │                       │  scripts/map_coarsen.py   Tier 2: DP-simplify + round  │
  │                       ▼                                                        │
  │  OSM/Overpass ─▶ portal/mapbuild/data/atlas/*.geojson  (COMMITTED, coarse)     │
  │   (rail/pipeline        portal/mapbuild/data/rights-of-way.json  (COMMITTED)   │
  │    rights-of-way)       via network-map/basemap/fetch_rights_of_way.py         │
  │                                                                                │
  └────────────────────────────────────┬───────────────────────────────────────-─┘
                                        │  git commit  (small, reviewable GeoJSON)
                                        ▼
  ┌──────────────────────────── portal.sfmix.org (production) ────────────────────┐
  │                                                                                │
  │  portal/mapbuild/  (self-contained Django app, separate from `dashboard`)      │
  │     data/            committed geometry artifacts (baked into the image)       │
  │     geometry.py      render-geometry engine (was scripts/map_geometry.py)      │
  │     builder.py       joins committed geometry + NetBox → map.json              │
  │     tasks.py         Django-Q2 task: build_map()  (scheduled + on-demand)      │
  │     views.py         admin-gated build-status viewer                           │
  │                                                                                │
  │  NetBox (public) ─────▶ builder.py ─────▶ map.json        (PUBLIC, served)     │
  │  Prometheus (optional)             └────▶ map-links.json  (PRIVATE, traffic)   │
  │                                                                                │
  └────────────────────────────────────────────────────────────────────────────-─┘
                                        │
                                        ▼
              frontend  website/static/js/network-map.js  (consumes map.json)
```

## The two halves

### 1. Offline geometry pipeline (repo, laptop only)

Lives in `scripts/` and `network-map/basemap/`. **Never runs in the portal.**
It exists because real cable routes come from carrier KMZs that are private and
too detailed to ship, and because rail/pipeline rights-of-way come from bulk OSM
extracts. Both are distilled into small committed artifacts.

| Step | Script | Input | Output |
|------|--------|-------|--------|
| KMZ parse lib | `scripts/map_kmz.py` | — | (library) |
| Tier 1 — mine | `scripts/map_kmz_mine.py` | private KMZs + NetBox circuit hints | `network-map/atlas_precise/*.geojson` **(gitignored)** |
| Tier 2 — coarsen | `scripts/map_coarsen.py` | `atlas_precise/` | `portal/mapbuild/data/atlas/*.geojson` **(committed)** |
| Rights-of-way | `network-map/basemap/fetch_rights_of_way.py` | OSM Overpass | `portal/mapbuild/data/rights-of-way.json` **(committed)** |
| Basemap | `network-map/basemap/fetch_basemap.py` | OSM Overpass | `website/static/map/basemap-*.json` **(committed)** + mirrors water/roads → `portal/mapbuild/data/` |

Route-tracing helpers used only during mining (`scripts/map_trace_path.py`,
`scripts/map_boldyn_route.py`) stay here too. So do the NetBox reconcilers/lint
that keep NetBox honest so the builder can trust it (see §3).

Why `atlas_precise/` is gitignored but `atlas/` is committed: the precise mine
retains full carrier detail (sensitive, large); the coarsened atlas is a handful
of rounded vertices safe to publish and small enough to review in a diff.

### 2. The portal builder (production)

Lives in `portal/mapbuild/`, a **self-contained Django app kept separate from
the portal's own models/views** (`dashboard`) — the map shares the portal's
application server and nothing else. It consumes only:

- **Committed geometry** in `portal/mapbuild/data/` (atlas, sites overrides,
  basemap water rings + roads, rights-of-way) — baked into the Docker image.
- **NetBox** (`netbox.sfmix.org`, world-reachable) — the source of truth for
  sites, devices, transport circuits, and cabling.
- **Prometheus** (optional) — for authoritative per-port link speeds; falls
  back to NetBox `interface.speed` when unreachable.

It emits two files (atomic write):

- `map.json` — **PUBLIC.** Opaque per-generation cable ids, render-ready
  `path`/`media`/`drops`, sites, metros, pre-aggregated `metro_cables`. No
  circuit ids or provider names.
- `map-links.json` — **PRIVATE.** Maps each opaque cable id → member
  `{host, ifname}` ports + circuit id/provider. The portal reads this to key
  the per-link traffic overlay; it is never served to the browser.

## Why the builder is NetBox-only

The portal has a **public IP only — no internal/OOB network access.** The
builder therefore must not depend on anything internal:

| Input | Old source (internal) | New source (portal-viable) |
|-------|-----------------------|----------------------------|
| Which links exist | sflow-rt `/topology/json` (LLDP) | NetBox cable traces between `peering_switch`/transit-router interfaces |
| Devices per site | sflow nodes + Arista eAPI | NetBox `peering_switch` (+ transit-router) devices |
| Intra-site LAGs | sflow topology | NetBox intra-site inter-switch cabling |
| Link speed / capacity | sflow `ifspeed` series | NetBox `interface.speed` (Prometheus preferred if reachable) |
| Cable geometry | committed atlas | committed atlas (unchanged) |

NetBox becoming authoritative for **cabling** (not just circuits) is what makes
this possible. The reconcilers in §3 keep NetBox's cabling matching ground truth
so the builder can trust NetBox instead of live LLDP.

## 3. Keeping NetBox trustworthy (repo, laptop/CI ops tools)

Because the builder trusts NetBox, NetBox must match the wire. Two tools, run by
operators (and lintable in CI), enforce that:

- **`scripts/netbox_backbone_lint.py`** — cross-checks live LLDP against NetBox.
  Every inter-site `peering_switch`↔`peering_switch` link must trace end-to-end
  in NetBox; every intra-site inter-switch link must be cabled. Exits non-zero on
  any gap (CI/pre-deploy gate).
- **`scripts/map_intra_cabling.py`** — reconciles intra-site inter-switch cabling
  from LLDP ground truth: CREATE missing direct cables, REPLACE stale cables
  (LLDP wins; `--plan` prompts, `--apply --yes` writes), SKIP interfaces not yet
  in NetBox. Re-run to import cabling as it moves over time.
- **`scripts/map_circuits.py`** — the inter-site circuit twin (leased circuits +
  passive-site cross-connect cabling).

The rule: the offline pipeline provides *geometry*, NetBox provides *topology*,
and the lint keeps the two in agreement. If the lint is clean, the portal build
reflects reality.

## 4. Running the build (Django-Q2)

The build runs in the portal as a background job via **Django-Q2** (DB-backed
ORM broker — no Redis; shares the portal's SQLite volume):

- A **scheduled** daily `build_map()` task.
- **On-demand** rebuild (`async_task`) triggered from the admin status page.
- A **`qcluster`** service in `docker-compose.yml` (same image, runs the worker).
- An **admin-gated status view** over Q2's `Success`/`Failure`/`Schedule`/`OrmQ`
  tables: run history, last success, failure tracebacks, queue depth.

For local iteration the same builder runs standalone:
`python portal/manage.py build_map --out … --links-out …` (see
`network-map/dev/deploy_demo.sh`, which publishes the password-protected preview
at demo.sfmix.org).

## 5. Frontend

`website/static/js/network-map.js` consumes `map.json` v2 directly —
`cable.path` / `cable.media` (submarine spans) / `cable.drops`, plus top-level
`metros` and `metro_cables` for the zoomed-out inter-metro tier. It fetches the
per-link traffic feed (keyed by opaque cable id) for utilisation colouring. The
basemap (`website/static/map/basemap-*.json`) and sprites are served by the
website; only `map.json` + the traffic feed come from the portal.

## File map (quick reference)

```
scripts/
  map_kmz.py, map_kmz_mine.py, map_coarsen.py      offline KMZ pipeline (laptop)
  map_trace_path.py, map_boldyn_route.py           mining route helpers (laptop)
  map_circuits.py, map_intra_cabling.py            NetBox reconcilers (laptop/CI)
  netbox_backbone_lint.py                          NetBox↔LLDP lint (laptop/CI)
network-map/
  atlas_precise/          GITIGNORED  precise mined geometry
  basemap/                fetch_basemap.py, fetch_rights_of_way.py (laptop)
  dev/                    deploy_demo.sh + local preview helpers
  fixtures/               offline build fixtures (no network)
  ARCHITECTURE.md         this file
  DEPLOY.md               production deploy runbook
portal/mapbuild/          self-contained builder app (production)
  data/atlas/*.geojson    COMMITTED  coarse cable geometry (image-baked)
  data/rights-of-way.json COMMITTED  rail/pipeline routing corridors
  data/sites.json         COMMITTED  site name/operator/metro overrides
  data/basemap-*.json     COMMITTED  water rings + road corridors (build inputs)
  geometry.py             render-geometry engine (was scripts/map_geometry.py)
  routing.py              infra-following Dijkstra over rights-of-way
  circuits.py             NetBox circuit geometry-hints (own copy; see miner)
  builder.py              NetBox + geometry → map.json / map-links.json
  tasks.py, views.py      Django-Q2 task + admin status + public map.json
  management/commands/build_map.py   standalone/manual build runner
website/static/
  js/network-map.js       frontend (consumes map.json v2)
  map/basemap-*.json       COMMITTED  basemap water/roads (served + build input)
```
