# SFMIX Network Map — cable atlas & build pipeline

An interactive, subway-style map of the SFMIX fabric at `/network-map/` on
sfmix.org. Datacenters are stations at their true coordinates; dark-fiber
circuits are stylized routes that *roughly* follow their real paths and are
coloured by semi-realtime traffic.

**See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design** (offline KMZ
pipeline vs the in-portal NetBox-sourced builder) and [`DEPLOY.md`](DEPLOY.md)
for the deploy runbook. This file is the day-to-day atlas + circuit guide.

## How the pieces fit

```
laptop (offline):  provider KMZ  --map_kmz_mine.py (Tier 1, NetBox-hinted)-->  atlas_precise/  (GITIGNORED)
                                 --map_coarsen.py  (Tier 2, DP + round)     -->  portal/mapbuild/data/atlas/<ID>.geojson  (committed)
                                                                                        | git commit + ansible deploy_portal
portal.sfmix.org:  mapbuild + Django-Q2 (qcluster)   daily schedule + on-demand
                     joins NetBox (devices, circuits, cabling, speeds) + committed geometry
                     -> map.json        (PUBLIC: opaque ids, no circuit/provider)  written to the db volume
                     -> map-links.json  (PRIVATE: opaque id -> ports/circuit)      written to the db volume
                   GET /statistics/map/map.json   (mapbuild view, CORS + cache)
                   GET /statistics/map/traffic     (Django, Prometheus per-id sums, cached ~45s)
browser (static sfmix.org page):  load structure once  ->  poll traffic  ->  recolour
```

The builder runs **inside the portal** (no metrics.sfo02, no sflow-rt, no eAPI,
no rsync — the portal has only a public IP and NetBox is world-reachable). sfmix.org
stays a static shell (page, vendored MapLibre, committed basemap, sprites,
renderer); all *data* comes from portal.sfmix.org.

## Privacy / NDA

- **KMZ files are shared under NDA. They never enter this repo and their exact
  path points must never be revealed.** They live only on laptops; the full-res
  mined geometry (`network-map/atlas_precise/`) is **gitignored**.
- `map_coarsen.py` is the privacy gate: it emits a **deliberately coarsened**
  approximation (Douglas–Peucker `~0.0008°` ≈ 89 m, rounded to 4 decimals ≈ 11 m)
  into the committed `portal/mapbuild/data/atlas/`. It reads as "roughly this
  corridor", not an engineering route — exact splice/vault points are gone.
- The public `map.json` carries an **opaque per-generation id** for each cable —
  no circuit id, provider, or port name. **Note:** the committed atlas files
  themselves *do* carry `circuit` metadata (provider name + circuit id + endpoints
  + status) and the coarse corridor geometry — so the repo source discloses more
  than the served map. The private `map-links.json` (opaque id → ports/circuit) is
  written only to the portal's db volume and never served or committed.

## Cable atlas format

One file per circuit: `portal/mapbuild/data/atlas/<CIRCUIT-ID>.geojson`, a GeoJSON
`FeatureCollection` with a foreign member `circuit` (build-time metadata) and one
Feature per segment. See `atlas/_TEMPLATE.geojson`.

- `circuit.match`: list of normalized tokens matched against **NetBox transport
  circuit CIDs** (the builder joins atlas geometry to the circuit a switch port
  traces to). Duplex/BiDi cores of one leased fibre share a stem, e.g.
  `FID-2025-0740-1/-2` → match `[FID-2025-0740, …]`.
- `medium` on each segment ∈ `underground | aerial | submarine | bridge | building`
  — drives line styling and whimsy placement (water crossings get wave treatment).
- `status` ∈ `active | planned | retired | …` (mirrors the NetBox circuit lifecycle).

## Intra-site links (switch ↔ switch)

Cables carry a `scope`: `inter` (site-to-site, leased circuits + atlas geometry) or
`intra` (switch-to-switch within one site). The builder derives intra links from
**NetBox intra-site inter-switch cabling** (`core_port`-tagged interfaces traced to
a far interface at the same site); parallel physical links between the same switch
pair collapse into one **LAG** (`members` = physical link count, rendered as
tightly-spaced parallel strands). Geometry is just the straight line between the two
switches' in-building positions, so intra links appear only at the device zoom tier.
Keep NetBox cabling honest with `scripts/netbox_backbone_lint.py` +
`scripts/map_intra_cabling.py` (see ARCHITECTURE.md §3).

### Link speed

Capacity (inter- *and* intra-site) comes from **NetBox `interface.speed`** — the
builder is fully NetBox-sourced and no longer reads the sflow `ifspeed` series at
build time. A transit router's physical member ports are often untagged (only the
LAG bundle carries `core_port`), so their speed is captured from the far end of the
NetBox cable trace. A port with no NetBox speed yields capacity 0, which the portal
treats as "unknown" and skips util colouring. (The live sflow/Prometheus series is
still used by the **traffic** endpoint for utilisation, not by the structure build.)

## Adding a circuit

1. Model the circuit in NetBox (transport/dark-fiber, provider, A/Z terminations)
   and cable the switch `core_port` interfaces to it. `netbox_backbone_lint.py`
   confirms the port traces end-to-end. Until an atlas file exists the link still
   appears, drawn as an *approximate* rights-of-way-routed / auto-arc line.
2. On a laptop, mine + coarsen the provider KMZ into the committed atlas:
   ```
   scripts/map_kmz_mine.py            # Tier 1: NetBox-hinted mine -> atlas_precise/ (gitignored)
   scripts/map_coarsen.py             # Tier 2: DP + round -> portal/mapbuild/data/atlas/<ID>.geojson
   ```
   For a single hand-traced KMZ, `scripts/map_trace_path.py <file.kmz> --list` then
   `--placemark … --circuit-id … --a-site … --z-site …` still works; pipe the output
   through the coarsener. For circuits with no KMZ (HE, DRT), the builder routes over
   committed rail/highway rights-of-way, or hand-draw a corridor into a copy of
   `_TEMPLATE.geojson`.
3. `git add` the atlas file + commit. Deploy with
   `ansible-playbook deploy_portal.playbook.yml --vault-password-file ~/.sfmix_ansible_vault`
   (rebuilds the image with the new committed atlas), then trigger a build from
   **/admin/map-build/ → Rebuild now** (or `docker compose exec portal python
   manage.py build_map --check` to see atlas↔topology drift first).

### KMZ vendor formats (why some circuits still auto-route)

Provider KMZs vary wildly, which is why not every circuit has traced geometry:
- **Per-circuit / FID-labeled** (Zayo `Service …`, BIG "Existing and New SV
  Routes", "6 Node Bay Ring", "QTS↔OpenColo") — one named LineString (sometimes
  split into segments). Mined directly.
- **No usable KMZ** — Hurricane Electric and Digital Realty waves: none provided →
  the builder routes over committed rail/highway rights-of-way (`routing.infra_route`)
  or a hand-drawn corridor.
- **Boldyn BART-corridor network** (`Customer Facing Boldyn Fiber Network …`) —
  Boldyn's fiber rides BART/public rights-of-way, so the KMZ is a *layered network*,
  not per-circuit paths. `scripts/map_boldyn_route.py` builds a graph from every
  segment vertex (snapped + stitched), prefers built fiber over in-progress, and
  Dijkstra-routes between two datacenters anchored on the NetBox site coords.
- **Other master maps** (`BIG External-Sales`, `Boldyn Fiber Route - APs`) —
  hundreds of unnamed segments; same routing approach, lower priority.

## Retiring a circuit

Set `"status": "retired"` in the atlas file (or delete it). `build_map --check`
reports active-but-gone and retired-but-live. A configured-but-down link stays on
the map as *offline* until it's removed from NetBox.

## Local development

No network, no Hugo, no portal required:

```
python3 network-map/dev/make_fixture.py     # (re)build the synthetic fixture
python3 network-map/dev/serve.py            # http://localhost:8765/network-map/
```

The harness serves the synthetic `fixtures/map.json` and fabricates jittered live
traffic so link re-colouring animates. To build the *real* map from NetBox locally
(needs `pip install pynetbox requests` + NetBox creds):
`PYTHONPATH=portal python3 -c "from mapbuild import builder; …"` — or use
`network-map/dev/deploy_demo.sh` to publish it to the password-gated demo, which
points the frontend at the live portal endpoints.

To preview inside the real Hugo site: `hugo server -s website` and browse
`/network-map/` (the page's `data-*-url` attributes point at portal.sfmix.org).

For non-interactive visual checks (e.g. after touching sprites, decorations, or
renderer code), `dev/screenshot.mjs` captures the harness headlessly — it waits
on the map's own loaded state (the dev shell exposes `window.__map`), so no
flaky fixed timeouts:

```
python3 network-map/dev/serve.py &
node network-map/dev/screenshot.mjs http://localhost:8765/network-map/ /tmp/map.png
```

## Deployment

- **Builder + serving** live in the portal (`portal/mapbuild/` + Django-Q2). A
  `qcluster` worker runs `build_map_task` on a daily schedule and on-demand from the
  admin page, writing `map.json` + `map-links.json` to the shared `db` volume; the
  `mapbuild` view serves `map.json` at `/statistics/map/map.json` (CORS-open) and the
  Django `ix_map_traffic` view serves the live traffic feed. Deploy with
  `ansible-playbook deploy_portal.playbook.yml --vault-password-file ~/.sfmix_ansible_vault`
  (rebuilds the image, runs migrations, brings up `portal` + `qcluster`).
- **Website** (`website/`) is the static shell — MapLibre, basemap, sprites,
  `network-map.js` — deployed by the GitHub Pages workflow on `main`. Its
  `data-structure-url` points at `<portal>/statistics/map/map.json`. No build-time
  data step.

## Directory map

```
network-map/
  README.md                  this file
  ARCHITECTURE.md            offline pipeline ↔ in-portal builder boundary
  DEPLOY.md                  deploy runbook
  atlas_precise/             GITIGNORED  full-res mined geometry (NDA)
  basemap/                   fetch_basemap.py / fetch_dem.py / gen_sutro_tower.py / fetch_rights_of_way.py + README
  sprites-src/               vector sprite art (shipped as SVG, rasterized in-browser)
  fixtures/map.json          synthetic structure for dev (generated)
  dev/make_fixture.py        regenerates fixtures/map.json
  dev/serve.py               offline dev harness
  dev/screenshot.mjs         headless-Chrome map screenshot (visual verification)
  dev/deploy_demo.sh         publish frontend → demo.sfmix.org (points at live portal)
portal/mapbuild/data/
  atlas/<ID>.geojson         committed coarsened circuit shapes (+ _TEMPLATE)
  sites.json                 display names/operators/metros per site code (public)
  basemap-*.json             water rings + road corridors (build inputs, image-baked)
  rights-of-way.json         rail/pipeline corridors for KMZ-less routing
```

Related code: `portal/mapbuild/` (builder/geometry/routing/circuits/tasks/views),
`scripts/map_kmz*.py` + `scripts/map_coarsen.py` (offline KMZ pipeline),
`scripts/netbox_backbone_lint.py` + `scripts/map_intra_cabling.py` (NetBox lint/reconcile),
`website/layouts/_default/network-map.html`, `website/static/js/network-map.js`,
`portal/dashboard/` (traffic view), `ansible/roles/ixp_portal`.
