# SFMIX Network Map — cable atlas & build pipeline

An interactive, subway-style map of the SFMIX fabric at `/network-map/` on
sfmix.org. Datacenters are stations at their true coordinates; dark-fiber
circuits are stylized routes that *roughly* follow their real paths and are
coloured by semi-realtime traffic.

## How the pieces fit

```
laptop:  provider KMZ  --scripts/map_trace_path.py (coarsen)-->  network-map/atlas/<ID>.geojson  (committed)
                                                                       | ansible deploy (atlas + builder)
metrics.sfo02:  gen_map_structure.py  (daily cron + on-demand poke)
                  joins live eAPI port descriptions/status + sflow-rt topology + atlas + NetBox sites
                  -> map.json        (PUBLIC: opaque ids, no circuit/provider) --rsync--> portal /var/www/sfmix-map/
                  -> map-links.json  (PRIVATE: opaque id -> ports/circuit)     --rsync--> portal /var/lib/sfmix-map/
portal.sfmix.org:  GET /map/map.json               (nginx static, CORS + cache)
                   GET /statistics/map/traffic      (Django, Prometheus per-id sums, cached 30-60s)
browser (static sfmix.org page):  load structure once  ->  poll traffic every 60s  ->  recolour
```

sfmix.org stays a static shell (page, vendored MapLibre, committed basemap,
sprites, renderer). All *data* comes from portal.sfmix.org.

## Privacy / NDA

- **KMZ files are shared under NDA. They never enter this repo and their exact
  path points must never be revealed.** They live only on laptops.
- `scripts/map_trace_path.py` reads a local KMZ and emits a **deliberately
  coarsened** approximation (Douglas–Peucker ~300 m, rounded to 3–4 decimals).
  Only that abstraction is committed to `atlas/`. It reads as "roughly this
  corridor", not an engineering route.
- The public `map.json` carries an **opaque per-generation id** for each cable —
  no circuit id, provider, or port name. Circuit metadata lives only in the repo
  atlas (backend) and the private `map-links.json` (portal-only).
- A local, gitignored `network-map/.kmz-cache/` is allowed for convenience.

## Cable atlas format

One file per circuit: `atlas/<CIRCUIT-ID>.geojson`, a GeoJSON `FeatureCollection`
with a foreign member `circuit` (backend-only metadata) and one Feature per
segment. See `atlas/_TEMPLATE.geojson`.

- `circuit.match`: list of normalized tokens matched against the `{...}` / `(...)`
  in live interface descriptions (`Core: Transport <SITE> via <Provider> {<ID>} [<Speed>]`).
- `medium` on each segment ∈ `underground | aerial | submarine | bridge | building`
  — drives line styling and whimsy placement (water crossings get wave treatment).
- `status` ∈ `active | retired` (planned circuits may use `active` before turn-up).

## Intra-site links (switch ↔ switch)

Cables carry a `scope`: `inter` (site-to-site, from `Core: Transport` ports +
atlas geometry, above) or `intra` (switch-to-switch within one site). The builder
derives intra links from the sflow-rt LLDP topology: any confirmed link whose two
ends live at the same site becomes an intra cable, and parallel physical links
between the same switch pair collapse into one **LAG** (`members` = physical link
count, rendered as tightly-spaced parallel strands). Geometry is just the straight
line between the two switches' in-building positions, so intra links appear only at
the device zoom tier (inside the building box). No atlas or KMZ is involved.

### Link speed

Capacity (inter- *and* intra-site) comes from the **`ifspeed` label** sflow-rt
exports on every `sflow_ifoutoctets` Prometheus series — the ground-truth speed the
device negotiates, and the same source the Grafana weathermap trusts
(`scripts/gen_weathermap.py`). The human-typed `[<Speed>]` description token is only
a fallback for a port that has no series yet; a stale token never wins over the live
label. (NetBox is the other candidate source-of-truth, but it is itself fed from
device ground-truth, so the sflow label and NetBox agree — we prefer the live label.)
A port with neither yields capacity 0, which the portal treats as "unknown" and
skips util colouring. `--facts-fixture` stands in for the live series in tests
(`network-map/fixtures/ifspeed.json`).

## Adding a circuit

1. Provision the ports with the description grammar
   `Core: Transport <SITE> via <Provider> {<CIRCUIT-ID>} [<Speed>]`. The `{...}`
   token is load-bearing — it's how the builder matches the port to geometry.
   Until an atlas file exists the link still appears, drawn as a dashed
   *approximate* auto-arc (and greyed if it's provisioned but down).
2. On a laptop, convert the provider KMZ:
   `scripts/map_trace_path.py <file.kmz> --list`   # see placemark names
   `scripts/map_trace_path.py <file.kmz> --placemark "<name>" \
       --circuit-id <ID> --provider "<Provider>" --a-site <a> --z-site <z> \
       > network-map/atlas/<ID>.geojson`
   Then split/tag `medium` per segment by hand (water crossings are obvious).
   For circuits with no KMZ (HE, DRT), hand-draw in geojson.io: load the basemap
   + neighbouring atlas files as reference, draw a plausible corridor between the
   two sites, paste into a copy of `_TEMPLATE.geojson`, set `geometry` to
   `hand-drawn`.
3. `git add` the atlas file, ansible-push atlas + builder to metrics.sfo02, then
   **poke the builder** (re-run its cron command) and run
   `scripts/gen_map_structure.py --check` until clean.

**Batch import:** `KMZ_DIR=~/Downloads/sfmix ./network-map/import_atlas.sh`
regenerates all currently-mapped circuits from their KMZs in one pass (a manifest
of circuit → KMZ file + placemark + sites + match-tokens). Edit it to add circuits.

### KMZ vendor formats (why some circuits still auto-arc)

Provider KMZs vary wildly, which is why not every circuit has traced geometry:
- **Per-circuit / FID-labeled** (Zayo `Service …`, BIG "Existing and New SV
  Routes", "6 Node Bay Ring", "QTS↔OpenColo") — one named LineString (sometimes
  split into segments; `--merge` chains them). These are extracted (9 circuits).
- **No usable KMZ** — Hurricane Electric (`HE #4757047`, `HE#4490766`) and
  Digital Realty (`DRT #285322`) circuits: none provided. The HE 10G backup rides
  Zayo, but our two Zayo KMZs are single-service (`FBDK-1721530` sjc01↔fmt01,
  `F22M-0204477` within-SF) — neither covers the fmt01↔sfo02 corridor the backup
  needs. So it **borrows the site-pair's known corridor** (the BIG primary
  `FID-2023-0409`, same fmt01↔sfo02 buildings) drawn *dotted/approximate* parallel
  to the primary, instead of a bezier floating across open water. For HE's true
  (diverse) path, pull the Zayo service KMZ for `#4757047`/`#4490766` by service
  number. Some BIG circuits (FID-2023-0408, -0742, -0763, FID-2022-0145) similarly
  ride a neighbouring path via the site-pair fallback.

  **Match precedence** (`match_atlas`): circuit-token match → the circuit's own
  surveyed route (solid); site-pair-only match → borrowed corridor (dotted,
  `approximate`); no match → dashed auto-arc. `--check` lists BORROWED corridors
  separately (informational, not drift).
- **Boldyn BART-corridor network** (`Customer Facing Boldyn Fiber Network …`) —
  Boldyn's fiber rides BART/public rights-of-way, so the KMZ is a *layered
  network*, not per-circuit paths. Its folder tree is:
  - `CONSTRUCTION COMPLETE` → `Underground` / `Aerial` / `Elevated Bart` — the
    **built, in-service fiber** (the real basemap), tagged by medium;
  - `IN PROGRESS` → `BART ROW` / `PUBLIC ROW` → **named circuit-specific callouts**
    ("365 Main Diverse Entrance", "Conduit From Balboa To 200 Paul", "DRT Santa
    Clara Data Center Ring", …) — proposed/under-construction routes;
  - `DATA CENTERS` → Point placemarks (365 Main, 55 South Market, 2805 Lafayette,
    48233 Warm Springs, …).
  `scripts/map_boldyn_route.py` handles this: it builds a graph from every segment
  vertex (snapped + stitched so laterals joining a line mid-span connect),
  **prefers built fiber over in-progress** (routing penalty), Dijkstra-routes
  between two datacenters, and tags the traced segments by their real medium
  (Underground/Aerial). E.g. `--a-site fmt01 --z-site sjc02` traces the built
  DF-231-4 corridor. `--list` shows the datacenter Points.
- **Other master maps** (`BIG External-Sales`, `Boldyn Fiber Route - APs`) —
  hundreds of unnamed/BART-line segments; the same routing approach applies but
  they're lower-priority (the customer-facing Boldyn KMZ is cleaner).

The builder falls back to a site-pair match, then a dashed auto-arc, so a circuit
without atlas geometry still appears — it just doesn't trace its real corridor.

## Retiring a circuit

Set `"status": "retired"` in the atlas file (or delete it). `--check` reports
active-but-gone and retired-but-live. A configured-but-down link stays on the map
as *offline* until its interface description is removed.

## Local development

No network, no Hugo, no portal required:

```
python3 network-map/dev/make_fixture.py     # (re)build the synthetic fixture
python3 network-map/dev/serve.py            # http://localhost:8765/network-map/
```

The harness serves the synthetic `fixtures/map.json` and fabricates jittered
live traffic so link re-colouring animates. See `dev/serve.py`.

To preview inside the real Hugo site: `hugo server -s website` and browse
`/network-map/` (the page's `data-*-url` attributes point at portal.sfmix.org;
override them locally if you want live-ish data).

## Deployment

- **Builder** (`scripts/gen_map_structure.py`) is deployed to metrics.sfo02 by
  `ansible/roles/sflow_rt` (tag `map_structure`): it copies the script, syncs the
  atlas + `sites.json` to `~sfmix/network-map/`, and installs a daily cron that
  builds `map.json` + `map-links.json` and rsyncs both to the portal host
  (rrsync-restricted to `/var/lib/sfmix-map`).
- **Portal** (`ansible/roles/ixp_portal`) creates `/var/lib/sfmix-map`, authorizes
  the builder's key, bind-mounts the dir read-only into the container
  (`SFMIX_MAP_LINKS_PATH=/data/map/map-links.json`), and serves only
  `map.json` via nginx (`location = /map/map.json`, CORS-open). The live traffic
  feed is the Django view `/statistics/map/traffic`.
- **One-time operator step**: generate an SSH keypair for the push, vault the
  private key as `map_builder_rsync_privkey` (sflow_rt) and set the public key as
  `map_builder_rsync_pubkey` (ixp_portal). Run ansible with
  `--vault-password-file ~/.sfmix_ansible_vault`. Poke a rebuild any time with
  `ansible-playbook push_servers.playbook.yml --tags map_structure` (then the
  cron command, or run the builder directly on the host).
- **Website** (`website/`) is the static shell — MapLibre, basemap, sprites,
  `network-map.js` — deployed by the existing GitHub Pages workflow. No build-time
  data step; all data is fetched live from the portal.

## Directory map

```
network-map/
  README.md                  this file
  atlas/<ID>.geojson         committed coarsened circuit shapes (+ _TEMPLATE)
  sites.json                 display names/operators per site code (public)
  decorations.geojson        whimsy layer (sea monster, sea lions, fog, scrolls)
  basemap/README.md          how the committed OSM basemap was extracted
  fixtures/map.json          synthetic structure for dev (generated)
  dev/make_fixture.py        regenerates fixtures/map.json
  dev/serve.py               offline dev harness
```

Related code: `scripts/map_trace_path.py`, `scripts/gen_map_structure.py`,
`website/layouts/_default/network-map.html`, `website/static/js/network-map.js`,
`portal/dashboard/` (traffic view), `ansible/roles/sflow_rt` + `ansible/roles/ixp_portal`.
