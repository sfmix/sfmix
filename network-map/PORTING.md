# Porting the network map to another IXP

This map was built for SFMIX, but most of it is not inherently SFMIX-specific. This
doc separates the **reusable engine** from the **per-IXP configuration and data**,
inventories what is still hardcoded, and lays out a concrete path to make it
reasonably generic. It reflects the state after the builder moved into the portal
(`portal/mapbuild/`) and became **fully NetBox-sourced** (no sflow-rt / eAPI /
interface-description parsing) — which already collapsed most of the old
"collector profile" work.

## The three layers

1. **Engine — generic, reuse as-is.** No knowledge of any particular IXP; operates
   on coordinates, site records, and metric values passed in.
   - `portal/mapbuild/geometry.py` — all render-geometry construction (smoothing,
     orient, de-loop, box-edge clip, water spans, lane assignment, metro
     aggregation). Pure functions over lon/lat + boxes + water rings.
   - `portal/mapbuild/routing.py` — infra-following Dijkstra over committed
     rights-of-way, for links with no mined geometry. Generic given a corridor set.
   - `website/static/js/network-map.js` — the renderer. It only styles pre-built
     geometry (colour by util, widths, zoom tiers, popovers, selection, LAG-strand
     px offset). Nothing here is SFMIX-specific except the basemap asset URLs and a
     few Bay-Area view constants (below).
   - The **contracts**: `map.json` v2 (public, opaque ids, render-ready geometry),
     `map-links.json` (private, member ports + circuit metadata), the atlas GeoJSON
     format (`atlas/_TEMPLATE.geojson`), and the portal traffic-feed pattern
     (opaque-id → summed member-port bps, cached, CORS). These are all IXP-neutral.

2. **Profile — per-IXP config.** How this IXP's network describes itself in NetBox.
   Much smaller now that the builder is NetBox-native (see "Collector" below).

3. **Data — per-IXP inputs.** Sites (NetBox + `sites.json`), the coarsened cable
   atlas (`portal/mapbuild/data/atlas/*.geojson`), the basemap
   (`portal/mapbuild/data/basemap-*.json` + `website/static/map/*`), and whimsy
   (`decorations.json`). Mostly data-driven; the geography is naturally specific to
   wherever the IXP is.

## What's already reusable / data-driven

- Site lat/lon/name/address from NetBox (`load_sites`), overridable in
  `portal/mapbuild/data/sites.json`.
- Cable geometry + circuit metadata as committed data in `atlas/*.geojson`.
- **Topology, devices, cabling, and capacity all come from NetBox** — the builder
  needs only NetBox (world-reachable) + committed geometry, no internal network.
- Endpoint URLs are env-overridable: `NETBOX_API_ENDPOINT`/`NETBOX_API_TOKEN`,
  `PROMETHEUS_URL` (traffic feed only); Django `MAP_*` / `SFMIX_MAP_*` settings;
  most ansible values in `roles/ixp_portal/defaults`.
- The decorations/whimsy layer is optional and URL-fed (renders only if present).
- The render engine and the JSON contracts (above).

## What's SFMIX-specific and needs work (from the code inventory)

Grouped by concern; **[HARD]** = hardcoded in source, **[DATA]** = already config.

### A. Site identity & code shape  *(highest-value refactor)*
- **[HARD]** A site table is still duplicated in the offline/dev tools:
  `map_trace_path.SITE_COORDS`, `make_fixture.SITES` (plus
  `map_boldyn_route.SITE_DC_NAME`). The builder itself reads NetBox, but these
  laptop tools should share **one** source (extend `sites.json` / NetBox).
- **[HARD]** Site-code shape is baked in: device names are parsed for the site as
  the "second dotted label" (`site_of` in `portal/mapbuild/builder.py`, and in
  `portal/dashboard/`). A different IXP's naming (or non-FQDN device ids) won't match.

### B. Collector profile (NetBox conventions)
Largely **done** by the move to NetBox-sourcing — the old interface-description
grammar (`Core: Transport … via … {ID} [Speed]`), the five regexes, the sflow-rt
`/topology/json` shape, the Arista `pyeapi` collection, and the `ifspeed` series
dependency are all **retired**. What remains is a few NetBox conventions:
- **[HARD]** NetBox device role `peering_switch` (includes transit routers) and the
  `core_port` interface **tag** that scopes transport ports; circuit types
  `dark-fiber`/`transport`; the `map_exclude` tag; netrc realm `sfmix.org` (only for
  the offline lint/reconcile eAPI, not the builder).
- **[DATA]** Speed comes from NetBox `interface.speed`; capacity vocab is just bps.
A new IXP mostly needs the same NetBox roles/tags (or a small mapping) — no
collector code.

### C. Provider / KMZ tooling  *(inherently per-provider)*
- **[HARD]** `map_boldyn_route.py` (Boldyn/BART folder model, `SITE_DC_NAME`),
  provider-specific mining in `map_kmz_mine.py`, and circuit-id formats (`FID-*`,
  `FBDK-*`, `DF-*`, `SO-*`). Unavoidably specific to *which carriers* an IXP buys
  from, but the **atlas output format is generic** and the `map_kmz`/`map_coarsen`
  primitives (KML parse, chain, Douglas-Peucker coarsen, round) are reusable. A new
  IXP mines its own providers' KMZs into the same atlas format.

### D. Basemap & view  *(geography — regenerate per region)*
- **[HARD]** `fetch_basemap.py BBOX` (Bay Area) and the committed basemap
  (water/land/roads/airports + rights-of-way). Regenerate for the new metro.
- **[HARD]** Map `center`/`zoom`/`maxBounds` and tier thresholds
  (`METRO_ZOOM`/`EXPAND_ZOOM`/…) and attribution string in `network-map.js`; the
  whimsy content + coords in `decorations.json`. Should come from a small site
  config block (Hugo params or a `map-config.json`).

### E. Deployment / infra  *(in-portal, mostly parameterized)*
- **[HARD]** Hostnames (`portal.sfmix.org`, `netbox.sfmix.org`, …), the `sfmix`
  user, ansible role names, the shared opaque-id UUID namespace, and the
  sfmix.org-hosted switch icon. Most are ansible `defaults`/env already; the rest
  are find-replace. The build runs in the portal (Django-Q2 `qcluster`) and writes
  to the shared db volume — no separate build host, no rsync.

### F. Scale/heuristic constants  *(tune, don't rewrite)*
- Building-box size, device-grid layout, the capacity→width ladder and util colour
  ramp, and the geometry heuristics (`LOOP_MAX_M`, `APPROACH_M`, coarsening
  tolerances). Sensible defaults; a much larger or denser fabric would tune them.

## Recommended path to "reasonably generic"

Ordered by leverage. None of this blocks SFMIX; each step also de-duplicates SFMIX's
own code.

1. **Unify site identity.** One site table (NetBox + `sites.json`) consumed by the
   builder, both KMZ tools, and the fixture. Add `site_code_regex` +
   `fqdn_site_index` to config; delete the duplicate tables in the laptop tools.
2. **Generalise the NetBox conventions.** Move the role/tag/circuit-type names
   (`peering_switch`, `core_port`, `dark-fiber`/`transport`, `map_exclude`) into a
   small config block so another IXP maps its own NetBox conventions without code
   edits. (The heavy lifting — dropping the description grammar / sflow / eAPI — is
   already done.)
3. **Site/view config block.** A `map-config.json` (or Hugo params) for center,
   bounds, zoom tiers, attribution, basemap asset base, decorations URL.
4. **Package the engine.** `geometry.py`/`routing.py` + the JSON contracts + the
   atlas format + the portal traffic view are already generic; document them as the
   stable API (this doc + `atlas/_TEMPLATE.geojson` + a short `map.json` schema note).
5. **Per-IXP KMZ mining.** Keep `map_kmz`/`map_coarsen`/`map_boldyn_route`
   primitives; each IXP mines its carriers' KMZs into the atlas format.
6. **Deploy vars.** Fold remaining hostnames/user/namespace into ansible group_vars
   so a new deployment is a vars file.

### To stand up the map for a new IXP (target end-state)
1. Point at the IXP's NetBox (API + token); tag transport ports `core_port`, set the
   device role, and write `sites.json` overrides.
2. Fill a small conventions block (code shape, NetBox role/tag/circuit-type names).
3. Regenerate the basemap for the metro (`fetch_basemap.py` with a new BBOX) and set
   the view config; optionally add local whimsy.
4. Mine the IXP's fibre providers' KMZs into `portal/mapbuild/data/atlas/` (or ship
   none and let every link route over rights-of-way / auto-arc initially).
5. Deploy the portal with an IXP vars file (hosts/namespace).

Everything else — the geometry engine, the renderer, the traffic feed, the opaque-id
privacy model, the atlas format, the NetBox-sourced builder — is shared.
