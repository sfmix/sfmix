# Porting the network map to another IXP

This map was built for SFMIX, but most of it is not inherently SFMIX-specific. This
doc separates the **reusable engine** from the **per-IXP configuration and data**,
inventories what is still hardcoded, and lays out a concrete path to make it
reasonably generic. It reflects the state after geometry prep was moved to the
backend (`scripts/map_geometry.py`).

## The three layers

1. **Engine — generic, reuse as-is.** No knowledge of any particular IXP; operates
   on coordinates, site records, and metric values passed in.
   - `scripts/map_geometry.py` — all render-geometry construction (smoothing,
     orient, de-loop, box-edge clip, water spans, lane assignment, metro
     aggregation). Pure functions over lon/lat + boxes + water rings.
   - `website/static/js/network-map.js` — the renderer. It only styles pre-built
     geometry (colour by util, widths, zoom tiers, popovers, selection, LAG-strand
     px offset). Nothing here is SFMIX-specific except the basemap asset URLs and a
     few Bay-Area view constants (below).
   - The **contracts**: `map.json` v2 (public, opaque ids, render-ready geometry),
     `map-links.json` (private, member ports + circuit metadata), the atlas GeoJSON
     format (`atlas/_TEMPLATE.geojson`), and the portal traffic-feed pattern
     (opaque-id → summed member-port bps, cached, CORS). These are all IXP-neutral.

2. **Profile — per-IXP config (small, should be declarative).** How this IXP's
   network describes itself. Today this is **scattered and hardcoded**; the porting
   work is mostly about pulling it into config. See "Collector profile" below.

3. **Data — per-IXP inputs.** Sites (NetBox + `sites.json`), the coarsened cable
   atlas (`atlas/*.geojson`), the basemap (`website/static/map/*`), and whimsy
   (`decorations.geojson`). Mostly already data-driven; the geography is naturally
   specific to wherever the IXP is.

## What's already reusable / data-driven

- Site lat/lon/name/address from NetBox (`_load_netbox_sites`), overridable in
  `network-map/sites.json`.
- Cable geometry + circuit metadata as committed data in `atlas/*.geojson`.
- Endpoint URLs are env-overridable: `SFLOW_URL`, `PROM_URL`, `IXP_NETBOX_API`,
  `GRAFANA_*`, `PROMETHEUS_URL`; portal host via the Hugo `map_portal_base` param;
  most ansible values in `roles/*/defaults`; Django `SFMIX_MAP_*` settings.
- The decorations/whimsy layer is optional and URL-fed (renders only if present).
- The render engine and the JSON contracts (above).

## What's SFMIX-specific and needs work (from the code inventory)

Grouped by concern; **[HARD]** = hardcoded in source, **[DATA]** = already config.

### A. Site identity & code shape  *(highest-value refactor)*
- **[HARD]** The site table is duplicated in **three** places:
  `map_trace_path.SITE_COORDS`, `make_fixture.SITES`, `gen_weathermap.METROS`
  (plus `map_boldyn_route.SITE_DC_NAME`). Should be **one** source read everywhere
  (extend `sites.json` / NetBox).
- **[HARD]** Site-code shape is baked in: `RE_SITE = [A-Za-z]{3}\d{2}`
  (`gen_map_structure.py`) and FQDN→site "second dotted label" parsing
  (`site_of`/`short` in the builder, weathermap, and `portal/views.py`). A
  different IXP's naming (or non-FQDN device ids) won't match.

### B. Collector profile (device/metric conventions)  *(highest-value refactor)*
- **[HARD]** The interface-description grammar
  `Core: Transport <SITE> via <Provider> {<TOKEN>} [<Speed>]` and its five regexes,
  the `"Core: Transport"` marker, the `cross-x`/`in cab` skip strings, `EXCLUDE_DESC`,
  and the `via A + B` provider-merge convention — all in `gen_map_structure.py`.
- **[HARD]** Data-source shapes: sflow-rt `/topology/json` node/link structure;
  Prometheus metric names (`sflow_ifoutoctets`/`sflow_ifinoctets`, labels
  `host`/`ifname`/`ifspeed`/`ifoperstatus`, and the `sflow_ixp_*` peering series);
  octet-gauge ×8 semantics; NetBox role `peering_switch` + netrc realm `sfmix.org`.
- **[HARD]** Arista-only collection: `pyeapi` + `show interfaces description` etc.
  A non-Arista fabric needs a different collector.

These two (A + B) are the cross-cutting ones — they thread through nearly every
backend file. Extracting them into a single **profile** (a dataclass / JSON) is the
bulk of "make it generic":

```
profile = {
  site_code_regex, fqdn_site_index,           # identity
  desc_marker, desc_grammar (the 5 regexes),  # what a backbone port looks like
  exclude_desc, xconnect_markers,
  speed_vocab,                                # 100G -> 1e11
  metrics: {octets_in, octets_out, speed_label, operstatus_label, host_label, ...},
  netbox: {role, api, token_file}, collector: "arista_eapi" | ...,
}
```

### C. Provider / KMZ tooling  *(inherently per-provider)*
- **[HARD]** `map_boldyn_route.py` (Boldyn/BART folder model, `SITE_DC_NAME`,
  metric-latitude constant), the whole `import_atlas.sh` manifest (vendor KMZ
  filenames, placemark names, match tokens), and circuit-id formats (`FID-*`,
  `FBDK-*`, `DF-*`). This is unavoidably specific to *which carriers* an IXP buys
  from, but the **atlas output format is generic** and the `map_trace_path`
  primitives (KML parse, chain, Douglas-Peucker coarsen) are reusable. A new IXP
  writes its own thin import manifest against its providers' KMZs.

### D. Basemap & view  *(geography — regenerate per region)*
- **[HARD]** `fetch_basemap.py BBOX` (Bay Area) and the committed
  `website/static/map/*` (water/land/roads/airports). Regenerate for the new metro.
- **[HARD]** Map `center`/`zoom`/`maxBounds` and tier thresholds
  (`METRO_ZOOM`/`EXPAND_ZOOM`/…) and attribution string in `network-map.js`; the
  whimsy content + coords in `decorations.geojson`. Should come from a small site
  config block (Hugo params or a `map-config.json`).

### E. Deployment / infra  *(mostly already parameterized)*
- **[HARD]** Hostnames (`metrics.sfo02`, `portal.sfmix.org`, …), output paths
  (`/var/www/sfmix-map`, `/var/lib/sfmix-map`), the `sfmix` user, ansible role
  names, the shared opaque-id UUID namespace, Grafana UIDs, and the sfmix.org-hosted
  switch icon. Most are ansible `defaults`/env already; the rest are find-replace.

### F. Scale/heuristic constants  *(tune, don't rewrite)*
- Building-box size, device-grid layout, weathermap column/row spacing, the
  capacity→width ladder and util colour ramp, and the geometry heuristics
  (`LOOP_MAX_M`, `APPROACH_M`, coarsening tolerances). Sensible defaults; a
  much larger or denser fabric would tune them.

## Recommended path to "reasonably generic"

Ordered by leverage. None of this blocks SFMIX; each step also de-duplicates SFMIX's
own code.

1. **Unify site identity.** One site table (NetBox + `sites.json`) consumed by the
   builder, both KMZ tools, the fixture, and the weathermap. Add `site_code_regex`
   + `fqdn_site_index` to config; delete the three duplicate tables. *(Removes the
   biggest correctness trap — the tables already drift.)*
2. **Extract a collector profile.** Move the description grammar, marker/skip
   strings, speed vocab, metric names/labels, and NetBox role into one
   `profile.json` (or a `Collector` class). Ship an `arista_eapi` collector and make
   `load_eapi_inventory`/`load_iface_facts`/`topo_adjacency` read the profile. This
   is what lets a non-SFMIX fabric plug in.
3. **Site/view config block.** A `map-config.json` (or Hugo params) for center,
   bounds, zoom tiers, attribution, basemap asset base, decorations URL — so a new
   region is config, not code edits.
4. **Package the engine.** `map_geometry.py` + the JSON contracts + the atlas format
   + the portal traffic view are already generic; document them as the stable API
   (this doc + `atlas/_TEMPLATE.geojson` + a short `map.json` schema note).
5. **Per-IXP import manifests.** Keep `map_trace_path`/`map_boldyn_route` primitives;
   each IXP writes its own `import_atlas.sh` for its carriers. Document the pattern.
6. **Deploy vars.** Fold remaining hostnames/paths/user/namespace into ansible
   group_vars so a new deployment is a vars file.

### To stand up the map for a new IXP (target end-state)
1. Point at the IXP's NetBox (role + API) and write `sites.json` overrides.
2. Fill a `profile.json` (code shape, description grammar, metric names, collector).
3. Regenerate the basemap for the metro (`fetch_basemap.py` with a new BBOX) and set
   the view config; optionally add local whimsy.
4. Write an `import_atlas.sh` for the IXP's fibre providers' KMZs (or ship none and
   let every link auto-arc initially).
5. Deploy with an IXP vars file (hosts/paths/namespace).

Everything else — the geometry engine, the renderer, the traffic feed, the opaque-id
privacy model, the atlas format — is shared.
