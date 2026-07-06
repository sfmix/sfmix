# Network map — deployment

Two deployment targets, one build. The **demo** is a password-gated static snapshot for
iterating; **production** embeds the map in the public static site with live, self-refreshing data
served from the portal.

---

## Build (shared)

`scripts/gen_map_structure.py` (default `--source=netbox`) produces two artifacts:

- **`map.json`** — PUBLIC. Sites, inter-site cables (render-ready `path`/`media`/`drops`, capacity,
  status), intra-site LAGs, metros. Cable ids are opaque per-generation uuids — **no** circuit ids,
  providers, ports, or exact fibre points.
- **`map-links.json`** — PRIVATE. Per opaque cable id → its member `{host, ifname}` list (the join
  key for traffic). Never served publicly.

Inputs: NetBox transport circuits (traced to switch ports) + committed coarse atlas
(`network-map/atlas/`, from the KMZ-mining pipeline) + live LLDP topology (intra-site) + Prometheus
`ifspeed` (capacity). Geometry for KMZ-less links is routed over the basemap transport network
(`infra_route`, see Follow-ups).

---

## Demo  (`demo.sfmix.org/network-map/`)

`network-map/dev/deploy_demo.sh` — one command, run from anywhere with NetBox creds + the
`sfmix.org` netrc entry. Off-box (no sflow-rt/Prometheus) it: generates live fixtures
(`gen_live_fixtures.py`: eAPI-LLDP topology + NetBox sites), builds `--source=netbox`, adds a
**synthetic** traffic overlay (`gen_synth_traffic.py`), assembles a self-contained bundle from
`website/static/` (NOT the stale Hugo `public/` — that mismatch crashes on `cable.segments`), and
rsyncs to the portal host. The whole `demo.sfmix.org` vhost already sits behind the "SFMIX Demo"
nginx basic-auth, so the subdir inherits it.

Demo = static snapshot + fake traffic. It is **not** the live pipeline; keep synthetic data off the
public site.

---

## Production  (public `sfmix.org/network-map/` + `portal.sfmix.org` data)

Three planes (mostly already built; see Activation for what's left):

1. **sfmix.org — static shell (Hugo → GitHub Pages).** `layouts/_default/network-map.html` already
   ships the page: vendored MapLibre + `network-map.js` + committed basemap/sprites, and data
   attributes pointing at the portal:
   `data-structure-url=<portal>/map/map.json`, `data-traffic-url=<portal>/statistics/map/traffic`.
   Deploy = Hugo build + Pages workflow. No per-build data in the static site.

2. **portal.sfmix.org — the changing, semi-static plane.**
   - nginx serves `/map/map.json` (+ basemap/sprites/decorations) as static files, with **CORS**
     (the static site fetches them cross-origin). Updated by the builder rsync.
   - Django `/statistics/map/traffic` reads the PRIVATE `map-links.json`, queries Prometheus for
     each member interface's bps, sums per cable id, and returns
     `{generation, links:{id:{in_bps,out_bps,util_pct,series_*}}}`, cached ~45 s. The public never
     touches Prometheus, and no host/ifname leaks (only opaque ids out).

3. **metrics.sfo02 — the builder.** `gen_map_structure.py` on a daily cron (+ ansible
   `push_servers.playbook.yml --tags map_structure`): reads live sflow-rt LLDP + NetBox + the
   committed atlas, writes `map.json` (public) + `map-links.json` (private), and rsyncs both to the
   portal over an rrsync-restricted key.

Data flow: **NetBox/LLDP/atlas → builder (metrics.sfo02) → rsync → portal → CORS fetch → static
site**. The map "changes" by the builder re-running + the portal traffic endpoint refreshing; the
static site itself is rebuilt only when the page/JS/basemap change.

### Activation (operator-pending)

1. **rsync key**: generate a builder→portal keypair; vault the private half as
   `map_builder_rsync_privkey` (sflow_rt role), set `map_builder_rsync_pubkey` (ixp_portal),
   rrsync-restrict to the two dest paths.
2. **Deploy** (always `--vault-password-file ~/.sfmix_ansible_vault`, direct SSH):
   `ansible-playbook push_servers.playbook.yml --tags map_structure` (builder + cron) and
   `deploy_portal.playbook.yml` (portal `/map/` + traffic endpoint). Website via the Pages workflow.
3. **Verify**: `curl <portal>/map/map.json` is the NetBox build; the public `/network-map/` renders
   with live util; `netbox_backbone_lint.py` is green (gate the builder cron on it).

---

## Follow-ups

- **Infra-routing rights-of-way data (build-time only, not a basemap layer).** `infra_route`
  currently routes over the basemap highways (`motorway`/`trunk`). To make better local routing
  choices for KMZ-less links, feed it a build-time routing network including **railways, bridges,
  and utility pipelines** (fibre follows these) — e.g. an OSM extract consumed only during
  generation to shape the geometry; it need not render on the map.
- **Passive-site + planned rendering.** A splice site (scl03) should draw as a small splice marker,
  not a full building; and planned circuits (Boldyn `SO-*`, not yet cabled) could show dashed when
  we choose to emit them.
- **Live traffic ids.** The demo's synthetic traffic is keyed to a snapshot generation; production
  traffic matches because the portal serves the same generation's `map-links.json`.
