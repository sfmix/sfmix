# Network map — deployment

Two deployment targets, one builder. The **demo** is a password-gated static snapshot for
iterating; **production** embeds the map in the public static site with live, self-refreshing data
served from the portal. The builder now lives **inside the portal** (`portal/mapbuild`) and runs on
a schedule via Django-Q2 — there is no separate build host and no rsync. See `ARCHITECTURE.md` for
the offline-pipeline ↔ portal-builder split.

---

## Build (shared)

`portal/mapbuild/builder.py` (also runnable as `manage.py build_map`, or imported directly)
produces two artifacts:

- **`map.json`** — PUBLIC. Sites, inter-site cables (render-ready `path`/`media`/`drops`, capacity,
  status), intra-site LAGs, metros, pre-aggregated metro cables. Cable ids are opaque per-generation
  uuids — **no** circuit ids, providers, ports, or exact fibre points.
- **`map-links.json`** — PRIVATE. Per opaque cable id → its member `{host, ifname}` list (the join
  key for traffic). Never served publicly.

Inputs, all NetBox + committed geometry (no internal network needed):
- NetBox transport circuits traced to switch ports (inter-site), NetBox intra-site inter-switch
  cabling (LAGs), NetBox devices/sites, and NetBox `interface.speed` (capacity).
- Committed coarse geometry baked into the image at `portal/mapbuild/data/`: cable `atlas/`,
  `sites.json` overrides, `basemap-water.json`, `basemap-roads.json`, `rights-of-way.json`.
- KMZ-less links are routed over the committed transport corridors (`routing.infra_route`).

NetBox honesty is enforced by `scripts/netbox_backbone_lint.py` (gate this in CI) and reconciled by
`scripts/map_intra_cabling.py` + `scripts/map_circuits.py`.

---

## Demo  (`demo.sfmix.org/network-map/`)

`network-map/dev/deploy_demo.sh` — one command, run from anywhere with NetBox creds
(`NETBOX_API_ENDPOINT`/`NETBOX_API_TOKEN` or `scripts/.env`) and `pip install pynetbox requests`. It
builds the map straight from NetBox using the packaged builder (`PYTHONPATH=portal python -c "from
mapbuild import builder ..."`), adds a **synthetic** traffic overlay (`gen_synth_traffic.py`),
assembles a self-contained bundle from `website/static/` (NOT the stale Hugo `public/` — that
mismatch crashes on `cable.segments`), and rsyncs to the demo vhost, which already sits behind the
"SFMIX Demo" nginx basic-auth.

Demo = static snapshot + fake traffic. It is **not** the live pipeline; keep synthetic data off the
public site.

---

## Production  (public `sfmix.org/network-map/` + `portal.sfmix.org` data)

Three planes:

1. **sfmix.org — static shell (Hugo → GitHub Pages).** `layouts/_default/network-map.html` ships the
   page: vendored MapLibre + `network-map.js` + committed basemap/sprites, with data attributes
   pointing at the portal: `data-structure-url=<portal>/statistics/map/map.json`,
   `data-traffic-url=<portal>/statistics/map/traffic`. Deploy = Hugo build + Pages workflow. No
   per-build data in the static site.

2. **portal.sfmix.org — builds + serves the changing plane.**
   - **`qcluster`** service (Django-Q2, ORM broker on the shared SQLite `db` volume) runs
     `mapbuild.tasks.build_map_task` on a **daily schedule** (created idempotently on startup) and
     **on demand** from the admin page. It writes `map.json` + `map-links.json` into
     `/app/db/map/` on the `db` volume.
   - `GET /statistics/map/map.json` (mapbuild view) serves the PUBLIC map with CORS + a 5-minute
     cache — the static site fetches it cross-origin.
   - `GET /statistics/map/traffic` (dashboard) reads the PRIVATE `map-links.json`, queries Prometheus
     per member interface, sums per cable id, and returns `{generation, links:{id:{…}}}`, cached
     ~45 s. The public never touches Prometheus and no host/ifname leaks (only opaque ids out).
   - `GET /admin/map-build/` (IX-admin only) shows current map, next scheduled run, queue depth,
     recent successes/failures, and a **Rebuild now** button.

Data flow: **NetBox + committed geometry → qcluster build (portal) → db volume → portal serves
map.json (CORS) + traffic → static site fetch**. The map "changes" as the scheduled build re-runs
and the traffic endpoint refreshes; the static shell is rebuilt only when page/JS/basemap change.

### Activation / deploy

1. **Env**: set `NETBOX_API_TOKEN` (+ `NETBOX_API_ENDPOINT` if not the default) in the portal `.env`;
   `PROMETHEUS_URL` is already set for the traffic endpoint.
2. **Deploy** (always `--vault-password-file ~/.sfmix_ansible_vault`, direct SSH):
   `ansible-playbook deploy_portal.playbook.yml` rebuilds the image (adds `django-q2`, `pynetbox`,
   `requests`), and `docker compose up -d` brings up the one-shot `migrate` (applies `django_q`
   tables), `portal`, and `qcluster`. First boot registers the daily schedule and can be primed with
   **Rebuild now** (or `docker compose exec portal python manage.py build_map`).
3. **Point the static site** `data-structure-url` at `<portal>/statistics/map/map.json`; deploy the
   website via the Pages workflow.
4. **Verify**: `curl <portal>/statistics/map/map.json` is the NetBox build; `/admin/map-build/`
   shows a green success; the public `/network-map/` renders with live util;
   `netbox_backbone_lint.py` is green.

---

## Follow-ups

- **Build performance.** A full NetBox build is ~3 min (sequential circuit-hint + trace calls).
  Fine for a daily/on-demand job; if it needs to be faster, have `netbox_topology` cache the traced
  circuit so `netbox_cables` doesn't re-trace, and batch the circuit-termination fetches.
- **Passive-site + planned rendering.** Passive splice sites (scl03) already draw as a box with a
  through-patch cross-connect; planned circuits (Boldyn `SO-*`, not yet cabled) could show dashed
  when we choose to emit them.
- **circuit_hints duplication.** `portal/mapbuild/circuits.py` is the portal's self-contained copy of
  the NetBox circuit-geometry helpers; the offline miner (`scripts/map_kmz_mine.py`) keeps its own
  copy. They derive geom-groups identically and must stay in sync — consider unifying if they drift.
