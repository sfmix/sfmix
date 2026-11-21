# 016 — Site listings from NetBox (LG `/api/v1/sites`)

Status: proposed, 2026-11-21. Nothing built yet.

## Problem

NetBox is the source of truth for sites (slug, `site_id`, status, address,
lat/lon, region, PeeringDB facility). Several public surfaces still keep
their own hand-written copy of that list:

| Surface | Hand-maintained copy |
|---|---|
| sfmix.org `/locations/` | Markdown table, duplicated in 5 locale files (`website/content/locations*.md`) |
| sfmix.org hero/footer, `llms.txt`, about pages | "9 locations across SF, San Jose, Santa Clara, and Fremont" baked into an i18n *key* (4 tomls, 2 layouts) and 5 about pages |
| Network map (`portal/mapbuild`) | `data/sites.json` overrides for display name / operator / metro |
| Grafana weathermap lab (`scripts/weathermap_layouts.py`) | `SITE_METRO` / `METRO_NAME` dicts |

Adding nuq01 (`site_id` 9) on 2026-11-21 took 19 file edits. The map was
the subtle one: a site with no override silently becomes its own one-site
metro. `weathermap_layouts.py` still doesn't know nuq01.

## Design

The looking glass serves the site list. lg-server already holds a hot NetBox
cache: one GraphQL query refreshed every `refresh_interval_secs` (300 s),
which already pulls site facility/region/PeeringDB id for each peering
switch. It also already serves a public IX-F export built from that cache
(`/api/v1/participants.json` → RPC `/rpc/v1/participants.json`). Sites fit
the same path:

```
NetBox ──GraphQL, 300 s──▶ lg-server (ixp_data.sites) ──RPC /rpc/v1/sites──▶ lg-http GET /api/v1/sites
                                                                               ├──▶ website CI (Hugo, 6-hourly)
                                                                               └──▶ weathermap lab, scripts, MCP
NetBox ──────────────────────────────────────────────────────────────────────────▶ mapbuild (daily; already reads NetBox)
```

Why the LG and not a static `sites.json` from Ansible (the first draft of
this doc):

- **No Ansible step.** A NetBox edit reaches the website at the next
  scheduled build (≤ 6 h + 5 min), with no tag to remember.
- **One store.** Site data joins the existing `ixp_data` cache that the IX-F
  export uses, rather than becoming a second rendered artefact. The IX-F
  switch entries can then reference their site, instead of each copying
  facility, city and PeeringDB id.
- **Same boundary as everything else.** lg-server owns the NetBox access and
  shapes the data. lg-http is the public HTTP surface.

### Naming: `/api/v1/sites`, not `/locations`

Existing vocabulary, surveyed 2026-11-21:

| Where | Term |
|---|---|
| NetBox | **Site** object; slug = site code; custom field `site_id` |
| lg-server Rust | `site` (`SiteEntry`, `device.site`) |
| Portal `map.json` | `sites`, `metros` |
| Website | page title **"Locations"**; column "SFMIX **Site Code**"; route-server page says "see Locations for site codes" |
| IX-F schema | `colo`, `pdb_facility_id`, `city` (per switch) |
| `participants_table.json` | `peering_ports[].location` = facility *name* (the odd one out) |
| LG REST style | plural kebab-case nouns: `/participants`, `/peering-vlans`, `/participant-ports` |

So the data is called **sites** everywhere it's a data noun. "Locations" is
only the human page title, and that stays as-is on sfmix.org. The endpoint
is `GET /api/v1/sites` (RPC `/rpc/v1/sites`). Fields: `code` (slug, the
"site code"), `site_id` (our numeric custom field), `metro` (site group),
`city` (region). Don't expose the NetBox PK. NetBox's own REST filters call
*that* `site_id`, which is a known ambiguity, but our Jinja/Rust/LRG docs
already mean the custom field. Other payloads refer to a site by `site`
(= code). When the participants table moves to the LG (follow-on below),
`location` becomes `site` and the facility name is looked up from
`/api/v1/sites`.

### 1. NetBox data model (fill the gaps, don't add a side store)

What already exists and gets reused:

- **Status**: `active` means listed. `planned` (oak01, scl03) can render
  as a "coming soon" row or be hidden; that's a website choice, not data.
  `unassigned` has no `site_id` and is excluded by rule.
- **`site_id`** custom field: shown as `sfo02 / 1`.
- **Region**: already the city (Sunnyvale exists, nuq01 is in it).
- **`peeringdb_facility`**: the address link.
- **physical_address**, lat/lon.

What's missing, and goes in NetBox:

| Need | Where in NetBox | Notes |
|---|---|---|
| Metro grouping for the map/weathermap ("Santa Clara/Sunnyvale") | **Site Group** (currently unused) | One group per metro: San Francisco, Oakland, Fremont, San Jose, Santa Clara/Sunnyvale. |
| Short display name ("365 Main", "H5 Silicon Valley") | **description** | Already half-used this way. Normalise all 12. |
| Facility operator ("Digital Realty", "H5 Data Centers") | new custom field `facility_operator` (text) | lg-server already has a PeeringDB cache, but a NetBox field lets us write "Equinix" rather than the PeeringDB org name. |
| MMR operator + portal | new custom fields `mmr_operator` (text), `mmr_portal_url` (URL) | Usually equals the facility operator, but not always. |

sfo02's "Suite 303" moves into the first segment of its NetBox
`physical_address`. scl02 currently links to PeeringDB *campus* 10. Drop
that for the facility link unless we want a `peeringdb_campus` field (not
proposed).

### 2. lg-server: sites in the existing NetBox fetch

- `fetch_port_map` (`looking-glass/src/netbox.rs`): add a `site_list` block
  to the existing single GraphQL query: `slug status description facility
  physical_address latitude longitude custom_fields region { name } group {
  name }`. Keep only sites with a `site_id`. Filter in Rust, as switch status
  already is, because of the NetBox 4.5 enum-filter change.
- Add `sites: Vec<IxpSite>` to `NetboxIxpData`, the same struct and refresh
  as the switches and VLANs:

  ```rust
  pub struct IxpSite {
      pub code: String,            // slug, "nuq01"
      pub site_id: u32,
      pub status: String,          // "active" | "planned"
      pub name: String,            // description, "H5 Silicon Valley"
      pub facility: String,        // "H5 Data Centers Silicon Valley"
      pub street: String,          // physical_address up to first comma
      pub city: String,            // region
      pub metro: String,           // site group
      pub facility_operator: String,
      pub mmr_operator: String,
      pub mmr_portal_url: String,
      pub peeringdb_facility: Option<u64>,
      pub lat: Option<f64>,
      pub lon: Option<f64>,
  }
  ```

- `IxpSwitch` gains `site: String` (code). The IX-F builder looks up
  colo/city/PeeringDB id from `sites`, so `SiteEntry` is parsed once.
- RPC: `GET /rpc/v1/sites` → `{"sites": [...]}` sorted by `site_id`.
  **Return 503 until the first NetBox fetch has succeeded.** Otherwise a
  freshly restarted lg-server serves an empty list, and the website would
  publish an empty locations page. The cache-warm work in 859e641 made that
  window short, but it still exists.

### 3. lg-http: public `GET /api/v1/sites`

A plain proxy like `get_ixf_member_export`, anonymous. All of it is already
public (PeeringDB / IX-F / the website itself), so per-ASN isolation doesn't
apply. Set `Cache-Control: public, max-age=300` to match the refresh
interval. It sits under the existing lg-web `/api/v1/` nginx location and
rate limit; one request per website build is nothing. Optionally add an MCP
tool `show_sites` / lg-cli `show sites`, which costs little with the data in
hand. Fixtures for tests stay synthetic.

### 4. Consumers

**Website (Hugo).**
- CI: add a `curl -fsSL -o data/sites.json https://lg.sfmix.org/api/v1/sites`
  step. Also switch the participants curl to `-f`. Today an HTTP error page
  would be written into `participants_table.json`. With `-f` a failed fetch
  (including the 503 above) fails the build and the previous Pages deploy
  stays up. The template also `errorf`s if there are zero active sites.
  The existing 6-hourly scheduled build picks up NetBox changes without a
  commit.
- `/locations/`: move the table into a `locations` layout (like
  `participants.html`), driven by `.Site.Data.sites`. Locale content files
  keep only the prose. Headers go through `T`, rows are data.
- Hero/footer/llms.txt/about: replace the literal sentence with a format
  string, e.g. `T "Peer with nearly %d networks at %d locations across %s."`,
  filled with the active-site count and the city list (joined with a
  translated `T "and"`). The about pages use a small `{{< site-count >}}`
  shortcode. The "nearly 100 networks" figure can come from the participants
  data in the same change. The i18n tomls lose the number-bearing key, so
  translations stop going stale on every site add.
- `llms.txt` is static. Either template it as a Hugo output or drop the
  count from it.

**Network map (`portal/mapbuild`).** It already queries NetBox for
devices, cables and circuits, and joins them to sites by slug. It keeps
reading NetBox directly: `load_sites()` takes name ← description, operator ←
`facility_operator`, metro ← site group. Delete `data/sites.json`. Moving it
to `/api/v1/sites` would add a cross-service dependency to a daily batch job
in exchange for three field mappings, so that's not worth it. If cartographic
nudges (`label_anchor`) are ever needed, they're presentation and can come
back as a map-only file keyed by code. The daily Q2 build then follows NetBox
without a portal deploy.

**Weathermap lab.** Either read `/api/v1/sites`, or delete
`weathermap_layouts.py` with the pending Grafana weathermap retirement (the
portal `/weathermap/` already groups by map metro).

### 5. Guardrail

Add a check to `scripts/netbox_ix_lint.py`. Every site with a `site_id` (or
status `active`) must have a region, site group, description,
`facility_operator`, `mmr_operator`, `mmr_portal_url`, `peeringdb_facility`
and lat/lon. `site_id` must be unique. A half-filled new site then fails lint
before it renders as a blank row or a stray metro. lg-server should also log
a warning for a `site_id` site with missing fields rather than skipping it.

## Alternatives considered

- **Static `sites.json` rendered by the Ansible `participants_json` role**
  (first draft). That copies the `participants_table.json` pattern, but it
  is only as fresh as the last Ansible run, and it makes a second rendered
  copy of data the LG already caches.
- **GitHub Action queries NetBox directly.** That puts a NetBox token in
  GitHub secrets and needs NetBox reachable from Actions runners.
- **Portal publishes it** (it already rebuilds from NetBox daily). That makes
  the public website depend on the portal, and it's only daily.

## Follow-on: retire the Ansible-rendered participant artefacts

There are two IX-F exports today, built from the same NetBox data. One is
static, rendered by the Ansible `participants_json` role and served at
`lg.sfmix.org/participants.json` (Jinja). The other is live, from lg-server
at `/api/v1/participants.json` (Rust). `participants_table.json`, which the
website uses, is Ansible-only. With `/api/v1/sites` in place, the same move
for the participants table (`/api/v1/participants-table`, or reshape
`/api/v1/participants`) would let the `participants_json` role go away.
Point `/participants.json` at the LG route and check what PeeringDB / the
IX-F database have registered first. That's a separate change, but it's the
"unify state" end state this doc points toward.

## Rollout

1. NetBox: create site groups, normalise descriptions, add the 3 custom
   fields (`netbox_schema.playbook.yml` defines `site_id`, so add them there)
   and fill all sites. Fix sfo02's suite in the address.
2. Lint check (fails until step 1 is complete, which is useful as a checklist).
3. LG: query + `IxpSite` + IX-F switch→site refactor + RPC/REST route, with
   unit tests on synthetic GraphQL fixtures. Confirm the IX-F output is
   byte-identical before/after. Tag a `looking-glass-v*` release and deploy
   lg-server and lg-web. Mind worktree-deployed lg-web; don't revert it from
   a `main` push. Verify `curl -f https://lg.sfmix.org/api/v1/sites`, and
   that it 503s, not `[]`, during a restart.
4. Website: CI curl, locations layout, format-string hero/about. Compare the
   rendered `/locations/` against today's in all 5 locales before pushing.
5. mapbuild: read the NetBox fields, delete `data/sites.json`, deploy portal,
   rebuild the map and diff `map.json` sites/metros against the previous build.
6. Retire or rewire `weathermap_layouts.py`.

## Aside found while surveying

The IX-F `switch` list (both the Jinja `participants.yaml.j2` and lg-server's
`peering_switches` query, `role == peering_switch`) includes the AS40271
transit routers (`ar1.scl02.transit`, `cr1.*.transit`). Those are not IXP
switches. Check whether they carry IX member ports. If not, filter them out
of the IX-F `switch` list.
