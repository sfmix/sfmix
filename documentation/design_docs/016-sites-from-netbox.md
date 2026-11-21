# 016 — Site listings and participant exports from NetBox, served by the LG

Status: LG part built 2026-11-21 (branch `worktree-design-016-sites-from-netbox`):
`/api/v1/sites` and `/api/v1/participants-table` added, the IX-F export
brought to parity with the static file, and the Ansible `participants_json`
renderer removed. Not yet deployed. NetBox fields, website locations layout,
mapbuild and lint are still to do.

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
cache, rebuilt by one refresh job every `refresh_interval_secs` (300 s). That
job already pulled site facility/region/PeeringDB id for each peering switch. It also already serves a public IX-F export built from that cache
(`/api/v1/participants.json` → RPC `/rpc/v1/participants.json`). Sites fit
the same path:

```
NetBox ──refresh job, 300 s──▶ lg-server (ixp_data.sites) ──RPC /rpc/v1/sites──▶ lg-http GET /api/v1/sites
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

### 2. lg-server: sites in the existing NetBox refresh job (built)

- One refresh job, two GraphQL lookups. `fetch_port_map`
  (`looking-glass/src/netbox.rs`) runs the existing port-map query and a
  separate `SITES_QUERY` (`site_list { slug status description facility
  physical_address latitude longitude custom_fields region group }`)
  concurrently (`tokio::try_join!`) through a shared `graphql_query` helper.
  Both results land in the same `NetboxFetchResult`, so every consumer sees
  one consistent snapshot. Only sites with a `site_id` are kept, and status
  is filtered in Rust because of the NetBox 4.5 enum-filter change.
- `NetboxIxpData.sites: Vec<IxpSite>`, sorted by `site_id`. Fields NetBox
  doesn't have yet (`metro` = site group, `facility_operator`,
  `mmr_operator`, `mmr_portal_url`) are `null` until filled in. `street` is
  the first line of `physical_address` (NetBox separates lines with `\r\n`).
- The port-map query now selects only `site { slug }` for peering switches
  and peering-port devices. `IxpSwitch` and `EnrichedPort` carry the site code,
  and the IX-F switch's colo/city/PeeringDB id are looked up from `sites`.
- Tenants carry `ixp_membership` (from the `ixp_participant` /
  `ixp_infrastructure` tags). The LG keeps every tenant with an ASN for port
  classification, which includes AS40271 transit customers. The public exports
  filter to IXP members, matching the Ansible `netbox_participants` lookup.
- RPC `GET /rpc/v1/sites` → `{"sites": [...]}`. All three NetBox exports
  (`participants.json`, `participants-table`, `sites`) return **503 until the
  first NetBox fetch has succeeded**. A freshly restarted lg-server never hands
  PeeringDB an empty member list, or the website an empty page.

### 3. lg-http: public `GET /api/v1/sites` (built)

A plain proxy like `get_ixf_member_export`, anonymous. All of it is already
public (PeeringDB / IX-F / the website itself), so per-ASN isolation doesn't
apply. `Cache-Control: public, max-age=300` matches the refresh interval
(shared helper with the other two exports). It sits under the existing lg-web `/api/v1/` nginx location and
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

## Participant exports moved to the LG (built)

There were two IX-F exports built from the same NetBox data: the static
Ansible one (`participants_json` role, Jinja, `lg.sfmix.org/participants.json`)
and lg-server's live `/api/v1/participants.json`. `participants_table.json`
existed only on the Ansible side. Both are now served by lg-server, and the
role is deleted:

| Public URL | Served by | Notes |
|---|---|---|
| `/api/v1/participants.json` | lg-server IX-F builder | Canonical, give this to PeeringDB |
| `/api/v1/participants-table` | `participants_table.rs` (new) | Same shape as the old file, so the website template is unchanged |
| `/participants.json`, `/participants.min.json`, `/participants_table.json` | nginx `rewrite` → the routes above | Legacy aliases for external scrapers; nothing in-repo uses them |

In-repo consumers moved to the `/api/v1/` URLs: website CI (`curl -f`), the
participants page footer link, the sflow-rt member/MAC import cron (now
fetch-to-file, then PUT only on success, so it never PUTs an empty body), the
LG index page links, and `scripts/participant_speeds.py`. The IX-F schema
moved to `looking-glass/doc/ixp-member-list.schema.json`.

**Parity check, 2026-11-21.** `cargo run --example netbox_exports` (live
NetBox) was diffed against the static files fetched minutes earlier:

- **Participants table: byte-identical.** 99 participants, same order
  (IXP participants by ASN, then infrastructure), every field equal. The only
  normalisation was `peering_ports: null`, a Jinja/YAML artefact for
  AS63055, which is now `[]`.
- **IX-F:** all 99 members and every connection identical (switch ids,
  speeds, VLAN, IPs, MACs). ixp/VLAN blocks are equal. One switch differs:
  `switch02.sjc01` (NetBox status `decommissioning`, no connections
  reference it) was listed by the Jinja template, which didn't filter switch
  status. lg-server lists active switches only.
- Fixed in the LG along the way. It had listed 8 non-IXP tenants (AS40271
  transit customers) as IX-F members with empty connection lists; that is now
  filtered by tag plus non-empty connections. The timestamp is now RFC 3339
  UTC (`…Z`): the static file had local time with no zone, and the LG had
  `+0000`. Both outputs validate against the IX-F schema.

Cutover order matters: deploy lg-server/lg-http **before** the nginx aliases
or the website CI change go live. If the website change lands first, the
scheduled build fails on `curl -f` and the last good deploy stays up, so that
order is safe but noisy.

## Rollout

1. ~~LG: sites lookup, `/api/v1/sites`, `/api/v1/participants-table`, IX-F
   parity, 503 guard, tests.~~ Built; parity verified (above).
2. Deploy the LG (musl build, `looking_glass` role) to the LG server and
   lg-web. Verify `curl -f https://lg.sfmix.org/api/v1/{sites,participants-table,participants.json}`
   and `/api/v1/netbox/status`. Mind worktree-deployed lg-web: don't revert it
   from a `main` push.
3. lg-web nginx (`--tags looking_glass_web`): legacy aliases. Re-run the
   parity diff against the *aliased* `/participants.json` and
   `/participants_table.json`.
4. metrics (`--tags sflow_rt`): new cron. Check the next import landed
   (sflow-rt member count unchanged).
5. Land on `main` so the website CI uses `/api/v1/participants-table`.
   Trigger `workflow_dispatch` and check sfmix.org/participants/.
6. PeeringDB: set SFMIX's IX-F member export URL to
   `https://lg.sfmix.org/api/v1/participants.json`. Done by hand in the
   PeeringDB IX settings; the old URL keeps working as an alias.
7. Remove the stale static files from lg-web:
   `/var/www/lg-web/participants{,.min,_table,_table.min}.json`. nginx no
   longer serves them after step 3.
8. NetBox: create site groups, normalise descriptions, add the 3 custom
   fields (`netbox_schema.playbook.yml` defines `site_id`, so add them there)
   and fill all sites. Fix sfo02's suite in the address.
9. Lint check (fails until step 8 is complete, which is useful as a checklist).
10. Website: sites curl, locations layout, format-string hero/about. Compare
    the rendered `/locations/` against today's in all 5 locales before pushing.
11. mapbuild: read the NetBox fields, delete `data/sites.json`, deploy portal,
    rebuild the map and diff `map.json` sites/metros against the previous build.
12. Retire or rewire `weathermap_layouts.py`.
13. Runbooks that say "run `--tags participants_json`" (participant
    offboarding, MAC refresh) drop that step: NetBox edits show up within
    300 s.

## Aside found while surveying

The IX-F `switch` list (lg-server's `peering_switches` query,
`role == peering_switch`) includes the AS40271
transit routers (`ar1.scl02.transit`, `cr1.*.transit`). Those are not IXP
switches. Check whether they carry IX member ports. If not, filter them out
of the IX-F `switch` list.
