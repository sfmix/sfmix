# 016 — Site listings from NetBox (`sites.json`)

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

Follow the `participants_table.json` pattern. Ansible renders a public JSON
artefact from NetBox onto lg-web, and the website build curls it.
The map builder already talks to NetBox, so it reads the same NetBox fields
directly and drops its override file.

```
NetBox ──netbox_data──▶ participants_json role ──▶ lg.sfmix.org/sites.json ──curl──▶ website CI (Hugo)
   └──────────────── mapbuild (portal, daily Q2 schedule) ──▶ map.json
```

### 1. NetBox data model (fill the gaps, don't add a side store)

What already exists and gets reused:

- **Status**: `active` means listed. `planned` (oak01, scl03) can render
  as a "coming soon" row or be hidden; that's a website choice, not data.
  `unassigned` has no `site_id` and is excluded by rule.
- **`site_id`** custom field: shown as `sfo02 / 1`.
- **Region**: already the city (Sunnyvale exists, nuq01 is in it). The
  table's city and the hero's city list come from here.
- **`peeringdb_facility`**: the address link.
- **physical_address**, lat/lon.

What's missing, and goes in NetBox:

| Need | Where in NetBox | Notes |
|---|---|---|
| Metro grouping for the map/weathermap ("Santa Clara/Sunnyvale") | **Site Group** (currently unused) | One group per metro: San Francisco, Oakland, Fremont, San Jose, Santa Clara/Sunnyvale. |
| Short display name ("365 Main", "H5 Silicon Valley") | **description** | Already half-used this way. Normalise all 12. |
| Facility operator ("Digital Realty", "H5 Data Centers") | new custom field `facility_operator` (text) | PeeringDB org name was considered. A NetBox field keeps the website build PeeringDB-free and lets us write "Equinix" rather than "Equinix, Inc.". |
| MMR operator + portal | new custom fields `mmr_operator` (text), `mmr_portal_url` (URL) | Usually equals the facility operator, but not always. |

Street address in the table = `physical_address` up to the first comma, plus
the region name. sfo02's "Suite 303" moves into the first segment of its
NetBox address. scl02 currently links to PeeringDB *campus* 10. Drop that
for the facility link unless we want a `peeringdb_campus` field (not proposed).

### 2. Producer: `sites.json` in the `participants_json` role

Use a new template, `sites.yaml.j2`, beside `participants_table.yaml.j2`. It
reuses the `netbox_sites` fact that `netbox_data` already loads, writes
`sites.json` to `participants_json_output_directory`, and is validated
against a small JSON schema in the role (as the IX-F output is). One entry
per site with a `site_id`:

```json
{"sites": [
  {"code": "nuq01", "site_id": 9, "status": "active",
   "name": "H5 Silicon Valley", "facility": "H5 Data Centers Silicon Valley",
   "street": "1360 Kifer Rd", "city": "Sunnyvale", "metro": "Santa Clara/Sunnyvale",
   "facility_operator": "H5 Data Centers",
   "mmr_operator": "H5 Data Centers", "mmr_portal_url": "https://h5datacenters.com/",
   "peeringdb_facility": 2873, "lat": 37.372036, "lon": -121.987545}
]}
```

Everything in it is already public (PeeringDB / IX-F), so no isolation
concerns. Add `sites\.json` to the existing lg-web nginx static location
regex. Tag: `participants_json` (plus a `sites_json` tag for a narrow run).

Freshness: like `participants*.json`, the file updates when the Ansible tag
runs. That's acceptable because site changes are rare, and a new or
renumbered site already needs `route_servers`, `alice` and `dns` runs (the
`12276:1984:<site_id>` LRG and alice labels read `site_id`). The runbook
becomes: edit NetBox → `--tags dns,route_servers,alice,participants_json`.

### 3. Consumers

**Website (Hugo).**
- CI: add a `curl -fsSL -o data/sites.json https://lg.sfmix.org/sites.json`
  step. Also switch the participants curl to `-f`. Today an HTTP error page
  would be written into `participants_table.json`. With `-f` a failed fetch
  fails the build and the previous Pages deploy stays up. The existing
  6-hourly scheduled build picks up NetBox changes without a commit.
- `/locations/`: move the table into a `locations` layout (like
  `participants.html`), driven by `.Site.Data.sites`. Locale content files
  keep only the prose. Headers go through `T`, rows are data.
- Hero/footer/llms.txt/about: replace the literal sentence with a format
  string, e.g. `T "Peer with nearly %d networks at %d locations across %s."`,
  filled with the active-site count and the region list (joined with a
  translated `T "and"`). The about pages use a small `{{< site-count >}}`
  shortcode. The "nearly 100 networks" figure can come from
  `participants_table.json` in the same change. The i18n tomls lose the
  number-bearing key, so translations stop going stale on every site add.
- `llms.txt` is static. Either template it (move it to a Hugo output) or
  drop the count from it.

**Network map (`portal/mapbuild`).** `load_sites()` takes name ←
description, operator ← `facility_operator`, metro ← site group. Delete
`data/sites.json`. If cartographic nudges (`label_anchor`) are ever needed,
they're presentation and can come back as a map-only file keyed by code. The
daily Q2 build then follows NetBox without a portal deploy.

**Weathermap lab.** Either read `sites.json` / NetBox site groups, or delete
`weathermap_layouts.py` with the pending Grafana weathermap retirement
(the portal `/weathermap/` already groups by map metro).

### 4. Guardrail

Add a check to `scripts/netbox_ix_lint.py`. Every site with a `site_id` (or
status `active`) must have a region, site group, description,
`facility_operator`, `mmr_operator`, `mmr_portal_url`, `peeringdb_facility`
and lat/lon. `site_id` must be unique. A half-filled new site then fails lint
before it renders as a blank row or a stray metro.

## Alternatives considered

- **GitHub Action queries NetBox directly.** No Ansible run needed, but it
  puts a NetBox token in GitHub secrets and needs NetBox reachable from
  Actions runners. The public artefact on lg-web avoids both.
- **Portal publishes `sites.json`** (it already rebuilds from NetBox daily).
  That's fresher, but the public website would then depend on the portal.
  lg-web already serves the website's other build input.
- **Derive operator names from PeeringDB at build time.** It adds a third
  party to the website build and the names need tidying anyway.

## Rollout

1. NetBox: create site groups, normalise descriptions, add the 3 custom
   fields (`netbox_schema.playbook.yml` defines `site_id`, so add them there)
   and fill all sites. Fix sfo02's suite in the address.
2. Lint check (fails until step 1 is complete, which is useful as a checklist).
3. `sites.yaml.j2` + schema + nginx regex. Deploy `--tags participants_json`
   to lg-web. Verify `curl -f https://lg.sfmix.org/sites.json`.
4. Website: CI curl, locations layout, format-string hero/about. Compare the
   rendered `/locations/` against today's in all 5 locales before pushing.
5. mapbuild: read NetBox fields, delete `data/sites.json`, deploy portal,
   rebuild the map and diff `map.json` sites/metros against the previous build.
6. Retire or rewire `weathermap_layouts.py`.

## Aside found while surveying

The IX-F export's `switch` list (`participants.yaml.j2`, `role ==
peering_switch`) includes the AS40271 transit routers (`ar1.scl02.transit`,
`cr1.*.transit`). Those are not IXP switches. Check whether they carry IX
member ports. If not, filter them out of the IX-F `switch` list.
