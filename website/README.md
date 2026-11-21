# SFMIX Website

Static website for [sfmix.org](https://sfmix.org), built with [Hugo](https://gohugo.io/) and deployed via GitHub Pages.

## CI/CD

Every push to `main` triggers a GitHub Actions workflow that:

1. Builds the Hugo site (with `--minify`)
2. Fetches live data the looking glass serves from NetBox: participants (`https://lg.sfmix.org/api/v1/participants-table`) and sites (`https://lg.sfmix.org/api/v1/sites`, which drives `/locations/`, the location count and city list; design doc 016). The build fails if either fetch fails, so the last good deploy stays up.
3. Deploys to GitHub Pages at [sfmix.org](https://sfmix.org)

The workflow also runs on a schedule (every 6 hours) to keep participant and site data fresh, and can be triggered manually via `workflow_dispatch`.

DNS is a CNAME from `sfmix.org` to `sfmix.github.io`, managed by the `sfmix_dns` Ansible role in [sfmix/sfmix](https://github.com/sfmix/sfmix).

## Local Development

Requires [Hugo](https://gohugo.io/installation/) (extended edition, v0.142.0+).

```bash
# Fetch participant and site data (the build fails without sites.json)
mkdir -p data
curl -fsSL -o data/participants_table.json https://lg.sfmix.org/api/v1/participants-table
curl -fsSL -o data/sites.json https://lg.sfmix.org/api/v1/sites

# Start dev server with live reload
hugo server

# Visit http://localhost:1313
```

## Structure

```
content/              # Markdown content pages
layouts/              # Hugo templates
  _default/           # Base layout and single page template
  partials/           # Shared components (nav, etc.)
  index.html          # Homepage template
static/               # Static assets (CSS, images, docs, favicon)
data/                 # Runtime data (gitignored, fetched at build time)
hugo.toml             # Hugo configuration
.github/workflows/    # CI/CD pipeline
```

## Content Editing

Pages are Markdown files in `content/`. Each has YAML front matter:

```yaml
---
title: "Page Title"
url: "/page-slug/"
---

Page content in Markdown...
```

