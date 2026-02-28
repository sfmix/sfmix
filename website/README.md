# SFMIX Website

Static website for [sfmix.org](https://sfmix.org), built with [Hugo](https://gohugo.io/) and deployed to `web.sfmix.org` via GitHub Actions.

## CI/CD

Every push to `main` that touches `website/` triggers a GitHub Actions workflow (`.github/workflows/website.yml`) that:

1. Builds the Hugo site (with `--minify`)
2. Fetches live participant data from `https://lg.sfmix.org/participants_table.json`
3. Deploys the built `public/` directory to `web.sfmix.org` via rsync over SSH

The deploy key is stored as the `DEPLOY_SSH_KEY` GitHub Actions secret. The VM is provisioned by the `sfmix_website` Ansible role in `ansible/roles/sfmix_website/` (nginx, Let's Encrypt TLS, deploy user).

## Local Development

Requires [Hugo](https://gohugo.io/installation/) (extended edition, v0.142.0+).

```bash
# Fetch participant data
mkdir -p data
curl -sL -o data/participants_table.json https://lg.sfmix.org/participants_table.json

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

