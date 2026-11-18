# AGENTS.md

Guidance for AI coding agents (and humans) working in this repo. The README
covers *what* lives here; this file covers *how to work in it safely*.

## Context for this repo

The monorepo for SFMIX, an Internet Exchange in the SF Bay Area.

A lot of the code here drives **production network devices and servers that
other networks and core Internet infrastructure like root and TLD DNS servers
depend on**.

Treat changes in here as ops work with real-world impacts, not just code
changes.

| Path | What | Language / tool |
|---|---|---|
| `ansible/` | Server/VM/Proxmox config, route servers, DNS, metrics, LG, portal deploys | Ansible (pipenv) |
| `looking-glass/` | Rust workspace: `lg-server` (device SSH, state, RPC), `lg-cli` (telnet/SSH), `lg-http` (REST + MCP), `lg-neighborhood-watch` | Rust (cargo) |
| `portal/` | Participant portal, portal.sfmix.org | Django |
| `website/` | sfmix.org, GitHub Pages | Hugo |
| `network-map/` | MapLibre network/subway map | JS + Python build |
| `scripts/` | NetBox / discovery / ops utilities | Python 3.12 (pipenv) |
| `terraform/authentik/` | login.sfmix.org (authentik) config | Terraform |
| `documentation/` | Public docs + numbered design docs | Markdown |
| `development_ixp/` | Local containerlab + NetBox dev environment | docker / containerlab |
| `sensors/` | ESPHome environmental sensors | YAML |

NetBox (netbox.sfmix.org) is the source of truth for devices, ports,
participants and IPs. Ansible inventory, LG device lists, the portal, and the
network map all read from it. Fix data in NetBox instead of hard-coding
around it.

## Build, test, run

```bash
# Looking glass: static musl binaries (target hosts have old glibc)
cd looking-glass
cargo build --workspace
cargo test --workspace
cargo build --workspace --release --target x86_64-unknown-linux-musl

# Portal: offline dev with synthetic fixtures + a dev login (no SSO)
cd portal
python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
python manage.py migrate
python manage.py test
LG_USE_FIXTURES=true python manage.py runserver

# Website
cd website
mkdir -p data && curl -sL -o data/participants_table.json https://lg.sfmix.org/participants_table.json
hugo server

# Scripts / Ansible
cd scripts && pipenv sync
cd ansible && pipenv sync && pipenv run ansible-galaxy install -r requirements.yml
```

Run the relevant build/tests for every component you touch before you commit.
For Ansible changes, a `--check --diff` run against the target hosts is the
test.

## Ansible

- Always pass `--vault-password-file`, ideally with a socket to a password manager.
- Ansible uses **direct SSH** to hosts' public names, or ProxyJump via
  `shell.sfmix.org` for mgmt-only hosts. Administration hosts are expected to
  be attached to the internal management network, usually by Tailscale.
- **Scope every run.** `push_servers.playbook.yml` covers the whole fleet, so
  always use `--tags` and/or `--limit`. Preview with `--check --diff` first.
  Some hosts (notably the LG web tier) are sometimes deployed from unmerged
  worktree branches, so a run from `main` can revert them. Leave out tags you
  don't need.
- Per-service deploys have started having their own `deploy_*.playbook.yml`
  (portal, LG, login, backups, www-staging, ...). Prefer those over
  `push_servers`.
- Reload services in place; don't restart them. Prometheus and similar
  services reload with `docker exec ... kill -HUP 1`. Never use
  `docker kill --signal`: Docker then treats the container as manually
  stopped and won't start it again after a reboot.
- As the production VMs are not oversized, don't build on production hosts
  (especially the route servers). Build locally or in CI and then place the
  artifacts.
- When a one-shot cleanup task has run fleet-wide, verify it and then delete
  the task. Don't keep dead migration code in roles.

## Network devices

- Switch and router configs (Arista EOS, Nokia SR-OS, VyOS mgmt gateways,
  Junos mgmt switches) are **applied directly on the devices**. The
  `sfmix_network_devices` templates and playbooks are reference material and
  not the live push path. PDUs are configured through their web UIs.
- Device changes are outward-facing and can drop participants' BGP sessions.
  Propose the exact commands and get explicit approval before running any
  config change on gear. Read-only `show` commands are fine.
- BGP maintenance is always graceful: shut down each neighbor administratively
  first, then do the disruptive work.
- VyOS: use `commit-confirm` and make sure to confirm it! An unconfirmed commit
  reboots the box.
- Read-only device and fabric state is also available through the looking
  glass (telnet `lg.sfmix.org`, REST, or MCP).

## Hosts and naming

- Sites have both an ID/name as well as a numeric ID. e.g. 200 Paul Avenue is `sfo01` as well as `2`. Hosts are typically
  `<role>[nn].<site>.sfmix.org` (e.g. `switch01.sfo02`, `metrics.sfo02`).
- New VMs are mgmt-network-only by default. A host gets a public IP only if
  it serves a public frontend or an ingestion endpoint that public-only hosts
  push to.
- AS12276 is the IXP. AS40271 is the separate IP transit network, ip.sfmix.org (Nokia `cr1`
  routers). Don't mix them up.

## Data, privacy, and secrets

- This is a **public repo**. Never commit secrets, NetBox/API tokens,
  `scripts/.env`, `sensors/secrets.yaml`, or unencrypted vault material.
  Secrets in inventory are `ansible-vault` encrypted.
- `*.kmz` files and `network-map/atlas_precise/` hold NDA'd fiber paths and
  must never be committed. Only the coarsened `network-map/atlas/*.geojson`
  is publishable.
- Portal and LG dev fixtures must be **synthetic**. Don't copy real
  participant data into fixtures, tests, or docs examples.
- Participant-facing changes should minimise what participants have to do.
  Never ask participants to renumber just to tidy things up.

## Code conventions

- This is single-instance, single-org software. The producer and consumer of
  every API live in this repo. While not strictly forbidden, you should
  generally avoid adding backward-compat shims (optional fields, version
  negotiation, parallel old and new paths). Change the format and update every
  call site in the same commit.
- Unify state instead of layering it: one store updated in place beats a
  cache plus a separate history store.
- Looking glass boundaries: `lg-server` owns device access, durable state,
  and policy, and the frontends talk to it over RPC. `lg-http` is the user
  HTTP/MCP surface. New crates follow `lg-*` naming. Data exposed through
  `lg-http`/MCP must obey the same per-ASN isolation as the portal.
- Website copy goes through the `T` i18n partial
  (`website/layouts/partials/T.html`, `website/i18n/*.toml`). The theme and
  language cookies (`sfmix-theme`, `sfmix-lang`) are shared across sfmix.org,
  the LG, the portal, and snappy, so aim to keep them consistent.
- Visualizations and reports for operators are local HTML files or committed
  pages, not third-party hosted artifacts.

## Design docs

- Non-trivial designs go in `documentation/design_docs/NNN-slug.md`: next
  free number, a `# NNN — Title` heading, and a `Status:` line under it.
- Reasoning, rollout records, and runbooks belong in the doc. Keep the doc
  up to date as reality changes.

## Git workflow

- As we generally have 1-2 active authors at a time, most confident operators
  push without any pull requests.
  Work lands directly on `main` with linear history: rebase onto `origin/main`,
  then fast-forward push (`git push origin HEAD:main`).
  No merge commits, no force-push.
- Do parallel or agent work in a git worktree so it doesn't disturb the shared
  checkout.
- Commit messages are **succinct**: an `area: summary` or
  `type(scope): summary` subject (e.g. `fix(lg): ...`, `feat(portal): ...`,
  `dns: ...`, `docs(012): ...`) plus at most a couple of lines of body. The
  long reasoning goes in a design doc.
- Looking glass releases come from `looking-glass-v<semver>` tags, which CI
  builds into GitHub Release binaries. The website deploys from `main` via
  GitHub Actions.

## Before calling something done

1. Builds and tests pass for every component you touched.
2. Ansible changes: `--check --diff` is clean apart from the intended change.
3. Deployed services: verify the **live** result (served TLS cert, HTTP
   200, `systemctl is-active`, metrics scraping), not just the file on disk.
4. Design docs and READMEs that describe the changed behavior are updated.
