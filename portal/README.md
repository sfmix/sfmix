# SFMIX Participant Portal

Django-based participant dashboard for SFMIX IX users. Authenticates via Authentik SSO (OIDC) at `login.sfmix.org`, using PeeringDB-sourced ASN group memberships to control which networks a user can view.

## Architecture

- **Host:** `web.sfmix.org` (Ansible group `sfmix_website`), DNS CNAME `portal.sfmix.org` → `web`
- **Runtime:** Django + Gunicorn in Docker, port 8000, behind Nginx with Let's Encrypt TLS
- **Auth:** `mozilla-django-oidc` → Authentik OIDC at `login.sfmix.org`
- **Data:** NetBox API with proactive in-process cache (background thread per Gunicorn worker, 4-hour refresh cycle with exponential backoff on failure)
- **Monitoring:** Prometheus metrics at `/metrics/` (restricted to trusted networks), admin health dashboard at `/admin/netbox-status/`
- **ASN gating:** Authentik groups like `as64500` (sourced from PeeringDB federation) are extracted from the OIDC `groups` claim and stored in the Django session. Each user sees only their own networks.
- **Install dir:** `/opt/ixp_portal/`

## Authentik Setup

Create an OIDC provider + application in Authentik for the portal:

| Parameter          | Value                                             |
|--------------------|---------------------------------------------------|
| Client ID          | `portal`                                          |
| Client type        | Confidential                                      |
| Redirect URI       | `https://portal.sfmix.org/oidc/callback/`         |
| Scopes             | `openid profile email groups`                     |
| Authorization flow | `default-provider-authorization-implicit-consent` |

The `groups` scope must use the existing `SFMIX: OpenID 'groups'` ScopeMapping (same one Grafana uses).

Set the resulting client secret as `OIDC_RP_CLIENT_SECRET` in the portal's environment.

## Local Development

```bash
cd portal
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# For local dev without real OIDC, create a superuser:
python manage.py migrate
python manage.py createsuperuser

# Run dev server
python manage.py runserver
```

For full OIDC testing against `login.sfmix.org`, set these env vars:
```bash
export OIDC_RP_CLIENT_ID=portal
export OIDC_RP_CLIENT_SECRET=<from-authentik>
export OIDC_PROVIDER_URL=https://login.sfmix.org/application/o/portal
export IXP_NETBOX_URL=https://netbox.sfmix.org
export IXP_NETBOX_TOKEN=<read-only-netbox-token>
```

## Production Deployment

### Quick Deploy

```bash
cd ansible
pipenv run ansible-playbook deploy_portal.playbook.yml --vault-password-file ~/.sfmix_ansible_vault
```

Or as part of the full push:
```bash
pipenv run ansible-playbook push_servers.playbook.yml --tags ixp_portal --vault-password-file ~/.sfmix_ansible_vault
```

### What the Ansible Role Does

The `ixp_portal` role (`ansible/roles/ixp_portal/`) performs these steps:

1. Installs Docker and docker-compose
2. Rsyncs `portal/` source to `/opt/ixp_portal/` (excludes `.venv`, `__pycache__`, `db.sqlite3`, `staticfiles`, `.env`)
3. Templates `.env` from vault-encrypted secrets (`ansible/roles/ixp_portal/templates/dotenv.j2`)
4. Builds and starts the Docker container (`docker-compose up -d --build`)
5. Runs Django migrations
6. Ensures Let's Encrypt cert for `portal.sfmix.org` via certbot
7. Deploys and enables Nginx reverse proxy vhost

### Secrets

Stored vault-encrypted in `ansible/inventory/host_vars/web.sfmix.org.yml`:

| Variable                        | Description                  |
|---------------------------------|------------------------------|
| `ixp_portal_django_secret_key`  | Django secret key            |
| `ixp_portal_oidc_client_secret` | Authentik OIDC client secret |
| `ixp_portal_netbox_token`       | NetBox API read-only token   |

### Verification

After deploying, check the container logs for a successful NetBox cache refresh:

```bash
ssh web.sfmix.org "sudo docker-compose -f /opt/ixp_portal/docker-compose.yml logs --tail 20 2>&1 | grep -iE 'netbox|error'"
```

Expected output: `NetBox cache refreshed in N.Ns: NN tenants, NN IPs, NN ports` from each Gunicorn worker.

IX Administrators can also check health in the browser at `https://portal.sfmix.org/admin/netbox-status/` after logging in.

Smoke test:
```bash
ssh web.sfmix.org "curl -s -o /dev/null -w '%{http_code}' -H 'Host: portal.sfmix.org' http://localhost:8000/login/"
# Expected: 200
```

### Troubleshooting

**SSH rate limiting / connection resets during deploy:**
`web.sfmix.org` has `PerSourceMaxStartups 10` in sshd. Ansible rsync opens extra SSH connections which can trip this. Admin IPs should be in `PerSourcePenaltyExemptList` (managed by `ansible/roles/sfmix_server/tasks/sshd.yml`).

**NetBox cache empty (0 tenants, 0 IPs):**
Check that `IXP_NETBOX_TOKEN` in `/opt/ixp_portal/.env` is a valid NetBox API token. Look for HTTP 403 errors in the container logs. The background cache thread starts when the first HTTP request hits each Gunicorn worker (via `dashboard.middleware.NetBoxCacheMiddleware`). On failure, the refresh loop retries with exponential backoff (30s → 60s → ... → 1h cap). IX Administrators can view the current error and clear/force-refresh from `/admin/netbox-status/`.

**500 errors on network detail pages:**
Check container logs for tracebacks. Common cause: NetBox objects with `null` nested fields (e.g. `custom_fields.participant` is null on some peering ports).

**Health check DisallowedHost warnings:**
The docker-compose health check hits `localhost:8000` which isn't in `ALLOWED_HOSTS`. These log warnings are harmless.

## Key Files

| File                                                      | Purpose                                                                    |
|-----------------------------------------------------------|----------------------------------------------------------------------------|
| `ansible/deploy_portal.playbook.yml`                      | Deployment playbook                                                        |
| `ansible/roles/ixp_portal/tasks/main.yml`                 | Ansible tasks (rsync, docker, nginx, certbot)                              |
| `ansible/roles/ixp_portal/defaults/main.yml`              | Default variables (domain, ports, OIDC, NetBox URL)                        |
| `ansible/roles/ixp_portal/templates/dotenv.j2`            | Environment variable template                                              |
| `ansible/roles/ixp_portal/templates/nginx-portal.conf.j2` | Nginx vhost template                                                       |
| `ansible/inventory/host_vars/web.sfmix.org.yml`           | Host secrets (vault-encrypted)                                             |
| `portal/dashboard/services.py`                            | NetBox data fetching, proactive cache, health tracking, Prometheus metrics |
| `portal/dashboard/middleware.py`                          | Starts background refresh thread per Gunicorn worker                       |
| `portal/ixp_portal/settings.py`                           | Django settings (OIDC, logging, middleware)                                |
| `portal/Dockerfile`                                       | Container image (Python 3.12 + Gunicorn)                                   |
| `portal/docker-compose.yml`                               | Docker Compose config                                                      |

## Environment Variables

| Variable                      | Default                                        | Description                                         |
|-------------------------------|------------------------------------------------|-----------------------------------------------------|
| `DJANGO_SECRET_KEY`           | `insecure-dev-key-change-me`                   | Django secret key                                   |
| `DJANGO_DEBUG`                | `true`                                         | Debug mode                                          |
| `DJANGO_ALLOWED_HOSTS`        | `*`                                            | Comma-separated allowed hosts                       |
| `OIDC_RP_CLIENT_ID`           | `portal`                                       | Authentik OIDC client ID                            |
| `OIDC_RP_CLIENT_SECRET`       | (empty)                                        | Authentik OIDC client secret                        |
| `OIDC_PROVIDER_URL`           | `https://login.sfmix.org/application/o/portal` | OIDC provider base URL                              |
| `IXP_NETBOX_URL`              | `https://netbox.sfmix.org`                     | NetBox API base URL                                 |
| `IXP_NETBOX_TOKEN`            | (empty)                                        | NetBox API read-only token                          |
| `PROMETHEUS_TRUSTED_NETWORKS` | `127.0.0.0/8,::1/128`                          | Comma-separated CIDRs allowed to scrape `/metrics/` |

## NetBox Cache

The portal maintains an in-process cache of participant data from NetBox, refreshed by a background thread in each Gunicorn worker.

- **Refresh interval:** 4 hours after a successful fetch
- **On failure:** exponential backoff starting at 30s, doubling each attempt, capped at 1 hour. Once backoff reaches the cap it waits until the next normal 4-hour cycle. Stale data continues to be served.
- **Startup:** the cache starts empty; the first refresh fires immediately when the background thread starts (triggered by the first HTTP request via `NetBoxCacheMiddleware`)
- **Per-worker isolation:** each Gunicorn worker has its own independent cache and refresh thread (no shared Redis/memcached)

### Health & Observability

- **Admin dashboard:** IX Administrators see a "NetBox Status" link in the nav bar, leading to `/admin/netbox-status/`. Shows health badge (Healthy / Degraded / No data), cache age, item counts, refresh duration, success/failure counts, and last error message. Includes a "Clear Cache & Refresh Now" button.
- **Prometheus metrics** at `/metrics/`, restricted to `PROMETHEUS_TRUSTED_NETWORKS`:

| Metric                            | Type      | Description                                                 |
|-----------------------------------|-----------|-------------------------------------------------------------|
| `netbox_refresh_duration_seconds` | Histogram | Time spent fetching data from NetBox                        |
| `netbox_refresh_success_total`    | Counter   | Successful cache refreshes                                  |
| `netbox_refresh_failure_total`    | Counter   | Failed cache refreshes                                      |
| `netbox_cache_age_seconds`        | Gauge     | Seconds since last successful refresh                       |
| `netbox_cache_items{type}`        | Gauge     | Cached items by type (tenants, ip_addresses, peering_ports) |
