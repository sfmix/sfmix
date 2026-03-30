# SFMIX Participant Portal

Django-based participant dashboard for SFMIX IX users. Authenticates via Authentik SSO (OIDC) at `login.sfmix.org`, using PeeringDB-sourced ASN group memberships to control which networks a user can view.

## Architecture

- **Auth:** `mozilla-django-oidc` → Authentik OIDC provider
- **Data:** IXF participants JSON from `lg.sfmix.org`, optional NetBox API
- **ASN gating:** Authentik groups like `as64500` are extracted from OIDC `groups` claim and stored in the Django session. Each user sees only their own networks.

## Authentik Setup

Create an OIDC provider + application in Authentik for the portal:

| Parameter | Value |
|-----------|-------|
| Client ID | `portal` |
| Client type | Confidential |
| Redirect URI | `https://portal.sfmix.org/oidc/callback/` |
| Scopes | `openid profile email groups` |
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
```

## Production Deployment

The portal runs on `web.sfmix.org` alongside the static website, with `portal.sfmix.org` as a DNS CNAME to `web`.

**Deploy via Ansible:**
```bash
cd ansible
ansible-playbook deploy_portal.playbook.yml --vault-password-file ~/.sfmix_ansible_vault
```

Or as part of the full push:
```bash
ansible-playbook push_servers.playbook.yml --tags ixp_portal --vault-password-file ~/.sfmix_ansible_vault
```

The Ansible role (`ixp_portal`) handles:
- Syncing portal source to `/opt/ixp_portal`
- Templating `.env` from vault-encrypted secrets in `host_vars/web.sfmix.org.yml`
- Building + running the Docker container (gunicorn on `127.0.0.1:8000`)
- Obtaining TLS cert for `portal.sfmix.org` via certbot
- Nginx reverse proxy vhost

**Secrets** are stored vault-encrypted in `ansible/inventory/host_vars/web.sfmix.org.yml`:
- `ixp_portal_django_secret_key` — Django secret key
- `ixp_portal_oidc_client_secret` — Authentik OIDC client secret (update after creating provider)
- `ixp_portal_netbox_token` — NetBox API token

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DJANGO_SECRET_KEY` | `insecure-dev-key-change-me` | Django secret key |
| `DJANGO_DEBUG` | `true` | Debug mode |
| `DJANGO_ALLOWED_HOSTS` | `*` | Comma-separated allowed hosts |
| `OIDC_RP_CLIENT_ID` | `portal` | Authentik OIDC client ID |
| `OIDC_RP_CLIENT_SECRET` | (empty) | Authentik OIDC client secret |
| `OIDC_PROVIDER_URL` | `https://login.sfmix.org/application/o/portal` | OIDC provider base URL |
| `IXP_PARTICIPANTS_URL` | `https://lg.sfmix.org/participants_table.json` | IXF participants data |
| `IXP_NETBOX_URL` | `https://netbox.sfmix.org` | NetBox API base URL |
| `IXP_NETBOX_TOKEN` | (empty) | NetBox API token (optional) |
