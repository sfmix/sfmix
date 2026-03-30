# 003 - login.sfmix.org: Authentik SSO Platform

## Overview

Deploy [Authentik](https://goauthentik.io/) as the centralized SSO/identity platform for SFMIX at `login.sfmix.org`. Two distinct authentication audiences:

1. **SFMIX Administrators** — staff who manage SFMIX infrastructure (NetBox, Grafana, etc.)
2. **IX Participants** — network operators who authenticate via PeeringDB federated login, identified by their ASN

## Infrastructure

| Item | Value |
|------|-------|
| **Hostname** | `login.sfmix.org` |
| **VM ID** | 105 |
| **Hypervisor** | `pve01.scl04.sfmix.org` |
| **OS** | Debian Trixie (13) |
| **Ansible group** | `login` |
| **Ansible role** | `authentik` |
| **Playbook** | `deploy_login.playbook.yml` |

### Networking

- **IPv4:** `192.33.255.71` (VLAN 110 — Public Site-spanning Access LAN)
- **IPv6:** `2620:11a:b000:110::71`
- **Gateway:** `192.33.255.65` / `2620:11a:b000:110::1`
- **DNS:** `login.sfmix.org` A/AAAA records
- **Subnet:** `192.33.255.64/27` / `2620:11a:b000:110::/64`

## Architecture

```
                    ┌─────────────────────────────────┐
                    │        login.sfmix.org          │
                    │                                 │
  HTTPS :443 ──────▶  nginx (TLS termination)        │
                    │    │                            │
                    │    ▼                            │
                    │  Authentik Server (:9000)       │
                    │  Authentik Worker               │
                    │  PostgreSQL 16                  │
                    │  Redis                          │
                    │                                 │
                    │  (all via docker-compose)       │
                    └─────────────────────────────────┘
```

### Components (docker-compose)

- **authentik server** — Web UI + API (port 9000/9443)
- **authentik worker** — Background tasks, outpost management
- **postgresql 16-alpine** — Authentik database
- **redis alpine** — Cache/message broker
- **nginx** — TLS termination, reverse proxy to authentik (host-level, not containerized)

## Authentication Flows

### Flow 1: SFMIX Administrator Login

**Purpose:** SFMIX staff authenticate to manage infrastructure services
(Grafana, NetBox, etc.). Access requires membership in the `IX Administrators`
group.

#### Group Model

| Group | Purpose | How assigned |
|-------|---------|-------------|
| `IX Administrators` | IX operators — access to Grafana and admin tools | Automatically via GitHub or PeeringDB (see below) |
| `authentik Admins` | Authentik platform superusers | Manually assigned (subset of IX Admins) |

Not all IX Administrators are authentik Admins. `authentik Admins` is manually
assigned to users who need to manage the Authentik platform itself.

#### Two Paths to IX Administrator

There are two ways a user can become an IX Administrator:

**Path 1: GitHub team membership**

Users who are members of the `sfmix/ix-administrators` team on GitHub are
automatically added to the `IX Administrators` group on first login.

| Parameter | Value |
|-----------|-------|
| Client ID | `Ov23liaNukEQ6zEzsem9` |
| Callback URL | `https://login.sfmix.org/source/oauth/callback/github/` |
| Additional Scopes | `read:org` (for team membership check) |
| Provider type | `github` (built-in) |

The user property mapping (`GitHub Admin User Mapping`) fetches `/user/teams`
from the GitHub API using the OAuth token. If the user is a member of
`sfmix/ix-administrators`, the mapping returns `IX Administrators` in the
`groups` list.

**Path 2: PeeringDB AS12276 admin**

Users who are administrators of AS12276 (SFMIX) on PeeringDB are automatically
added to the `IX Administrators` group on first login. This allows SFMIX
operators who may not have GitHub accounts to gain admin access.

The PeeringDB user property mapping (`PeeringDB User Mapping`) checks the
`networks` claim. If any network has `asn == 12276`, the mapping adds
`IX Administrators` to the user's groups (in addition to the per-ASN groups
like `as12276`).

#### User Identity Canonicalization

Both sources use `email_link` matching mode and set `username = email`. This
ensures that a user who logs in via both GitHub and PeeringDB with the same
email address is linked to a single Authentik user. Groups from both sources
are merged onto that user.

#### Session Duration

All login stages set to **8 hours**. This limits how long a session persists
before requiring re-authentication.

#### Group Sync on Every Login

A `UserWriteStage` (`default-source-authentication-write`) has been added to
the `default-source-authentication` flow with `user_creation_mode=never_create`.
This ensures that on every returning login (not just first enrollment):

1. The source's user property mapping is re-evaluated against the fresh
   OAuth token / OIDC claims.
2. The user's group memberships are updated to match the mapping output.
3. If a user is removed from the GitHub `ix-administrators` team, they
   lose `IX Administrators` on next login.
4. If a user loses PeeringDB admin access to AS12276, same applies.

The `never_create` mode ensures this stage only updates existing users and
cannot accidentally create new ones during the authentication flow.

**Authentication flow stages:**
1. `default-source-authentication-write` (UserWriteStage, order=5) — re-evaluate user attributes and groups
2. `default-source-authentication-login` (UserLoginStage, order=10) — create session

Combined with the 8-hour session duration, group membership is re-evaluated
at least every 8 hours.

#### Downstream Applications (OIDC Providers)

##### Grafana (`grafana.sfmix.org`) — DONE

Authentik OIDC provider with `default-provider-authorization-implicit-consent`
flow (no user prompt). Grafana uses Generic OAuth with env vars.

| Parameter | Value |
|-----------|-------|
| Client ID | `grafana` |
| Redirect URI | `https://grafana.sfmix.org/login/generic_oauth` |
| Scopes | `openid profile email groups` |
| Auth URL | `https://login.sfmix.org/application/o/authorize/` |
| Token URL | `https://login.sfmix.org/application/o/token/` |
| Userinfo URL | `https://login.sfmix.org/application/o/userinfo/` |

**Role mapping** (via `GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH`):
- `IX Administrators` + `authentik Admins` → `GrafanaAdmin`
- `IX Administrators` only → `Admin`
- No matching group → empty string (denied by `role_attribute_strict`)

**Defense in depth (two layers of access control):**

1. **Authentik layer:** An `ExpressionPolicy` (`Grafana: Require Admin Group`)
   bound to the Grafana application checks:
   ```python
   return ak_is_group_member(request.user, name="IX Administrators")
   ```
   Non-members are denied at the Authentik authorization step, before any
   redirect to Grafana occurs.

2. **Grafana layer:** `GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT=true`
   independently denies login if the `groups` OIDC claim doesn't include
   `IX Administrators`. This ensures Grafana enforces its own access control
   even if the Authentik policy is misconfigured or removed.

The `groups` OIDC scope is served by a custom `ScopeMapping`
(`SFMIX: OpenID 'groups'`) that returns all Authentik group memberships in
the token claims.

##### Future downstream apps
- NetBox (`netbox.sfmix.org`) — has OIDC/SAML support
- LibreNMS (`librenms.sfmix.org`)
- Any future admin tools

**Authorization summary:**
- `IX Administrators` → access to downstream admin apps (Grafana, etc.)
- `authentik Admins` → additionally can manage Authentik configuration

### Flow 2: IX Participant Login (PeeringDB Federation)

**Purpose:** IX participants authenticate using their PeeringDB identity, associated with their ASN(s). This enables self-service access to participant-facing tools.

**Method:** PeeringDB OIDC via Authentik's built-in `openidconnect` source type.

PeeringDB supports full OIDC with discovery at
`https://auth.peeringdb.com/.well-known/openid-configuration`.
Using the native `openidconnect` provider type with OIDC well-known URL means
no custom Python code — only DB-stored property mappings for ASN logic.

> **Note:** `authorization_code_auth_method` must be `post_body` (not `basic_auth`)
> because PeeringDB's token endpoint requires `client_secret_post`.

**PeeringDB OAuth2 Configuration:**

| Parameter | Value |
|-----------|-------|
| Authorization URL | `https://auth.peeringdb.com/oauth2/authorize/` |
| Access Token URL | `https://auth.peeringdb.com/oauth2/token/` |
| Profile/Userinfo URL | `https://auth.peeringdb.com/oauth2/userinfo/` |
| OIDC Well-Known URL | `https://auth.peeringdb.com/.well-known/openid-configuration` |
| JWKS URL | `https://auth.peeringdb.com/oauth2/.well-known/jwks.json` |
| Scopes | `openid profile email networks` (openid added by OIDC type) |
| Additional Scopes | `networks` |
| Client type | Confidential |
| Grant type | Authorization code |
| Auth method | `post_body` (`client_secret_post`) |
| Redirect URI | `https://login.sfmix.org/source/oauth/callback/peeringdb/` |

**PeeringDB profile response** (with `networks` scope):
```json
{
  "id": 3,
  "name": "Example User",
  "given_name": "Example",
  "family_name": "User",
  "email": "user@example.com",
  "verified_user": true,
  "verified_email": true,
  "networks": [
    {
      "perms": 15,
      "asn": 64500,
      "name": "Example Network",
      "id": 12345
    }
  ]
}
```

**User identity model:**

One Authentik user per PeeringDB identity (not per ASN). Username is the
user's email address. All administered ASNs become group memberships.

**Authentik configuration details:**

- Source `user_path_template`: `users` (creates internal users, not external)
- `default-source-enrollment-write` stage: `user_type=internal`

**Property mappings (two custom `OAuthSourcePropertyMapping` objects):**

1. **PeeringDB User Mapping** — Username is email, attributes store full
   PeeringDB profile including all administered networks.

   ```python
   pdb_name = info.get("name", "")
   pdb_email = info.get("email", "")
   pdb_sub = info.get("sub", str(info.get("id", "")))
   networks = info.get("networks", [])

   return {
       "username": pdb_email,
       "name": pdb_name,
       "email": pdb_email,
       "attributes": {
           "peeringdb_id": pdb_sub,
           "peeringdb_name": pdb_name,
           "peeringdb_networks": [
               {"asn": n["asn"], "name": n["name"]}
               for n in networks if "asn" in n
           ],
       },
   }
   ```

2. **PeeringDB ASN Group Mapping** — Creates an Authentik group for each ASN
   the PeeringDB user administers (e.g. `as12276`, `as63055`).

   ```python
   networks = info.get("networks", [])
   result = []
   for n in networks:
       asn = n.get("asn")
       if asn:
           result.append("as" + str(asn))
   return result
   ```

**Group sync on login:** Authentik's `GroupUpdateStage` performs a full sync
on each login: it removes all PeeringDB-sourced groups from the user, then
re-adds only the groups returned by the current property mapping. If a user
loses admin access to a network on PeeringDB, they are automatically removed
from the corresponding ASN group on next login. Groups from other sources
(e.g. `authentik Admins`) are unaffected.

**Future:** Cross-reference ASN groups with SFMIX participant list from NetBox
to restrict enrollment to actual IX participants.

**Downstream applications for participants (future):**
- Per-ASN traffic statistics via a dedicated lightweight app (server-side
  PromQL queries against Prometheus, rendered charts only — no direct
  Grafana/Prometheus access for participants, to prevent query manipulation)
- Participant portal (LibreIXP or custom)
- Looking glass (authenticated views)

**Authorization:**
- Participants see only resources related to their own ASN(s)
- Grafana remains admin-only (authentik Admins group)

## Deployment Steps

### Phase 1: VM Bootstrap & Network — DONE

1. [x] VM 105 running on `pve01.scl04.sfmix.org`
2. [x] Public IPs: `192.33.255.71` / `2620:11a:b000:110::71`
3. [x] DNS: `login.sfmix.org` A + AAAA records
4. [x] SSH access verified
5. [x] Base `sfmix_server` role applied (users, firewall, Docker, sysctl)

### Phase 2: Authentik Deployment — DONE

1. [x] Secrets vault-encrypted in `group_vars/login.yml`
2. [x] Nginx TLS termination with Let's Encrypt (certbot, auto-renew)
3. [x] Deployed via `ansible-playbook deploy_login.playbook.yml`
4. [x] Admin user bootstrapped via `ak create_recovery_key`
5. [x] Brand domain set to `login.sfmix.org` via API

### Phase 3: PeeringDB Participant Federation — DONE

1. [x] OAuth2 app registered at PeeringDB under SFMIX org (id 340)
   - Client ID: `1yl8JKUEMKL6JQ8sYRwiVUzi4CsjoBUUCzXei84K`
   - Client type: Confidential, Authorization code grant
   - Redirect URI: `https://login.sfmix.org/source/oauth/callback/peeringdb/`
2. [x] PeeringDB configured as OAuth Source in Authentik
   - Provider type: `openidconnect` (native OIDC with discovery URL)
   - Auth method: `post_body` (`client_secret_post`)
   - Additional scopes: `networks` (OIDC type adds `openid profile email`)
   - OIDC well-known: `https://auth.peeringdb.com/.well-known/openid-configuration`
   - Source promoted to login page identification stage
   - `group_matching_mode`: `identifier`
3. [x] Custom property mappings created for ASN user/group mapping
4. [x] End-to-end PeeringDB login flow tested and working
5. [ ] Create OIDC provider(s) for participant-facing applications

### Phase 4: Admin SSO — DONE

1. [x] GitHub OAuth App created under sfmix org
   - Client ID: `Ov23liaNukEQ6zEzsem9`
   - Callback URL: `https://login.sfmix.org/source/oauth/callback/github/`
2. [x] GitHub configured as OAuth Source in Authentik
   - Provider type: `github` (built-in)
   - Additional scopes: `read:org`
   - `group_matching_mode`: `name_link` (links to existing `authentik Admins`)
3. [x] GitHub team `sfmix/ix-administrators` maps to `authentik Admins` group
4. [x] Session duration set to 8 hours (forces re-evaluation of group membership)
5. [x] Both login flows tested end-to-end
6. [x] Grafana OIDC provider created, access restricted to authentik Admins
7. [ ] Create OIDC/SAML providers for remaining admin apps (NetBox, LibreNMS, etc.)

## Security Considerations

- All secrets (DB password, secret key, SMTP credentials, OAuth client secrets) stored in Ansible Vault
- TLS required — no plain HTTP (redirect 80→443)
- Authentik admin interface restricted to `ixp_admin_source_subnets` via nginx or Authentik policy
- PeeringDB source: only `verified_user: true` accounts should be allowed to enroll
- Rate limiting on login endpoints
- TOTP/WebAuthn MFA encouraged for admin accounts

## Network Issue: VXLAN MTU / MSS Clamping

During deployment, Docker image pulls from `ghcr.io` failed with TLS handshake
timeouts. Root cause: asymmetric routing through a VXLAN tunnel (MTU 1400) on
`br110` between `edge-gw.sfo02` and `edge-gw.fmt01`.

- Outbound traffic from VM exits via Nokia transit at sfo02 (`eth4.1402`)
- Return traffic arrives at fmt01, crosses `vxlan110` (MTU 1400) to reach sfo02
- Packets >1400 bytes silently dropped at L2 bridge (no ICMP frag-needed)

**Fix:** TCP MSS clamping on `br110` at both edge-gws (persisted in VyOS config):
```
set interfaces bridge br110 ip adjust-mss 1360
set interfaces bridge br110 ipv6 adjust-mss 1340
```

## Open Questions

- [ ] Should admin login also support PeeringDB (some admins may have PeeringDB accounts)?
- [ ] Which SMTP relay to use? (`smtp.gmail.com` is in the current config — is there a dedicated relay?)
- [ ] Should we integrate with Teleport as well, or keep them separate?
- [ ] Should enrollment be restricted to ASNs that are actual SFMIX participants?
