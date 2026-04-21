# Looking Glass — Remaining Work

## Split Binary Architecture
Deployed and running on alice.sfmix.org in split mode (lg-server + lg-cli + lg-http).
Monolith code removed from Ansible; only split mode is supported.

**Deployment topology:**
- lg-server binds to `127.0.0.1:9090` (RPC, internal only)
- lg-cli binds to `0.0.0.0:2023` (telnet, public)
- lg-http binds to `127.0.0.1:8080` (REST+MCP, behind nginx)
- nginx on alice.sfmix.org terminates TLS for `lg-ng.sfmix.org` → proxies to lg-http
- DNS: `lg-ng.sfmix.org` CNAME → `alice.sfmix.org`
- Separate certbot cert for lg-ng.sfmix.org (SNI-based vhost selection)

---

## Bugs / Polish

### ~~P1: Device header uses Unicode box-drawing in Plain mode~~ ✓
- Fixed: Plain mode now uses `+--- hostname ---+` ASCII chars
- Rich/Color modes unchanged (Unicode box drawing + dimmed ANSI)

### P3: CLI commands target all devices by default
- Commands in telnet/SSH fan out to every device unconditionally
- Should default to a single device (or current context), with an explicit `--all` / `all` option to fan out
- Fanning out to all devices should be opt-in, not the default

### ~~P2: Nokia SR-OS command timeouts~~ ✓ (partial)
**Fixed:**
- Added `command_timeout_secs` to `DeviceConfig` (default 15s)
- Fixed russh `inactivity_timeout` to use `command_timeout_secs` (was hard-coded 30s)
- Added `@device` syntax for targeting specific devices (e.g. `show int @switch01`)

**Root cause discovered:**
- Device is SR-OS 25.10.R1 (MD-CLI capable)
- The `| as-json` pipe is **not enabled** for the `looking-glass` user
- Available pipes: `count`, `match`, `no-more`, `repeat`, `reverse-dns` — no `as-json`
- The `looking-glass` user also lacks `environment` command permissions

**Device config needed:**
- Enable JSON output for the `looking-glass` user profile
- Likely: `configure system management-interface cli md-cli environment output-format json`
- Or enable in user profile settings

---

## Future Work

### Switch to native Authentik DCR when available

**Context:** Authentik doesn't support Dynamic Client Registration (RFC 7591) as of 2026.
See: https://github.com/goauthentik/authentik/issues/8751

**Current workaround:** lg-http acts as an OAuth authorization server proxy:
- `GET /.well-known/oauth-authorization-server` — proxies Authentik's real endpoints + adds `registration_endpoint`
- `POST /oauth/register` — returns the shared `looking-glass` public `client_id`
- Protected resource metadata advertises `https://lg-ng.sfmix.org` as the authorization server

**When Authentik adds DCR support:**
1. Remove `GET /.well-known/oauth-authorization-server` from `lg-http/src/rest.rs`
2. Remove `POST /oauth/register` from `lg-http/src/rest.rs`
3. Remove `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `mcp_client_id` fields from `HttpState` and `OidcConfig`
4. Update protected resource metadata handler to advertise Authentik directly:
   - Change `authorization_servers: [resource_url]` back to `authorization_servers: [authorization_server]`
   - Re-add `authorization_server` field to `HttpState`
5. Remove `looking_glass_oidc_authorization_endpoint` and `looking_glass_oidc_mcp_client_id` from Ansible inventory
6. Remove the `allowed_redirect_uris` localhost regex from `authentik_provider_oauth2.looking_glass` in Terraform (Authentik's DCR will register the redirect URI dynamically instead)
7. Monitor https://github.com/goauthentik/authentik/issues/8751 for upstream progress

---

## Features

### ~~lg-cli SSH frontend adaptation~~ ✓
- Adapted the monolith SSH handler to use `ServiceContext` + RPC in `lg-cli/src/main.rs`
- Full SSH server with certificate auth, OIDC device flow, and agent cert injection

**Auth architecture:**
- OIDC device flow (`login` command) runs entirely in lg-cli
- SSH CA cert signing happens in lg-cli (it holds the CA private key)
- Agent cert injection stays in lg-cli (it has the SSH connection)
- lg-server trusts authenticated RPC requests — edge daemons (lg-cli, lg-http) are responsible for identity verification
- This keeps secrets (CA key, OIDC client) at the edge and simplifies the RPC protocol

### ~~CI: build --workspace in release workflow~~ ✓
- Added `--workspace` flag to `.github/workflows/looking-glass.yml`

### ~~Ansible: service_tokens support in lg-http template~~ ✓
- Already present in `lg-http.yml.j2` (lines 31-34, `looking_glass_service_tokens | default([])`)

### Production cutover checklist
- [x] Deploy DNS: `lg-ng.sfmix.org` CNAME added
- [x] Certbot cert for lg-ng.sfmix.org created
- [x] Nginx vhost configured (SNI-based)
- [x] Split binaries deployed (lg-server, lg-cli, lg-http)
- [x] `looking_glass_http_enabled: true` set
- [x] `looking_glass_http_bind: "127.0.0.1"` set (behind nginx)
- [x] All three services active
- [x] Smoke test REST (https://lg-ng.sfmix.org/api/v1/)
- [x] Smoke test MCP (https://lg-ng.sfmix.org/mcp/sse)
- [x] Smoke test telnet (port 2023)
- [x] Smoke test SSH (port 2222) with OIDC login + cert injection
