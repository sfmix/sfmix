# Looking Glass — Remaining Work

## Bugs / Polish

### P3: CLI commands target all devices by default
- Commands in telnet/SSH fan out to every device unconditionally
- Should default to a single device (or current context), with an explicit `--all` / `all` option to fan out

### Nokia SR-OS: enable `| as-json` for `looking-glass` user
- The `| as-json` pipe and `environment` command are not permitted for the `looking-glass` user
- Likely fix: `configure system management-interface cli md-cli environment output-format json` in user profile

---

## Future Work

### Switch to native Authentik DCR when available

Authentik doesn't support Dynamic Client Registration (RFC 7591) as of 2026.
Track: https://github.com/goauthentik/authentik/issues/8751

Current workaround: lg-http acts as an OAuth authorization server proxy (`/.well-known/oauth-authorization-server`, `/oauth/register`).

**When DCR lands:**
1. Remove `GET /.well-known/oauth-authorization-server` and `POST /oauth/register` from `lg-http/src/rest.rs`
2. Remove `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `mcp_client_id` from `HttpState`/`OidcConfig`
3. Update protected resource metadata: `authorization_servers: [authorization_server]` (direct Authentik URL)
4. Remove `looking_glass_oidc_authorization_endpoint` / `looking_glass_oidc_mcp_client_id` from Ansible inventory
5. Remove `allowed_redirect_uris` localhost regex from `authentik_provider_oauth2.looking_glass` in Terraform
