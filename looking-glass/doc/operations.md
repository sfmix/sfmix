# Operations Guide

Setup, configuration, deployment, and authentication for the looking glass.

## Configuration Reference

Configuration is a single YAML file. See [`config/example.yml`](../config/example.yml) for a complete annotated example.

### `service` (required)

```yaml
service:
  name: "SFMIX Looking Glass"     # Display name shown in banners
  operator: "SFMIX"               # Operator name (optional)
  operator_url: "https://sfmix.org"  # Operator URL (optional)
  peeringdb_ix_id: 60             # PeeringDB IX ID (optional)
```

### `site` (required)

```yaml
site:
  name: "sfo02"                        # Site identifier
  display_name: "200 Paul, San Francisco"  # Human-readable (optional)
```

### `listen` (required)

```yaml
listen:
  telnet:
    enabled: true          # default: true
    bind: "[::]:23"        # default: [::]:23
  ssh:
    enabled: true          # default: true
    bind: "[::]:2222"      # default: [::]:2222
    host_key: "/etc/looking-glass/ssh_host_ed25519_key"  # required
  mcp:
    enabled: true          # default: true
    bind: "[::]:8080"      # default: [::]:8080
    transport: "sse"       # default: "sse"
```

### `auth` (optional)

Required for SSH certificate authentication and MCP identity extraction.

```yaml
auth:
  oidc:
    issuer: "https://login.sfmix.org/application/o/looking-glass/"
    client_id: "looking-glass"
    scopes: ["openid", "profile", "email", "groups"]
    group_prefix: "as"               # default: "as" — prefix for ASN group names
    admin_group: "IX Administrators"  # default: "IX Administrators"
```

The `group_prefix` determines how ASN ownership is extracted from OIDC group claims. With `group_prefix: "as"`, a group named `as64500` grants the user ownership of AS64500.

### `devices` (required)

```yaml
devices:
  - name: "switch01.sfo02.sfmix.org"
    platform: arista_eos          # arista_eos | nokia_sros
    host: "switch01.sfo02.sfmix.org"
    port: 22                      # default: 22
    username: "looking-glass"
    auth_method: ssh_key          # default: ssh_key (ssh_key | password)
    ssh_key: "/etc/looking-glass/device_key"  # path to private key
    host_key_fingerprint: "SHA256:..."  # optional — pin device host key
```

**`host_key_fingerprint`**: If set, the looking glass verifies the device's SSH host key fingerprint matches this value on every connection. Format is `SHA256:base64...` as output by `ssh-keygen -lf /path/to/key`. If omitted, all host keys are accepted (TOFU model).

Get a device's fingerprint:
```bash
ssh-keygen -lf <(ssh-keyscan -t ed25519 switch01.sfo02.sfmix.org 2>/dev/null)
```

### `rate_limits` (optional)

```yaml
rate_limits:
  global:
    max_concurrent: 10       # max commands in flight across all devices (default: 10)
    commands_per_minute: 60  # (reserved for future use)
  per_device:
    max_concurrent: 2        # max concurrent SSH sessions per device (default: 2)
    commands_per_minute: 20  # (reserved for future use)
  per_user:
    commands_per_minute: 10  # sliding window per user/IP-prefix (default: 10)
```

#### Rate Limit Keys

Rate limiting is identity-aware. The key used for per-user CPM depends on the user's authentication state:

| State | Key | Example |
|-------|-----|---------|
| Authenticated (SSH cert, MCP headers) | Email address | `alice@example.com` |
| Anonymous IPv4 | /24 prefix | `net:192.0.2.0/24` |
| Anonymous IPv6 | /56 prefix | `net:2001:db8:abcd:ab00::/56` |

This prevents users from rotating IPs within the same allocation to bypass limits.

### `participants` (optional)

Maps ASNs to their physical ports and BGP sessions for per-ASN access control.

```yaml
participants:
  source: file
  file: "/etc/looking-glass/participants.yml"
```

#### Participants File Format

```yaml
# /etc/looking-glass/participants.yml
participants:
  - asn: 64500
    name: "Example Networks"
    ports:
      - device: "switch01.sfo02"
        interface: "Ethernet3/1"
    sessions:
      - device: "switch01.sfo02"
        neighbor: "192.0.2.1"
        neighbor_v6: "2001:db8::1"

  - asn: 64501
    name: "Another Peer"
    ports:
      - device: "switch01.sfo02"
        interface: "Ethernet3/2"
      - device: "switch02.fmt01"
        interface: "Ethernet3/5"
    sessions:
      - device: "switch01.sfo02"
        neighbor: "192.0.2.2"
```

### `policies` (optional)

```yaml
policies:
  file: "/etc/looking-glass/policies.yml"
```

If omitted, a sensible default policy is used. See [Policy Engine](#policy-engine) below.

## Authentication

### SSH (opkssh + OIDC)

The SSH frontend authenticates users via OpenSSH certificates issued by [opkssh](https://github.com/openpubkey/opkssh). The certificate's extensions contain OIDC claims:

- **`email`** — user's email address
- **`groups`** — comma-separated group memberships (e.g. `as64500,IX Administrators`)

Groups prefixed with the configured `group_prefix` (default `as`) are parsed as ASN ownership claims. The `admin_group` (default `IX Administrators`) grants full access.

Generate a host key for the SSH frontend:
```bash
ssh-keygen -t ed25519 -f /etc/looking-glass/ssh_host_ed25519_key -N ""
```

### MCP (reverse proxy + OIDC)

The MCP frontend extracts identity from headers set by a reverse proxy (e.g. nginx + Authentik):

- **`X-Forwarded-Email`** — authenticated user's email
- **`X-Forwarded-Groups`** — comma-separated group memberships
- **`X-Forwarded-For`** — client IP (for anonymous rate limiting)

Example nginx configuration:
```nginx
location /mcp {
    auth_request /outpost.goauthentik.io/auth/nginx;
    # ... authentik auth_request config ...

    proxy_set_header X-Forwarded-Email $authentik_email;
    proxy_set_header X-Forwarded-Groups $authentik_groups;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_pass http://127.0.0.1:8080;
}
```

If no auth headers are present, the MCP frontend treats the request as anonymous.

## Policy Engine

The policy engine uses first-match evaluation on a list of rules. Each rule has optional match criteria and an allow list of command patterns.

### Default Policy

When no policy file is configured, the built-in default policy provides:

1. **Authenticated users**: all `show`, `ping`, `traceroute` commands (port ownership enforced separately)
2. **Public users**: broad show access, ping, traceroute (participant port queries blocked by ownership check)
3. **Default deny**: anything not matched is denied

### Custom Policy File

```yaml
# /etc/looking-glass/policies.yml
policies:
  - name: "admin-full-access"
    match:
      groups: ["IX Administrators"]
    allow:
      - "show *"
      - "ping *"
      - "traceroute *"

  - name: "authenticated"
    match:
      authenticated: true
    allow:
      - "show *"
      - "ping *"
      - "traceroute *"

  - name: "public-read-only"
    match:
      authenticated: false
    allow:
      - "show interfaces status"
      - "show interface *"
      - "show optics"
      - "show optics *"
      - "show ip bgp summary"
      - "show bgp *"
      - "show lldp neighbors"
      - "show arp"
      - "show ipv6 neighbors"
      - "show participants"
      - "ping *"
      - "traceroute *"

  - name: "default-deny"
    deny: true
```

Rules support trailing `*` wildcards. Match criteria:

- **`groups`**: user must be a member of at least one listed group
- **`authenticated`**: `true` or `false` — match on authentication state
- No `match` block: matches everything (use for default-deny)

## Deployment

### Central Instance

The central instance runs on a Linux server with management network access to all devices across all sites. Suitable for `lg.sfmix.org`.

```yaml
# All devices, all sites
devices:
  - name: "switch01.sfo02.sfmix.org"
    # ...
  - name: "switch02.fmt01.sfmix.org"
    # ...
  - name: "cr1.sjc01.transit.sfmix.org"
    # ...
```

### Site-Local Instance

Optional instances on OOB management routers, configured with only local devices. SSH + MCP only (no telnet).

```yaml
listen:
  telnet:
    enabled: false
  ssh:
    enabled: true
    bind: "[::]:2222"
    host_key: "/etc/looking-glass/ssh_host_ed25519_key"
  mcp:
    enabled: true
    bind: "[::]:8080"

devices:
  - name: "switch01.sfo02.sfmix.org"
    # only local device(s)
```

### systemd Service

```ini
[Unit]
Description=IXP Looking Glass
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/looking-glass --config /etc/looking-glass/config.yml
Restart=on-failure
RestartSec=5
User=looking-glass
Group=looking-glass
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

`CAP_NET_BIND_SERVICE` allows binding to port 23 without running as root.

### Build

```bash
# Release build (static musl binary)
cargo build --release --target x86_64-unknown-linux-musl

# Binary at target/x86_64-unknown-linux-musl/release/looking-glass
ls -lh target/x86_64-unknown-linux-musl/release/looking-glass
```

The release profile optimizes for size (`opt-level = "s"`, LTO, strip, single codegen unit).

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `RUST_LOG` | Logging level filter (default: `info`). Set to `debug` for verbose output. |

```bash
RUST_LOG=debug ./looking-glass --config config.yml
```
