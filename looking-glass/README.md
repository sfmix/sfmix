# Looking Glass

A multi-purpose IXP looking glass with Telnet, SSH, and MCP (Model Context Protocol) interfaces. Single static binary, designed for Internet Exchange Point operators.

## Features

- **Telnet frontend** (port 23) — unauthenticated public access
- **SSH frontend** (port 2222) — authenticated via opkssh + OIDC, per-ASN port visibility
- **MCP frontend** (port 8080) — LLM agent access over streamable HTTP
- **Multi-platform backend** — Arista EOS and Nokia SR-OS via SSH
- **Policy engine** — declarative YAML rules, first-match evaluation
- **Rate limiting** — global concurrency, per-device concurrency, per-user sliding window
- **Identity-aware** — per-ASN port access, admin overrides, IP-prefix grouping for anonymous users

## Quick Start

```bash
# Build (static musl binary, ~8 MB stripped)
cargo build --release --target x86_64-unknown-linux-musl

# Configure
cp config/example.yml /etc/looking-glass/config.yml
# Edit config.yml — at minimum set your devices

# Run
./target/release/looking-glass --config /etc/looking-glass/config.yml
```

Default ports: telnet `:23`, SSH `:2222`, MCP `:8080`.

## Architecture

```
┌───────────┐  ┌───────────┐  ┌───────────┐
│  Telnet   │  │    SSH     │  │    MCP    │
│  :23      │  │   :2222    │  │   :8080   │
│ anonymous │  │ OIDC certs │  │ HTTP+auth │
└─────┬─────┘  └─────┬─────┘  └─────┬─────┘
      │              │              │
      └──────┬───────┴──────────────┘
             │
      ┌──────▼──────┐
      │   Command   │   Structured commands (no raw CLI)
      │   Router    │
      └──────┬──────┘
             │
      ┌──────▼──────┐
      │   Policy    │   First-match rules + port ownership checks
      │   Engine    │
      └──────┬──────┘
             │
      ┌──────▼──────┐
      │    Rate     │   Global concurrency + per-user CPM
      │   Limiter   │   + per-device concurrency
      └──────┬──────┘
             │
      ┌──────▼──────┐
      │   Device    │   SSH to network devices
      │    Pool     │   Platform drivers (EOS, SR-OS)
      └─────────────┘
```

### Source Layout

| File | Purpose |
|------|---------|
| `src/main.rs` | Entry point, config loading, server startup |
| `src/config.rs` | YAML config deserialization |
| `src/command.rs` | Structured command types and parser |
| `src/identity.rs` | User identity (anonymous, authenticated, admin) |
| `src/policy.rs` | Policy engine (rules, port ownership, evaluation) |
| `src/ratelimit.rs` | Rate limiter (global semaphore, per-user sliding window, IP prefix grouping) |
| `src/participants.rs` | ASN-to-port/session mapping |
| `src/frontend/telnet.rs` | Telnet server and session handler |
| `src/frontend/ssh.rs` | SSH server with opkssh certificate auth |
| `src/frontend/mcp.rs` | MCP server over streamable HTTP (axum + rmcp) |
| `src/backend/pool.rs` | Device pool with per-device concurrency semaphores |
| `src/backend/driver.rs` | Platform driver trait |
| `src/backend/arista_eos.rs` | Arista EOS CLI translation |
| `src/backend/nokia_sros.rs` | Nokia SR-OS CLI translation |
| `src/backend/ssh.rs` | SSH client for device connections (with host key verification) |

## Configuration Reference

Configuration is a single YAML file. See [`config/example.yml`](config/example.yml) for a complete annotated example.

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

See [Participants File Format](#participants-file-format) below.

### `policies` (optional)

```yaml
policies:
  file: "/etc/looking-glass/policies.yml"
```

If omitted, a sensible default policy is used. See [Policy Engine](#policy-engine) below.

## Commands

All frontends accept the same command set. Commands are parsed into structured form before dispatch — no raw CLI strings are passed to devices.

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `show interfaces status` | Interface summary (name, link state, speed, VLAN) |
| `show interface <port>` | Detailed counters for a specific interface |
| `show optics` | Transceiver DOM optical power levels (all ports) |
| `show optics <port>` | Detailed DOM for a specific port |
| `show ip bgp summary` | BGP IPv4 peer summary |
| `show bgp ipv6 unicast summary` | BGP IPv6 peer summary |
| `show lldp neighbors` | LLDP neighbor table |
| `show arp` | ARP table (IPv4) |
| `show ipv6 neighbors` | IPv6 neighbor discovery table |
| `show mac address-table` | MAC address table |
| `show vxlan vtep` | VXLAN VTEP endpoints |
| `show participants` | List IXP participants (ASN + name) |
| `ping <destination>` | Ping from the looking glass vantage point |
| `traceroute <destination>` | Traceroute from the looking glass vantage point |

Platform drivers translate these into native CLI syntax:

| Structured Command | Arista EOS | Nokia SR-OS |
|-------------------|------------|-------------|
| `show interfaces status` | `show interfaces status` | `show port` |
| `show interface Eth3/1` | `show interfaces Ethernet3/1` | `show port Eth3/1 detail` |
| `show optics` | `show interfaces transceiver` | `show port detail` |
| `show ip bgp summary` | `show ip bgp summary` | `show router bgp summary` |
| `show lldp neighbors` | `show lldp neighbors` | `show system lldp neighbor` |

## Access Tiers

| Tier | Interface | Authentication | Capabilities |
|------|-----------|----------------|--------------|
| **Public** | Telnet, MCP | None | BGP summary, interface status, optics (global), LLDP, ARP/ND, ping, traceroute |
| **Participant** | SSH, MCP | OIDC (PeeringDB/GitHub) | Public + own port details, own port optics |
| **Administrator** | SSH, MCP | OIDC (IX Administrators group) | Full read-only access to all ports |

### Port Ownership

Port-scoped commands (`show interface <port>`, `show optics <port>`) targeting participant-facing interfaces require authentication:

- **Anonymous users** can query infrastructure ports (uplinks, fabric) but not participant ports
- **Authenticated participants** can query their own ports (matched by ASN from OIDC groups)
- **Administrators** (in the `admin_group`) can query any port

Infrastructure ports (not listed in the participants file) are visible to everyone.

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

## Participants File Format

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

## Authentication

### SSH (opkssh + OIDC)

The SSH frontend authenticates users via OpenSSH certificates issued by [opkssh](https://github.com/openpubkey/opkssh). The certificate's extensions contain OIDC claims:

- **`email`** → user's email address
- **`groups`** → comma-separated group memberships (e.g. `as64500,IX Administrators`)

Groups prefixed with the configured `group_prefix` (default `as`) are parsed as ASN ownership claims. The `admin_group` (default `IX Administrators`) grants full access.

Generate a host key for the SSH frontend:
```bash
ssh-keygen -t ed25519 -f /etc/looking-glass/ssh_host_ed25519_key -N ""
```

### MCP (reverse proxy + OIDC)

The MCP frontend extracts identity from headers set by a reverse proxy (e.g. nginx + Authentik):

- **`X-Forwarded-Email`** → authenticated user's email
- **`X-Forwarded-Groups`** → comma-separated group memberships
- **`X-Forwarded-For`** → client IP (for anonymous rate limiting)

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

## Testing

### Unit Tests

```bash
cargo test
```

27 tests covering:
- Command parsing (8 tests)
- Policy evaluation with port ownership (10 tests)
- Rate limiting — per-user CPM, user independence, global concurrency (3 tests)
- IP-to-prefix rate key grouping — IPv4 /24, IPv6 /56 (4 tests)
- Device driver command translation (2 tests)

### Integration Testing with Containerlab

A containerlab topology is provided for testing against real Arista EOS devices:

```bash
cd test/clab
sudo containerlab deploy -t lg-test.clab.yml
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `RUST_LOG` | Logging level filter (default: `info`). Set to `debug` for verbose output. |

```bash
RUST_LOG=debug ./looking-glass --config config.yml
```

## Tech Stack

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `russh` | SSH client (device backend) and server (SSH frontend) |
| `ssh-key` | SSH key types, certificate parsing |
| `rmcp` | MCP server SDK (streamable HTTP) |
| `axum` | HTTP framework (MCP transport, middleware) |
| `clap` | CLI argument parsing |
| `serde` / `serde_yaml` | Configuration and data file parsing |
| `dashmap` | Concurrent per-user rate limit state |
| `tracing` | Structured logging |
| `thiserror` | Error type derivation |

## License

BSD-2-Clause
