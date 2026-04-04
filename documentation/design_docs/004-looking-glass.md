# 004 - Multi-Purpose Looking Glass Service

## Overview

A new open-source looking glass service for IXPs, designed to be generally applicable but deployed for SFMIX. Augments the existing OpenBSD bgplg/bgplgd BGP looking glass at `lg.sfmix.org` with additional query interfaces beyond BGP route lookups:

1. **SSH/Telnet CLI** — interactive text interface for network debugging
2. **MCP (Model Context Protocol) interface** — LLM agent access to IXP state
3. **Device backend** — rate-limited, policy-controlled interaction with network devices
4. **Identity-aware access control** — unauthenticated public queries and authenticated per-ASN views via built-in OIDC device authorization flow (Authentik)

### Goals

- **Open source and general-purpose**: usable by any IXP, not hard-coded to SFMIX
- **Compact and portable**: single statically-linked Rust binary, minimal resource footprint, suitable for deployment on embedded/router platforms
- **Centralized**: primary deployment model is a single central instance reaching all devices over the management network
- **Platform-flexible**: device interaction via textual CLI (SSH/NETCONF), not vendor-specific APIs
- **Defense in depth**: policy engine controls what commands reach devices, per-user and per-role
- **Minimal device load**: global rate limiter prevents query floods from overwhelming network gear
- **Two access tiers**: public (unauthenticated) and participant (authenticated by ASN)

### Non-Goals

- Replace Alice LG / route server looking glass (those cover BGP RIB browsing)
- Full network automation / config push (read-only queries only)
- Replace Grafana/Prometheus for time-series monitoring

## Existing Infrastructure

| Component            | Current State                                                           |
|----------------------|-------------------------------------------------------------------------|
| `lg.sfmix.org`       | OpenBSD bgplg + bgplgd (BGP route viewer, ping, traceroute)             |
| `alice.sfmix.org`    | Alice LG route browser (birdwatcher backend on route servers)           |
| Peering switches     | Arista EOS (DCS-7280SR series), eAPI enabled                            |
| Transit/core routers | Nokia SR-OS                                                             |
| Management routers   | VyOS (OOB mgmt routers + management edge gateways like `edge-gw.sfo02`) |
| SSO                  | Authentik at `login.sfmix.org`, PeeringDB federation, `as{ASN}` groups  |

The existing bgplg provides BGP route lookups, ping, and traceroute — and will continue to do so. The new looking glass complements both bgplg and Alice LG by providing operational queries against the peering switches and core routers that neither covers today — interface stats, MAC tables, ARP/ND tables, LLDP, VXLAN state, etc.

## Architecture

### Deployment Model

The looking glass is a single compact Rust binary that can run anywhere with
management network reachability to the target devices. Two deployment modes:

**Central instance (`lg.sfmix.org`)** — the primary, user-facing deployment.
This is the service that participants, the public, and LLM agents connect to. It
is configured with devices across *all* sites, reaching them over the
management network (see design doc 001).

**Site-local instances (optional)** — lightweight instances deployed directly on
OOB management routers at individual sites. These are primarily for IX
administrators doing site-level debugging, configured with only the local
devices at that site. Same binary, smaller config.

```
  Users (Telnet :23, SSH :2222, MCP via HTTPS :443)
        │
        ▼
  ┌─── lg.sfmix.org ──────────────────────┐
  │                                        │
  │  Frontends → Command Router            │
  │                  │                     │
  │           Policy Engine                │
  │                  │                     │
  │            Rate Limiter                │
  │                  │                     │
  │          Device Backend Pool           │
  └──────────────────┼─────────────────────┘
                     │ SSH
                     ▼
            Management Network
          ┌─────┬──────┬──────┐
          ▼     ▼      ▼      ▼
      switch01  switch02   cr1     ...
       (EOS)    (EOS)    (SR-OS)
```

### Instance Configuration

Both the central and site-local instances use the same binary and config format.
The difference is just scope:

|                         | Central (`lg.sfmix.org`)         | Site-local (admin)       |
|-------------------------|----------------------------------|--------------------------|
| **Audience**            | Public, participants, LLM agents | IX administrators        |
| **Devices**             | All devices across all sites     | Only devices at one site |
| **Network path**        | Management network               | Local OOB mgmt LAN       |
| **Frontends**           | Telnet, SSH, MCP                 | SSH, MCP                 |
| **DNS**                 | `lg.sfmix.org`                   | N/A (mgmt network IP)    |
| **Participant mapping** | All sites                        | Local site only          |

## Components

### 1. Frontend Interfaces

#### 1a. Telnet Server (Public, Unauthenticated)

Classic IXP looking glass experience. Binds on port 23 (or configurable). Presents a simple text menu or accepts direct commands. No authentication — all queries are restricted to the public command set.

Supported public commands:
- `show interfaces status` (summary only: port name, status, speed — no counters)
- `show interface <port>` — detailed counters/errors for **core/infrastructure ports** (uplinks, inter-switch links, etc.)
- `show optics <port>` — detailed DOM for core/infrastructure ports
- `show ip bgp summary` / `show bgp ipv6 unicast summary`
- `show lldp neighbors`
- `ping <destination>` / `traceroute <destination>` (from the LG host, not from devices)
- `show arp` / `show ipv6 neighbors` (aggregated, without per-port attribution)
- `show optics` — DOM (digital optical monitoring): Tx/Rx power, laser bias, temperature, voltage
- `show participants` (IXF member list)
- `help`

Core/infrastructure ports (uplinks, fabric links, router-facing ports) are always visible to all users. Participant-facing ports are restricted to the owning ASN unless the user is an admin.

#### 1b. SSH Server (Authenticated)

Binds on port 2222 (or configurable). The looking glass is its own SSH Certificate Authority and OIDC client, using the **OIDC device authorization flow** (RFC 8628):

- User connects with `ssh -A -p 2222 lg.sfmix.org` (agent forwarding recommended)
- Anonymous session starts with public-tier access
- User types `login` to initiate authentication
- LG starts OIDC device authorization flow with Authentik, displays verification URL and user code
- User opens URL in browser, enters code, authenticates via PeeringDB or GitHub
- LG polls token endpoint, verifies JWT signature against Authentik JWKS
- On success: generates ephemeral Ed25519 keypair, signs an SSH user certificate embedding OIDC claims (email, groups) as extensions, with 12-hour lifetime
- If SSH agent is forwarded: injects the certificate into the user's agent for fast re-authentication on subsequent connections
- If no agent: session-only authentication (must re-login next session)
- On reconnection with a valid certificate: LG verifies cert against its own CA key, extracts identity from extensions, grants authenticated access immediately

Authenticated users get the full public command set **plus**:
- `show interface <port>` — detailed counters/errors for **their own participant ports** (matched by ASN ↔ port mapping from NetBox or config)
- `show mac address-table interface <port>` — MAC table for their own ports
- `show arp interface <port>` / `show ipv6 neighbors interface <port>`
- `show ip bgp neighbor <addr> ...` — BGP neighbor detail for their own sessions
- `show optics <port>` — detailed DOM for their own participant ports
- `show vxlan vtep` and tunnel state for their own cross-connects (if applicable)

IX Administrators (`IX Administrators` group) get unrestricted read-only access to all show commands.

#### 1c. MCP Interface (LLM Agent Access)

Exposes the looking glass as an MCP server, enabling LLM agents (e.g. Claude, Cursor, custom tools) to query IXP state programmatically.

**Transport**: SSE (Server-Sent Events) over HTTP, or stdio for local use.

**Two modes:**
- **Public (unauthenticated)**: same command set as telnet
- **Authenticated**: Bearer token (OIDC access token from `login.sfmix.org`), same enriched command set as SSH

**MCP Tools exposed:**
- `show_interfaces` — list interfaces with status
- `show_bgp_summary` — BGP peer summary (address family selectable)
- `show_participants` — IXF member list
- `show_interface_detail` — detailed counters (authenticated, own ports only)
- `show_bgp_neighbor` — BGP neighbor detail (authenticated, own sessions only)
- `show_arp_table` / `show_nd_table` — ARP/ND entries
- `show_mac_table` — MAC address table (scoped by auth)
- `ping` / `traceroute` — network reachability test
- `show_lldp` — LLDP neighbor information
- `show_optics` — DOM / transceiver optical levels

**MCP Resources exposed:**
- `ixp://participants` — IXF-format participant list
- `ixp://prefixes` — peering LAN prefixes
- `ixp://status` — IXP operational status summary

### 2. Command Router

Central dispatcher that:
1. Receives a parsed command + caller identity (anonymous, or authenticated with ASN list + groups)
2. Consults the **policy engine** to determine if the command is allowed for this caller
3. If allowed, submits the command to the **rate limiter** queue
4. Returns the result (or a rejection/rate-limit message)

Commands are represented as structured objects, not raw CLI strings. This prevents injection and allows policy evaluation before any device interaction.

```
Command {
    verb: "show",
    resource: "interface",
    target: "Ethernet3/1",
    device: "switch01.sfo02.sfmix.org",  // optional, can be inferred
    address_family: "ipv4",              // optional
    caller: Identity { anonymous: false, asns: [64500], groups: ["as64500"], email: "user@example.com" },
}
```

### 3. Policy Engine

A declarative policy system that maps `(command, identity) → allow | deny`.

Policy rules are defined in a configuration file (YAML or TOML). The engine is evaluated top-to-bottom, first match wins.

Example policy structure:

```yaml
policies:
  # IX Administrators: full read-only access
  - name: admin-full-access
    match:
      groups: ["IX Administrators"]
    allow:
      - "show *"

  # Authenticated participants: own ports + public
  - name: participant-own-ports
    match:
      authenticated: true
    allow:
      - "show interface {own_ports}"
      - "show mac address-table interface {own_ports}"
      - "show arp interface {own_ports}"
      - "show ipv6 neighbors interface {own_ports}"
      - "show ip bgp neighbor {own_sessions}"

  # Public: limited set
  - name: public
    match:
      authenticated: false
    allow:
      - "show interfaces status"
      - "show ip bgp summary"
      - "show bgp ipv6 unicast summary"
      - "show lldp neighbors"
      - "show participants"
      - "ping"
      - "traceroute"

  # Default deny
  - name: default-deny
    deny: true
```

**Port-to-ASN mapping** is loaded from configuration (sourced from NetBox or a static YAML file) and provides the `{own_ports}` and `{own_sessions}` expansions used by the policy engine.

### 4. Rate Limiter

Protects network devices from excessive queries.

- **Global rate limit**: max N concurrent device sessions, M commands per minute across all users
- **Per-device rate limit**: max concurrent sessions and commands/minute per device
- **Per-user rate limit**: max commands/minute per authenticated user (or per source IP for anonymous)
- **Queue with timeout**: commands that can't be dispatched immediately are queued with a configurable timeout (e.g. 10s)

Implementation: token bucket per dimension (global, per-device, per-user), with a bounded async queue.

### 5. Device Backend

Manages connections to network devices and translates structured commands into platform-specific CLI.

#### Design Principles

- **Textual interface**: all device interaction is via SSH CLI (not vendor APIs), making it easy to add new platforms
- **Connection pooling**: maintain a small pool of persistent SSH sessions per device to avoid connection overhead
- **Read-only**: the backend never sends configuration commands; this is enforced both in the policy engine and at the device backend level (e.g. privilege level restrictions, read-only user accounts on devices)
- **Timeout**: all device commands have a hard timeout (e.g. 30s) to prevent hung sessions

#### Platform Drivers

Each platform driver translates structured `Command` objects into the platform's native CLI syntax and parses the text output into structured data (where feasible).

**Arista EOS driver:**
- Connect via SSH (or optionally eAPI JSON-RPC for structured output)
- Commands like `show interfaces status`, `show ip bgp summary`, `show mac address-table`, etc.
- Use a read-only user account (e.g. `looking-glass` with `privilege 1` or a role restricting to `show` commands)

**Nokia SR-OS driver:**
- Connect via SSH
- Classic CLI or MD-CLI depending on device configuration
- Commands like `show port`, `show router bgp summary`, `show service sap-using`, etc.
- Read-only user profile

**Generic driver (future):**
- Pluggable driver interface for other platforms (Juniper, Cisco, etc.)
- Contributed by the community or other IXPs

#### Command Translation Table (examples)

| Structured Command             | Arista EOS                           | Nokia SR-OS (classic)                 |
|--------------------------------|--------------------------------------|---------------------------------------|
| `show interfaces status`       | `show interfaces status`             | `show port`                           |
| `show interface <intf> detail` | `show interfaces <intf>`             | `show port <port> detail`             |
| `show bgp summary (ipv4)`      | `show ip bgp summary`                | `show router bgp summary`             |
| `show bgp summary (ipv6)`      | `show bgp ipv6 unicast summary`      | `show router bgp summary family ipv6` |
| `show mac address-table`       | `show mac address-table`             | `show service fdb-mac`                |
| `show arp`                     | `show arp`                           | `show router arp`                     |
| `show ipv6 neighbors`          | `show ipv6 neighbors`                | `show router neighbor`                |
| `show lldp neighbors`          | `show lldp neighbors`                | `show system lldp neighbor`           |
| `show optics`                  | `show interfaces transceiver`        | `show port detail` (DOM section)      |
| `show optics <intf>`           | `show interfaces <intf> transceiver` | `show port <port> optical`            |

### 6. Authentication

#### Built-in SSH CA + OIDC Device Authorization Flow

The looking glass is its own SSH Certificate Authority and OIDC client. No external tools (opkssh, etc.) are required on the client side — users need only a standard SSH client.

**First-time authentication flow:**
1. User connects: `ssh -A -p 2222 lg.sfmix.org` (agent forwarding recommended)
2. Anonymous session starts with public-tier access
3. User types `login`
4. LG initiates OIDC device authorization flow (RFC 8628) with Authentik
5. LG displays verification URL (`https://login.sfmix.org/application/o/device/`) and user code
6. User opens URL in browser, enters code, authenticates via PeeringDB or GitHub
7. LG polls Authentik token endpoint until approval or timeout
8. LG verifies the ID token JWT signature against Authentik's JWKS
9. LG extracts claims: `email`, `groups` (including `as{ASN}` from PeeringDB federation)
10. LG generates an ephemeral Ed25519 keypair and signs an SSH user certificate:
    - Embeds `email` and `groups` (comma-separated) as certificate extensions
    - Principal: `looking-glass`
    - Lifetime: 12 hours
    - Signed by LG's CA key
11. If SSH agent is forwarded: injects the key+certificate into the user's agent with a 12-hour lifetime constraint
12. Session identity is upgraded to authenticated

**Subsequent connections (within 12 hours):**
1. User connects: `ssh -A -p 2222 lg.sfmix.org`
2. SSH client offers the certificate from the agent
3. LG verifies certificate signature against its own CA key and checks validity period
4. LG extracts identity from certificate extensions
5. Session starts immediately with authenticated access — no browser interaction needed

**Telnet login:**
The `login` command is also available on telnet. It performs the same OIDC device flow but cannot inject certificates (no SSH agent). Authentication is session-only.

**Authentik OIDC provider configuration:**

| Parameter              | Value                                                    |
|------------------------|----------------------------------------------------------|
| Client ID              | `looking-glass`                                          |
| Authorization flow     | Device code (RFC 8628)                                   |
| Device auth endpoint   | `https://login.sfmix.org/application/o/device/`          |
| Token endpoint         | `https://login.sfmix.org/application/o/token/`           |
| JWKS URI               | `https://login.sfmix.org/application/o/looking-glass/jwks/` |
| Scopes                 | `openid profile email groups`                            |
| Policy                 | None (all authenticated users allowed)                   |

The `groups` scope returns all Authentik group memberships, including `as{ASN}` groups from PeeringDB federation (see design doc 003).

**CA key management:**
- CA private key stored at `/etc/looking-glass/ca_ed25519_key`
- Generated once, deployed via Ansible Vault
- Public key fingerprint logged at startup for verification

#### OIDC Bearer Token for MCP Access

The MCP HTTP/SSE endpoint accepts an `Authorization: Bearer <token>` header. The token is an OIDC access token issued by `login.sfmix.org`. The looking glass validates the token by verifying the JWT signature against the Authentik JWKS.

### 7. Configuration

The service is configured via a single YAML (or TOML) file. Example:

```yaml
# looking-glass.yml

service:
  name: "SFMIX Looking Glass"
  operator: "SFMIX"
  operator_url: "https://sfmix.org"
  peeringdb_ix_id: 60

site:
  name: "sfo02"               # site identifier, used in banners and MCP responses
  display_name: "200 Paul, San Francisco"  # human-readable

listen:
  telnet:
    enabled: true
    bind: "[::]:23"
  ssh:
    enabled: true
    bind: "[::]:2222"
    host_key: "/etc/looking-glass/ssh_host_ed25519_key"
    ca_key: "/etc/looking-glass/ca_ed25519_key"
  mcp:
    enabled: true
    bind: "127.0.0.1:8080"   # behind nginx reverse proxy
    transport: "sse"          # "sse" or "stdio"

auth:
  oidc:
    issuer: "https://login.sfmix.org/application/o/looking-glass/"
    client_id: "looking-glass"
    device_auth_endpoint: "https://login.sfmix.org/application/o/device/"
    token_endpoint: "https://login.sfmix.org/application/o/token/"
    jwks_uri: "https://login.sfmix.org/application/o/looking-glass/jwks/"
    cert_lifetime_secs: 43200   # 12 hours
    scopes: ["openid", "profile", "email", "groups"]
    group_prefix: "as"   # groups matching "as{number}" are treated as ASN claims
    admin_group: "IX Administrators"

devices:
  - name: "switch01.sfo02.sfmix.org"
    platform: "arista_eos"
    host: "switch01.sfo02.sfmix.org"
    port: 22
    username: "looking-glass"
    # password or key from environment or vault
    auth_method: "ssh_key"
    ssh_key: "/etc/looking-glass/device_key"

  - name: "cr1.sjc01.transit.sfmix.org"
    platform: "nokia_sros"
    host: "cr1.sjc01.transit.sfmix.org"
    port: 22
    username: "looking-glass"
    auth_method: "ssh_key"
    ssh_key: "/etc/looking-glass/device_key"

rate_limits:
  global:
    max_concurrent: 10
    commands_per_minute: 60
  per_device:
    max_concurrent: 2
    commands_per_minute: 20
  per_user:
    commands_per_minute: 10

# Port-to-ASN mapping (can also be loaded from NetBox API)
participants:
  source: "file"            # "file" or "netbox"
  file: "/etc/looking-glass/participants.yml"
  # netbox:
  #   url: "https://netbox.sfmix.org"
  #   token_env: "LG_NETBOX_TOKEN"

policies:
  # Inline or file reference
  file: "/etc/looking-glass/policies.yml"
```

Participant port mapping file example:

```yaml
# participants.yml
participants:
  - asn: 64500
    name: "Example Network"
    ports:
      - device: "switch01.sfo02.sfmix.org"
        interface: "Ethernet3/1"
      - device: "switch02.fmt01.sfmix.org"
        interface: "Ethernet3/1"
    sessions:
      - device: "switch01.sfo02.sfmix.org"    # or route server
        neighbor: "206.197.187.10"
        neighbor_v6: "2001:504:30::ba01:6450:0"
```

## Technology Choices

| Decision        | Choice                         | Rationale                                                                                                                                      |
|-----------------|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| **Language**    | Rust                           | Performance, safety, good async ecosystem (tokio), strong SSH libraries, single static binary. Consistent with btest-rs precedent in the repo. |
| **Linking**     | Static (musl)                  | `x86_64-unknown-linux-musl` target for fully static binary with zero runtime dependencies. Runs on any Linux (VyOS, Debian, Alpine, etc.).     |
| **SSH library** | `russh`                        | Mature async SSH server and client implementation for Rust                                                                                     |
| **Telnet**      | `tokio::net::TcpListener`      | Simple line-oriented protocol, no library needed                                                                                               |
| **MCP**         | `rmcp` or hand-rolled SSE      | MCP SDK for Rust, or simple JSON-RPC over SSE                                                                                                  |
| **Config**      | `serde` + YAML                 | Standard Rust config parsing                                                                                                                   |
| **Deployment**  | Single static binary + systemd | `scp` binary to mgmt router, drop config, enable service. Ansible role for automation.                                                         |

### Binary Size Budget

Target: **< 10 MB** stripped static binary. Rust with musl + LTO + `opt-level = "s"` + `strip = true` should achieve this comfortably. This is important since the binary will live on management routers which may have limited disk.

## Project Structure

```
looking-glass/                    # standalone crate, potentially its own repo later
├── Cargo.toml
├── LICENSE                       # BSD-2-Clause (consistent with btest-rs)
├── README.md
├── src/
│   ├── main.rs                   # CLI entry point, config loading, server startup
│   ├── config.rs                 # Configuration types and parsing
│   ├── identity.rs               # Identity/auth types (anonymous, authenticated, admin)
│   ├── policy.rs                 # Policy engine
│   ├── command.rs                # Structured command types and routing
│   ├── oidc.rs                  # OIDC device authorization flow + JWT verification
│   ├── ratelimit.rs              # Rate limiter (token bucket)
│   ├── frontend/
│   │   ├── mod.rs
│   │   ├── telnet.rs             # Telnet server
│   │   ├── ssh.rs                # SSH server (built-in CA + OIDC device flow)
│   │   └── mcp.rs                # MCP server (SSE transport)
│   ├── backend/
│   │   ├── mod.rs                # Device backend pool
│   │   ├── driver.rs             # Driver trait
│   │   ├── arista_eos.rs         # Arista EOS driver
│   │   ├── nokia_sros.rs         # Nokia SR-OS driver
│   │   └── pool.rs               # Connection pool management
│   └── participants.rs           # Participant/port mapping loader
├── config/
│   └── example.yml               # Example configuration
└── tests/
    ├── policy_test.rs
    └── command_test.rs
```

## Deployment (SFMIX-specific)

### Central Instance (`lg.sfmix.org`)

The primary user-facing instance. Configured with all devices across all sites,
reached over the site-spanning management network.

| Item                | Value                                                |
|---------------------|------------------------------------------------------|
| **DNS**             | `lg.sfmix.org`                                       |
| **Deployment host** | `alice.sfmix.org` (Linux)                            |
| **Ansible role**    | `looking_glass` (new)                                |
| **Playbook**        | `deploy_looking_glass.playbook.yml`                  |
| **Binary path**     | `/usr/local/bin/looking-glass`                       |
| **Config path**     | `/etc/looking-glass/config.yml`                      |
| **systemd unit**    | `looking-glass.service`                              |
| **Listening**       | Telnet :23, SSH :2222, MCP/SSE via nginx :443        |
| **Devices**         | All peering switches + core routers across all sites |
| **Network**         | Management network (see design doc 001)              |

**Deployment target: `alice.sfmix.org`** — an existing Linux host already on
the management network. The looking glass binary runs alongside the existing
Alice LG service. The main requirement is management network reachability to
all device management IPs.

**Nginx reverse proxy** — the existing nginx on `alice.sfmix.org` is extended
with a location block to proxy MCP traffic to the looking glass daemon:

```nginx
# /etc/nginx/sites-enabled/alice.sfmix.org
server {
    listen 443 ssl;
    server_name alice.sfmix.org;

    # ... existing Alice LG config ...

    # Looking glass MCP (SSE)
    location /mcp {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
        proxy_set_header Host $host;
        proxy_buffering off;          # required for SSE
        proxy_cache off;
        chunked_transfer_encoding off;
    }
}
```

The MCP endpoint is then reachable at `https://alice.sfmix.org/mcp`.

### Site-Local Instances (Optional)

For IX administrators doing direct site-level debugging. Deployed on VyOS OOB
management routers, configured with only local devices.

| Item              | Value                                           |
|-------------------|-------------------------------------------------|
| **Hosts**         | `mgmt-rtr.sfo02`, `mgmt-rtr.fmt01`, etc.        |
| **Access**        | SSH + MCP, mgmt network IPs (not public-facing) |
| **Ansible group** | `management_router` (existing)                  |
| **Frontends**     | SSH :2222, MCP :8080 (local)                    |
| **Devices**       | Local site devices only                         |

These are optional and can be deployed later. The same Ansible role handles
both modes — the config template just scopes the device list and frontend
config based on a `looking_glass_mode: central | site_local` variable.

### Coexistence with bgplg

The existing OpenBSD bgplg at `lg.sfmix.org` continues to serve BGP route
lookups, ping, and traceroute. The new looking glass runs alongside it,
providing the additional device-query interfaces (interface stats, MAC/ARP/ND
tables, LLDP, etc.) that bgplg does not cover.

The bgplg web interface remains on port 80/443 at `lg.sfmix.org`; the new LG
runs on `alice.sfmix.org` with telnet :23, SSH :2222, and MCP behind nginx on
:443 at `/mcp`. DNS for `lg.sfmix.org` can be pointed at the new service later
if desired.

### Device Accounts

Create read-only `looking-glass` user accounts on all devices:

**Arista EOS:**
```
username looking-glass privilege 1 role network-operator secret ...
```

**Nokia SR-OS:**
```
configure system security user-params local-user user "looking-glass" access console ssh
configure system security user-params local-user user "looking-glass" console member ["default"]
```

Device credentials are managed via Ansible Vault and deployed to
`/etc/looking-glass/device_key` on the LG host(s).

### Build & Cross-Compilation

```bash
# Build static musl binary (from dev machine or CI)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
strip target/x86_64-unknown-linux-musl/release/looking-glass

# Result: single static binary, ~5-10 MB, zero runtime deps
# Deploy via Ansible copy module
```

## Development Phases

### Phase 1: Core + Telnet (MVP)

- [ ] Project skeleton (Cargo.toml, module structure)
- [ ] Config parsing
- [ ] Structured command types
- [ ] Policy engine (public tier only)
- [ ] Rate limiter
- [ ] Arista EOS driver (SSH CLI)
- [ ] Telnet frontend
- [ ] Basic integration test with containerlab (Arista cEOS)

### Phase 2: SSH + Authentication

- [x] SSH server with built-in CA and OIDC device authorization flow
- [x] OIDC JWT verification against Authentik JWKS
- [x] SSH certificate generation and agent injection
- [x] Certificate-based fast re-authentication
- [x] `login` command for SSH and telnet sessions
- [ ] Participant port mapping (file-based)
- [ ] Policy engine (authenticated tier)
- [ ] Nokia SR-OS driver

### Phase 3: MCP Interface

- [ ] MCP server (SSE transport)
- [ ] Tool definitions matching command set
- [ ] Resource definitions (participants, prefixes, status)
- [ ] Authenticated MCP mode (Bearer token)

### Phase 4: Polish + Deploy

- [ ] NetBox participant source (API integration)
- [ ] Ansible role for deployment
- [ ] Monitoring integration (Prometheus metrics endpoint)
- [ ] Documentation and README
- [ ] Publish as open-source

## Security Considerations

- **No configuration writes**: the device backend categorically rejects any command that is not a `show` / read-only command, independent of policy
- **Read-only device accounts**: defense in depth — even if the LG software has a bug, the device account cannot modify configuration
- **Rate limiting at multiple levels**: prevents both accidental and malicious query floods
- **Command injection prevention**: commands are structured objects, not raw strings passed to a shell
- **OIDC token validation**: tokens are validated against `login.sfmix.org` JWKS, not just decoded
- **Telnet has no write access by design**: the unauthenticated tier has the most restrictive policy
- **SSH host key pinning**: the LG presents a stable host key; users can verify it
- **Secrets management**: device credentials and OIDC client secrets loaded from environment variables or Ansible Vault, never in the config file

## Open Questions

- [x] ~~**Central instance deployment target**~~ — `alice.sfmix.org` (Linux)
- [ ] Should we support a web UI as well, or is SSH + MCP sufficient? (A simple web UI could be added later as another frontend)
- [ ] Should the ping/traceroute commands execute from the LG host or from the network devices?
- [x] ~~What is the preferred opkssh deployment model?~~ — Built-in: LG is its own SSH CA and OIDC client, no external tools needed
- [ ] Should we expose sflow/netflow data through the LG, or keep that exclusively in Grafana?
- [ ] Should participant port mapping be real-time from NetBox, or a periodically-generated snapshot?
- [ ] Should the LG binary also serve as a health-check endpoint for monitoring?
