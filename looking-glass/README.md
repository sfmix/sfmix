# Looking Glass

A multi-purpose IXP looking glass with Telnet, SSH, and MCP (Model Context Protocol) interfaces. Single static binary, designed for Internet Exchange Point operators.

## Features

- **Telnet frontend** (port 23) — unauthenticated public access with IOS-style Tab completion and `?` help
- **SSH frontend** (port 2222) — authenticated via OIDC device flow + SSH certificates, per-ASN port visibility
- **HTTP frontend** (port 8080) — REST API (`/api/v1/*`) + MCP (`/mcp`) on a single port
- **Multi-platform backend** — Arista EOS and Nokia SR-OS via SSH
- **Policy engine** — declarative YAML rules, first-match evaluation
- **Rate limiting** — global concurrency, per-device concurrency, per-user sliding window
- **Identity-aware** — per-ASN port access, admin overrides, IP-prefix grouping for anonymous users
- **Declarative grammar** — CLI command tree defined in YAML, validated at compile time

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

Default ports: telnet `:23`, SSH `:2222`, HTTP `:8080`.

## Architecture

```
  lg-cli                          lg-http
┌──────────────────────┐        ┌─────────────────────┐
│ ┌────────┐┌────────┐ │        │     HTTP :8080      │
│ │ Telnet ││  SSH   │ │        │ /api/v1/*     /mcp  │
│ │  :23   ││ :2222  │ │        └──────────┬──────────┘
│ └───┬────┘└───┬────┘ │                   │
│     └────┬────┘      │                   │
│   ┌──────▼──────┐    │                   │
│   │     CLI     │    │                   │
│   │   Grammar   │    │                   │
│   │   Engine    │    │                   │
│   └──────┬──────┘    │                   │
└──────────┼───────────┘                   │
           └───────────┬───────────────────┘
                       │
              ╔════════▼════════╗
              ║  Authenticated  ║
              ║       RPC       ║
              ╚════════╤════════╝
                       │
                   lg-server
┌───────────┐ ┌──────┼──────────────────┐ ┌───────────┐
│           │ │ ┌────▼─────┐            │ │   State   │
│  Netbox   ├─▶ │Execution │            │ │   Cache   │
│           │ │ │  Core    │            │◀┤           │
└───────────┘ │ └────┬─────┘            │ └───────────┘
              │      │                  │
              │ ┌────▼─────┐ ┌────────────────┐
              │ │ Policy   ├▶│ Rate Limiter   │
              │ │ Engine   │ │ (Requestor)    │
              │ └────┬─────┘ └────────────────┘
              │      │                  │
              │ ┌────▼─────┐ ┌────────────────┐
              │ │ Device   ├▶│ Rate Limiter   │
              │ │  Pool    │ │ (Device)       │
              │ └────┬─────┘ └────────────────┘
              │      │                  │
              └──────┼──────────────────┘
                     │
                 ╱───▼───╲
                 │Devices│
                 ╲───────╱
```

## Commands

All frontends accept the same command set. Commands support IOS-style abbreviations (e.g. `sh int st`, `sh ip bgp sum`).

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `show interfaces status` | Interface summary (name, link state, speed, VLAN) |
| `show interface <port>` | Detailed counters for a specific interface |
| `show optics` | Transceiver DOM optical power levels (all ports) |
| `show optics <port>` | Detailed DOM for a specific port |
| `show lldp neighbors` | LLDP neighbor table |
| `show mac address-table` | MAC address table |
| `show participants` | List IXP participants (ASN + name) |
| `ping <destination>` | Ping from the looking glass vantage point |
| `traceroute <destination>` | Traceroute from the looking glass vantage point |

## Access Tiers

| Tier | Interface | Authentication | Capabilities |
|------|-----------|----------------|--------------|
| **Public** | Telnet, HTTP | None | Interface status, optics (global), LLDP, MAC table, participants, ping, traceroute |
| **Participant** | SSH, HTTP | OIDC (PeeringDB/GitHub) | Public + own port details, own port optics |
| **Administrator** | SSH, HTTP | OIDC (IX Administrators group) | Full read-only access to all ports |

## MCP Interface

The MCP (Model Context Protocol) endpoint at `/mcp/sse` allows LLM agents and tools (e.g. Windsurf, Claude Desktop) to query the looking glass programmatically.

### Configuration

In your MCP client, add the server URL:

```json
{
  "mcpServers": {
    "sfmix": {
      "serverUrl": "https://lg-ng.sfmix.org/mcp/sse"
    }
  }
}
```

### Authentication

The MCP endpoint requires authentication. Compliant MCP clients (Windsurf, etc.) handle this automatically:

1. Client connects → server returns `401 Unauthorized` with a `WWW-Authenticate` header
2. Client fetches `/.well-known/oauth-protected-resource` to discover the authorization server
3. Client fetches `/.well-known/oauth-authorization-server` and registers via `POST /oauth/register`
4. Client opens a browser window for the OAuth consent flow (Authentik)
5. After approval, subsequent requests carry `Authorization: Bearer <token>`

No manual token configuration is needed in the MCP config — the client handles the OAuth flow automatically on first connection.

### Anonymous access

The MCP endpoint does not support anonymous access. All requests require a valid token from the OIDC provider. Authentication follows the same tiers as the HTTP REST API (Participant or Administrator).

## Documentation

- **[Operations Guide](doc/operations.md)** — configuration reference, authentication, policy engine, deployment, systemd
- **[Development Guide](doc/development.md)** — source layout, grammar system, adding commands, testing, tech stack

## License

BSD-2-Clause
