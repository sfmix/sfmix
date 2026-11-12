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
| `show mac address-table` | MAC address table, with the participant on participant-facing ports |
| `show vlans` | IXP peering LANs (VLAN ID, name, IPv4/IPv6 prefixes) |
| `show participants` | List IXP participants (ASN + name) |
| `ping <destination>` | Ping once from the looking glass host (`@device` to ping from a specific device) |
| `traceroute <destination>` | Traceroute once from the looking glass host (`@device` to trace from a specific device) |
| `terminal length <n\|0\|auto>` | Telnet/SSH pager page length: `auto` (default) follows the window size, `0` never pages |

### Pager (telnet / SSH)

Output that fits on one screen prints inline. Longer output opens a full-screen pager (`less`-style keys: SPACE/b page, j/k line, `/` search, `n`/`N`, `S` wrap/chop, `h` help, `q` quit) that reflows when the window is resized. On quit, the lines you paged through are left in your scrollback. The window size comes from the SSH PTY (and window-change requests) or telnet NAWS; clients that report none (SSH exec, `nc`) are never paged. Implementation: `lg-cli/src/pager.rs`.

## Access Tiers

| Tier | Interface | Authentication | Capabilities |
|------|-----------|----------------|--------------|
| **Public** | Telnet, HTTP | None | Interface status, optics (global), LLDP, MAC table, participants, ping, traceroute |
| **Participant** | SSH, HTTP | OIDC (PeeringDB/GitHub) | Public + own port details, own port optics |
| **Administrator** | SSH, HTTP | OIDC (IX Administrators group) | Full read-only access to all ports |

## MCP Interface

The MCP (Model Context Protocol) endpoint at `/mcp` allows LLM agents and tools (e.g. Windsurf, Claude Desktop) to query the looking glass programmatically.

### Configuration

In your MCP client, add the server URL:

```json
{
  "mcpServers": {
    "sfmix": {
      "serverUrl": "https://lg.sfmix.org/mcp"
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

### Metrics tools

Three tools read history and statistics from the fabric Prometheus. lg-server runs them through `POST /rpc/v1/metrics`, which resolves and authorizes each request (`src/metrics/`). They are enabled by a `metrics:` block in `lg-server.yml`.

| Tool | Target | Returns |
|---|---|---|
| `port_metrics` | `device`+`interface`, or `asn` (all of a participant's ports) | Traffic in/out (bps, % of speed); error/discard counters; optics per lane (Rx/Tx dBm, bias mA, SNR for coherent optics) plus module temperature. LAGs are broken out per member, with a total. |
| `link_metrics` | `device`+`interface` (LAGs followed member by member) | Both ends of each physical link side by side. The far end comes from the cached LLDP table. Also derives per-lane loss (A tx − B rx) and sent-minus-received traffic in each direction. |
| `peer_traffic` | `asn` (optional `peer_asn`, `direction`, `top`) | Per-peer bps from the sFlow peering matrix: the top N peers per direction, an "other" row and a total. |

Output is sized for LLM context:

- **Latest reading by default:** traffic is a 1-minute average; errors are the count over the last 15 minutes.
- **`range`** (`"1h"`, `"24h"`, `"7d"`, max 30d) returns one summary row per series instead. Rows show last/avg/p95 over step averages and the true min/max. Counter rows show the total and the maximum per step.
- **`points`** additionally returns the downsampled series. Use it only when the shape over time matters.
- **`families`** (`traffic`, `errors`, `optics`) limits what `port_metrics` and `link_metrics` fetch.

Who may query what, using the same model as the portal:

- **Participants:** their own ports, LAG members and peer traffic.
- **Infrastructure ports and other networks' data:** IX Administrators only.

The far end of a link is shown only if the caller may also see it.

```yaml
metrics:
  prometheus_url: "http://metrics.oob.sfo02.sfmix.org:9090"
  max_range_secs: 2592000   # match Prometheus retention
  timeout_secs: 15
  max_ports: 16             # cap for asn-wide port queries
```

## Documentation

- **[Operations Guide](doc/operations.md)** — configuration reference, authentication, policy engine, deployment, systemd
- **[Development Guide](doc/development.md)** — source layout, grammar system, adding commands, testing, tech stack

## License

BSD-2-Clause
