# Looking Glass

A multi-purpose IXP looking glass with Telnet, SSH, and MCP (Model Context Protocol) interfaces. Single static binary, designed for Internet Exchange Point operators.

## Features

- **Telnet frontend** (port 23) — unauthenticated public access with IOS-style Tab completion and `?` help
- **SSH frontend** (port 2222) — authenticated via opkssh + OIDC, per-ASN port visibility
- **MCP frontend** (port 8080) — LLM agent access over streamable HTTP
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
      │   Grammar   │   Declarative YAML command tree
      │   Engine    │   (parse + complete)
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

## Commands

All frontends accept the same command set. Commands support IOS-style abbreviations (e.g. `sh int st`, `sh ip bgp sum`).

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `show interfaces status` | Interface summary (name, link state, speed, VLAN) |
| `show interface <port>` | Detailed counters for a specific interface |
| `show optics` | Transceiver DOM optical power levels (all ports) |
| `show optics <port>` | Detailed DOM for a specific port |
| `show ip bgp summary` | BGP IPv4 peer summary |
| `show bgp ipv6 unicast summary` | BGP IPv6 peer summary |
| `show bgp neighbor <addr>` | BGP neighbor detail |
| `show lldp neighbors` | LLDP neighbor table |
| `show arp` | ARP table (IPv4) |
| `show ipv6 neighbors` | IPv6 neighbor discovery table |
| `show mac address-table` | MAC address table |
| `show vxlan vtep` | VXLAN VTEP endpoints |
| `show participants` | List IXP participants (ASN + name) |
| `ping <destination>` | Ping from the looking glass vantage point |
| `traceroute <destination>` | Traceroute from the looking glass vantage point |

## Access Tiers

| Tier | Interface | Authentication | Capabilities |
|------|-----------|----------------|--------------|
| **Public** | Telnet, MCP | None | BGP summary, interface status, optics (global), LLDP, ARP/ND, ping, traceroute |
| **Participant** | SSH, MCP | OIDC (PeeringDB/GitHub) | Public + own port details, own port optics |
| **Administrator** | SSH, MCP | OIDC (IX Administrators group) | Full read-only access to all ports |

## Documentation

- **[Operations Guide](doc/operations.md)** — configuration reference, authentication, policy engine, deployment, systemd
- **[Development Guide](doc/development.md)** — source layout, grammar system, adding commands, testing, tech stack

## License

BSD-2-Clause
