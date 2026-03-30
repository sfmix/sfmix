# Looking Glass

A multi-purpose IXP looking glass service with SSH, Telnet, and MCP interfaces.

## Features

- **Telnet CLI** — unauthenticated public access to basic IXP operational state
- **SSH CLI** — authenticated access via OpenID Connect (opkssh), with per-ASN port visibility
- **MCP interface** — LLM agent access to IXP state (public and authenticated modes)
- **Multi-platform device backend** — Arista EOS, Nokia SR-OS, extensible to others
- **Policy engine** — declarative rules controlling what each user tier can query
- **Rate limiting** — global, per-device, and per-user limits to protect network equipment

## Quick Start

```bash
cargo build --release
cp config/example.yml /etc/looking-glass/config.yml
# Edit config.yml with your devices, auth, and policy settings
./target/release/looking-glass --config /etc/looking-glass/config.yml
```

## Configuration

See [`config/example.yml`](config/example.yml) for a full annotated example.

Key sections:
- `listen` — bind addresses for telnet, SSH, and MCP
- `auth` — OIDC issuer configuration for authenticated access
- `devices` — network devices to query
- `rate_limits` — query throttling
- `participants` — ASN-to-port mapping (file or NetBox source)
- `policies` — command access rules

## Access Tiers

| Tier          | Interface   | Authentication                 | Capabilities                                         |
|---------------|-------------|--------------------------------|------------------------------------------------------|
| Public        | Telnet, MCP | None                           | BGP summary, interface status, LLDP, ping/traceroute |
| Participant   | SSH, MCP    | OIDC (PeeringDB)               | Public + own port details, own BGP sessions          |
| Administrator | SSH, MCP    | OIDC (IX Administrators group) | Full read-only access                                |

## Architecture

See the [design document](../documentation/design_docs/004-looking-glass.md) for full details.

## License

BSD-2-Clause
