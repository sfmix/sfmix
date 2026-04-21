# Nokia SR-OS JSON Schema Samples

These JSON samples were captured from `cr1.sjc01.transit.sfmix.org` (Nokia SR-OS) using the MD-CLI `info json /state` commands.

## Commands Used

### Router Interfaces
```
info json /state router interface * | no-more
```
- **File**: `router-interface.json`
- **Top-level key**: `nokia-state:interface` (array)
- **Key fields per interface**:
  - `interface-name` — Interface name (e.g., "system", "lag-core-1-10")
  - `if-index` — Interface index
  - `oper-state` — Operational state ("up", "down")
  - `protocol` — Protocols running on interface (e.g., "ospfv2 mpls rsvp ospfv3")
  - `oper-ip-mtu` — Operational IP MTU
  - `creation-origin` — How interface was created ("manual")
  - `last-oper-change` — Timestamp of last state change
  - `statistics/ip/*` — IP packet/octet counters
  - `ipv4/oper-state` — IPv4 operational state
  - `ipv4/primary/oper-address` — Primary IPv4 address
  - `ipv6/address[]` — IPv6 addresses with state

### BGP Neighbors
```
info json /state router bgp neighbor * | no-more
```
- **File**: `router-bgp-neighbor.json`
- **Top-level key**: `nokia-state:neighbor` (array)
- **Key fields per neighbor**:
  - `ip-address` — Neighbor IP address
  - `statistics/session-state` — Session state ("Established", "Idle", etc.)
  - `statistics/peer-port` — Remote TCP port
  - `statistics/local-port` — Local TCP port (usually 179)
  - `statistics/negotiated-family[]` — Address families (e.g., "VPN-IPv4", "VPN-IPv6")
  - `statistics/peer-identifier` — BGP router ID
  - `statistics/established-transitions` — Number of state transitions
  - `statistics/last-established-time` — Timestamp of last establishment
  - `statistics/hold-time-interval` — Negotiated hold time
  - `statistics/keep-alive-interval` — Negotiated keepalive
  - `statistics/received-paths` — Number of received prefixes
  - `statistics/family-prefix/*` — Per-AFI prefix counts (received, active, sent, etc.)

## Notes

1. **Pagination**: Use `| no-more` pipe to disable pagination in PTY sessions.
2. **Wildcards**: Use `*` to query all items in a list (e.g., `interface *`, `neighbor *`).
3. **JSON Pointer Limitation**: Keys contain colons (e.g., `nokia-state:interface`), so use `val.get("nokia-state:interface")` instead of JSON pointer syntax.
4. **Description**: Interface descriptions are config-only, not available in state.
