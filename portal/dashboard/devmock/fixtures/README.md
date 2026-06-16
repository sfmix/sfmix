# devmock fixtures

These JSON files are the **synthetic** data the portal renders from when
`LG_USE_FIXTURES=true` (see `../loader.py`). Each file mirrors the shape of one
real API endpoint response, but its **content is fake** — see the rules below.

## ⚠️ No real participant data — ever

Fixtures must contain only placeholder, documentation-reserved values. When
editing or adding fixtures, follow these conventions so it stays obvious that
nothing here is real:

| Field kind | Use only |
|------------|----------|
| ASNs       | RFC 5398 doc range: `64496`–`64511`, `65536`–`65551` |
| IPv4       | RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| IPv6       | RFC 3849: `2001:db8::/32` |
| MACs       | locally-administered `0200.5e..` style |
| Org names  | obvious placeholders (`Example Networks LLC`, `Placeholder Transit Inc.`) |
| Hostnames  | `*.example.net` / `*.example.org` |

There is intentionally **no capture-from-production script** — it would risk
copying real participant data into the repo.

## File-naming convention

The loader maps an API path to a filename mechanically (`loader.fixture_candidates`):
strip `/api/v1/`, replace `/` → `_`, append `__key-value` per sorted query param,
add `.json`. A request first tries the param-specific file, then the base file.

```
/api/v1/interfaces/status              -> interfaces_status.json
/api/v1/interfaces/status?asn=64496    -> interfaces_status__asn-64496.json (else interfaces_status.json)
/api/v1/participants/64496             -> participants_64496.json
/api/v1/routeservers/rs1/neighbors     -> alice/routeservers_rs1_neighbors.json
```

A missing fixture logs `[devmock] no fixture for <path> …` and returns an empty
list/object, so the page degrades to empty instead of erroring — and the log
tells you exactly which filename to create.

## Catalog (current surface)

| Source | Fixture file | Endpoint | Consumed by |
|--------|--------------|----------|-------------|
| lg | `participants.json` | `/api/v1/participants` | participants list |
| lg | `participants_<asn>.json` | `/api/v1/participants/{asn}` | network detail, mac-table gating |
| lg | `peeringdb-cache.json` | `/api/v1/peeringdb-cache` | participant website links |
| lg | `interfaces_status.json` | `/api/v1/interfaces/status` | network detail, lldp |
| lg | `optics.json` | `/api/v1/optics` | network detail (admin), optics page |
| lg | `optics_inventory.json` | `/api/v1/optics/inventory` | optics page |
| lg | `lldp_neighbors.json` | `/api/v1/lldp/neighbors` | network detail, lldp page |
| lg | `mac-address-table.json` | `/api/v1/mac-address-table` | mac-table page |
| lg | `arp.json` | `/api/v1/arp` | network detail (v4 MAC binding) |
| lg | `ipv6_neighbors.json` | `/api/v1/ipv6/neighbors` | network detail (v6 MAC binding) |
| lg | `participant-ports.json` | `/api/v1/participant-ports` | lldp page (port→participant) |
| lg | `netbox_status.json` | `/api/v1/netbox/status` | NetBox status page |
| lg | `device-cache_status.json` | `/api/v1/device-cache/status` | device cache page |
| alice | `routeservers.json` | `/api/v1/routeservers` | network detail (RS sessions) |
| alice | `routeservers_<rs>_neighbors.json` | `/api/v1/routeservers/{rs}/neighbors` | network detail (RS sessions) |

The synthetic dataset is internally consistent: 3 participants (AS64496 with a
2-member LAG that has one member **down** → degraded; AS64497, AS64498), one
optic in the **warn** band (switch01 Ethernet1, RX −13.5 on a 10GBASE-LR), and
RS sessions with a couple of filtered routes — so the network-detail alerts
panel has something to show. `AS64496` is the dev-login "member" persona.

## Extending over time

1. **Expose a field the view didn't read before** — add it (with a placeholder
   value) to the relevant fixture, then read it in the view/template. No loader change.
2. **Call a new method on an existing client** — add the method to
   `dashboard/lg_client.py` / `alice_client.py` as `return self._get("/api/v1/<thing>")`.
   Hit the page, copy the `[devmock] no fixture for …` filename from the log, and
   create `lg/<thing>.json`. Add a catalog row above.
3. **Add a query-param or path-id variant** — drop a more specific file
   (e.g. `optics__asn-64497.json`); it automatically wins over the base file.
4. **Add a whole new data source** — write a `NewClient` with the same single
   `_get(path, ...)` seam, append `("dashboard.new_client", "NewClient", "newsource")`
   to `_CLIENTS` in `../loader.py`, and create a `newsource/` fixtures dir.
