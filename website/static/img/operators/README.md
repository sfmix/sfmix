# Operator logos (map info pane)

Curated fallback logos for datacenter operators shown in the network map's info
pane. The map resolves an operator badge in three tiers:

1. **PeeringDB org logo** — used first when the facility's PeeringDB org has a
   `logo` (fetched at build time into `map.json`).
2. **Repo-local logo (these files)** — used when PeeringDB has no org logo.
3. **Initials monogram** — generated in the browser; always renders, so a site
   never shows an empty badge.

## Adding a logo

Drop a file named `<operator-slug>.svg` here, where the slug is the operator
name lowercased with non-alphanumerics collapsed to `-` (see `slug()` in
`website/static/js/network-map.js`). Examples:

| Operator (in `portal/mapbuild/data/sites.json`) | File |
| --- | --- |
| Digital Realty | `digital-realty.svg` |
| Hurricane Electric | `hurricane-electric.svg` |
| Equinix | `equinix.svg` |
| CoreSite | `coresite.svg` |
| QTS | `qts.svg` |
| OpenColo | `opencolo.svg` |

Notes:
- SVG preferred (crisp on the white logo chip). A raster (PNG) logo can be
  shipped by embedding it inside an SVG wrapper as a base64 `data:` URI (see
  `digital-realty.svg` / `opencolo.svg`) — the loader only tries the `.svg` path,
  and an img-loaded SVG blocks *external* references but allows inline `data:`
  URIs, so the file stays self-contained.
- The logo renders on a white rounded chip ~40px tall; provide adequate padding
  in the artwork or let the chip's padding handle it.
- **Use official assets you have rights to display.** These are operator
  trademarks; ship real logos only with permission/authorisation, otherwise the
  monogram fallback is the safe default.
- Each file here is the operator's **official brand mark**, used to identify that
  operator on the map with the operator's authorisation:
  - `qts.svg`, `equinix.svg`, `hurricane-electric.svg` — genuine, unaltered
    official SVGs (full emblem + wordmark).
  - `digital-realty.svg`, `opencolo.svg` — the operator's official raster logo
    embedded verbatim as a `data:` URI inside an SVG wrapper (their logos are
    only published as PNG).
