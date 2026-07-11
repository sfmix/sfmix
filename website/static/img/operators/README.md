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
- SVG preferred (crisp on the white logo chip); PNG works if named `.svg` is not
  available — but the loader only tries the `.svg` path, so convert to SVG.
- The logo renders on a white rounded chip ~40px tall; provide adequate padding
  in the artwork or let the chip's padding handle it.
- **Use official assets you have rights to display.** These are operator
  trademarks; ship real logos only with permission, otherwise the monogram
  fallback is the safe default.
- Files here are a mix:
  - `qts.svg` is the operator's **official brand mark** (the genuine, unaltered
    press-kit SVG — full sunburst emblem + wordmark), used to identify the
    operator on the map with the operator's authorisation.
  - `equinix.svg`, `digital-realty.svg`, `opencolo.svg`, `hurricane-electric.svg`
    are **typographic wordmarks in each operator's official brand colour** (e.g.
    Equinix red `#ED1822`, Digital Realty teal `#01969D`, OpenColo two-tone
    blue). These do **not** reproduce the operators' distinctive graphical marks.
  - To upgrade any wordmark to the exact logo, drop that operator's official
    press-kit SVG in place of the file (same filename) once you have the right to
    display it.
