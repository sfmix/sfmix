# Committed basemap (all-vector GeoJSON)

The map renders **entirely from vector GeoJSON** on the client — no tile server,
no raster tiles, no PMTiles. MapLibre internally tiles and simplifies each
`geojson` source by zoom (via geojson-vt), so a single moderately-detailed file
per layer gives correct zoom-dependent detail. Three files live in
`website/static/map/`:

- `basemap-water.json` — SF/San Pablo Bay + Pacific, assembled coastline→water
  polygons from the **full-resolution** osmdata source (detailed, smooth shoreline
  incl. Treasure Island, piers, sloughs).
- `basemap-land.json`  — a single bbox rectangle used as the paper backdrop;
  water draws on top, so the crisp edge comes from the water polygons.
- `basemap-airports.json` — OSM `aeroway` runway shapes + terminal footprints +
  aerodrome ICAO points (SFO/OAK/SJC/Moffett/…). Rendered as subtle grey hints;
  ICAO codes are tiny labels shown only at zoom ≥ 10.5.
- `basemap-roads.json` — freeways: all `motorway` (incl. the I-80 Bay Bridge,
  I-580 Richmond, CA-92 San Mateo, CA-84 Dumbarton crossings) as
  `class: motorway`, plus major `trunk` state routes as `class: trunk`. The
  renderer shows motorways at all zooms and fades trunks in above z≈9.5.

Target bbox (SF Bay Area): `[-122.75, 37.15, -121.6, 38.05]`.
Current sizes: ~1.5 MB raw total, ~200 KB gzipped on the wire. Committed to the
repo and served by GitHub Pages (which gzips automatically). Keep raw under
~3 MB; if you need much more, move these to portal.sfmix.org instead.

## Regenerating (rare — coastlines don't move)

`fetch_basemap.py` reproduces all three files. It needs internet and GDAL
(`ogr2ogr`), both present on a dev laptop; it downloads nothing permanent.

```
python3 network-map/basemap/fetch_basemap.py
```

Pipeline it runs:

- **Water**: downloads osmdata.openstreetmap.de "simplified water polygons"
  (pre-assembled coastline→water, ~24 MB zip), then
  `ogr2ogr -t_srs EPSG:4326 -clipdst <bbox> -simplify 0.00006` → clipped bay,
  coords rounded to 5 decimals.
- **Roads**: Overpass query for `highway=motorway` with the Bay Area refs in the
  bbox, `ogr2ogr -simplify 0.00015`, coords rounded to 5 decimals.
- **Land**: emitted directly as the bbox rectangle.

The osmdata "simplified" source is already generalized; for crisper close-zoom
shoreline swap in the full `water-polygons-split-3857.zip` (~800 MB) — but that
is overkill for this stylized, orientation-only basemap.
