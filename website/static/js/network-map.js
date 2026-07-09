/* SFMIX network map — subway-style, all-vector MapLibre view of the fabric.
 *
 * Data model (see network-map/README.md):
 *   structure  GET data-structure-url  -> {generation, sites, cables[]}
 *   traffic    GET data-traffic-url     -> {generation, links:{id:{in_bps,out_bps,util_pct,series_*}}}
 * The page is a static shell; all data comes from portal.sfmix.org. Structure is
 * loaded once; traffic is polled and applied with setFeatureState (no relayout).
 * Circuit ids/providers never appear here — cables carry only an opaque id.
 */
(function () {
  "use strict";

  var el = document.getElementById("network-map");
  if (!el || typeof maplibregl === "undefined") return;

  var STRUCTURE_URL = el.dataset.structureUrl;
  var TRAFFIC_URL = el.dataset.trafficUrl;
  var BASEMAP_BASE = el.dataset.basemapBase || "/map/";
  var SPRITE_BASE = el.dataset.spriteBase || "/map/sprites/";
  var DECOR_URL = el.dataset.decorationsUrl || "";
  // Portal origin, derived from the (absolute) structure URL, so portal-relative
  // asset paths in map.json (e.g. cached operator logos at /statistics/map/logos/)
  // resolve to the portal rather than this static site's origin.
  var PORTAL_ORIGIN = (function () {
    try { return new URL(STRUCTURE_URL, window.location.href).origin; }
    catch (e) { return ""; }
  })();
  var POLL_MS = 60000;

  // ---- early prefetch (startup perf) --------------------------------------
  // Start every startup fetch immediately, in parallel with map/style init,
  // instead of serially after the map 'load' event. Previously:
  //   - structure (map.json) was fetched only inside the load handler, so the
  //     network layers appeared well after the basemap;
  //   - roads/airports GeoJSON was fetched (and parsed) TWICE — once by the
  //     MapLibre source worker, again by the shield/label builders. Now each
  //     is fetched ONCE here; the parsed object feeds the source via setData
  //     AND the builders (the style declares those sources empty).
  //   - the water-texture sprite + decorations feed also start now, so the
  //     ripple restyle and critters land with the rest instead of trailing.
  // loadSvgImage / DECO_SPRITE_PX below are hoisted/assigned before any
  // .then() callback here can run.
  function fetchJson(url) {
    return fetch(url, { mode: "cors" }).then(function (r) {
      if (!r.ok) throw new Error(url + ": " + r.status);
      return r.json();
    });
  }
  var EMPTY_FC = { type: "FeatureCollection", features: [] };
  var PREFETCH = {
    structure: fetchJson(STRUCTURE_URL),
    roads: fetchJson(BASEMAP_BASE + "basemap-roads.json"),
    airports: fetchJson(BASEMAP_BASE + "basemap-airports.json"),
    decorations: DECOR_URL ? fetchJson(DECOR_URL) : null,
    waterTexture: loadSvgImage("water-texture", 176),
    decoIcons: {} // icon name -> sprite promise, filled when the feed arrives
  };
  if (PREFETCH.decorations) {
    PREFETCH.decorations.then(function (deco) {
      deco.features.forEach(function (f) {
        var ic = f.geometry.type === "Point" && f.properties.icon;
        if (ic && !PREFETCH.decoIcons[ic]) PREFETCH.decoIcons[ic] = loadSvgImage(ic, DECO_SPRITE_PX);
      });
    }).catch(function () {});
  }
  // Three tiers: metro (overview) -> site -> device. Below METRO_ZOOM the map
  // shows one node per metro to avoid clustering tight sites (e.g. Santa Clara);
  // above it, individual sites; above EXPAND_ZOOM, devices within each site.
  var METRO_ZOOM = 10.6;
  var EXPAND_ZOOM = 13.0;       // building box + switch dots become readable here
  var DEVICE_LABEL_ZOOM = 14.3; // switch captions wait for room to avoid collisions

  // i18n bridge (English fallback keys)
  var I18N = {};
  try { I18N = JSON.parse(document.getElementById("map-i18n").textContent); } catch (e) {}
  function t(s) { return I18N[s] || s; }

  var RAMP = [
    [0, "#5794F2"], [20, "#73BF69"], [40, "#FADE2A"], [60, "#FF9830"], [80, "#F2495C"]
  ];
  var UTIL_COLOR_EXPR = ["interpolate", ["linear"], ["coalesce", ["feature-state", "util"], 0],
    0, RAMP[0][1], 20, RAMP[1][1], 40, RAMP[2][1], 60, RAMP[3][1], 80, RAMP[4][1]];
  // planned / not-yet-in-service spans: a cool slate blue, clearly outside the
  // utilization ramp and distinct from the "down" grey
  var PLANNED_COLOR = "#7d9cc0";
  // barber-pole stripe colour: a strongly darkened shade of the SAME hue the
  // link is showing (candy-stripe look) — a fixed pale stripe vanished on the
  // light green/yellow/orange utilization colours
  var FLOW_STRIPE_EXPR = ["interpolate", ["linear"], ["coalesce", ["feature-state", "util"], 0],
    0, "#173a75", 20, "#26521f", 40, "#6e5e00", 60, "#7d4306", 80, "#75141f"];
  // perpendicular offset (px) by the feature's "offset" step — shared by the
  // cable layers AND the water-treatment layers so they track the same path.
  var OFFSET_EXPR = ["interpolate", ["linear"], ["zoom"],
    8, ["*", ["get", "offset"], 2.2], 12, ["*", ["get", "offset"], 5],
    15, ["*", ["get", "offset"], 9], 16.5, ["*", ["get", "offset"], 15]];

  function fmtBps(b) {
    if (!b || b < 1) return "0";
    var u = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"], i = 0;
    while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
    return (b >= 100 ? b.toFixed(0) : b.toFixed(1)) + " " + u[i];
  }
  function capLabel(b) { return fmtBps(b).replace("bps", "b/s"); }

  // Flat GeoJSON props for a site — shared by the station roundel, the building
  // footprint, and the clickable title bubble so all three open the same detail.
  // Only scalars (MapLibre stringifies nested values); PeeringDB fields are
  // present only when the backend enriched the site.
  function siteProps(code, s) {
    return { code: code, name: s.name || code, operator: s.operator || "",
      metro: s.metro || "", address: s.address || "", ndev: (s.devices || []).length,
      logo: s.logo || "", operator_website: s.operator_website || "",
      pdb_url: s.pdb_url || "", city: s.city || "", state: s.state || "",
      net_count: s.net_count || 0, ix_count: s.ix_count || 0 };
  }

  function weightForCapacity(bps) {
    var g = bps / 1e9;
    if (g >= 800) return 5.0;
    if (g >= 400) return 4.0;
    if (g >= 100) return 2.6;
    if (g >= 40) return 2.0;
    if (g >= 10) return 1.5;
    return 1.1;
  }

  // ---- vector sprites ------------------------------------------------------
  // All sprite art ships as SVG (network-map/sprites-src, served from
  // /map/sprites/). MapLibre only takes bitmaps, so each is rasterized here at
  // SPRITE_RES× its logical size; pixelRatio keeps the icon-size math unchanged
  // while the extra pixels keep critters crisp at the ground-anchored zoom
  // growth (they reach ~2× logical size at z14).
  var SPRITE_RES = 4;
  function loadSvgImage(name, logicalPx) {
    return fetch(SPRITE_BASE + name + ".svg").then(function (r) {
      if (!r.ok) throw new Error("sprite " + name + ": " + r.status);
      return r.text();
    }).then(function (svg) {
      return new Promise(function (resolve, reject) {
        var url = URL.createObjectURL(new Blob([svg], { type: "image/svg+xml" }));
        var img = new Image();
        img.onload = function () {
          URL.revokeObjectURL(url);
          var w = Math.round(logicalPx * SPRITE_RES);
          var h = Math.round(w * img.height / img.width);
          var c = document.createElement("canvas");
          c.width = w; c.height = h;
          var g = c.getContext("2d");
          g.drawImage(img, 0, 0, w, h);
          resolve({ image: g.getImageData(0, 0, w, h), pixelRatio: SPRITE_RES });
        };
        img.onerror = function () { URL.revokeObjectURL(url); reject(new Error("sprite " + name)); };
        img.src = url;
      });
    });
  }

  // ---- build GeoJSON from structure --------------------------------------
  function buildSources(structure) {
    var sites = structure.sites;

    // The backend (portal/mapbuild) has already done ALL geometry prep —
    // smoothing, a->z orientation, de-looping, box-edge clipping, water spans, and
    // per-pair lane assignment. Here we only STYLE it: fan a parallel bundle's links into
    // parallel strands and turn the pre-built geometry into GeoJSON features. The
    // px spacing of the parallel strands IS a rendering choice, so it lives here.
    var cableFeatures = [], mediaFeatures = [], flowFeatures = [];
    var PAIR_STEP = 2.8;    // px-lane spacing between DISTINCT circuits on a pair
    var STRAND_FRAC = 0.34; // tight spacing between a bundle's own parallel strands
    BUNDLE_PROPS = {}; CABLE_STRANDS = {};
    structure.cables.forEach(function (c) {
      var laneCount = c.lane_count || 1;
      var base = ((c.lane || 0) - (laneCount - 1) / 2) * PAIR_STEP;
      var strands = Math.max(1, c.members || 1);
      CABLE_STRANDS[c.id] = strands;
      // remember parallel bundles so the info pane's ◀ ▶ stepper can rebuild a
      // strand's props without re-querying rendered features
      if (strands > 1) {
        BUNDLE_PROPS[c.id] = { id: c.id, scope: c.scope, status: c.status,
          approximate: !!c.approximate, capacity_bps: c.capacity_bps,
          members: strands, a_site: c.a_site, z_site: c.z_site,
          a_device: c.a_device || "", z_device: c.z_device || "" };
      }
      // one flow feature per inter cable (rides the bundle's lane): the barber-
      // pole stripe animated toward the dominant traffic direction (dir set on
      // each traffic poll; 0 = unknown/idle = hidden)
      if (c.scope === "inter" && c.status === "up") {
        flowFeatures.push({
          type: "Feature", id: c.id,
          properties: { id: c.id, weight: weightForCapacity(c.capacity_bps),
            offset: base, dir: 0 },
          geometry: { type: "LineString", coordinates: c.path }
        });
      }
      for (var st = 0; st < strands; st++) {
        var strandOff = strands > 1 ? (st - (strands - 1) / 2) * STRAND_FRAC : 0;
        cableFeatures.push({
          type: "Feature", id: c.id,
          properties: {
            // sid = per-strand feature-state key (promoteId): each parallel
            // strand colours by its OWN member utilization (see applyTraffic)
            sid: strands > 1 ? c.id + "#" + st : c.id,
            id: c.id, scope: c.scope, status: c.status,
            approximate: !!c.approximate, weight: weightForCapacity(c.capacity_bps),
            capacity_bps: c.capacity_bps, offset: base + strandOff,
            members: strands, strand: st, a_site: c.a_site, z_site: c.z_site,
            a_device: c.a_device || "", z_device: c.z_device || ""
          },
          geometry: { type: "LineString", coordinates: c.path }
        });
      }
      // water-crossing spans (pre-computed sub-spans of the path) get the submerged
      // treatment; carry the cable's base offset so the band centres on the bundle
      (c.media || []).forEach(function (m) {
        mediaFeatures.push({
          type: "Feature",
          properties: { medium: m.medium, id: c.id, offset: base },
          geometry: { type: "LineString", coordinates: m.coordinates }
        });
      });
    });

    var stationFeatures = [], deviceFeatures = [], buildingFeatures = [];
    Object.keys(sites).forEach(function (code) {
      var s = sites[code];
      stationFeatures.push({
        type: "Feature",
        properties: siteProps(code, s),
        geometry: { type: "Point", coordinates: [s.lon, s.lat] }
      });
      if (s.building) {
        // the building box carries the same site props so clicking the footprint
        // (added to PICK_LAYERS) opens the same detail as the roundel/label.
        buildingFeatures.push({
          type: "Feature", properties: siteProps(code, s),
          geometry: { type: "Polygon", coordinates: [s.building] }
        });
      }
      (s.devices || []).forEach(function (d) {
        deviceFeatures.push({
          type: "Feature",
          properties: { id: d.id, site: code },
          geometry: { type: "Point", coordinates: [d.dlon, d.dlat] }
        });
      });
    });

    // ---- device drops: the pre-built fine lines carrying each trunk from its
    // box-edge entry point to the specific switch inside (built on the backend).
    var dropFeatures = [];
    structure.cables.forEach(function (c) {
      (c.drops || []).forEach(function (seg) {
        dropFeatures.push({
          type: "Feature", id: c.id,
          properties: { id: c.id, status: c.status, approximate: !!c.approximate },
          geometry: { type: "LineString", coordinates: seg }
        });
      });
    });

    // ---- metro tier: metro nodes + pre-aggregated metro trunks from the backend.
    var metros = structure.metros || {};
    var metroStationFeatures = Object.keys(metros).map(function (name) {
      var m = metros[name];
      return { type: "Feature",
        properties: { metro: name, nsite: (m.codes || []).length,
          codes: (m.codes || []).join(", ") },
        geometry: { type: "Point", coordinates: [m.lon, m.lat] } };
    });
    METRO_MEMBERS = {};
    var metroMediaFeatures = [], metroFlowFeatures = [];
    var metroCableFeatures = (structure.metro_cables || []).map(function (g) {
      METRO_MEMBERS[g.id] = g.member_ids; METRO_CAP[g.id] = g.capacity_bps;
      (g.media || []).forEach(function (m) {
        metroMediaFeatures.push({ type: "Feature", properties: { id: g.id, medium: m.medium },
          geometry: { type: "LineString", coordinates: m.coordinates } });
      });
      if (g.status === "up") {
        metroFlowFeatures.push({ type: "Feature", id: g.id,
          properties: { id: g.id, weight: weightForCapacity(g.capacity_bps),
            offset: 0, dir: 0 },
          geometry: { type: "LineString", coordinates: g.path } });
      }
      return { type: "Feature", id: g.id,
        properties: { id: g.id, scope: "metro", status: g.status,
          approximate: !!g.approximate, weight: weightForCapacity(g.capacity_bps),
          capacity_bps: g.capacity_bps, offset: 0,
          a_site: g.a_metro, z_site: g.z_metro, nmember: g.members },
        geometry: { type: "LineString", coordinates: g.path } };
    });

    return {
      cables: fc(cableFeatures), media: fc(mediaFeatures),
      stations: fc(stationFeatures), devices: fc(deviceFeatures),
      buildings: fc(buildingFeatures), drops: fc(dropFeatures),
      metroStations: fc(metroStationFeatures), metroCables: fc(metroCableFeatures),
      metroMedia: fc(metroMediaFeatures),
      flows: fc(flowFeatures), metroFlows: fc(metroFlowFeatures)
    };
  }
  function fc(features) { return { type: "FeatureCollection", features: features }; }
  function avg(a) { return a.reduce(function (s, x) { return s + x; }, 0) / a.length; }
  var METRO_MEMBERS = {}, METRO_CAP = {}, METRO_STATS = {}, BUNDLE_PROPS = {}, CABLE_STRANDS = {};
  var STATION_KEYS = [], METRO_KEYS = [];

  // ---- map ----------------------------------------------------------------
  var map = new maplibregl.Map({
    container: "network-map",
    style: {
      version: 8,
      // No paint-property transitions: the barber-pole ticker steps
      // line-dasharray every 90ms, and the default 300ms transition made each
      // step schedule ~18 further frames — overlapping ticks pinned the map at
      // a constant 60fps (~1 CPU core + GPU, with every frame re-draping the
      // whole scene onto the 3D terrain). With transitions off a dash step
      // costs ONE frame, so animation renders at the ticker rate (~11fps).
      // Selection dim/highlight snap instead of fading; nothing else here
      // relied on transitions.
      transition: { duration: 0, delay: 0 },
      sources: {
        // Static, coarse basemap data: cap the client-side geojson-vt tile
        // pyramid (default maxzoom 18 built tiles far deeper than this coarse
        // data warrants) and simplify a little harder. Overzoom past the cap
        // is visually free at the widths these layers draw.
        water: { type: "geojson", data: BASEMAP_BASE + "basemap-water.json",
          tolerance: 0.5, maxzoom: 13 },
        land: { type: "geojson", data: BASEMAP_BASE + "basemap-land.json",
          tolerance: 0.5, maxzoom: 12 },
        // airports/roads start EMPTY and are filled from the shared PREFETCH
        // (single fetch shared with the shield/label builders — see load handler)
        airports: { type: "geojson", data: EMPTY_FC, tolerance: 0.5, maxzoom: 12 },
        roads: { type: "geojson", data: EMPTY_FC, tolerance: 0.5, maxzoom: 14, buffer: 32 },
        // committed terrarium DEM pyramid (z8-10, fetch_dem.py) — hillshade +
        // gentle 3D terrain. 256px tiles are fetched at map-zoom+1 and the
        // source under/overzooms outside 8..10.
        dem: { type: "raster-dem", tiles: [BASEMAP_BASE + "dem/{z}/{x}/{y}.png"],
          tileSize: 256, encoding: "terrarium", minzoom: 8, maxzoom: 10,
          bounds: [-124.0, 36.2, -120.3, 39.0] },
        sutro: { type: "geojson", data: BASEMAP_BASE + "sutro.json" }
      },
      // Night chart: dark ground so the fog banks and utilization colours glow.
      // Water keeps a clearly BLUE (if deep) tone against neutral-slate land, so
      // the shoreline reads at a glance and the submarine veil blends into water.
      layers: [
        // bg = water, not land: beyond the basemap bbox it's almost all ocean,
        // and a land-coloured bg leaves a visible seam at the water polygon edge
        { id: "bg", type: "background", paint: { "background-color": "#12324e" } },
        { id: "land", type: "fill", source: "land", paint: { "fill-color": "#242c33" } },
        // topography: hillshade relief over the land, under everything else;
        // strongest at the metro tiers, fading as street-level detail takes over
        { id: "hillshade", type: "hillshade", source: "dem",
          paint: { "hillshade-shadow-color": "#0a1016",
            "hillshade-highlight-color": "#46545f",
            "hillshade-exaggeration": ["interpolate", ["linear"], ["zoom"],
              9, 0.5, 12, 0.35, 13.5, 0.12] } },
        // airports — runway/terminal hints (no clutter; ICAO labels via markers).
        // NB deliberately BELOW water: a fill layer rendered under the airport
        // fills gets its low-zoom tile stencil corrupted (the z8 south-bay tile
        // paints parity-inverted: ponds fill, bay doesn't). Airports are all on
        // land, so water-over-airports is visually identical — and renders.
        { id: "airport-terminal", type: "fill", source: "airports",
          filter: ["==", ["get", "kind"], "terminal"],
          paint: { "fill-color": "#2c3b48", "fill-opacity": 0.7 } },
        { id: "airport-runway-fill", type: "fill", source: "airports",
          filter: ["==", ["get", "kind"], "runway"],
          paint: { "fill-color": "#34434f" } },
        { id: "airport-runway", type: "line", source: "airports",
          filter: ["==", ["get", "kind"], "runway_line"],
          layout: { "line-cap": "butt" },
          paint: { "line-color": "#3c4c59",
            "line-width": ["interpolate", ["linear"], ["zoom"], 9, 0.8, 12, 3, 15, 9] } },
        { id: "water", type: "fill", source: "water",
          paint: { "fill-color": "#12324e", "fill-outline-color": "#2e5273" } },
        { id: "trunk-casing", type: "line", source: "roads", minzoom: 9.5,
          filter: ["==", ["get", "class"], "trunk"],
          layout: { "line-cap": "round", "line-join": "round" },
          paint: { "line-color": "#141f28", "line-opacity": ["interpolate", ["linear"], ["zoom"], 9.5, 0, 11, 1],
            "line-width": ["interpolate", ["linear"], ["zoom"], 10, 1.2, 16, 4] } },
        { id: "trunk", type: "line", source: "roads", minzoom: 9.5,
          filter: ["==", ["get", "class"], "trunk"],
          layout: { "line-cap": "round", "line-join": "round" },
          paint: { "line-color": "#33434f", "line-opacity": ["interpolate", ["linear"], ["zoom"], 9.5, 0, 11, 1],
            "line-width": ["interpolate", ["linear"], ["zoom"], 10, 0.6, 16, 2.6] } },
        { id: "roads-casing", type: "line", source: "roads",
          filter: ["==", ["get", "class"], "motorway"],
          layout: { "line-cap": "round", "line-join": "round" },
          paint: { "line-color": "#141f28",
            "line-width": ["interpolate", ["linear"], ["zoom"], 8, 1.2, 12, 3.2, 16, 7] } },
        { id: "roads", type: "line", source: "roads",
          filter: ["==", ["get", "class"], "motorway"],
          layout: { "line-cap": "round", "line-join": "round" },
          paint: { "line-color": "#3d4f5d",
            "line-width": ["interpolate", ["linear"], ["zoom"], 8, 0.6, 12, 1.8, 16, 4.5] } },
        // Sutro Tower, comically large 3D (pieces from gen_sutro_tower.py) —
        // tilt the map (right-drag / the compass control) to see it stand up
        { id: "sutro-tower", type: "fill-extrusion", source: "sutro",
          paint: {
            "fill-extrusion-color": ["get", "color"],
            "fill-extrusion-base": ["get", "base"],
            "fill-extrusion-height": ["get", "height"],
            "fill-extrusion-opacity": 0.95 } }
      ]
    },
    // fadeDuration 0 works with the style's transition:0 above: a dasharray
    // step schedules extra frames through BOTH the paint transition AND the
    // 300ms symbol/pattern cross-fade — each alone keeps the 60fps loop.
    // Cost: collision-culled symbols (road shields) pop in/out instead of
    // fading — barely noticeable on this map.
    fadeDuration: 0,
    center: [-122.05, 37.6],
    zoom: 9.1,
    // load already tilted (looking north-ish across the terrain) so the 3D —
    // hills, Sutro Tower, billboarded critters — reads immediately
    pitch: 42,
    // NOT lower: at z8 the vendored MapLibre (5.6.0) mis-tessellates the tile
    // holding the south bay — fill parity inverts and the bay paints as land
    // (ponds fill, water doesn't). Data-side fixes (validity repair, grid
    // splits, tolerance/buffer) don't help; revisit on a MapLibre upgrade.
    minZoom: 9,
    maxZoom: 16.5,  // deep enough to inspect intra-site switch links / bundle strands
    maxBounds: [[-124.2, 36.0], [-120.1, 39.2]],
    attributionControl: false
  });
  window.__nmmap = map; // exposed for dev/screenshot tooling
  // compass shown (with pitch visualization): tilting is how you meet the tower
  map.addControl(new maplibregl.NavigationControl({ showCompass: true, visualizePitch: true }), "top-right");
  map.addControl(new maplibregl.AttributionControl({
    customAttribution: "Basemap © OpenStreetMap contributors · Terrain © Mapzen/AWS · SFMIX"
  }), "bottom-right");
  // gentle 3D terrain from the same DEM — puts the hills under the hillshade
  // (and Sutro Tower on an actual Mount Sutro) once the map is pitched.
  // Pitch-gated: terrain draping is by far the dominant per-frame render cost
  // (ablation: ~10-24x frame time on software GL), and near pitch 0 it is
  // visually indistinguishable from the flat hillshade. So terrain only mounts
  // while the view is meaningfully tilted; flattening the map (e.g. the
  // compass control's pitch reset) drops it and buys back the frame budget.
  // Toggled on pitchend (not per pitch frame) to avoid thrashing mid-gesture.
  var TERRAIN_PITCH = 15; // degrees; the load default (42) starts terrain on
  function syncTerrain() {
    var want = map.getPitch() >= TERRAIN_PITCH;
    if (want === !!map.getTerrain()) return;
    map.setTerrain(want ? { source: "dem", exaggeration: 1.3 } : null);
  }
  map.on("load", syncTerrain);
  map.on("pitchend", syncTerrain);

  var siteMarkers = [], deviceMarkers = [], decoTextMarkers = [], metroMarkers = [],
    airportMarkers = [], siteBoxMarkers = [];

  map.on("load", function () {
    // roads/airports: feed the (style-declared-empty) sources from the shared
    // prefetch — the same parsed object also drives the shield/label builders
    // in init(), so each file is fetched and parsed exactly once.
    PREFETCH.roads.then(function (fc) { map.getSource("roads").setData(fc); })
      .catch(function () {});
    PREFETCH.airports.then(function (fc) { map.getSource("airports").setData(fc); })
      .catch(function () {});
    PREFETCH.structure
      .then(function (structure) { init(structure); })
      .catch(function (e) { showStatus(t("live stats unavailable")); console.error(e); });
  });

  var STATE = { generation: null };

  function init(structure) {
    STATE.generation = structure.generation;
    var src = buildSources(structure);
    STATE.flows = src.flows; STATE.metroFlows = src.metroFlows;


    map.addSource("cables", { type: "geojson", data: src.cables, promoteId: "sid" });
    map.addSource("cable-media", { type: "geojson", data: src.media });
    map.addSource("stations", { type: "geojson", data: src.stations, promoteId: "code" });
    map.addSource("devices", { type: "geojson", data: src.devices });
    map.addSource("metro-cables", { type: "geojson", data: src.metroCables, promoteId: "id" });
    map.addSource("metro-cable-media", { type: "geojson", data: src.metroMedia });
    map.addSource("metro-stations", { type: "geojson", data: src.metroStations, promoteId: "metro" });
    STATION_KEYS = Object.keys(structure.sites);
    METRO_KEYS = src.metroStations.features.map(function (f) { return f.properties.metro; });
    map.addSource("buildings", { type: "geojson", data: src.buildings });
    map.addSource("drops", { type: "geojson", data: src.drops, promoteId: "id" });

    // NB: a zoom `interpolate` must be the OUTERMOST expression — it cannot be
    // nested inside a multiply. So the per-feature property math lives in each
    // zoom stop's output instead.
    var offsetExpr = OFFSET_EXPR;
    function widthExprAdd(add) {
      return ["interpolate", ["linear"], ["zoom"],
        8, ["+", ["*", ["get", "weight"], 0.8], add],
        12, ["+", ["*", ["get", "weight"], 1.5], add],
        16, ["+", ["*", ["get", "weight"], 2.8], add]];
    }
    var widthExpr = widthExprAdd(0);

    // site building footprints — fade in at the device tier as the "box" that
    // contains the switches (below cables so links route to/over the box).
    // minzoom matches the 0-opacity end of each fade: an opacity-0 layer still
    // costs evaluation + draw every frame, minzoom skips it entirely.
    map.addLayer({
      id: "site-building", type: "fill", source: "buildings", minzoom: EXPAND_ZOOM - 0.5,
      paint: { "fill-color": "#2a3a47", "fill-outline-color": "#4d6375",
        "fill-opacity": ["interpolate", ["linear"], ["zoom"], EXPAND_ZOOM - 0.5, 0, EXPAND_ZOOM + 0.5, 0.85] }
    });
    map.addLayer({
      id: "site-building-outline", type: "line", source: "buildings", minzoom: EXPAND_ZOOM - 0.5,
      paint: { "line-color": "#4d6375", "line-width": 1.2,
        "line-opacity": ["interpolate", ["linear"], ["zoom"], EXPAND_ZOOM - 0.5, 0, EXPAND_ZOOM + 0.5, 0.9] }
    });
    // passive-site cross-connect: at a switchless site the inter cables land on the
    // box edge and this bridges them across the box (no device to drop to). Drawn
    // over the box, fading in with it.
    map.addLayer({
      id: "cable-crossconnect", type: "line", source: "cables", minzoom: EXPAND_ZOOM - 0.5,
      filter: ["==", ["get", "scope"], "crossconnect"],
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": "#9fb8c6", "line-width": 2, "line-dasharray": [1, 1.2],
        "line-opacity": ["interpolate", ["linear"], ["zoom"], EXPAND_ZOOM - 0.5, 0, EXPAND_ZOOM + 0.5, 0.9] }
    });

    // casing (dark under-stroke) for inter cables
    map.addLayer({
      id: "cables-casing", type: "line", source: "cables",
      filter: ["==", ["get", "scope"], "inter"],
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": "#0b3640", "line-opacity": 0.9,
        "line-offset": offsetExpr,
        "line-width": widthExprAdd(2.2) }
    });
    // down links (grey dashed)
    map.addLayer({
      id: "cables-down", type: "line", source: "cables",
      filter: ["all", ["==", ["get", "scope"], "inter"], ["==", ["get", "status"], "down"]],
      layout: { "line-cap": "butt", "line-join": "round" },
      paint: { "line-color": "#9aa4aa", "line-dasharray": [1.5, 1.5],
        "line-offset": offsetExpr, "line-width": widthExpr }
    });
    // planned / not-yet-in-service links (delivered dark fibre awaiting its
    // onward span, or future orders): long slate-blue dashes, no flow stripes
    map.addLayer({
      id: "cables-planned", type: "line", source: "cables",
      filter: ["all", ["==", ["get", "scope"], "inter"], ["==", ["get", "status"], "planned"]],
      layout: { "line-cap": "butt", "line-join": "round" },
      paint: { "line-color": PLANNED_COLOR, "line-dasharray": [2.4, 1.8],
        "line-offset": offsetExpr, "line-width": widthExpr }
    });
    // approximate links (dotted, still util-coloured)
    map.addLayer({
      id: "cables-approx", type: "line", source: "cables",
      filter: ["all", ["==", ["get", "scope"], "inter"], ["==", ["get", "approximate"], true],
        ["==", ["get", "status"], "up"]],
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": UTIL_COLOR_EXPR, "line-dasharray": [0.4, 1.8],
        "line-offset": offsetExpr, "line-width": widthExpr }
    });
    // normal links (solid, util-coloured)
    map.addLayer({
      id: "cables-line", type: "line", source: "cables",
      filter: ["all", ["==", ["get", "scope"], "inter"], ["==", ["get", "approximate"], false],
        ["==", ["get", "status"], "up"]],
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": UTIL_COLOR_EXPR, "line-offset": offsetExpr, "line-width": widthExpr }
    });
    // barber-pole flow stripes: an animated dash riding each live link toward
    // its dominant traffic direction (see addFlowLayers / the ticker below)
    map.addSource("flows", { type: "geojson", data: src.flows, promoteId: "id" });
    addFlowLayers("flows", "flow", function (add) {
      return ["interpolate", ["linear"], ["zoom"],
        8, ["+", ["*", ["get", "weight"], 0.3], add],
        12, ["+", ["*", ["get", "weight"], 0.55], add],
        16, ["+", ["*", ["get", "weight"], 1.0], add]];
    }, offsetExpr);
    // intra-site links (only visible zoomed in)
    map.addLayer({
      id: "cables-intra", type: "line", source: "cables", minzoom: EXPAND_ZOOM - 0.5,
      filter: ["==", ["get", "scope"], "intra"],
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": UTIL_COLOR_EXPR, "line-width": 2.2, "line-dasharray": [2, 1],
        "line-offset": offsetExpr,
        "line-opacity": ["interpolate", ["linear"], ["zoom"], EXPAND_ZOOM - 0.5, 0, EXPAND_ZOOM + 0.5, 0.9] }
    });
    // invisible fat hit target
    map.addLayer({
      id: "cables-hit", type: "line", source: "cables",
      layout: { "line-cap": "round" },
      // Fat and forgiving when zoomed out (thin cables are hard to tap); narrows
      // deep in so each parallel-link strand sits in its own hit lane and is
      // individually selectable (strands are ~5px apart at max zoom).
      paint: { "line-color": "#000", "line-opacity": 0, "line-offset": offsetExpr,
        "line-width": ["interpolate", ["linear"], ["zoom"], 8, 18, 13, 15, 15, 8, 16.5, 4.5] }
    });

    // selection highlight — the clicked cable's strands drawn bright on top while
    // the rest are dimmed (see selectFeature). Filter matches nothing until a click.
    map.addLayer({
      id: "cables-highlight", type: "line", source: "cables",
      filter: ["==", ["get", "id"], "__none__"],
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": ["case", ["==", ["get", "status"], "planned"], PLANNED_COLOR,
          UTIL_COLOR_EXPR],
        "line-offset": offsetExpr,
        "line-width": widthExprAdd(1.6) }
    });

    // stations: outer ring + inner dot
    map.addLayer({
      id: "stations-ring", type: "circle", source: "stations",
      paint: {
        "circle-radius": ["interpolate", ["linear"], ["zoom"], 8, 5, 12, 8, 15, 11],
        "circle-color": "#ffffff",
        "circle-stroke-color": ["case", ["boolean", ["feature-state", "dim"], false], "#b7bcc0", "#0b3640"],
        "circle-stroke-width": ["interpolate", ["linear"], ["zoom"], 8, 2, 15, 3.5],
        // roundel gives way to the building box + switches at the device tier;
        // also dims when another link is isolated. Zoom interpolate stays OUTERMOST;
        // the dim case is baked into the pre-device-tier stop.
        "circle-opacity": ["interpolate", ["linear"], ["zoom"],
          EXPAND_ZOOM - 0.5, ["case", ["boolean", ["feature-state", "dim"], false], 0.15, 1],
          EXPAND_ZOOM + 0.5, 0],
        "circle-stroke-opacity": ["interpolate", ["linear"], ["zoom"],
          EXPAND_ZOOM - 0.5, ["case", ["boolean", ["feature-state", "dim"], false], 0.2, 1],
          EXPAND_ZOOM + 0.5, 0]
      }
    });
    map.addLayer({
      // maxzoom = the fade-out end; NB stations-ring stays ungated — it's a
      // PICK_LAYERS click target and must remain queryable at all zooms
      id: "stations-dot", type: "circle", source: "stations", maxzoom: EXPAND_ZOOM + 0.5,
      paint: {
        "circle-radius": ["interpolate", ["linear"], ["zoom"], 8, 1.8, 15, 3.2],
        "circle-color": "#0b3640",
        "circle-opacity": ["interpolate", ["linear"], ["zoom"],
          EXPAND_ZOOM - 0.5, ["case", ["boolean", ["feature-state", "dim"], false], 0.15, 1],
          EXPAND_ZOOM + 0.5, 0]
      }
    });
    // device drops — short stubs from the site centroid to each switch, so cables
    // terminate on the specific device once the building box is open
    map.addLayer({
      id: "cable-drops", type: "line", source: "drops", minzoom: EXPAND_ZOOM - 0.5,
      layout: { "line-cap": "round" },
      paint: {
        "line-color": ["case", ["==", ["get", "status"], "down"], "#9aa4aa",
          ["==", ["get", "status"], "planned"], PLANNED_COLOR, UTIL_COLOR_EXPR],
        "line-width": ["interpolate", ["linear"], ["zoom"], EXPAND_ZOOM, 1.5, 16, 3],
        "line-opacity": ["interpolate", ["linear"], ["zoom"], EXPAND_ZOOM - 0.3, 0, EXPAND_ZOOM + 0.6, 0.95]
      }
    });
    // devices (fade in when zoomed into a site)
    map.addLayer({
      id: "devices-dot", type: "circle", source: "devices", minzoom: EXPAND_ZOOM - 0.5,
      paint: {
        "circle-radius": ["interpolate", ["linear"], ["zoom"], EXPAND_ZOOM, 3, 15, 6],
        "circle-color": "#137a8a", "circle-stroke-color": "#fff", "circle-stroke-width": 2,
        "circle-opacity": ["interpolate", ["linear"], ["zoom"], EXPAND_ZOOM - 0.5, 0, EXPAND_ZOOM + 0.5, 1],
        "circle-stroke-opacity": ["interpolate", ["linear"], ["zoom"], EXPAND_ZOOM - 0.5, 0, EXPAND_ZOOM + 0.5, 1]
      }
    });

    // metro trunk cables (overview tier). NB: the zoom interpolate must be the
    // OUTERMOST expression — bake the casing/highlight width bump into each stop.
    function metroWidthAdd(add) {
      return ["interpolate", ["linear"], ["zoom"],
        8, ["+", ["*", ["get", "weight"], 1.3], add],
        10.6, ["+", ["*", ["get", "weight"], 1.8], add]];
    }
    map.addLayer({
      id: "metro-casing", type: "line", source: "metro-cables",
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": "#0b3640", "line-opacity": 0.9,
        "line-width": metroWidthAdd(2.4) }
    });
    map.addLayer({
      id: "metro-line", type: "line", source: "metro-cables",
      filter: ["!=", ["get", "status"], "planned"],
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": UTIL_COLOR_EXPR, "line-width": metroWidthAdd(0) }
    });
    // planned metro trunk (every member span still awaiting turn-up)
    map.addLayer({
      id: "metro-planned", type: "line", source: "metro-cables",
      filter: ["==", ["get", "status"], "planned"],
      layout: { "line-cap": "butt", "line-join": "round" },
      paint: { "line-color": PLANNED_COLOR, "line-dasharray": [2.4, 1.8],
        "line-width": metroWidthAdd(0) }
    });
    map.addSource("metro-flows", { type: "geojson", data: src.metroFlows, promoteId: "id" });
    addFlowLayers("metro-flows", "metro-flow", function (add) {
      return ["interpolate", ["linear"], ["zoom"],
        8, ["+", ["*", ["get", "weight"], 0.5], add],
        10.6, ["+", ["*", ["get", "weight"], 0.7], add]];
    }, 0);
    map.addLayer({
      id: "metro-highlight", type: "line", source: "metro-cables",
      filter: ["==", ["get", "id"], "__none__"],
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": ["case", ["==", ["get", "status"], "planned"], PLANNED_COLOR,
          UTIL_COLOR_EXPR],
        "line-width": metroWidthAdd(1.6) }
    });
    map.addLayer({
      id: "metro-stations-ring", type: "circle", source: "metro-stations",
      paint: {
        "circle-radius": ["interpolate", ["linear"], ["zoom"], 8, 8, 10.6, 12],
        "circle-color": ["case", ["boolean", ["feature-state", "dim"], false], "#c3c7cb", "#0b3640"],
        "circle-stroke-color": "#ffffff", "circle-stroke-width": 3,
        "circle-opacity": ["case", ["boolean", ["feature-state", "dim"], false], 0.25, 1],
        "circle-stroke-opacity": ["case", ["boolean", ["feature-state", "dim"], false], 0.25, 1]
      }
    });
    map.addLayer({
      id: "metro-stations-dot", type: "circle", source: "metro-stations",
      paint: { "circle-radius": 3.2, "circle-color": "#ffffff",
        "circle-opacity": ["case", ["boolean", ["feature-state", "dim"], false], 0.25, 1] }
    });

    addLabels(structure);
    // builders consume the SAME parsed objects the sources were fed from —
    // called from init so their layers/markers slot under site-building etc.
    PREFETCH.airports.then(addAirportLabels).catch(function () {});
    PREFETCH.roads.then(addRoadShields).catch(function () {});
    addWaterTreatment();
    if (DECOR_URL) addDecorations();
    wireInteractions();
    wireLegend();
    infoPane.init();
    setTier();
    map.on("zoom", setTier);

    pollTraffic();
    setInterval(pollTraffic, POLL_MS);
  }

  // ---- barber-pole traffic flow -------------------------------------------
  // A pale dashed stripe rides each live link, animated stepwise through
  // FLOW_SEQ so the dashes crawl along the line — toward the line's a->z end
  // on the forward layer, backwards on the reverse layer. Which layer a link
  // lands on comes from its traffic (dir: 1 = a->z dominates = out>=in on the
  // a side, -1 = z->a). line-dasharray can't be data-driven, hence two layers.
  var FLOW_SEQ = [
    [0, 4, 3], [0.5, 4, 2.5], [1, 4, 2], [1.5, 4, 1.5], [2, 4, 1], [2.5, 4, 0.5], [3, 4, 0],
    [0, 0.5, 3, 3.5], [0, 1, 3, 3], [0, 1.5, 3, 2.5], [0, 2, 3, 2],
    [0, 2.5, 3, 1.5], [0, 3, 3, 1], [0, 3.5, 3, 0.5]
  ];
  function addFlowLayers(source, idBase, widthFn, offsetExpr) {
    [1, -1].forEach(function (dir) {
      map.addLayer({
        id: idBase + (dir === 1 ? "-fwd" : "-rev"), type: "line", source: source,
        filter: ["==", ["get", "dir"], dir],
        layout: { "line-cap": "butt", "line-join": "round" },
        paint: { "line-color": FLOW_STRIPE_EXPR, "line-opacity": 0.85,
          "line-offset": offsetExpr, "line-width": widthFn(0.4),
          "line-dasharray": FLOW_SEQ[0] }
      });
    });
  }
  // ONE shared animation clock (barber pole + fog): every animated mutation
  // happens inside the same tick, so they all share a single repaint and the
  // map renders at ~11fps while animating instead of a continuous 60fps.
  var flowPhase = 0;
  var FOG_TICK = null;  // registered by addFog, driven by this same clock
  var DECO_TICK = null; // registered by addDecorations (roaming cattle)
  setInterval(function () {
    if (document.hidden) return;
    // While the camera is moving (user gesture or easeTo/zoomTo animation) the
    // map already repaints every frame — skip the tick entirely so the dash
    // stepping, fog redraw and cattle setData don't add main-thread/worker work
    // (source re-tiling!) to every interaction frame. The animations freeze for
    // the duration of the gesture and resume on the next tick after moveend.
    if (map.isMoving()) return;
    flowPhase = (flowPhase + 1) % FLOW_SEQ.length;
    var fwd = FLOW_SEQ[flowPhase], rev = FLOW_SEQ[FLOW_SEQ.length - 1 - flowPhase];
    [["flow-fwd", fwd], ["flow-rev", rev], ["metro-flow-fwd", fwd], ["metro-flow-rev", rev]]
      .forEach(function (p) {
        if (map.getLayer(p[0])) map.setPaintProperty(p[0], "line-dasharray", p[1]);
      });
    if (FOG_TICK) FOG_TICK();
    if (DECO_TICK) DECO_TICK();
  }, 90);

  // Toggle metro / site / device tiers by zoom (layer visibility + markers).
  var SITE_LAYERS = ["cables-casing", "cables-down", "cables-planned", "cables-approx",
    "cables-line", "cables-hit", "cable-water", "cable-submarine", "cable-ripple",
    "cable-drops", "stations-ring", "stations-dot", "flow-fwd", "flow-rev"];
  // the metro water veil MUST toggle with its tier: it's wider than the site-tier
  // veil and sits above the site flow stripes, so left visible it drowns the
  // barber pole over water crossings at close zoom
  var METRO_LAYERS = ["metro-casing", "metro-line", "metro-planned", "metro-stations-ring",
    "metro-stations-dot", "metro-flow-fwd", "metro-flow-rev", "metro-submarine",
    "metro-water", "metro-ripple"];
  function setVis(ids, on) {
    ids.forEach(function (id) { if (map.getLayer(id)) map.setLayoutProperty(id, "visibility", on ? "visible" : "none"); });
  }
  // setTier runs on EVERY 'zoom' event (i.e. every animation frame of a zoom);
  // memoize on the tier tuple so the marker loops and ~25 setLayoutProperty
  // calls only happen when a tier boundary is actually crossed. Callers that
  // create markers after the fact (airport labels, structure reload) pass
  // force=true since new markers start hidden regardless of the cached state.
  var tierKey = null;
  function setTier(force) {
    var z = map.getZoom();
    var metro = z < METRO_ZOOM;
    // site name: beside the roundel at the site tier, then ABOVE the building box
    // once the box opens (device tier) — never overlapping the switches inside
    var besideOn = !metro && z < EXPAND_ZOOM;
    var aboveBoxOn = z >= EXPAND_ZOOM;
    var deviceOn = z >= DEVICE_LABEL_ZOOM;
    var showIcao = z >= ICAO_ZOOM;
    var key = "" + metro + besideOn + aboveBoxOn + deviceOn + showIcao;
    if (key === tierKey && force !== true) return;
    tierKey = key;
    setVis(METRO_LAYERS, metro);
    setVis(SITE_LAYERS, !metro);
    siteMarkers.forEach(function (m) { m.getElement().style.display = besideOn ? "" : "none"; });
    siteBoxMarkers.forEach(function (m) { m.getElement().style.display = aboveBoxOn ? "" : "none"; });
    metroMarkers.forEach(function (m) { m.getElement().style.display = metro ? "" : "none"; });
    // device dots appear with the building box; their labels wait until there's
    // room so adjacent switch captions don't collide
    deviceMarkers.forEach(function (m) { m.getElement().style.display = deviceOn ? "" : "none"; });
    airportMarkers.forEach(function (m) { m.getElement().style.display = showIcao ? "" : "none"; });
  }

  // ---- HTML label markers -------------------------------------------------
  function addLabels(structure) {
    // metro labels (overview tier)
    var metroPts = {};
    Object.keys(structure.sites).forEach(function (code) {
      var s = structure.sites[code], name = s.metro || code;
      var m = metroPts[name] || (metroPts[name] = { lats: [], lons: [] });
      m.lats.push(s.lat); m.lons.push(s.lon);
    });
    Object.keys(metroPts).forEach(function (name) {
      var m = metroPts[name];
      var d = document.createElement("div");
      d.className = "nm-label nm-label-site";
      d.innerHTML = '<span class="nm-code">' + name + "</span>";
      var mk = new maplibregl.Marker({ element: d, anchor: "left", offset: [14, 0] })
        .setLngLat([avg(m.lons), avg(m.lats)]).addTo(map);
      mk.getElement().style.display = "none";
      metroMarkers.push(mk);
    });
    Object.keys(structure.sites).forEach(function (code) {
      var s = structure.sites[code];
      var d = document.createElement("div");
      d.className = "nm-label nm-label-site";
      d.innerHTML = '<span class="nm-code">' + code + '</span> ' +
        '<span class="nm-name">' + (s.name || "") + "</span>";
      var m = new maplibregl.Marker({ element: d, anchor: "left", offset: [12, 0] })
        .setLngLat([s.lon, s.lat]).addTo(map);
      siteMarkers.push(m);
      // device-tier label: same site name sitting ABOVE the building box, clear
      // of the switches (below their dots) and their captions
      var b = document.createElement("div");
      b.className = "nm-label nm-label-site nm-label-box";
      b.innerHTML = '<span class="nm-code">' + code + '</span> ' +
        '<span class="nm-name">' + (s.name || "") + "</span>";
      // the title bubble is clickable (CSS re-enables pointer events on it) —
      // opens the same site detail as the building footprint / roundel.
      (function (code, s) {
        b.addEventListener("click", function (ev) {
          ev.stopPropagation();
          clearSelection();
          var d = siteDetailFromProps(siteProps(code, s));
          if (d) infoPane.showDetail(d.title, d.body);
        });
      })(code, s);
      var bm = new maplibregl.Marker({ element: b, anchor: "bottom", offset: [0, -26] })
        .setLngLat([s.lon, s.lat]).addTo(map);
      bm.getElement().style.display = "none";
      siteBoxMarkers.push(bm);
      (s.devices || []).forEach(function (dev) {
        var dd = document.createElement("div");
        dd.className = "nm-label nm-label-device";
        dd.textContent = dev.id.split(".")[0];
        // caption below each switch dot — clears the dot, the intra-link line,
        // and neighbouring switches in the in-building grid
        var dm = new maplibregl.Marker({ element: dd, anchor: "top", offset: [0, 7] })
          .setLngLat([dev.dlon, dev.dlat]).addTo(map);
        dm.getElement().style.display = "none";
        deviceMarkers.push(dm);
      });
    });
  }
  // ---- airport ICAO labels (tiny, zoom-gated) -----------------------------
  var ICAO_ZOOM = 10.5;
  function addAirportLabels(fc) {
    fc.features.forEach(function (f) {
      if (f.properties.kind !== "aerodrome" || !f.properties.icao) return;
      var d = document.createElement("div");
      d.className = "nm-label nm-label-icao";
      d.textContent = f.properties.icao;
      var m = new maplibregl.Marker({ element: d, anchor: "center" })
        .setLngLat(f.geometry.coordinates).addTo(map);
      m.getElement().style.display = "none";
      airportMarkers.push(m);
    });
    setTier(true); // force: the new markers start hidden regardless of tier
  }

  // ---- highway shields ------------------------------------------------------
  // Small route badges (I/US/CA) drawn with canvas text — no glyph server
  // needed — and placed ALONG the road lines as a symbol layer, so MapLibre's
  // collision engine spaces them out and drops any that would overlap other
  // symbols. Positioning is therefore fully dynamic with zoom/pan.
  function addRoadShields(fc) {
        // Only the few LONGEST segments per route get a shield: freeways come as
        // hundreds of short parallel-carriageway fragments, and labelling each
        // one reads as a breadcrumb trail (880 especially).
        var byRef = {};
        fc.features.forEach(function (f) {
          var ref = (f.properties.ref || "").trim();
          // mainline routes only — "I 205 Bus" / "US 101 Spur" / detours would
          // mint duplicate shields in odd places
          if (!/^(I|US|CA) \d+$/.test(ref)) return;
          (byRef[ref] = byRef[ref] || []).push(f);
        });
        function segLen(f) {
          var c = f.geometry.coordinates, l = 0;
          for (var i = 1; i < c.length; i++) {
            var dx = c[i][0] - c[i - 1][0], dy = c[i][1] - c[i - 1][1];
            l += Math.sqrt(dx * dx + dy * dy);
          }
          return l;
        }
        // Shields are POINTS sampled every STEP degrees of cumulative length
        // along a route's segments (longest first), deduped by proximity across
        // the whole route. Line-placement per segment misses fragmented routes
        // entirely (US 101 is 1100+ short carriageway pieces, none long enough
        // to earn a shield) and doubles up on parallel carriageways.
        var STEP = 0.12, MIN_APART = 0.10, PER_REF_CAP = 24;
        var shieldPoints = [];
        Object.keys(byRef).forEach(function (ref) {
          var name = "shield-" + ref;
          if (!map.hasImage(name)) map.addImage(name, shieldImage(ref), { pixelRatio: SHIELD_RES });
          byRef[ref].sort(function (a, b) { return segLen(b) - segLen(a); });
          var kept = [];
          // acc carries ACROSS segments: fragmented routes (US 101 is 1100+
          // short carriageway pieces) would otherwise never accumulate a STEP
          var acc = STEP / 2;
          byRef[ref].forEach(function (f) {
            if (kept.length >= PER_REF_CAP) return;
            var c = f.geometry.coordinates;
            for (var i = 1; i < c.length && kept.length < PER_REF_CAP; i++) {
              var dx = c[i][0] - c[i - 1][0], dy = c[i][1] - c[i - 1][1];
              acc += Math.sqrt(dx * dx + dy * dy);
              if (acc < STEP) continue;
              acc = 0;
              var p = c[i];
              var clear = kept.every(function (k) {
                return Math.abs(k[0] - p[0]) + Math.abs(k[1] - p[1]) > MIN_APART;
              });
              if (clear) {
                kept.push(p);
                shieldPoints.push({ type: "Feature", properties: { ref: ref },
                  geometry: { type: "Point", coordinates: p } });
              }
            }
          });
        });
        map.addSource("shield-roads", { type: "geojson",
          data: { type: "FeatureCollection", features: shieldPoints } });
        map.addLayer({
          id: "road-shields", type: "symbol", source: "shield-roads", minzoom: 10,
          layout: {
            "icon-image": ["concat", "shield-", ["get", "ref"]],
            "icon-size": ["interpolate", ["linear"], ["zoom"], 10, 0.8, 12.5, 1]
            // default point placement, viewport-aligned; collision thins any
            // remaining bunching against other shields
          },
          paint: { "icon-opacity": ["interpolate", ["linear"], ["zoom"], 10, 0, 10.8, 0.85] }
        }, map.getLayer("site-building") ? "site-building" : undefined);
  }
  // Shield badges follow the real sign shapes — Interstate shield with the red
  // chief, US-route white badge, California's green miner's-spade — in muted
  // night-theme takes on the official palettes.
  var SHIELD_RES = 3;
  function shieldImage(ref) {
    var parts = ref.split(/\s+/), sys = parts[0], num = parts[1] || parts[0];
    var S = SHIELD_RES;
    var probe = document.createElement("canvas").getContext("2d");
    var font = "700 " + (num.length >= 3 ? 8 : 9.5) * S + "px system-ui, sans-serif";
    probe.font = font;
    var W = Math.round(Math.max(19 * S, probe.measureText(num).width + 8 * S));
    var H = 20 * S;
    var c = document.createElement("canvas"); c.width = W; c.height = H;
    var g = c.getContext("2d");
    g.lineJoin = "round";
    function px(x, y) { return [x * W, y * H]; }
    function trace(pts) {
      // pts: ["M",x,y] | ["C",x1,y1,x2,y2,x,y] | ["Q",x1,y1,x,y] in unit coords
      g.beginPath();
      pts.forEach(function (p) {
        if (p[0] === "M") g.moveTo.apply(g, px(p[1], p[2]));
        else if (p[0] === "Q") g.quadraticCurveTo.apply(g, px(p[1], p[2]).concat(px(p[3], p[4])));
        else g.bezierCurveTo.apply(g, px(p[1], p[2]).concat(px(p[3], p[4]), px(p[5], p[6])));
      });
      g.closePath();
    }
    var textY;
    if (sys === "I") {
      // interstate: shield, red chief over blue field, white rim
      trace([["M", 0.07, 0.10], ["Q", 0.5, 0.01, 0.93, 0.10],
        ["C", 1.03, 0.34, 0.90, 0.74, 0.5, 0.98],
        ["C", 0.10, 0.74, -0.03, 0.34, 0.07, 0.10]]);
      g.fillStyle = "#2a4a70"; g.fill();
      g.save(); g.clip();
      g.fillStyle = "#7d3540"; g.fillRect(0, 0, W, 0.30 * H);
      g.restore();
      g.lineWidth = 1.3 * S; g.strokeStyle = "#c3cfda"; g.stroke();
      g.fillStyle = "#e8eef4"; textY = 0.63 * H;
    } else if (sys === "CA") {
      // california: green spade, handle notch at the top
      trace([["M", 0.10, 0.13], ["Q", 0.34, 0.17, 0.5, 0.26], ["Q", 0.66, 0.17, 0.90, 0.13],
        ["C", 1.02, 0.44, 0.87, 0.78, 0.5, 0.98],
        ["C", 0.13, 0.78, -0.02, 0.44, 0.10, 0.13]]);
      g.fillStyle = "#1f4a3a"; g.fill();
      g.lineWidth = 1.3 * S; g.strokeStyle = "#6b9c81"; g.stroke();
      g.fillStyle = "#e8eef4"; textY = 0.62 * H;
    } else {
      // US route: the white cut-corner badge, dark numerals
      trace([["M", 0.10, 0.06], ["Q", 0.5, 0.12, 0.90, 0.06],
        ["C", 1.0, 0.16, 0.98, 0.38, 0.90, 0.52],
        ["C", 0.80, 0.72, 0.66, 0.88, 0.5, 0.97],
        ["C", 0.34, 0.88, 0.20, 0.72, 0.10, 0.52],
        ["C", 0.02, 0.38, 0.0, 0.16, 0.10, 0.06]]);
      g.fillStyle = "#c8d1d7"; g.fill();
      g.lineWidth = 1.1 * S; g.strokeStyle = "#7f8b94"; g.stroke();
      g.fillStyle = "#232c33"; textY = 0.52 * H;
    }
    g.font = font; g.textAlign = "center"; g.textBaseline = "middle";
    g.fillText(num, W / 2, textY);
    return g.getImageData(0, 0, W, H);
  }

  // ---- water: a subtle ripple texture on the bay, reused over undersea cable --
  // A submarine cable span reads as "submerged": the util colour is muted toward
  // the water tone and the SAME ripple texture that styles the bay is laid over
  // it, so it blends into the water instead of contrasting with it.
  function addWaterTreatment() {
    // the veil sits over the cable body (submerged read) but UNDER the barber-
    // pole stripes — at close zoom the veil grows to ~9-18px and would swallow
    // the flow animation entirely if it were painted on top
    var beforeId = map.getLayer("flow-fwd") ? "flow-fwd"
      : map.getLayer("stations-ring") ? "stations-ring" : undefined;
    // depth shade: slightly deeper water tone over the crossing (very soft) —
    // all three treatment tones are keyed to the night water (#12324e): the
    // shade sits a step darker, the veil a step lighter, crests lighter still
    map.addLayer({
      id: "cable-submarine", type: "line", source: "cable-media",
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": "#0b2138", "line-opacity": 0.6, "line-offset": OFFSET_EXPR,
        "line-width": ["interpolate", ["linear"], ["zoom"], 8, 6, 14, 18] }
    }, beforeId);
    // mute the cable's util colour toward the water tone (submerged look) — the
    // blue veil sits OVER the cable so the crossing clearly reads as under water
    map.addLayer({
      id: "cable-water", type: "line", source: "cable-media",
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": "#2c5478", "line-opacity": 0.7, "line-offset": OFFSET_EXPR,
        "line-width": ["interpolate", ["linear"], ["zoom"], 8, 3, 14, 9] }
    }, beforeId);
    // ripple texture over the span (matches the bay); replaces the mute layer's
    // flat look with the same wave texture the water fill uses
    map.addLayer({
      id: "cable-ripple", type: "line", source: "cable-media",
      layout: { "line-cap": "butt", "line-join": "round" },
      paint: { "line-color": "#8fb4d0", "line-opacity": 0.7, "line-width": 2, "line-offset": OFFSET_EXPR,
        "line-dasharray": [0.6, 1.8] }
    }, beforeId);
    // METRO tier: the same submerged veil + waves over metro trunks that cross the
    // bay, so the zoomed-out inter-metro view also reads submarine (no per-cable
    // media at that tier otherwise). Sits over metro-line, below metro stations.
    var metroBefore = map.getLayer("metro-stations-ring") ? "metro-stations-ring" : undefined;
    // depth shade for the metro tier too — without it (and with the veil
    // narrower than the fat metro trunk) the util colour bled around the veil
    // edges and the crossing read painted-on rather than submerged
    map.addLayer({
      id: "metro-submarine", type: "line", source: "metro-cable-media",
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": "#0b2138", "line-opacity": 0.6,
        "line-width": ["interpolate", ["linear"], ["zoom"], 8, 14, 10.6, 22] }
    }, metroBefore);
    map.addLayer({
      id: "metro-water", type: "line", source: "metro-cable-media",
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": "#2c5478", "line-opacity": 0.7,
        "line-width": ["interpolate", ["linear"], ["zoom"], 8, 10, 10.6, 16] }
    }, metroBefore);
    map.addLayer({
      id: "metro-ripple", type: "line", source: "metro-cable-media",
      layout: { "line-cap": "butt", "line-join": "round" },
      paint: { "line-color": "#8fb4d0", "line-opacity": 0.7, "line-width": 6 }
    }, metroBefore);
    PREFETCH.waterTexture.then(function (sp) {
      if (!map.hasImage("water-texture")) map.addImage("water-texture", sp.image, { pixelRatio: sp.pixelRatio });
      if (map.getLayer("metro-ripple")) {
        map.setPaintProperty("metro-ripple", "line-pattern", "water-texture");
        map.setPaintProperty("metro-ripple", "line-width",
          ["interpolate", ["linear"], ["zoom"], 8, 9, 10.6, 16]);
      }
      // ripples on the cable span
      map.setPaintProperty("cable-ripple", "line-pattern", "water-texture");
      map.setPaintProperty("cable-ripple", "line-width",
        ["interpolate", ["linear"], ["zoom"], 8, 5, 14, 14]);
      // texture the bay itself (subtle), just above the flat water fill (which
      // itself sits above the airports — see the layer-order note in the style)
      if (!map.getLayer("water-texture")) {
        map.addLayer({
          id: "water-texture", type: "fill", source: "water",
          paint: { "fill-pattern": "water-texture", "fill-opacity": 0.75 }
        }, map.getLayer("trunk-casing") ? "trunk-casing" : beforeId);
      }
    }).catch(function () {});
  }

  // ---- decorations (whimsy) ----------------------------------------------
  function addDecorations() {
    PREFETCH.decorations
      .then(function (deco) {
        var points = { type: "FeatureCollection", features: [] };
        var icons = {};
        var roamers = []; // features that wander (cattle) — see DECO_TICK below
        deco.features.forEach(function (f) {
          if (f.geometry.type === "Point") {
            points.features.push(f);
            if (f.properties.icon) icons[f.properties.icon] = true;
            if (f.properties.label) addDecoText(f);
            if (f.properties.roam) {
              var c = f.geometry.coordinates;
              // per-critter phases spread the herd out; radius is in degrees
              // (~0.012° ≈ 1km — cartoonishly large, matching the giant-object
              // scale of the other decorations). Lat swing is squished so they
              // graze in an ellipse rather than a circle.
              roamers.push({ f: f, lng0: c[0], lat0: c[1],
                r: f.properties.roam === true ? 0.012 : f.properties.roam,
                p1: (roamers.length * 1.7) % 6.283, p2: (roamers.length * 2.9) % 6.283,
                w1: 0.9 + (roamers.length % 3) * 0.15, w2: 0.6 + (roamers.length % 2) * 0.2,
                base: f.properties.rotation || 0 });
            }
          } else if (f.properties.kind === "image-overlay" && f.properties.icon === "fog") {
            addFog(f);
          }
        });
        map.addSource("decorations", { type: "geojson", data: points });
        // roaming cattle: nudge each roamer along a slow Lissajous path every
        // tick and re-feed the source. Deterministic (no per-frame randomness),
        // so it's smooth and cheap at the shared ~11fps clock. A small heading
        // sway suggests an ambling graze — we do NOT flip to face direction, as
        // that would need a mirrored sprite (a 180° icon-rotate is upside-down).
        if (roamers.length) {
          var roamT = 0, decoSrc = map.getSource("decorations");
          DECO_TICK = function () {
            roamT += 0.05; // keep time flowing so motion is continuous on resume
            // setData() re-tiles the whole GeoJSON source every tick — skip it
            // when no roamer is anywhere near the viewport (their wander radius
            // is ~0.012°, use a generous margin so they never freeze on-screen)
            var b = map.getBounds();
            var visible = roamers.some(function (m) {
              return m.lng0 >= b.getWest() - 0.1 && m.lng0 <= b.getEast() + 0.1 &&
                     m.lat0 >= b.getSouth() - 0.1 && m.lat0 <= b.getNorth() + 0.1;
            });
            if (!visible) return;
            roamers.forEach(function (m) {
              var dx = Math.cos(roamT * m.w1 + m.p1);
              var dy = Math.sin(roamT * m.w2 + m.p2);
              m.f.geometry.coordinates = [m.lng0 + m.r * dx, m.lat0 + m.r * 0.55 * dy];
              m.f.properties.rotation = m.base + 5 * dy; // gentle amble sway
            });
            decoSrc.setData(points);
          };
        }
        var loaded = 0, want = Object.keys(icons).length;
        if (!want) return;
        Object.keys(icons).forEach(function (name) {
          // sprite loads were kicked off as soon as the decorations feed
          // arrived (see PREFETCH.decoIcons); fall back for any straggler
          (PREFETCH.decoIcons[name] || loadSvgImage(name, DECO_SPRITE_PX)).then(function (sp) {
            if (!map.hasImage(name)) map.addImage(name, sp.image, { pixelRatio: sp.pixelRatio });
            if (++loaded === want) addDecoLayer();
          }).catch(function () { if (++loaded === want) addDecoLayer(); });
        });
      }).catch(function () {});
  }
  // Decoration sprites scale as if pinned to the ground (doubling per zoom
  // level, like the geography) between z8 and z12, so they read as objects
  // with a real — if cartoonishly giant — physical size. Past z12 growth is
  // damped so a monster never swallows the screen.
  var DECO_SIZE_STOPS = [[8, 0.12], [12, 1.92], [14, 2.1]];
  function decoSizeFactor(z) {
    var s = DECO_SIZE_STOPS, last = s.length - 1;
    if (z <= s[0][0]) return s[0][1];
    if (z >= s[last][0]) return s[last][1];
    for (var i = 0; i < last; i++) {
      var z0 = s[i][0], v0 = s[i][1], z1 = s[i + 1][0], v1 = s[i + 1][1];
      if (z <= z1) {
        // exponential-base-2 interpolation, mirroring the style expression
        var t = (Math.pow(2, z - z0) - 1) / (Math.pow(2, z1 - z0) - 1);
        return v0 + (v1 - v0) * t;
      }
    }
    return s[last][1];
  }
  function addDecoLayer() {
    if (map.getLayer("decorations")) return;
    // NB zoom interpolate must be OUTERMOST; per-feature size goes in each stop.
    var sizeExpr = ["interpolate", ["exponential", 2], ["zoom"],
      DECO_SIZE_STOPS[0][0], ["*", ["coalesce", ["get", "size"], 1], DECO_SIZE_STOPS[0][1]],
      DECO_SIZE_STOPS[1][0], ["*", ["coalesce", ["get", "size"], 1], DECO_SIZE_STOPS[1][1]],
      DECO_SIZE_STOPS[2][0], ["*", ["coalesce", ["get", "size"], 1], DECO_SIZE_STOPS[2][1]]];
    // fade the critters once device-level detail matters, so a giant
    // Chonkers can't hide the infrastructure you zoomed in to inspect
    var fadeExpr = ["interpolate", ["linear"], ["zoom"], 12, 0.9, 14, 0.55];
    // ground layer (anchors etc): registered to the ground — keeps heading
    // when the map rotates/pitches, lies flat on the seabed
    map.addLayer({
      id: "decorations", type: "symbol", source: "decorations",
      filter: ["!=", ["get", "billboard"], true],
      layout: {
        "icon-image": ["get", "icon"], "icon-size": sizeExpr,
        "icon-rotate": ["coalesce", ["get", "rotation"], 0],
        "icon-rotation-alignment": "map",
        "icon-pitch-alignment": "map",
        "icon-allow-overlap": true, "icon-ignore-placement": true
      },
      paint: { "icon-opacity": fadeExpr }
    });
    // billboard layer (critters): viewport-aligned so they STAND UP in the
    // default pitched view instead of lying flat on the water
    map.addLayer({
      id: "decorations-billboard", type: "symbol", source: "decorations",
      filter: ["==", ["get", "billboard"], true],
      layout: {
        "icon-image": ["get", "icon"], "icon-size": sizeExpr,
        "icon-rotate": ["coalesce", ["get", "rotation"], 0],
        "icon-rotation-alignment": "viewport",
        "icon-pitch-alignment": "viewport",
        "icon-allow-overlap": true, "icon-ignore-placement": true
      },
      paint: { "icon-opacity": fadeExpr }
    });
  }
  var DECO_SPRITE_PX = 160; // rendered sprite height (see network-map/sprites-src)
  function addDecoText(f) {
    var d = document.createElement("div");
    d.className = "nm-label nm-label-deco";
    d.textContent = t(f.properties.label);
    // anchor the caption below the sprite so graphic and text don't overlap;
    // the offset tracks the sprite's zoom-dependent height (see placeDecoText)
    var m = new maplibregl.Marker({ element: d, anchor: "top" })
      .setLngLat(f.geometry.coordinates).addTo(map);
    m._decoSize = f.properties.size || 1;
    decoTextMarkers.push(m);
    placeDecoText(true);
  }
  // Also a per-frame 'zoom' listener: skip the setOffset pass (each one is a
  // marker DOM write + reprojection) unless the sprite size factor moved
  // enough to matter (< ~half a px of caption offset at the largest sprite).
  var decoFactorLast = -1;
  function placeDecoText(force) {
    var factor = decoSizeFactor(map.getZoom());
    if (force !== true && Math.abs(factor - decoFactorLast) < 0.005) return;
    decoFactorLast = factor;
    decoTextMarkers.forEach(function (m) {
      m.setOffset([0, DECO_SPRITE_PX * m._decoSize * factor / 2 + 4]);
    });
  }
  map.on("zoom", placeDecoText);
  function addFog(f) {
    var ring = f.geometry.coordinates[0];
    // corners: use bbox corners ordered TL,TR,BR,BL for image source
    var lons = ring.map(function (c) { return c[0]; }), lats = ring.map(function (c) { return c[1]; });
    var w = Math.min.apply(null, lons), e = Math.max.apply(null, lons);
    var s = Math.min.apply(null, lats), n = Math.max.apply(null, lats);
    var canvas = document.createElement("canvas");
    canvas.width = FOG_W; canvas.height = FOG_H;
    drawFog(canvas, 0);
    // canvas source — the marine layer flows in off the ocean, each puff
    // drifting west->east and wrapping back around independently. It must NOT
    // stay in animate mode: an animated canvas source re-uploads and repaints
    // on every frame (a continuous 60fps). Instead it idles paused and the
    // shared animation clock redraws the canvas, then plays it for exactly one
    // frame so the new texture uploads with that tick's repaint.
    map.addSource("fog", { type: "canvas", canvas: canvas, animate: true,
      coordinates: [[w, n], [e, n], [e, s], [w, s]] });
    map.addLayer({ id: "fog", type: "raster", source: "fog",
      paint: { "raster-opacity": ["interpolate", ["linear"], ["zoom"], 9,
        (f.properties.max_opacity || 0.35), 13, (f.properties.min_opacity || 0.1)],
        "raster-fade-duration": 0 } });
    var src = map.getSource("fog");
    src.pause();
    var t0 = performance.now();
    FOG_TICK = function () {
      drawFog(canvas, (performance.now() - t0) / 1000);
      src.play();
      requestAnimationFrame(function () { src.pause(); });
    };
  }
  var FOG_W = 512, FOG_H = 256;
  var FOG_DRIFT = 0.012; // unit-widths per second — a slow oceanic crawl
  function drawFog(canvas, t) {
    // Marine layer: overlapping soft elliptical puffs arranged in drifting
    // horizontal banks, denser toward the bottom, feathered to nothing at the
    // edges so the overlay quad has no visible border.
    var W = FOG_W, H = FOG_H;
    var g = canvas.getContext("2d");
    g.globalCompositeOperation = "source-over";
    g.clearRect(0, 0, W, H);
    // deterministic layout — same fog bank, animated only by the drift phase
    var puffs = [
      // [cx, cy, rx, ry, alpha] in unit coords; alphas run hot because the
      // raster layer's zoom-faded opacity multiplies them back down
      // densest bank at the top (north edge = the Gate itself), thinning as
      // it spills south over the city
      [0.10, 0.28, 0.16, 0.10, 0.85], [0.24, 0.34, 0.20, 0.12, 0.90],
      [0.42, 0.26, 0.22, 0.11, 0.95], [0.60, 0.32, 0.20, 0.12, 0.90],
      [0.78, 0.27, 0.19, 0.10, 0.85], [0.92, 0.34, 0.15, 0.10, 0.80],
      [0.16, 0.52, 0.14, 0.08, 0.60], [0.35, 0.58, 0.18, 0.09, 0.68],
      [0.55, 0.54, 0.17, 0.08, 0.65], [0.74, 0.60, 0.16, 0.09, 0.60],
      [0.30, 0.76, 0.13, 0.06, 0.38], [0.52, 0.80, 0.15, 0.07, 0.42],
      [0.70, 0.74, 0.12, 0.06, 0.35]
    ];
    puffs.forEach(function (p, i) {
      // drift west->east; each puff wraps around independently (with a lane
      // wide enough that it fully leaves before re-entering) and rows move at
      // slightly different speeds so the bank shears organically
      var speed = FOG_DRIFT * (0.75 + 0.5 * ((i * 7) % 5) / 4);
      var margin = p[2] + 0.05;
      var x = ((p[0] + margin + t * speed) % (1 + 2 * margin)) - margin;
      var cx = x * W, cy = p[1] * H, rx = p[2] * W, ry = p[3] * H;
      g.save();
      g.translate(cx, cy); g.scale(1, ry / rx);
      var grd = g.createRadialGradient(0, 0, rx * 0.15, 0, 0, rx);
      grd.addColorStop(0, "rgba(255,255,255," + p[4] + ")");
      grd.addColorStop(0.7, "rgba(255,255,255," + (p[4] * 0.45).toFixed(3) + ")");
      grd.addColorStop(1, "rgba(255,255,255,0)");
      g.fillStyle = grd;
      g.beginPath(); g.arc(0, 0, rx, 0, Math.PI * 2); g.fill();
      g.restore();
    });
    // feather all four edges so the quad boundary never shows
    g.globalCompositeOperation = "destination-in";
    var fx = g.createLinearGradient(0, 0, W, 0);
    fx.addColorStop(0, "rgba(0,0,0,0)"); fx.addColorStop(0.15, "rgba(0,0,0,1)");
    fx.addColorStop(0.85, "rgba(0,0,0,1)"); fx.addColorStop(1, "rgba(0,0,0,0)");
    g.fillStyle = fx; g.fillRect(0, 0, W, H);
    var fy = g.createLinearGradient(0, 0, 0, H);
    fy.addColorStop(0, "rgba(0,0,0,0)"); fy.addColorStop(0.2, "rgba(0,0,0,1)");
    fy.addColorStop(0.85, "rgba(0,0,0,1)"); fy.addColorStop(1, "rgba(0,0,0,0)");
    g.fillStyle = fy; g.fillRect(0, 0, W, H);
  }

  // ---- traffic poll -------------------------------------------------------
  function pollTraffic() {
    fetch(TRAFFIC_URL, { mode: "cors" })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (traffic) {
        hideStatus();
        if (traffic.generation && traffic.generation !== STATE.generation) {
          refetchStructure(); return;
        }
        applyTraffic(traffic);
      })
      .catch(function () { showStatus(t("live stats unavailable")); });
  }
  var LAST_TRAFFIC = {};
  function applyTraffic(traffic) {
    LAST_TRAFFIC = traffic.links || {};
    Object.keys(LAST_TRAFFIC).forEach(function (id) {
      var tr = LAST_TRAFFIC[id], util = tr.util_pct;
      // parallel bundles: each strand colours by its own member's utilization
      // (strand feature ids are id#n — see buildSources); a missing member
      // breakdown falls back to the combined figure on every strand
      var strands = CABLE_STRANDS[id] || 1;
      if (strands > 1) {
        for (var st = 0; st < strands; st++) {
          var m = tr.members && tr.members[st];
          map.setFeatureState({ source: "cables", id: id + "#" + st },
            { util: m && m.util_pct != null ? m.util_pct : util });
        }
      } else {
        map.setFeatureState({ source: "cables", id: id }, { util: util });
      }
      if (map.getSource("drops")) map.setFeatureState({ source: "drops", id: id }, { util: util });
      if (map.getSource("flows")) map.setFeatureState({ source: "flows", id: id }, { util: util });
    });
    // aggregate member stats onto metro trunks (util = sum bps / sum capacity)
    Object.keys(METRO_MEMBERS).forEach(function (mid) {
      var inb = 0, outb = 0, cap = 0, util = 0;
      METRO_MEMBERS[mid].forEach(function (cid) {
        var tr = LAST_TRAFFIC[cid]; if (!tr) return;
        inb += tr.in_bps || 0; outb += tr.out_bps || 0;
      });
      var mc = METRO_CAP[mid] || 0;
      if (mc > 0) util = Math.min(100, 100 * Math.max(inb, outb) / mc);
      METRO_STATS[mid] = { in_bps: inb, out_bps: outb, util_pct: Math.round(util * 10) / 10 };
      map.setFeatureState({ source: "metro-cables", id: mid }, { util: util });
      if (map.getSource("metro-flows")) map.setFeatureState({ source: "metro-flows", id: mid }, { util: util });
    });
    // steer the barber-pole stripes toward each link's dominant direction
    updateFlowDirs(STATE.flows, "flows", LAST_TRAFFIC);
    updateFlowDirs(STATE.metroFlows, "metro-flows", METRO_STATS);
    var ts = document.getElementById("nm-ts");
    if (ts && traffic.generated_at) ts.textContent = t("Last updated") + ": " + fmtTime(traffic.generated_at);
  }
  function updateFlowDirs(geo, sourceId, stats) {
    if (!geo) return;
    var changed = false;
    geo.features.forEach(function (f) {
      var tr = stats[f.properties.id];
      var dir = tr && (tr.in_bps || tr.out_bps) ? (tr.out_bps >= tr.in_bps ? 1 : -1) : 0;
      if (f.properties.dir !== dir) { f.properties.dir = dir; changed = true; }
    });
    if (changed && map.getSource(sourceId)) map.getSource(sourceId).setData(geo);
  }
  function refetchStructure() {
    fetch(STRUCTURE_URL, { mode: "cors" }).then(function (r) { return r.json(); })
      .then(function (structure) {
        STATE.generation = structure.generation;
        var src = buildSources(structure);
        STATE.flows = src.flows; STATE.metroFlows = src.metroFlows;
        if (map.getSource("flows")) map.getSource("flows").setData(src.flows);
        if (map.getSource("metro-flows")) map.getSource("metro-flows").setData(src.metroFlows);
        map.getSource("cables").setData(src.cables);
        map.getSource("cable-media").setData(src.media);
        map.getSource("stations").setData(src.stations);
        map.getSource("devices").setData(src.devices);
        map.getSource("metro-cables").setData(src.metroCables);
        if (map.getSource("metro-cable-media")) map.getSource("metro-cable-media").setData(src.metroMedia);
        map.getSource("metro-stations").setData(src.metroStations);
        map.getSource("buildings").setData(src.buildings);
        map.getSource("drops").setData(src.drops);
        setTier(true);
        pollTraffic();
      }).catch(function () {});
  }
  function fmtTime(iso) {
    try { return new Date(iso).toLocaleTimeString(); } catch (e) { return iso; }
  }

  // ---- interactions --------------------------------------------------------
  var hoverable = window.matchMedia && window.matchMedia("(hover: hover)").matches;

  // Priority order for picking what a click/hover targets (topmost intent first).
  // site-building last: at close zoom (roundel faded) the box footprint is the
  // site's hit target; devices/cables render above it so they still win on overlap.
  var PICK_LAYERS = ["metro-stations-ring", "metro-line", "devices-dot",
    "stations-ring", "cables-hit", "site-building"];
  function pick(point) {
    var layers = PICK_LAYERS.filter(function (l) { return map.getLayer(l); });
    var f = map.queryRenderedFeatures(point, { layers: layers });
    return f.length ? f[0] : null;
  }

  function wireInteractions() {
    // One global click dispatcher (robust across layers incl. the invisible fat
    // hit line) — opens the popover and, for a cable/trunk, isolates it.
    map.on("click", function (e) {
      var f = pick(e.point);
      if (!f) { clearSelection(); infoPane.showAbout(); return; }
      var ev = { features: [f], lngLat: e.lngLat };
      var layer = f.layer.id;
      var d;
      if (layer === "cables-hit") { selectFeature("cables", f); d = cableDetail(ev); }
      else if (layer === "metro-line") { selectFeature("metro", f); d = cableDetail(ev, true); }
      else if (layer === "metro-stations-ring") { clearSelection(); d = metroDetail(ev); }
      else { clearSelection(); d = stationDetail(ev); }  // stations / devices
      if (d) infoPane.showDetail(d.title, d.body);
    });
    if (hoverable) {
      map.on("mousemove", function (e) {
        map.getCanvas().style.cursor = pick(e.point) ? "pointer" : "";
      });
    }
  }

  // ---- click-to-isolate: highlight one cable, dim the rest ----------------
  var DIM_LAYERS = {
    cables: ["cables-casing", "cables-line", "cables-approx", "cables-down",
      "cables-planned", "cables-intra", "cable-drops", "cable-water", "cable-submarine",
      "cable-ripple", "flow-fwd", "flow-rev"],
    metro: ["metro-casing", "metro-line", "metro-planned", "metro-flow-fwd", "metro-flow-rev"]
  };
  // which station source + key list pairs with each cable source
  var STATION_SRC = { cables: "stations", metro: "metro-stations" };
  var STATION_KEYS_FOR = function (src) { return src === "cables" ? STATION_KEYS : METRO_KEYS; };
  var _origOpacity = {}, _selActive = false, _dimmedStationSrc = null;
  function _dim(layer) {
    if (!map.getLayer(layer)) return;
    if (!(layer in _origOpacity)) {
      var o = map.getPaintProperty(layer, "line-opacity");
      _origOpacity[layer] = (o == null ? 1 : o);
    }
    map.setPaintProperty(layer, "line-opacity", 0.1);
  }
  function _setStationDim(src, keys, endpoints) {
    keys.forEach(function (k) {
      map.setFeatureState({ source: src, id: k }, { dim: endpoints.indexOf(k) < 0 });
    });
  }
  function clearSelection() {
    if (!_selActive) return;
    _selActive = false;
    if (map.getLayer("cables-highlight")) map.setFilter("cables-highlight", ["==", ["get", "id"], "__none__"]);
    if (map.getLayer("metro-highlight")) map.setFilter("metro-highlight", ["==", ["get", "id"], "__none__"]);
    Object.keys(_origOpacity).forEach(function (l) {
      if (map.getLayer(l)) map.setPaintProperty(l, "line-opacity", _origOpacity[l]);
    });
    if (_dimmedStationSrc) {
      STATION_KEYS_FOR(_dimmedStationSrc === "stations" ? "cables" : "metro")
        .forEach(function (k) { map.setFeatureState({ source: _dimmedStationSrc, id: k }, { dim: false }); });
      _dimmedStationSrc = null;
    }
  }
  function selectFeature(source, feat) {
    clearSelection();
    _selActive = true;
    var props = feat.properties || {};
    DIM_LAYERS[source].forEach(_dim);
    var hl = source === "cables" ? "cables-highlight" : "metro-highlight";
    // A parallel-link strand isolates to just that strand (its siblings dim with the
    // rest); a single-strand link highlights whole. metro trunks have no strand.
    if (source === "cables" && props.members > 1 && props.strand != null && props.strand !== "") {
      map.setFilter(hl, ["all", ["==", ["get", "id"], props.id],
        ["==", ["get", "strand"], Number(props.strand)]]);
    } else {
      map.setFilter(hl, ["==", ["get", "id"], props.id]);
    }
    // highlight the two endpoint sites; dim the rest
    var ssrc = STATION_SRC[source];
    _setStationDim(ssrc, STATION_KEYS_FOR(source), [props.a_site, props.z_site]);
    _dimmedStationSrc = ssrc;
  }
  window.__nmSelect = selectFeature;       // exposed for dev/screenshot tooling
  window.__nmClearSelect = clearSelection;

  // The three detail builders each return {title, body} — the click dispatcher
  // renders them into the info pane (instead of a popover anchored to the click).
  function metroDetail(e) {
    var f = e.features && e.features[0]; if (!f) return null;
    var p = f.properties;
    var body = row(p.nsite + " " + (p.nsite == 1 ? t("site") : t("sites")), "") +
      '<div class="nm-pop-row"><span class="v" style="font-weight:500">' + p.codes + "</span></div>";
    return { title: p.metro, body: body };
  }

  function cableDetail(e, isMetro) {
    var f = e.features && e.features[0]; if (!f) return null;
    var p = f.properties, id = p.id;
    var tr = isMetro ? METRO_STATS[id] : LAST_TRAFFIC[id];
    var devShort = function (d) { return (d || "").split(".")[0]; };
    var head = p.a_site.toUpperCase() + " ⇆ " + p.z_site.toUpperCase();
    if (p.scope === "intra") {
      head = p.a_site.toUpperCase() + " · " + devShort(p.a_device) + " ⇆ " + devShort(p.z_device);
    } else if (p.scope === "metro") head = p.a_site + " ⇆ " + p.z_site;
    var rows = "";
    var isMember = !isMetro && p.members > 1 && p.strand != null && p.strand !== "";
    var st = isMember ? Number(p.strand) : -1;
    // this link's own stats when the feed carries the per-member breakdown
    // (array index = strand index); null on a failed member query -> fall back
    // to the combined bundle figures below
    var mtr = isMember && tr && tr.members ? tr.members[st] : null;
    var mspd = isMember
      ? ((mtr && mtr.speed_bps) || (p.capacity_bps > 0 ? p.capacity_bps / p.members : 0)) : 0;
    if (p.scope === "metro" && p.nmember) rows += row(p.nmember + " " + t("circuits"), "");
    if (isMember) {
      // one physical link of a parallel bundle was clicked — the ◀ ▶ stepper
      // walks the selection through its siblings (they sit ~a strand-width
      // apart on screen, too fiddly to click individually); handled by the
      // delegated listener in infoPane.init
      rows += row(t("Parallel link"),
        linkNavBtn(id, st - 1, "◀", t("Previous link")) +
        '<span class="nm-linknav-pos">' + (st + 1) + " / " + p.members + "</span>" +
        linkNavBtn(id, st + 1, "▶", t("Next link")));
      if (mspd > 0) rows += row(t("Link speed"), capLabel(mspd));
      if (p.capacity_bps > 0) rows += row(t("Combined capacity"), capLabel(p.capacity_bps));
    } else {
      if (p.members > 1) rows += row(t("Parallel links"), p.members + "×");
      if (p.capacity_bps > 0) rows += row(t("Capacity"), capLabel(p.capacity_bps));
    }
    if (p.status === "down") {
      rows += '<div class="nm-pop-row"><span class="nm-chip nm-chip-offline">' + t("link offline") + "</span></div>";
    } else if (p.status === "planned") {
      rows += '<div class="nm-pop-row"><span class="nm-chip nm-chip-planned">' + t("planned — not yet in service") + "</span></div>";
    } else if (mtr) {
      rows += row(t("In"), fmtBps(mtr.in_bps));
      rows += row(t("Out"), fmtBps(mtr.out_bps));
      rows += row(t("of capacity"), (mtr.util_pct != null ? mtr.util_pct + "%" : "—"));
      rows += sparkline(mtr, mspd);
    } else if (tr) {
      rows += row(t("In"), fmtBps(tr.in_bps));
      rows += row(t("Out"), fmtBps(tr.out_bps));
      rows += row(t("of capacity"), (tr.util_pct != null ? tr.util_pct + "%" : "—"));
      rows += sparkline(tr, p.capacity_bps);
    }
    if (p.approximate) rows += '<div style="margin-top:6px"><span class="nm-badge-approx">' + t("approximate route") + "</span></div>";
    return { title: head, body: rows };
  }

  function stationDetail(e) {
    var f = e.features && e.features[0]; if (!f) return null;
    return siteDetailFromProps(f.properties);
  }

  // ---- parallel-link stepper --------------------------------------------------
  function linkNavBtn(id, strand, glyph, label) {
    return '<button class="nm-linknav-btn" type="button" data-cable="' + esc(id) +
      '" data-strand="' + strand + '" aria-label="' + esc(label) + '">' + glyph + "</button>";
  }
  // Re-select cable `id` at member `strand` (wrapping both ways) and re-render
  // the pane — a synthesized strand feature is enough for selectFeature and
  // cableDetail, so no queryRenderedFeatures round-trip is needed (the sibling
  // strand may even be off-screen).
  function selectBundleLink(id, strand) {
    var c = BUNDLE_PROPS[id]; if (!c) return;
    var props = {};
    Object.keys(c).forEach(function (k) { props[k] = c[k]; });
    props.strand = ((strand % c.members) + c.members) % c.members;
    var fake = { properties: props };
    selectFeature("cables", fake);
    var d = cableDetail({ features: [fake] });
    if (d) infoPane.showDetail(d.title, d.body);
  }
  window.__nmBundleLink = selectBundleLink;  // exposed for dev/screenshot tooling

  // Base path for repo-local operator logos (curated fallback when PeeringDB has
  // no org logo); filename is the operator slug, e.g. /img/operators/equinix.svg
  var OPLOGO_BASE = "/img/operators/";
  // Portal path prefix under which the builder caches PeeringDB operator logos.
  var LOGO_URL_PREFIX = "/statistics/map/logos/";
  // Allow only http(s) links out; refuses javascript:/data: URIs that could ride
  // in on third-party (PeeringDB-sourced) fields like operator_website.
  function httpUrl(u) { return /^https?:\/\//i.test(u || "") ? u : ""; }
  function slug(s) { return (s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, ""); }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  // Operator badge: a coloured initials monogram is always drawn as the base; a
  // logo <img> is layered on top and hides itself on error, walking PeeringDB
  // logo -> repo-local curated logo -> (monogram shows through).
  function monogramHtml(op) {
    var init = (op || "?").split(/\s+/).map(function (w) { return w.charAt(0); }).join("").slice(0, 2).toUpperCase() || "?";
    var hue = 0; for (var i = 0; i < (op || "").length; i++) hue = (hue * 31 + op.charCodeAt(i)) % 360;
    return '<span class="nm-info-mono" style="background:hsl(' + hue + ',45%,42%)">' + esc(init) + "</span>";
  }
  // Resolve the map.json `logo` field to a safe src: cached logos are served as
  // portal-relative paths (prefixed with the portal origin); a bare https URL is
  // tolerated for back-compat; anything else (e.g. a javascript: URI) is refused.
  function logoSrc(raw) {
    raw = raw || "";
    if (raw.indexOf(LOGO_URL_PREFIX) === 0) return PORTAL_ORIGIN + raw;
    if (/^https:\/\//i.test(raw)) return raw;
    return "";
  }
  function operatorLogoHtml(p) {
    var mono = monogramHtml(p.operator);
    var pdb = logoSrc(p.logo);
    var local = p.operator ? OPLOGO_BASE + slug(p.operator) + ".svg" : "";
    var first = pdb || local;
    if (!first) return '<div class="nm-info-logo">' + mono + "</div>";
    var second = (pdb && local) ? local : "";
    var onerr = second
      ? "this.onerror=function(){this.style.display='none'};this.src='" + second + "'"
      : "this.onerror=null;this.style.display='none'";
    return '<div class="nm-info-logo">' + mono +
      '<img class="nm-info-logo-img" alt="' + esc(p.operator) + '" src="' + esc(first) + '" onerror="' + onerr + '"></div>';
  }

  function siteDetailFromProps(p) {
    var isDevice = p.id && !p.code;   // device feature: {id, site}, no code
    var code = p.code || (p.id ? p.id.split(".").slice(1).join(".") : "");
    var name = p.name || p.id || "";
    if (isDevice) { name = p.id.split(".")[0]; code = p.site || ""; }
    var body = "";
    if (!isDevice) {
      body += operatorLogoHtml(p);
      if (p.operator) {
        var opsite = httpUrl(p.operator_website);
        body += opsite
          ? '<div class="nm-info-operator"><a href="' + esc(opsite) + '" target="_blank" rel="noopener">' + esc(p.operator) + " ↗</a></div>"
          : '<div class="nm-info-operator">' + esc(p.operator) + "</div>";
      }
    } else if (p.operator) {
      body += '<div class="nm-info-addr">' + esc(p.operator) + "</div>";
    }
    var hasAddr = p.address && p.address.indexOf("synthetic") < 0;
    if (hasAddr) body += '<div class="nm-info-addr">' + esc(p.address) + "</div>";
    else if (p.city) body += '<div class="nm-info-addr">' + esc(p.city) + (p.state ? ", " + esc(p.state) : "") + "</div>";
    // PeeringDB: one compact stat line + a link (only when the site was enriched)
    if (!isDevice) {
      var stats = [];
      if (p.net_count) stats.push(p.net_count + " " + t("networks"));
      if (p.ix_count) stats.push(p.ix_count + " " + t("IXes"));
      if (stats.length) body += '<div class="nm-info-stats">' + stats.join(" · ") + "</div>";
      if (p.pdb_url) body += '<div class="nm-info-pdb"><a href="' + esc(p.pdb_url) + '" target="_blank" rel="noopener">' + t("View on PeeringDB") + " ↗</a></div>";
    }
    var title = (code ? code.toUpperCase() + " · " : "") + name;  // rendered via textContent
    return { title: title, body: body };
  }
  window.__nmSiteDetail = siteDetailFromProps;   // exposed for dev/screenshot tooling

  function row(k, v) {
    return '<div class="nm-pop-row"><span class="k">' + k + '</span><span class="v">' + v + "</span></div>";
  }
  function sparkline(tr, cap) {
    var si = tr.series_in || [], so = tr.series_out || [];
    var n = Math.max(si.length, so.length); if (!n) return "";
    var max = cap || 1;
    for (var i = 0; i < n; i++) { max = Math.max(max, si[i] || 0, so[i] || 0); }
    var W = 200, H = 40;
    function path(arr) {
      if (!arr.length) return "";
      return arr.map(function (v, i) {
        var x = (i / (arr.length - 1)) * W;
        var y = H - (v / max) * (H - 3) - 1;
        return (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
      }).join(" ");
    }
    return '<div class="nm-spark"><svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none">' +
      '<path d="' + path(so) + '" fill="none" stroke="#fade2a" stroke-width="1.6"/>' +
      '<path d="' + path(si) + '" fill="none" stroke="#00cf00" stroke-width="1.6"/>' +
      "</svg></div>";
  }

  // ---- info pane (top-left) ----------------------------------------------
  // Holds the "about this map" blurb + links when idle, and a clicked feature's
  // details when something is selected. Small/collapsed when not needed.
  var infoPane = (function () {
    var root, toggle, titleEl, aboutEl, detailEl, detailBody;
    var defaultTitle = "";
    function expanded() { return root && !root.classList.contains("collapsed"); }
    function setCollapsed(collapsed) {
      if (!root) return;
      root.classList.toggle("collapsed", collapsed);
      if (toggle) toggle.setAttribute("aria-expanded", String(!collapsed));
    }
    function setTitle(s) { if (titleEl) titleEl.textContent = s; }
    function showAbout() {
      if (!root) return;
      if (detailEl) detailEl.hidden = true;
      if (aboutEl) aboutEl.hidden = false;
      setTitle(defaultTitle);
    }
    function showDetail(title, bodyHtml) {
      if (!root) return;
      if (aboutEl) aboutEl.hidden = true;
      if (detailEl) detailEl.hidden = false;
      if (detailBody) detailBody.innerHTML = bodyHtml || "";
      setTitle(title || defaultTitle);
      setCollapsed(false);              // a selection always reveals the pane
      if (root.querySelector(".nm-info-body")) root.querySelector(".nm-info-body").scrollTop = 0;
    }
    function init() {
      root = document.getElementById("nm-info");
      if (!root) return;
      toggle = root.querySelector(".nm-info-toggle");
      titleEl = root.querySelector(".nm-info-title");
      aboutEl = root.querySelector(".nm-info-about");
      detailEl = root.querySelector(".nm-info-detail");
      detailBody = root.querySelector(".nm-info-detail-body");
      // parallel-link stepper (◀ ▶ in cableDetail) — delegated, since the body
      // is re-rendered wholesale on every showDetail
      if (detailBody) detailBody.addEventListener("click", function (ev) {
        var b = ev.target && ev.target.closest && ev.target.closest(".nm-linknav-btn");
        if (b) selectBundleLink(b.getAttribute("data-cable"), Number(b.getAttribute("data-strand")));
      });
      defaultTitle = titleEl ? titleEl.textContent : "";
      if (toggle) toggle.addEventListener("click", function () { setCollapsed(expanded()); });
      var back = root.querySelector(".nm-info-back");
      if (back) back.addEventListener("click", function () { showAbout(); });
      // Roomy screens: open to the blurb; phones: stay a compact pill until asked.
      var narrow = window.matchMedia && window.matchMedia("(max-width: 640px)").matches;
      setCollapsed(narrow);
    }
    return { init: init, showAbout: showAbout, showDetail: showDetail };
  })();
  window.__nmInfo = infoPane;               // exposed for dev/screenshot tooling

  // ---- legend collapse (mobile) ------------------------------------------
  function wireLegend() {
    var legend = document.getElementById("nm-legend");
    var toggle = legend && legend.querySelector(".nm-legend-toggle");
    if (!toggle) return;
    if (window.matchMedia && window.matchMedia("(max-width: 640px)").matches) legend.classList.add("collapsed");
    toggle.addEventListener("click", function () { legend.classList.toggle("collapsed"); });
  }

  // ---- status chip --------------------------------------------------------
  function showStatus(msg) { var s = document.getElementById("nm-status"); if (s) { s.textContent = msg; s.style.display = "block"; } }
  function hideStatus() { var s = document.getElementById("nm-status"); if (s) s.style.display = "none"; }
})();
