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
  var POLL_MS = 60000;
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

  function fmtBps(b) {
    if (!b || b < 1) return "0";
    var u = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"], i = 0;
    while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
    return (b >= 100 ? b.toFixed(0) : b.toFixed(1)) + " " + u[i];
  }
  function capLabel(b) { return fmtBps(b).replace("bps", "b/s"); }

  function weightForCapacity(bps) {
    var g = bps / 1e9;
    if (g >= 800) return 5.0;
    if (g >= 400) return 4.0;
    if (g >= 100) return 2.6;
    if (g >= 40) return 2.0;
    if (g >= 10) return 1.5;
    return 1.1;
  }

  // Chaikin corner-cutting: soft subway curves without moving endpoints much.
  function chaikin(pts, iters) {
    for (var k = 0; k < (iters || 2); k++) {
      if (pts.length < 3) break;
      var out = [pts[0]];
      for (var i = 0; i < pts.length - 1; i++) {
        var p = pts[i], q = pts[i + 1];
        out.push([p[0] * 0.75 + q[0] * 0.25, p[1] * 0.75 + q[1] * 0.25]);
        out.push([p[0] * 0.25 + q[0] * 0.75, p[1] * 0.25 + q[1] * 0.75]);
      }
      out.push(pts[pts.length - 1]);
      pts = out;
    }
    return pts;
  }

  function cableCoords(cable) {
    var coords = [];
    cable.segments.forEach(function (seg) {
      seg.coordinates.forEach(function (c) {
        // drop exact consecutive dupes at segment joins
        var last = coords[coords.length - 1];
        if (!last || last[0] !== c[0] || last[1] !== c[1]) coords.push(c);
      });
    });
    return coords;
  }

  // ---- build GeoJSON from structure --------------------------------------
  function buildSources(structure) {
    var sites = structure.sites;

    // parallel-offset index per unordered site pair
    var pairCount = {}, pairSeen = {};
    structure.cables.forEach(function (c) {
      if (c.scope !== "inter") return;
      var key = [c.a_site, c.z_site].sort().join("~");
      pairCount[key] = (pairCount[key] || 0) + 1;
    });

    var cableFeatures = [], mediaFeatures = [], coordsById = {};
    var STRAND_FRAC = 0.34; // strand spacing as a fraction of the pair spacing
    structure.cables.forEach(function (c) {
      var raw = cableCoords(c);
      var smooth = c.scope === "intra" ? raw : chaikin(raw, 2);
      coordsById[c.id] = { coords: smooth, approx: !!c.approximate };
      var base = 0;
      if (c.scope === "inter") {
        var key = [c.a_site, c.z_site].sort().join("~");
        var n = pairCount[key]; var i = (pairSeen[key] = (pairSeen[key] || 0) + 1) - 1;
        base = (i - (n - 1) / 2);
      }
      // A LAG / BiDi shows its member links as closely-spaced parallel strands;
      // distinct circuits between the same pair are spaced a full step apart.
      var strands = Math.max(1, c.members || 1);
      for (var st = 0; st < strands; st++) {
        var strandOff = strands > 1 ? (st - (strands - 1) / 2) * STRAND_FRAC : 0;
        cableFeatures.push({
          type: "Feature", id: c.id,
          properties: {
            id: c.id, scope: c.scope, status: c.status,
            approximate: !!c.approximate, weight: weightForCapacity(c.capacity_bps),
            capacity_bps: c.capacity_bps, offset: base + strandOff,
            members: strands, strand: st, a_site: c.a_site, z_site: c.z_site
          },
          geometry: { type: "LineString", coordinates: smooth }
        });
      }
      // per-segment media features for water treatment (bridge/submarine)
      c.segments.forEach(function (seg) {
        if (seg.medium === "bridge" || seg.medium === "submarine") {
          mediaFeatures.push({
            type: "Feature",
            properties: { medium: seg.medium, id: c.id },
            geometry: { type: "LineString", coordinates: seg.coordinates }
          });
        }
      });
    });

    var stationFeatures = [], deviceFeatures = [], buildingFeatures = [], deviceCoord = {};
    Object.keys(sites).forEach(function (code) {
      var s = sites[code];
      (s.devices || []).forEach(function (d) { deviceCoord[d.id] = [d.dlon, d.dlat]; });
      stationFeatures.push({
        type: "Feature",
        properties: { code: code, name: s.name || code, operator: s.operator || "",
          metro: s.metro || "", address: s.address || "", ndev: (s.devices || []).length },
        geometry: { type: "Point", coordinates: [s.lon, s.lat] }
      });
      if (s.building) {
        buildingFeatures.push({
          type: "Feature", properties: { code: code },
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

    // ---- device drops: at high zoom a cable terminates on its specific switch.
    // The trunk still ends at the site centroid; these short stubs fan from the
    // centroid to the a/z device so multiple cables don't knot on one point.
    var dropFeatures = [];
    structure.cables.forEach(function (c) {
      if (c.scope !== "inter") return;
      [["a_site", "a_device"], ["z_site", "z_device"]].forEach(function (pair) {
        var s = sites[c[pair[0]]], dc = deviceCoord[c[pair[1]]];
        if (s && dc) {
          dropFeatures.push({
            type: "Feature", id: c.id,
            properties: { id: c.id, status: c.status, approximate: !!c.approximate },
            geometry: { type: "LineString", coordinates: [[s.lon, s.lat], dc] }
          });
        }
      });
    });

    // ---- metro tier: group sites by metro, collapse cables to metro trunks ----
    var metros = {}; // name -> {lats,lons,codes}
    Object.keys(sites).forEach(function (code) {
      var s = sites[code], name = s.metro || code;
      (metros[name] = metros[name] || { lats: [], lons: [], codes: [] });
      metros[name].lats.push(s.lat); metros[name].lons.push(s.lon); metros[name].codes.push(code);
    });
    var metroOf = {}, metroCentroid = {};
    Object.keys(metros).forEach(function (name) {
      var m = metros[name];
      metroCentroid[name] = [avg(m.lons), avg(m.lats)];
      m.codes.forEach(function (c) { metroOf[c] = name; });
    });
    var metroStationFeatures = Object.keys(metros).map(function (name) {
      return { type: "Feature",
        properties: { metro: name, nsite: metros[name].codes.length,
          codes: metros[name].codes.join(", ") },
        geometry: { type: "Point", coordinates: metroCentroid[name] } };
    });

    // aggregate inter-metro cables (drop intra-metro; those appear at site tier)
    var mGroups = {}; // key -> {a,z,cap,members[],anyUp,allApprox,count}
    METRO_MEMBERS = {};
    structure.cables.forEach(function (c) {
      if (c.scope !== "inter") return;
      var ma = metroOf[c.a_site], mz = metroOf[c.z_site];
      if (!ma || !mz || ma === mz) return; // intra-metro link, not a trunk
      var key = [ma, mz].sort().join("~");
      var g = mGroups[key] || (mGroups[key] = { a: ma, z: mz, cap: 0, members: [], anyUp: false, allApprox: true, ids: [] });
      g.cap += c.capacity_bps; g.members.push(c.id); g.ids.push(c.id);
      if (c.status !== "down") g.anyUp = true;
      if (!c.approximate) g.allApprox = false;
    });
    var metroCableFeatures = Object.keys(mGroups).map(function (key) {
      var g = mGroups[key];
      var id = "metro:" + key;
      METRO_MEMBERS[id] = g.ids; METRO_CAP[id] = g.cap;
      // Trace the trunk along its richest real member cable (prefer non-approx,
      // then most points) so it follows a real corridor instead of floating; run
      // it centroid -> real path -> centroid so it meets the metro roundels.
      var ca = metroCentroid[g.a], cz = metroCentroid[g.z], best = null;
      g.ids.forEach(function (cid) {
        var e = coordsById[cid];
        if (!e || e.coords.length < 3) return;
        if (!best || (best.approx && !e.approx) ||
            (best.approx === e.approx && e.coords.length > best.coords.length)) best = e;
      });
      var line, real = false;
      if (best) {
        var pts = best.coords.slice();
        if (dist(pts[0], ca) > dist(pts[pts.length - 1], ca)) pts.reverse();
        line = [ca].concat(pts, [cz]);
        real = !best.approx;
      } else {
        line = chaikin([ca, midBulge(ca, cz), cz], 2);
      }
      return { type: "Feature", id: id,
        properties: { id: id, scope: "metro", status: g.anyUp ? "up" : "down",
          approximate: !real, weight: weightForCapacity(g.cap),
          capacity_bps: g.cap, offset: 0, a_site: g.a, z_site: g.z, nmember: g.members.length },
        geometry: { type: "LineString", coordinates: line } };
    });

    return {
      cables: fc(cableFeatures), media: fc(mediaFeatures),
      stations: fc(stationFeatures), devices: fc(deviceFeatures),
      buildings: fc(buildingFeatures), drops: fc(dropFeatures),
      metroStations: fc(metroStationFeatures), metroCables: fc(metroCableFeatures)
    };
  }
  function fc(features) { return { type: "FeatureCollection", features: features }; }
  function avg(a) { return a.reduce(function (s, x) { return s + x; }, 0) / a.length; }
  function dist(a, b) { return Math.hypot(a[0] - b[0], a[1] - b[1]); }
  function midBulge(a, z) {
    var mx = (a[0] + z[0]) / 2, my = (a[1] + z[1]) / 2;
    var dx = z[0] - a[0], dy = z[1] - a[1];
    return [mx - dy * 0.08, my + dx * 0.08];
  }
  var METRO_MEMBERS = {}, METRO_CAP = {}, METRO_STATS = {};
  var STATION_KEYS = [], METRO_KEYS = [];

  // ---- map ----------------------------------------------------------------
  var map = new maplibregl.Map({
    container: "network-map",
    style: {
      version: 8,
      sources: {
        water: { type: "geojson", data: BASEMAP_BASE + "basemap-water.json" },
        land: { type: "geojson", data: BASEMAP_BASE + "basemap-land.json" },
        airports: { type: "geojson", data: BASEMAP_BASE + "basemap-airports.json" },
        roads: { type: "geojson", data: BASEMAP_BASE + "basemap-roads.json", tolerance: 0.5 }
      },
      layers: [
        { id: "bg", type: "background", paint: { "background-color": "#f4f1e9" } },
        { id: "land", type: "fill", source: "land", paint: { "fill-color": "#f4f1e9" } },
        { id: "water", type: "fill", source: "water",
          paint: { "fill-color": "#a7c6cf", "fill-outline-color": "#8fb2bd" } },
        // airports — runway/terminal hints (no clutter; ICAO labels via markers)
        { id: "airport-terminal", type: "fill", source: "airports",
          filter: ["==", ["get", "kind"], "terminal"],
          paint: { "fill-color": "#cfc9ba", "fill-opacity": 0.7 } },
        { id: "airport-runway-fill", type: "fill", source: "airports",
          filter: ["==", ["get", "kind"], "runway"],
          paint: { "fill-color": "#b7b3a7" } },
        { id: "airport-runway", type: "line", source: "airports",
          filter: ["==", ["get", "kind"], "runway_line"],
          layout: { "line-cap": "butt" },
          paint: { "line-color": "#b0aca0",
            "line-width": ["interpolate", ["linear"], ["zoom"], 9, 0.8, 12, 3, 15, 9] } },
        { id: "trunk-casing", type: "line", source: "roads", minzoom: 9.5,
          filter: ["==", ["get", "class"], "trunk"],
          layout: { "line-cap": "round", "line-join": "round" },
          paint: { "line-color": "#dfd6bf", "line-opacity": ["interpolate", ["linear"], ["zoom"], 9.5, 0, 11, 1],
            "line-width": ["interpolate", ["linear"], ["zoom"], 10, 1.2, 16, 4] } },
        { id: "trunk", type: "line", source: "roads", minzoom: 9.5,
          filter: ["==", ["get", "class"], "trunk"],
          layout: { "line-cap": "round", "line-join": "round" },
          paint: { "line-color": "#f1ebda", "line-opacity": ["interpolate", ["linear"], ["zoom"], 9.5, 0, 11, 1],
            "line-width": ["interpolate", ["linear"], ["zoom"], 10, 0.6, 16, 2.6] } },
        { id: "roads-casing", type: "line", source: "roads",
          filter: ["==", ["get", "class"], "motorway"],
          layout: { "line-cap": "round", "line-join": "round" },
          paint: { "line-color": "#d3c9b0",
            "line-width": ["interpolate", ["linear"], ["zoom"], 8, 1.2, 12, 3.2, 16, 7] } },
        { id: "roads", type: "line", source: "roads",
          filter: ["==", ["get", "class"], "motorway"],
          layout: { "line-cap": "round", "line-join": "round" },
          paint: { "line-color": "#efe8d6",
            "line-width": ["interpolate", ["linear"], ["zoom"], 8, 0.6, 12, 1.8, 16, 4.5] } }
      ]
    },
    center: [-122.05, 37.6],
    zoom: 9.1,
    minZoom: 8,
    maxZoom: 15,
    maxBounds: [[-122.95, 37.0], [-121.4, 38.2]],
    attributionControl: false
  });
  window.__nmmap = map; // exposed for dev/screenshot tooling
  map.addControl(new maplibregl.NavigationControl({ showCompass: false }), "top-right");
  map.addControl(new maplibregl.AttributionControl({
    customAttribution: "Basemap © OpenStreetMap contributors · SFMIX"
  }), "bottom-right");

  var siteMarkers = [], deviceMarkers = [], decoTextMarkers = [], metroMarkers = [],
    airportMarkers = [], siteBoxMarkers = [];

  map.on("load", function () {
    fetch(STRUCTURE_URL, { mode: "cors" })
      .then(function (r) { return r.json(); })
      .then(function (structure) { init(structure); })
      .catch(function (e) { showStatus(t("live stats unavailable")); console.error(e); });
  });

  var STATE = { generation: null };

  function init(structure) {
    STATE.generation = structure.generation;
    var src = buildSources(structure);

    map.addSource("cables", { type: "geojson", data: src.cables, promoteId: "id" });
    map.addSource("cable-media", { type: "geojson", data: src.media });
    map.addSource("stations", { type: "geojson", data: src.stations, promoteId: "code" });
    map.addSource("devices", { type: "geojson", data: src.devices });
    map.addSource("metro-cables", { type: "geojson", data: src.metroCables, promoteId: "id" });
    map.addSource("metro-stations", { type: "geojson", data: src.metroStations, promoteId: "metro" });
    STATION_KEYS = Object.keys(structure.sites);
    METRO_KEYS = src.metroStations.features.map(function (f) { return f.properties.metro; });
    map.addSource("buildings", { type: "geojson", data: src.buildings });
    map.addSource("drops", { type: "geojson", data: src.drops, promoteId: "id" });

    // NB: a zoom `interpolate` must be the OUTERMOST expression — it cannot be
    // nested inside a multiply. So the per-feature property math lives in each
    // zoom stop's output instead.
    var offsetExpr = ["interpolate", ["linear"], ["zoom"],
      8, ["*", ["get", "offset"], 2.2],
      12, ["*", ["get", "offset"], 5],
      15, ["*", ["get", "offset"], 9]];
    function widthExprAdd(add) {
      return ["interpolate", ["linear"], ["zoom"],
        8, ["+", ["*", ["get", "weight"], 0.8], add],
        12, ["+", ["*", ["get", "weight"], 1.5], add],
        16, ["+", ["*", ["get", "weight"], 2.8], add]];
    }
    var widthExpr = widthExprAdd(0);

    // site building footprints — fade in at the device tier as the "box" that
    // contains the switches (below cables so links route to/over the box)
    map.addLayer({
      id: "site-building", type: "fill", source: "buildings",
      paint: { "fill-color": "#d8d2c2", "fill-outline-color": "#7d7867",
        "fill-opacity": ["interpolate", ["linear"], ["zoom"], EXPAND_ZOOM - 0.5, 0, EXPAND_ZOOM + 0.5, 0.85] }
    });
    map.addLayer({
      id: "site-building-outline", type: "line", source: "buildings",
      paint: { "line-color": "#7d7867", "line-width": 1.2,
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
    // approximate links (dotted, still util-coloured)
    map.addLayer({
      id: "cables-approx", type: "line", source: "cables",
      filter: ["all", ["==", ["get", "scope"], "inter"], ["==", ["get", "approximate"], true],
        ["!=", ["get", "status"], "down"]],
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": UTIL_COLOR_EXPR, "line-dasharray": [0.4, 1.8],
        "line-offset": offsetExpr, "line-width": widthExpr }
    });
    // normal links (solid, util-coloured)
    map.addLayer({
      id: "cables-line", type: "line", source: "cables",
      filter: ["all", ["==", ["get", "scope"], "inter"], ["==", ["get", "approximate"], false],
        ["!=", ["get", "status"], "down"]],
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": UTIL_COLOR_EXPR, "line-offset": offsetExpr, "line-width": widthExpr }
    });
    // intra-site links (only visible zoomed in)
    map.addLayer({
      id: "cables-intra", type: "line", source: "cables",
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
      paint: { "line-color": "#000", "line-opacity": 0, "line-offset": offsetExpr, "line-width": 18 }
    });

    // selection highlight — the clicked cable's strands drawn bright on top while
    // the rest are dimmed (see selectFeature). Filter matches nothing until a click.
    map.addLayer({
      id: "cables-highlight", type: "line", source: "cables",
      filter: ["==", ["get", "id"], "__none__"],
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": UTIL_COLOR_EXPR, "line-offset": offsetExpr,
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
      id: "stations-dot", type: "circle", source: "stations",
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
      id: "cable-drops", type: "line", source: "drops",
      layout: { "line-cap": "round" },
      paint: {
        "line-color": ["case", ["==", ["get", "status"], "down"], "#9aa4aa", UTIL_COLOR_EXPR],
        "line-width": ["interpolate", ["linear"], ["zoom"], EXPAND_ZOOM, 1.5, 16, 3],
        "line-opacity": ["interpolate", ["linear"], ["zoom"], EXPAND_ZOOM - 0.3, 0, EXPAND_ZOOM + 0.6, 0.95]
      }
    });
    // devices (fade in when zoomed into a site)
    map.addLayer({
      id: "devices-dot", type: "circle", source: "devices",
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
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": UTIL_COLOR_EXPR, "line-width": metroWidthAdd(0) }
    });
    map.addLayer({
      id: "metro-highlight", type: "line", source: "metro-cables",
      filter: ["==", ["get", "id"], "__none__"],
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": UTIL_COLOR_EXPR, "line-width": metroWidthAdd(1.6) }
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
    addAirportLabels();
    addWaterTreatment();
    if (DECOR_URL) addDecorations();
    wireInteractions();
    wireLegend();
    setTier();
    map.on("zoom", setTier);

    pollTraffic();
    setInterval(pollTraffic, POLL_MS);
  }

  // Toggle metro / site / device tiers by zoom (layer visibility + markers).
  var SITE_LAYERS = ["cables-casing", "cables-down", "cables-approx", "cables-line",
    "cables-hit", "cable-water", "cable-drops", "stations-ring", "stations-dot"];
  var METRO_LAYERS = ["metro-casing", "metro-line", "metro-stations-ring", "metro-stations-dot"];
  function setVis(ids, on) {
    ids.forEach(function (id) { if (map.getLayer(id)) map.setLayoutProperty(id, "visibility", on ? "visible" : "none"); });
  }
  function setTier() {
    var z = map.getZoom();
    var metro = z < METRO_ZOOM;
    setVis(METRO_LAYERS, metro);
    setVis(SITE_LAYERS, !metro);
    // site name: beside the roundel at the site tier, then ABOVE the building box
    // once the box opens (device tier) — never overlapping the switches inside
    var besideOn = !metro && z < EXPAND_ZOOM;
    var aboveBoxOn = z >= EXPAND_ZOOM;
    siteMarkers.forEach(function (m) { m.getElement().style.display = besideOn ? "" : "none"; });
    siteBoxMarkers.forEach(function (m) { m.getElement().style.display = aboveBoxOn ? "" : "none"; });
    metroMarkers.forEach(function (m) { m.getElement().style.display = metro ? "" : "none"; });
    // device dots appear with the building box; their labels wait until there's
    // room so adjacent switch captions don't collide
    deviceMarkers.forEach(function (m) { m.getElement().style.display = z >= DEVICE_LABEL_ZOOM ? "" : "none"; });
    var showIcao = z >= ICAO_ZOOM;
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
  function addAirportLabels() {
    fetch(BASEMAP_BASE + "basemap-airports.json").then(function (r) { return r.json(); })
      .then(function (fc) {
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
        setTier();
      }).catch(function () {});
  }

  // ---- water: a subtle ripple texture on the bay, reused over undersea cable --
  // A submarine cable span reads as "submerged": the util colour is muted toward
  // the water tone and the SAME ripple texture that styles the bay is laid over
  // it, so it blends into the water instead of contrasting with it.
  function addWaterTreatment() {
    var beforeId = map.getLayer("stations-ring") ? "stations-ring" : undefined;
    // depth shade: slightly deeper water tone over the crossing (very soft)
    map.addLayer({
      id: "cable-submarine", type: "line", source: "cable-media",
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": "#7ba7b6", "line-opacity": 0.4,
        "line-width": ["interpolate", ["linear"], ["zoom"], 8, 5, 14, 15] }
    }, beforeId);
    // mute the cable's util colour toward the water tone (submerged look)
    map.addLayer({
      id: "cable-water", type: "line", source: "cable-media",
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": "#a7c6cf", "line-opacity": 0.45,
        "line-width": ["interpolate", ["linear"], ["zoom"], 8, 2.5, 14, 7] }
    }, beforeId);
    // ripple texture over the span (matches the bay); replaces the mute layer's
    // flat look with the same wave texture the water fill uses
    map.addLayer({
      id: "cable-ripple", type: "line", source: "cable-media",
      layout: { "line-cap": "butt", "line-join": "round" },
      paint: { "line-color": "#cfe2e8", "line-opacity": 0.5, "line-width": 2,
        "line-dasharray": [0.6, 1.8] }
    }, beforeId);
    map.loadImage(SPRITE_BASE + "water-texture.png").then(function (img) {
      if (!map.hasImage("water-texture")) map.addImage("water-texture", img.data);
      // ripples on the cable span
      map.setPaintProperty("cable-ripple", "line-pattern", "water-texture");
      map.setPaintProperty("cable-ripple", "line-width",
        ["interpolate", ["linear"], ["zoom"], 8, 5, 14, 14]);
      // texture the bay itself (subtle), just above the flat water fill
      if (!map.getLayer("water-texture")) {
        map.addLayer({
          id: "water-texture", type: "fill", source: "water",
          paint: { "fill-pattern": "water-texture", "fill-opacity": 0.75 }
        }, map.getLayer("airport-terminal") ? "airport-terminal" : beforeId);
      }
    }).catch(function () {});
  }

  // ---- decorations (whimsy) ----------------------------------------------
  function addDecorations() {
    fetch(DECOR_URL, { mode: "cors" }).then(function (r) { return r.json(); })
      .then(function (deco) {
        var points = { type: "FeatureCollection", features: [] };
        var icons = {};
        deco.features.forEach(function (f) {
          if (f.geometry.type === "Point") {
            points.features.push(f);
            if (f.properties.icon) icons[f.properties.icon] = true;
            if (f.properties.label) addDecoText(f);
          } else if (f.properties.kind === "image-overlay" && f.properties.icon === "fog") {
            addFog(f);
          }
        });
        map.addSource("decorations", { type: "geojson", data: points });
        var loaded = 0, want = Object.keys(icons).length;
        if (!want) return;
        Object.keys(icons).forEach(function (name) {
          map.loadImage(SPRITE_BASE + name + ".png").then(function (img) {
            if (!map.hasImage(name)) map.addImage(name, img.data);
            if (++loaded === want) addDecoLayer();
          }).catch(function () { if (++loaded === want) addDecoLayer(); });
        });
      }).catch(function () {});
  }
  function addDecoLayer() {
    if (map.getLayer("decorations")) return;
    map.addLayer({
      id: "decorations", type: "symbol", source: "decorations",
      layout: {
        "icon-image": ["get", "icon"],
        // grows with zoom: small & icon-like when zoomed out, large & detailed in.
        // NB zoom interpolate must be OUTERMOST; per-feature size goes in each stop.
        "icon-size": ["interpolate", ["linear"], ["zoom"],
          8, ["*", ["coalesce", ["get", "size"], 1], 0.16],
          11, ["*", ["coalesce", ["get", "size"], 1], 0.34],
          14, ["*", ["coalesce", ["get", "size"], 1], 0.72]],
        "icon-rotate": ["coalesce", ["get", "rotation"], 0],
        "icon-allow-overlap": true, "icon-ignore-placement": true
      },
      paint: { "icon-opacity": 0.9 }
    });
  }
  function addDecoText(f) {
    var d = document.createElement("div");
    d.className = "nm-label nm-label-deco";
    d.textContent = f.properties.label;
    // anchor the caption below the sprite so graphic and text don't overlap
    var m = new maplibregl.Marker({ element: d, anchor: "top", offset: [0, 24] })
      .setLngLat(f.geometry.coordinates).addTo(map);
    decoTextMarkers.push(m);
  }
  function addFog(f) {
    var ring = f.geometry.coordinates[0];
    // corners: use bbox corners ordered TL,TR,BR,BL for image source
    var lons = ring.map(function (c) { return c[0]; }), lats = ring.map(function (c) { return c[1]; });
    var w = Math.min.apply(null, lons), e = Math.max.apply(null, lons);
    var s = Math.min.apply(null, lats), n = Math.max.apply(null, lats);
    var fog = makeFogDataURL();
    map.addSource("fog", { type: "image", url: fog,
      coordinates: [[w, n], [e, n], [e, s], [w, s]] });
    map.addLayer({ id: "fog", type: "raster", source: "fog",
      paint: { "raster-opacity": ["interpolate", ["linear"], ["zoom"], 9,
        (f.properties.max_opacity || 0.35), 13, (f.properties.min_opacity || 0.1)],
        "raster-fade-duration": 0 } });
  }
  function makeFogDataURL() {
    var c = document.createElement("canvas"); c.width = c.height = 64;
    var g = c.getContext("2d");
    var grd = g.createRadialGradient(32, 32, 4, 32, 32, 34);
    grd.addColorStop(0, "rgba(255,255,255,0.9)");
    grd.addColorStop(1, "rgba(255,255,255,0.0)");
    g.fillStyle = grd; g.fillRect(0, 0, 64, 64);
    return c.toDataURL();
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
      var util = LAST_TRAFFIC[id].util_pct;
      map.setFeatureState({ source: "cables", id: id }, { util: util });
      if (map.getSource("drops")) map.setFeatureState({ source: "drops", id: id }, { util: util });
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
    });
    var ts = document.getElementById("nm-ts");
    if (ts && traffic.generated_at) ts.textContent = t("Last updated") + ": " + fmtTime(traffic.generated_at);
  }
  function refetchStructure() {
    fetch(STRUCTURE_URL, { mode: "cors" }).then(function (r) { return r.json(); })
      .then(function (structure) {
        STATE.generation = structure.generation;
        var src = buildSources(structure);
        map.getSource("cables").setData(src.cables);
        map.getSource("cable-media").setData(src.media);
        map.getSource("stations").setData(src.stations);
        map.getSource("devices").setData(src.devices);
        map.getSource("metro-cables").setData(src.metroCables);
        map.getSource("metro-stations").setData(src.metroStations);
        map.getSource("buildings").setData(src.buildings);
        map.getSource("drops").setData(src.drops);
        setTier();
        pollTraffic();
      }).catch(function () {});
  }
  function fmtTime(iso) {
    try { return new Date(iso).toLocaleTimeString(); } catch (e) { return iso; }
  }

  // ---- interactions (popovers) -------------------------------------------
  var popup = new maplibregl.Popup({ closeButton: false, closeOnClick: true,
    className: "nm-popup", maxWidth: "280px", offset: 12 });
  var hoverable = window.matchMedia && window.matchMedia("(hover: hover)").matches;

  // Priority order for picking what a click/hover targets (topmost intent first).
  var PICK_LAYERS = ["metro-stations-ring", "metro-line", "devices-dot",
    "stations-ring", "cables-hit"];
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
      if (!f) { clearSelection(); return; }
      var ev = { features: [f], lngLat: e.lngLat };
      var layer = f.layer.id;
      if (layer === "cables-hit") { selectFeature("cables", f); showCablePopup(ev); }
      else if (layer === "metro-line") { selectFeature("metro", f); showCablePopup(ev, true); }
      else if (layer === "metro-stations-ring") { clearSelection(); showMetroPopup(ev); }
      else { clearSelection(); showStationPopup(ev); }  // stations / devices
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
      "cables-intra", "cable-drops", "cable-water", "cable-submarine", "cable-ripple"],
    metro: ["metro-casing", "metro-line"]
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
    map.setFilter(hl, ["==", ["get", "id"], props.id]);
    // highlight the two endpoint sites; dim the rest
    var ssrc = STATION_SRC[source];
    _setStationDim(ssrc, STATION_KEYS_FOR(source), [props.a_site, props.z_site]);
    _dimmedStationSrc = ssrc;
  }
  window.__nmSelect = selectFeature;       // exposed for dev/screenshot tooling
  window.__nmClearSelect = clearSelection;

  function showMetroPopup(e) {
    var f = e.features && e.features[0]; if (!f) return;
    var p = f.properties;
    popup.setLngLat(e.lngLat).setHTML(
      '<div class="nm-pop"><div class="nm-pop-head">' + p.metro + '</div><div class="nm-pop-body">' +
      row(p.nsite + (p.nsite == 1 ? " site" : " sites"), "") +
      '<div class="nm-pop-row"><span class="v" style="font-weight:500">' + p.codes + "</span></div>" +
      "</div></div>").addTo(map);
  }

  function showCablePopup(e, isMetro) {
    var f = e.features && e.features[0]; if (!f) return;
    var p = f.properties, id = p.id;
    var tr = isMetro ? METRO_STATS[id] : LAST_TRAFFIC[id];
    map.getCanvas().style.cursor = "pointer";
    var head = p.a_site.toUpperCase() + " ⇆ " + p.z_site.toUpperCase();
    if (p.scope === "intra") head = p.a_site.toUpperCase() + " · intra-site";
    else if (p.scope === "metro") head = p.a_site + " ⇆ " + p.z_site;
    var rows = "";
    if (p.scope === "metro" && p.nmember) rows += row(p.nmember + " circuits", "");
    rows += row(t("Capacity"), capLabel(p.capacity_bps));
    if (p.status === "down") {
      rows += '<div class="nm-pop-row"><span class="nm-chip nm-chip-offline">' + t("link offline") + "</span></div>";
    } else if (tr) {
      rows += row(t("In"), fmtBps(tr.in_bps));
      rows += row(t("Out"), fmtBps(tr.out_bps));
      rows += row(t("of capacity"), (tr.util_pct != null ? tr.util_pct + "%" : "—"));
      rows += sparkline(tr, p.capacity_bps);
    }
    if (p.approximate) rows += '<div style="margin-top:6px"><span class="nm-badge-approx">' + t("approximate route") + "</span></div>";
    popup.setLngLat(e.lngLat).setHTML(
      '<div class="nm-pop"><div class="nm-pop-head">' + head + '</div><div class="nm-pop-body">' + rows + "</div></div>"
    ).addTo(map);
  }

  function showStationPopup(e) {
    var f = e.features && e.features[0]; if (!f) return;
    var p = f.properties;
    var code = p.code || (p.id ? p.id.split(".").slice(1).join(".") : "");
    var name = p.name || p.id || "";
    var body = "";
    if (p.operator) body += row("", p.operator);
    if (p.metro) body += row("", p.metro);
    if (p.address && p.address.indexOf("synthetic") < 0) body += '<div class="nm-pop-row"><span class="v" style="font-weight:500">' + p.address + "</span></div>";
    if (p.id && !p.code) { name = p.id.split(".")[0]; code = p.site || ""; }
    popup.setLngLat(e.lngLat).setHTML(
      '<div class="nm-pop"><div class="nm-pop-head">' + (code ? code.toUpperCase() + " · " : "") + name +
      '</div><div class="nm-pop-body">' + body + "</div></div>"
    ).addTo(map);
  }

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
