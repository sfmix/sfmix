#!/usr/bin/env python3
"""Local dev harness for the SFMIX network map.

Serves, on one port (default 8765):
  GET /map/map.json            -> the synthetic fixtures/map.json (structure)
  GET /statistics/map/traffic  -> fabricated live traffic, jittered every request
                                  so link re-colouring is visibly exercised
  GET /network-map/  or  /     -> a dev shell page that mounts the real
                                  website/static/js/network-map.js against these
                                  mock endpoints (no Hugo build required)
  everything else              -> static files from website/static/

This lets the entire MapLibre frontend be built and human-validated offline
before any Hugo/portal wiring exists. All traffic values are fake; the fixture
carries only synthetic cable shapes (never the NDA'd atlas).

Usage:  python3 network-map/dev/serve.py [--port 8765]
Then open http://localhost:8765/network-map/
"""
import argparse
import http.server
import json
import math
import os
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir))
STATIC = os.path.join(REPO, "website", "static")
FIXTURE = os.path.join(HERE, os.pardir, "fixtures", "map.json")

SERIES_POINTS = 48
SERIES_STEP_S = 1800


def load_fixture():
    with open(FIXTURE) as fh:
        return json.load(fh)


def fabricate_traffic(mapdata):
    """Produce a traffic feed matching the fixture's opaque cable ids."""
    now = time.time()
    links = {}
    for i, cable in enumerate(mapdata["cables"]):
        cap = cable["capacity_bps"]
        if cable["status"] == "down":
            links[cable["id"]] = {
                "in_bps": 0, "out_bps": 0, "util_pct": 0,
                "series_in": [0] * SERIES_POINTS, "series_out": [0] * SERIES_POINTS,
            }
            continue
        # deterministic-ish base load per cable, animated by wall clock + jitter
        phase = i * 0.7
        base = 0.15 + 0.35 * (0.5 + 0.5 * math.sin(now / 30.0 + phase))
        jitter = 0.08 * math.sin(now / 3.0 + phase * 2)
        frac_out = max(0.0, min(0.98, base + jitter))
        frac_in = max(0.0, min(0.98, base * 0.8 - jitter))
        out_bps = frac_out * cap
        in_bps = frac_in * cap
        series_out = [max(0.0, min(0.98, base + 0.2 * math.sin(now / 900.0 + phase + k / 5.0))) * cap
                      for k in range(SERIES_POINTS)]
        series_in = [v * 0.8 for v in series_out]
        links[cable["id"]] = {
            "in_bps": round(in_bps), "out_bps": round(out_bps),
            "util_pct": round(100 * max(frac_in, frac_out), 1),
            "series_in": [round(v) for v in series_in],
            "series_out": [round(v) for v in series_out],
        }
    return {
        "generation": mapdata["generation"],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "series": {"step_s": SERIES_STEP_S, "points": SERIES_POINTS},
        "links": links,
    }


DEV_SHELL = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SFMIX Network Map — dev harness</title>
<link rel="stylesheet" href="/vendor/maplibre-gl/maplibre-gl.css">
<link rel="stylesheet" href="/css/network-map.css">
<style>
  body { margin: 0; font-family: system-ui, sans-serif; background:#0b3640; color:#eee; }
  .devbar { padding: 6px 12px; font-size: 13px; background:#08262e; }
  #network-map { width: 100vw; height: calc(100vh - 33px); }
</style>
</head><body>
<div class="devbar">dev harness · mock data · <code>/map/map.json</code> + <code>/statistics/map/traffic</code></div>
<div id="network-map"
     data-structure-url="/map/map.json"
     data-traffic-url="/statistics/map/traffic"
     data-basemap-base="/map/"
     data-sprite-base="/map/sprites/"
     data-decorations-url="/map/decorations.json">
  <div id="nm-status"></div>
  <div id="nm-info" class="collapsed">
    <button class="nm-info-toggle" type="button" aria-expanded="false" aria-controls="nm-info-body">
      <span class="nm-info-icon" aria-hidden="true">i</span>
      <span class="nm-info-title">About this map</span>
      <span class="nm-info-chevron" aria-hidden="true"></span>
    </button>
    <div class="nm-info-body" id="nm-info-body">
      <div class="nm-info-about">
        <p>A live subway-style map of the SFMIX backbone across the Bay Area.</p>
        <p>Routes are approximate: they trace real transport corridors, not the exact fiber path on the ground. Links without surveyed geometry are routed along rights-of-way and then coarsened for display.</p>
        <p class="nm-info-algos">Path-finding: <a href="https://en.wikipedia.org/wiki/Dijkstra%27s_algorithm" target="_blank" rel="noopener">Dijkstra</a> · <a href="https://en.wikipedia.org/wiki/Ramer%E2%80%93Douglas%E2%80%93Peucker_algorithm" target="_blank" rel="noopener">Ramer–Douglas–Peucker</a></p>
        <p>Some locations shown aren't open for peering yet — including pending sites and passive, cross-connect-only facilities.</p>
        <p class="nm-info-hint">Tap any link or station for details.</p>
      </div>
      <div class="nm-info-detail" hidden>
        <button class="nm-info-back" type="button">Back to map info</button>
        <div class="nm-info-detail-body"></div>
      </div>
    </div>
  </div>
  <div id="nm-legend">
    <button class="nm-legend-toggle" type="button">Legend</button>
    <div class="nm-legend-body">
      <h4>Link utilization</h4>
      <div class="nm-ramp"></div>
      <div class="nm-ramp-labels"><span>0%</span><span>50%</span><span>100%</span></div>
      <div class="nm-legend-key"><span class="swatch" style="border-top-color:#9aa4aa;border-top-style:dashed"></span> offline</div>
      <div class="nm-legend-key"><span class="swatch" style="border-top-color:#73BF69;border-top-style:dotted"></span> approximate route</div>
      <div class="nm-ts" id="nm-ts"></div>
    </div>
  </div>
</div>
<script type="application/json" id="map-i18n">{
  "In": "In", "Out": "Out", "of capacity": "of capacity",
  "Last updated": "Last updated", "approximate route": "approximate route",
  "link offline": "link offline", "Capacity": "Capacity",
  "underground": "underground", "aerial": "aerial", "submarine": "submarine",
  "bridge": "bridge", "building": "building",
  "Location": "Location", "Networks": "Networks", "Exchanges": "Exchanges",
  "View on PeeringDB": "View on PeeringDB",
  "live stats unavailable": "live stats unavailable"
}</script>
<script src="/vendor/maplibre-gl/maplibre-gl.js"></script>
<script>
  // expose the map instance for dev tooling (dev/screenshot.mjs waits on it)
  (function () {
    var RealMap = maplibregl.Map;
    maplibregl.Map = function (o) { var m = new RealMap(o); window.__map = m; return m; };
    maplibregl.Map.prototype = RealMap.prototype;
  })();
</script>
<script src="/js/network-map.js" defer></script>
</body></html>
"""


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=STATIC, **kw)

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        # NB: no ACAO here — end_headers() already adds it for every response;
        # a duplicate produces "*, *", which browsers reject wholesale.
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/statistics/map/traffic":
            return self._send_json(fabricate_traffic(load_fixture()))
        if path == "/map/map.json":
            return self._send_json(load_fixture())
        # /map/decorations.json + basemap + sprites are served as static files
        # from website/static/map/ by the fall-through handler.
        if path in ("/", "/network-map", "/network-map/"):
            return self._send_html(DEV_SHELL)
        return super().do_GET()

    def end_headers(self):
        # static assets are same-origin here, but keep CORS open for parity
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def log_message(self, fmt, *args):
        pass  # quiet


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print("dev harness on http://localhost:%d/network-map/" % args.port)
    print("serving static from", STATIC)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
