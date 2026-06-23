/* SFMIX participant traffic charts.
 *
 * A <sfmix-chart> custom element fetches a *named panel* from the portal
 * (which builds the PromQL server-side — the browser never sends a query) and
 * renders it with uPlot. Two kinds:
 *
 *   <sfmix-chart panel="if_counters" kind="mirror" asn="6939" port="0" range="24h">
 *   <sfmix-chart panel="peers_from"  kind="stacked" asn="6939" range="24h">
 *
 * The range picker calls setRange() on every chart, which re-queries and
 * redraws. Colours are pulled from the portal's CSS custom properties so the
 * charts look native.
 *
 * Interaction features:
 *   - Time zone toggle ("SF Time" = US/Pacific, "UTC"): one page-global choice,
 *     remembered in localStorage, applied to every chart's axis/legend/crosshair
 *     without re-querying (charts redraw from cached data).
 *   - Stacked charts: clicking a legend item isolates that band; a second click
 *     adds another; the stack is recomputed over just the selected peers. When
 *     the selection empties (all toggled off) every band is shown again.
 *   - Crosshair picker: hovering (or dragging a touch) shows a vertical
 *     crosshair and updates the legend values + a time readout to that exact
 *     point in time. Drag-to-zoom is disabled so a touch acts purely as a picker.
 */
(function () {
  "use strict";

  // Resolve the portal palette from CSS custom properties (set by tailwind @theme).
  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return (v && v.trim()) || fallback;
  }
  var TEAL = cssVar("--color-primary-light", "#1a6070");
  var AMBER = cssVar("--color-accent", "#e8913a");
  var BORDER = cssVar("--color-border", "#dee2e6");
  var TEXT_LIGHT = cssVar("--color-text-light", "#666666");
  // Distinct bands for the stacked peer chart (teal/amber-leaning, colour-blind-ish safe).
  var PALETTE = [TEAL, AMBER, "#2a5a8c", "#1d7a3e", "#8B2FC9", "#c2701f", "#5a8ca0", "#a03b6a", "#9ca3af"];

  // ── Time zone ───────────────────────────────────────────────────────────
  // One page-global choice ("sf" = US/Pacific, "utc"). Remembered across visits;
  // defaults to SF time. Charts read it at draw time, so a toggle just redraws.
  var TZ_KEY = "sfmix.chartTz";
  var TZ_ZONES = { sf: "America/Los_Angeles", utc: "UTC" };
  var TZ_ABBR = { sf: "PT", utc: "UTC" };
  var TZ_LABELS = { sf: "SF Time", utc: "UTC" };

  function currentTz() {
    var t = null;
    try { t = localStorage.getItem(TZ_KEY); } catch (e) {}
    return t === "utc" || t === "sf" ? t : "sf";
  }
  function tzZone() { return TZ_ZONES[currentTz()]; }

  // Intl formatters are not free to build; cache one per zone.
  var _partsFmt = {};
  function partsFmt(zone) {
    if (!_partsFmt[zone]) {
      _partsFmt[zone] = new Intl.DateTimeFormat("en-US", {
        timeZone: zone, hour12: false,
        year: "numeric", month: "2-digit", day: "2-digit",
        hour: "2-digit", minute: "2-digit", second: "2-digit",
      });
    }
    return _partsFmt[zone];
  }

  // uPlot's tzDate contract: given a unix timestamp (seconds), return a Date
  // whose *local* getters (getHours, getDate, …) read as the wall-clock in the
  // target zone. We synthesise that by reading the zone's wall-clock parts via
  // Intl and feeding them to the local Date constructor.
  function zonedDate(unixSec, zone) {
    var parts = {};
    partsFmt(zone).formatToParts(new Date(unixSec * 1000)).forEach(function (p) {
      if (p.type !== "literal") parts[p.type] = p.value;
    });
    var hour = parts.hour === "24" ? 0 : parseInt(parts.hour, 10);
    return new Date(
      parseInt(parts.year, 10), parseInt(parts.month, 10) - 1, parseInt(parts.day, 10),
      hour, parseInt(parts.minute, 10), parseInt(parts.second, 10)
    );
  }
  function tzDateFn() {
    var zone = tzZone();
    return function (ts) { return zonedDate(ts, zone); };
  }

  var _labelFmt = {};
  function labelFmt(zone) {
    if (!_labelFmt[zone]) {
      _labelFmt[zone] = new Intl.DateTimeFormat("en-US", {
        timeZone: zone, hour12: false,
        month: "short", day: "2-digit",
        hour: "2-digit", minute: "2-digit", second: "2-digit",
      });
    }
    return _labelFmt[zone];
  }
  // Human point-in-time string for the legend, e.g. "Jun 22, 14:05:00 PT".
  function fmtTime(unixSec) {
    if (unixSec == null) return "";
    var tz = currentTz();
    return labelFmt(TZ_ZONES[tz]).format(new Date(unixSec * 1000)) + " " + TZ_ABBR[tz];
  }

  // bits/sec -> human string.
  function fmtBps(v) {
    if (v == null || isNaN(v)) return "—";
    var a = Math.abs(v), u = "bps", d = v;
    if (a >= 1e9) { d = v / 1e9; u = "Gbps"; }
    else if (a >= 1e6) { d = v / 1e6; u = "Mbps"; }
    else if (a >= 1e3) { d = v / 1e3; u = "Kbps"; }
    var s = Math.abs(d) >= 100 ? Math.round(d) : d.toFixed(1);
    return s + " " + u;
  }
  function fmtAxis(v) {
    var a = Math.abs(v);
    if (a >= 1e9) return (v / 1e9) + "G";
    if (a >= 1e6) return (v / 1e6) + "M";
    if (a >= 1e3) return (v / 1e3) + "k";
    return "" + v;
  }

  // Unit-aware value/axis formatters. Panels carry a "unit" (bps | percent |
  // count); bps is the default and keeps the original behaviour.
  function fmtVal(v, unit) {
    if (v == null || isNaN(v)) return "—";
    if (unit === "percent") return (Math.abs(v) >= 100 ? Math.round(v) : v.toFixed(1)) + "%";
    if (unit === "count") return Math.round(v).toLocaleString();
    return fmtBps(v);
  }
  function fmtAxisFor(unit) {
    return function (v) { return unit === "percent" ? v + "%" : fmtAxis(v); };
  }

  function lastNonNull(values) {
    for (var k = values.length - 1; k >= 0; k--) { if (values[k] != null) return values[k]; }
    return null;
  }

  function cumulative(seriesValues) {
    // seriesValues: array of value-arrays (per peer). Returns cumulative arrays,
    // smallest-on-top painter order handled by caller.
    var n = seriesValues.length, len = seriesValues[0] ? seriesValues[0].length : 0;
    var cum = [];
    var running = new Array(len).fill(0);
    for (var i = 0; i < n; i++) {
      running = running.map(function (acc, j) { return acc + (seriesValues[i][j] || 0); });
      cum.push(running.slice());
    }
    return cum; // cum[i] = sum of series 0..i
  }

  // Common cursor: vertical crosshair only, no drag-to-zoom (so a touch drag is
  // a picker, not a zoom-select). `points` toggled per-kind by the caller.
  function pickerCursor(extra) {
    var c = { y: false, drag: { x: false, y: false, setScale: false } };
    if (extra) for (var k in extra) c[k] = extra[k];
    return c;
  }

  // Drive the uPlot cursor from touch so dragging a finger across the chart
  // moves the crosshair and updates the legend (uPlot's own cursor is mouse-only).
  function enableTouchPicker(u) {
    if (!u || !u.over) return;
    var over = u.over;
    function handle(e) {
      if (!e.touches || !e.touches.length) return;
      var t = e.touches[0];
      var rect = over.getBoundingClientRect();
      var left = t.clientX - rect.left;
      var top = t.clientY - rect.top;
      if (left < 0 || left > rect.width) return;
      u.setCursor({ left: left, top: top });
      if (e.cancelable) e.preventDefault(); // keep the gesture on the chart, not page scroll
    }
    over.addEventListener("touchstart", handle, { passive: false });
    over.addEventListener("touchmove", handle, { passive: false });
  }

  function drawMirror(host, data) {
    // out above the axis, in mirrored below.
    var xs = data.timestamps;
    var out = (data.series.find(function (s) { return s.name === "out"; }) || {}).values || [];
    var inb = (data.series.find(function (s) { return s.name === "in"; }) || {}).values || [];
    var inNeg = inb.map(function (v) { return v == null ? null : -v; });

    var opts = {
      width: host.clientWidth || 720,
      height: 240,
      tzDate: tzDateFn(),
      cursor: pickerCursor(),
      scales: { x: { time: true } },
      legend: { live: true },
      axes: [
        { stroke: TEXT_LIGHT, grid: { stroke: BORDER, width: 1 }, ticks: { stroke: BORDER } },
        { stroke: TEXT_LIGHT, grid: { stroke: BORDER, width: 1 }, ticks: { stroke: BORDER }, values: function (u, sp) { return sp.map(fmtAxis); } },
      ],
      series: [
        { value: function (u, v) { return fmtTime(v); } },
        { label: "Out → IX", stroke: TEAL, width: 2, fill: TEAL + "26", value: function (u, v) { return fmtBps(v); } },
        { label: "In ← IX", stroke: AMBER, width: 2, fill: AMBER + "26", value: function (u, v) { return fmtBps(v == null ? null : -v); } },
      ],
    };
    return new uPlot(opts, [xs, out, inNeg], host);
  }

  function drawStacked(host, data, ctx) {
    var xs = data.timestamps;
    var unit = data.unit;
    var peers = data.series; // already sorted, top peers + Other
    if (!peers.length) return null;

    // Selection of peer indices to isolate; empty Set => show all. Lives on the
    // host element so it survives a tz-driven redraw but resets on a re-query.
    var sel = ctx.sel;
    var shownIdx = [];
    for (var i = 0; i < peers.length; i++) {
      if (sel.size === 0 || sel.has(i)) shownIdx.push(i);
    }
    // Cumulative over just the shown subset (original order preserved).
    var cum = cumulative(shownIdx.map(function (idx) { return peers[idx].values; }));

    // Painter's algorithm: draw the largest cumulative first so smaller bands
    // paint over it, leaving each peer's slice visible. uPlot draws series in
    // array order, so list cumulative arrays from top (total) down to bottom.
    // Colour by *original* index so a peer keeps its colour when isolated.
    var series = [{ value: function (u, v) { return fmtTime(v); } }];
    var seriesData = [xs];
    for (var k = shownIdx.length - 1; k >= 0; k--) {
      var origIdx = shownIdx[k];
      var color = PALETTE[origIdx % PALETTE.length];
      var p = peers[origIdx];
      var lbl = p.asn ? p.name + " (AS" + p.asn + ")" : p.name;
      series.push({ label: lbl, stroke: color, width: 0, fill: color, points: { show: false } });
      seriesData.push(cum[k]);
    }

    var legend = document.createElement("div");
    legend.className = "nd-tf-legend";

    // Point-in-time readout, updated by the crosshair; "latest" when idle.
    var timeEl = document.createElement("div");
    timeEl.className = "nd-tf-leg-time";
    legend.appendChild(timeEl);

    var valEls = [];
    peers.forEach(function (p, i) {
      var item = document.createElement("button");
      item.type = "button";
      item.className = "nd-tf-leg-item";
      var active = sel.size === 0 || sel.has(i);
      if (!active) item.classList.add("nd-tf-off");
      item.setAttribute("aria-pressed", sel.has(i) ? "true" : "false");
      item.title = active ? "Show only this series (click again to add more)" : "Add this series";

      var sw = document.createElement("span");
      sw.className = "nd-tf-sw";
      sw.style.background = PALETTE[i % PALETTE.length];
      var nameEl = document.createElement("span");
      nameEl.className = "nd-tf-leg-name";
      nameEl.innerHTML = escapeHtml(p.name) +
        (p.asn ? ' <span class="nd-tf-leg-asn">AS' + escapeHtml(p.asn) + "</span>" : "");
      var valEl = document.createElement("span");
      valEl.className = "nd-tf-leg-val";
      valEl.textContent = fmtVal(lastNonNull(p.values), unit);
      valEls.push(valEl);

      item.appendChild(sw);
      item.appendChild(nameEl);
      item.appendChild(valEl);
      item.addEventListener("click", function () {
        // Toggle this peer. Removing the last selected one empties the set,
        // which the renderer treats as "all shown" — so an all-off state can't
        // happen: it falls back to everything.
        if (sel.has(i)) sel.delete(i); else sel.add(i);
        ctx.rerender();
      });
      legend.appendChild(item);
    });

    // Reflect the crosshair: idx null => latest values, else values at that time.
    function renderAt(idx) {
      if (idx == null) {
        timeEl.textContent = "latest";
        peers.forEach(function (p, i) { valEls[i].textContent = fmtVal(lastNonNull(p.values), unit); });
      } else {
        timeEl.textContent = fmtTime(xs[idx]);
        peers.forEach(function (p, i) { valEls[i].textContent = fmtVal(p.values[idx], unit); });
      }
    }
    renderAt(null);

    var opts = {
      width: host.clientWidth || 720,
      height: 240,
      legend: { show: false },
      tzDate: tzDateFn(),
      cursor: pickerCursor({ points: { show: false } }),
      scales: { x: { time: true } },
      axes: [
        { stroke: TEXT_LIGHT, grid: { stroke: BORDER, width: 1 }, ticks: { stroke: BORDER } },
        { stroke: TEXT_LIGHT, grid: { stroke: BORDER, width: 1 }, ticks: { stroke: BORDER }, values: function (u, sp) { return sp.map(fmtAxisFor(unit)); } },
      ],
      series: series,
      hooks: { setCursor: [function (u) { renderAt(u.cursor.idx); }] },
    };
    var u = new uPlot(opts, seriesData, host);
    host.appendChild(legend);
    return u;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  function drawAggregate(host, data) {
    // Exchange-wide ingress above the axis, egress mirrored below.
    var xs = data.timestamps;
    var s0 = data.series[0] || { values: [] };
    var s1 = data.series[1] || { values: [] };
    var neg = (s1.values || []).map(function (v) { return v == null ? null : -v; });
    var opts = {
      width: host.clientWidth || 720,
      height: 240,
      tzDate: tzDateFn(),
      cursor: pickerCursor(),
      scales: { x: { time: true } },
      legend: { live: true },
      axes: [
        { stroke: TEXT_LIGHT, grid: { stroke: BORDER, width: 1 }, ticks: { stroke: BORDER } },
        { stroke: TEXT_LIGHT, grid: { stroke: BORDER, width: 1 }, ticks: { stroke: BORDER }, values: function (u, sp) { return sp.map(fmtAxis); } },
      ],
      series: [
        { value: function (u, v) { return fmtTime(v); } },
        { label: s0.name || "Ingress", stroke: TEAL, width: 2, fill: TEAL + "26", value: function (u, v) { return fmtBps(v); } },
        { label: s1.name || "Egress", stroke: AMBER, width: 2, fill: AMBER + "26", value: function (u, v) { return fmtBps(v == null ? null : -v); } },
      ],
    };
    return new uPlot(opts, [xs, s0.values || [], neg], host);
  }

  function drawLine(host, data) {
    // One or more plain lines; unit-aware axis/legend (bps, percent, count).
    var xs = data.timestamps;
    var unit = data.unit;
    var series = [{ value: function (u, v) { return fmtTime(v); } }];
    var seriesData = [xs];
    data.series.forEach(function (s, i) {
      var color = PALETTE[i % PALETTE.length];
      series.push({ label: s.name, stroke: color, width: 2, value: function (u, v) { return fmtVal(v, unit); } });
      seriesData.push(s.values);
    });
    var opts = {
      width: host.clientWidth || 720,
      height: 240,
      tzDate: tzDateFn(),
      cursor: pickerCursor(),
      scales: { x: { time: true } },
      legend: { live: true },
      axes: [
        { stroke: TEXT_LIGHT, grid: { stroke: BORDER, width: 1 }, ticks: { stroke: BORDER } },
        { stroke: TEXT_LIGHT, grid: { stroke: BORDER, width: 1 }, ticks: { stroke: BORDER }, values: function (u, sp) { return sp.map(fmtAxisFor(unit)); } },
      ],
      series: series,
    };
    return new uPlot(opts, seriesData, host);
  }

  var DRAW = { mirror: drawMirror, stacked: drawStacked, aggregate: drawAggregate, line: drawLine };

  class SfmixChart extends HTMLElement {
    connectedCallback() {
      this.panel = this.getAttribute("panel");
      this.kind = this.getAttribute("kind") || "mirror";
      this.asn = this.getAttribute("asn");
      this.port = this.getAttribute("port");
      // Optional explicit metrics endpoint (e.g. the exchange-wide stats page);
      // defaults to the per-participant endpoint built from `asn`.
      this.endpoint = this.getAttribute("endpoint");
      this.range = this.getAttribute("range") || "24h";
      this._sel = new Set(); // isolated peer indices for the stacked legend
      this._ro = new ResizeObserver(this._onResize.bind(this));
      this._ro.observe(this);
      this.load();
    }
    disconnectedCallback() {
      if (this._ro) this._ro.disconnect();
      if (this._u) this._u.destroy();
    }
    setRange(r) {
      if (r === this.range) return;
      this.range = r;
      this.load();
    }
    // Redraw from cached data (no re-query) — used by the time-zone toggle.
    applyTz() { if (this._data) this._render(); }
    _onResize() {
      if (this._u && this.clientWidth) this._u.setSize({ width: this.clientWidth, height: 240 });
    }
    _reset() {
      if (this._u) { this._u.destroy(); this._u = null; }
      this.innerHTML = "";
    }
    _skeleton(msg) {
      this._reset();
      var d = document.createElement("div");
      d.className = "nd-tf-skel";
      d.textContent = msg;
      this.appendChild(d);
    }
    _render() {
      this._reset();
      var draw = DRAW[this.kind] || drawMirror;
      this._u = draw(this, this._data, { sel: this._sel, rerender: this._render.bind(this) });
      if (this._u) enableTouchPicker(this._u);
    }
    load() {
      this._skeleton("querying…");
      var base = this.endpoint || ("/participants/" + encodeURIComponent(this.asn) + "/metrics/");
      var url = base + "?panel=" + encodeURIComponent(this.panel) +
        "&range=" + encodeURIComponent(this.range);
      if (this.port != null && this.port !== "") url += "&port=" + encodeURIComponent(this.port);
      var token = (this._tok = Symbol());
      fetch(url, { headers: { Accept: "application/json" } })
        .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
        .then(function (data) {
          if (this._tok !== token) return; // a newer load() superseded this one
          var hasData = data.series && data.series.some(function (s) {
            return s.values && s.values.some(function (v) { return v != null && v !== 0; });
          });
          if (!hasData) { this._skeleton("No traffic data for this window."); return; }
          this._data = data;
          this._sel = new Set(); // fresh data: drop any prior isolation
          this._render();
        }.bind(this))
        .catch(function () {
          if (this._tok !== token) return;
          this._skeleton("Unable to load traffic data.");
        }.bind(this));
    }
  }
  if (!customElements.get("sfmix-chart")) customElements.define("sfmix-chart", SfmixChart);

  // Range picker: each picker is local to its own chart group (the enclosing
  // .nd-tf-band) — the peer-traffic section and every per-port interface band
  // have independent ranges.
  document.addEventListener("click", function (e) {
    var btn = e.target.closest(".nd-tf-range button");
    if (!btn) return;
    var group = btn.closest(".nd-tf-band") || document;
    var r = btn.getAttribute("data-range");
    group.querySelectorAll(".nd-tf-range button").forEach(function (b) {
      b.classList.toggle("on", b.getAttribute("data-range") === r);
    });
    group.querySelectorAll("sfmix-chart").forEach(function (c) { c.setRange(r); });
  });

  // ── Time-zone toggle ─────────────────────────────────────────────────────
  // Injected next to every range picker so it sits beside any chart. The choice
  // is page-global: clicking any toggle updates them all + redraws every chart.
  function buildTzToggle() {
    var wrap = document.createElement("div");
    wrap.className = "nd-tf-tz";
    wrap.setAttribute("role", "group");
    wrap.setAttribute("aria-label", "Time zone");
    var cur = currentTz();
    ["sf", "utc"].forEach(function (tz) {
      var b = document.createElement("button");
      b.type = "button";
      b.setAttribute("data-tz", tz);
      b.textContent = TZ_LABELS[tz];
      if (tz === cur) b.classList.add("on");
      wrap.appendChild(b);
    });
    return wrap;
  }
  function injectTzToggles() {
    document.querySelectorAll(".nd-tf-range").forEach(function (range) {
      if (range.parentNode && range.parentNode.querySelector(".nd-tf-tz")) return;
      range.insertAdjacentElement("afterend", buildTzToggle());
    });
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest(".nd-tf-tz button");
    if (!btn) return;
    var tz = btn.getAttribute("data-tz");
    if (tz !== "sf" && tz !== "utc") return;
    try { localStorage.setItem(TZ_KEY, tz); } catch (err) {}
    document.querySelectorAll(".nd-tf-tz button").forEach(function (b) {
      b.classList.toggle("on", b.getAttribute("data-tz") === tz);
    });
    document.querySelectorAll("sfmix-chart").forEach(function (c) { if (c.applyTz) c.applyTz(); });
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", injectTzToggles);
  } else {
    injectTzToggles();
  }
})();
