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

  function drawMirror(host, data) {
    // out above the axis, in mirrored below.
    var xs = data.timestamps;
    var out = (data.series.find(function (s) { return s.name === "out"; }) || {}).values || [];
    var inb = (data.series.find(function (s) { return s.name === "in"; }) || {}).values || [];
    var inNeg = inb.map(function (v) { return v == null ? null : -v; });

    var opts = {
      width: host.clientWidth || 720,
      height: 240,
      cursor: { y: false },
      scales: { x: { time: true } },
      legend: { live: true },
      axes: [
        { stroke: TEXT_LIGHT, grid: { stroke: BORDER, width: 1 }, ticks: { stroke: BORDER } },
        { stroke: TEXT_LIGHT, grid: { stroke: BORDER, width: 1 }, ticks: { stroke: BORDER }, values: function (u, sp) { return sp.map(fmtAxis); } },
      ],
      series: [
        { value: function (u, v) { return v == null ? "" : new Date(v * 1000).toLocaleString(); } },
        { label: "Out → IX", stroke: TEAL, width: 2, fill: TEAL + "26", value: function (u, v) { return fmtBps(v); } },
        { label: "In ← IX", stroke: AMBER, width: 2, fill: AMBER + "26", value: function (u, v) { return fmtBps(v == null ? null : -v); } },
      ],
    };
    return new uPlot(opts, [xs, out, inNeg], host);
  }

  function drawStacked(host, data) {
    var xs = data.timestamps;
    var peers = data.series; // already sorted, top peers + Other
    if (!peers.length) return null;
    var vals = peers.map(function (p) { return p.values; });
    var cum = cumulative(vals);

    // Painter's algorithm: draw the largest cumulative first so smaller bands
    // paint over it, leaving each peer's slice visible. uPlot draws series in
    // array order, so list cumulative arrays from top (total) down to bottom.
    var series = [{ value: function (u, v) { return v == null ? "" : new Date(v * 1000).toLocaleString(); } }];
    var seriesData = [xs];
    for (var i = peers.length - 1; i >= 0; i--) {
      var color = PALETTE[i % PALETTE.length];
      var lbl = peers[i].asn ? peers[i].name + " (AS" + peers[i].asn + ")" : peers[i].name;
      series.push({ label: lbl, stroke: color, width: 0, fill: color, points: { show: false } });
      seriesData.push(cum[i]);
    }

    var opts = {
      width: host.clientWidth || 720,
      height: 240,
      legend: { show: false },
      cursor: { y: false },
      scales: { x: { time: true } },
      axes: [
        { stroke: TEXT_LIGHT, grid: { stroke: BORDER, width: 1 }, ticks: { stroke: BORDER } },
        { stroke: TEXT_LIGHT, grid: { stroke: BORDER, width: 1 }, ticks: { stroke: BORDER }, values: function (u, sp) { return sp.map(fmtAxis); } },
      ],
      series: series,
    };
    var u = new uPlot(opts, seriesData, host);

    // Custom legend: peer name + current value (de-cumulated, real per-peer).
    var legend = document.createElement("div");
    legend.className = "nd-tf-legend";
    peers.forEach(function (p, i) {
      var last = null;
      for (var k = p.values.length - 1; k >= 0; k--) { if (p.values[k] != null) { last = p.values[k]; break; } }
      var item = document.createElement("span");
      item.className = "nd-tf-leg-item";
      var asnTag = p.asn ? ' <span class="nd-tf-leg-asn">AS' + escapeHtml(p.asn) + "</span>" : "";
      item.innerHTML =
        '<span class="nd-tf-sw" style="background:' + PALETTE[i % PALETTE.length] + '"></span>' +
        '<span class="nd-tf-leg-name">' + escapeHtml(p.name) + asnTag + "</span>" +
        '<span class="nd-tf-leg-val">' + fmtBps(last) + "</span>";
      legend.appendChild(item);
    });
    host.appendChild(legend);
    return u;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  var DRAW = { mirror: drawMirror, stacked: drawStacked };

  class SfmixChart extends HTMLElement {
    connectedCallback() {
      this.panel = this.getAttribute("panel");
      this.kind = this.getAttribute("kind") || "mirror";
      this.asn = this.getAttribute("asn");
      this.port = this.getAttribute("port");
      this.range = this.getAttribute("range") || "24h";
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
    load() {
      this._skeleton("querying…");
      var url = "/participants/" + encodeURIComponent(this.asn) + "/metrics/?panel=" +
        encodeURIComponent(this.panel) + "&range=" + encodeURIComponent(this.range);
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
          this._reset();
          this._u = (DRAW[this.kind] || drawMirror)(this, data);
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
})();
