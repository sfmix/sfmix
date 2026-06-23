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
 *   - Held point: a bold accent-coloured "background" crosshair + a point on each
 *     series marks a pinned moment, and the readout freezes on its values so you
 *     can keep moving the faint live crosshair to compare other points. Desktop:
 *     click to pin (click again / ✕ to clear). Mobile: drag to move the crosshair,
 *     lift to hold that point; ✕ clears.
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

  function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
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

  // ── Held ("pinned") point marker ───────────────────────────────────────────
  // A bold, accent-coloured crosshair (vs the live cursor's faint blue-grey
  // dashed line) plus a filled point on each series — echoing uPlot's own cursor
  // points so the pin reads as "the same kind of marker, frozen in place". Lives
  // in u.over as DOM children, inserted *behind* the live cursor, so it survives
  // cursor moves (uPlot only repaints the canvas on data/scale/size changes) and
  // needs no canvas hooks.
  function makePinMarker(u) {
    var wrap = document.createElement("div");
    wrap.className = "nd-tf-pin-marker";
    wrap.style.display = "none";
    var line = document.createElement("div");
    line.className = "nd-tf-pin-xline";
    wrap.appendChild(line);
    u.over.insertBefore(wrap, u.over.firstChild); // behind the live cursor/points
    return { wrap: wrap, line: line, dots: [] };
  }
  function positionPinMarker(u, m, heldIdx, withDots) {
    if (heldIdx == null) { m.wrap.style.display = "none"; return; }
    var xpos = u.valToPos(u.data[0][heldIdx], "x");
    if (xpos < 0 || xpos > u.over.clientWidth + 1) { m.wrap.style.display = "none"; return; }
    m.wrap.style.display = "";
    m.line.style.left = Math.round(xpos) + "px";
    m.dots.forEach(function (d) { d.remove(); });
    m.dots.length = 0;
    if (!withDots) return; // stacked has no live cursor points either — line only
    for (var i = 1; i < u.series.length; i++) {
      var s = u.series[i];
      if (s.show === false) continue;
      var yval = u.data[i][heldIdx];
      if (yval == null) continue;
      var ypos = u.valToPos(yval, s.scale || "y");
      var dot = document.createElement("div");
      dot.className = "nd-tf-pin-dot";
      var stroke = typeof s.stroke === "function" ? s.stroke(u, i) : s.stroke;
      dot.style.background = stroke || TEXT_LIGHT;
      dot.style.left = Math.round(xpos) + "px";
      dot.style.top = Math.round(ypos) + "px";
      m.wrap.appendChild(dot);
      m.dots.push(dot);
    }
  }

  // Pointer interactions — symmetric on mouse and touch: press-drag-scrub the pin
  // and release to hold it.
  //   Touch: a finger drag moves the live crosshair; lifting holds that point.
  //   Mouse: pressing pins the point under the cursor and dragging scrubs it
  //          around live; releasing holds it. A press-release in place on the
  //          already-pinned point clears it (toggle). Plain hover (no button)
  //          still roams the live crosshair via uPlot.
  function attachInteractions(u, host) {
    var over = u.over;
    function place(e, prevent) {
      if (!e.touches || !e.touches.length) return;
      var t = e.touches[0];
      var rect = over.getBoundingClientRect();
      var left = t.clientX - rect.left, top = t.clientY - rect.top;
      if (left < 0 || left > rect.width) return;
      u.setCursor({ left: left, top: top });
      if (prevent && e.cancelable) e.preventDefault();
    }
    over.addEventListener("touchstart", function (e) { place(e, false); }, { passive: true });
    over.addEventListener("touchmove", function (e) { place(e, true); }, { passive: false });
    over.addEventListener("touchend", function (e) {
      if (e.cancelable) e.preventDefault(); // suppress the synthesized click
      if (u.cursor.idx != null) host._setHeld(u.cursor.idx);
    }, { passive: false });

    // Mouse drag-scrub. Listeners on document (added only while pressed, removed
    // on release) keep the scrub alive even if the pointer leaves the chart.
    over.addEventListener("mousedown", function (e) {
      if (e.button !== 0) return;
      e.preventDefault(); // no text selection while scrubbing
      var before = host._heldIdx, moved = false;
      if (u.cursor.idx != null) host._setHeld(u.cursor.idx);
      function move() {
        moved = true;
        if (u.cursor.idx != null) host._setHeld(u.cursor.idx);
      }
      function up() {
        document.removeEventListener("mousemove", move);
        document.removeEventListener("mouseup", up);
        // A click in place on the already-pinned point clears it.
        if (!moved && before != null && before === u.cursor.idx) host._setHeld(null);
      }
      document.addEventListener("mousemove", move);
      document.addEventListener("mouseup", up);
    });
  }

  // For the non-stacked charts (mirror/aggregate/line) we reuse uPlot's own
  // built-in legend rather than adding a second readout: this driver writes the
  // held (or, absent a pin, the live cursor) values into the existing .u-value
  // cells and flags the legend as pinned so CSS can recolour it. Runs from the
  // setCursor hook, so it wins over uPlot's own live update on every move.
  function makeLegendDriver(u) {
    var legendEl = u.root.querySelector(".u-legend");
    function render(liveIdx, heldIdx) {
      if (!legendEl) return;
      legendEl.classList.toggle("nd-tf-leg-pinned", heldIdx != null);
      var idx = heldIdx != null ? heldIdx : liveIdx;
      if (idx == null) return; // idle + unpinned: leave uPlot's default values
      var cells = legendEl.querySelectorAll(".u-value");
      for (var i = 0; i < u.series.length; i++) {
        var cell = cells[i];
        if (!cell) continue;
        var raw = u.data[i][idx];
        if (i === 0) {
          cell.textContent = (heldIdx != null ? "📌 " : "") + fmtTime(raw);
        } else {
          var s = u.series[i];
          cell.textContent = s.value ? s.value(u, raw, i, idx) : (raw == null ? "—" : String(raw));
        }
      }
    }
    return { render: render };
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
      hooks: { setCursor: [function () { host._refresh(); }] },
    };
    var u = new uPlot(opts, [xs, out, inNeg], host);
    return { u: u, render: makeLegendDriver(u).render };
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

    // Time line: a pinned segment ("📌 …" + clear) and a live cursor segment.
    // Created once; render toggles their visibility to avoid per-move churn.
    var timeEl = document.createElement("div");
    timeEl.className = "nd-tf-leg-time";
    var pinSpan = document.createElement("span");
    pinSpan.className = "nd-tf-leg-pin"; pinSpan.style.display = "none";
    var clearBtn = document.createElement("button");
    clearBtn.type = "button"; clearBtn.className = "nd-tf-pin-clear"; clearBtn.textContent = "✕";
    clearBtn.title = "Clear pinned point"; clearBtn.style.display = "none";
    clearBtn.addEventListener("click", function (e) { e.stopPropagation(); ctx.host._setHeld(null); });
    var cursorSpan = document.createElement("span");
    cursorSpan.className = "nd-tf-leg-cursor";
    timeEl.appendChild(pinSpan); timeEl.appendChild(clearBtn); timeEl.appendChild(cursorSpan);
    legend.appendChild(timeEl);

    var valEls = [], liveEls = [];
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
      valEls.push(valEl);
      // Secondary live value, shown in parens beside the held value when a pin
      // is active and the cursor is elsewhere.
      var liveEl = document.createElement("span");
      liveEl.className = "nd-tf-leg-live"; liveEl.style.display = "none";
      liveEls.push(liveEl);

      item.appendChild(sw);
      item.appendChild(nameEl);
      item.appendChild(valEl);
      item.appendChild(liveEl);
      item.addEventListener("click", function () {
        // Toggle this peer. Removing the last selected one empties the set,
        // which the renderer treats as "all shown" — so an all-off state can't
        // happen: it falls back to everything.
        if (sel.has(i)) sel.delete(i); else sel.add(i);
        ctx.rerender();
      });
      legend.appendChild(item);
    });

    // Render the legend for a live cursor index + held index. With a pin active,
    // the held values are primary and the live cursor's values trail in parens.
    function renderAt(liveIdx, heldIdx) {
      var heldOn = heldIdx != null;
      var liveElsewhere = heldOn && liveIdx != null && liveIdx !== heldIdx;
      if (heldOn) {
        pinSpan.style.display = ""; pinSpan.textContent = "📌 " + fmtTime(xs[heldIdx]);
        clearBtn.style.display = "";
        cursorSpan.style.display = liveElsewhere ? "" : "none";
        if (liveElsewhere) cursorSpan.textContent = " · ⌖ " + fmtTime(xs[liveIdx]);
      } else {
        pinSpan.style.display = "none"; clearBtn.style.display = "none";
        cursorSpan.style.display = "";
        cursorSpan.textContent = liveIdx != null ? fmtTime(xs[liveIdx]) : "latest";
      }
      var primaryIdx = heldOn ? heldIdx : (liveIdx != null ? liveIdx : null);
      peers.forEach(function (p, i) {
        var pv = primaryIdx != null ? p.values[primaryIdx] : lastNonNull(p.values);
        valEls[i].textContent = fmtVal(pv, unit);
        if (liveElsewhere) {
          liveEls[i].style.display = "";
          liveEls[i].textContent = "(" + fmtVal(p.values[liveIdx], unit) + ")";
        } else {
          liveEls[i].style.display = "none";
        }
      });
    }

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
      hooks: { setCursor: [function () { ctx.host._refresh(); }] },
    };
    var u = new uPlot(opts, seriesData, host);
    host.appendChild(legend);
    return { u: u, render: renderAt };
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
      hooks: { setCursor: [function () { host._refresh(); }] },
    };
    var u = new uPlot(opts, [xs, s0.values || [], neg], host);
    return { u: u, render: makeLegendDriver(u).render };
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
      hooks: { setCursor: [function () { host._refresh(); }] },
    };
    var u = new uPlot(opts, seriesData, host);
    return { u: u, render: makeLegendDriver(u).render };
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
      this._heldIdx = null;  // pinned point-in-time index (null = none)
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
    // Pin (or clear) the held point in time and refresh the readout + line.
    _setHeld(idx) { this._heldIdx = idx; this._refresh(); }
    // Push the current (live cursor, held) state into the chart's readout and
    // reposition the held line. Cheap; safe to call on every cursor move/resize.
    _refresh() {
      if (!this._u || !this._renderReadout || !this._data) return;
      var held = this._heldIdx;
      this._renderReadout(this._u.cursor.idx, held);
      if (this._pinMarker) positionPinMarker(this._u, this._pinMarker, held, this._pinDots);
    }
    _onResize() {
      if (this._u && this.clientWidth) {
        this._u.setSize({ width: this.clientWidth, height: 240 });
        this._refresh();
      }
    }
    _reset() {
      if (this._u) { this._u.destroy(); this._u = null; }
      this._renderReadout = null;
      this._pinMarker = null;
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
      var res = draw(this, this._data, { sel: this._sel, rerender: this._render.bind(this), host: this });
      if (!res || !res.u) return;
      this._u = res.u;
      this._renderReadout = res.render || function () {};
      this._pinMarker = makePinMarker(this._u);
      this._pinDots = this.kind !== "stacked"; // match the live cursor: dots only where it shows them
      attachInteractions(this._u, this);
      this._refresh();
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
          this._heldIdx = null;  // and any pinned point (timescale/peers differ)
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
