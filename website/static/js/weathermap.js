/* SFMIX backbone weathermap — the classic schematic view, off-Grafana.
 *
 * Data (both from the portal, same feeds as the geographic network map):
 *   structure  GET data-structure-url  -> weathermap.json {generation, view,
 *              metros, nodes[{id,kind,site,metro,x,y,label}],
 *              links[{id,a,z,scope,status,capacity_bps,members}]}
 *   traffic    GET data-traffic-url    -> /statistics/map/traffic
 *              {generation, links:{id:{in_bps,out_bps,util_pct,members[]}}}
 *
 * Every link is drawn as its physical member strands; each strand splits at
 * its midpoint into two directional halves — the half nearer a node is
 * coloured by the traffic *leaving* that node on the strand (A-half = out,
 * Z-half = in, matching the traffic feed's a-side port convention) with a
 * chevron pointing along the flow. Structure loads once; traffic repaints via
 * plain attribute updates (no relayout). The link ids are per-generation
 * opaque ids shared with map.json, so a generation mismatch between the two
 * feeds triggers a structure refetch.
 */
(function () {
  "use strict";
  var root = document.getElementById("weathermap");
  if (!root) return;
  var STRUCTURE_URL = root.dataset.structureUrl;
  var TRAFFIC_URL = root.dataset.trafficUrl;
  var POLL_MS = 60000;

  var I18N = {};
  try { I18N = JSON.parse(document.getElementById("wm-i18n").textContent); } catch (e) {}
  function t(s) { return I18N[s] || s; }

  // Same utilization ramp as the geographic map (and the old Grafana panel).
  var RAMP = [
    [0, "#5794F2"], [20, "#73BF69"], [40, "#FADE2A"], [60, "#FF9830"], [80, "#F2495C"]
  ];
  var PLANNED_COLOR = "#7d9cc0";
  var OFFLINE_COLOR = "#9aa4aa";

  function hex2rgb(h) {
    return [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
  }
  function utilColor(u) {
    if (u == null || isNaN(u)) u = 0;
    if (u <= RAMP[0][0]) return RAMP[0][1];
    for (var i = 1; i < RAMP.length; i++) {
      if (u <= RAMP[i][0]) {
        var a = hex2rgb(RAMP[i - 1][1]), b = hex2rgb(RAMP[i][1]);
        var f = (u - RAMP[i - 1][0]) / (RAMP[i][0] - RAMP[i - 1][0]);
        return "rgb(" + Math.round(a[0] + (b[0] - a[0]) * f) + "," +
          Math.round(a[1] + (b[1] - a[1]) * f) + "," +
          Math.round(a[2] + (b[2] - a[2]) * f) + ")";
      }
    }
    return RAMP[RAMP.length - 1][1];
  }

  function fmtBps(b) {
    if (!b || b < 1) return "0";
    var u = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"], i = 0;
    while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
    return (b >= 100 ? b.toFixed(0) : b.toFixed(1)) + " " + u[i];
  }
  function capLabel(b) { return fmtBps(b).replace("bps", "b/s"); }

  function strandWidth(bps) { // per physical member link
    var g = bps / 1e9;
    if (g >= 400) return 7;
    if (g >= 100) return 5;
    if (g >= 40) return 4;
    if (g >= 10) return 3;
    return 2.2;
  }

  var svgNS = "http://www.w3.org/2000/svg";
  function el(name, attrs, parent) {
    var n = document.createElementNS(svgNS, name);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }

  // STATE.strands[cableId] = [{h1,h2,c1,c2,speed}] per member; chips/hit by id.
  var STATE = { generation: null, nodes: {}, links: [], strands: {}, chips: {}, traffic: null };

  // ---- slippy viewport: drag pans, wheel/pinch/dblclick/buttons zoom -------
  var SVG = null, FITBOX = null, VIEWBOX = null, dragDist = 0;

  function applyViewBox() {
    SVG.setAttribute("viewBox", VIEWBOX.x.toFixed(1) + " " + VIEWBOX.y.toFixed(1) +
      " " + VIEWBOX.w.toFixed(1) + " " + VIEWBOX.h.toFixed(1));
  }
  function clampViewBox() {
    var over = 0.15; // allow a little slack past the drawing's edge
    VIEWBOX.w = Math.min(Math.max(VIEWBOX.w, FITBOX.w / 8), FITBOX.w);
    VIEWBOX.h = VIEWBOX.w * FITBOX.h / FITBOX.w;
    VIEWBOX.x = Math.min(Math.max(VIEWBOX.x, -FITBOX.w * over),
      FITBOX.w * (1 + over) - VIEWBOX.w);
    VIEWBOX.y = Math.min(Math.max(VIEWBOX.y, -FITBOX.h * over),
      FITBOX.h * (1 + over) - VIEWBOX.h);
  }
  function viewScale() { // CSS px per user unit (letterboxed "meet" fitting)
    var r = SVG.getBoundingClientRect();
    return Math.min(r.width / VIEWBOX.w, r.height / VIEWBOX.h);
  }
  function clientToUser(cx, cy) {
    var r = SVG.getBoundingClientRect(), s = viewScale();
    var ox = (r.width - VIEWBOX.w * s) / 2, oy = (r.height - VIEWBOX.h * s) / 2;
    return [VIEWBOX.x + (cx - r.left - ox) / s, VIEWBOX.y + (cy - r.top - oy) / s];
  }
  function zoomAt(cx, cy, factor) {
    var p = clientToUser(cx, cy);
    var w1 = Math.min(Math.max(VIEWBOX.w / factor, FITBOX.w / 8), FITBOX.w);
    var f = VIEWBOX.w / w1;
    VIEWBOX.x = p[0] - (p[0] - VIEWBOX.x) / f;
    VIEWBOX.y = p[1] - (p[1] - VIEWBOX.y) / f;
    VIEWBOX.w = w1;
    clampViewBox();
    applyViewBox();
  }
  function initPanZoom(svg, W, H) {
    SVG = svg;
    var same = FITBOX && FITBOX.w === W && FITBOX.h === H;
    FITBOX = { x: 0, y: 0, w: W, h: H };
    if (!same || !VIEWBOX) VIEWBOX = { x: 0, y: 0, w: W, h: H };
    clampViewBox();
    applyViewBox();

    var pointers = {};
    svg.addEventListener("pointerdown", function (e) {
      pointers[e.pointerId] = { x: e.clientX, y: e.clientY };
      dragDist = 0;
    });
    svg.addEventListener("pointermove", function (e) {
      if (!pointers[e.pointerId]) return;
      var ids = Object.keys(pointers);
      if (ids.length === 1) {
        var p = pointers[e.pointerId], s = viewScale();
        VIEWBOX.x -= (e.clientX - p.x) / s;
        VIEWBOX.y -= (e.clientY - p.y) / s;
        dragDist += Math.abs(e.clientX - p.x) + Math.abs(e.clientY - p.y);
        pointers[e.pointerId] = { x: e.clientX, y: e.clientY };
        if (dragDist > 6) {
          hideTooltip();
          // capture only once it's clearly a pan, so plain clicks/hovers on
          // the hit lines keep working (capture re-targets their events)
          try { svg.setPointerCapture(e.pointerId); } catch (err) {}
        }
        clampViewBox();
        applyViewBox();
      } else if (ids.length === 2) { // pinch
        var a = pointers[ids[0]], b = pointers[ids[1]];
        var before = Math.hypot(a.x - b.x, a.y - b.y);
        pointers[e.pointerId] = { x: e.clientX, y: e.clientY };
        a = pointers[ids[0]]; b = pointers[ids[1]];
        var after = Math.hypot(a.x - b.x, a.y - b.y);
        dragDist = 99;
        if (before > 4 && after > 4) zoomAt((a.x + b.x) / 2, (a.y + b.y) / 2, after / before);
      }
    });
    function drop(e) { delete pointers[e.pointerId]; }
    svg.addEventListener("pointerup", drop);
    svg.addEventListener("pointercancel", drop);
    svg.addEventListener("wheel", function (e) {
      e.preventDefault();
      zoomAt(e.clientX, e.clientY, Math.pow(1.0015, -e.deltaY));
    }, { passive: false });
    svg.addEventListener("dblclick", function (e) {
      e.preventDefault();
      zoomAt(e.clientX, e.clientY, 1.7);
    });
  }
  (function bindZoomButtons() {
    var box = document.getElementById("wm-zoom");
    if (!box) return;
    box.addEventListener("click", function (e) {
      var act = e.target && e.target.getAttribute("data-zoom");
      if (!act || !SVG) return;
      var r = SVG.getBoundingClientRect();
      var cx = r.left + r.width / 2, cy = r.top + r.height / 2;
      if (act === "in") zoomAt(cx, cy, 1.5);
      else if (act === "out") zoomAt(cx, cy, 1 / 1.5);
      else { VIEWBOX = { x: FITBOX.x, y: FITBOX.y, w: FITBOX.w, h: FITBOX.h }; applyViewBox(); }
    });
  })();

  var tooltip = document.createElement("div");
  tooltip.className = "wm-tooltip";
  tooltip.hidden = true;
  root.appendChild(tooltip);

  function showTooltip(evt, link) {
    var tr = (STATE.traffic && STATE.traffic.links[link.id]) || null;
    var html = "<h4>" + link.a.replace(/^site:/, "") + " ⇄ " + link.z.replace(/^site:/, "") + "</h4>";
    if (link.status === "planned") {
      html += "<div class='wm-tt-note'>" + t("planned — not yet in service") + "</div>";
    } else if (link.status !== "up") {
      html += "<div class='wm-tt-note'>" + t("link offline") + "</div>";
    } else if (tr) {
      html += "<div class='wm-tt-row'><span>" + t("Out") + " (" + link.a.replace(/^site:/, "") + " → " + link.z.replace(/^site:/, "") + ")</span><b>" + fmtBps(tr.out_bps) + "</b></div>";
      html += "<div class='wm-tt-row'><span>" + t("In") + " (" + link.z.replace(/^site:/, "") + " → " + link.a.replace(/^site:/, "") + ")</span><b>" + fmtBps(tr.in_bps) + "</b></div>";
      html += "<div class='wm-tt-row'><span>" + t("Capacity") + "</span><b>" + capLabel(link.capacity_bps) + "</b></div>";
      html += "<div class='wm-tt-row'><span>%</span><b>" + (tr.util_pct != null ? tr.util_pct : 0) + "%</b></div>";
      if (tr.members && tr.members.length > 1) {
        html += "<div class='wm-tt-note'>" + tr.members.length + " × " + t("Parallel links") + "</div>";
        tr.members.forEach(function (m, i) {
          if (!m) return;
          html += "<div class='wm-tt-row wm-tt-member'><span>#" + (i + 1) +
            " · " + capLabel(m.speed_bps || 0) + "</span><b>" +
            fmtBps(m.out_bps) + " / " + fmtBps(m.in_bps) + "</b></div>";
        });
      }
    } else {
      html += "<div class='wm-tt-note'>" + t("live stats unavailable") + "</div>";
    }
    tooltip.innerHTML = html;
    tooltip.hidden = false;
    moveTooltip(evt);
  }
  function moveTooltip(evt) {
    var r = root.getBoundingClientRect();
    var x = evt.clientX - r.left + 14, y = evt.clientY - r.top + 14;
    x = Math.min(x, r.width - tooltip.offsetWidth - 8);
    y = Math.min(y, r.height - tooltip.offsetHeight - 8);
    tooltip.style.left = x + "px";
    tooltip.style.top = y + "px";
  }
  function hideTooltip() { tooltip.hidden = true; }

  // Chevron polygon at fraction f along (x1,y1)->(x2,y2), pointing forward.
  function chevron(parent, x1, y1, x2, y2, f, w) {
    var mx = x1 + (x2 - x1) * f, my = y1 + (y2 - y1) * f;
    var ang = Math.atan2(y2 - y1, x2 - x1) * 180 / Math.PI;
    var s = Math.max(w * 1.4, 4.5);
    var c = el("path", {
      d: "M " + (-s * 0.7) + " " + (-s) + " L " + s + " 0 L " + (-s * 0.7) + " " + s + " Z",
      transform: "translate(" + mx + " " + my + ") rotate(" + ang + ")",
      class: "wm-chevron"
    }, parent);
    return c;
  }

  function render(struct) {
    STATE.generation = struct.generation;
    STATE.strands = {}; STATE.chips = {}; STATE.nodes = {}; STATE.links = struct.links;
    var old = root.querySelector("svg");
    if (old) old.remove();
    var W = struct.view.width, H = struct.view.height;
    var svg = el("svg", { viewBox: "0 0 " + W + " " + H, class: "wm-svg", role: "img",
      preserveAspectRatio: "xMidYMid meet" });
    root.insertBefore(svg, root.firstChild);
    var gMetros = el("g", {}, svg), gLinks = el("g", {}, svg),
      gChips = el("g", {}, svg), gNodes = el("g", {}, svg), gHit = el("g", {}, svg);

    struct.nodes.forEach(function (n) { STATE.nodes[n.id] = n; });

    // metro halo: rounded rect over the group's node bbox, name above it
    var byMetro = {};
    struct.nodes.forEach(function (n) { (byMetro[n.metro] = byMetro[n.metro] || []).push(n); });
    Object.keys(byMetro).forEach(function (m) {
      var xs = byMetro[m].map(function (n) { return n.x; }),
        ys = byMetro[m].map(function (n) { return n.y; });
      var x0 = Math.min.apply(0, xs) - 82, x1 = Math.max.apply(0, xs) + 82;
      var y0 = Math.min.apply(0, ys) - 46, y1 = Math.max.apply(0, ys) + 40;
      el("rect", { x: x0, y: y0, width: x1 - x0, height: y1 - y0, rx: 18, class: "wm-metro" }, gMetros);
      el("text", { x: (x0 + x1) / 2, y: y0 - 10, class: "wm-metro-label", "text-anchor": "middle" }, gMetros)
        .textContent = m;
    });

    // fan parallel strands: all member strands between the same node pair
    // share one perpendicular offset series so nothing overlaps
    var pairs = {};
    struct.links.forEach(function (l) {
      var k = l.a < l.z ? l.a + "|" + l.z : l.z + "|" + l.a;
      (pairs[k] = pairs[k] || []).push(l);
    });

    Object.keys(pairs).forEach(function (k) {
      var group = pairs[k];
      var total = group.reduce(function (s, l) { return s + (l.members || 1); }, 0);
      var spacing = 9, idx = 0;
      group.forEach(function (l, gi) {
        var A = STATE.nodes[l.a], Z = STATE.nodes[l.z];
        if (!A || !Z) return;
        var dx = Z.x - A.x, dy = Z.y - A.y, len = Math.hypot(dx, dy) || 1;
        var px = -dy / len, py = dx / len; // unit perpendicular
        var perMember = (l.capacity_bps || 0) / (l.members || 1);
        var w = strandWidth(perMember);
        var strands = [];
        for (var mi = 0; mi < (l.members || 1); mi++, idx++) {
          var off = (idx - (total - 1) / 2) * spacing;
          var x1 = A.x + px * off, y1 = A.y + py * off;
          var x2 = Z.x + px * off, y2 = Z.y + py * off;
          var mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
          var cls = "wm-strand" + (l.status !== "up" ? " wm-strand-" + l.status : "");
          var base = l.status === "planned" ? PLANNED_COLOR : OFFLINE_COLOR;
          var h1 = el("line", { x1: x1, y1: y1, x2: mx, y2: my, class: cls,
            "stroke-width": w, stroke: l.status === "up" ? utilColor(0) : base }, gLinks);
          var h2 = el("line", { x1: mx, y1: my, x2: x2, y2: y2, class: cls,
            "stroke-width": w, stroke: l.status === "up" ? utilColor(0) : base }, gLinks);
          var c1 = null, c2 = null;
          if (l.status === "up") {
            c1 = chevron(gLinks, x1, y1, x2, y2, 0.26, w); // A-half: flow A -> Z
            c2 = chevron(gLinks, x2, y2, x1, y1, 0.26, w); // Z-half: flow Z -> A
          }
          strands.push({ h1: h1, h2: h2, c1: c1, c2: c2 });
        }
        STATE.strands[l.id] = strands;

        // utilization chip clear of the strand fan; when several distinct
        // cables share the pair, slide each cable's chip along the line
        if (l.status === "up") {
          var ox = (total * spacing) / 2 + 14;
          var along = (gi - (group.length - 1) / 2) * 46;
          var cxm = (A.x + Z.x) / 2 + px * ox + (dx / len) * along;
          var cym = (A.y + Z.y) / 2 + py * ox + (dy / len) * along;
          var chip = el("g", { class: "wm-chip", transform: "translate(" + cxm + " " + cym + ")" }, gChips);
          el("rect", { x: -22, y: -11, width: 44, height: 22, rx: 11 }, chip);
          var txt = el("text", { x: 0, y: 4.5, "text-anchor": "middle" }, chip);
          txt.textContent = "–%";
          STATE.chips[l.id] = { g: chip, rect: chip.firstChild, text: txt };
        }

        // one wide transparent hit line per cable for hover/tap details
        var hit = el("line", { x1: A.x, y1: A.y, x2: Z.x, y2: Z.y, class: "wm-hit",
          "stroke-width": Math.max(total * spacing + 10, 18) }, gHit);
        hit.addEventListener("pointerenter", function (e) {
          if (e.pointerType === "mouse" && !e.buttons) showTooltip(e, l);
        });
        hit.addEventListener("pointermove", function (e) {
          if (e.pointerType === "mouse" && !e.buttons) moveTooltip(e);
        });
        hit.addEventListener("pointerleave", hideTooltip);
        // taps: only when it wasn't a pan gesture
        hit.addEventListener("click", function (e) {
          if (dragDist < 6) { showTooltip(e, l); e.stopPropagation(); }
        });
      });
    });
    svg.addEventListener("click", function () { if (dragDist < 6) hideTooltip(); });
    initPanZoom(svg, W, H);

    struct.nodes.forEach(function (n) {
      var g = el("g", { class: "wm-node wm-node-" + n.kind,
        transform: "translate(" + n.x + " " + n.y + ")" }, gNodes);
      if (n.kind === "junction") {
        el("circle", { r: 7 }, g);
        el("text", { y: 23, "text-anchor": "middle", class: "wm-node-label" }, g)
          .textContent = n.label;
      } else {
        var wpx = n.label.length * 9.2 + 20;
        el("rect", { x: -wpx / 2, y: -14, width: wpx, height: 28, rx: 7 }, g);
        el("text", { y: 5, "text-anchor": "middle", class: "wm-node-label" }, g)
          .textContent = n.label;
      }
      var title = el("title", {}, g);
      title.textContent = n.site_name + " (" + n.site + ")";
    });
  }

  function paintStrand(s, outBps, inBps, speed) {
    var uo = speed ? 100 * outBps / speed : 0;
    var ui = speed ? 100 * inBps / speed : 0;
    s.h1.setAttribute("stroke", utilColor(uo));
    s.h2.setAttribute("stroke", utilColor(ui));
    // chevron on the DOMINANT direction only (and only when it carries real
    // traffic) — the split-half colouring still shows both directions' load
    var active = 2e6;
    var domOut = outBps >= inBps;
    if (s.c1) { s.c1.setAttribute("fill", utilColor(uo)); s.c1.style.opacity = (domOut && outBps > active) ? 0.95 : 0; }
    if (s.c2) { s.c2.setAttribute("fill", utilColor(ui)); s.c2.style.opacity = (!domOut && inBps > active) ? 0.95 : 0; }
  }

  function applyTraffic(traffic) {
    STATE.traffic = traffic;
    STATE.links.forEach(function (l) {
      var e = traffic.links[l.id], strands = STATE.strands[l.id];
      if (!e || !strands || l.status !== "up") return;
      if (e.members && e.members.length === strands.length) {
        strands.forEach(function (s, i) {
          var m = e.members[i];
          if (m) paintStrand(s, m.out_bps, m.in_bps, m.speed_bps || (l.capacity_bps / strands.length));
        });
      } else {
        var spd = l.capacity_bps || 0;
        strands.forEach(function (s) { paintStrand(s, e.out_bps, e.in_bps, spd); });
      }
      var chip = STATE.chips[l.id];
      if (chip) {
        var u = e.util_pct != null ? e.util_pct : 0;
        chip.text.textContent = Math.round(u) + "%";
        chip.rect.setAttribute("fill", utilColor(u));
        chip.g.classList.toggle("wm-chip-dark", u > 30 && u < 62); // yellow needs dark text
      }
    });
    var ts = document.getElementById("wm-ts");
    if (ts) ts.textContent = t("Last updated") + ": " + new Date().toLocaleTimeString();
  }

  function pollTraffic() {
    fetch(TRAFFIC_URL).then(function (r) { return r.json(); }).then(function (traffic) {
      if (traffic.generation && STATE.generation && traffic.generation !== STATE.generation) {
        // topology was rebuilt (ids rotate every generation): reload structure
        return fetch(STRUCTURE_URL).then(function (r) { return r.json(); })
          .then(function (s) { render(s); applyTraffic(traffic); });
      }
      applyTraffic(traffic);
    }).catch(function () {
      var ts = document.getElementById("wm-ts");
      if (ts) ts.textContent = t("live stats unavailable");
    });
  }

  var info = document.getElementById("wm-info");
  if (info) {
    var btn = info.querySelector(".wm-info-toggle");
    btn.addEventListener("click", function () {
      var open = info.classList.toggle("collapsed");
      btn.setAttribute("aria-expanded", open ? "false" : "true");
    });
  }

  fetch(STRUCTURE_URL).then(function (r) { return r.json(); }).then(function (s) {
    render(s);
    root.classList.add("wm-ready");
    pollTraffic();
    setInterval(pollTraffic, POLL_MS);
  }).catch(function () {
    root.classList.add("wm-error");
  });
})();
