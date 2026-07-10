/* Loader lab — loading-screen concepts over the REAL demo map.
 *
 * concept.html?c=<key> hosts an iframe of ../network-map/ (same-origin on
 * demo.sfmix.org) under a full-screen overlay. The harness polls the frame for
 * window.__nmmap and treats the first map.loaded()===true as "map ready" —
 * i.e. the loader dismisses on the map's genuine first idle, not a timer, so
 * each concept demos with real load timing. A concept supplies:
 *   start(ctx)          begin the waiting animation
 *   reveal(ctx, done)   map is ready — play the exit and call done()
 *   minMs               keep the loader up at least this long so the exit
 *                       animation reads even on a warm cache
 */
(function () {
  "use strict";

  var PALETTE = ["#8d43b8", "#4079e0", "#93c11f", "#ef9420", "#d5173e"];
  var READY_CAP_MS = 15000; // never trap the user behind a broken loader

  var stage = document.getElementById("stage");
  var frame = document.getElementById("nm-frame");
  var overlay = document.getElementById("overlay");
  var hud = document.getElementById("hud");

  /* ---- shared helpers ---------------------------------------------------- */

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text) n.textContent = text;
    return n;
  }

  function fullCanvas() {
    var c = document.createElement("canvas");
    function fit() {
      c.width = overlay.clientWidth * (window.devicePixelRatio || 1);
      c.height = overlay.clientHeight * (window.devicePixelRatio || 1);
    }
    fit();
    window.addEventListener("resize", fit);
    overlay.appendChild(c);
    return c;
  }

  function fadeOverlayOut(ms, done) {
    overlay.style.transition = "opacity " + ms + "ms ease";
    overlay.style.pointerEvents = "none";
    requestAnimationFrame(function () { overlay.style.opacity = "0"; });
    setTimeout(function () { overlay.classList.add("gone"); if (done) done(); }, ms + 60);
  }

  /* ---- concepts ----------------------------------------------------------- */

  var CONCEPTS = {

    /* 1. Community standard: plain dark veil, fade the map in. */
    fade: {
      name: "Plain fade",
      minMs: 400,
      start: function () { overlay.style.background = "#0a1526"; },
      reveal: function (ctx, done) { fadeOverlayOut(700, done); }
    },

    /* 2. Community standard: veil + spinner + label (the sourcedata-spinner
       pattern from the mapbox/maplibre gists). */
    spinner: {
      name: "Night veil + spinner",
      minMs: 700,
      start: function () {
        overlay.style.background =
          "linear-gradient(180deg,#0a1526 0%,#0e2438 60%,#12324e 100%)";
        overlay.appendChild(el("div", "ll-spinner"));
        overlay.appendChild(el("div", "ll-loading-text", "Loading the map…"));
      },
      reveal: function (ctx, done) { fadeOverlayOut(600, done); }
    },

    /* 3. Branded: SFMIX wordmark in the logo rainbow + a barber-pole progress
       stripe that echoes the map's animated cable dashes. */
    barber: {
      name: "SFMIX barber-pole",
      minMs: 1100,
      start: function () {
        overlay.style.background = "#0a1526";
        var w = el("div", "ll-wordmark");
        "SFMIX".split("").forEach(function (ch) { w.appendChild(el("span", null, ch)); });
        overlay.appendChild(w);
        var track = el("div", "ll-barber-track");
        track.appendChild(el("div", "ll-barber-stripes"));
        overlay.appendChild(track);
        overlay.appendChild(el("div", "ll-loading-text", "assembling the backbone…"));
      },
      reveal: function (ctx, done) {
        // one fast final sweep of the stripes, then fade
        var s = overlay.querySelector(".ll-barber-stripes");
        if (s) s.style.animationDuration = "0.25s";
        setTimeout(function () { fadeOverlayOut(650, done); }, 350);
      }
    },

    /* 4. Rainbow warpspeed: star streaks in the five SFMIX hues accelerating
       toward the viewer; on ready, a final kick, then an expanding center
       "eye" (an animated radial mask) irises the map in. */
    warp: {
      name: "Technicolor warpspeed → iris",
      minMs: 2400,
      start: function (ctx) {
        overlay.style.background = "#05070f";
        var canvas = fullCanvas();
        var g = canvas.getContext("2d");
        var stars = [];
        for (var i = 0; i < 340; i++) {
          stars.push({
            a: Math.random() * Math.PI * 2,
            d: Math.pow(Math.random(), 2) * 0.45 + 0.002, // fraction of half-diagonal
            c: PALETTE[i % PALETTE.length],
            w: Math.random() * 1.6 + 0.4
          });
        }
        ctx.warp = { canvas: canvas, g: g, stars: stars, boost: 1, iris: -1, t0: performance.now() };
        var self = this;
        (function tick() {
          if (overlay.classList.contains("gone")) return;
          self._frame(ctx);
          requestAnimationFrame(tick);
        })();
      },
      _frame: function (ctx) {
        var W = ctx.warp.canvas.width, H = ctx.warp.canvas.height;
        var g = ctx.warp.g, cx = W / 2, cy = H / 2;
        var half = Math.hypot(cx, cy);
        g.fillStyle = "rgba(5,7,15,0.34)"; // motion trails
        g.fillRect(0, 0, W, H);
        // gentle ramp over the wait, hard kick during reveal
        var age = (performance.now() - ctx.warp.t0) / 1000;
        var speed = (1.012 + Math.min(age * 0.004, 0.02)) * ctx.warp.boost;
        for (var i = 0; i < ctx.warp.stars.length; i++) {
          var s = ctx.warp.stars[i];
          var d0 = s.d; s.d *= speed;
          if (s.d > 1.05) { s.d = Math.random() * 0.03 + 0.002; d0 = s.d; }
          var x0 = cx + Math.cos(s.a) * d0 * half, y0 = cy + Math.sin(s.a) * d0 * half;
          var x1 = cx + Math.cos(s.a) * s.d * half, y1 = cy + Math.sin(s.a) * s.d * half;
          g.strokeStyle = s.c;
          g.globalAlpha = Math.min(0.3 + s.d * 2.2, 1);
          g.lineWidth = s.w * (0.5 + s.d * 2);
          g.beginPath(); g.moveTo(x0, y0); g.lineTo(x1, y1); g.stroke();
        }
        g.globalAlpha = 1;
        // the "eye": a glowing rainbow rim at the iris radius while it opens
        if (ctx.warp.iris >= 0) {
          var r = ctx.warp.iris * (window.devicePixelRatio || 1);
          var rim = g.createConicGradient ? g.createConicGradient(age, cx, cy) : null;
          if (rim) {
            PALETTE.forEach(function (c, k) { rim.addColorStop(k / PALETTE.length, c); });
            rim.addColorStop(1, PALETTE[0]);
            g.strokeStyle = rim;
          } else {
            g.strokeStyle = "#ffffff";
          }
          g.lineWidth = 3 + r * 0.02;
          g.globalAlpha = 0.9;
          g.beginPath(); g.arc(cx, cy, Math.max(r, 1), 0, Math.PI * 2); g.stroke();
          g.globalAlpha = 1;
        }
      },
      reveal: function (ctx, done) {
        ctx.warp.boost = 1.14; // hyperspace kick
        var maxR = Math.hypot(overlay.clientWidth, overlay.clientHeight) / 2 + 140;
        stage.style.transform = "scale(1.12)";
        setTimeout(function () {
          stage.classList.add("settle");
          stage.style.transform = "scale(1)";
          var t0 = performance.now(), DUR = 950;
          (function iris() {
            var p = Math.min((performance.now() - t0) / DUR, 1);
            var e = 1 - Math.pow(1 - p, 3); // ease-out cubic
            var r = e * maxR;
            ctx.warp.iris = r;
            var m = "radial-gradient(circle at 50% 50%, transparent " + r + "px, black " + (r + 110) + "px)";
            overlay.style.maskImage = m;
            overlay.style.webkitMaskImage = m;
            if (p < 1) { requestAnimationFrame(iris); }
            else { overlay.classList.add("gone"); done(); }
          })();
        }, 480);
      }
    },

    /* 4b. The full kit: warpspeed starfield behind the SFMIX wordmark and
       barber-pole stripe, ending in the same hyperspace kick + iris. */
    warpbrand: {
      name: "Warpspeed + wordmark + barber-pole",
      minMs: 2600,
      start: function (ctx) {
        CONCEPTS.warp.start.call(CONCEPTS.warp, ctx);
        var brand = el("div", "ll-brand");
        var w = el("div", "ll-wordmark");
        "SFMIX".split("").forEach(function (ch) { w.appendChild(el("span", null, ch)); });
        brand.appendChild(w);
        var track = el("div", "ll-barber-track");
        track.appendChild(el("div", "ll-barber-stripes"));
        brand.appendChild(track);
        brand.appendChild(el("div", "ll-loading-text", "assembling the backbone…"));
        overlay.appendChild(brand);
        ctx.brand = brand;
      },
      reveal: function (ctx, done) {
        // final fast stripe sweep, fade the branding, then punch the iris
        var s = ctx.brand.querySelector(".ll-barber-stripes");
        if (s) s.style.animationDuration = "0.25s";
        setTimeout(function () {
          ctx.brand.style.transition = "opacity 0.35s ease";
          ctx.brand.style.opacity = "0";
          CONCEPTS.warp.reveal.call(CONCEPTS.warp, ctx, done);
        }, 320);
      }
    },

    /* 5. Space drop: starfield, a rising horizon glow, then falling through
       clouds while the map zooms up underneath and sharpens into place. */
    skyfall: {
      name: "Orbital drop through the clouds",
      minMs: 3200,
      start: function (ctx) {
        overlay.style.background = "#020714";
        // the map underneath starts far away and blurred; reveal eases it in
        stage.style.transform = "scale(1.6)";
        stage.style.filter = "blur(7px)";
        var canvas = fullCanvas();
        var g = canvas.getContext("2d");
        var stars = [], clouds = [];
        for (var i = 0; i < 220; i++) {
          stars.push({ x: Math.random(), y: Math.random(), r: Math.random() * 1.4 + 0.3,
                       tw: Math.random() * Math.PI * 2 });
        }
        ctx.sky = { canvas: canvas, g: g, stars: stars, clouds: clouds,
                    t0: performance.now(), landing: false };
        var self = this;
        (function tick() {
          if (overlay.classList.contains("gone")) return;
          self._frame(ctx);
          requestAnimationFrame(tick);
        })();
      },
      _spawnCloud: function (sky, W, H) {
        sky.clouds.push({
          a: Math.random() * Math.PI * 2,
          d: 0.05 + Math.random() * 0.1, // grows outward past the camera
          r: (0.10 + Math.random() * 0.22) * Math.min(W, H),
          v: 1.014 + Math.random() * 0.012,
          o: 0.10 + Math.random() * 0.16
        });
      },
      _frame: function (ctx) {
        var sky = ctx.sky, W = sky.canvas.width, H = sky.canvas.height;
        var g = sky.g, cx = W / 2, cy = H / 2;
        var age = (performance.now() - sky.t0) / 1000;
        // space -> upper atmosphere: background deepens toward the map's night blue
        var desc = Math.min(age / 3.5, 1);          // 0 space .. 1 atmosphere
        if (sky.landing) desc = 1;
        var grad = g.createLinearGradient(0, 0, 0, H);
        grad.addColorStop(0, desc < 0.5 ? "#020714" : "#071a30");
        grad.addColorStop(1, "rgb(" + Math.round(10 + 25 * desc) + "," +
                               Math.round(18 + 40 * desc) + "," +
                               Math.round(35 + 55 * desc) + ")");
        g.fillStyle = grad; g.fillRect(0, 0, W, H);
        // horizon glow rising as we come in
        var glowY = H * (1.25 - desc * 0.45);
        var glow = g.createRadialGradient(cx, glowY, 0, cx, glowY, H * 0.9);
        glow.addColorStop(0, "rgba(70,140,200," + (0.28 * desc) + ")");
        glow.addColorStop(1, "rgba(70,140,200,0)");
        g.fillStyle = glow; g.fillRect(0, 0, W, H);
        // stars fade out as the air thickens
        g.fillStyle = "#ffffff";
        for (var i = 0; i < sky.stars.length; i++) {
          var s = sky.stars[i];
          g.globalAlpha = Math.max(0, (1 - desc)) * (0.4 + 0.6 * Math.abs(Math.sin(age * 2 + s.tw)));
          g.beginPath(); g.arc(s.x * W, s.y * H, s.r, 0, Math.PI * 2); g.fill();
        }
        g.globalAlpha = 1;
        // clouds streaming past once we hit atmosphere
        if (desc > 0.35 && sky.clouds.length < (sky.landing ? 26 : 14) && Math.random() < 0.3) {
          this._spawnCloud(sky, W, H);
        }
        var half = Math.hypot(cx, cy);
        for (var j = sky.clouds.length - 1; j >= 0; j--) {
          var c = sky.clouds[j];
          c.d *= sky.landing ? c.v * 1.02 : c.v;
          if (c.d > 1.6) { sky.clouds.splice(j, 1); continue; }
          var x = cx + Math.cos(c.a) * c.d * half, y = cy + Math.sin(c.a) * c.d * half;
          var rr = c.r * (0.4 + c.d * 1.6);
          var puff = g.createRadialGradient(x, y, 0, x, y, rr);
          puff.addColorStop(0, "rgba(225,235,245," + c.o + ")");
          puff.addColorStop(1, "rgba(225,235,245,0)");
          g.fillStyle = puff;
          g.beginPath(); g.arc(x, y, rr, 0, Math.PI * 2); g.fill();
        }
      },
      reveal: function (ctx, done) {
        ctx.sky.landing = true; // clouds rush and thin while the map arrives
        stage.classList.add("settle");
        stage.style.transform = "scale(1)";
        stage.style.filter = "blur(0px)";
        setTimeout(function () { fadeOverlayOut(900, done); }, 550);
      }
    }
  };

  /* ---- harness ------------------------------------------------------------ */

  var key = new URLSearchParams(location.search).get("c") || "fade";
  var concept = CONCEPTS[key] || CONCEPTS.fade;
  document.title = "Loader lab — " + concept.name;

  hud.innerHTML = "";
  hud.appendChild(el("div", "hud-name", concept.name));
  var timeRow = el("div", "hud-time", "waiting for the map…");
  hud.appendChild(timeRow);
  var ctl = el("div", "hud-row");
  var replay = el("button", null, "replay");
  replay.addEventListener("click", function () { location.reload(); });
  var back = el("a", null, "all concepts");
  back.href = "./";
  ctl.appendChild(replay); ctl.appendChild(back);
  hud.appendChild(ctl);

  var ctx = {};
  var t0 = performance.now();
  concept.start(ctx);
  // noveil suppresses the map's now-built-in warpbrand veil so lab concepts
  // demo over a bare load, not on top of another loader
  frame.src = "../network-map/?noveil=1";

  var revealed = false;
  function onReady(how) {
    if (revealed) return;
    revealed = true;
    var readyMs = performance.now() - t0;
    var wait = Math.max(0, concept.minMs - readyMs);
    setTimeout(function () {
      concept.reveal(ctx, function () {
        timeRow.textContent = "map ready " + (readyMs / 1000).toFixed(2) + "s (" + how +
          ") · revealed " + ((performance.now() - t0) / 1000).toFixed(2) + "s";
      });
      timeRow.textContent = "map ready " + (readyMs / 1000).toFixed(2) + "s (" + how + ")";
    }, wait);
  }

  var poll = setInterval(function () {
    var m;
    try { m = frame.contentWindow && frame.contentWindow.__nmmap; } catch (e) { return; }
    // loaded() flips true at the map's first idle (style + tiles in, nothing
    // pending) — the same signal a production loader would key on.
    if (m && m.loaded && m.loaded()) { clearInterval(poll); onReady("idle"); }
  }, 100);
  setTimeout(function () { clearInterval(poll); onReady("cap"); }, READY_CAP_MS);
})();
