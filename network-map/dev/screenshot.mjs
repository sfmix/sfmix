#!/usr/bin/env node
// Headless screenshot of the network map for visual verification.
//
//   node network-map/dev/screenshot.mjs <url> <out.png> [waitExpr]
//
// Launches headless Chrome (SwiftShader WebGL, throwaway profile), navigates
// to <url>, polls <waitExpr> in the page until truthy (default: the MapLibre
// map instance is loaded and the decorations layer exists), then captures a
// PNG. Prints READY or TIMED-OUT; a screenshot is written either way.
//
// The dev shell (dev/serve.py) exposes the map instance as window.__map for
// the default wait expression. Typical loop: run serve.py, screenshot at the
// zooms/centers you care about, eyeball the PNGs.
//
// Gotchas this encodes: --user-data-dir + --disable-extensions (else Chrome
// loads the desktop profile and the first devtools target is some extension's
// background page), type === "page" target selection, and waiting on the
// map's own layer state instead of a fixed timeout (SwiftShader is slow and
// fixed timeouts race the render). NB the wait can't use map.loaded(): the
// animated fog canvas source keeps the map perpetually repainting, so
// loaded() never settles true; the decorations layer existing is the last
// async setup step, plus the post-wait paint delay below.
import { writeFileSync, mkdtempSync } from "fs";
import { spawn } from "child_process";
import { tmpdir } from "os";

const [url, out, waitExpr = "!!(window.__map && window.__map.getLayer('decorations'))"] = process.argv.slice(2);
if (!url || !out) {
  console.error("usage: node screenshot.mjs <url> <out.png> [waitExpr]");
  process.exit(2);
}
const port = 9334;
const profile = mkdtempSync(tmpdir() + "/map-shot-");
const chrome = spawn("google-chrome", ["--headless=new", "--use-angle=swiftshader",
  "--enable-unsafe-swiftshader", "--remote-debugging-port=" + port,
  "--user-data-dir=" + profile, "--no-first-run", "--disable-extensions",
  "--window-size=900,650", "--hide-scrollbars", "about:blank"], { stdio: "ignore" });
process.on("exit", () => chrome.kill());
const sleep = ms => new Promise(r => setTimeout(r, ms));

let target;
for (let i = 0; i < 50 && !target; i++) {
  await sleep(200);
  try {
    const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    target = list.find(t => t.type === "page");
  } catch {}
}
if (!target) throw new Error("chrome devtools never came up");
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((res, rej) => {
  ws.onopen = res;
  ws.onerror = () => rej(new Error("devtools websocket failed"));
  setTimeout(() => rej(new Error("devtools websocket open timeout")), 10000);
});
let id = 0; const pending = {};
ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pending[m.id]) pending[m.id](m); };
const send = (method, params = {}) => new Promise((res, rej) => {
  const i = ++id; pending[i] = res;
  ws.send(JSON.stringify({ id: i, method, params }));
  setTimeout(() => rej(new Error("timeout on " + method)), 30000);
});

await send("Page.enable");
await send("Page.navigate", { url });
let ready = false;
for (let i = 0; i < 90; i++) {  // up to 45s
  await sleep(500);
  const r = await send("Runtime.evaluate", { expression: waitExpr, returnByValue: true });
  if (r.result?.result?.value) { ready = true; break; }
}
await sleep(1500); // let the last frame paint
const shot = await send("Page.captureScreenshot", { format: "png" });
writeFileSync(out, Buffer.from(shot.result.data, "base64"));
console.log((ready ? "READY " : "TIMED-OUT ") + out);
process.exit(ready ? 0 : 1);
