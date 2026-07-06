#!/usr/bin/env python3
"""Synthetic per-cable traffic overlay for the DEMO (no live Prometheus off-box).

Deterministic per cable id (stable across runs), generation matched to the map so
the frontend accepts it. Emits the traffic contract the map JS expects:
{generation, generated_at, links:{id:{in_bps,out_bps,util_pct,series_in,series_out}}}.
Clearly synthetic — for the password-gated demo only, never the live public map.

  gen_synth_traffic.py <map.json> <traffic.json>
"""
import hashlib
import json
import sys


def h(s, mod):
    return int(hashlib.md5(s.encode()).hexdigest(), 16) % mod


def main():
    m = json.load(open(sys.argv[1]))
    links = {}
    for c in m["cables"]:
        cid = c["id"]
        cap = c.get("capacity_bps") or 100e9
        util = 5 + h(cid, 70)                      # 5..74 %, stable per id
        inb = cap * util / 100.0
        outb = inb * (0.45 + h(cid + "o", 45) / 100.0)
        si = [round(inb * (0.85 + h(cid + str(k), 30) / 100.0)) for k in range(24)]
        so = [round(outb * (0.85 + h(cid + "o" + str(k), 30) / 100.0)) for k in range(24)]
        links[cid] = {"in_bps": round(inb), "out_bps": round(outb), "util_pct": util,
                      "series_in": si, "series_out": so}
    json.dump({"generation": m["generation"], "generated_at": m["generated_at"], "links": links},
              open(sys.argv[2], "w"))
    print("traffic.json: %d links (generation %s)" % (len(links), m["generation"]))


if __name__ == "__main__":
    main()
