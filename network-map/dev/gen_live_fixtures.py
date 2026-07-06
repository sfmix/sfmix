#!/usr/bin/env python3
"""Generate builder fixtures from LIVE infrastructure, for building the map off-box
(where sflow-rt / Prometheus aren't reachable but NetBox + device eAPI are):

  * topology.json  — LLDP adjacency from `show lldp neighbors detail` over every
    active peering_switch (eAPI JSON-RPC; sflow-rt-shaped {nodes, links})
  * sites.json     — {slug: {lat, lon, name}} from NetBox site records

On metrics.sfo02 you don't need this — the builder reads live sflow-rt + Prometheus
directly. NetBox creds: NETBOX_API_ENDPOINT/NETBOX_API_TOKEN (or scripts/.env).
eAPI creds: the `sfmix.org` ~/.netrc entry (same as discovery.py / map_kmz_mine).

  gen_live_fixtures.py <out-dir>   # writes <out-dir>/topo_live.json, sites_live.json
"""
import json
import netrc
import os
import sys
import warnings

import requests

warnings.filterwarnings("ignore")


def main():
    out = sys.argv[1]
    ep = os.environ["NETBOX_API_ENDPOINT"].rstrip("/")
    tok = os.environ["NETBOX_API_TOKEN"]
    nb = requests.Session()
    nb.headers = {"Authorization": "Token %s" % tok, "Accept": "application/json"}

    def nbget(path, **kw):
        kw["limit"] = 200
        url, res = ep + path, []
        while url:
            j = nb.get(url, params=kw, timeout=40, verify=False).json()
            res += j["results"]
            url, kw = j.get("next"), {}
        return res

    sites = {s["slug"]: {"lat": float(s["latitude"]), "lon": float(s["longitude"]),
                         "name": s.get("facility") or s.get("name")}
             for s in nbget("/api/dcim/sites/") if s.get("latitude") is not None}
    json.dump(sites, open(os.path.join(out, "sites_live.json"), "w"), indent=2)

    user, _, pw = netrc.netrc().authenticators("sfmix.org")
    devs = {d["name"] for d in nbget("/api/dcim/devices/", role="peering_switch", status="active")}

    def eapi(host, cmds):
        body = {"jsonrpc": "2.0", "method": "runCmds",
                "params": {"version": 1, "cmds": cmds, "format": "json"}, "id": 1}
        return requests.post("https://%s.sfmix.org/command-api" % host, json=body,
                             auth=(user, pw), verify=False, timeout=20).json()["result"]

    nodes, links, seen, unreachable = {}, {}, set(), []
    for dev in sorted(devs):
        try:
            res = eapi(dev, ["show lldp neighbors detail"])[0]
        except Exception:
            unreachable.append(dev)
            continue
        nodes[dev + ".sfmix.org"] = {}
        for ifn, e in res.get("lldpNeighbors", {}).items():
            for n in e.get("lldpNeighborInfo", []):
                far = n.get("systemName", "").replace(".sfmix.org", "")
                fifn = n.get("neighborInterfaceInfo", {}).get("interfaceId", "").strip('"')
                if far not in devs:
                    continue
                key = frozenset([(dev, ifn), (far, fifn)])
                if key in seen:
                    continue
                seen.add(key)
                links["l%d" % len(links)] = {"node1": dev + ".sfmix.org", "port1": ifn,
                                             "node2": far + ".sfmix.org", "port2": fifn}
    json.dump({"nodes": nodes, "links": links},
              open(os.path.join(out, "topo_live.json"), "w"), indent=2)
    print("fixtures: %d sites, %d nodes, %d links (unreachable: %s)"
          % (len(sites), len(nodes), len(links), unreachable or "none"))


if __name__ == "__main__":
    main()
