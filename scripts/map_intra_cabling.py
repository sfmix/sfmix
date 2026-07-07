#!/usr/bin/env python3
"""Reconcile intra-site inter-switch cabling in NetBox against LLDP ground-truth.

Peering-switch<->peering-switch links (the intra-site LAGs, and switch<->transit-
router links that will become peering switches) should have representative NetBox
cabling matching what LLDP actually sees. This detects those links and:

  * MISSING  — neither end cabled -> create a direct interface<->interface cable.
  * CONFLICT — an end is cabled to something LLDP disagrees with (stale data) ->
    the cable is deleted and replaced (LLDP is ground-truth). Without --apply this
    only PROMPTS; the operator validates before it removes anything.
  * SKIP     — an interface isn't in NetBox yet (import it first).

Cabling moves over time; re-run to import the current truth. Never touches
inter-site links (those are transport circuits — see map_circuits.py).

  map_intra_cabling.py --plan                 # show proposals (read-only)
  map_intra_cabling.py --apply --yes          # create missing + replace conflicts

Creds: NETBOX_API_ENDPOINT/NETBOX_API_TOKEN or --env-file; eAPI via ~/.netrc (sfmix.org).
"""
import argparse
import json
import netrc
import os
import sys
import warnings

import requests
import urllib3

warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_env(path):
    for l in open(path):
        if "=" in l and not l.startswith("#"):
            k, v = l.strip().split("=", 1)
            os.environ.setdefault(k, v.strip().strip('"').strip("'"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--yes", action="store_true", help="required with --apply to write")
    ap.add_argument("--env-file")
    args = ap.parse_args()
    if args.env_file:
        load_env(args.env_file)
    ep = os.environ["NETBOX_API_ENDPOINT"].rstrip("/")
    tok = os.environ["NETBOX_API_TOKEN"]
    web = ep.rsplit("/api", 1)[0]
    S = requests.Session()
    S.headers = {"Authorization": "Token %s" % tok, "Accept": "application/json",
                 "Content-Type": "application/json"}
    S.verify = False

    def nbget(path, **kw):
        kw["limit"] = 500
        url, out = ep + path, []
        while url:
            j = S.get(url, params=kw, timeout=60).json()
            out += j["results"]
            url, kw = j.get("next"), {}
        return out

    user, _, pw = netrc.netrc().authenticators("sfmix.org")

    def eapi(host, cmds):
        body = {"jsonrpc": "2.0", "method": "runCmds",
                "params": {"version": 1, "cmds": cmds, "format": "json"}, "id": 1}
        return requests.post("https://%s.sfmix.org/command-api" % host, json=body,
                             auth=(user, pw), verify=False, timeout=25).json()["result"]

    devs = {d["name"]: d["site"]["slug"]
            for d in nbget("/api/dcim/devices/", role="peering_switch") if d["status"]["value"] == "active"}

    # LLDP -> intra-site peering<->peering links
    links, unreachable = {}, []
    for name in sorted(devs):
        try:
            res = eapi(name, ["show lldp neighbors detail"])[0]
        except Exception:
            unreachable.append(name)
            continue
        for ifn, e in res.get("lldpNeighbors", {}).items():
            for n in e.get("lldpNeighborInfo", []):
                far = n.get("systemName", "").replace(".sfmix.org", "")
                fifn = n.get("neighborInterfaceInfo", {}).get("interfaceId", "").strip('"')
                if far in devs and far != name and devs[far] == devs[name]:
                    links[frozenset([(name, ifn), (far, fifn)])] = None
    if unreachable:
        print("(no eAPI/LLDP from: %s)" % ", ".join(unreachable))

    _ic = {}

    def iface(dev, ifn):
        k = (dev, ifn)
        if k not in _ic:
            r = nbget("/api/dcim/interfaces/", device=dev, name=ifn)
            _ic[k] = r[0] if r else None
        return _ic[k]

    def trace_far_iface(iid):
        tr = S.get("%s/api/dcim/interfaces/%d/trace/" % (ep, iid), timeout=40).json()
        far = tr[-1][2] if tr else None
        node = (far[0] if far else None)
        if node and "/api/dcim/interfaces/" in node.get("url", ""):
            return node.get("id")
        return None

    creates, replaces, skips, ok = [], [], [], 0
    for lk in links:
        (da, ia), (db, ib) = sorted(lk)
        ea, eb = iface(da, ia), iface(db, ib)
        if not ea or not eb:
            miss = da + " " + ia if not ea else db + " " + ib
            skips.append("%s <-> %s : interface %s not in NetBox (import it first)" % (da + "/" + ia, db + "/" + ib, miss))
            continue
        if trace_far_iface(ea["id"]) == eb["id"]:
            ok += 1
            continue
        stale = []
        for e in (ea, eb):
            if e.get("cable"):
                stale.append((e, e["cable"]["id"]))
        site = devs[da]
        job = {"a": ea, "b": eb, "site": site, "stale": stale,
               "label": "%s/%s <-> %s/%s" % (da, ia, db, ib)}
        (replaces if stale else creates).append(job)

    def cable_body(ea, eb, site):
        return {"a_terminations": [{"object_type": "dcim.interface", "object_id": ea["id"]}],
                "b_terminations": [{"object_type": "dcim.interface", "object_id": eb["id"]}],
                "status": "connected", "type": "smf", "label": "Inter-switch: %s" % site}

    print("\n=== intra-site inter-switch cabling vs LLDP ===")
    print("%d links: %d already cabled, %d missing, %d conflicting, %d unresolvable\n"
          % (len(links), ok, len(creates), len(replaces), len(skips)))
    for j in creates:
        print("CREATE  %s" % j["label"])
        print("    POST %s/api/dcim/cables/ %s" % (web, json.dumps(cable_body(j["a"], j["b"], j["site"]))))
    for j in replaces:
        print("REPLACE %s  (LLDP ground-truth disagrees with existing cabling)" % j["label"])
        for e, cid in j["stale"]:
            print("    stale cable #%s on %s/%s -> %s/dcim/cables/%s/" % (cid, e["device"]["name"], e["name"], web, cid))
        print("    then POST %s/api/dcim/cables/ %s" % (web, json.dumps(cable_body(j["a"], j["b"], j["site"]))))
    for s in skips:
        print("SKIP    %s" % s)

    if args.apply and args.yes:
        print("\n== APPLYING ==")
        for j in replaces:  # delete stale first to free the ports
            for e, cid in j["stale"]:
                r = S.delete("%s/api/dcim/cables/%s/" % (ep, cid), timeout=30)
                print("  del stale cable #%s (%s/%s) -> %s" % (cid, e["device"]["name"], e["name"], r.status_code))
        for j in creates + replaces:
            r = S.post("%s/api/dcim/cables/" % ep, data=json.dumps(cable_body(j["a"], j["b"], j["site"])), timeout=30)
            print("  %s %s" % (("OK cable #%s" % r.json()["id"]) if r.status_code in (200, 201) else "FAIL %s %s" % (r.status_code, r.text[:120]), j["label"]))
    elif args.apply:
        print("\n(refusing to write without --yes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
