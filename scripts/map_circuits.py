#!/usr/bin/env python3
"""Reconcile inter-site transport circuits between the switch fabric and NetBox.

NetBox is the intended source-of-truth for the map's transport links (see
network-map/CIRCUITS_PLAN.md). Device *link state* is authoritative for delivery: a
transport port that is `connected` (light) means its dark-fibre circuit is delivered and
its NetBox termination must be cabled to that interface. Signals fused:

  1. `show running-config` `!! CID:` (canonical circuit id) + `!! PP` (ODF landing) + BiDi/duplex.
  2. `show interfaces status` linkStatus (connected|notconnect|disabled) — delivery truth.
  3. NetBox dark-fibre circuits + terminations + the cable trace through patch panels.
  4. network-map/atlas/*.geojson (geometry, keyed by cid).

Configs/status are read from --configs-dir (files `cfg.<device>` and `st.<device>.json`).
Fetch e.g.:
  for d in <devs>; do ssh $d.sfmix.org 'show running-config' > cfg.$d
                      ssh $d.sfmix.org 'show interfaces status | json' > st.$d.json; done

Modes (all read-only except --apply):
  --audit   reconciliation summary (per-circuit inventory + gap buckets).
  --plan    per-logical-circuit cabling change plan: for each DELIVERED circuit, the exact
            NetBox cable(s) to create (switch->ODF->termination), as ready API requests,
            with a cable-trace URL per interface. Nothing is written.
  --apply   execute the concrete last-hop cable proposals from --plan (requires --yes).
"""
import argparse
import glob
import json
import os
import re
import sys

import pynetbox
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, os.pardir))
ATLAS_DIR = os.path.join(REPO, "network-map", "atlas")
RE_TOKEN = re.compile(r"\{([^}]+)\}")


def norm(s):
    return re.sub(r"[^A-Z0-9]", "", (s or "").upper())


def load_env(path):
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v.strip().strip('"').strip("'"))


def site_of_device(dev):
    p = dev.split(".")
    return p[1] if len(p) > 1 else dev


def parse_configs(configs_dir):
    """{(device, ifname): {cid, so, pp, link, token}} from EOS `!!` comments + description."""
    out = {}
    if not configs_dir or not os.path.isdir(configs_dir):
        return out
    for path in glob.glob(os.path.join(configs_dir, "cfg.*")):
        dev = os.path.basename(path)[4:]
        try:
            rc = open(path).read()
        except OSError:
            continue
        for m in re.finditer(r"(?ms)^interface (Ethernet\S+)\n(.*?)(?=^interface |\Z)", rc):
            ifn, body = m.group(1), m.group(2)
            if "Core: Transport" not in body:
                continue
            cid = re.search(r"CID:(\S+)", body)
            pp = re.search(r"!!\s*(?:PP\s+)+(.+)", body)
            desc = re.search(r"description (.+)", body)
            dtext = desc.group(1) if desc else ""
            tok = re.search(r"\{([^}]+)\}", dtext)
            link = ("bidi" if re.search(r"BiDi", dtext) else
                    "duplex" if re.search(r"Ports?\s+\d+\s*&|cable id \d+ & \d+", body) else "?")
            out[(dev, ifn)] = {"cid": cid.group(1) if cid else "", "pp": pp.group(1).strip() if pp else "",
                               "link": link, "token": tok.group(1) if tok else ""}
    return out


def parse_link_state(configs_dir):
    """{(device, ifname): linkStatus} from `show interfaces status | json` (st.<device>.json)."""
    out = {}
    if not configs_dir:
        return out
    for path in glob.glob(os.path.join(configs_dir, "st.*.json")):
        dev = os.path.basename(path)[3:-5]
        try:
            d = json.load(open(path))
        except Exception:
            continue
        for ifn, info in (d.get("interfaceStatuses") or d.get("interfaces") or {}).items():
            out[(dev, ifn)] = info.get("linkStatus") or info.get("lineProtocolStatus") or "?"
    return out


def atlas_cids():
    out = {}
    for path in glob.glob(os.path.join(ATLAS_DIR, "*.geojson")):
        if os.path.basename(path).startswith("_"):
            continue
        try:
            c = json.load(open(path)).get("circuit", {})
        except Exception:
            continue
        for k in [c.get("circuit_id", "")] + list(c.get("match", [])):
            if k:
                out[norm(k)] = os.path.basename(path)
    return out


def trace_terminus(session, ep, iface_id):
    """{kind: uncabled|dead-end|circuittermination|other|error, detail, port:{object_type,object_id,label}}."""
    try:
        hops = session.get("%s/api/dcim/interfaces/%d/trace/" % (ep, iface_id), timeout=30).json()
    except Exception as e:
        return {"kind": "error", "detail": repr(e)[:60]}
    if not hops:
        return {"kind": "uncabled"}
    far = hops[-1][2]
    if not far:
        n = (hops[-1][0][0] if isinstance(hops[-1][0], list) else hops[-1][0]) or {}
        url = n.get("url", "")
        otype = ("dcim.frontport" if "front-ports" in url else "dcim.rearport" if "rear-ports" in url
                 else "dcim.interface" if "interfaces" in url else "?")
        return {"kind": "dead-end", "detail": "%s %s" % ((n.get("device") or {}).get("name", ""), n.get("name", "")),
                "port": {"object_type": otype, "object_id": n.get("id"),
                         "label": "%s %s" % ((n.get("device") or {}).get("name", ""), n.get("name", ""))}}
    f = far[0] if isinstance(far, list) else far
    url = f.get("url", "")
    if "circuit-termination" in url or "circuittermination" in url:
        return {"kind": "circuittermination", "detail": f.get("circuit", {}).get("cid") if isinstance(f.get("circuit"), dict) else None}
    return {"kind": "other", "detail": url.split("/api/")[1].split("/")[1] if "/api/" in url else "?"}


def gather(nb, sess, ep, configs, links):
    circuits = list(nb.circuits.circuits.filter(type="dark-fiber"))
    cid_by_norm = {norm(c.cid): c for c in circuits}
    term_sites, term_by_cid_side = {}, {}
    for t in nb.circuits.circuit_terminations.all():
        c = getattr(t, "circuit", None)
        if not c:
            continue
        term = getattr(t, "termination", None)
        site = term.slug if term and hasattr(term, "slug") else (str(term) if term else "?")
        term_sites.setdefault(c.cid, {})[t.term_side] = site
        term_by_cid_side.setdefault(c.cid, {})[site] = {"id": t.id, "side": t.term_side, "cabled": bool(getattr(t, "cable", None))}
    records = []
    for i in nb.dcim.interfaces.filter(description__ic="Core: Transport"):
        cfg = configs.get((str(i.device), i.name), {})
        tok = (RE_TOKEN.search(i.description or "") or [None, ""])[1] if RE_TOKEN.search(i.description or "") else ""
        key = cfg.get("cid") or tok
        circ = cid_by_norm.get(norm(key)) if key else None
        rec = {"iface": i, "id": i.id, "tag": "%s/%s" % (i.device, i.name), "site": site_of_device(str(i.device)),
               "cid": key, "cid_src": "comment" if cfg.get("cid") else ("token" if tok else ""),
               "circuit": circ, "pp": cfg.get("pp", ""), "linktype": cfg.get("link", ""),
               "link_state": links.get((str(i.device), i.name), "?"), "trace": None}
        if circ:
            rec["trace"] = trace_terminus(sess, ep, i.id)
        records.append(rec)
    return circuits, cid_by_norm, term_sites, term_by_cid_side, records, atlas_cids()


def cmd_audit(circuits, term_sites, records, atlas):
    by_circuit = {}
    for r in records:
        if r["circuit"]:
            tr = r.get("trace") or {}
            by_circuit.setdefault(r["circuit"].cid, []).append(
                "%s[%s,%s]" % (r["tag"], r["link_state"], tr.get("kind")))
    print("== dark-fibre circuit inventory (%d) ==" % len(circuits))
    for c in sorted(circuits, key=lambda c: (str(c.status), c.cid)):
        ts = term_sites.get(c.cid, {})
        print("   %-22s %-11s %-11s atlas=%-3s %s" % (
            c.cid, "%s-%s" % (ts.get("A", "?"), ts.get("Z", "?")), str(c.status)[:11],
            "yes" if norm(c.cid) in atlas else "NO", ", ".join(by_circuit.get(c.cid, [])) or "(no port)"))
    so = [c.cid for c in circuits if str(c.cid).upper().startswith("SO-")]
    if so:
        print("\nCID CONVENTION: rename when delivered -> " + ", ".join("%s->DF-%s" % (c, c[3:]) for c in so))


def build_and_plan(circuits, records, term_by_cid_side, web):
    """Per-logical-circuit cabling plan. Returns (proposals) and prints the change plan with
    ready API requests + a trace URL per interface. Only DELIVERED (connected) circuits."""
    by_cid = {}
    for r in records:
        if r["circuit"]:
            by_cid.setdefault(r["circuit"].cid, []).append(r)
    proposals = []
    for c in sorted(circuits, key=lambda c: c.cid):
        rs = by_cid.get(c.cid, [])
        delivered = any(r["link_state"] == "connected" for r in rs)
        if not delivered:
            continue
        ts = term_by_cid_side.get(c.cid, {})
        print("\n=== %s  (%s, %s)  terminations: %s ===" % (
            c.cid, c.provider, c.status,
            " ".join("%s@%s%s" % (v["side"], s, "*cabled" if v["cabled"] else "") for s, v in ts.items())))
        # group this circuit's ports by site (end)
        ends = {}
        for r in rs:
            ends.setdefault(r["site"], []).append(r)
        for site, ers in sorted(ends.items()):
            conn = [r for r in ers if r["link_state"] == "connected"]
            term = ts.get(site)
            print("  END %s  (%d connected port%s, linktype=%s):" % (
                site, len(conn), "s" if len(conn) != 1 else "", conn[0]["linktype"] if conn else "?"))
            for r in ers:
                tr = r.get("trace") or {}
                print("    %-26s link=%-10s netbox-cabling=%s" % (r["tag"], r["link_state"], tr.get("kind")))
                print("      trace: %s/dcim/interfaces/%d/trace/" % (web, r["id"]))
                if r["pp"]:
                    print("      !! PP: %s" % r["pp"][:60])
            if not term:
                print("      ACTION: no NetBox termination at %s — create CircuitTermination, then cable. (human)" % site)
                continue
            if term["cabled"]:
                print("      OK: termination %s@%s already cabled." % (term["side"], site))
                continue
            if len(conn) > 1:
                print("      ACTION (⚑ Step 2): %d BiDi links share one circuit/termination — model one core-"
                      "circuit per link first, then cable each. Not auto-proposed." % len(conn))
                continue
            r = conn[0]
            tr = r.get("trace") or {}
            if tr.get("kind") == "dead-end" and tr.get("port", {}).get("object_type") in ("dcim.frontport", "dcim.rearport"):
                p = tr["port"]
                proposals.append({"cid": c.cid, "site": site, "iface": r["tag"], "iface_id": r["id"],
                                  "port": p, "term_id": term["id"]})
                print("      PROPOSE cable  %s  <->  %s termination %s@%s" % (p["label"], c.cid, term["side"], site))
                print("        POST %s/api/dcim/cables/ " % web + json.dumps({
                    "a_terminations": [{"object_type": p["object_type"], "object_id": p["object_id"]}],
                    "b_terminations": [{"object_type": "circuits.circuittermination", "object_id": term["id"]}],
                    "status": "connected", "type": "smf", "label": "map-sync %s" % c.cid}))
            elif tr.get("kind") == "uncabled":
                print("      ACTION: switch port is delivered but has NO NetBox cable. Enter the physical patch "
                      "per !! PP above (switch->ODF), then the last hop to termination %s becomes auto-proposable. (human)" % term["id"])
            elif tr.get("kind") == "circuittermination":
                print("      OK: already traces to a circuit termination.")
            else:
                print("      ACTION: traces to %s (not a circuit termination) — reconcile physically. (human)" % tr.get("detail"))
    return proposals


def cmd_apply(nb, proposals, yes):
    if not yes:
        sys.exit("refusing to write without --yes")
    print("== APPLYING %d cable(s) ==" % len(proposals))
    for p in proposals:
        t = nb.circuits.circuit_terminations.get(p["term_id"])
        if t is None or getattr(t, "cable", None):
            print("  SKIP %s@%s termination already cabled" % (p["cid"], p["site"])); continue
        cable = nb.dcim.cables.create(
            a_terminations=[{"object_type": p["port"]["object_type"], "object_id": p["port"]["object_id"]}],
            b_terminations=[{"object_type": "circuits.circuittermination", "object_id": p["term_id"]}],
            status="connected", type="smf", label="map-sync %s" % p["cid"])
        print("  CABLED %s <-> %s@%s (cable #%s)" % (p["port"]["label"], p["cid"], p["site"], cable.id))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--audit", action="store_true")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--env-file")
    ap.add_argument("--configs-dir", help="dir of cfg.<device> + st.<device>.json")
    args = ap.parse_args()
    if args.env_file:
        load_env(args.env_file)
    ep = os.environ.get("NETBOX_API_ENDPOINT", "").rstrip("/")
    tok = os.environ.get("NETBOX_API_TOKEN", "")
    if not ep or not tok:
        sys.exit("set NETBOX_API_ENDPOINT and NETBOX_API_TOKEN (or --env-file)")
    web = re.sub(r"/api/?$", "", ep)
    nb = pynetbox.api(ep, token=tok)
    sess = requests.Session(); sess.headers = {"Authorization": "Token %s" % tok}
    configs, links = parse_configs(args.configs_dir), parse_link_state(args.configs_dir)
    if configs or links:
        print("(device signals: %d !! comments, %d link states)\n" % (len(configs), len(links)))
    try:
        circuits, cid_by_norm, term_sites, term_by_cid_side, records, atlas = gather(nb, sess, ep, configs, links)
    except pynetbox.core.query.RequestError as e:
        if "403" in str(e) or "expired" in str(e).lower():
            sys.exit("NetBox auth failed (%s). Refresh NETBOX_API_TOKEN in your env/.env." % str(e)[:80])
        raise
    if args.audit:
        cmd_audit(circuits, term_sites, records, atlas)
    if args.plan or args.apply:
        proposals = build_and_plan(circuits, records, term_by_cid_side, web)
        print("\n%d concrete last-hop cable(s) proposed." % len(proposals))
        if args.apply:
            cmd_apply(nb, proposals, args.yes)
        else:
            print("Review above, then: --apply --yes to create the concrete cables.")
    if not (args.audit or args.plan or args.apply):
        sys.exit("choose --audit | --plan | --apply")
    return 0


if __name__ == "__main__":
    sys.exit(main())
