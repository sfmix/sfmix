#!/usr/bin/env python3
"""Reconcile inter-site transport circuits between the switch fabric and NetBox.

NetBox is the intended source-of-truth for the map's transport links (see
network-map/CIRCUITS_PLAN.md). This tool cross-references three signals —

  1. Switch transport ports  — interfaces described `Core: Transport <SITE> via
     <Provider> {<TOKEN>} [<Speed>]`.
  2. NetBox dark-fibre circuits — circuits.Circuit(type=dark-fiber) + terminations,
     and the cable trace from each switch interface through patch panels.
  3. Cable atlas — network-map/atlas/*.geojson (coarsened geometry, keyed by cid).

Modes:
  --audit   read-only: report reconciliation gaps (the human gap-prompt).
  --plan    read-only: print the concrete, HIGH-CONFIDENCE NetBox changes that would
            sync the model to reality (completing the last patch-panel hop to a circuit
            termination), plus the items that need a human. Writes nothing.
  --apply   EXECUTE the --plan proposals (requires --yes). Idempotent, conservative.

  scripts/map_circuits.py --audit --env-file scripts/.env
  scripts/map_circuits.py --plan  --env-file scripts/.env
  scripts/map_circuits.py --apply --yes --env-file scripts/.env
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


def site_of_device(dev_name):
    parts = dev_name.split(".")
    return parts[1] if len(parts) > 1 else dev_name


def parse_configs(configs_dir):
    """Parse Arista EOS running-configs (files named cfg.<device>) for the authoritative
    per-interface transport info in the `!!` comments:
      !! SO:<so> CID:<cid>          -> canonical circuit id (beats the {token})
      !! PP <panel> Port(s) N ...   -> patch-panel/ODF landing (the switch->ODF hop)
      description ... BiDi #N / Ports A & B  -> link type (bidi vs duplex)
    Returns {(device, ifname): {"cid","so","pp","link"}}. Empty if dir missing."""
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
            so = re.search(r"SO:(\S+)", body)
            pp = re.search(r"!!\s*(?:PP\s+)+(.+)", body)
            desc = re.search(r"description (.+)", body)
            dtext = desc.group(1) if desc else ""
            link = ("bidi" if re.search(r"BiDi", dtext) else
                    "duplex" if re.search(r"Ports?\s+\d+\s*&|cable id \d+ & \d+", body) else "?")
            out[(dev, ifn)] = {"cid": cid.group(1) if cid else "", "so": so.group(1) if so else "",
                               "pp": pp.group(1).strip() if pp else "", "link": link}
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
    """Follow /trace/. Returns a dict:
      kind: uncabled | dead-end | circuittermination | other | error
      detail: circuit cid (for circuittermination) or a label
      port: {object_type, object_id, device, name}  (for dead-end — the demarc port)
    """
    try:
        hops = session.get("%s/api/dcim/interfaces/%d/trace/" % (ep, iface_id), timeout=30).json()
    except Exception as e:
        return {"kind": "error", "detail": repr(e)[:60]}
    if not hops:
        return {"kind": "uncabled"}
    far = hops[-1][2]
    if not far:
        near = hops[-1][0]
        n = (near[0] if isinstance(near, list) else near) or {}
        url = n.get("url", "")
        otype = ("dcim.frontport" if "front-ports" in url else
                 "dcim.rearport" if "rear-ports" in url else
                 "dcim.interface" if "interfaces" in url else "?")
        return {"kind": "dead-end",
                "detail": "%s %s" % ((n.get("device") or {}).get("name", ""), n.get("name", "")),
                "port": {"object_type": otype, "object_id": n.get("id"),
                         "device": (n.get("device") or {}).get("name", ""), "name": n.get("name", "")}}
    f = far[0] if isinstance(far, list) else far
    url = f.get("url", "")
    if "circuit-termination" in url or "circuittermination" in url:
        cid = f.get("circuit", {}).get("cid") if isinstance(f.get("circuit"), dict) else None
        return {"kind": "circuittermination", "detail": cid}
    kind = url.split("/api/")[1].split("/")[1] if "/api/" in url else "?"
    return {"kind": "other", "detail": kind}


def gather(nb, sess, ep, configs):
    """Return (circuits, cid_by_norm, term_sites, term_by_cid_side, records, atlas).
    `configs` is the parsed EOS `!!` comment data — its `!! CID` is the AUTHORITATIVE
    interface->circuit key (the description `{token}` is only a fallback)."""
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
        term_by_cid_side.setdefault(c.cid, {})[site] = {"id": t.id, "cabled": bool(getattr(t, "cable", None))}
    ifaces = list(nb.dcim.interfaces.filter(description__ic="Core: Transport"))
    records = []
    for i in ifaces:
        cfg = configs.get((str(i.device), i.name), {})
        token = (RE_TOKEN.search(i.description or "") or [None, ""])[1] if RE_TOKEN.search(i.description or "") else ""
        # authoritative: comment CID; fallback: description token
        key = cfg.get("cid") or token
        cid_src = "comment" if cfg.get("cid") else ("token" if token else "")
        circ = cid_by_norm.get(norm(key)) if key else None
        rec = {"iface": i, "tag": "%s/%s" % (i.device, i.name), "site": site_of_device(str(i.device)),
               "token": token, "cid": key, "cid_src": cid_src, "circuit": circ,
               "pp": cfg.get("pp", ""), "link": cfg.get("link", ""), "trace": None}
        if circ:
            rec["trace"] = ({"kind": "uncabled"} if not getattr(i, "cable", None)
                            else trace_terminus(sess, ep, i.id))
        records.append(rec)
    return circuits, cid_by_norm, term_sites, term_by_cid_side, records, atlas_cids()


def build_proposals(records, term_by_cid_side):
    """HIGH-CONFIDENCE proposals: a dead-end trace whose (circuit, site) is unique and
    whose near-side termination exists and is uncabled -> cable demarc port <-> termination.
    Ambiguous cases (>1 port per circuit-side, no port, etc.) are returned as 'manual'."""
    # group ALL matched ports by (circuit cid, site) — a termination is a single point,
    # so ANY sibling port on the same circuit-side (dead-end, bypass, or uncabled) makes
    # it ambiguous (likely a LAG that needs one core-circuit per link). Only a clean 1:1
    # dead-end is auto-proposable.
    groups = {}
    for r in records:
        if r["circuit"]:
            groups.setdefault((r["circuit"].cid, r["site"]), []).append(r)
    proposals, manual = [], []
    for (cid, site), rs in groups.items():
        if not any((r.get("trace") or {}).get("kind") == "dead-end" for r in rs):
            continue  # nothing to complete here; other buckets handle it
        term = term_by_cid_side.get(cid, {}).get(site)
        if len(rs) != 1:
            manual.append("circuit %s @ %s has %d switch ports but one termination — model as %d core-circuits or a LAG (human)"
                          % (cid, site, len(rs), len(rs)))
            continue
        r = rs[0]
        if not term:
            manual.append("%s -> %s: no NetBox termination at %s (human: add termination)" % (r["tag"], cid, site))
            continue
        if term["cabled"]:
            manual.append("%s -> %s: termination @ %s already cabled elsewhere (human: verify)" % (r["tag"], cid, site))
            continue
        port = r["trace"]["port"]
        if port["object_type"] not in ("dcim.frontport", "dcim.rearport"):
            manual.append("%s -> %s: demarc is a %s, not a patch port (human)" % (r["tag"], cid, port["object_type"]))
            continue
        proposals.append({"iface": r["tag"], "cid": cid, "site": site,
                          "port": port, "term_id": term["id"]})
    return proposals, manual


def cmd_plan(proposals, manual, records):
    print("== PROPOSED NetBox changes (high-confidence, 1:1 last-hop cabling) ==")
    if not proposals:
        print("  (none)")
    for p in proposals:
        print("  CABLE  %s %s  <->  circuit %s termination @ %s"
              % (p["port"]["device"], p["port"]["name"], p["cid"], p["site"]))
        print("         (completes the trace from %s to its dark-fibre circuit)" % p["iface"])
    print("\n== NEEDS A HUMAN (not auto-proposed) ==")
    seen = set()
    for m in manual:
        if m not in seen:
            print("  - " + m); seen.add(m)
    # uncabled / other / no-cid from records
    for r in records:
        tr = r.get("trace") or {}
        if r["circuit"] and tr.get("kind") == "uncabled":
            print("  - %s -> %s: NO cable at all — human to patch switch->ODF->circuit" % (r["tag"], r["circuit"].cid))
        elif r["circuit"] and tr.get("kind") == "other":
            print("  - %s -> %s: cabled to another interface (bypasses circuit) — human to reconcile" % (r["tag"], r["circuit"].cid))
        elif not r["circuit"]:
            id_shown = ("%s (from %s)" % (r["cid"], r["cid_src"])) if r["cid"] else "(no id)"
            print("  - %s: circuit %s has no NetBox dark-fibre circuit — human to add/attach" % (r["tag"], id_shown))
    print("\nplan: %d auto-proposed cable(s); rerun with --apply --yes to execute." % len(proposals))


def cmd_apply(nb, proposals, assume_yes):
    if not assume_yes:
        sys.exit("refusing to write without --yes")
    print("== APPLYING %d cable(s) to NetBox ==" % len(proposals))
    for p in proposals:
        # re-check the termination is still uncabled (idempotent / safe)
        t = nb.circuits.circuit_terminations.get(p["term_id"])
        if t is None or getattr(t, "cable", None):
            print("  SKIP  %s termination @ %s already cabled" % (p["cid"], p["site"]))
            continue
        cable = nb.dcim.cables.create(
            a_terminations=[{"object_type": p["port"]["object_type"], "object_id": p["port"]["object_id"]}],
            b_terminations=[{"object_type": "circuits.circuittermination", "object_id": p["term_id"]}],
            status="connected", type="smf",
            label="map-sync %s" % p["cid"],
        )
        print("  CABLED %s %s <-> %s @ %s  (cable #%s)"
              % (p["port"]["device"], p["port"]["name"], p["cid"], p["site"], cable.id))


def cmd_audit(circuits, cid_by_norm, term_sites, records, atlas):
    by_circuit = {}
    resolved = uncabled = dead = wrong = other = nocid = 0
    seen = set()
    for r in records:
        c = r["circuit"]
        if not c:
            nocid += 1
            continue
        seen.add(c.cid)
        tr = r.get("trace") or {}
        k = tr.get("kind")
        if k == "uncabled":
            state = "uncabled"; uncabled += 1
        elif k == "dead-end":
            state = "dead-end@%s" % tr.get("detail"); dead += 1
        elif k == "circuittermination":
            if tr.get("detail") and norm(tr["detail"]) != norm(c.cid):
                state = "WRONG->%s" % tr["detail"]; wrong += 1
            else:
                state = "resolved"; resolved += 1
        else:
            state = "%s:%s" % (k, tr.get("detail")); other += 1
        by_circuit.setdefault(c.cid, []).append("%s(%s)" % (r["tag"], state))
    print("== dark-fibre circuit inventory (%d) ==" % len(circuits))
    for c in sorted(circuits, key=lambda c: (str(c.status), c.cid)):
        ts = term_sites.get(c.cid, {})
        az = "%s-%s" % (ts.get("A", "?"), ts.get("Z", "?"))
        at = "yes" if norm(c.cid) in atlas else "NO"
        ports = by_circuit.get(c.cid, [])
        print("   %-22s %-11s %-13s %-11s atlas=%-3s %s" % (
            c.cid, az, str(c.provider)[:13], str(c.status)[:11], at,
            ", ".join(ports) if ports else "(no described port)"))
    active = [c for c in circuits if str(c.status).lower() == "active"]
    so_named = [c.cid for c in circuits if str(c.cid).upper().startswith("SO-")]
    if so_named:
        renames = ", ".join("%s -> DF-%s" % (c, c[3:]) for c in so_named)
        print("\nCID CONVENTION: %d dark-fibre circuit(s) use the SO- (service-order) prefix; the "
              "circuit id should be DF- (DF-<cust>-<order>[-<core>]).\n  Rename candidates in NetBox: %s"
              % (len(so_named), renames))
    print("\nSUMMARY: resolved=%d uncabled=%d dead_end=%d wrong=%d no_cid=%d | active=%d no_port=%d no_atlas=%d" % (
        resolved, uncabled, dead, wrong, nocid, len(active),
        len([c for c in active if c.cid not in seen]),
        len([c for c in active if norm(c.cid) not in atlas])))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--audit", action="store_true")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--yes", action="store_true", help="required with --apply to actually write")
    ap.add_argument("--env-file")
    ap.add_argument("--configs-dir", help="dir of EOS running-configs (files cfg.<device>) "
                    "for authoritative !! CID / !! PP comment data. Fetch e.g.: "
                    "for d in <devs>; do ssh $d.sfmix.org 'show running-config' > cfg.$d; done")
    args = ap.parse_args()
    if args.env_file:
        load_env(args.env_file)
    ep = os.environ.get("NETBOX_API_ENDPOINT", "").rstrip("/")
    tok = os.environ.get("NETBOX_API_TOKEN", "")
    if not ep or not tok:
        sys.exit("set NETBOX_API_ENDPOINT and NETBOX_API_TOKEN (or --env-file)")
    nb = pynetbox.api(ep, token=tok)
    sess = requests.Session()
    sess.headers = {"Authorization": "Token %s" % tok}

    configs = parse_configs(args.configs_dir)
    circuits, cid_by_norm, term_sites, term_by_cid_side, records, atlas = gather(nb, sess, ep, configs)
    if configs:
        print("(using EOS !! comments from %d interfaces as authoritative CID/PP)\n" % len(configs))
    if args.audit:
        cmd_audit(circuits, cid_by_norm, term_sites, records, atlas)
    if args.plan or args.apply:
        proposals, manual = build_proposals(records, term_by_cid_side)
        if args.apply:
            cmd_apply(nb, proposals, args.yes)
        else:
            cmd_plan(proposals, manual, records)
    if not (args.audit or args.plan or args.apply):
        sys.exit("choose --audit | --plan | --apply")
    return 0


if __name__ == "__main__":
    sys.exit(main())
