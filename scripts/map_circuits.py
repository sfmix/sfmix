#!/usr/bin/env python3
"""Reconcile inter-site transport circuits between the switch fabric and NetBox.

Read-only auditor (Phase 2 of network-map/CIRCUITS_PLAN.md). It cross-references
three signals and reports the gaps that block making NetBox the source-of-truth for
the map's transport links:

  1. Switch transport ports  — interfaces described `Core: Transport <SITE> via
     <Provider> {<TOKEN>} [<Speed>]` (the bootstrap signal).
  2. NetBox dark-fibre circuits — circuits.Circuit(type=dark-fiber) + terminations,
     and the cable trace from each switch interface through patch panels to the
     circuit's CircuitTermination (the intended source-of-truth linkage).
  3. Cable atlas — network-map/atlas/*.geojson (coarsened geometry, keyed by cid).

Usage:
  NETBOX_API_ENDPOINT=... NETBOX_API_TOKEN=... scripts/map_circuits.py --audit
  scripts/map_circuits.py --audit --env-file scripts/.env
No writes. Bootstrap/apply is a separate, reviewed step (see the plan).
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
RE_SITE = re.compile(r"Transport\s+(?:to\s+)?([A-Za-z]{3}\d{2})", re.I)


def norm(s):
    """Normalize a circuit id/token for matching (drop non-alphanumerics, upcase).
    FID-2023-0408 == FID20230408; FBDK/1721530/ZFS == FBDK1721530ZFS."""
    return re.sub(r"[^A-Z0-9]", "", (s or "").upper())


def load_env(path):
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v.strip().strip('"').strip("'"))


def site_of_device(dev_name):
    # switch01.fmt01 / switch01.fmt01.sfmix.org -> fmt01
    parts = dev_name.split(".")
    return parts[1] if len(parts) > 1 else dev_name


def atlas_cids():
    """Normalized cid/match-token -> atlas filename."""
    out = {}
    for path in glob.glob(os.path.join(ATLAS_DIR, "*.geojson")):
        if os.path.basename(path).startswith("_"):
            continue
        try:
            c = json.load(open(path)).get("circuit", {})
        except Exception:
            continue
        keys = [c.get("circuit_id", "")] + list(c.get("match", []))
        for k in keys:
            if k:
                out[norm(k)] = os.path.basename(path)
    return out


def trace_terminus(session, ep, iface_id):
    """Follow /trace/ and return ('circuittermination', cid) | ('dead-end', last) |
    ('other', type) | (None, None). Walks through patch-panel front/rear ports."""
    try:
        hops = session.get("%s/api/dcim/interfaces/%d/trace/" % (ep, iface_id), timeout=30).json()
    except Exception as e:
        return ("error", repr(e)[:60])
    if not hops:
        return ("uncabled", None)
    far = hops[-1][2]
    if not far:
        # the near side of the last hop tells us where the chain dead-ended
        near = hops[-1][0]
        n = (near[0] if isinstance(near, list) else near) or {}
        return ("dead-end", "%s %s" % ((n.get("device") or {}).get("name", ""), n.get("name", "")))
    f = far[0] if isinstance(far, list) else far
    url = f.get("url", "")
    if "circuit-terminations" in url or "circuittermination" in url:
        return ("circuittermination", f.get("circuit", {}).get("cid") if isinstance(f.get("circuit"), dict) else None)
    kind = url.split("/api/")[1].split("/")[1] if "/api/" in url else "?"
    return ("other", kind)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--audit", action="store_true", help="report reconciliation gaps (read-only)")
    ap.add_argument("--env-file", help="load NETBOX_API_ENDPOINT/TOKEN from this file")
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

    # --- gather ---
    circuits = list(nb.circuits.circuits.filter(type="dark-fiber"))
    cid_by_norm = {}
    term_sites = {}   # cid -> {"A": site, "Z": site}
    for c in circuits:
        cid_by_norm[norm(c.cid)] = c
        term_sites[c.cid] = {}
    for t in nb.circuits.circuit_terminations.all():
        c = getattr(t, "circuit", None)
        if not c:
            continue
        term = getattr(t, "termination", None)
        site = term.slug if term and hasattr(term, "slug") else (str(term) if term else "?")
        term_sites.setdefault(c.cid, {})[t.term_side] = site

    ifaces = list(nb.dcim.interfaces.filter(description__ic="Core: Transport"))
    atlas = atlas_cids()

    # --- reconcile per transport interface ---
    no_cid, uncabled, dead_end, resolved, wrong, other = [], [], [], [], [], []
    seen_cids = set()
    for i in ifaces:
        d = i.description or ""
        m = RE_TOKEN.search(d)
        token = m.group(1) if m else ""
        circ = cid_by_norm.get(norm(token)) if token else None
        tag = "%s/%s" % (i.device, i.name)
        if not circ:
            no_cid.append((tag, token))
            continue
        seen_cids.add(circ.cid)
        if not getattr(i, "cable", None):
            uncabled.append((tag, circ.cid))
            continue
        kind, detail = trace_terminus(sess, ep, i.id)
        if kind == "circuittermination":
            if detail and norm(detail) != norm(circ.cid):
                wrong.append((tag, circ.cid, detail))
            else:
                resolved.append((tag, circ.cid))
        elif kind == "dead-end":
            dead_end.append((tag, circ.cid, detail))
        else:
            other.append((tag, circ.cid, "%s:%s" % (kind, detail)))

    # --- circuit + atlas coverage ---
    active = [c for c in circuits if str(c.status).lower() == "active"]
    active_no_port = [c.cid for c in active if c.cid not in seen_cids]
    active_no_atlas = [c.cid for c in active if norm(c.cid) not in atlas]
    known_sites = None
    atlas_no_circuit = [fn for k, fn in atlas.items()
                        if k not in cid_by_norm and not any(norm(mt) == k for c in circuits for mt in [c.cid])]

    def show(title, rows, fmt):
        print("\n%s (%d)" % (title, len(rows)))
        for r in rows[:40]:
            print("   " + fmt(r))

    print("== transport reconciliation: %d Core:Transport ifaces, %d dark-fibre circuits ==" % (len(ifaces), len(circuits)))
    show("RESOLVED (iface traces to its circuit termination)", resolved, lambda r: "%s -> %s" % r)
    show("UNCABLED transport iface (no cable at all)", uncabled, lambda r: "%s -> %s" % r)
    show("CABLED BUT DEAD-ENDS before the circuit termination (last patch-panel hop missing)", dead_end,
         lambda r: "%s -> %s  (ends at %s)" % r)
    show("WRONG circuit (traces to a DIFFERENT circuit)", wrong, lambda r: "%s desc=%s trace=%s" % r)
    show("NO NetBox circuit for description token", no_cid, lambda r: "%s tok={%s}" % r)
    show("OTHER terminus (not a circuit termination)", other, lambda r: "%s -> %s (%s)" % r)
    show("ACTIVE circuit with NO described switch port", active_no_port, lambda r: r)
    show("ACTIVE circuit with NO atlas geometry (auto-arc)", active_no_atlas, lambda r: r)
    show("atlas file with no matching circuit", atlas_no_circuit, lambda r: r)
    print("\nSUMMARY: resolved=%d uncabled=%d dead_end=%d wrong=%d no_cid=%d | active_circuits=%d no_port=%d no_atlas=%d"
          % (len(resolved), len(uncabled), len(dead_end), len(wrong), len(no_cid),
             len(active), len(active_no_port), len(active_no_atlas)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
