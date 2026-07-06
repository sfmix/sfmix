#!/usr/bin/env python3
"""Tier 1: mine an EXACT per-circuit cable path out of NDA provider KMZs, using
NetBox as the hint source, and write it to the GITIGNORED network-map/atlas_precise/.

NetBox now holds, per transport circuit: provider, and A/Z (+ any passive) site
buildings with lat/long + street address. Those are exactly the anchors needed to
(a) pick the right KMZ + the right objects inside it (provider maps often carry a
whole regional network for context), and (b) stitch fragmented segments into a
complete A->Z path. This tool turns those hints into an exact path; the separate
Tier-2 coarsener (map_coarsen.py) is the ONLY thing that may derive a committed,
published-safe geometry from it.

    # exact path for one circuit (writes network-map/atlas_precise/<CID>.geojson):
    scripts/map_kmz_mine.py --kmz-dir ~/Downloads/sfmix --cid FID-2023-0409

    # show NetBox geometry hints for all transport circuits (no KMZ needed):
    scripts/map_kmz_mine.py --hints

Run only on a machine where the NDA KMZs live. The exact output is gitignored;
never commit network-map/atlas_precise/.  NetBox creds: SFMIX_OPERATOR_CONFIG_FILE
(yaml, like netbox_ix_lint.py) or NETBOX_API_ENDPOINT / NETBOX_API_TOKEN env.
"""
import argparse
import glob
import json
import os
import re
import sys

import pynetbox

import map_kmz as K

PRECISE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "network-map", "atlas_precise",
)


# ---------------------------------------------------------------------------
# NetBox
# ---------------------------------------------------------------------------
def get_netbox():
    cfg_file = os.environ.get("SFMIX_OPERATOR_CONFIG_FILE", "/opt/sfmix/operator_config.yaml")
    if os.path.exists(cfg_file):
        import yaml
        cfg = yaml.safe_load(open(cfg_file))
        return pynetbox.api(cfg["netbox_api_endpoint"], token=cfg["netbox_api_key"])
    url, tok = os.environ.get("NETBOX_API_ENDPOINT"), os.environ.get("NETBOX_API_TOKEN")
    if not (url and tok):
        sys.exit("No NetBox creds: set SFMIX_OPERATOR_CONFIG_FILE or "
                 "NETBOX_API_ENDPOINT/NETBOX_API_TOKEN")
    return pynetbox.api(url, token=tok)


def _site_hint(term):
    """(slug, (lon,lat)|None, address) for a circuit termination's site."""
    site = getattr(term, "termination", None)
    if not site or not hasattr(site, "slug"):
        return (None, None, "")
    site.full_details()
    lon = float(site.longitude) if site.longitude is not None else None
    lat = float(site.latitude) if site.latitude is not None else None
    coords = (lon, lat) if (lon is not None and lat is not None) else None
    return (site.slug, coords, (site.physical_address or "").replace("\r", " ").replace("\n", " ").strip())


def circuit_hints(nb, cids=None):
    """Per transport circuit, the geometry anchors NetBox knows.

    Returns dicts: {cid, provider, provider_slug, status, a_site, z_site,
    a_coords, z_coords, a_addr, z_addr, match, geom_group}. `geom_group` clusters
    the duplex/BiDi cores that ride ONE leased fibre (same provider + endpoints +
    shared CID stem) so they can share one mined geometry."""
    circuits = []
    for c in nb.circuits.circuits.filter(type="dark-fiber"):
        circuits.append(c)
    for c in nb.circuits.circuits.filter(type="transport"):
        circuits.append(c)
    hints = []
    for c in circuits:
        if cids and c.cid not in cids:
            continue
        terms = {t.term_side: t for t in nb.circuits.circuit_terminations.filter(circuit_id=c.id)}
        a = _site_hint(terms["A"]) if "A" in terms else (None, None, "")
        z = _site_hint(terms["Z"]) if "Z" in terms else (None, None, "")
        hints.append({
            "cid": c.cid,
            "provider": c.provider.name if c.provider else None,
            "provider_slug": c.provider.slug if c.provider else None,
            "status": c.status.value if hasattr(c.status, "value") else str(c.status),
            "a_site": a[0], "a_coords": a[1], "a_addr": a[2],
            "z_site": z[0], "z_coords": z[1], "z_addr": z[2],
        })
    _assign_geom_groups(hints)
    return hints


def _cid_stem(cid):
    # strip a short trailing core suffix: FID-2025-0740-1 -> FID-2025-0740,
    # DF-00000231-0004-0002 -> DF-00000231-0004. Only 1-4 digit suffixes, and
    # only when it leaves a plausible full CID behind (>=2 dashes remain).
    m = re.match(r"^(.*?)-(\d{1,4})$", cid)
    if m and m.group(1).count("-") >= 2:
        return m.group(1)
    return cid


def _assign_geom_groups(hints):
    # Group cores of one leased fibre: same provider + A/Z sites + CID stem.
    for h in hints:
        stem = _cid_stem(h["cid"])
        h["geom_group"] = "%s|%s|%s|%s" % (
            h["provider_slug"], stem, h["a_site"] or "", h["z_site"] or "")
    groups = {}
    for h in hints:
        groups.setdefault(h["geom_group"], []).append(h["cid"])
    for h in hints:
        # match tokens = every core CID sharing this leased fibre + the stem
        stem = _cid_stem(h["cid"])
        h["match"] = sorted(set(groups[h["geom_group"]]) | {stem})
        h["geom_cid"] = stem  # atlas keyed on the leased circuit stem


# ---------------------------------------------------------------------------
# Provider extraction profiles (KMZ -> exact path). Anchored on NetBox coords.
# ---------------------------------------------------------------------------
def _nearest_end(pts_list, anchor):
    """Of many (name,desc,pts), the one whose either end is closest to anchor."""
    best = None
    for item in pts_list:
        pts = item[-1]
        d = min(K.dist(pts[0], anchor), K.dist(pts[-1], anchor))
        if best is None or d < best[0]:
            best = (d, item)
    return best[1] if best else None


def profile_merge(lss, hint):
    """Zayo-style single-service KMZ: every LineString is part of the one path;
    chain them all, anchored/oriented by the NetBox endpoints."""
    path = K.chain_segments([pts for _, _, pts in lss])
    return K.orient_a_to_z(path, hint["a_coords"], hint["z_coords"])


def profile_named(lss, hint):
    """BIG-style multi-route KMZ: pick the LineString(s) whose name/description
    carries a match token, else the one geometrically anchored on the endpoints."""
    toks = [t.lower() for t in hint.get("match", []) if t]
    cand = [(n, d, p) for (n, d, p) in lss
            if any(t in (n + " " + d).lower() for t in toks)]
    if cand:
        path = K.chain_segments([p for _, _, p in cand]) if len(cand) > 1 else cand[0][2]
    else:
        # fall back to geometry: the linestring anchored on the A endpoint
        anchor = hint["a_coords"] or hint["z_coords"]
        if not anchor:
            return None
        item = _nearest_end(lss, anchor)
        path = item[-1] if item else None
    return K.orient_a_to_z(path, hint["a_coords"], hint["z_coords"]) if path else None


# graph-stitch (Boldyn BART right-of-way) lives in map_boldyn_route.py; the miner
# shells to / imports it for provider_slug == 'boldyn-networks'. Wired as a TODO
# so the exact-path step is validated against the real KMZ on the laptop.
PROFILES = {
    "zayo": profile_merge,
    "big_fiber": profile_named,
    "digital-realty": profile_named,
    "hurricane-electric": profile_named,
    # 'boldyn-networks': graph-stitch (see map_boldyn_route.py) — TODO integrate
}


def mine_circuit(hint, kmz_dir):
    """Return an exact path (list of (lon,lat)) for one circuit, or None."""
    prof = PROFILES.get(hint["provider_slug"])
    if not prof:
        print("  ! no extraction profile for provider %r (cid %s) — "
              "Boldyn uses map_boldyn_route.py graph-stitch" % (hint["provider_slug"], hint["cid"]),
              file=sys.stderr)
        return None
    # Locating the exact KMZ file for a provider/circuit is operator knowledge
    # (filenames aren't in NetBox); scan the dir and let the profile filter.
    kmzs = glob.glob(os.path.join(kmz_dir, "*.kmz")) + glob.glob(os.path.join(kmz_dir, "*.kml"))
    lss = []
    for f in kmzs:
        try:
            lss += K.linestrings(K.read_kml(f))
        except Exception as e:
            print("  ! %s: %s" % (os.path.basename(f), e), file=sys.stderr)
    if not lss:
        print("  ! no LineStrings under %s" % kmz_dir, file=sys.stderr)
        return None
    return prof(lss, hint)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kmz-dir", default=os.path.expanduser("~/Downloads/sfmix"),
                    help="directory of NDA KMZ files (laptop only)")
    ap.add_argument("--cid", action="append", help="limit to these circuit id(s)")
    ap.add_argument("--hints", action="store_true",
                    help="print NetBox geometry hints and exit (no KMZ needed)")
    args = ap.parse_args()

    nb = get_netbox()
    hints = circuit_hints(nb, set(args.cid) if args.cid else None)

    if args.hints:
        for h in sorted(hints, key=lambda x: x["cid"]):
            print("%-22s %-16s %s(%s)->%s(%s)  match=%s" % (
                h["cid"], h["provider_slug"] or "-",
                h["a_site"], "geo" if h["a_coords"] else "NO-GEO",
                h["z_site"], "geo" if h["z_coords"] else "NO-GEO",
                ",".join(h["match"])))
        return 0

    os.makedirs(PRECISE_DIR, exist_ok=True)
    # one geometry per leased-fibre group; mine using any core's hint
    by_group = {}
    for h in hints:
        by_group.setdefault(h["geom_cid"], h)
    n = 0
    for geom_cid, h in sorted(by_group.items()):
        path = mine_circuit(h, args.kmz_dir)
        if not path:
            print("SKIP %s (no path mined)" % geom_cid)
            continue
        fc = K.atlas_fc(geom_cid, h["provider"], h["a_site"], h["z_site"],
                        [[lon, lat] for lon, lat in path], match=h["match"],
                        status=h["status"], geometry="exact-kmz")
        out = os.path.join(PRECISE_DIR, "%s.geojson" % geom_cid)
        json.dump(fc, open(out, "w"), indent=2)
        print("MINED %s -> %s (%d pts, exact) [gitignored]" % (geom_cid, out, len(path)))
        n += 1
    print("\n%d exact path(s) written to %s. Next: map_coarsen.py -> committed atlas." % (n, PRECISE_DIR))
    return 0


if __name__ == "__main__":
    sys.exit(main())
