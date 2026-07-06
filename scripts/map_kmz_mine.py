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
ENDPOINT_TOL_M = 2000  # an endpoint must land within ~2 km of the NetBox site


def _load_lss(files):
    lss = []
    for f in files:
        try:
            lss += K.linestrings(K.read_kml(f))
        except Exception as e:
            print("  ! %s: %s" % (os.path.basename(f), e), file=sys.stderr)
    return lss


SINGLE_SPAN_TOL_M = 700  # each end of a single-span route must be this close to
# its OWN site. Tighter than inter-site spacing (~1.3 km) so a route ending at a
# NEIGHBOURING datacenter (e.g. scl04 when we want scl02) is rejected -> graph-stitch.


def _span_score(pts, a, z):
    """Best (A-end + Z-end) fit of a linestring to the circuit's endpoints, meters."""
    e0, e1 = pts[0], pts[-1]
    return min(K.meters_between(e0, a) + K.meters_between(e1, z),
               K.meters_between(e1, a) + K.meters_between(e0, z))


def _endpoint_gap(pts, a, z):
    """The WORSE of the two endpoint distances, in the better orientation — so both
    ends must independently land near their site (sum can hide one bad end)."""
    e0, e1 = pts[0], pts[-1]
    return min(max(K.meters_between(e0, a), K.meters_between(e1, z)),
               max(K.meters_between(e1, a), K.meters_between(e0, z)))


def profile_merge(files, hint):
    """Zayo-style single-service KMZ: every LineString is part of the one path;
    chain them all, anchored/oriented by the NetBox endpoints."""
    lss = _load_lss(files)
    if not lss:
        return None
    path = K.chain_segments([pts for _, _, pts in lss])
    return K.orient_a_to_z(path, hint["a_coords"], hint["z_coords"])


def graph_route(files, hint, folder_aware=False):
    """Route A->Z over the provider's own drawn segments (map_boldyn_route's
    snap-graph + Dijkstra between the nodes nearest the NetBox A/Z coords). Used
    when no single LineString spans the circuit — the physical path is a chain
    through a waypoint (Boldyn's BART network; BIG's off-ring sites like QTS that
    reach the ring only via OpenColo). This DERIVES the chain from real segments
    rather than hand-assuming it. Returns None if an endpoint is off-network or
    the route is disconnected. folder_aware uses Boldyn's built/planned costing."""
    import map_boldyn_route as B
    a, z = hint["a_coords"], hint["z_coords"]
    if not (a and z):
        return None
    segs = []
    for f in files:
        try:
            if folder_aware:
                s, _pts = B.parse_kml(B.mtp.read_kml(f))
                segs += s
            else:
                segs += [(pts, "underground", True) for _n, _d, pts in K.linestrings(K.read_kml(f))]
        except Exception as e:
            print("  ! %s: %s" % (os.path.basename(f), e), file=sys.stderr)
    if not segs:
        return None
    node_xy, adj, _emeta = B.build_graph(segs)
    sa, da = B.nearest_node(node_xy, a)
    sz, dz = B.nearest_node(node_xy, z)
    if da > ENDPOINT_TOL_M or dz > ENDPOINT_TOL_M:
        return None
    path, _cost = B.dijkstra(adj, sa, sz)
    if not path:
        return None
    return [a] + [node_xy[s] for s in path] + [z]


def profile_named(files, hint):
    """BIG-style multi-route KMZ: pick the route for THIS circuit. Prefer a
    LineString whose name/description carries the CID token; else the single
    LineString that best spans both NetBox endpoints. If no single route spans
    them (an off-ring site reached only via a waypoint), fall back to routing the
    chain over the provider's drawn segments — never hand-assume the waypoint."""
    a, z = hint["a_coords"], hint["z_coords"]
    if not (a and z):
        return None
    lss = _load_lss(files)
    if not lss:
        return None
    toks = [t.lower() for t in hint.get("match", []) if t]
    named = [(n, d, p) for (n, d, p) in lss
             if any(t in (n + " " + d).lower() for t in toks)]
    # SINGLE best-spanning candidate (prefer CID-named). Never chain duplicates.
    # Accept only if BOTH ends land near their own site.
    pool = named or lss
    best = min(pool, key=lambda it: _span_score(it[2], a, z))
    if _endpoint_gap(best[2], a, z) <= SINGLE_SPAN_TOL_M:
        return K.orient_a_to_z(best[2], a, z)
    # no single span — route the chain over the provider's segments
    routed = graph_route(files, hint, folder_aware=False)
    if routed:
        print("  · %s: no single-span route; graph-stitched over provider segments"
              % hint["cid"], file=sys.stderr)
    return routed


def profile_boldyn(files, hint):
    """Boldyn rides BART rights-of-way — the KMZ is a network, not a per-circuit
    path, so always graph-route (built/planned aware)."""
    return graph_route(files, hint, folder_aware=True)


PROFILES = {
    "zayo": profile_merge,
    "big_fiber": profile_named,
    "digital-realty": profile_named,
    "hurricane-electric": profile_named,
    "boldyn-networks": profile_boldyn,
}


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _digits(s):
    return re.sub(r"\D", "", s or "")


def discover_kmz(kmz_dir):
    return sorted(glob.glob(os.path.join(kmz_dir, "**", "*.kmz"), recursive=True)
                  + glob.glob(os.path.join(kmz_dir, "**", "*.kml"), recursive=True))


def _path_matches(path, hint):
    """True if the KMZ file path carries the circuit's CID/order token. Provider
    folders here are named by circuit, so the path is the most reliable selector.
    Matches on alnum-normalized token OR a >=6-digit run (handles FBDK/1721530/ZFS
    vs FBDK-1721530-ZFS, and SO-00000231-0000 vs a '00000231-0000' folder)."""
    np, dp = _norm(path), _digits(path)
    for tok in hint.get("match", []):
        if not tok:
            continue
        if _norm(tok) and _norm(tok) in np:
            return True
        dt = _digits(tok)
        if len(dt) >= 6 and dt in dp:
            return True
    return False


# provider_slug -> substring identifying that provider's KMZ folder. Used to
# scope the same-provider fallback so we never mine across unrelated providers.
PROVIDER_FOLDER = {
    "big_fiber": "BIG Fiber", "zayo": "Zayo", "boldyn-networks": "Boldyn",
}


def _file_provider_ok(path, slug):
    sub = PROVIDER_FOLDER.get(slug)
    return bool(sub) and sub.lower() in path.lower()


# Regional/marketing overview maps (a provider's whole footprint, other metros)
# — the "context" hierarchy, not SFMIX service maps. Excluded from the fallback
# routing graph so a stray far-away segment can't shortcut a local route.
_OVERVIEW_PATTERNS = ("external-sales", "external sales", "sales map")


def _is_overview(path):
    p = path.lower()
    return any(pat in p for pat in _OVERVIEW_PATTERNS)


def _boldyn_graph_files(files):
    """The Boldyn BART network graph: prefer the newest 'Customer Facing Boldyn
    Fiber Network <M.D.YY>' map; else the access-points map; else whatever's given."""
    net = [f for f in files if "customer facing boldyn fiber network" in f.lower()]
    if net:
        def datekey(f):
            m = re.search(r"(\d{1,2})\.(\d{1,2})\.(\d{2})", os.path.basename(f))
            return (int(m.group(3)), int(m.group(1)), int(m.group(2))) if m else (0, 0, 0)
        return [max(net, key=datekey)]
    ap = [f for f in files if "boldyn fiber route" in f.lower()]
    return ap or files


def mine_circuit(hint, kmz_files):
    """Return (path, used_files, matched_by_path) for one circuit."""
    prof = PROFILES.get(hint["provider_slug"])
    if not prof:
        print("  ! no extraction profile for provider %r (cid %s) — Boldyn graph-stitch TODO"
              % (hint["provider_slug"], hint["cid"]), file=sys.stderr)
        return None, [], False
    if not (hint["a_coords"] and hint["z_coords"]):
        print("  ! %s: missing A/Z site geo in NetBox — cannot anchor, skip" % hint["cid"],
              file=sys.stderr)
        return None, [], False
    # First choice: KMZ files whose PATH carries the CID (provider folders are
    # named by circuit). Fallback: any same-provider map (the route may be a
    # placemark inside another circuit's folder / a shared regional map) — the
    # profile's both-endpoint scoring picks the right route and rejects if none
    # spans this circuit. Never fall across providers (that fabricates garbage).
    cand = [f for f in kmz_files if _path_matches(f, hint)]
    by_path = bool(cand)
    if not cand:
        cand = [f for f in kmz_files
                if _file_provider_ok(f, hint["provider_slug"]) and not _is_overview(f)]
    # Boldyn without a dedicated route KMZ routes over the shared BART network graph.
    if hint["provider_slug"] == "boldyn-networks" and not by_path:
        cand = _boldyn_graph_files(cand)
    if not cand:
        print("  ! no KMZ for %s (%s) — wave/hand-draw?" % (hint["cid"], hint["provider_slug"]),
              file=sys.stderr)
        return None, [], False
    path = prof(cand, hint)
    if not path:
        print("  ! %s: no route in %d %s map(s) spans %s->%s"
              % (hint["cid"], len(cand), hint["provider_slug"], hint["a_site"], hint["z_site"]),
              file=sys.stderr)
        return None, cand, by_path
    return path, cand, by_path


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

    kmz_files = discover_kmz(args.kmz_dir)
    print("found %d KMZ/KML under %s" % (len(kmz_files), args.kmz_dir), file=sys.stderr)
    os.makedirs(PRECISE_DIR, exist_ok=True)
    # one geometry per leased-fibre group; mine using any core's hint
    by_group = {}
    for h in hints:
        by_group.setdefault(h["geom_cid"], h)
    n = 0
    for geom_cid, h in sorted(by_group.items()):
        path, used, by_path = mine_circuit(h, kmz_files)
        if not path:
            print("SKIP %s (no path mined)" % geom_cid)
            continue
        fc = K.atlas_fc(geom_cid, h["provider"], h["a_site"], h["z_site"],
                        [[lon, lat] for lon, lat in path], match=h["match"],
                        status=h["status"], geometry="exact-kmz")
        safe = re.sub(r"[^A-Za-z0-9._-]", "-", geom_cid)  # FBDK/1721530/ZFS -> FBDK-1721530-ZFS
        out = os.path.join(PRECISE_DIR, "%s.geojson" % safe)
        json.dump(fc, open(out, "w"), indent=2)
        src = ("path-matched:" + ";".join(os.path.basename(f) for f in used)) if by_path \
            else ("same-provider across %d files" % len(used))
        da = K.meters_between(path[0], h["a_coords"])
        dz = K.meters_between(path[-1], h["z_coords"])
        warn = "  !! ENDPOINTS OFF A=%.0fm Z=%.0fm" % (da, dz) if (da > 1500 or dz > 1500) else ""
        print("MINED %-22s %d pts exact -> %s  [%s]%s"
              % (geom_cid, len(path), os.path.basename(out), src, warn))
        n += 1
    print("\n%d exact path(s) written to %s. Next: map_coarsen.py -> committed atlas." % (n, PRECISE_DIR))
    return 0


if __name__ == "__main__":
    sys.exit(main())
