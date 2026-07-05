#!/usr/bin/env python3
"""Build the public network-map structure from live network state + cable atlas.

Runs on metrics.sfo02 (daily cron + on-demand poke). Joins:
  * core-port inventory from Arista eAPI  (descriptions + oper status) — the
    runtime source of truth; a port whose description starts "Core: Transport"
    is a backbone link end, and it is included even when DOWN (rendered offline).
  * LLDP topology from sflow-rt /topology/json — confirms which ends pair up.
  * the committed cable atlas (network-map/atlas/*.geojson) — coarsened geometry.
  * NetBox site records + network-map/sites.json — lat/lon, names, operators.

Emits two files (atomic tmp+rename):
  * map.json        PUBLIC  — opaque per-generation cable ids, no circuit/provider
  * map-links.json  PRIVATE — opaque id -> member ports + circuit id/provider
The portal serves map.json (static, CORS) and reads map-links.json to key the
per-link traffic feed. Circuit ids / providers never appear in map.json.

Modes:
  (default)   build and write map.json + map-links.json
  --check     report atlas<->topology drift; exit 1 on drift (no writes)
  --dry-run   print map.json to stdout instead of writing

Fixture mode (for local dev / CI, no network needed):
  --eapi-fixture F      JSON {device: {ifname: {description, oper}}}
  --topology-fixture F  sflow-rt /topology/json snapshot
  --sites-fixture F     JSON {site: {lat, lon, name, operator, address}}
"""
import argparse
import json
import os
import re
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, os.pardir))
ATLAS_DIR = os.path.join(REPO, "network-map", "atlas")
SITES_JSON = os.path.join(REPO, "network-map", "sites.json")

SFLOW_URL = os.environ.get("SFLOW_URL", "http://127.0.0.1:8008")
PROM_URL = os.environ.get("PROM_URL", "http://127.0.0.1:9090")
NETBOX_API = os.environ.get("IXP_NETBOX_API", "")
NS = uuid.UUID("5f1e9d0c-0000-4000-8000-5f6d6978aabb")

SPEED_BITS = {"1G": 1e9, "10G": 10e9, "25G": 25e9, "40G": 40e9,
              "100G": 100e9, "400G": 400e9, "800G": 800e9,
              "1Gbps": 1e9, "10Gbps": 10e9, "25Gbps": 25e9, "40Gbps": 40e9,
              "100Gbps": 100e9, "400Gbps": 400e9, "800Gbps": 800e9}

# Description grammar: "Core: Transport <SITE> via <Provider> {<TOKEN>} [<Speed>]"
# Parsed with separate anchored searches (one combined regex mis-greeds provider).
RE_SITE = re.compile(r"Transport\s+(?:to\s+)?([A-Za-z]{3}\d{2})", re.I)
RE_PROVIDER = re.compile(r"via\s+(.+?)\s*(?:[{\[(]|$)", re.I)
RE_BTOK = re.compile(r"\{([^}]+)\}")
RE_PTOK = re.compile(r"\(([^)]*#[^)]*)\)")
RE_SPEED = re.compile(r"\[([^\]]+)\]")


def site_of(fqdn):
    # switch01.fmt01.sfmix.org -> fmt01 ; switch01.fmt01 -> fmt01
    parts = fqdn.split(".")
    return parts[1] if len(parts) > 1 else fqdn


def short(fqdn):
    return ".".join(fqdn.split(".")[:2])


def norm_token(tok):
    """Normalize a circuit token for matching (strip spaces, '#')."""
    return re.sub(r"[\s#]", "", tok or "").upper()


def speed_to_bps(s):
    if not s:
        return 100e9
    s = s.strip()
    return SPEED_BITS.get(s, SPEED_BITS.get(s.replace("bps", "").strip() + "G", 100e9))


# ---------------------------------------------------------------------------
# Inputs (live or fixture)
# ---------------------------------------------------------------------------
def _get_json(url):
    import urllib.request
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def load_topology(args):
    if args.topology_fixture:
        return json.load(open(args.topology_fixture))
    return _get_json("%s/topology/json" % SFLOW_URL)


def load_eapi_inventory(args):
    """Return {device_short: {ifname: {"description":..., "oper": "up"|"down"}}}."""
    if args.eapi_fixture:
        return json.load(open(args.eapi_fixture))
    # live: query each active peering switch via eAPI (idioms from topology.py.j2)
    import netrc
    import pyeapi
    import urllib.request
    tokfile = os.path.expanduser("~/.netbox_api_token")
    token = open(tokfile).read().strip()
    devs, url = [], "%s/api/dcim/devices/?status=active&role=peering_switch&limit=200" % NETBOX_API
    while url:
        req = urllib.request.Request(url, headers={"Authorization": "Token %s" % token})
        data = json.load(urllib.request.urlopen(req, timeout=30))
        devs += [d["name"] for d in data["results"]]
        url = data["next"]
    auth = netrc.netrc().authenticators("sfmix.org")
    user, _, pw = auth
    inv = {}
    for dev in devs:
        try:
            node = pyeapi.connect(host=dev, transport="https", username=user,
                                  password=pw, timeout=30, return_node=True)
            resp = node.enable(["show interfaces description"])
            ifaces = resp[0]["result"]["interfaceDescriptions"]
            inv[short(dev)] = {
                ifn: {"description": v.get("description", ""),
                      "oper": "up" if v.get("interfaceStatus", "").lower() in ("up", "connected") else "down"}
                for ifn, v in ifaces.items()}
        except Exception as e:
            print("warning: eAPI %s failed: %r" % (dev, e), file=sys.stderr)
    return inv


def load_iface_facts(args):
    """{(short_host, ifname): speed_bps} from the sflow ``ifspeed`` series label.

    This is the ground-truth-derived link speed sflow-rt learns from the devices
    and exports on every ``sflow_ifoutoctets`` series — the same source the Grafana
    weathermap (scripts/gen_weathermap.py) trusts. It is authoritative over the
    human-typed ``[<Speed>]`` description token, which callers use only as a
    fallback when a port has no series yet. (NetBox is the other candidate
    source-of-truth; it is itself fed from device ground-truth, so the sflow label
    and NetBox should agree — we prefer the live label and leave NetBox as a
    documented alternative.) Returns {} if Prometheus is unreachable."""
    if args.facts_fixture:
        raw = json.load(open(args.facts_fixture))
        out = {}
        for k, v in raw.items():
            if "|" not in k:
                continue  # skip _comment and other metadata keys
            host, ifn = k.split("|", 1)
            sp = v.get("speed") if isinstance(v, dict) else v
            if SPEED_BITS.get(sp):
                out[(short(host), ifn)] = SPEED_BITS[sp]
        return out
    try:
        import urllib.parse
        match = urllib.parse.quote('{__name__="sflow_ifoutoctets"}')
        rows = _get_json("%s/api/v1/series?match[]=%s" % (PROM_URL, match)).get("data", [])
    except Exception as e:
        print("warning: ifspeed series fetch failed (%r); falling back to "
              "description [Speed] tokens" % e, file=sys.stderr)
        return {}
    out = {}
    for s in rows:
        b = SPEED_BITS.get(s.get("ifspeed"))
        if b and s.get("host") and s.get("ifname"):
            out[(short(s["host"]), s["ifname"])] = b
    return out


def port_speed_bps(facts, host, ifname, desc=""):
    """Authoritative ifspeed label if we have it, else the description token."""
    b = facts.get((host, ifname))
    if b:
        return b
    m = RE_SPEED.search(desc or "")
    return speed_to_bps(m.group(1)) if m else 0


def load_sites(args):
    override = json.load(open(SITES_JSON)).get("sites", {}) if os.path.exists(SITES_JSON) else {}
    if args.sites_fixture:
        base = json.load(open(args.sites_fixture))
    elif NETBOX_API:
        base = _load_netbox_sites()
    else:
        base = {}
    sites = {}
    for code in set(list(base) + list(override)):
        b = base.get(code, {}); o = override.get(code, {})
        sites[code] = {
            "lat": b.get("lat"), "lon": b.get("lon"),
            "name": o.get("name") or b.get("name") or code,
            "operator": o.get("operator") or b.get("operator") or "",
            "metro": o.get("metro") or b.get("metro") or "",
            "address": b.get("address", ""),
        }
    return sites


def _load_netbox_sites():
    import urllib.request
    token = open(os.path.expanduser("~/.netbox_api_token")).read().strip()
    url = "%s/api/dcim/sites/?limit=200" % NETBOX_API
    out = {}
    while url:
        req = urllib.request.Request(url, headers={"Authorization": "Token %s" % token})
        data = json.load(urllib.request.urlopen(req, timeout=30))
        for s in data["results"]:
            out[s["slug"]] = {"lat": s.get("latitude"), "lon": s.get("longitude"),
                              "name": s.get("facility") or s.get("name"),
                              "address": (s.get("physical_address") or "").replace("\r\n", ", ")}
        url = data["next"]
    return out


def load_atlas():
    atlas = []
    if not os.path.isdir(ATLAS_DIR):
        return atlas
    for fn in sorted(os.listdir(ATLAS_DIR)):
        if not fn.endswith(".geojson") or fn.startswith("_"):
            continue
        d = json.load(open(os.path.join(ATLAS_DIR, fn)))
        c = d.get("circuit", {})
        atlas.append({
            "file": fn, "a_site": c.get("a_site"), "z_site": c.get("z_site"),
            "status": c.get("status", "active"), "provider": c.get("provider", ""),
            "match": [norm_token(m) for m in c.get("match", [])],
            "segments": [{"medium": f["properties"].get("medium", "underground"),
                          "coordinates": f["geometry"]["coordinates"]} for f in d["features"]],
        })
    return atlas


# ---------------------------------------------------------------------------
# Core-port parsing + cable assembly
# ---------------------------------------------------------------------------
def parse_core_ports(inv, facts):
    """Return list of core-port dicts from interface descriptions. Port speed comes
    from the authoritative ifspeed label (``facts``); the ``[<Speed>]`` description
    token is only a fallback for ports with no series yet."""
    ports = []
    for dev, ifaces in inv.items():
        for ifn, meta in ifaces.items():
            desc = meta.get("description", "")
            if "Core: Transport" not in desc:
                continue
            if "cross-x" in desc or "in cab" in desc.lower():
                continue  # intra-cabinet cross-connect, not a mapped link
            ms, mp = RE_SITE.search(desc), RE_PROVIDER.search(desc)
            mb, mpt = RE_BTOK.search(desc), RE_PTOK.search(desc)
            tok = (mb.group(1) if mb else (mpt.group(1) if mpt else ""))
            ports.append({
                "device": dev, "ifname": ifn, "site": site_of(dev),
                "remote_site": (ms.group(1).lower() if ms else ""),
                "provider": (mp.group(1).strip() if mp else ""),
                "token": tok.strip(), "ntoken": norm_token(tok),
                "speed_bps": port_speed_bps(facts, dev, ifn, desc) or 100e9,
                "oper": meta.get("oper", "down"), "desc": desc,
            })
    return ports


def topo_adjacency(topology):
    """Set of frozenset({'dev short:ifname', ...}) for confirmed LLDP links."""
    adj = set()
    for l in topology.get("links", {}).values():
        a = "%s:%s" % (short(l["node1"]), l["port1"])
        b = "%s:%s" % (short(l["node2"]), l["port2"])
        adj.add(frozenset([a, b]))
    return adj


def assemble_cables(ports, adj):
    """Group core ports into cables. Primary key: normalized circuit token;
    tokenless ports fall back to an unordered (site,remote_site)+provider key."""
    groups = {}
    for p in ports:
        if p["ntoken"]:
            key = ("tok", p["ntoken"])
        else:
            key = ("pair", frozenset([p["site"], p["remote_site"]]), p["provider"].lower())
        groups.setdefault(key, []).append(p)

    # Merge tokenless "pair" groups into a token group when they describe the same
    # physical link — e.g. one end reads "via Zayo {F22M-0204477}" and the far end
    # just "via Zayo" (no token). Match on unordered site-pair + provider so the
    # two ends collapse into one cable instead of a real link + a phantom.
    def prov0(p):
        return (p["provider"].split("+")[0].split()[0].lower() if p["provider"] else "")
    tok_index = {}  # (sitepair, prov0) -> token key
    for key, members in groups.items():
        if key[0] != "tok":
            continue
        sites = frozenset(s for m in members for s in (m["site"], m["remote_site"]) if s)
        tok_index[(sites, prov0(members[0]))] = key
    for key in [k for k in groups if k[0] == "pair"]:
        tgt = tok_index.get((key[1], (key[2].split("+")[0].split() or [""])[0]))
        if tgt:
            groups[tgt].extend(groups.pop(key))

    cables = []
    for key, members in groups.items():
        sites = sorted({m["site"] for m in members} |
                       {m["remote_site"] for m in members if m["remote_site"]})
        # need exactly two distinct sites to place a cable
        endpoints = [s for s in sites if s]
        if len(endpoints) < 2:
            continue
        a_site, z_site = endpoints[0], endpoints[1]
        # up if any member port participates in a confirmed LLDP link
        up = False
        for m in members:
            tag = "%s:%s" % (m["device"], m["ifname"])
            if any(tag in fs for fs in adj) and m["oper"] == "up":
                up = True
        # capacity: sum speeds of member ports on the a_site side (one strand/end)
        cap = sum(m["speed_bps"] for m in members if m["site"] == a_site) or \
            sum(m["speed_bps"] for m in members) / max(1, len(endpoints))
        cables.append({
            "key": key, "a_site": a_site, "z_site": z_site,
            "members": sorted(("%s" % m["device"], m["ifname"]) for m in members),
            "tokens": sorted({m["ntoken"] for m in members if m["ntoken"]}),
            "provider": next((m["provider"] for m in members if m["provider"]), ""),
            "capacity_bps": cap, "status": "up" if up else "down",
        })
    return cables


# ---------------------------------------------------------------------------
# Geometry: atlas match or auto-arc
# ---------------------------------------------------------------------------
def bezier_arc(p0, p1, bulge=0.1, steps=18):
    mx, my = (p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2
    dx, dy = p1[0] - p0[0], p1[1] - p0[1]
    cx, cy = mx - dy * bulge, my + dx * bulge
    out = []
    for i in range(steps + 1):
        t = i / steps
        out.append([round((1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * cx + t ** 2 * p1[0], 5),
                    round((1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * cy + t ** 2 * p1[1], 5)])
    return out


def match_atlas(cable, atlas):
    """Return (atlas_entry, exact). A token match is this circuit's own surveyed
    route (exact=True → solid). A pair-only match means the circuit has no route of
    its own (e.g. an HE/Zayo backup whose KMZ we lack) and is borrowing the site
    pair's known corridor (exact=False → drawn approximate/dotted, parallel to the
    circuit that does own it) — better than a bare auto-arc, honestly flagged."""
    toks = set(cable["tokens"])
    for a in atlas:
        if toks & set(a["match"]):
            return a, True
    pair = frozenset([cable["a_site"], cable["z_site"]])
    for a in atlas:
        if frozenset([a["a_site"], a["z_site"]]) == pair:
            return a, False
    return None, False


def device_layout(devices):
    """Grid of offsets INSIDE the building footprint, sized so device dots, their
    (below-dot) labels, and the intra-link lines don't overlap. Switches sit
    within the box at the device tier, not stacked on the site point."""
    import math
    n = len(devices)
    if n <= 1:
        return {devices[0]: (0.0, 0.0)} if devices else {}
    cols = min(n, 3 if n <= 6 else 4)
    rows = math.ceil(n / cols)
    sx, sy = 0.00095, 0.00060  # inside the ~210x200 m box, with label margin
    out = {}
    for i, d in enumerate(devices):
        r, c = divmod(i, cols)
        x = 0.0 if cols == 1 else (-sx + 2 * sx * c / (cols - 1))
        y = 0.0 if rows == 1 else (sy - 2 * sy * r / (rows - 1))
        out[d] = (round(x, 6), round(y, 6))
    return out


def building_rect(lat, lon):
    """Stylized building footprint (~210x200 m — deliberately larger than the real
    footprint so the box + switches inside are readable when zoomed in)."""
    dx, dy = 0.00130, 0.00090
    return [[round(lon - dx, 6), round(lat - dy, 6)], [round(lon + dx, 6), round(lat - dy, 6)],
            [round(lon + dx, 6), round(lat + dy, 6)], [round(lon - dx, 6), round(lat + dy, 6)],
            [round(lon - dx, 6), round(lat - dy, 6)]]


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build(args):
    topology = load_topology(args)
    inv = load_eapi_inventory(args)
    sites_meta = load_sites(args)
    atlas = load_atlas()

    facts = load_iface_facts(args)
    ports = parse_core_ports(inv, facts)
    adj = topo_adjacency(topology)
    cables = assemble_cables(ports, adj)

    # devices per site (from topology nodes + inventory)
    devs_by_site = {}
    for node in topology.get("nodes", {}):
        devs_by_site.setdefault(site_of(node), set()).add(short(node))
    for dev in inv:
        devs_by_site.setdefault(site_of(dev), set()).add(dev)

    generation = "g-" + uuid.uuid5(NS, args.generation_seed or str(len(cables))).hex[:10]

    sites_out = {}
    for code, meta in sites_meta.items():
        if meta.get("lat") is None:
            continue
        devs = sorted(devs_by_site.get(code, []))
        layout = device_layout(devs)
        sites_out[code] = {
            "lat": meta["lat"], "lon": meta["lon"], "name": meta["name"],
            "operator": meta["operator"], "metro": meta["metro"], "address": meta["address"],
            "building": building_rect(meta["lat"], meta["lon"]),
            "devices": [{"id": d, "dlat": round(meta["lat"] + layout[d][1], 6),
                         "dlon": round(meta["lon"] + layout[d][0], 6)} for d in devs],
        }

    cables_out, links_private, drift = [], {}, {"missing": [], "stale": [],
                                                 "retired_live": [], "borrowed": []}
    matched_files = set()
    for c in cables:
        a, z = c["a_site"], c["z_site"]
        if a not in sites_out or z not in sites_out:
            continue
        a_ll = [sites_out[a]["lon"], sites_out[a]["lat"]]
        z_ll = [sites_out[z]["lon"], sites_out[z]["lat"]]
        atlas_hit, exact = match_atlas(c, atlas)
        if atlas_hit:
            matched_files.add(atlas_hit["file"])
            segments = atlas_hit["segments"]
            # pair-only match = this circuit has no route of its own; borrow the
            # pair's corridor but flag approximate so it draws dotted (see match_atlas)
            approximate = not exact
            if not exact:
                drift["borrowed"].append((a, z, c["tokens"] or c["provider"], atlas_hit["file"]))
            if atlas_hit["status"] == "retired":
                drift["retired_live"].append((atlas_hit["file"], a, z))
        else:
            segments = [{"medium": "underground", "coordinates": bezier_arc(a_ll, z_ll)}]
            approximate = True
            drift["missing"].append((a, z, c["tokens"] or c["provider"]))
        oid = str(uuid.uuid5(NS, generation + "|" + "|".join("%s:%s" % m for m in c["members"])))
        cables_out.append({
            "id": oid, "scope": "inter", "a_site": a, "z_site": z,
            "a_device": c["members"][0][0], "z_device": c["members"][-1][0],
            "capacity_bps": c["capacity_bps"], "status": c["status"],
            "approximate": approximate, "members": len(c["members"]),
            "segments": segments,
        })
        links_private[oid] = {
            "members": [{"host": m[0], "ifname": m[1]} for m in c["members"]],
            "circuit": c["tokens"], "provider": c["provider"],
            "capacity_bps": c["capacity_bps"],
        }

    # intra-site inter-switch links from the LLDP topology: any confirmed link
    # whose two ends live at the same site. Parallel physical links between the
    # same switch pair collapse into one LAG (members = physical link count). We
    # record only the a_device end's port in the private feed so per-link traffic
    # isn't double-counted across both ends of the same fibre.
    intra_groups = {}  # (site, (devA, devB)) -> [(host, ifname) on devA end]
    for l in topology.get("links", {}).values():
        d1, d2 = short(l["node1"]), short(l["node2"])
        s1, s2 = site_of(l["node1"]), site_of(l["node2"])
        if not s1 or s1 != s2 or d1 == d2:
            continue
        da, db = sorted([d1, d2])
        ends = {d1: l["port1"], d2: l["port2"]}
        intra_groups.setdefault((s1, (da, db)), []).append((da, ends[da]))
    for (site, (da, db)), member_ports in sorted(intra_groups.items()):
        if site not in sites_out:
            continue
        dc = {d["id"]: [d["dlon"], d["dlat"]] for d in sites_out[site]["devices"]}
        if da not in dc or db not in dc:
            continue
        # capacity = sum of member-port speeds from the authoritative ifspeed label
        # (description [Speed] token as fallback; 0 if neither is known, in which
        # case the portal treats it as "unknown" and skips util colouring).
        cap = 0
        for h, i in member_ports:
            desc = (inv.get(h, {}).get(i, {}) or {}).get("description", "")
            cap += port_speed_bps(facts, h, i, desc)
        oid = str(uuid.uuid5(NS, generation + "|intra|" + site + "|" + da + "|" + db))
        cables_out.append({
            "id": oid, "scope": "intra", "a_site": site, "z_site": site,
            "a_device": da, "z_device": db, "capacity_bps": cap,
            "status": "up", "approximate": False, "members": len(member_ports),
            "segments": [{"medium": "building", "coordinates": [dc[da], dc[db]]}],
        })
        links_private[oid] = {
            "members": [{"host": h, "ifname": i} for h, i in member_ports],
            "circuit": [], "provider": "", "capacity_bps": cap, "scope": "intra",
        }

    # atlas entries never seen in topology
    for a in atlas:
        if a["file"] not in matched_files and a["status"] == "active":
            drift["stale"].append((a["file"], a["a_site"], a["z_site"]))

    gen_at = args.now or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    mapjson = {"generation": generation, "generated_at": gen_at,
               "sites": sites_out, "cables": cables_out}
    linksjson = {"generation": generation, "generated_at": gen_at, "links": links_private}
    return mapjson, linksjson, drift


def atomic_write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--out", default="/var/www/sfmix-map/map.json")
    ap.add_argument("--links-out", default="/var/lib/sfmix-map/map-links.json")
    ap.add_argument("--eapi-fixture")
    ap.add_argument("--topology-fixture")
    ap.add_argument("--sites-fixture")
    ap.add_argument("--facts-fixture", help='JSON {"host|ifname": {"speed":"100G"}} '
                    "standing in for the live sflow ifspeed series")
    ap.add_argument("--generation-seed", help="stable seed for opaque ids (default: derived)")
    ap.add_argument("--now", help="override generated_at (for reproducible tests)")
    args = ap.parse_args()

    mapjson, links, drift = build(args)

    if args.check:
        # "borrowed" is an intended fallback (route-less circuit riding the pair's
        # corridor, drawn dotted), not drift — report it but don't fail on it.
        n = len(drift["missing"]) + len(drift["stale"]) + len(drift["retired_live"])
        print("cables: %d   sites: %d" % (len(mapjson["cables"]), len(mapjson["sites"])))
        print("\nMISSING atlas (live link -> auto-arc): %s" % (drift["missing"] or "none"))
        print("STALE atlas (active, not in topology):  %s" % (drift["stale"] or "none"))
        print("RETIRED-but-live:                       %s" % (drift["retired_live"] or "none"))
        print("BORROWED corridor (pair-only, dotted):  %s" % (drift["borrowed"] or "none"))
        print("\n" + ("DRIFT DETECTED" if n else "atlas in sync"))
        return 1 if n else 0

    if args.dry_run:
        print(json.dumps(mapjson, indent=2))
        return 0

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    os.makedirs(os.path.dirname(args.links_out), exist_ok=True)
    atomic_write(args.out, mapjson)
    atomic_write(args.links_out, links)
    print("wrote %s (%d cables) and %s" % (args.out, len(mapjson["cables"]), args.links_out),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
