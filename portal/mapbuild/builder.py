"""Build the public network-map structure from NetBox + committed geometry.

NetBox is the single source of truth for topology and capacity; the committed
geometry inputs (cable atlas, site overrides, basemap water rings, rights-of-way)
ship in this package's data/ dir, produced offline by the repo KMZ pipeline (see
network-map/ARCHITECTURE.md). Because everything comes from NetBox (world-
reachable) + baked-in data, this runs in the portal with only a public network —
no sflow-rt, no eAPI, no internal access.

Emits two structures:
  * map.json        PUBLIC  — opaque per-generation cable ids, render-ready
                              path/media/drops, sites, metros, metro_cables.
                              No circuit ids or provider names.
  * map-links.json  PRIVATE — opaque id -> member {host, ifname} ports + circuit
                              id/provider, so the portal can key the per-link
                              traffic overlay. Never served to the browser.

Entry points: build() returns (map, links, drift); write_outputs() writes them
atomically. The Django-Q2 task and the build_map management command call these.
"""
import json
import os
import re
import time
import uuid

from . import geometry as mg
from . import circuits as circ
from .routing import infra_route

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
ATLAS_DIR = os.path.join(DATA_DIR, "atlas")
SITES_JSON = os.path.join(DATA_DIR, "sites.json")
WATER_JSON = os.path.join(DATA_DIR, "basemap-water.json")

# uuid5 namespace for opaque per-generation cable ids (stable within a generation)
NS = uuid.UUID("5f1e9d0c-0000-4000-8000-5f6d6978aabb")

# The sflow/Prometheus traffic series label hosts by FQDN (e.g.
# switch01.sfo02.sfmix.org), while NetBox device names are bare hostnames
# (switch01.sfo02). The PRIVATE map-links member host is the Prometheus join key,
# so emit it as the FQDN; map.json's display device ids stay the bare name.
DEVICE_DOMAIN = os.environ.get("MAP_DEVICE_DOMAIN", "sfmix.org")


def traffic_host(dev):
    return "%s.%s" % (dev, DEVICE_DOMAIN) if dev and not dev.endswith("." + DEVICE_DOMAIN) else dev

SPEED_BITS = {"1G": 1e9, "10G": 10e9, "25G": 25e9, "40G": 40e9,
              "100G": 100e9, "400G": 400e9, "800G": 800e9,
              "1Gbps": 1e9, "10Gbps": 10e9, "25Gbps": 25e9, "40Gbps": 40e9,
              "100Gbps": 100e9, "400Gbps": 400e9, "800Gbps": 800e9}


def site_of(name):
    # switch01.fmt01 -> fmt01 ; ar1.scl02.transit -> scl02
    parts = name.split(".")
    return parts[1] if len(parts) > 1 else name


def norm_token(tok):
    """Normalize a circuit token for atlas matching (strip spaces, '#')."""
    return re.sub(r"[\s#]", "", tok or "").upper()


def port_speed_bps(facts, host, ifname):
    """NetBox-derived link speed for a port, or 0 if unknown (util-colouring off)."""
    return facts.get((host, ifname)) or 0


# ---------------------------------------------------------------------------
# NetBox session + inputs
# ---------------------------------------------------------------------------
def _netbox_session():
    """(pynetbox api, requests.Session, api_base) sharing one set of creds, so the
    topology + cable passes reuse a single authenticated session."""
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    nb = circ.get_netbox()
    api = nb.base_url.rstrip("/")  # already includes /api
    S = requests.Session()
    S.headers = {"Authorization": "Token %s" % nb.token, "Accept": "application/json"}
    S.verify = False
    return nb, S, api


def load_water_rings():
    """Water polygon rings from the committed basemap, for submarine-span
    detection. [] if absent (then no cable gets water treatment — safe)."""
    try:
        d = json.load(open(WATER_JSON))
    except (OSError, ValueError):
        return []
    rings = []
    for f in d.get("features", []):
        g = f.get("geometry", {})
        polys = g["coordinates"] if g.get("type") == "MultiPolygon" else [g.get("coordinates", [])]
        for poly in polys:
            rings += list(poly)
    return rings


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


def load_sites(nb):
    """Site lat/lon/name/address from NetBox, with name/operator/metro overrides
    from the committed data/sites.json."""
    override = json.load(open(SITES_JSON)).get("sites", {}) if os.path.exists(SITES_JSON) else {}
    base = {}
    for s in nb.dcim.sites.all():
        base[s.slug] = {
            "lat": float(s.latitude) if s.latitude is not None else None,
            "lon": float(s.longitude) if s.longitude is not None else None,
            "name": s.facility or s.name,
            "address": (s.physical_address or "").replace("\r\n", ", "),
        }
    sites = {}
    for code in set(list(base) + list(override)):
        b = base.get(code, {})
        o = override.get(code, {})
        sites[code] = {
            "lat": b.get("lat"), "lon": b.get("lon"),
            "name": o.get("name") or b.get("name") or code,
            "operator": o.get("operator") or b.get("operator") or "",
            "metro": o.get("metro") or b.get("metro") or "",
            "address": b.get("address", ""),
        }
    return sites


# ---------------------------------------------------------------------------
# Topology + cables from NetBox
# ---------------------------------------------------------------------------
def netbox_topology(nb, S, api):
    """Reconstruct a {nodes, links} topology purely from NetBox, plus a
    {(device, ifname): speed_bps} map. Scope: interfaces tagged `core_port` on
    active peering_switch devices (transit routers carry that role too). Each such
    cabled interface is traced to its terminal far interface; if the far end is
    another mapped device's interface, that pair is one link. Node ids are the
    FULL NetBox device names so interface lookups and site_of() work directly for
    3-part transit names (ar1.scl02.transit). A core port whose trace lands on a
    patch panel with no onward path is skipped — the same gap the backbone lint
    reports."""
    devs = {}  # NetBox device name -> site slug
    for d in nb.dcim.devices.filter(role="peering_switch", status="active"):
        if d.name.lower().startswith("old-"):
            continue  # decommissioned kit kept in NetBox for history
        devs[d.name] = d.site.slug if d.site else ""

    def nbget(path, **params):
        params["limit"] = 500
        url, out = api + path, []
        while url:
            j = S.get(url, params=params, timeout=60).json()
            out += j.get("results", [])
            url, params = j.get("next"), {}
        return out

    speeds, ports = {}, []
    for i in nbget("/dcim/interfaces/", tag="core_port"):
        dev = i["device"]["name"]
        if dev not in devs or not i.get("cable"):
            continue
        ports.append((dev, i["name"], i["id"]))
        if i.get("speed"):
            speeds[(dev, i["name"])] = i["speed"] * 1000  # NetBox kbps -> bps

    id_iface = {}  # interface id -> (device, ifname), cached across traces

    def far_iface(iid):
        tr = S.get("%s/dcim/interfaces/%d/trace/" % (api, iid), timeout=40).json()
        if not tr:
            return None
        far = tr[-1][2]
        node = far[0] if far else None
        if not node or "/dcim/interfaces/" not in (node.get("url") or ""):
            return None
        fid = node.get("id")
        if fid not in id_iface:
            r = S.get("%s/dcim/interfaces/%d/" % (api, fid), timeout=40).json()
            id_iface[fid] = (r["device"]["name"], r["name"])
            # capture the far port's speed too: a transit router's physical member
            # ports (e.g. Juniper xe-0/0/13) are often untagged — only the LAG
            # bundle carries core_port — so they'd miss the tagged-query speed pass.
            if r.get("speed"):
                speeds[(r["device"]["name"], r["name"])] = r["speed"] * 1000
        return id_iface[fid]

    links, seen = {}, set()
    for dev, ifn, iid in ports:
        far = far_iface(iid)
        if not far:
            continue
        fdev, fifn = far
        if fdev not in devs or (fdev == dev and fifn == ifn):
            continue  # far end is unmapped kit, or a self-loop
        key = frozenset([(dev, ifn), (fdev, fifn)])
        if key in seen:
            continue
        seen.add(key)
        links["%s:%s|%s:%s" % (dev, ifn, fdev, fifn)] = {
            "node1": dev, "port1": ifn, "node2": fdev, "port2": fifn}
    return {"nodes": {n: {"ports": {}} for n in devs}, "links": links}, speeds


def netbox_cables(topology, facts, nb, S, api):
    """Inter-site transport cables from NetBox (source of truth): one cable per
    LEASED circuit (BiDi cores grouped by geom stem). We scope to transport ports
    via the inter-site links, trace each interface to its NetBox transport circuit,
    and group by leased stem — so each interface attributes to its OWN circuit (a
    passive-site chain like scl02->scl03 + sfo02->scl03 stays two segments).
    Geometry matches the atlas by CID tokens; map_exclude circuits are dropped;
    status from the circuit lifecycle (active->up, planned->planned, else down)."""
    hints = circ.circuit_hints(nb)
    bycid = {h["cid"]: h for h in hints}
    gc_hint = {h["geom_cid"]: h for h in hints}
    exclude = {c.cid for c in nb.circuits.circuits.filter(tag="map_exclude")}

    if_cache = {}  # (dev, ifn) -> (id, netbox_speed_bps)

    def iface_info(dev, ifn):
        key = (dev, ifn)
        if key not in if_cache:
            r = S.get(api + "/dcim/interfaces/", params={"device": dev, "name": ifn}, timeout=40).json()
            res = r.get("results") or []
            if_cache[key] = (res[0]["id"], (res[0]["speed"] * 1000 if res[0].get("speed") else None)) \
                if res else (None, None)
        return if_cache[key]

    def traced_cid(iid):
        tr = S.get("%s/dcim/interfaces/%d/trace/" % (api, iid), timeout=40).json()
        for hop in tr:
            for side in (hop[0], hop[2]):
                for nd in side or []:
                    if isinstance(nd.get("circuit"), dict):
                        return nd["circuit"]["cid"]
        return None

    members = {}  # geom_cid -> {(dev, ifname): speed_bps}
    for l in topology.get("links", {}).values():
        ends = [(l["node1"], l["port1"], site_of(l["node1"])),
                (l["node2"], l["port2"], site_of(l["node2"]))]
        s1, s2 = ends[0][2], ends[1][2]
        if not s1 or not s2 or s1 == s2:
            continue  # inter-site transport only
        for dev, ifn, _s in ends:
            iid, nb_spd = iface_info(dev, ifn)
            if not iid:
                continue
            cid = traced_cid(iid)
            if not cid or cid not in bycid or cid in exclude:
                continue
            gc = bycid[cid]["geom_cid"]
            spd = facts.get((dev, ifn)) or nb_spd or 100e9
            members.setdefault(gc, {})[(dev, ifn)] = spd

    cables = []
    for gc, mem in members.items():
        h = gc_hint[gc]
        a, z = h["a_site"], h["z_site"]
        if not (a and z):
            continue
        mlist = sorted(mem)
        cap = sum(s for (d, _i), s in mem.items() if site_of(d) == a) or (sum(mem.values()) / 2)
        st = h.get("status")
        status = "up" if st == "active" else ("planned" if st == "planned" else "down")
        cables.append({
            "key": ("nb", gc), "a_site": a, "z_site": z, "members": mlist,
            "tokens": sorted({norm_token(t) for t in h.get("match", [])}),
            "provider": h.get("provider") or "", "capacity_bps": cap, "status": status,
        })
    return cables


# ---------------------------------------------------------------------------
# Geometry: atlas match or infra-following route / arc
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
    toks = set(cable["tokens"])
    for a in atlas:
        if toks & set(a["match"]):
            return a
    pair = frozenset([cable["a_site"], cable["z_site"]])
    for a in atlas:
        if frozenset([a["a_site"], a["z_site"]]) == pair:
            return a
    return None


def device_layout(devices):
    """Grid of offsets INSIDE the building footprint, sized so device dots, their
    (below-dot) labels, and the intra-link lines don't overlap."""
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
    """Stylized building footprint (~210x200 m — larger than the real footprint so
    the box + switches inside are readable when zoomed in)."""
    dx, dy = 0.00130, 0.00090
    return [[round(lon - dx, 6), round(lat - dy, 6)], [round(lon + dx, 6), round(lat - dy, 6)],
            [round(lon + dx, 6), round(lat + dy, 6)], [round(lon - dx, 6), round(lat + dy, 6)],
            [round(lon - dx, 6), round(lat - dy, 6)]]


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build(generation_seed=None, now=None):
    """Assemble the public map + private links structures. Returns
    (map_dict, links_dict, drift_dict)."""
    nb, S, api = _netbox_session()
    topology, facts = netbox_topology(nb, S, api)  # capacity straight from NetBox
    cables = netbox_cables(topology, facts, nb, S, api)
    sites_meta = load_sites(nb)
    atlas = load_atlas()

    # devices per site (from the NetBox topology nodes)
    devs_by_site = {}
    for node in topology.get("nodes", {}):
        devs_by_site.setdefault(site_of(node), set()).add(node)

    generation = "g-" + uuid.uuid5(NS, generation_seed or str(len(cables))).hex[:10]

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

    water = load_water_rings()
    box = {code: mg.rect_bounds(sites_out[code]["building"]) for code in sites_out}
    devll = {code: {d["id"]: [d["dlon"], d["dlat"]] for d in sites_out[code]["devices"]}
             for code in sites_out}

    cables_out, links_private = [], {}
    drift = {"missing": [], "stale": [], "retired_live": []}
    matched_files = set()
    for c in cables:
        a, z = c["a_site"], c["z_site"]
        if a not in sites_out or z not in sites_out:
            continue
        a_ll = [sites_out[a]["lon"], sites_out[a]["lat"]]
        z_ll = [sites_out[z]["lon"], sites_out[z]["lat"]]
        atlas_hit = match_atlas(c, atlas)
        if atlas_hit:
            matched_files.add(atlas_hit["file"])
            segments = atlas_hit["segments"]
            approximate = False
            if atlas_hit["status"] == "retired":
                drift["retired_live"].append((atlas_hit["file"], a, z))
        else:
            routed = infra_route(a_ll, z_ll)  # follow rail/highway rights-of-way if we can
            segments = [{"medium": "underground",
                         "coordinates": routed or bezier_arc(a_ll, z_ll)}]
            approximate = True
            drift["missing"].append((a, z, c["tokens"] or c["provider"]))
        # Represent the link by ONE end (a-side preferred): a point-to-point link's
        # two ends mirror each other, so counting both would double the LAG strand
        # count AND double-count traffic (summing in-octets over both ends = both
        # directions, forcing in==out). Passive-splice segments have only one real
        # end. capacity_bps is already the a-side sum, so this stays consistent.
        a_ports = [m for m in c["members"] if site_of(m[0]) == a]
        z_ports = [m for m in c["members"] if site_of(m[0]) == z]
        rep = a_ports or z_ports or c["members"]
        a_dev = a_ports[0][0] if a_ports else ""
        z_dev = z_ports[0][0] if z_ports else ""
        geom = mg.build_inter_geometry(segments, a_ll, z_ll, box.get(a), box.get(z), water,
                                       devll.get(a, {}).get(a_dev), devll.get(z, {}).get(z_dev))
        oid = str(uuid.uuid5(NS, generation + "|" + "|".join("%s:%s" % m for m in c["members"])))
        cables_out.append({
            "id": oid, "scope": "inter", "a_site": a, "z_site": z,
            "a_device": a_dev, "z_device": z_dev,
            "capacity_bps": c["capacity_bps"], "status": c["status"],
            "approximate": approximate, "members": len(rep),
            "path": geom["path"], "media": geom["media"], "drops": geom["drops"],
        })
        links_private[oid] = {
            "members": [{"host": traffic_host(m[0]), "ifname": m[1]} for m in rep],
            "circuit": c["tokens"], "provider": c["provider"],
            "capacity_bps": c["capacity_bps"],
        }

    # intra-site inter-switch links from the NetBox topology: any link whose two
    # ends live at the same site. Parallel physical links between the same switch
    # pair collapse into one LAG (members = physical link count). We record only
    # the a_device end's port in the private feed so per-link traffic isn't
    # double-counted across both ends of the same fibre.
    intra_groups = {}  # (site, (devA, devB)) -> [(dev, ifname) on devA end]
    for l in topology.get("links", {}).values():
        d1, d2 = l["node1"], l["node2"]
        s1, s2 = site_of(d1), site_of(d2)
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
        cap = sum(port_speed_bps(facts, h, i) for h, i in member_ports)
        oid = str(uuid.uuid5(NS, generation + "|intra|" + site + "|" + da + "|" + db))
        cables_out.append({
            "id": oid, "scope": "intra", "a_site": site, "z_site": site,
            "a_device": da, "z_device": db, "capacity_bps": cap,
            "status": "up", "approximate": False, "members": len(member_ports),
            "path": [dc[da], dc[db]], "media": [], "drops": [],
        })
        links_private[oid] = {
            "members": [{"host": traffic_host(h), "ifname": i} for h, i in member_ports],
            "circuit": [], "provider": "", "capacity_bps": cap, "scope": "intra",
        }

    # passive-site cross-connects: at a switchless site (e.g. scl03, a DRT splice),
    # the inter-site cables land on the building-box edge but there's no device to
    # drop to. Draw the through-patch as a plain segment between the box-edge
    # landing points, so the site reads as a full box with a cross-connect.
    for code, s in sites_out.items():
        if s["devices"]:
            continue
        ends = []
        for c in cables_out:
            if c["scope"] != "inter" or not c["path"]:
                continue
            if c["a_site"] == code:
                ends.append(c["path"][0])
            elif c["z_site"] == code:
                ends.append(c["path"][-1])
        if len(ends) < 2:
            continue
        if len(ends) == 2:
            segs = [ends]
        else:  # >2 landings: star them through the box centroid
            cx = [round(sum(e[0] for e in ends) / len(ends), 6),
                  round(sum(e[1] for e in ends) / len(ends), 6)]
            segs = [[e, cx] for e in ends]
        for k, seg in enumerate(segs):
            oid = str(uuid.uuid5(NS, generation + "|xc|" + code + "|" + str(k)))
            cables_out.append({
                "id": oid, "scope": "crossconnect", "a_site": code, "z_site": code,
                "a_device": "", "z_device": "", "capacity_bps": 0, "status": "up",
                "approximate": False, "members": 0, "path": seg, "media": [], "drops": [],
            })

    # atlas entries never seen in topology
    for a in atlas:
        if a["file"] not in matched_files and a["status"] == "active":
            drift["stale"].append((a["file"], a["a_site"], a["z_site"]))

    # parallel-lane ordinals + pre-aggregated metro trunks (frontend just draws them)
    mg.assign_lanes(cables_out)
    groups = {}
    for code, s in sites_out.items():
        g = groups.setdefault(s["metro"] or code, {"lons": [], "lats": [], "codes": []})
        g["lons"].append(s["lon"]); g["lats"].append(s["lat"]); g["codes"].append(code)
    metros_out, metro_of, metro_centroid = {}, {}, {}
    for name, g in groups.items():
        c = [sum(g["lons"]) / len(g["lons"]), sum(g["lats"]) / len(g["lats"])]
        metro_centroid[name] = c
        for code in g["codes"]:
            metro_of[code] = name
        metros_out[name] = {"lon": round(c[0], 6), "lat": round(c[1], 6), "codes": g["codes"]}
    metro_cables = mg.metro_aggregate(cables_out, sites_out, metro_of, metro_centroid)
    # metro trunks get their own water-crossing spans so the submarine treatment
    # (blue veil + waves) also applies at the zoomed-out inter-metro tier.
    for mc in metro_cables:
        mc["media"] = mg.water_spans(mc.get("path", []), water)

    gen_at = now or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    mapjson = {"generation": generation, "generated_at": gen_at, "sites": sites_out,
               "metros": metros_out, "cables": cables_out, "metro_cables": metro_cables}
    linksjson = {"generation": generation, "generated_at": gen_at, "links": links_private}
    return mapjson, linksjson, drift


def _atomic_write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


def write_outputs(mapjson, linksjson, out_path, links_path):
    """Atomically write the public map + private links files."""
    _atomic_write(out_path, mapjson)
    _atomic_write(links_path, linksjson)
