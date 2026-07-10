"""Build the public network-map structure from NetBox + committed geometry.

NetBox is the single source of truth for topology and capacity; the committed
geometry inputs (cable atlas, site overrides, basemap water rings, rights-of-way)
ship in this package's data/ dir, produced offline by the repo KMZ pipeline (see
network-map/ARCHITECTURE.md). Because everything comes from NetBox (world-
reachable) + baked-in data, this runs in the portal with only a public network —
no sflow-rt, no eAPI, no internal access.

Emits three structures:
  * map.json        PUBLIC  — opaque per-generation cable ids, render-ready
                              path/media/drops, sites, metros, metro_cables.
                              No circuit ids or provider names.
  * weathermap.json PUBLIC  — the same graph laid out schematically (nodes with
                              canvas positions + links keyed by the same cable
                              ids), for the website's weathermap renderer.
                              Derived from map.json — see weathermap.py.
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
    from the committed data/sites.json. Also carries the PeeringDB facility id
    (NetBox custom field `peeringdb_facility`, or a sites.json override) so the
    build can enrich the site with public PeeringDB metadata."""
    override = json.load(open(SITES_JSON)).get("sites", {}) if os.path.exists(SITES_JSON) else {}
    base = {}
    for s in nb.dcim.sites.all():
        base[s.slug] = {
            "lat": float(s.latitude) if s.latitude is not None else None,
            "lon": float(s.longitude) if s.longitude is not None else None,
            "name": s.facility or s.name,
            "address": (s.physical_address or "").replace("\r\n", ", "),
            "pdb_fac": (s.custom_fields or {}).get("peeringdb_facility"),
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
            "pdb_fac": o.get("peeringdb_facility") or b.get("pdb_fac"),
        }
    return sites


def _peeringdb_api_key():
    """Optional PeeringDB API key from the operator config (raises the rate
    limit; the fac/org endpoints read fine without it). None if unset."""
    cfg_file = os.environ.get("SFMIX_OPERATOR_CONFIG_FILE", "/opt/sfmix/operator_config.yaml")
    if os.path.exists(cfg_file):
        try:
            import yaml
            return (yaml.safe_load(open(cfg_file)) or {}).get("peeringdb_api_key")
        except Exception:
            return None
    return os.environ.get("PEERINGDB_API_KEY")


# public PeeringDB fields threaded from load/enrich into the emitted site
PDB_SITE_FIELDS = ("pdb_fac", "pdb_url", "operator_website", "city", "state",
                   "country", "net_count", "ix_count", "logo")

# Operator logos come from PeeringDB org records as absolute peeringdb.com URLs.
# We never emit those into map.json (that would hotlink a third party from every
# visitor's browser and leak visitor IPs to PeeringDB); instead the build
# downloads each logo and rewrites `logo` to a portal-served path under this
# prefix. The host nginx serves these directly from the map-public bind mount
# (location /statistics/map/logos/), alongside map.json — no Django view.
LOGO_URL_PREFIX = "/statistics/map/logos/"
LOGO_MAX_BYTES = 512 * 1024
# content-type -> extension; also the allowlist of acceptable logo formats
LOGO_CONTENT_TYPES = {
    "image/png": "png", "image/jpeg": "jpg", "image/svg+xml": "svg",
    "image/webp": "webp", "image/gif": "gif",
}


def enrich_peeringdb(sites):
    """Merge public PeeringDB facility metadata into sites that carry a facility
    id. Best-effort and offline-safe: if the PeeringDB client can't be built or a
    lookup fails, the affected site is simply left unenriched."""
    fac_ids = {c: s["pdb_fac"] for c, s in sites.items() if s.get("pdb_fac")}
    if not fac_ids:
        return
    try:
        from .peeringdb import PeeringDBClient
        client = PeeringDBClient(api_key=_peeringdb_api_key())
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("PeeringDB enrichment skipped: %s", e)
        return
    for code, fac_id in fac_ids.items():
        meta = client.facility_meta(fac_id)
        if meta:
            sites[code].update(meta)


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
    cids = {}      # (dev, ifn) -> traced transport-circuit cid (netbox_cables reuses this)

    def _far_and_cid(iid):
        """One trace call → (far (dev, ifn) | None, first circuit cid on the path).
        Doing both here means netbox_cables never has to re-trace the same port."""
        tr = S.get("%s/dcim/interfaces/%d/trace/" % (api, iid), timeout=40).json()
        if not tr:
            return None, None
        cid = None
        for hop in tr:
            for side in (hop[0], hop[2]):
                for nd in side or []:
                    if cid is None and isinstance(nd.get("circuit"), dict):
                        cid = nd["circuit"]["cid"]
        far = tr[-1][2]
        node = far[0] if far else None
        if not node or "/dcim/interfaces/" not in (node.get("url") or ""):
            return None, cid
        fid = node.get("id")
        if fid not in id_iface:
            r = S.get("%s/dcim/interfaces/%d/" % (api, fid), timeout=40).json()
            id_iface[fid] = (r["device"]["name"], r["name"])
            # capture the far port's speed too: a transit router's physical member
            # ports (e.g. Juniper xe-0/0/13) are often untagged — only the LAG
            # bundle carries core_port — so they'd miss the tagged-query speed pass.
            if r.get("speed"):
                speeds[(r["device"]["name"], r["name"])] = r["speed"] * 1000
        return id_iface[fid], cid

    links, seen = {}, set()
    for dev, ifn, iid in ports:
        far, cid = _far_and_cid(iid)
        if cid:
            cids[(dev, ifn)] = cid
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
    return {"nodes": {n: {"ports": {}} for n in devs}, "links": links}, speeds, cids


def netbox_cables(topology, facts, cids, nb):
    """Inter-site transport cables from NetBox (source of truth): one cable per
    LEASED circuit (BiDi cores grouped by geom stem). Scoped to the inter-site
    links; each transport port's circuit cid was already captured during the
    topology trace (``cids``), so we group by leased stem here without re-tracing —
    each interface attributes to its OWN circuit (a passive-site chain like
    scl02->scl03 + sfo02->scl03 stays two segments). Geometry matches the atlas by
    CID tokens; map_exclude circuits are dropped; status from the circuit lifecycle
    (active->up, planned->planned, else down). A circuit whose traced port
    dead-ends at a passive site's termination (delivered span, onward span not
    yet patched) is still drawn, single-ended, as a planned segment."""
    hints = circ.circuit_hints(nb)
    bycid = {h["cid"]: h for h in hints}
    gc_hint = {h["geom_cid"]: h for h in hints}
    exclude = {c.cid for c in nb.circuits.circuits.filter(tag="map_exclude")}

    members = {}  # geom_cid -> {(dev, ifname): speed_bps}
    for l in topology.get("links", {}).values():
        ends = [(l["node1"], l["port1"], site_of(l["node1"])),
                (l["node2"], l["port2"], site_of(l["node2"]))]
        s1, s2 = ends[0][2], ends[1][2]
        if not s1 or not s2 or s1 == s2:
            continue  # inter-site transport only
        for dev, ifn, _s in ends:
            cid = cids.get((dev, ifn))
            if not cid or cid not in bycid or cid in exclude:
                continue
            gc = bycid[cid]["geom_cid"]
            spd = facts.get((dev, ifn)) or 100e9  # NetBox speed already in facts
            members.setdefault(gc, {})[(dev, ifn)] = spd

    # Stub spans: a core port whose trace reached a circuit but never a far
    # switch (the circuit terminates at a passive site, and the onward span
    # isn't patched yet — e.g. sfo01<->oak01 waiting on oak01<->fmt01). The
    # topology-link pass above can't see these, so add the port here and force
    # the cable to "planned": the fibre exists but carries nothing.
    stubs, linked = set(), set(members)
    for (dev, ifn), cid in sorted(cids.items()):
        h = bycid.get(cid)
        if not h or cid in exclude:
            continue
        gc = h["geom_cid"]
        if gc in linked or site_of(dev) not in (h["a_site"], h["z_site"]):
            continue
        members.setdefault(gc, {})[(dev, ifn)] = facts.get((dev, ifn)) or 100e9
        stubs.add(gc)

    cables = []
    for gc, mem in members.items():
        h = gc_hint[gc]
        a, z = h["a_site"], h["z_site"]
        if not (a and z):
            continue
        mlist = sorted(mem)
        cap = sum(s for (d, _i), s in mem.items() if site_of(d) == a) or (sum(mem.values()) / 2)
        st = h.get("status")
        status = "planned" if gc in stubs else (
            "up" if st == "active" else ("planned" if st == "planned" else "down"))
        cables.append({
            "key": ("nb", gc), "a_site": a, "z_site": z, "members": mlist,
            "member_speed": dict(mem),
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
    topology, facts, cids = netbox_topology(nb, S, api)  # capacity + circuit cids from NetBox
    cables = netbox_cables(topology, facts, cids, nb)
    sites_meta = load_sites(nb)
    enrich_peeringdb(sites_meta)
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
        # public PeeringDB metadata, when the site carries a facility id
        for k in PDB_SITE_FIELDS:
            if meta.get(k):
                sites_out[code][k] = meta[k]

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
        # members stay in rep's sorted order: the traffic feed's per-member array
        # index IS the map's strand index (frontend fans strands in this order)
        links_private[oid] = {
            "members": [{"host": traffic_host(m[0]), "ifname": m[1],
                         "speed_bps": int(c.get("member_speed", {}).get(m) or 0)} for m in rep],
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
        # stable member order: the traffic feed's per-member array index IS the
        # map's strand index (topology iteration order is not deterministic)
        member_ports = sorted(member_ports)
        cap = sum(port_speed_bps(facts, h, i) for h, i in member_ports)
        oid = str(uuid.uuid5(NS, generation + "|intra|" + site + "|" + da + "|" + db))
        cables_out.append({
            "id": oid, "scope": "intra", "a_site": site, "z_site": site,
            "a_device": da, "z_device": db, "capacity_bps": cap,
            "status": "up", "approximate": False, "members": len(member_ports),
            "path": [dc[da], dc[db]], "media": [], "drops": [],
        })
        links_private[oid] = {
            "members": [{"host": traffic_host(h), "ifname": i,
                         "speed_bps": int(port_speed_bps(facts, h, i))} for h, i in member_ports],
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


def _atomic_write_bytes(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def cache_logos(mapjson, out_dir):
    """Download PeeringDB operator logos and rewrite each site's ``logo`` to a
    local, portal-served path, so the browser never hotlinks peeringdb.com.

    Logos land in ``<out_dir>/logos/<sha256[:16]>.<ext>`` and the ``logo`` field
    becomes ``/statistics/map/logos/<name>`` (resolved against the portal origin
    by the frontend). Best-effort and offline-safe: any logo that can't be
    fetched, isn't a recognised image type, or exceeds the size cap is dropped
    from map.json entirely (the frontend then falls back to the bundled operator
    icon / monogram) rather than left as a third-party hotlink. Stale files from
    prior builds are pruned so the directory tracks the current generation."""
    import hashlib
    import logging
    log = logging.getLogger(__name__)

    sites = mapjson.get("sites", {})
    urls = sorted({
        s["logo"] for s in sites.values()
        if isinstance(s.get("logo"), str) and s["logo"].startswith(("http://", "https://"))
    })
    logos_dir = os.path.join(out_dir, "logos")
    mapping = {}  # source peeringdb URL -> served path
    keep = set()  # filenames for the current generation (for pruning)

    if urls:
        import requests
        sess = requests.Session()
        for url in urls:
            try:
                r = sess.get(url, timeout=15, stream=True)
                r.raise_for_status()
                ctype = r.headers.get("Content-Type", "").split(";")[0].strip().lower()
                ext = LOGO_CONTENT_TYPES.get(ctype)
                if not ext:
                    raise ValueError("unsupported content-type %r" % ctype)
                # read one byte past the cap so an oversize body is detected
                data = r.raw.read(LOGO_MAX_BYTES + 1, decode_content=True)
                if len(data) > LOGO_MAX_BYTES:
                    raise ValueError("logo exceeds %d bytes" % LOGO_MAX_BYTES)
                name = "%s.%s" % (hashlib.sha256(url.encode()).hexdigest()[:16], ext)
                _atomic_write_bytes(os.path.join(logos_dir, name), data)
                mapping[url] = LOGO_URL_PREFIX + name
                keep.add(name)
            except Exception as e:  # network/HTTP/type/size — never fatal to a build
                log.warning("logo cache failed for %s: %s", url, e)

    for s in sites.values():
        u = s.get("logo")
        if not isinstance(u, str):
            continue
        if u in mapping:
            s["logo"] = mapping[u]
        elif u.startswith(("http://", "https://")):
            s.pop("logo", None)  # fetch failed: drop rather than hotlink

    # prune logos from prior generations
    if os.path.isdir(logos_dir):
        for fn in os.listdir(logos_dir):
            if fn not in keep and not fn.endswith(".tmp"):
                try:
                    os.remove(os.path.join(logos_dir, fn))
                except OSError:
                    pass


def write_outputs(mapjson, linksjson, out_path, links_path):
    """Atomically write the public map + private links files. Operator logos are
    downloaded and rewritten to portal-served paths (see cache_logos) before the
    public map is materialised, so map.json never carries a peeringdb.com URL.

    Also derives + writes weathermap.json (the schematic view of the same
    graph, see weathermap.py) next to map.json — same generation, same cable
    ids, served by the same nginx location block. Returns the weathermap dict
    so the task summary can report its node/link counts."""
    from .weathermap import weathermap_from_map
    wm = weathermap_from_map(mapjson)
    cache_logos(mapjson, os.path.dirname(out_path))
    _atomic_write(out_path, mapjson)
    _atomic_write(os.path.join(os.path.dirname(out_path), "weathermap.json"), wm)
    _atomic_write(links_path, linksjson)
    return wm
