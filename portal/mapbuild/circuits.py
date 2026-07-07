"""NetBox circuit geometry anchors for the map builder.

Per transport/dark-fibre circuit, this pulls the endpoints, provider, status,
and the geom-group key that clusters the duplex/BiDi cores riding one leased
fibre so they share a single mined geometry (the committed atlas is keyed on the
leased-circuit stem).

This is the NetBox-query half that both the offline KMZ miner (to anchor mining
on real endpoints) and this in-portal builder need. It lives here, in the
self-contained builder package; the offline miner imports it (see
network-map/ARCHITECTURE.md).
"""
import os
import re
import sys

import pynetbox


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
