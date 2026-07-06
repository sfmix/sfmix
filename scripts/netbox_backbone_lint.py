#!/usr/bin/env python3
import os
import re
import sys
import netrc
from typing import Dict, List, Optional, Set, Tuple

import requests
import pynetbox
import yaml
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
Cross-check the live inter-site backbone topology against NetBox.

Ground truth is the switches' own LLDP: every link between two `peering_switch`
devices that sit in *different* sites is a backbone transport link and MUST
resolve to a complete end-to-end path in NetBox -- either a single cabled
transport circuit whose trace reaches the far switch interface, or a chain of
circuits meeting at a passive splice site (e.g. a dark-fibre span + a carrier
wave handing off in a passive building).

This catches the gaps NetBox can't see on its own: a physical link that exists
on the wire but whose circuit is un-cabled, half-cabled, mis-cabled, or missing.
"""

EAPI_NETRC_HOST = "sfmix.org"


def url_strip_api(api_url: str) -> str:
    return re.sub(r"/api", "", api_url)


def eapi_credentials() -> Tuple[str, str]:
    # Same source discovery.py uses for eAPI: the `sfmix.org` netrc entry.
    auth_info = netrc.netrc().authenticators(EAPI_NETRC_HOST)
    if not auth_info:
        raise ValueError(f"No netrc entry for {EAPI_NETRC_HOST!r} (needed for eAPI)")
    username, _, password = auth_info
    if not (username and password):
        raise ValueError(f"Incomplete eAPI credentials in netrc for {EAPI_NETRC_HOST!r}")
    return username, password


def eapi_run(host: str, cmds: List[str], user: str, pw: str, timeout: int = 25):
    body = {
        "jsonrpc": "2.0",
        "method": "runCmds",
        "params": {"version": 1, "cmds": cmds, "format": "json"},
        "id": 1,
    }
    r = requests.post(
        f"https://{host}/command-api", json=body, auth=(user, pw), verify=False, timeout=timeout
    )
    r.raise_for_status()
    return r.json()["result"]


def _node_kind_id(node: dict) -> Tuple[Optional[str], Optional[int]]:
    """('interfaces'|'sites'|..., id) for a trace endpoint node."""
    url = node.get("url", "")
    if "/api/" not in url:
        return None, node.get("id")
    parts = url.split("/api/", 1)[1].strip("/").split("/")
    # parts like ['dcim','interfaces','123'] or ['circuits','circuit-terminations','5']
    kind = parts[1] if len(parts) > 1 else parts[0]
    return kind, node.get("id")


def analyze_trace(trace: list) -> Tuple[Set[str], Optional[str], Optional[int]]:
    """Return (circuit CIDs traversed, far-endpoint kind, far-endpoint id)."""
    if not trace:
        return set(), "uncabled", None
    circuits: Set[str] = set()
    for hop in trace:
        for side in (hop[0], hop[2]):
            for node in side or []:
                if isinstance(node.get("circuit"), dict):
                    circuits.add(node["circuit"]["cid"])
    far = trace[-1][2]
    far_node = far[0] if far else None
    if not far_node:
        return circuits, "deadend", None
    kind, fid = _node_kind_id(far_node)
    return circuits, kind, fid


def check_backbone_transport_paths(
    netbox: pynetbox.api, api_endpoint: str, token: str
) -> int:
    print(
        "[!!] Checking that every inter-site backbone link (LLDP) has an "
        "end-to-end NetBox path"
    )
    user, pw = eapi_credentials()
    sess = requests.Session()
    sess.headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
    base = api_endpoint.rstrip("/")

    # Circuits explicitly marked out-of-scope for the map (tag `map_exclude`);
    # a backbone link that rides one of these is reported as excluded, not a gap.
    exclude_cids: Set[str] = {
        c.cid for c in netbox.circuits.circuits.filter(tag="map_exclude")
    }

    # 1) peering switches: name -> site slug
    devs: Dict[str, str] = {}
    for d in netbox.dcim.devices.filter(role="peering_switch", status="active"):
        devs[d.name] = d.site.slug

    # 2) live LLDP -> inter-site links (both ends peering switches, different sites)
    links: Dict[frozenset, None] = {}
    unreachable: List[str] = []
    for name in sorted(devs):
        try:
            res = eapi_run(f"{name}.sfmix.org", ["show lldp neighbors detail"], user, pw)[0]
        except Exception:
            unreachable.append(name)
            continue
        for ifn, entry in res.get("lldpNeighbors", {}).items():
            for n in entry.get("lldpNeighborInfo", []):
                far = n.get("systemName", "").replace(".sfmix.org", "")
                fifn = n.get("neighborInterfaceInfo", {}).get("interfaceId", "").strip('"')
                if far in devs and devs[far] != devs[name]:
                    links[frozenset([(name, ifn), (far, fifn)])] = None
    if unreachable:
        print(f"     (note: no eAPI/LLDP from {', '.join(unreachable)} -- skipped)")

    # 3) trace each link in NetBox and classify
    ifid_cache: Dict[Tuple[str, str], Optional[int]] = {}

    def ifid(dev: str, ifn: str) -> Optional[int]:
        key = (dev, ifn)
        if key not in ifid_cache:
            got = netbox.dcim.interfaces.filter(device=dev, name=ifn)
            got = list(got)
            ifid_cache[key] = got[0].id if got else None
        return ifid_cache[key]

    def trace(ifid_: int) -> list:
        r = sess.get(f"{base}/api/dcim/interfaces/{ifid_}/trace/", timeout=40)
        r.raise_for_status()
        return r.json()

    full = chained = excluded = 0
    findings: List[str] = []
    for lk in links:
        (da, ia), (db, ib) = sorted(lk)
        id_a, id_b = ifid(da, ia), ifid(db, ib)
        if not id_a or not id_b:
            findings.append(
                f"{da} {ia} <-> {db} {ib}: interface missing in NetBox"
            )
            continue
        ca, ka, fa = analyze_trace(trace(id_a))
        cb, kb, fb = analyze_trace(trace(id_b))
        if (ca | cb) & exclude_cids:
            excluded += 1  # rides a map_exclude circuit -> intentionally out-of-scope
            continue
        if ka == "interfaces" and fa == id_b:
            full += 1  # single circuit, cabled both ends, traces end-to-end
        elif ka == "sites" and kb == "sites" and fa == fb and ca and cb:
            chained += 1  # circuits chain at a passive splice site
        else:
            if not ca and not cb:
                why = "no NetBox circuit on either end (unmodelled / excluded)"
            elif ca == cb:
                why = f"circuit {'/'.join(sorted(ca))} not cabled end-to-end (a:{ka} b:{kb})"
            else:
                why = f"a:[{'/'.join(sorted(ca)) or '-'} ->{ka}] b:[{'/'.join(sorted(cb)) or '-'} ->{kb}]"
            findings.append(f"{da} {ia} <-> {db} {ib}: {why}")

    for f in sorted(findings):
        print("  INCOMPLETE backbone path:", f)
    print(
        f"     summary: {full} full + {chained} chained end-to-end, "
        f"{excluded} excluded (map-out-of-scope), "
        f"{len(findings)} incomplete (of {len(links)} inter-site links)"
    )
    return len(findings)


def netbox_client(operator_config) -> pynetbox.core.api.Api:
    return pynetbox.api(
        operator_config["netbox_api_endpoint"], token=operator_config["netbox_api_key"]
    )


def netbox_lint(operator_config: Dict[str, str]) -> int:
    netbox = netbox_client(operator_config)
    return check_backbone_transport_paths(
        netbox=netbox,
        api_endpoint=operator_config["netbox_api_endpoint"],
        token=operator_config["netbox_api_key"],
    )


if __name__ == "__main__":
    if not (OPERATOR_CONFIG_FILE := os.environ.get("SFMIX_OPERATOR_CONFIG_FILE")):
        OPERATOR_CONFIG_FILE = "/opt/sfmix/operator_config.yaml"
    with open(OPERATOR_CONFIG_FILE) as f:
        operator_config = yaml.safe_load(f)
    for required_config in ["netbox_api_endpoint", "netbox_api_key"]:
        if not operator_config.get(required_config):
            sys.exit(f"No {required_config} in {OPERATOR_CONFIG_FILE}")

    incomplete = netbox_lint(operator_config=operator_config)
    # Non-zero exit if any backbone link lacks an end-to-end NetBox path,
    # so this can gate CI / a pre-deploy check.
    sys.exit(1 if incomplete else 0)
