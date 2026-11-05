"""Fleet hardware data for peering-gear: NetBox -> plain view-model dicts.

NetBox is the only source (scripts/hardware_inventory.py keeps it current).
The view model per device:

    {name, role, role_label, site, manufacturer, model, serial, mfg_date,
     donor, donated_on, netbox_url,
     slots: [{bay, kind, label, position, accepts,
              module: None | {manufacturer, model, description, serial, status,
                              profile, attributes, mfg_date, power_on_hours,
                              endurance_used_pct, donor, donated_on}}]}

Dates stay ISO strings here; analysis.py parses them. In DEBUG with
GEAR_USE_FIXTURES the same shape is read from gear/devmock/fleet.json.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import httpx
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

CACHE_KEY = "gear:fleet"
CACHE_TTL = 600
FIXTURE = Path(__file__).parent / "devmock" / "fleet.json"

ROLE_LABELS = {
    "peering_switch": "Peering switches & core routers",
    "edge-router": "Transit & edge routers",
    "vm-hypervisor": "Hypervisors",
}
ROLE_ORDER = list(ROLE_LABELS)


def roles() -> List[str]:
    return list(getattr(settings, "GEAR_DEVICE_ROLES", ROLE_ORDER))


def get_fleet(refresh: bool = False) -> List[Dict[str, Any]]:
    if getattr(settings, "GEAR_USE_FIXTURES", False):
        return json.loads(FIXTURE.read_text())
    if not refresh:
        cached = cache.get(CACHE_KEY)
        if cached is not None:
            return cached
    fleet = _fetch_from_netbox()
    cache.set(CACHE_KEY, fleet, CACHE_TTL)
    return fleet


def _get_all(path: str, params: List[tuple]) -> List[Dict[str, Any]]:
    base = settings.IXP_NETBOX_URL.rstrip("/")
    url = f"{base}/api/{path.strip('/')}/"
    out: List[Dict[str, Any]] = []
    first = True
    with httpx.Client(
        headers={"Authorization": f"Token {settings.IXP_NETBOX_TOKEN}", "Accept": "application/json"},
        timeout=30,
        follow_redirects=True,
    ) as client:
        while url:
            resp = client.get(url, params=(params + [("limit", "500")]) if first else None)
            resp.raise_for_status()
            body = resp.json()
            out.extend(body.get("results", []))
            url, first = body.get("next"), False
    return out


def _cf(obj: Dict[str, Any], key: str) -> Any:
    return (obj.get("custom_fields") or {}).get(key)


def _fetch_from_netbox() -> List[Dict[str, Any]]:
    devices = _get_all("dcim/devices", [("role", r) for r in roles()] + [("status", "active")])
    if not devices:
        return []
    ids = [("device_id", str(d["id"])) for d in devices]
    bays = _get_all("dcim/module-bays", ids)
    modules = _get_all("dcim/modules", ids)
    mt_ids = sorted({m["module_type"]["id"] for m in modules})
    mtypes = {}
    for i in range(0, len(mt_ids), 100):
        for mt in _get_all("dcim/module-types", [("id", str(x)) for x in mt_ids[i : i + 100]]):
            mtypes[mt["id"]] = mt
    mod_by_bay = {m["module_bay"]["id"]: m for m in modules}
    base = settings.IXP_NETBOX_URL.rstrip("/")

    by_dev: Dict[int, List[Dict[str, Any]]] = {}
    for b in bays:
        kind = _cf(b, "slot_kind")
        if not kind:
            continue  # bay not modeled by hardware discovery (e.g. patch-panel cassettes)
        m = mod_by_bay.get(b["id"])
        module = None
        if m:
            mt = mtypes.get(m["module_type"]["id"], m["module_type"])
            module = {
                "manufacturer": (mt.get("manufacturer") or {}).get("name", ""),
                "model": mt.get("model", ""),
                "description": mt.get("description", ""),
                "profile": (mt.get("profile") or {}).get("name"),
                "attributes": mt.get("attributes") or {},
                "serial": m.get("serial") or "",
                "status": (m.get("status") or {}).get("value", "active"),
                "mfg_date": _cf(m, "mfg_date"),
                "power_on_hours": _cf(m, "power_on_hours"),
                "endurance_used_pct": _cf(m, "endurance_used_pct"),
                "donor": _cf(m, "donor"),
                "donated_on": _cf(m, "donated_on"),
                "netbox_url": f"{base}/dcim/modules/{m['id']}/",
            }
        by_dev.setdefault(b["device"]["id"], []).append(
            {
                "bay": b["name"],
                "kind": kind,
                "label": b.get("label") or "",
                "position": b.get("position") or "",
                "accepts": _cf(b, "slot_accepts") or {},
                "module": module,
            }
        )

    fleet = []
    for d in devices:
        role = (d.get("role") or {}).get("slug", "")
        fleet.append(
            {
                "name": d["name"],
                "role": role,
                "site": (d.get("site") or {}).get("name", ""),
                "manufacturer": d["device_type"]["manufacturer"]["name"],
                "model": d["device_type"]["model"],
                "serial": d.get("serial") or "",
                "mfg_date": _cf(d, "mfg_date"),
                "hw_last_seen": _cf(d, "hw_last_seen"),
                "donor": _cf(d, "donor"),
                "donated_on": _cf(d, "donated_on"),
                "netbox_url": f"{base}/dcim/devices/{d['id']}/",
                "slots": by_dev.get(d["id"], []),
            }
        )
    return fleet
