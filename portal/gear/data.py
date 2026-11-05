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

import fcntl
import json
import logging
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List

import httpx
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

CACHE_KEY = "gear:fleet"
# Hardware changes rarely and a cold NetBox fetch pages through ~1k bays and
# modules (~10 s), so pages always read a pre-built snapshot (stale-while-
# revalidate): a background thread per worker re-fetches every REFRESH_INTERVAL,
# one worker at a time via a file lock, and the snapshot never expires, so a
# NetBox outage just means slightly older data, never a slow page.
REFRESH_INTERVAL = 15 * 60
POLL_INTERVAL = 60
BACKOFF_MAX = 3600
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
    return get_snapshot(refresh)["fleet"]


def get_snapshot(refresh: bool = False) -> Dict[str, Any]:
    """{"fleet": [...], "fetched_at": epoch}. Never blocks on NetBox once warm."""
    if getattr(settings, "GEAR_USE_FIXTURES", False):
        return {"fleet": json.loads(FIXTURE.read_text()), "fetched_at": time.time()}
    if not refresh:
        snap = cache.get(CACHE_KEY)
        if snap is not None:
            return snap
    return _refresh()  # first boot (no snapshot yet) or explicit refresh


def _refresh() -> Dict[str, Any]:
    t0 = time.monotonic()
    snap = {"fleet": _fetch_from_netbox(), "fetched_at": time.time()}
    cache.set(CACHE_KEY, snap, None)  # never expires; replaced by the next refresh
    logger.info("peering-gear: refreshed %d devices from NetBox in %.1fs (pid=%d)",
                len(snap["fleet"]), time.monotonic() - t0, os.getpid())
    return snap


@contextmanager
def _lock():
    path = Path(getattr(settings, "NETBOX_CACHE_LOCK_FILE", "/tmp/.netbox_refresh.lock")).with_name(".gear_refresh.lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _is_stale() -> bool:
    snap = cache.get(CACHE_KEY)
    return snap is None or time.time() - snap.get("fetched_at", 0) >= REFRESH_INTERVAL


def _loop() -> None:
    failures = 0
    while True:
        delay = POLL_INTERVAL
        if _is_stale():
            with _lock() as mine:
                if mine and _is_stale():
                    try:
                        _refresh()
                        failures = 0
                    except Exception:
                        failures += 1
                        delay = min(30 * 2 ** (failures - 1), BACKOFF_MAX)
                        logger.exception("peering-gear: NetBox refresh failed (#%d); retry in %ds", failures, delay)
        time.sleep(delay)


def start_background_refresh() -> None:
    """Start the per-worker warmer (idempotent). Called from GearHostMiddleware."""
    if getattr(start_background_refresh, "_started", False):
        return
    start_background_refresh._started = True
    threading.Thread(target=_loop, name="gear-refresh", daemon=True).start()


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
    v = (obj.get("custom_fields") or {}).get(key)
    # Select-type custom fields come back as {"value": ..., "label": ...}.
    if isinstance(v, dict) and set(v) == {"value", "label"}:
        return v["value"]
    return v


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
