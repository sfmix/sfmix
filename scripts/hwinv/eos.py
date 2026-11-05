"""Arista EOS hardware collector (eAPI).

Chassis, PSUs, fan trays and every front-panel transceiver cage (including
empty ones) from ``show inventory``, enriched with media type / wavelength
(``show interfaces transceiver hardware``) and optic date codes parsed from the
raw IDPROM (``show idprom transceiver``).
"""

from __future__ import annotations

import logging
import re
from datetime import date
from typing import Any, Dict, Optional, Tuple

import pyeapi

from .model import DeviceHardware, Part, Slot
from .util import parse_date, parse_yymmdd, title_vendor

logger = logging.getLogger("hwinv")

# Front-panel cage layout per chassis model: list of (first, last, form_factor).
# Lets us name the form factor of EMPTY cages, which the IDPROM can't tell us.
CAGE_LAYOUT = {
    "DCS-7280SR-48C6": [(1, 48, "SFP+"), (49, 54, "QSFP28")],
    "DCS-7280CR3-36S": [(1, 34, "QSFP28"), (35, 36, "QSFP-DD")],
}

# SFF-8024 identifier byte -> form factor.
SFF_IDENTIFIER = {0x03: "SFP+", 0x0C: "QSFP", 0x0D: "QSFP+", 0x11: "QSFP28", 0x18: "QSFP-DD", 0x19: "OSFP", 0x1E: "QSFP+"}

PSU_WATTS_RE = re.compile(r"PWR-(\d{3,4})")


def _cage_form_factor(model: str, cage: int) -> Optional[str]:
    for first, last, ff in CAGE_LAYOUT.get(model, []):
        if first <= cage <= last:
            return ff
    return None


def _speed_from_media(media: str) -> Optional[int]:
    m = re.match(r"(\d+)(G|BASE)", media or "")
    if not m:
        return None
    n = int(m.group(1))
    return n if m.group(2) == "G" else max(1, n // 1000)  # "1000BASE-T" -> 1


def _idprom_facts(pages: Dict[str, Any]) -> Tuple[Optional[str], Optional[date]]:
    """(form_factor, date_code) from raw IDPROM pages.

    QSFP (SFF-8636) exposes upper page 0 where byte 0 is the identifier and
    bytes 84-89 are the YYMMDD date code; SFP (SFF-8472) A0h has the same
    offsets in its lower page. Try every page and keep the first that parses.
    """
    ff, dc = None, None
    for page in pages.values():
        regs = page.get("registers") or []
        if len(regs) < 92:
            continue
        ff = ff or SFF_IDENTIFIER.get(regs[0])
        if dc is None:
            dc = parse_yymmdd(bytes(regs[84:90]).decode("ascii", "replace"))
    return ff, dc


def collect(nb_device: Any) -> DeviceHardware:
    params = _eapi_params(nb_device.name)
    node = pyeapi.connect(**params)
    inv, ver, power, xhw = (
        r["result"]
        for r in node.enable(
            [
                "show inventory",
                "show version",
                "show system environment power",
                "show interfaces transceiver hardware",
            ]
        )
    )
    try:
        idprom = node.enable(["show idprom transceiver"])[0]["result"].get("interfaces", {})
    except Exception as exc:  # older EOS / odd optics: date codes are a bonus
        logger.warning("%s: idprom read failed: %s", nb_device.name, exc)
        idprom = {}

    sysinfo = inv.get("systemInformation", {})
    model = sysinfo.get("name", "")
    hw = DeviceHardware(
        name=nb_device.name,
        serial=sysinfo.get("serialNum") or ver.get("serialNumber"),
        mfg_date=parse_date(sysinfo.get("mfgDate")),
        facts={
            "model": ver.get("modelName"),
            "eos": ver.get("version"),
            "uptime_s": ver.get("uptime"),
            "mem_kb": ver.get("memTotal"),
            "hw_rev": sysinfo.get("hardwareRev"),
        },
        authoritative_kinds=["psu", "fan", "transceiver"],
    )

    # PSUs ----------------------------------------------------------------
    psu_env = power.get("powerSupplies", {})
    for slot_id, psu in sorted(inv.get("powerSupplySlots", {}).items(), key=lambda kv: int(kv[0])):
        name = psu.get("name", "")
        part = None
        if name and name != "Not Present":
            env = psu_env.get(slot_id, {})
            watts = env.get("capacity") or (int(m.group(1)) if (m := PSU_WATTS_RE.match(name)) else None)
            part = Part(
                manufacturer="Arista",
                model=name,
                serial=_clean_serial(psu.get("serialNum")),
                description=f"{int(watts)}W power supply" if watts else "Power supply",
                attributes={
                    "wattage": int(watts) if watts else None,
                    "hot_swappable": True,
                    "input_current": "DC" if "DC" in name else "AC",
                    "input_voltage": 120 if "DC" not in name else 48,
                },
                status="active" if env.get("state", "ok") == "ok" else "failed",
            )
        hw.slots.append(Slot(bay=f"PSU {slot_id}", kind="psu", part=part, position=slot_id))

    # Fan trays ----------------------------------------------------------
    for slot_id, fan in sorted(inv.get("fanTraySlots", {}).items(), key=lambda kv: int(kv[0])):
        name = fan.get("name", "")
        part = None
        if name and name != "Not Present":
            part = Part(
                manufacturer="Arista",
                model=name,
                serial=_clean_serial(fan.get("serialNum")),
                description=f"Fan tray ({fan.get('numFans', 1)} fan)",
            )
        hw.slots.append(Slot(bay=f"Fan Tray {slot_id}", kind="fan", part=part, position=slot_id))

    # Transceiver cages --------------------------------------------------
    xhw_ifaces = xhw.get("interfaces", {})
    for slot_id, x in sorted(inv.get("xcvrSlots", {}).items(), key=lambda kv: int(kv[0])):
        cage = int(slot_id)
        bay = f"Ethernet{cage}"
        # First lane's interface carries the module's media facts.
        lane = xhw_ifaces.get(f"{bay}/1") or xhw_ifaces.get(bay) or {}
        id_ff, date_code = _idprom_facts((idprom.get(bay) or {}).get("pages", {}))
        ff = _cage_form_factor(model, cage) or id_ff
        part = None
        if x.get("mfgName") not in (None, "", "Not Present"):
            media = lane.get("mediaType") or lane.get("detectedMediaType") or ""
            part = Part(
                manufacturer=title_vendor(x["mfgName"]),
                model=x.get("modelName", "").strip() or "unknown",
                serial=_clean_serial(x.get("serialNum")),
                description=" ".join(filter(None, [id_ff or ff, media])),
                attributes={
                    "form_factor": id_ff or ff,
                    "media": media or None,
                    "speed_gbps": _speed_from_media(media),
                    "wavelength_nm": int(round(lane["wavelength"])) if lane.get("wavelength") else None,
                },
                mfg_date=date_code,
            )
        hw.slots.append(
            Slot(
                bay=bay,
                kind="transceiver",
                part=part,
                position=slot_id,
                label=f"{ff} cage" if ff else "",
                accepts={"form_factor": ff} if ff else {},
            )
        )
    return hw


def _clean_serial(s: Optional[str]) -> Optional[str]:
    s = (s or "").strip()
    return None if s in ("", "N/A", "Not Specified") else s


def _eapi_params(host: str) -> Dict[str, Any]:
    from discovery import get_eapi_connection_parameters  # reuse netrc creds

    params = get_eapi_connection_parameters()
    params["host"] = host
    return params
