"""Juniper Junos hardware collector (PyEZ / NETCONF RPCs, read-only).

Chassis serial + EEPROM manufacture date from ``get-chassis-inventory
extensive``, transceivers from the inventory ("Xcvr N": serial, description)
joined with ``get-pic-detail`` (vendor name, vendor part number, wavelength,
media). Empty cages don't appear anywhere in Junos, so per-platform cage
layouts name them.

The MX150 is a fixed x86 appliance (vMX on an "Opus" chassis): its single AC
power supply and fans are built in and not field-replaceable, and Junos reports
no part numbers or serials for them, so they are recorded in facts only. Junos
exposes no transceiver date codes.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from .model import DeviceHardware, Part, Slot
from .util import title_vendor

logger = logging.getLogger("hwinv")

# Per-platform optic cages: {(fpc, pic): [(first_port, last_port, form_factor, ifd_prefix)]}.
# Bay names match the NetBox interface names (ge-0/0/10, xe-0/0/12, ...).
CAGE_LAYOUT: Dict[str, Dict[Tuple[int, int], List[Tuple[int, int, str, str]]]] = {
    "MX150": {(0, 0): [(10, 11, "SFP", "ge"), (12, 13, "SFP+", "xe")]},
}
FF_PREFIX = {"SFP": "ge", "SFP+": "xe", "SFP28": "et", "QSFP+": "et", "QSFP28": "et", "QSFP-DD": "et"}
CAGE_ALSO_ACCEPTS = {"SFP+": ["SFP"], "QSFP28": ["QSFP+"]}
FF_RE = re.compile(r"^(QSFP-DD|QSFP28|QSFP\+|QSFP|SFP28|SFP\+|SFP|XFP|CFP\d?)-?(.*)$", re.I)


# ── Connection ───────────────────────────────────────────────────────


def _management_host(nb_device: Any) -> str:
    ip = nb_device.primary_ip4 or nb_device.primary_ip6
    if ip:
        return str(ipaddress.ip_interface(ip.address).ip)
    return f"{nb_device.name}.sfmix.org"


def _connect(nb_device: Any, host: str) -> Any:
    """SSH key/agent first (how operators reach the MX150s); else discovery's password login."""
    from jnpr.junos import Device
    from jnpr.junos.exception import ConnectAuthError

    import discovery

    logging.getLogger("ncclient").setLevel(logging.WARNING)  # it logs every RPC body at INFO
    user = discovery._get_netconf_ssh_credentials()["username"]
    try:
        dev = Device(host=host, user=user, gather_facts=False)
        dev.open(auto_probe=10)
        return dev
    except ConnectAuthError:
        logger.info("%s: key auth refused, trying password", nb_device.name)

    class _Dev(discovery.JuniperJunOSDevice):
        management_host = host  # type: ignore[assignment]

    return _Dev(nb_device.name, nb_device)._junos_connect()


# ── Parsing helpers ──────────────────────────────────────────────────


def _t(el: Any, path: str) -> str:
    if el is None:
        return ""
    return (el.findtext(path) or "").strip()


def _juniper_date(s: str) -> Optional[date]:
    """Juniper ID-EEPROM manufacture-date: 'MM-DD-YYYY' ('00-00-0000' = unset)."""
    m = re.match(r"^(\d{2})-(\d{2})-(\d{4})$", s or "")
    if not m:
        return None
    try:
        return date(int(m.group(3)), int(m.group(1)), int(m.group(2)))
    except ValueError:
        return None


def _speed(media: Optional[str]) -> Optional[int]:
    m = re.match(r"^(\d+)G", media or "")
    if m:
        return int(m.group(1))
    return 1 if re.match(r"^1000BASE", media or "") else None


def _media(cable_type: str, desc_rest: str) -> Optional[str]:
    """'10GBASE LR' -> '10GBASE-LR'; else derive from inventory text ('10G-LR')."""
    if cable_type:
        return re.sub(r"\s+", "-", cable_type.strip()).upper()
    m = re.match(r"^(\d+)G-?(.+)$", desc_rest)
    return f"{m.group(1)}GBASE-{m.group(2)}".upper() if m else None


def _form_factor(desc: str, speed: Optional[int]) -> Tuple[Optional[str], str]:
    m = FF_RE.match(desc or "")
    if not m:
        return None, desc or ""
    ff = m.group(1).upper()
    if ff == "QSFP":
        ff = "QSFP28" if (speed or 0) >= 100 else "QSFP+"
    return ff, m.group(2)


def _cages(model: str, fpc: int, pic: int) -> Dict[int, Tuple[str, str]]:
    """port -> (form_factor, ifd_prefix) for the platform's known cages."""
    out: Dict[int, Tuple[str, str]] = {}
    for first, last, ff, prefix in CAGE_LAYOUT.get(model, {}).get((fpc, pic), []):
        for port in range(first, last + 1):
            out[port] = (ff, prefix)
    return out


# ── Collection ───────────────────────────────────────────────────────


def _pics(inv: Any) -> List[Tuple[int, int, Any]]:
    """(fpc, pic, element) for every PIC in the inventory, at any nesting depth."""
    out = []
    for fpc_el in inv.xpath(".//*[starts-with(normalize-space(name), 'FPC ')]"):
        fpc = int(_t(fpc_el, "name").split()[1])
        for pic_el in fpc_el.xpath(".//*[starts-with(normalize-space(name), 'PIC ')]"):
            out.append((fpc, int(_t(pic_el, "name").split()[1]), pic_el))
    return out


def _pic_ports(dev: Any, fpc: int, pic: int) -> Dict[int, Any]:
    try:
        detail = dev.rpc.get_pic_detail(fpc_slot=str(fpc), pic_slot=str(pic))
    except Exception as exc:  # optics detail is enrichment, inventory still has serials
        logger.warning("pic detail %s/%s failed: %s", fpc, pic, exc)
        return {}
    return {int(_t(p, "port-number")): p for p in detail.iter("port") if _t(p, "port-number").isdigit()}


def _transceiver_part(xcvr: Any, port: Any) -> Tuple[Part, Optional[str]]:
    desc = _t(xcvr, "description")
    media0 = _media(_t(port, "cable-type"), "")
    ff, rest = _form_factor(desc, _speed(media0))
    media = media0 or _media("", rest)
    wl = re.match(r"^(\d+)", _t(port, "wavelength"))
    inv_pn = _t(xcvr, "part-number")
    vendor = _t(port, "sfp-vendor-name")
    jnpr = inv_pn and inv_pn != "NON-JNPR"
    attrs = {"form_factor": ff, "media": media, "speed_gbps": _speed(media), "wavelength_nm": int(wl.group(1)) if wl else None}
    part = Part(
        manufacturer=title_vendor(vendor) if vendor else ("Juniper" if jnpr else "Unknown"),
        model=_t(port, "sfp-vendor-pno") or (inv_pn if jnpr else "") or desc or "unknown",
        serial=_t(xcvr, "serial-number") or None,
        description=" ".join(filter(None, [ff, media, f"(Juniper {inv_pn})" if jnpr else None])),
        attributes={k: v for k, v in attrs.items() if v is not None},
    )
    return part, ff


def _transceiver_slots(dev: Any, inv: Any, model: str) -> List[Slot]:
    slots: List[Slot] = []
    for fpc, pic, pic_el in _pics(inv):
        cages = _cages(model, fpc, pic)
        ports = _pic_ports(dev, fpc, pic)
        seen: Dict[int, Tuple[Part, Optional[str]]] = {}
        for x in pic_el.xpath("./*[starts-with(normalize-space(name), 'Xcvr ')]"):
            n = int(_t(x, "name").split()[1])
            seen[n] = _transceiver_part(x, ports.get(n))
        for n in sorted(set(cages) | set(seen)):
            part, optic_ff = seen.get(n, (None, None))
            cage_ff, prefix = cages.get(n) or (optic_ff, FF_PREFIX.get(optic_ff or "", "xe"))
            accepts: Dict[str, Any] = {"form_factor": cage_ff} if cage_ff else {}
            if cage_ff in CAGE_ALSO_ACCEPTS:
                accepts["also_accepts"] = CAGE_ALSO_ACCEPTS[cage_ff]
            slots.append(
                Slot(
                    bay=f"{prefix}-{fpc}/{pic}/{n}",
                    kind="transceiver",
                    part=part,
                    position=str(n),
                    label=f"{cage_ff} cage" if cage_ff else "",
                    accepts=accepts,
                )
            )
    return slots


def _facts(chassis: Any, sw: Any, re_info: Any, env: Any) -> Dict[str, Any]:
    re_el = re_info.find(".//route-engine")
    up = re_el.find("up-time") if re_el is not None else None
    cpu = chassis.xpath(".//*[normalize-space(name)='CPU']")
    mid = chassis.xpath("./chassis-module[normalize-space(name)='Midplane']")
    return {
        "model": _t(sw, ".//product-model") or _t(chassis, "description"),
        "junos": _t(sw, ".//junos-version"),
        "uptime_s": int(up.get("seconds")) if up is not None and up.get("seconds") else None,
        "re_model": _t(re_el, "model"),
        "memory": _t(re_el, "memory-installed-size").strip("()") or _t(re_el, "memory-dram-size"),
        "cpu": _t(cpu[0], "part-number") if cpu else None,
        "midplane_pn": _t(mid[0], "part-number") if mid else None,
        "clei": _t(chassis, "clei-code"),
        # Built-in (non-FRU on MX150): status only, no part numbers/serials reported.
        "environment": {
            _t(i, "name"): _t(i, "status")
            for i in env.iter("environment-item")
            if _t(i, "class") in ("Power", "Fans")
        },
    }


def collect(nb_device: Any) -> DeviceHardware:
    host = _management_host(nb_device)
    logger.info("%s: Junos NETCONF via %s", nb_device.name, host)
    dev = _connect(nb_device, host)
    try:
        inv = dev.rpc.get_chassis_inventory(extensive=True)
        sw = dev.rpc.get_software_information()
        re_info = dev.rpc.get_route_engine_information()
        env = dev.rpc.get_environment_information()
        chassis = inv.find("chassis")
        model = _t(chassis, "model-number") or _t(chassis, "description")
        hw = DeviceHardware(
            name=nb_device.name,
            serial=_t(chassis, "serial-number") or None,
            mfg_date=_juniper_date(_t(chassis, "i2c-information/manufacture-date")),
            facts=_facts(chassis, sw, re_info, env),
            authoritative_kinds=["transceiver"],
        )
        hw.slots = _transceiver_slots(dev, chassis, model)
    finally:
        dev.close()
    logger.info(
        "%s: %d slots (%d populated)", nb_device.name, len(hw.slots), sum(s.part is not None for s in hw.slots)
    )
    return hw
