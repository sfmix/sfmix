"""Nokia SR-OS hardware collector (NETCONF state tree, read-only <get>).

Chassis, power supplies, fan trays, line cards/MDAs (only when they are FRUs
distinct from the chassis -- on the fixed-form SR-1-24D the card, MDA and CPM
all share the chassis serial) and every transceiver cage, including empty ones.

SR-OS reports optic vendor only as an IEEE OUI (no vendor-name leaf), so the
manufacturer comes from a small OUI table; SFF compliance codes give the media.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from datetime import date
from typing import Any, Dict, List, Optional

from lxml import etree

from .model import DeviceHardware, Part, Slot
from .util import parse_date, title_vendor

logger = logging.getLogger("hwinv")

# Narrow subtree filters: the full card/port state trees are megabytes of stats.
_FILTERS = {
    "system": "<system><platform/><up-time/><version/></system>",
    "chassis": "<chassis/>",
    "card": (
        "<card><slot-number/><equipped-type/><hardware-data/>"
        "<mda><mda-slot/><equipped-type/><hardware-data/></mda></card>"
    ),
    "cpm": "<cpm><cpm-slot/><equipped-type/><memory-capacity/><flash/><hardware-data/></cpm>",
    "port": "<port><port-id/><port-class/><type/><transceiver/></port>",
}

# Optic vendor OUIs (SR-OS exposes vendor-oui, not the vendor-name string).
OPTIC_OUI = {
    "38:86:02": "FLEXOPTIX",
    "00:90:65": "Finisar",
    "00:17:6a": "Avago",
    "00:02:c9": "Mellanox",
    "00:1c:73": "Arista",
}

# SR-OS port/connector type -> cage form factor (what fits in the cage).
CAGE_FORM_FACTOR = {
    "qsfp-dd-connector": "QSFP-DD",
    "qsfp28-connector": "QSFP28",
    "qsfp-connector": "QSFP+",
    "osfp-connector": "OSFP",
    "10/100/gig-ethernet-sfp": "SFP",
    "gig-ethernet-sfp": "SFP",
    "10-gig-ethernet-sfp": "SFP+",
}
CAGE_ALSO_ACCEPTS = {"QSFP-DD": ["QSFP28", "QSFP+"], "QSFP28": ["QSFP+"], "SFP+": ["SFP"]}

# SFF-8024 extended specification compliance codes: (QSFP name, SFP name).
SFF_EXT_COMPLIANCE = {
    0x01: ("100G-AOC", "25G-AOC"),
    0x02: ("100GBASE-SR4", "25GBASE-SR"),
    0x03: ("100GBASE-LR4", "25GBASE-LR"),
    0x04: ("100GBASE-ER4", "25GBASE-ER"),
    0x05: ("100GBASE-SR10", None),
    0x06: ("100G-CWDM4", None),
    0x07: ("100G-PSM4", None),
    0x08: ("100G-ACC", "25G-ACC"),
    0x0B: ("100GBASE-CR4", "25GBASE-CR"),
    0x10: ("40GBASE-ER4", None),
    0x11: ("4x10GBASE-SR", None),
    0x12: ("40G-PSM4", None),
    0x16: (None, "10GBASE-T"),
    0x17: ("100G-CLR4", None),
    0x18: ("100G-AOC", "25G-AOC"),
    0x19: ("100G-ACC", "25G-ACC"),
    0x1A: ("100GE-DWDM2", None),
    0x20: ("100G-SWDM4", None),
    0x21: ("100G-BIDI", None),
    0x25: ("100GBASE-DR", None),
    0x26: ("100GBASE-FR1", None),
    0x27: ("100GBASE-LR1", None),
}
# SFF-8636 byte 131 (QSFP) bits.
QSFP_COMPLIANCE_BITS = {
    0x01: "40G-ACTIVE", 0x02: "40GBASE-LR4", 0x04: "40GBASE-SR4", 0x08: "40GBASE-CR4",
    0x10: "10GBASE-SR", 0x20: "10GBASE-LR", 0x40: "10GBASE-LRM",
}
# SFF-8472 byte 3 (10G) and byte 6 (1G) bits.
SFP_10G_BITS = {0x10: "10GBASE-SR", 0x20: "10GBASE-LR", 0x40: "10GBASE-LRM", 0x80: "10GBASE-ER"}
SFP_1G_BITS = {0x01: "1000BASE-SX", 0x02: "1000BASE-LX", 0x04: "1000BASE-CX", 0x08: "1000BASE-T"}

NOKIA_PN_RE = re.compile(r"^(3HE\d{5}[A-Z]{2})[A-Z]{2}\d{2}$")


# ── NETCONF ──────────────────────────────────────────────────────────


def _management_host(nb_device: Any) -> str:
    ip = nb_device.primary_ip4 or nb_device.primary_ip6
    if ip:
        return str(ipaddress.ip_interface(ip.address).ip)
    return f"{nb_device.name}.sfmix.org"


def _fetch_state(host: str) -> Dict[str, etree._Element]:
    """One NETCONF session, one <get> per subtree; returns {key: <state> element}."""
    from ncclient import manager

    from discovery import NOKIA_SROS_STATE_NS, _get_netconf_ssh_credentials

    logging.getLogger("ncclient").setLevel(logging.WARNING)  # it logs every RPC body at INFO
    # The nightly job uses the dedicated read-only NETCONF user `hwinv` (ECDSA
    # key; SR-OS takes no ed25519 user keys). The shared `oxidized` login has
    # no NETCONF access on SR-OS, so by hand it's your own netrc login.
    key_user = os.environ.get("HWINV_SROS_USER")
    if key_user:
        auth = {"username": key_user, "key_filename": os.path.expanduser(
            os.environ.get("HWINV_SROS_KEY", "~/.ssh/id_ecdsa"))}
    else:
        creds = _get_netconf_ssh_credentials()
        auth = {"username": creds["username"], "password": creds["password"]}
    out: Dict[str, etree._Element] = {}
    with manager.connect(
        host=host,
        port=830,
        **auth,
        hostkey_verify=False,
        allow_agent=False,
        look_for_keys=False,
        device_params={"name": "default"},
        timeout=120,
    ) as m:
        for key, inner in _FILTERS.items():
            flt = f'<state xmlns="{NOKIA_SROS_STATE_NS}">{inner}</state>'
            reply = m.get(filter=("subtree", flt))
            data = _strip_ns(etree.fromstring(reply.data_xml.encode()))
            state = data.find("state")
            out[key] = state if state is not None else etree.Element("state")
    return out


def _strip_ns(root: etree._Element) -> etree._Element:
    for el in root.iter():
        if isinstance(el.tag, str):
            el.tag = etree.QName(el).localname
    return root


def _t(el: Optional[etree._Element], path: str) -> str:
    if el is None:
        return ""
    return (el.findtext(path) or "").strip()


# ── Parsing helpers ──────────────────────────────────────────────────


def _mdy(s: str) -> Optional[date]:
    """SR-OS hardware-data manufacturing-date: 'MMDDYYYY'."""
    m = re.match(r"^(\d{2})(\d{2})(\d{4})$", s or "")
    if not m:
        return None
    try:
        return date(int(m.group(3)), int(m.group(1)), int(m.group(2)))
    except ValueError:
        return None


def _nokia_model(pn: str) -> str:
    """Ordering code without the ICS/revision suffix: 3HE16724AARA01 -> 3HE16724AA."""
    m = NOKIA_PN_RE.match(pn)
    return m.group(1) if m else pn


def _status(oper: str) -> str:
    if oper in ("in-service", "ok", ""):
        return "active"
    return "failed" if oper == "failed" else "offline"


def _hw_part(hw: etree._Element, description: str, attributes: Optional[Dict[str, Any]] = None) -> Optional[Part]:
    """Part from a <hardware-data> block, or None if nothing is equipped."""
    pn = _t(hw, "part-number")
    if not pn or _t(hw, "oper-state") == "empty":
        return None
    full = [pn]
    if _t(hw, "common-language-equipment-identifier"):
        full.append(f"CLEI {_t(hw, 'common-language-equipment-identifier')}")
    return Part(
        manufacturer="Nokia",
        model=_nokia_model(pn),
        serial=_t(hw, "serial-number") or None,
        description=f"{description} ({', '.join(full)})",
        attributes=attributes or {},
        mfg_date=_mdy(_t(hw, "manufacturing-date")),
        status=_status(_t(hw, "oper-state")),
    )


def _hex_bytes(s: str) -> List[int]:
    try:
        return [int(b, 16) for b in s.split(":") if b]
    except ValueError:
        return []


def _optic_form_factor(sff_type: str, media: Optional[str]) -> Optional[str]:
    t = sff_type.lower()
    if "qsfp-dd" in t:
        return "QSFP-DD"
    if "qsfp28" in t:
        return "QSFP28"
    if "qsfp" in t:
        return "QSFP+"
    if "osfp" in t:
        return "OSFP"
    if "cfp" in t:
        return "CFP"
    if "sfp" in t:
        if media and media.startswith("25G"):
            return "SFP28"
        if media and media.startswith("10G"):
            return "SFP+"
        return "SFP"
    return None


def _optic_media(sff_type: str, compliance: str, extension: str) -> Optional[str]:
    """Decode SFF compliance bytes (SFF-8636 for QSFP, SFF-8472 for SFP)."""
    qsfp = "qsfp" in sff_type.lower() or "cfp" in sff_type.lower()
    raw = _hex_bytes(compliance)
    if not raw:
        return None
    try:
        ext = int(extension) if extension else None
    except ValueError:
        ext = None
    if qsfp:
        if raw[0] & 0x80 and ext in SFF_EXT_COMPLIANCE:
            return SFF_EXT_COMPLIANCE[ext][0]
        return next((n for bit, n in QSFP_COMPLIANCE_BITS.items() if raw[0] & bit), None)
    if ext in SFF_EXT_COMPLIANCE and SFF_EXT_COMPLIANCE[ext][1]:
        return SFF_EXT_COMPLIANCE[ext][1]
    if raw and (n := next((n for bit, n in SFP_10G_BITS.items() if raw[0] & bit), None)):
        return n
    if len(raw) > 3:
        return next((n for bit, n in SFP_1G_BITS.items() if raw[3] & bit), None)
    return None


def _speed(media: Optional[str]) -> Optional[int]:
    m = re.match(r"^(?:(\d+)x)?(\d+)G", media or "")
    if not m:
        return 1 if (media or "").startswith("1000BASE") else None
    return int(m.group(2)) * int(m.group(1) or 1)


def _optic_vendor(oui: str, pn: str) -> str:
    if pn.startswith("3HE"):
        return "Nokia"
    return title_vendor(OPTIC_OUI.get(oui.lower(), "Unknown"))


# ── Slot builders ────────────────────────────────────────────────────


def _psu_slots(chassis: etree._Element) -> List[Slot]:
    psus = chassis.findall("power-supply")
    installed = [p for p in psus if _t(p, "equipped-type") not in ("", "none")]
    family = _t(installed[0], "equipped-type") if installed else None
    family_pn = _nokia_model(_t(installed[0], "hardware-data/part-number")) if installed else None
    slots = []
    for ps in psus:
        sid = _t(ps, "power-supply-id")
        etype = _t(ps, "equipped-type")
        dc = etype.startswith("dc")
        attrs = {"hot_swappable": True, "input_current": "DC" if dc else "AC", "input_voltage": 48 if dc else 120}
        part = None
        if etype not in ("", "none"):
            part = _hw_part(ps.find("hardware-data"), f"{etype} power supply", attrs)
            if part and (_t(ps, "input-status") not in ("ok", "") or _t(ps, "output-status") not in ("ok", "")):
                part.status = "failed"
        accepts = {k: v for k, v in (("family", family), ("part_number", family_pn)) if v}
        slots.append(Slot(bay=f"PS{sid}", kind="psu", part=part, position=sid, accepts=accepts))
    return slots


def _fan_slots(chassis: etree._Element) -> List[Slot]:
    slots = []
    for fan in chassis.findall("fan"):
        sid = _t(fan, "fan-slot")
        part = _hw_part(fan.find("hardware-data"), "Fan tray")
        if part and _t(fan, "state") not in ("ok", ""):
            part.status = "failed"
        slots.append(Slot(bay=f"Fan Tray {sid}", kind="fan", part=part, position=sid))
    return slots


def _card_slots(card_state: etree._Element, chassis_serial: Optional[str]) -> List[Slot]:
    """Cards/MDAs that are separate FRUs (serial differs from the chassis)."""
    slots = []
    for card in card_state.iter("card"):
        n = _t(card, "slot-number")
        units = [(f"Slot {n}", _t(card, "equipped-type"), card.find("hardware-data"), "IOM card")]
        units += [
            (f"MDA {n}/{_t(m, 'mda-slot')}", _t(m, "equipped-type"), m.find("hardware-data"), "MDA")
            for m in card.findall("mda")
        ]
        for bay, etype, hw, what in units:
            serial = _t(hw, "serial-number")
            if serial and serial == chassis_serial:
                continue  # integrated into the chassis, not a separate FRU
            if _t(hw, "field-replaceable-unit") == "false":
                continue
            part = _hw_part(hw, f"{what} {etype}".strip()) if etype not in ("", "none", "unassigned") else None
            slots.append(Slot(bay=bay, kind="linecard", part=part))
    return slots


def _transceiver_slot(port: etree._Element) -> Optional[Slot]:
    pid = _t(port, "port-id")
    cage_ff = CAGE_FORM_FACTOR.get(_t(port, "type"))
    xcvr = port.find("transceiver")
    if xcvr is None or cage_ff is None:
        return None
    accepts: Dict[str, Any] = {"form_factor": cage_ff}
    if cage_ff in CAGE_ALSO_ACCEPTS:
        accepts["also_accepts"] = CAGE_ALSO_ACCEPTS[cage_ff]
    part = None
    if _t(xcvr, "equipped") == "true":
        part = _transceiver_part(xcvr, cage_ff)
    position = pid.rsplit("/c", 1)[-1] if "/c" in pid else pid
    return Slot(bay=pid, kind="transceiver", part=part, position=position, label=f"{cage_ff} cage", accepts=accepts)


def _transceiver_part(xcvr: etree._Element, cage_ff: str) -> Part:
    sff_type = _t(xcvr, "type")
    pn = _t(xcvr, "vendor-part-number")
    media = _optic_media(sff_type, _t(xcvr, "optical-compliance"), _t(xcvr, "optical-compliance-extension"))
    ff = _optic_form_factor(sff_type, media) or cage_ff
    try:
        wl = int(float(_t(xcvr, "laser-wavelength") or 0)) or None
    except ValueError:
        wl = None
    attrs = {"form_factor": ff, "media": media, "speed_gbps": _speed(media), "wavelength_nm": wl}
    return Part(
        manufacturer=_optic_vendor(_t(xcvr, "vendor-oui"), pn),
        model=pn or "unknown",
        serial=_t(xcvr, "vendor-serial-number") or None,
        description=" ".join(filter(None, [ff, media, _t(xcvr, "connector-code").upper() or None])),
        attributes={k: v for k, v in attrs.items() if v is not None},
        mfg_date=parse_date(_t(xcvr, "vendor-manufacture-date")),
    )


def _port_sort_key(slot: Slot) -> List[Any]:
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"/c?", slot.bay)]


def _facts(state: Dict[str, etree._Element]) -> Dict[str, Any]:
    sysel = state["system"].find("system")
    cpm = state["cpm"].find("cpm")
    chassis_hw = state["chassis"].find("chassis/hardware-data")
    up = _t(sysel, "up-time")
    flashes = [
        {
            "id": _t(f, "flash-id"),
            "model": _t(f, "model-number"),
            "serial": _t(f, "serial-number"),
            "capacity_kb": _t(f, "capacity"),
        }
        for f in (cpm.findall("flash") if cpm is not None else [])
        if _t(f, "oper-state") == "ok"
    ]
    return {
        "platform": _t(sysel, "platform"),
        "sros": _t(sysel, "version/version-number"),
        "uptime_s": int(up) // 1000 if up.isdigit() else None,  # SR-OS reports ms
        "part_number": _t(chassis_hw, "part-number"),
        "clei": _t(chassis_hw, "common-language-equipment-identifier"),
        "base_mac": _t(chassis_hw, "base-mac-address"),
        "cpm": _t(cpm, "equipped-type"),
        "cpm_memory_mb": _t(cpm, "memory-capacity"),
        "cards": [
            f"{_t(c, 'slot-number')}:{_t(c, 'equipped-type')}"
            + "".join(f" mda{_t(m, 'mda-slot')}:{_t(m, 'equipped-type')}" for m in c.findall("mda"))
            for c in state["card"].iter("card")
        ],
        "internal_flash": flashes,
    }


# ── Entry point ──────────────────────────────────────────────────────


def collect(nb_device: Any) -> DeviceHardware:
    host = _management_host(nb_device)
    logger.info("%s: SR-OS NETCONF via %s", nb_device.name, host)
    state = _fetch_state(host)

    chassis = state["chassis"].find("chassis")
    chassis_hw = chassis.find("hardware-data") if chassis is not None else None
    hw = DeviceHardware(
        name=nb_device.name,
        serial=_t(chassis_hw, "serial-number") or None,
        mfg_date=_mdy(_t(chassis_hw, "manufacturing-date")),
        facts=_facts(state),
        authoritative_kinds=["psu", "fan", "transceiver"],
    )
    if chassis is not None:
        hw.slots += _psu_slots(chassis)
        hw.slots += _fan_slots(chassis)
    cards = _card_slots(state["card"], hw.serial)
    if cards:
        hw.slots += cards
        hw.authoritative_kinds.append("linecard")
    xcvrs = [s for s in map(_transceiver_slot, state["port"].iter("port")) if s is not None]
    hw.slots += sorted(xcvrs, key=_port_sort_key)
    logger.info(
        "%s: %d slots (%d populated)", nb_device.name, len(hw.slots), sum(s.part is not None for s in hw.slots)
    )
    return hw
