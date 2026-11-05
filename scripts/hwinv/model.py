"""Normalized hardware-inventory contract shared by every collector.

A collector turns one live device into a ``DeviceHardware``: chassis facts plus
a flat list of ``Slot``s. Each slot becomes a NetBox module bay; a populated
slot also gets a module (module type = manufacturer + part number, with a
module-type profile and typed attributes). An empty slot is still reported --
empty bays are where donations could go, so they are first-class data.

Collectors must not talk to NetBox; ``netbox_sync`` owns all writes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional

# Slot kind -> NetBox module-type profile name. Profiles not built into NetBox
# (Transceiver, Mainboard, Line card) are created by netbox_sync.ensure_schema.
KIND_PROFILE: Dict[str, str] = {
    "psu": "Power supply",
    "fan": "Fan",
    "transceiver": "Transceiver",
    "memory": "Memory",
    "disk": "Hard disk",
    "cpu": "CPU",
    "mainboard": "Mainboard",
    "linecard": "Line card",
    "expansion": "Expansion card",
}
KINDS = tuple(KIND_PROFILE)


@dataclass
class Part:
    """A physical FRU seen in a slot."""

    manufacturer: str  # human name, e.g. "Arista", "Micron", "FLEXOPTIX"
    model: str  # part number; becomes the NetBox module type model
    serial: Optional[str] = None
    description: str = ""
    # Profile attributes, keyed per the profile schema (see netbox_sync.PROFILES),
    # e.g. memory: {"class": "DDR4", "size": 8, "data_rate": 2133, "ecc": True}.
    attributes: Dict[str, Any] = field(default_factory=dict)
    mfg_date: Optional[date] = None
    power_on_hours: Optional[int] = None
    endurance_used_pct: Optional[int] = None  # 0-100, drive's own life-used figure
    status: str = "active"  # NetBox module status: active | failed | offline


@dataclass
class Slot:
    bay: str  # NetBox module bay name: "PSU 1", "Fan Tray 2", "Et1/1", "P1-DIMMA1", "Bay 3", "CPU1"
    kind: str  # one of KINDS
    part: Optional[Part] = None  # None = empty slot
    position: Optional[str] = None  # bay position (NetBox module_bay.position)
    label: str = ""  # optional human label, e.g. "QSFP28 cage" / "3.5in SAS"
    # Free-form constraints describing what fits, used for upgrade suggestions:
    # e.g. {"form_factor": "QSFP28"} or {"class": "DDR4", "ecc": True, "registered": True}
    accepts: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeviceHardware:
    name: str  # NetBox device name
    serial: Optional[str] = None
    mfg_date: Optional[date] = None
    slots: List[Slot] = field(default_factory=list)
    # Informational only (logged, not written): uptime, OS version, etc.
    facts: Dict[str, Any] = field(default_factory=dict)
    # Bay kinds this collector fully enumerated. netbox_sync only removes stale
    # discovered modules for kinds listed here, so a collector that can't see
    # e.g. fans never wipes manually-entered fans.
    authoritative_kinds: List[str] = field(default_factory=list)
