"""Curated knowledge the hardware can't report about itself.

Upgrade suggestions here are *candidates* for admins to vet before asking
anyone for them -- keep entries short, generic where unsure, and edit freely.
Explicit asks live in NetBox as `planned` modules in empty bays.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

# CPU model regex -> launch year. Used to date servers whose DMI has no build date.
CPU_LAUNCH_YEAR = [
    (r"E5-26\d\d v3", 2014),
    (r"E5-26\d\d v4", 2016),
    (r"Atom C3\d{3}", 2017),
    (r"Xeon D-15\d\d", 2015),
    (r"Xeon D-21\d\d", 2018),
]

# Chassis model (prefix match) -> platform launch year, for hardware that can't
# report a build date (e.g. incoming servers recorded by hand).
PLATFORM_LAUNCH_YEAR = [
    ("ProLiant DL360 Gen9", 2014),
    ("ProLiant DL360 Gen10", 2017),
]

# Chassis model (prefix match) -> refresh candidates.
CHASSIS_SUCCESSORS: Dict[str, Dict[str, str]] = {
    "DCS-7280SR-48C6": {
        "why": "First-generation 7280R (Jericho) with 10G SFP+ access ports and only 6×100G uplinks.",
        "suggest": "Arista 7280R3-series, e.g. DCS-7280CR3-36S (already our standard) or DCS-7280SR3-48YC8 for 25G access.",
    },
    "SYS-E300": {
        "why": "Compact Atom/Xeon-D box: 4 DIMM slots, two 2.5\" SATA bays, no hot-swap, external power brick.",
        "suggest": "A 1U server with ECC RDIMM headroom, NVMe bays and redundant PSUs (any recent Xeon Scalable / EPYC 1U).",
    },
    "SYS-6029U": {
        "why": "Dual Haswell (2014) Xeons on DDR4-2133 with desktop-class 3.5\" drives.",
        "suggest": "A 2U dual-socket Xeon Scalable / EPYC server with NVMe or SAS SSD bays.",
    },
    "PIO-628U": {
        "why": "Dual Haswell (2014) Xeons on DDR4-2133 with desktop-class 3.5\" drives.",
        "suggest": "A 2U dual-socket Xeon Scalable / EPYC server with NVMe or SAS SSD bays.",
    },
    "MX150": {
        "why": "x86 vMX appliance with fixed PSU/fans and 10G SFP+ only.",
        "suggest": "A router with 100G ports and redundant PSUs (our cr1 Nokia 7750 SR-1 class).",
    },
}

# Drive models known to be desktop/consumer class (poor fit for 24×7 ZFS).
CONSUMER_DRIVES = [r"^ST\d+DM\d+", r"870 QVO", r"860 QVO", r"WD\d+EZ", r"^WDC WD\d+EZ"]

OPTIC_SUGGESTIONS = {
    "QSFP-DD": "400G-FR4/LR4 QSFP-DD (or 100G-LR4 QSFP28 — the cage takes both)",
    "QSFP28": "100GBASE-LR4 QSFP28",
    "QSFP+": "40GBASE-LR4 QSFP+",
    "SFP28": "25GBASE-LR SFP28",
    "SFP+": "10GBASE-LR SFP+",
    "SFP": "1000BASE-LX SFP",
}

SSD_SUGGESTION = "Enterprise SATA SSD rated ≥1 DWPD (e.g. Samsung PM893 or Micron 5400 PRO, 3.84 TB)"
HDD_SUGGESTION = "Enterprise 3.5\" drives (e.g. Seagate Exos / WD Ultrastar), or SSDs to retire spinning disk"


def cpu_year(model: str) -> Optional[int]:
    for pat, year in CPU_LAUNCH_YEAR:
        if re.search(pat, model or ""):
            return year
    return None


def platform_year(model: str) -> Optional[int]:
    for prefix, year in PLATFORM_LAUNCH_YEAR:
        if (model or "").startswith(prefix):
            return year
    return None


def chassis_successor(model: str) -> Optional[Dict[str, str]]:
    for prefix, info in CHASSIS_SUCCESSORS.items():
        if (model or "").upper().startswith(prefix.upper()):
            return info
    return None


def is_consumer_drive(model: str) -> bool:
    return any(re.search(p, model or "") for p in CONSUMER_DRIVES)


def memory_suggestion(accepts: Dict[str, Any], per_dimm_gb: Optional[int]) -> str:
    parts = []
    if per_dimm_gb:
        parts.append(f"up to {per_dimm_gb} GB")
    parts.append(accepts.get("class") or "DDR4")
    if accepts.get("ecc"):
        parts.append("ECC")
    if accepts.get("registered"):
        parts.append("RDIMM")
    elif accepts.get("form_factor"):
        parts.append(accepts["form_factor"])
    return " ".join(parts)
