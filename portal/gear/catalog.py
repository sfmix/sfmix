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

# Chassis model (prefix match) -> PSUs it runs on in steady state, for chassis
# with more PSU slots than power feeds; empty slots beyond this aren't a need.
# Unlisted chassis want every PSU slot filled.
PSU_STEADY_STATE: Dict[str, int] = {
    "7750 SR-1": 2,  # 3 slots, 2 feeds: a third PSU would sit unused
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


# Wishlist entries: what to buy for a group of compatible slots (keyed like
# analysis.wishlist() keys them). `fits` is the hard compatibility rule,
# `examples` are known-good part numbers -- anything matching `fits` is welcome.
WISHLIST = {
    "ddr4-rdimm": {
        "title": "DDR4 ECC registered DIMMs (RDIMM)",
        "fits": "288-pin DDR4 ECC Registered DIMMs, DDR4-2133 or faster (they run at the board's speed). "
                "Registered only: no LRDIMMs, no unbuffered/desktop sticks. 16 GB or larger per stick.",
        "examples": "Samsung M393A2K40BB1 (16 GB), Samsung M393A4K40BB1 / Micron MTA36ASF4G72PZ (32 GB), "
                    "or 64 GB RDIMMs for pve01.scl04",
    },
    "ddr4-sodimm": {
        "title": "DDR4 SO-DIMMs (laptop-size)",
        "fits": "260-pin DDR4 SO-DIMM, 2666 MT/s, 16 or 32 GB per stick.",
        "examples": "Samsung M471A2K43CB1 (16 GB, what's in there now), Samsung M471A4G43MB1 (32 GB)",
    },
    "ssd-2.5": {
        "title": "2.5\" SATA SSDs",
        "fits": "2.5-inch SATA SSDs (SAS also fits the DL360 bays), ideally data-center class with power-loss "
                "protection and ≥1 DWPD endurance; 1.92 TB or larger.",
        "examples": "Samsung PM893 / PM883, Micron 5400 PRO / 5300 PRO, Intel/Solidigm D3-S4510/S4520. "
                    "HPE Gen8/Gen9 SFF drive caddies (651687-001) are welcome too.",
    },
    "drive-3.5": {
        "title": "3.5\" drives (or 2.5\" SSDs on 3.5\" carriers)",
        "fits": "3.5-inch SATA or SAS hot-swap drives for the 12-bay Supermicro backplane. Enterprise "
                "HDDs, or SATA SSDs in 2.5→3.5\" adapters to retire spinning disk.",
        "examples": "Seagate Exos 7E/X-series, WD Ultrastar DC HC5xx (8 TB+), or enterprise SATA SSDs",
    },
}

# Who donated what, for the donor wall. Keys are the NetBox `donor` custom
# field value (or a pledge's credit name); everything here is optional.
DONORS: Dict[str, Dict[str, str]] = {
    "Internet Archive": {"url": "https://archive.org/"},
}


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


def psu_target(model: str, slots: int) -> int:
    """How many PSUs this chassis should run on (never more than it has slots)."""
    for prefix, n in PSU_STEADY_STATE.items():
        if (model or "").upper().startswith(prefix.upper()):
            return min(n, slots)
    return slots


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
