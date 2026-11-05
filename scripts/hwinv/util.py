"""Small parsing helpers shared by collectors."""

from __future__ import annotations

import re
from datetime import date
from typing import Optional

# Vendor strings as optics report them -> NetBox manufacturer display name.
VENDOR_NAMES = {
    "FLEXOPTIX": "Flexoptix",
    "FS": "FS",
    "FS.COM": "FS",
    "ARISTA NETWORKS": "Arista",
    "ARISTA": "Arista",
    "NOKIA": "Nokia",
    "JUNIPER": "Juniper",
    "JUNIPER NETWORKS": "Juniper",
    "FINISAR CORP.": "Finisar",
    "FINISAR CORP": "Finisar",
    "CISCO": "Cisco",
    "INTEL CORP": "Intel",
    "BRO FLEXOPTIX": "Flexoptix",  # Flexoptix optics coded for Brocade
    "OPNEXT,INC": "Opnext",
    "OPNEXT, INC": "Opnext",
    "METHODE ELEC.": "Methode",
    # Blank / placeholder vendor fields in the EEPROM.
    "OEM": "Generic",
    "UNDEFINED": "Generic",
    "": "Generic",
}


def title_vendor(raw: str) -> str:
    s = re.sub(r"\s+", " ", (raw or "").strip())
    return VENDOR_NAMES.get(s.upper(), s if not s.isupper() or len(s) <= 4 else s.title())


def parse_date(s: Optional[str]) -> Optional[date]:
    """ISO-ish 'YYYY-MM-DD' (also tolerates 'YYYY/MM/DD' and 'MM/DD/YYYY')."""
    if not s:
        return None
    s = s.strip()
    for pat, order in (
        (r"^(\d{4})[-/](\d{1,2})[-/](\d{1,2})", "ymd"),
        (r"^(\d{1,2})/(\d{1,2})/(\d{4})", "mdy"),
    ):
        m = re.match(pat, s)
        if m:
            a, b, c = (int(g) for g in m.groups())
            y, mo, d = (a, b, c) if order == "ymd" else (c, a, b)
            try:
                return date(y, mo, d)
            except ValueError:
                return None
    return None


def parse_yymmdd(s: Optional[str]) -> Optional[date]:
    """SFF date code: 'YYMMDD' (optionally followed by a lot code)."""
    m = re.match(r"^(\d{2})(\d{2})(\d{2})", (s or "").strip())
    if not m:
        return None
    yy, mm, dd = (int(g) for g in m.groups())
    try:
        return date(2000 + yy, mm, dd)
    except ValueError:
        return None
