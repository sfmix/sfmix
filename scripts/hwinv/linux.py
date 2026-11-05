"""Linux server hardware collector (Proxmox hypervisors, over SSH as root).

Runs a self-contained Python script on the host (stdlib only) that returns
JSON: DMI (system, board, BIOS, CPUs, DIMM slots, PSUs), physical drive bays
(SES enclosure slots, else ATA ports, plus NVMe controllers) with the disk in
each, and per-disk SMART (power-on hours, endurance used). Empty DIMM slots and
empty bays are reported -- they are the donation opportunities.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from .model import DeviceHardware, Part, Slot
from .util import parse_date, title_vendor

logger = logging.getLogger("hwinv")

# The script that runs on the host; also installed as the PVE forced command.
REMOTE_SCRIPT = (Path(__file__).parent / "remote_linux_inventory.py").read_text()
# Jump host for reaching the hypervisors from outside the network; the nightly
# job runs inside it and sets HWINV_SSH_PROXY_JUMP= (empty) to go direct.
PROXY_JUMP = os.environ.get("HWINV_SSH_PROXY_JUMP", "shell.sfmix.org")

_JUNK = {"", "Not Specified", "To Be Filled By O.E.M.", "Default string", "Unknown", "NO DIMM", "None", "0123456789"}


def _v(d: Dict[str, str], k: str) -> Optional[str]:
    v = (d.get(k) or "").strip()
    return None if v in _JUNK else v


def run_remote(host: str, proxy_jump: Optional[str] = None) -> Dict[str, Any]:
    proxy_jump = PROXY_JUMP if proxy_jump is None else proxy_jump
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", "-o", "StrictHostKeyChecking=accept-new"]
    if proxy_jump:
        cmd += ["-o", f"ProxyJump={proxy_jump}"]
    # With the nightly job's key the host's forced command runs the same
    # script and ignores this command line + stdin.
    cmd += [f"root@{host}", "python3", "-"]
    res = subprocess.run(cmd, input=REMOTE_SCRIPT, capture_output=True, text=True, timeout=300)
    if res.returncode != 0:
        raise RuntimeError(f"{host}: remote inventory failed: {res.stderr.strip()[-400:]}")
    return json.loads(res.stdout)


def collect(nb_device: Any, host: Optional[str] = None) -> DeviceHardware:
    data = run_remote(host or f"{nb_device.name}.sfmix.org")
    return parse(nb_device.name, data)


def parse(name: str, data: Dict[str, Any]) -> DeviceHardware:
    system = (data.get("system") or [{}])[0]
    board = (data.get("board") or [{}])[0]
    bios = (data.get("bios") or [{}])[0]
    chassis = (data.get("chassis") or [{}])[0]
    hw = DeviceHardware(
        name=name,
        # The chassis (DMI type 3) serial is the one on the sticker; Supermicro's
        # system (type 1) serial is a separate build number.
        serial=_v(chassis, "Serial Number") or _v(system, "Serial Number"),
        mfg_date=None,  # Supermicro DMI carries no build date
        facts={
            "system_vendor": _v(system, "Manufacturer"),
            "system_model": _v(system, "Product Name"),
            "pve": data.get("pve"),
            "uptime_s": data.get("uptime_s"),
        },
        authoritative_kinds=["mainboard", "cpu", "memory", "disk", "psu"],
    )

    # Mainboard -----------------------------------------------------------
    mem_arrays = data.get("mem_array") or []
    max_mem_gb = sum(_size_gb(_v(a, "Maximum Capacity")) or 0 for a in mem_arrays) or None
    dimm_slots = len(data.get("mem") or [])
    if _v(board, "Product Name"):
        hw.slots.append(
            Slot(
                bay="Mainboard",
                kind="mainboard",
                part=Part(
                    manufacturer=title_vendor(_v(board, "Manufacturer") or "Unknown"),
                    model=_v(board, "Product Name"),
                    serial=_v(board, "Serial Number"),
                    description=f"{_v(board, 'Manufacturer') or ''} {_v(board, 'Product Name')} mainboard".strip(),
                    attributes={
                        "dimm_slots": dimm_slots or None,
                        "max_memory_gb": max_mem_gb,
                        "bios_version": _v(bios, "Version"),
                        "bios_date": str(parse_date(_v(bios, "Release Date")) or "") or None,
                    },
                ),
            )
        )

    # CPUs ----------------------------------------------------------------
    for cpu in data.get("cpu") or []:
        sock = _v(cpu, "Socket Designation") or "CPU"
        populated = "Populated" in (cpu.get("Status") or "")
        part = None
        if populated:
            ver = re.sub(r"\s+", " ", _v(cpu, "Version") or "unknown CPU")
            ver = re.sub(r"\(R\)|\(TM\)|\bCPU\b", "", ver).replace("  ", " ").strip()
            ghz = re.search(r"@\s*([\d.]+)\s*GHz", ver)
            part = Part(
                manufacturer=title_vendor(_v(cpu, "Manufacturer") or "Intel").replace("Intel(R) Corporation", "Intel"),
                model=re.sub(r"\s*@.*$", "", ver).strip(),
                description=ver,
                attributes={
                    "cores": int(_v(cpu, "Core Count") or 0) or None,
                    "speed": float(ghz.group(1)) if ghz else None,
                    "architecture": "x86_64",
                },
            )
        hw.slots.append(Slot(bay=sock, kind="cpu", part=part))

    # Memory --------------------------------------------------------------
    ecc = any("ECC" in (a.get("Error Correction Type") or "") for a in mem_arrays)
    mem_class = None
    registered = None
    dimm_ff = None
    for dimm in data.get("mem") or []:
        loc = _v(dimm, "Locator") or "DIMM"
        size_gb = _size_gb(dimm.get("Size"))
        mem_class = mem_class or _v(dimm, "Type")
        dimm_ff = dimm_ff or _v(dimm, "Form Factor")
        if _is_rdimm(dimm):
            registered = True
        part = None
        if size_gb:
            rate = re.match(r"(\d+)", dimm.get("Speed") or "")
            pn = (_v(dimm, "Part Number") or "").strip() or f"{size_gb}GB {_v(dimm, 'Type') or ''}".strip()
            part = Part(
                manufacturer=title_vendor(_v(dimm, "Manufacturer") or "Unknown"),
                model=pn,
                serial=_v(dimm, "Serial Number"),
                description=" ".join(
                    filter(None, [f"{size_gb}GB", _v(dimm, "Type"), "RDIMM" if _is_rdimm(dimm) else _v(dimm, "Form Factor"), f"{rate.group(1)} MT/s" if rate else None])
                ),
                attributes={
                    "class": _v(dimm, "Type"),
                    "size": size_gb,
                    "data_rate": int(rate.group(1)) if rate else None,
                    "ecc": ecc,
                },
            )
        hw.slots.append(Slot(bay=loc, kind="memory", part=part))
    for s in hw.slots:
        if s.kind == "memory":
            s.accepts = {k: v for k, v in {"class": mem_class, "form_factor": dimm_ff, "ecc": ecc, "registered": registered}.items() if v is not None}

    # PSUs (only where the platform reports real, present supplies) --------
    for psu in data.get("psu") or []:
        loc = _v(psu, "Location")
        present = "Present" in (psu.get("Status") or "") and "Not Present" not in (psu.get("Status") or "")
        if not loc or (not present and not _v(psu, "Model Part Number")):
            continue  # boards that report PSU records for supplies they don't have
        watts = re.match(r"(\d+)", psu.get("Max Power Capacity") or "")
        part = None
        if present and _v(psu, "Model Part Number"):
            part = Part(
                manufacturer=title_vendor(_v(psu, "Manufacturer") or hw.facts.get("system_vendor") or "Unknown"),
                model=_v(psu, "Model Part Number"),
                serial=_v(psu, "Serial Number"),
                description=f"{watts.group(1)}W power supply" if watts else "Power supply",
                attributes={
                    "wattage": int(watts.group(1)) if watts else None,
                    "hot_swappable": psu.get("Hot Replaceable", "Yes") == "Yes",
                    "input_current": "AC",
                    "input_voltage": 120,
                },
                status="failed" if "Critical" in (psu.get("Status") or "") else "active",
            )
        hw.slots.append(Slot(bay=loc, kind="psu", part=part))

    # Drives --------------------------------------------------------------
    disks = data.get("disks") or {}
    smart = data.get("smart") or {}
    for bay in data.get("bays") or []:
        dname = bay.get("disk")
        part = _disk_part(disks.get(dname, {}), smart.get(dname, {})) if dname else None
        hw.slots.append(Slot(bay=bay["bay"], kind="disk", part=part, label=bay.get("bus", ""), accepts={"bus": bay.get("bus")}))
    return hw


# Supermicro BIOSes often report only "Type Detail: Synchronous", so also
# recognise registered DIMMs by part number (Micron ...PDZ/PZ, Samsung M393/M392,
# SK Hynix HMA/HMAA...R, Kingston KSM...R).
_RDIMM_PN = re.compile(r"^(?:\d+ASF\w*P[DZ]|MTA\w*P[DZ]|M39[23]|HMA{1,2}\w*R|KSM\w*R)", re.I)


def _is_rdimm(dimm: Dict[str, str]) -> bool:
    return "Registered" in (dimm.get("Type Detail") or "") or bool(_RDIMM_PN.match((dimm.get("Part Number") or "").strip()))


def _size_gb(s: Optional[str]) -> Optional[int]:
    m = re.match(r"\s*(\d+)\s*([MGT]B)", s or "")
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    return {"MB": n // 1024, "GB": n, "TB": n * 1024}[unit] or None


def _disk_part(blk: Dict[str, Any], sm: Dict[str, Any]) -> Part:
    model = (sm.get("model_name") or blk.get("model") or "unknown disk").strip()
    vendor = model.split()[0] if " " in model else (blk.get("vendor") or "").strip()
    vendor = {"ST": "Seagate", "WDC": "Western Digital", "Samsung": "Samsung"}.get(vendor, vendor)
    if model.startswith("ST") and not vendor:
        vendor = "Seagate"
    if re.match(r"ST\d", model):
        vendor = "Seagate"
    size_bytes = (sm.get("user_capacity") or {}).get("bytes") or int(blk.get("size") or 0)
    rpm = sm.get("rotation_rate")
    nvme = "nvme_smart_health_information_log" in sm or (blk.get("tran") == "nvme")
    dtype = "NVME" if nvme else ("SSD" if rpm == 0 or str(blk.get("rota")) in ("0", "False", "false") else "HD")
    poh = (sm.get("power_on_time") or {}).get("hours")
    ff = (sm.get("form_factor") or {}).get("name")
    status = "active"
    if sm.get("smart_status", {}).get("passed") is False:
        status = "failed"
    return Part(
        manufacturer=title_vendor(vendor or "Unknown"),
        model=model,
        serial=(sm.get("serial_number") or blk.get("serial") or "").strip() or None,
        description=" ".join(filter(None, [_human_size(size_bytes), dtype, ff, f"{rpm} rpm" if rpm else None])),
        attributes={
            "size": int(size_bytes / 1e9) if size_bytes else None,
            "type": dtype,
            "speed": rpm or None,
        },
        power_on_hours=int(poh) if poh is not None else None,
        endurance_used_pct=_endurance_used(sm),
        status=status,
    )


def _endurance_used(sm: Dict[str, Any]) -> Optional[int]:
    nv = sm.get("nvme_smart_health_information_log") or {}
    if "percentage_used" in nv:
        return int(nv["percentage_used"])
    # ATA device statistics page 7: "Percentage Used Endurance Indicator"
    for page in (sm.get("ata_device_statistics") or {}).get("pages", []):
        for t in page.get("table", []):
            if "Percentage Used Endurance" in t.get("name", "") and "value" in t:
                return int(t["value"])
    # Vendor wear attributes (normalized value counts down from 100).
    for a in (sm.get("ata_smart_attributes") or {}).get("table", []):
        if a.get("id") in (177, 231, 233) and a.get("name", "").lower().startswith(("wear", "ssd_life", "media_wearout")):
            return max(0, 100 - int(a.get("value", 100)))
    return None


def _human_size(b: int) -> str:
    if not b:
        return ""
    tb = b / 1e12
    return f"{tb:.0f}TB" if tb >= 1 else f"{b / 1e9:.0f}GB"
