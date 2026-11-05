#!/usr/bin/env python3
"""SFMIX hardware inventory, run ON a Linux server; prints one JSON document.

Shipped two ways from this one file: piped over SSH by hwinv/linux.py
(`ssh root@host python3 -`), and installed on the Proxmox hosts as
/usr/local/sbin/sfmix-hw-inventory -- the forced command of the nightly
job's SSH key (ansible role hardware_inventory). Read-only; stdlib only.
"""
import glob
import json
import os
import re
import subprocess


def sh(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout
    except Exception:
        return ""


def dmi(t):
    """Parse `dmidecode -t T` into a list of {key: value} dicts."""
    out, cur = [], None
    for line in sh("dmidecode", "-t", str(t)).splitlines():
        if line.startswith("Handle "):
            cur = {}
            out.append(cur)
        elif cur is not None and line.startswith("\t") and not line.startswith("\t\t") and ":" in line:
            k, v = line.strip().split(":", 1)
            cur[k.strip()] = v.strip()
    return [d for d in out if d]


def rd(p):
    try:
        return open(p).read().strip()
    except Exception:
        return ""


def disk_by_name():
    lj = json.loads(sh("lsblk", "-J", "-d", "-b", "-o", "NAME,MODEL,SERIAL,SIZE,ROTA,TRAN,TYPE,VENDOR") or "{}")
    return {d["name"]: d for d in lj.get("blockdevices", []) if d.get("type") == "disk" and not d["name"].startswith(("zd", "loop", "sr"))}


def main():
    disks = disk_by_name()
    bays = []
    seen = set()
    # 1) SES enclosures: every slot, populated or not.
    for slot in sorted(glob.glob("/sys/class/enclosure/*/*")):
        if not os.path.isdir(slot) or not os.path.exists(os.path.join(slot, "slot")) and not re.search(r"[Ss]lot", os.path.basename(slot)):
            continue
        blk = glob.glob(os.path.join(slot, "device/block/*"))
        name = os.path.basename(blk[0]) if blk else None
        bays.append({"bay": "Drive Bay " + str(int(re.sub(r"\D", "", os.path.basename(slot)) or 0)), "disk": name, "bus": "SES"})
        if name:
            seen.add(name)
    # 2) ATA ports: one bay per port; a port with no device is an empty bay.
    for port in sorted(glob.glob("/sys/class/ata_port/ata*"), key=lambda p: int(re.sub(r"\D", "", p) or 0)):
        n = os.path.basename(port)[3:]
        devs = [d for d in disks if re.search(r"/ata%s/" % n, os.path.realpath("/sys/block/" + d))]
        devs = [d for d in devs if d not in seen]
        if not devs and glob.glob("/sys/class/enclosure/*"):
            continue  # host has SES bays; bare ATA ports here are onboard extras
        bays.append({"bay": "SATA " + n, "disk": devs[0] if devs else None, "bus": "ATA"})
        seen.update(devs)
    # 3) NVMe controllers.
    for ctrl in sorted(glob.glob("/sys/class/nvme/nvme*")):
        ns = sorted(os.path.basename(p) for p in glob.glob(ctrl + "/nvme*n*") if re.match(r"nvme\d+n\d+$", os.path.basename(p)))
        bays.append({"bay": "NVMe " + os.path.basename(ctrl)[4:], "disk": ns[0] if ns else None, "bus": "NVMe"})
        seen.update(ns)
    # 4) Anything left over (USB/boot SATA DOM etc.).
    for d in disks:
        if d not in seen:
            bays.append({"bay": "Disk " + d, "disk": d, "bus": disks[d].get("tran") or "?"})

    smart = {}
    for d in disks:
        try:
            smart[d] = json.loads(sh("smartctl", "--json", "-x", "/dev/" + d) or "{}")
        except ValueError:
            smart[d] = {}

    print(json.dumps({
        "system": dmi(1), "board": dmi(2), "chassis": dmi(3), "bios": dmi(0),
        "cpu": dmi(4), "mem_array": dmi(16), "mem": dmi(17), "psu": dmi(39),
        "bays": bays, "disks": disks, "smart": smart,
        "uptime_s": float((rd("/proc/uptime").split() or ["0"])[0]),
        "pve": sh("pveversion").strip(),
    }))


main()
