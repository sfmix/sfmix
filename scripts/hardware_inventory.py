#!/usr/bin/env python3
"""Discover live chassis / FRU hardware and sync it into NetBox.

Slots (PSU / fan / optic cages / DIMM slots / drive bays / CPU sockets /
mainboard) become module bays, installed parts become modules. Feeds the
hardware-fleet app at peering-gear.sfmix.org. Design:
documentation/design_docs/010-peering-gear-hardware-fleet.md

  ./hardware_inventory.py --dry-run                 # everything, no writes
  ./hardware_inventory.py --device switch01.sfo01   # one device, writes
  ./hardware_inventory.py --dump-json /tmp/hw       # also save raw collections
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, List, Optional

import pynetbox

from hwinv.model import DeviceHardware
from hwinv.netbox_sync import NetBoxHardwareSync

logger = logging.getLogger("hwinv")

DEFAULT_ROLES = ["peering_switch", "edge-router", "vm-hypervisor"]


def collector_for(dev: Any) -> Optional[Callable[[Any], DeviceHardware]]:
    mfr = dev.device_type.manufacturer.slug
    role = dev.role.slug if dev.role else ""
    if mfr == "arista":
        from hwinv import eos

        return eos.collect
    if mfr == "nokia":
        from hwinv import sros

        return sros.collect
    if mfr == "juniper":
        from hwinv import junos

        return junos.collect
    if role == "vm-hypervisor":
        from hwinv import linux

        return linux.collect
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--device", action="append", help="limit to device name (repeatable)")
    ap.add_argument("--role", action="append", help=f"device role slug (default: {', '.join(DEFAULT_ROLES)})")
    ap.add_argument("--dry-run", action="store_true", help="collect and diff, write nothing")
    ap.add_argument("--dump-json", metavar="DIR", help="write each collected DeviceHardware as JSON here")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    for noisy in ("paramiko", "ncclient", "urllib3", "pyeapi"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    nb = pynetbox.api(os.environ["NETBOX_API_ENDPOINT"], token=os.environ["NETBOX_API_TOKEN"])
    devices: List[Any] = []
    if args.device:
        for name in args.device:
            d = nb.dcim.devices.get(name=name)
            if d is None:
                logger.error("no such device %s", name)
                return 2
            devices.append(d)
    else:
        for role in args.role or DEFAULT_ROLES:
            devices += list(nb.dcim.devices.filter(role=role, status="active"))

    work = []
    for d in devices:
        fn = collector_for(d)
        if fn is None:
            logger.warning("%s: no hardware collector for %s %s; skipping", d.name, d.device_type.manufacturer.name, d.device_type.model)
            continue
        work.append((d, fn))

    collected: List[DeviceHardware] = []
    failed: List[str] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(fn, d): d for d, fn in work}
        for fut in as_completed(futs):
            d = futs[fut]
            try:
                hw = fut.result()
            except Exception as exc:
                logger.error("%s: collection failed: %s", d.name, exc)
                failed.append(d.name)
                continue
            filled = sum(1 for s in hw.slots if s.part)
            logger.info("%s: %d slots (%d populated)", hw.name, len(hw.slots), filled)
            collected.append(hw)
            if args.dump_json:
                os.makedirs(args.dump_json, exist_ok=True)
                with open(os.path.join(args.dump_json, f"{hw.name}.json"), "w") as f:
                    json.dump(dataclasses.asdict(hw), f, indent=1, default=str)

    sync = NetBoxHardwareSync(nb, dry_run=args.dry_run)
    sync.preflight()
    for hw in sorted(collected, key=lambda h: h.name):
        try:
            sync.sync(hw)
        except Exception as exc:
            logger.error("%s: NetBox sync failed: %s", hw.name, exc)
            failed.append(hw.name)

    logger.info("%sdone: %s", "[DRY-RUN] " if args.dry_run else "", json.dumps(dict(sorted(sync.stats.items()))))
    if failed:
        logger.error("failed: %s", ", ".join(sorted(failed)))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
