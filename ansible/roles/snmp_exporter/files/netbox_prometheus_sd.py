#!/usr/bin/env python3
"""Write the Prometheus file_sd target list for SNMP polling from NetBox.

Enumerates active peering switches from NetBox (source of truth) and writes a
file_sd JSON document, one target group per device, labeled with the site and
bare device name. Intended to run on the metrics host from a systemd timer.
Prometheus watches the output file and reloads targets automatically.

On any NetBox failure the output file is left untouched, so Prometheus keeps
scraping the last-known target set across NetBox outages. An empty device
list is treated as a failure unless --allow-empty is given.

Pure stdlib (urllib/json) — no pip deps. Credentials from the environment:
  NETBOX_API_ENDPOINT, NETBOX_API_TOKEN
"""
import argparse
import json
import logging
import os
import re
import socket
import sys
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone

log = logging.getLogger("netbox-prometheus-sd")
logging.basicConfig(
    level=logging.INFO, stream=sys.stderr,
    format="%(asctime)s %(name)s %(levelname)s %(message)s")

DOMAIN = "sfmix.org"                 # NetBox device names are short (switch01.sfo02)


def _get(url: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Token {os.environ['NETBOX_API_TOKEN']}",
                 "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def fetch_devices(role: str) -> list:
    """Return all active NetBox devices of the given role (paginated REST)."""
    base = os.environ["NETBOX_API_ENDPOINT"].rstrip("/")
    url = (f"{base}/api/dcim/devices/?"
           + urllib.parse.urlencode({"role": role, "status": "active", "limit": 100}))
    devices = []
    while url:
        page = _get(url)
        devices.extend(page["results"])
        url = page.get("next")
    return devices


def _manufacturer(dev: dict) -> str:
    """Human manufacturer name from a device's device_type (or '')."""
    return (((dev.get("device_type") or {}).get("manufacturer") or {})
            .get("name") or "")


def _model(dev: dict) -> str:
    dt = dev.get("device_type") or {}
    return dt.get("model") or dt.get("display") or ""


def build_target_groups(devices: list, module_map: dict | None = None) -> list:
    """One file_sd target group per device.

    When ``module_map`` (a {manufacturer-name: snmp_module} dict) is given the
    discovery is *vendor-aware*: each target also carries ``module`` (which the
    scrape job relabels to __param_module so one job polls a mixed fleet),
    ``vendor`` and ``model``. Devices whose manufacturer isn't in the map are
    skipped — better no data than polling gear with the wrong MIB module.
    When the map is empty the labels are just ``device``/``site`` (switches).
    """
    groups = []
    for dev in sorted(devices, key=lambda d: d.get("name") or ""):
        name = (dev.get("name") or "").strip()
        if not name:
            log.warning("device id=%s has no name in NetBox — skipped",
                        dev.get("id"))
            continue
        fqdn = name if name.endswith("." + DOMAIN) else f"{name}.{DOMAIN}"
        labels = {
            "device": name,
            "site": ((dev.get("site") or {}).get("slug") or ""),
        }
        if module_map is not None:
            vendor = _manufacturer(dev)
            module = module_map.get(vendor)
            if not module:
                log.warning("%s: manufacturer %r not in --module-map — skipped "
                            "(add a mapping to poll it)", name, vendor)
                continue
            labels["module"] = module
            labels["vendor"] = vendor
            labels["model"] = _model(dev)
        try:
            socket.getaddrinfo(fqdn, None)
        except OSError:
            log.warning("%s does not resolve — skipped (fix DNS or the NetBox "
                        "name; it will be picked up on the next sync)", fqdn)
            continue
        groups.append({"targets": [fqdn], "labels": labels})
    return groups


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default="/opt/prometheus/file_sd/snmp_targets.json")
    ap.add_argument("--role", default="peering_switch",
                    help="NetBox device role slug to enumerate")
    ap.add_argument("--module-map", action="append", default=[],
                    metavar="MANUFACTURER=MODULE",
                    help="map a NetBox manufacturer name to an snmp_exporter "
                         "module; repeatable. Enables vendor-aware discovery "
                         "(emits module/vendor/model labels). Devices whose "
                         "manufacturer is unmapped are skipped.")
    ap.add_argument("--exclude-name-regex", default="",
                    help="skip devices whose NetBox name matches")
    ap.add_argument("--allow-empty", action="store_true",
                    help="write the file even when NetBox returns no devices")
    ap.add_argument("--status-file", default="",
                    help="write a small JSON status document here")
    args = ap.parse_args()

    if not (os.environ.get("NETBOX_API_ENDPOINT") and os.environ.get("NETBOX_API_TOKEN")):
        log.error("NETBOX_API_ENDPOINT / NETBOX_API_TOKEN not set")
        return 2

    module_map = None
    if args.module_map:
        module_map = {}
        for item in args.module_map:
            if "=" not in item:
                log.error("bad --module-map %r (want MANUFACTURER=MODULE)", item)
                return 2
            mfr, mod = item.split("=", 1)
            module_map[mfr.strip()] = mod.strip()

    status = {"time": datetime.now(timezone.utc).isoformat(), "ok": False}
    try:
        devices = fetch_devices(args.role)
        if args.exclude_name_regex:
            pat = re.compile(args.exclude_name_regex)
            skipped = [d["name"] for d in devices if pat.search(d["name"])]
            if skipped:
                log.info("excluding %d device(s) by name: %s",
                         len(skipped), ", ".join(sorted(skipped)))
            devices = [d for d in devices if not pat.search(d["name"])]
        if not devices and not args.allow_empty:
            raise RuntimeError(
                f"NetBox returned no active '{args.role}' devices; "
                "refusing to empty the target list (--allow-empty overrides)")
        groups = build_target_groups(devices, module_map)
        body = json.dumps(groups, indent=2, sort_keys=True) + "\n"
    except Exception as e:  # noqa: BLE001
        log.error("sync failed, leaving %s untouched: %s", args.output, e)
        status["error"] = str(e)
        _write_status(args.status_file, status)
        return 1

    old = ""
    if os.path.exists(args.output):
        with open(args.output) as f:
            old = f.read()
    changed = body != old
    if changed:
        d = os.path.dirname(args.output) or "."
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".snmp_targets.")
        with os.fdopen(fd, "w") as f:
            f.write(body)
        os.chmod(tmp, 0o644)             # prometheus runs as nobody
        os.replace(tmp, args.output)
        log.info("wrote %s (%d targets) — changed", args.output, len(groups))
    else:
        log.info("%s unchanged (%d targets)", args.output, len(groups))

    status.update(ok=True, targets=len(groups), changed=changed)
    _write_status(args.status_file, status)
    return 0


def _write_status(path: str, status: dict) -> None:
    if not path:
        return
    try:
        with open(path, "w") as f:
            json.dump(status, f)
    except OSError as e:
        log.warning("could not write status file %s: %s", path, e)


if __name__ == "__main__":
    sys.exit(main())
