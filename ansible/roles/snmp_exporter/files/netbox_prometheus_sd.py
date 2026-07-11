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


def build_target_groups(devices: list) -> list:
    groups = []
    for dev in sorted(devices, key=lambda d: d["name"]):
        name = dev["name"].strip()
        fqdn = name if name.endswith("." + DOMAIN) else f"{name}.{DOMAIN}"
        groups.append({
            "targets": [fqdn],
            "labels": {
                "device": name,
                "site": ((dev.get("site") or {}).get("slug") or ""),
            },
        })
    return groups


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default="/opt/prometheus/file_sd/snmp_targets.json")
    ap.add_argument("--role", default="peering_switch",
                    help="NetBox device role slug to enumerate")
    ap.add_argument("--exclude-name-regex", default=r"\.transit$",
                    help="skip devices whose NetBox name matches (the AS40271 "
                         "transit routers share the peering_switch role but "
                         "not the fabric's SNMP community)")
    ap.add_argument("--allow-empty", action="store_true",
                    help="write the file even when NetBox returns no devices")
    ap.add_argument("--status-file", default="",
                    help="write a small JSON status document here")
    args = ap.parse_args()

    if not (os.environ.get("NETBOX_API_ENDPOINT") and os.environ.get("NETBOX_API_TOKEN")):
        log.error("NETBOX_API_ENDPOINT / NETBOX_API_TOKEN not set")
        return 2

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
        groups = build_target_groups(devices)
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
