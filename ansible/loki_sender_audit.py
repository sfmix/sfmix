#!/usr/bin/env python3
"""Audit which expected hosts are actually shipping logs to Loki (read-only).

Compares the set of `host` label values currently in Loki against the hosts
defined in the Ansible inventory, and reports three groups:

  shipping  - inventory hosts that have logs in Loki (good)
  MISSING   - inventory hosts with no logs in the lookback window (onboard these)
  extra     - hosts shipping that are NOT in the Ansible inventory
              (expected for network devices / PDUs managed outside Ansible)

Loki is reached at its oob address by default. From a host without a route to
the oob network, run an ssh tunnel first, e.g.:
  ssh -N -L 3100:localhost:3100 metrics.sfo02.sfmix.org
and pass --loki-url http://localhost:3100

Usage:
  ./loki_sender_audit.py
  ./loki_sender_audit.py --loki-url http://localhost:3100 --lookback-hours 6
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request


def loki_host_values(loki_url, lookback_hours):
    start_ns = int((time.time() - lookback_hours * 3600) * 1_000_000_000)
    qs = urllib.parse.urlencode({"start": start_ns})
    url = f"{loki_url.rstrip('/')}/loki/api/v1/label/host/values?{qs}"
    with urllib.request.urlopen(url, timeout=20) as resp:
        data = json.load(resp)
    if data.get("status") != "success":
        raise RuntimeError(f"Loki returned: {data}")
    return set(data.get("data") or [])


def inventory_hosts(inventory):
    out = subprocess.check_output(
        ["ansible-inventory", "-i", inventory, "--list"], text=True
    )
    data = json.loads(out)
    hosts = set((data.get("_meta", {}).get("hostvars") or {}).keys())
    hosts.discard("localhost")
    return hosts


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--loki-url", default="http://metrics.oob.sfo02.sfmix.org:3100")
    ap.add_argument("--inventory", default="inventory/servers.yml")
    ap.add_argument("--lookback-hours", type=float, default=24.0)
    args = ap.parse_args()

    try:
        shipping = loki_host_values(args.loki_url, args.lookback_hours)
    except Exception as e:
        print(f"ERROR querying Loki at {args.loki_url}: {e}", file=sys.stderr)
        return 2
    try:
        expected = inventory_hosts(args.inventory)
    except Exception as e:
        print(f"ERROR reading inventory {args.inventory}: {e}", file=sys.stderr)
        return 2

    shipping_expected = sorted(expected & shipping)
    missing = sorted(expected - shipping)
    extra = sorted(shipping - expected)

    print(f"Loki: {args.loki_url}  (last {args.lookback_hours:g}h)")
    print(f"Inventory hosts: {len(expected)}   Shipping: {len(shipping)}\n")

    print(f"== shipping (in inventory) [{len(shipping_expected)}] ==")
    for h in shipping_expected:
        print(f"  ok   {h}")
    print(f"\n== MISSING (in inventory, no logs) [{len(missing)}] ==")
    for h in missing:
        print(f"  --   {h}")
    print(f"\n== extra (shipping, not in inventory: net devices/PDUs) [{len(extra)}] ==")
    for h in extra:
        print(f"  +    {h}")

    # Non-zero exit if anything expected is missing, for CI/cron use.
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
