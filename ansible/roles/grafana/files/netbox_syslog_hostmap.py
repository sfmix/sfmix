#!/usr/bin/env python3
"""Build the syslog-ng add-contextual-data host-map from NetBox (source of truth).

Polls NetBox for every IP address and the canonical host it belongs to (the
assigned VM or device), and writes a CSV that syslog-ng uses to rewrite the
log HOST to the canonical name (beating reverse-DNS). Intended to run on the
metrics host from a systemd timer; reloads syslog-ng only when the map changes
and logs a status line (and optional JSON status file) each run.

Pure stdlib (urllib/json) — no pip deps. Credentials from the environment:
  NETBOX_API_ENDPOINT, NETBOX_API_TOKEN

CSV format (selector,name,value):  <source-ip>,canonical_host,<fqdn>
"""
import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone

log = logging.getLogger("netbox-hostmap")
logging.basicConfig(
    level=logging.INFO, stream=sys.stderr,
    format="%(asctime)s %(name)s %(levelname)s %(message)s")

CONTEXT_NAME = "canonical_host"      # NV pair syslog-ng sets from the lookup
DOMAIN = "sfmix.org"                 # device names are often short; VMs are FQDNs

# NetBox 4.x (Strawberry) GraphQL returns the full list with no pagination args.
_GQL = """
query {
  ip_address_list {
    address
    dns_name
    assigned_object {
      __typename
      ... on VMInterfaceType { virtual_machine { name } }
      ... on InterfaceType { device { name } }
    }
  }
}
"""


def _graphql_url() -> str:
    base = os.environ["NETBOX_API_ENDPOINT"].rstrip("/")
    if base.endswith("/api"):
        base = base[:-4]
    return base + "/graphql/"


def _graphql(query: str, variables: dict) -> dict:
    req = urllib.request.Request(
        _graphql_url(),
        data=json.dumps({"query": query, "variables": variables}).encode(),
        headers={"Authorization": f"Token {os.environ['NETBOX_API_TOKEN']}",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        out = json.load(resp)
    if out.get("errors"):
        raise RuntimeError(f"NetBox GraphQL error: {out['errors']}")
    return out["data"]


def fetch_ip_hosts() -> "dict[str, set]":
    """Return {source_ip: {canonical_host, ...}} from NetBox (all IPs)."""
    owners: "dict[str, set]" = {}
    for r in _graphql(_GQL, {})["ip_address_list"]:
        obj = r.get("assigned_object") or {}
        host = (r.get("dns_name") or "").strip()
        if not host:
            vm = obj.get("virtual_machine")
            dev = obj.get("device")
            host = (vm or dev or {}).get("name", "") if (vm or dev) else ""
        host = host.strip()
        if not host:
            continue
        if host != DOMAIN and not host.endswith("." + DOMAIN):
            host = f"{host}.{DOMAIN}"     # normalize short device names to FQDN
        ip = r["address"].split("/", 1)[0]
        owners.setdefault(ip, set()).add(host)
    return owners


def build_csv(owners: "dict[str, set]") -> "tuple[str, int]":
    """Render the CSV body; drop IPs claimed by >1 host (ambiguous source)."""
    ambiguous = sorted(ip for ip, hosts in owners.items() if len(hosts) > 1)
    rows = sorted((ip, next(iter(hosts))) for ip, hosts in owners.items()
                  if len(hosts) == 1)
    body = "".join(f"{ip},{CONTEXT_NAME},{host}\n" for ip, host in rows)
    if ambiguous:
        log.info("%d IP(s) shared by multiple hosts, omitted: %s",
                 len(ambiguous), ", ".join(ambiguous))
    return body, len(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default="/opt/loki/host-map.csv")
    ap.add_argument("--reload-cmd", default="",
                    help="shell command to reload syslog-ng when the map changes")
    ap.add_argument("--status-file", default="",
                    help="write a small JSON status document here")
    args = ap.parse_args()

    if not (os.environ.get("NETBOX_API_ENDPOINT") and os.environ.get("NETBOX_API_TOKEN")):
        log.error("NETBOX_API_ENDPOINT / NETBOX_API_TOKEN not set")
        return 2

    status = {"time": datetime.now(timezone.utc).isoformat(), "ok": False}
    try:
        owners = fetch_ip_hosts()
        body, n = build_csv(owners)
    except Exception as e:  # noqa: BLE001
        log.error("sync failed: %s", e)
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
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".host-map.")
        with os.fdopen(fd, "w") as f:
            f.write(body)
        os.replace(tmp, args.output)
        log.info("wrote %s (%d entries) — changed", args.output, n)
        if args.reload_cmd:
            rc = subprocess.run(args.reload_cmd, shell=True).returncode
            log.info("reload (%s) rc=%d", args.reload_cmd, rc)
            status["reload_rc"] = rc
    else:
        log.info("%s unchanged (%d entries)", args.output, n)

    status.update(ok=True, entries=n, changed=changed)
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
