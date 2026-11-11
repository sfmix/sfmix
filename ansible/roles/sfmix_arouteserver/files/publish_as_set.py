#!/usr/bin/env python3
"""
Publish an RPSL as-set to the ARIN IRR (Reg-RWS), idempotently.

Usage: publish_as_set.py [--check] [--force] <as-set.rpsl>

Fetches the current object, prints a members/descr diff, and only writes
(POST if new, PUT if changed) when something differs. --check prints the
diff without writing. Exit 0 and a final line "CHANGED" or "UNCHANGED".

Env: ARIN_API_KEY, ARIN_ORG_HANDLE.
"""
import argparse
import os
import sys
import xml.etree.ElementTree as ET

import requests

API_ENDPOINT = "https://reg.arin.net/rest/irr/as-set"
NS = {"a": "http://www.arin.net/regrws/core/v1"}
TIMEOUT = 60


def parse_rpsl(text):
    """Return (name, descr lines, members list) from an RPSL as-set."""
    name, descr, members = None, [], []
    for line in text.splitlines():
        if ":" not in line or line.startswith((" ", "\t", "+")):
            continue
        key, val = line.split(":", 1)
        key, val = key.strip().lower(), val.strip()
        if key == "as-set":
            name = val
        elif key == "descr":
            descr.append(val)
        elif key == "members":
            members += [m.strip() for m in val.split(",") if m.strip()]
    if not name:
        sys.exit("as-set name not found in input")
    return name, descr, members


def fetch_current(api_key, name):
    """Return the published object as (descr, members, xml_root_or_None), or None.

    ARIN serves and accepts an object only in the format it was created in
    (RPSL-created objects 406 on application/xml and vice versa), so try both;
    XML objects are updated by round-tripping the fetched XML.
    """
    for accept in ("application/xml", "application/rpsl"):
        r = requests.get(f"{API_ENDPOINT}/{name}", params={"apikey": api_key},
                         headers={"Accept": accept}, timeout=TIMEOUT)
        if r.status_code != 406:
            break
    if r.status_code == 404:
        return None
    if not r.ok:
        sys.exit(f"GET {name} failed: HTTP {r.status_code}: {r.text.replace(api_key, '***')}")
    if accept == "application/rpsl":
        _, descr, members = parse_rpsl(r.text)
        return descr, members, None
    root = ET.fromstring(r.content)
    descr = [ln.text or "" for ln in root.findall("a:description/a:line", NS)]
    members = [m.get("name") for m in root.findall("a:members/a:member", NS)]
    return descr, members, root


def xml_body(root, descr, members):
    """Rewrite description + members of a fetched XML as-set."""
    ns = "{" + NS["a"] + "}"
    desc_el = root.find("a:description", NS)
    for ln in list(desc_el):
        desc_el.remove(ln)
    for i, text in enumerate(descr):
        ET.SubElement(desc_el, ns + "line", number=str(i)).text = text
    mem_el = root.find("a:members", NS)
    for m in list(mem_el):
        mem_el.remove(m)
    for m in members:
        ET.SubElement(mem_el, ns + "member", name=m)
    ET.register_namespace("", NS["a"])
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def write(method, api_key, org, name, body, ctype="application/rpsl"):
    url = API_ENDPOINT if method == "POST" else f"{API_ENDPOINT}/{name}"
    params = {"apikey": api_key}
    if method == "POST":
        params["orgHandle"] = org
    r = requests.request(method, url, params=params, data=body,
                         headers={"Content-Type": ctype, "Accept": ctype},
                         timeout=TIMEOUT)
    if not r.ok:
        sys.exit(f"{method} {name} failed: HTTP {r.status_code}: {r.text.replace(api_key, '***')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rpsl_file")
    ap.add_argument("--check", action="store_true", help="show diff, do not write")
    ap.add_argument("--force", action="store_true", help="PUT even if members/descr are unchanged")
    args = ap.parse_args()

    api_key = os.environ.get("ARIN_API_KEY") or sys.exit("ARIN_API_KEY not set")
    org = os.environ.get("ARIN_ORG_HANDLE") or sys.exit("ARIN_ORG_HANDLE not set")

    with open(args.rpsl_file, encoding="utf-8") as f:
        rpsl = f.read()
    name, descr, members = parse_rpsl(rpsl)

    current = fetch_current(api_key, name)
    if current is None:
        print(f"{name}: does not exist; would create with {len(members)} members")
        for m in members:
            print(f"  + {m}")
        if not args.check:
            write("POST", api_key, org, name, rpsl.encode())
        print("CHANGED")
        return

    cur_descr, cur_members, xml_root = current
    added = [m for m in members if m not in cur_members]
    removed = [m for m in cur_members if m not in members]
    for m in added:
        print(f"  + {m}")
    for m in removed:
        print(f"  - {m}")
    if cur_descr != descr:
        print(f"  descr: {cur_descr} -> {descr}")

    if not (added or removed or cur_descr != descr or args.force):
        print(f"{name}: up to date ({len(members)} members)")
        print("UNCHANGED")
        return
    print(f"{name}: {'would update' if args.check else 'updating'} "
          f"(+{len(added)} -{len(removed)}, {len(members)} members)")
    if not args.check:
        if xml_root is None:
            write("PUT", api_key, org, name, rpsl.encode())
        else:
            write("PUT", api_key, org, name, xml_body(xml_root, descr, members), "application/xml")
    print("CHANGED")


if __name__ == "__main__":
    main()
