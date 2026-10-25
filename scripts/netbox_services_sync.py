#!/usr/bin/env python3
"""
Sync SFMIX services (IX LAN, IX ports, PVLANs) into the netbox-services plugin.

Reads only NetBox: the physical/IPAM model stays the source of truth and Services are derived
from it. Dry-run by default; --apply writes. Only the fields built here are managed; lifecycle
dates, SLA, attachments and a PVLAN's primary (billing) tenant are left to humans. Services are
never deleted; synced ones whose source object disappeared are reported.

See documentation/design_docs/009-netbox-services.md.
"""
import argparse
import re
import sys
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional

import pynetbox

from discovery import netbox_api_client

SYNC_TAG = "services_sync"
IXLAN_SERVICE_ID = "SFMIX-IXLAN"
FABRIC_VLAN_GROUP = "exchange_fabric_vlans"
IXLAN_VIDS = (997, 998, 999)
PVLAN_NAME_RE = re.compile(r"^PVLAN-AS(\d+)-AS(\d+)$")
# Device statuses whose ports still carry live services
LIVE_DEVICE_STATUSES = {"active", "staged", "planned"}

RELATIONS = ("tenants", "devices", "interfaces", "cables", "vlans", "prefixes", "depends_on")
SCALARS = ("type", "status", "description", "tenant", "bandwidth", "cir")


class ServicesAPI:
    """The plugin registers its viewset at the plugin root (/api/plugins/services/), which
    pynetbox's app/endpoint addressing can't express, so talk to it over pynetbox's session."""

    def __init__(self, nb: pynetbox.api):
        self.url = f"{nb.base_url}/plugins/services/"
        self.session = nb.http_session
        scheme = "Bearer" if nb.token.startswith("nbt_") else "Token"
        self.headers = {"Authorization": f"{scheme} {nb.token}", "Accept": "application/json"}

    def _check(self, resp):
        if not resp.ok:
            raise RuntimeError(f"{resp.request.method} {resp.url}: {resp.status_code} {resp.text}")
        return resp.json() if resp.content else None

    def all(self) -> List[dict]:
        out, url, params = [], self.url, {"limit": 1000}
        while url:
            page = self._check(self.session.get(url, headers=self.headers, params=params))
            out.extend(page["results"])
            url, params = page["next"], None
        return out

    def create(self, data: dict) -> dict:
        return self._check(self.session.post(self.url, json=data, headers=self.headers))

    def update(self, pk: int, data: dict) -> dict:
        return self._check(self.session.patch(f"{self.url}{pk}/", json=data, headers=self.headers))


def kbps_to_mbps(kbps: Optional[int]) -> Optional[int]:
    return kbps // 1000 if kbps else None


class Fabric:
    """Bulk-loaded view of the NetBox objects the services are derived from."""

    def __init__(self, nb: pynetbox.api):
        self.nb = nb
        self.devices = {d.id: d for d in nb.dcim.devices.filter(role="peering_switch")}
        self.vlans = {v.vid: v for v in nb.ipam.vlans.filter(group=FABRIC_VLAN_GROUP)}
        self.tenants = {t.id: t for t in nb.tenancy.tenants.all()}
        self.tenants_by_asn = {
            t.custom_fields["as_number"]: t for t in self.tenants.values() if t.custom_fields.get("as_number")
        }
        self.peering_ports = list(nb.dcim.interfaces.filter(tag="peering_port"))
        self.peering_ports += list(nb.dcim.interfaces.filter(tag="encapsulated_peering_port"))
        self.peering_lan_prefixes = list(nb.ipam.prefixes.filter(tag="peering_lan"))
        self._by_id: Dict[int, Any] = {}
        self._members: Dict[int, List[Any]] = defaultdict(list)
        self._index(self.peering_ports)

    def _index(self, interfaces: Iterable[Any]):
        for i in interfaces:
            self._by_id[i.id] = i

    def interface(self, pk: int):
        if pk not in self._by_id:
            self._by_id[pk] = self.nb.dcim.interfaces.get(pk)
        return self._by_id[pk]

    def load_members(self, lag_ids: Iterable[int]):
        lag_ids = [pk for pk in set(lag_ids) if pk not in self._members]
        for start in range(0, len(lag_ids), 50):
            for m in self.nb.dcim.interfaces.filter(lag_id=lag_ids[start:start + 50]):
                self._members[m.lag.id].append(m)
                self._by_id[m.id] = m

    def label(self, field: str, pk) -> str:
        """Human name for a related-object ID, for the dry-run diff."""
        if field == "interfaces" and pk in self._by_id:
            return iface_label(self._by_id[pk])
        if field == "devices" and pk in self.devices:
            return self.devices[pk].name
        if field == "vlans":
            return next((f"{v.vid} {v.name}" for v in self.vlans.values() if v.id == pk), f"#{pk}")
        if field in ("tenant", "tenants") and pk in self.tenants:
            return self.tenants[pk].name
        if field == "prefixes":
            return next((p.prefix for p in self.peering_lan_prefixes if p.id == pk), f"#{pk}")
        if field == "cables":
            return f"cable #{pk}"
        return str(pk)

    def members(self, lag) -> List[Any]:
        self.load_members([lag.id])
        return sorted(self._members[lag.id], key=lambda m: m.name)

    def vlan_interfaces(self, vlan) -> List[Any]:
        found = list(self.nb.dcim.interfaces.filter(vlan_id=vlan.id))
        self._index(found)
        return found


class Port:
    """The physical side of an interface carrying a service: the interface itself, its parent
    (for a sub-interface) and the LAG members behind whichever of those is a LAG."""

    def __init__(self, fabric: Fabric, iface):
        self.iface = iface
        self.parent = fabric.interface(iface.parent.id) if iface.parent else None
        carrier = self.parent or iface
        self.lag = carrier if carrier.type.value == "lag" else None
        self.physical = fabric.members(self.lag) if self.lag else [carrier]

    @property
    def interfaces(self) -> List[Any]:
        return [i for i in (self.iface, self.parent) if i] + [
            m for m in self.physical if m.id not in (self.iface.id, self.parent and self.parent.id)
        ]

    @property
    def cables(self) -> List[int]:
        return sorted({i.cable.id for i in self.physical if i.cable})

    @property
    def bandwidth(self) -> Optional[int]:
        """Physical rate in Mbps (sum of LAG members)."""
        speeds = [m.speed for m in self.physical if m.speed]
        if speeds:
            return kbps_to_mbps(sum(speeds))
        return kbps_to_mbps((self.parent or self.iface).speed)

    @property
    def shaped(self) -> List[Any]:
        return [i for i in self.interfaces if i.custom_fields.get("rate_limit_bps")]

    @property
    def commit(self) -> Optional[int]:
        """Committed rate in Mbps as enforced by the rate_limit_bps shaper(s); the full physical
        rate when nothing on the port is shaped."""
        own = (self.iface.custom_fields.get("rate_limit_bps")
               or (self.parent and self.parent.custom_fields.get("rate_limit_bps"))
               or (self.lag and self.lag.custom_fields.get("rate_limit_bps")))
        if own:
            return min(own // 1_000_000, self.bandwidth or own // 1_000_000)
        if any(m.custom_fields.get("rate_limit_bps") for m in self.physical):
            # Shapers on individual LAG members cap only that member
            def member_rate(m) -> int:
                speed = kbps_to_mbps(m.speed) or 0
                shaper = m.custom_fields.get("rate_limit_bps")
                return min(speed, shaper // 1_000_000) if shaper else speed
            return sum(member_rate(m) for m in self.physical)
        return self.bandwidth


def iface_label(i) -> str:
    return f"{i.device.name} {i.name}"


def service_status(port: Port, fabric: Fabric) -> str:
    device = fabric.devices.get(port.iface.device.id)
    if device and device.status.value not in LIVE_DEVICE_STATUSES:
        return "deprovisioning"
    return "active" if port.iface.enabled else "offline"


def build_desired(fabric: Fabric, warnings: List[str]) -> Dict[str, dict]:
    desired: Dict[str, dict] = {}

    ixlan_vlans = [fabric.vlans[vid].id for vid in IXLAN_VIDS if vid in fabric.vlans]
    desired[IXLAN_SERVICE_ID] = {
        "type": "ixp_lan",
        "status": "active",
        "description": "SFMIX public peering LAN",
        "vlans": ixlan_vlans,
        "prefixes": sorted(p.id for p in fabric.peering_lan_prefixes),
    }

    fabric.load_members(
        [i.id for i in fabric.peering_ports if i.type.value == "lag"]
        + [i.parent.id for i in fabric.peering_ports if i.parent]
    )
    ix_service_by_carrier: Dict[int, str] = {}
    for iface in sorted(fabric.peering_ports, key=iface_label):
        participant = iface.custom_fields.get("participant")
        if not participant:
            warnings.append(f"skip {iface_label(iface)}: peering port without participant ({iface.description})")
            continue
        tenant = fabric.tenants[participant["id"]]
        asn = tenant.custom_fields.get("as_number")
        port = Port(fabric, iface)
        service_id = f"IXP-AS{asn}-{iface.device.name}-{iface.name}"
        for i in port.shaped:
            owner = (i.custom_fields.get("participant") or {}).get("id")
            if owner and owner != tenant.id:
                warnings.append(
                    f"{service_id}: shaper on {iface_label(i)} belongs to {i.custom_fields['participant']['name']}, "
                    f"not {tenant.name}")
        vlans = sorted({v.id for v in iface.tagged_vlans} | ({iface.untagged_vlan.id} if iface.untagged_vlan else set()))
        desired[service_id] = {
            "type": "ixp_port",
            "status": service_status(port, fabric),
            "description": f"IX port: {tenant.description or tenant.name} ({tenant.name}) on {iface.device.name}",
            "tenant": tenant.id,
            "tenants": [tenant.id],
            "devices": [iface.device.id],
            "interfaces": sorted(i.id for i in port.interfaces),
            "cables": port.cables,
            "vlans": vlans,
            "bandwidth": port.bandwidth,
            "cir": port.commit,
            "depends_on": [IXLAN_SERVICE_ID],
        }
        ix_service_by_carrier[(port.parent or iface).id] = service_id

    for vid, vlan in sorted(fabric.vlans.items()):
        m = PVLAN_NAME_RE.match(vlan.name)
        if not m:
            continue
        parties = []
        for asn in map(int, m.groups()):
            if asn in fabric.tenants_by_asn:
                parties.append(fabric.tenants_by_asn[asn].id)
            else:
                warnings.append(f"{vlan.name}: no tenant with as_number {asn}")
        ports = []
        for iface in sorted(fabric.vlan_interfaces(vlan), key=iface_label):
            device = fabric.devices.get(iface.device.id)
            if device and device.status.value not in LIVE_DEVICE_STATUSES:
                warnings.append(f"{vlan.name}: skip {iface_label(iface)} on {device.status.value} device")
                continue
            ports.append(Port(fabric, iface))
        bandwidths = [p.bandwidth for p in ports if p.bandwidth]
        desired[vlan.name] = {
            "type": "l2vpn",
            "status": "active" if vlan.status.value == "active" else "offline",
            "description": f"Private VLAN {vid} between AS{m.group(1)} and AS{m.group(2)}",
            "tenants": parties,
            "devices": sorted({p.iface.device.id for p in ports}),
            "interfaces": sorted({i.id for p in ports for i in p.interfaces}),
            "cables": sorted({c for p in ports for c in p.cables}),
            "vlans": [vlan.id],
            "bandwidth": min(bandwidths) if bandwidths else None,
            "depends_on": sorted({
                ix_service_by_carrier[p.parent.id] for p in ports
                if p.parent and p.parent.id in ix_service_by_carrier}),
        }
    return desired


def current_value(service: dict, field: str):
    value = service.get(field)
    if field in RELATIONS:
        return sorted(v["id"] if isinstance(v, dict) else v for v in value or [])
    if isinstance(value, dict):  # tenant {id,..} or choice {value,label}
        return value.get("id", value.get("value"))
    return value


def show(fabric: Fabric, field: str, value):
    if value is None or field not in RELATIONS + ("tenant",) or field == "depends_on":
        return repr(value)
    if field == "tenant":
        return fabric.label(field, value)
    return "[" + ", ".join(fabric.label(field, pk) for pk in value) + "]"


def diff(existing: Optional[dict], spec: dict, service_ids_by_pk: Dict[int, str]) -> Dict[str, Any]:
    changes = {}
    for field, want in spec.items():
        have = current_value(existing, field) if existing else None
        if field == "depends_on" and existing:
            have = sorted(service_ids_by_pk.get(pk, pk) for pk in have)
        if field in RELATIONS:
            want = sorted(want)
        if have != want:
            changes[field] = (have, want)
    return changes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    parser.add_argument("--only", choices=("ix", "pvlan"), help="limit to IX LAN or PVLAN services")
    parser.add_argument("-v", "--verbose", action="store_true", help="show unchanged services too")
    args = parser.parse_args()

    nb = netbox_api_client()
    api = ServicesAPI(nb)
    tag = nb.extras.tags.get(slug=SYNC_TAG)
    if not tag:
        print(f"Tag {SYNC_TAG!r} missing; run ansible/netbox_schema.playbook.yml first", file=sys.stderr)
        return 1

    warnings: List[str] = []
    fabric = Fabric(nb)
    desired = build_desired(fabric, warnings)
    if args.only == "ix":
        desired = {k: v for k, v in desired.items() if v["type"] in ("ixp_lan", "ixp_port")}
    elif args.only == "pvlan":
        desired = {k: v for k, v in desired.items() if v["type"] == "l2vpn"}

    existing = {s["service_id"]: s for s in api.all()}
    service_ids_by_pk = {s["id"]: s["service_id"] for s in existing.values()}

    # Create/update in dependency order: parents first so depends_on can be resolved to IDs
    order = sorted(desired, key=lambda sid: (bool(desired[sid].get("depends_on")), sid))
    counts = defaultdict(int)
    for service_id in order:
        spec = desired[service_id]
        changes = diff(existing.get(service_id), spec, service_ids_by_pk)
        if existing.get(service_id) and not changes:
            counts["unchanged"] += 1
            if args.verbose:
                print(f"  {service_id}")
            continue
        action = "update" if service_id in existing else "create"
        counts[action] += 1
        print(f"{'~' if action == 'update' else '+'} {service_id}")
        for field, (have, want) in changes.items():
            if action == "create":
                if want not in (None, []):
                    print(f"    {field}: {show(fabric, field, want)}")
            else:
                print(f"    {field}: {show(fabric, field, have)} -> {show(fabric, field, want)}")
        if not args.apply:
            continue
        payload = {field: want for field, (_, want) in changes.items()}
        if "depends_on" in payload:
            pks = {sid: pk for pk, sid in service_ids_by_pk.items()}
            payload["depends_on"] = [pks[sid] for sid in payload["depends_on"]]
        if action == "create":
            payload.update(service_id=service_id, type=spec["type"], tags=[{"slug": SYNC_TAG}])
            created = api.create(payload)
            existing[service_id] = created
            service_ids_by_pk[created["id"]] = service_id
        else:
            api.update(existing[service_id]["id"], payload)

    stale = sorted(
        sid for sid, s in existing.items()
        if sid not in desired and any(t["slug"] == SYNC_TAG for t in s.get("tags", []))
        and (not args.only or (s["type"]["value"] == "l2vpn") == (args.only == "pvlan"))
    )
    for sid in stale:
        print(f"? {sid}: tagged {SYNC_TAG} but no longer derived from NetBox (left alone)")
    for w in warnings:
        print(f"! {w}")
    print(f"\n{'Applied' if args.apply else 'Dry-run'}: {counts['create']} create, {counts['update']} update, "
          f"{counts['unchanged']} unchanged, {len(stale)} stale, {len(warnings)} warnings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
