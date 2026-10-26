#!/usr/bin/env python3
import os
import sys
import re
from collections import defaultdict
from typing import Dict

import pynetbox
import yaml

from netbox_services_sync import LIVE_DEVICE_STATUSES, PVLAN_NAME_RE, ServicesAPI

"""
Perform some sanity checking against the IX-specific data in Netbox
"""


def url_strip_api(api_url: str) -> str:
    # Yikes, total hax
    return re.sub(r"/api", "", api_url)


def check_peering_lan_ip_tags(netbox: pynetbox.api) -> None:
    # For each peering_lan VLAN,
    # For each prefix associated with the VLAN,
    # For each IP in the IP prefix,
    # Check that the IP is tagged "ixp_participant" or "ixp_infrastructure"
    print("[!!] Checking that all peering LAN IPs are tagged properly")
    for peering_vlan in netbox.ipam.vlans.filter(tag="peering_lan"):
        # print(peering_vlan)
        for ip_prefix in netbox.ipam.prefixes.filter(vlan_id=peering_vlan.id):
            # print(ip_prefix)
            for ip in netbox.ipam.ip_addresses.filter(parent=ip_prefix.prefix):
                tag_slugs = [tag.slug for tag in ip.tags]
                if not (
                    ("ixp_participant" in tag_slugs)
                    or ("ixp_infrastructure" in tag_slugs)
                ):
                    print(
                        "Peering LAN IP missing `ixp_participant` or `ixp_infrastructure` tag:",
                        ip.address,
                        url_strip_api(ip.url),
                    )


def check_peering_lan_ip_participant_lag(netbox: pynetbox.api) -> None:
    # For each IP tagged "ixp_participant"
    # Check that the custom_field `participant_lag` maps back to a plausible interface,
    # Check that the interface has tag "peering_port" and one of "ixp_participant" or "ixp_infrastructure"
    print(
        "[!!] Checking that all IXP Participant IPs have a valid `participant_lag` custom field"
    )
    for ip in netbox.ipam.ip_addresses.filter(tag="ixp_participant"):
        if not ip.custom_fields.get("participant_lag"):
            print(
                f"IXP Participant IP {ip.address} is missing `participant_lag` custom field",
                url_strip_api(ip.url),
            )


def check_peering_vlan_ports(netbox: pynetbox.api) -> None:
    # For each VLAN tagged "peering_vlan"
    # Check that all ports in the VLAN have tag "peering_port"
    print("[!!] Checking that all ports in peering VLANs have tag `peering_port`")
    for peering_vlan in netbox.ipam.vlans.filter(tag="peering_lan"):
        for interface in netbox.dcim.interfaces.filter(vlan_id=peering_vlan.id):
            if interface.name == "Vxlan1":
                continue
            if "peering_port" not in [tag.slug for tag in interface.tags]:
                print(
                    f"Interface {interface.name} on device {interface.device.name} is in peering VLAN {peering_vlan.vid} but is missing `peering_port` tag",
                    url_strip_api(interface.url),
                )


def check_peering_port_custom_field_participant(netbox: pynetbox.api) -> None:
    # For each interface tagged "peering_port"
    # Check that the custom_field `participant` maps back to a plausible device,
    # Check that the device has tag "ixp_participant"
    print("[!!] Checking that peering ports have `participant` custom field")
    for interface in netbox.dcim.interfaces.filter(tag="peering_port"):
        if not interface.custom_fields.get("participant"):
            print(
                f"Peering port {interface.name} on device {interface.device.name} "
                f"is missing `participant` custom field",
                url_strip_api(interface.url),
            )
        description_matches = re.search(
            r"\(AS(\d+)\)", interface.description, re.IGNORECASE
        )
        if not description_matches:
            print(
                f"Peering port {interface.name} on device {interface.device.name} "
                f"is missing ASN in description",
                url_strip_api(interface.url),
            )
            continue
        asn = int(description_matches.group(1))
        if interface.custom_fields.get("participant"):
            if f"as{asn}" != interface.custom_fields["participant"]["slug"]:
                print(
                    f"Peering port {interface.name} on device {interface.device.name} "
                    f"has mismatched ASN in description and custom field",
                    url_strip_api(interface.url),
                )


def check_peering_port_participant_matches_description_asn(
    netbox: pynetbox.api,
) -> None:
    print(
        "[!!] Checking that peering ports have matching ASN in description and participant custom field"
    )
    for interface in netbox.dcim.interfaces.filter(tag="peering_port"):
        if interface.custom_fields.get("participant"):
            interface_participant_asn = asn_to_n(
                interface.custom_fields["participant"]["slug"]
            )
            description_matches = re.search(r"\(AS(\d+)\)", interface.description)
            if description_matches:
                description_asn = asn_to_n(f"as{description_matches.group(1)}")
                if interface_participant_asn != description_asn:
                    print(
                        f"Peering port {interface.name} on device {interface.device.name} "
                        f'has mismatched ASN in description "{description_asn}" '
                        f' and participant custom field "{interface_participant_asn}"',
                        url_strip_api(interface.url),
                    )


def check_lag_member_participant_matches_lag(netbox: pynetbox.api) -> None:
    # A LAG member's `participant` must match its LAG's, or that of a peering sub-interface on
    # the LAG (e.g. Port-Channel101.998). A mismatch is left over from when the member was
    # someone else's port; any shaper on it is usually stale too.
    print("[!!] Checking that LAG member `participant` matches its LAG")
    lag_participants = {}
    for interface in netbox.dcim.interfaces.filter(cf_participant__empty="false"):
        if not interface.lag:
            continue
        lag_id = interface.lag.id
        if lag_id not in lag_participants:
            lag = netbox.dcim.interfaces.get(lag_id)
            lag_participants[lag_id] = {
                p["id"]
                for i in [lag, *netbox.dcim.interfaces.filter(parent_id=lag_id)]
                if (p := i.custom_fields.get("participant"))
            }
        participant = interface.custom_fields["participant"]
        if participant["id"] in lag_participants[lag_id]:
            continue
        stale = [f"participant {participant['name']}"]
        stale += [tag.slug for tag in interface.tags if tag.slug == "ixp_participant"]
        if rate_limit_bps := interface.custom_fields.get("rate_limit_bps"):
            stale.append(f"rate_limit_bps {rate_limit_bps}")
        print(
            f"LAG member {interface.name} on device {interface.device.name} has "
            f"{', '.join(stale)} but its LAG {interface.lag.name} does not",
            url_strip_api(interface.url),
        )


def check_participant_ports_have_services(netbox: pynetbox.api) -> None:
    # Each participant port is modelled by exactly one netbox-services Service (design doc 009):
    # a `peering` service for the participant on each peering port, and a billed `l2vpn` service
    # on each live port carrying a private VLAN. `ixp_participant` on interfaces is sticky (never
    # removed by discovery), so ports are taken from `peering_port`, which follows VLAN 998.
    print("[!!] Checking that each participant port has a service")
    services_by_port = defaultdict(list)
    for service in ServicesAPI(netbox).all():
        for interface in service["interfaces"]:
            interface_id = interface["id"] if isinstance(interface, dict) else interface
            services_by_port[(service["type"], interface_id)].append(service)

    def describe(services) -> str:
        return ", ".join(s["service_id"] for s in services)

    peering_ports = [
        *netbox.dcim.interfaces.filter(tag="peering_port"),
        *netbox.dcim.interfaces.filter(tag="encapsulated_peering_port"),
    ]
    for interface in peering_ports:
        # Missing participants are reported by check_peering_port_custom_field_participant
        if not (participant := interface.custom_fields.get("participant")):
            continue
        services = [
            s
            for s in services_by_port[("peering", interface.id)]
            if s["tenant"] == participant["id"]
        ]
        if len(services) != 1:
            print(
                f"Peering port {interface.name} on device {interface.device.name} has "
                f"{len(services) or 'no'} `peering` services for {participant['name']}"
                + (f": {describe(services)}" if services else ""),
                url_strip_api(interface.url),
            )

    device_statuses = {}
    for vlan in netbox.ipam.vlans.filter(group="exchange_fabric_vlans"):
        if not PVLAN_NAME_RE.match(vlan.name):
            continue
        for interface in netbox.dcim.interfaces.filter(vlan_id=vlan.id):
            device_id = interface.device.id
            if device_id not in device_statuses:
                device_statuses[device_id] = netbox.dcim.devices.get(device_id).status.value
            if device_statuses[device_id] not in LIVE_DEVICE_STATUSES:
                continue
            services = services_by_port[("l2vpn", interface.id)]
            if len(services) != 1:
                print(
                    f"{vlan.name} port {interface.name} on device {interface.device.name} has "
                    f"{len(services) or 'no'} `l2vpn` services"
                    + (f": {describe(services)}" if services else ""),
                    url_strip_api(interface.url),
                )
            elif not services[0]["tenant"]:
                print(
                    f"{vlan.name} port {interface.name} on device {interface.device.name}: "
                    f"service {services[0]['service_id']} has no billing tenant",
                    url_strip_api(interface.url),
                )


def netbox_client(operator_config) -> pynetbox.core.api.Api:
    return pynetbox.api(
        operator_config["netbox_api_endpoint"], token=operator_config["netbox_api_key"]
    )


def asn_to_n(asname: str) -> int:
    matches = re.match(r"as(\d+)", asname, re.IGNORECASE)
    if not matches:
        raise ValueError(f"AS Name: {asname!r} is un-parsable")
    return int(matches.group(1))


def check_participant_has_ports(netbox: pynetbox.core.api.Api) -> None:
    print("[!!] Check that each participant has some `peering_port` ports")
    for participant in netbox.tenancy.tenants.filter(tag="ixp_participant"):
        participant_interfaces = netbox.dcim.interfaces.filter(
            cf__participant=participant.id, tag="peering_port"
        )
        if not participant_interfaces:
            print(
                f"Participant {participant.name} has no `peering_port` tagged interfaces",
                url_strip_api(participant.url),
            )


def check_participant_has_ips(netbox: pynetbox.core.api.Api) -> None:
    print("[!!] Check that each participant has some `peering_lan_ip` IPs")
    for participant in netbox.tenancy.tenants.filter(tag="ixp_participant"):
        participant_ips = netbox.ipam.ip_addresses.filter(tenant_id=participant.id)
        if not participant_ips:
            print(
                f"Participant {participant.name} has no IPs",
                url_strip_api(participant.url),
            )


def check_ixp_participant_ip_tenant(netbox: pynetbox.core.api.Api) -> None:
    print("[!!] Check that IXP participant IPs have correct Tenant set")
    for ip in netbox.ipam.ip_addresses.filter(tag="ixp_participant"):
        if not ip.tenant:
            print(
                f"IXP Participant IP {ip.address} is missing Tenant",
                url_strip_api(ip.url),
            )
            continue

        # Check if the tenant has the ixp_participant tag
        tenant_tag_slugs = [tag.slug for tag in ip.tenant.tags]
        if "ixp_participant" not in tenant_tag_slugs:
            print(
                f"IXP Participant IP {ip.address} has Tenant {ip.tenant.name} "
                f"but Tenant is missing `ixp_participant` tag",
                url_strip_api(ip.url),
            )


def netbox_lint(operator_config: Dict[str, str]) -> None:
    netbox = netbox_client(operator_config)
    check_peering_lan_ip_tags(netbox=netbox)
    check_peering_lan_ip_participant_lag(netbox=netbox)
    check_peering_vlan_ports(netbox=netbox)
    check_peering_port_custom_field_participant(netbox=netbox)
    check_peering_port_participant_matches_description_asn(netbox=netbox)
    check_lag_member_participant_matches_lag(netbox=netbox)
    check_participant_ports_have_services(netbox=netbox)
    check_participant_has_ports(netbox=netbox)
    check_participant_has_ips(netbox=netbox)
    check_ixp_participant_ip_tenant(netbox=netbox)


if __name__ == "__main__":
    # Check for shared config
    if not (OPERATOR_CONFIG_FILE := os.environ.get("SFMIX_OPERATOR_CONFIG_FILE")):
        OPERATOR_CONFIG_FILE = "/opt/sfmix/operator_config.yaml"
    with open(OPERATOR_CONFIG_FILE) as f:
        operator_config = yaml.safe_load(f)
    for required_config in [
        "netbox_api_endpoint",
        "netbox_api_key",
    ]:
        if not operator_config.get(required_config):
            sys.exit(f"No {required_config} in {OPERATOR_CONFIG_FILE}")

    netbox_lint(operator_config=operator_config)
