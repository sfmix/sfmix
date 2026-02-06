#!/usr/bin/env python3
import argparse
import ipaddress
import json
import logging
import netrc
import re
import os
import subprocess
from typing import Any, Dict, Iterable, List, Set, Tuple

import pyeapi
import pynetbox


class CustomFormatter(logging.Formatter):
    whiteblack = "\x1b[37;40m"
    green = "\x1b[37;40m"
    yellow = "\x1b[33;40m"
    red = "\x1b[31;40m"
    bold_red = "\x1b[31;101m"
    reset = "\x1b[0m"
    message_format = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    )
    FORMATS = {
        logging.DEBUG: whiteblack + message_format + reset,
        logging.INFO: green + message_format + reset,
        logging.WARNING: yellow + message_format + reset,
        logging.ERROR: red + message_format + reset,
        logging.CRITICAL: bold_red + message_format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


logger = logging.getLogger("discovery")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

VLAN_MAC = Tuple[int, str]
VLAN_IP = Tuple[int, str]
PORT = Tuple[str, str]


def get_eapi_connection_parameters() -> Dict[str, Any]:
    connection_paramters: Dict[str, Any] = {}
    netrc_file = netrc.netrc()
    NETRC_HOST = "sfmix.org"
    auth_info = netrc_file.authenticators(NETRC_HOST)
    if not auth_info:
        raise ValueError("Couldn't get auth_info from netrc for ", NETRC_HOST)
    else:
        username, _, password = auth_info
        if not (username and password):
            raise ValueError(
                "Couldn't get username/password from netrc for ", NETRC_HOST
            )
        connection_paramters["username"] = username
        connection_paramters["password"] = password
        connection_paramters["transport"] = "https"
        connection_paramters["return_node"] = True
    return connection_paramters


def expand_vlan_id_ranges(vlan_id_ranges: str) -> Set[int]:
    result = set()
    for r in vlan_id_ranges.split(","):
        if "-" in r:
            start, end = r.split("-")
            for vlan_id in range(int(start), int(end) + 1):
                result.add(vlan_id)
        else:
            result.add(int(r))
    return result


def discover_vlan_ip_mac_map(vlan: int, peering_lan_prefix: str) -> Dict[VLAN_IP, str]:
    logger.debug(f"Discovering an IP Map for {peering_lan_prefix}")
    lookup_server = lookup_server_for_peering_lan(vlan, peering_lan_prefix)

    peering_lan_routes_json = subprocess.check_output(
        f"ssh {lookup_server} '"
        f"  ip --json route get {ipaddress.ip_network(peering_lan_prefix).network_address}"
        "'",
        shell=True,
    ).decode()
    peering_lan_routes = json.loads(peering_lan_routes_json)
    peering_lan_route = peering_lan_routes[0]
    peering_lan_device = peering_lan_route["dev"]

    logger.debug(f"Scanning IPs in {peering_lan_prefix}")
    peering_lan_ips = set(list_ips_for_peering_lan(peering_lan_prefix))
    peering_lan_neighbors_json = subprocess.check_output(
        f"ssh {lookup_server} '"
        f"  fping -c 1 {' '.join(peering_lan_ips)} --quiet >/dev/null 2>&1; "
        f"  ip --json neighbor show dev {peering_lan_device} to {peering_lan_prefix}"
        "'",
        shell=True,
    ).decode()
    vlan_ip_mac_map: Dict[VLAN_IP, str] = {}
    peering_lan_neighbors = json.loads(peering_lan_neighbors_json)
    for peering_lan_neighbor in peering_lan_neighbors:
        ip = peering_lan_neighbor.get("dst")
        mac = peering_lan_neighbor.get("lladdr")
        if mac and ip in peering_lan_ips:
            mac = mac.lower()
            vlan_ip_mac_map[(vlan, ip)] = mac
    return vlan_ip_mac_map


def list_ips_for_peering_lan(peering_lan: str) -> List[str]:
    return [
        str(ipaddress.ip_interface(netbox_ip_address.address).ip)
        for netbox_ip_address in netbox_api_client().ipam.ip_addresses.filter(
            parent=peering_lan
        )
    ]


def update_netbox_ip_macs(vlan_ip_mac_map: Dict[VLAN_IP, str]) -> None:
    netbox = netbox_api_client()
    for (vlan, ip), new_mac in vlan_ip_mac_map.items():
        try:
            existing_ip = netbox.ipam.ip_addresses.get(address=ip)
        except ValueError as e:
            logger.critical(f"Possible duplicate IP: {ip}")
            raise e
        if not existing_ip:
            if ip == "2001:504:30::ba04:7787:1":
                # FIXME
                logger.warning("Edgoo special case")
                continue
            raise RuntimeError(
                f"IP {ip} was initially detected, but is now missing from Netbox"
            )
        old_mac = existing_ip.custom_fields["participant_mac_address"]
        if old_mac != new_mac:
            logger.info(f"Updating MAC address: {ip} {old_mac} -> {new_mac}")
            existing_ip.custom_fields["participant_mac_address"] = new_mac
            existing_ip.save()
        else:
            logger.debug(f"Existing MAC Matches IP: {ip} -> {new_mac}")


def lookup_server_for_peering_lan(vlan: int, peering_lan: str) -> str:
    """
    For now, we just have the one Linux box and a single peering LAN, but this
    method could be extended in the future to support multiple Peering LANs
    """
    return "mgmt.rs-linux.sfmix.org"


def list_peering_lans() -> List[Tuple[int, str]]:
    """
    List the Peering LAN VLANs in Netbox, and return a listing of the associated
    peering LAN IP prefixes
    """
    logger.debug("Listing all Peering LANs from Netbox")
    netbox = netbox_api_client()
    peering_lans = []
    for vlan in netbox.ipam.vlans.filter(tag="peering_lan"):
        for ip_prefix in netbox.ipam.prefixes.filter(vlan_id=vlan.id):
            peering_lans.append((vlan.vid, ip_prefix.prefix))
    return peering_lans


def get_netbox_api_token() -> str:
    netbox_api_token = os.environ.get("NETBOX_API_TOKEN")
    if not netbox_api_token:
        raise RuntimeError("Environment variable NETBOX_API_TOKEN is not set")
    return netbox_api_token


def get_netbox_api_endpoint() -> str:
    netbox_api_endpoint = os.environ.get("NETBOX_API_ENDPOINT")
    if not netbox_api_endpoint:
        raise RuntimeError("Environment variable NETBOX_API_ENDPOINT is not set")
    return netbox_api_endpoint


def netbox_api_client() -> pynetbox.core.api.Api:
    return pynetbox.api(get_netbox_api_endpoint(), token=get_netbox_api_token())


def list_peering_switch_hostnames() -> List[str]:
    """
    List the Peering Switches in Netbox, and return a listing of the associated
    hostnames
    """
    logger.debug("Listing all Peering Switches from Netbox")
    netbox = netbox_api_client()
    peering_switches = []
    for device in netbox.dcim.devices.filter(role="peering_switch"):
        if not "cr1" in device.hostname:
          peering_switches.append(device.hostname)
    return peering_switches


def discover_vlan_mac_port_map(switch_hostname: str) -> Dict[VLAN_MAC, PORT]:
    """
    Discover the VLAN/MAC to port mapping for a given switch, and return a dictionary
    of the mapping.
    """
    logger.debug(f"Discovering VLAN/MAC to port mapping for {switch_hostname}")
    mac_port_map: Dict[VLAN_MAC, PORT] = dict()
    connection_params = get_eapi_connection_parameters()
    connection_params["host"] = switch_hostname
    switch = pyeapi.connect(**connection_params)
    response = switch.enable(["show mac address-table"])

    for mac_table_entry in response[0]["result"]["unicastTable"]["tableEntries"]:
        if mac_table_entry["interface"] == "Vxlan1":
            continue
        vlan_mac = (mac_table_entry["vlanId"], mac_table_entry["macAddress"].lower())
        port = (switch_hostname, mac_table_entry["interface"])
        mac_port_map[vlan_mac] = port

    return mac_port_map


def update_netbox_ip_participant_lag(ip_port_map: Dict[str, PORT]) -> None:
    netbox = netbox_api_client()
    for ip, (hostname, interface) in ip_port_map.items():
        nb_interface = netbox.dcim.interfaces.get(device=hostname, name=interface)
        nb_ip_address = netbox.ipam.ip_addresses.get(address=ip)
        if not nb_ip_address:
            raise RuntimeError(f"IP address is missing from Netbox: {ip}")
        if (
            not nb_ip_address.custom_fields["participant_lag"]
            or nb_ip_address.custom_fields["participant_lag"]["id"] != nb_interface.id
        ):
            logger.info(
                f"Updating participant_lag for IP address: {ip} -> {nb_interface.device!r}/{nb_interface!r}"
            )
            nb_ip_address.custom_fields["participant_lag"] = nb_interface.id
            nb_ip_address.save()
        else:
            logger.debug(f"No change for IP address: {ip}")


def discover_hardware_interfaces(device_hostname: str) -> None:
    netbox = netbox_api_client()
    connection_params = get_eapi_connection_parameters()
    connection_params["host"] = device_hostname
    logger.info(f"discover_hardware_interfaces: {device_hostname}")
    switch = pyeapi.connect(**connection_params)
    response = switch.enable(
        [
            "show interfaces",
            "show version",
            "show interfaces switchport",
            "show interfaces status",
        ]
    )

    interfaces_response = response[0]["result"]["interfaces"]
    show_version_response = response[1]["result"]
    interfaces_switchport_response = response[2]["result"]["switchports"]
    interfaces_statuses = response[3]["result"]["interfaceStatuses"]
    model = show_version_response["modelName"].upper()

    exchange_vlans = list(netbox.ipam.vlans.filter(group="exchange_fabric_vlans"))
    exchange_vlan_map = {
        exchange_vlan.vid: exchange_vlan for exchange_vlan in exchange_vlans
    }
    # Delete missing interfaces
    on_device_interfaces = interfaces_response.keys()
    for netbox_interface in netbox.dcim.interfaces.filter(device=device_hostname):
        if netbox_interface.name not in on_device_interfaces:
            logger.warning(
                f"Would delete interface (uncomment the code): {netbox_interface.device!r}/{netbox_interface!r}"
            )
            # logger.info(
            #     f"Deleting interface: {netbox_interface.device!r}/{netbox_interface!r}"
            # )
            # netbox_interface.delete()

    # Create/Update Interfaces
    netbox_interface_type = None
    for interface_name, interface_details in interfaces_response.items():
        if interface_name == "defaults":
            continue
        eapi_interface_type = interface_details["hardware"]
        if eapi_interface_type in ["generic", "vxlan", "vlan"]:
            netbox_interface_type = "other"
        elif eapi_interface_type in ["loopback", "subinterface"]:
            netbox_interface_type = "virtual"
        elif eapi_interface_type == "portChannel":
            netbox_interface_type = "lag"
        elif eapi_interface_type == "ethernet":
            if model == "DCS-7280SR-48C6-F":
                if interface_details["bandwidth"] == 100_000_000_000:
                    netbox_interface_type = "100gbase-x-qsfp28"
                elif interface_details["bandwidth"] == 25_000_000_000:
                    netbox_interface_type = "25gbase-x-sfp28"
                elif interface_details["bandwidth"] == 10_000_000_000:
                    netbox_interface_type = "10gbase-x-sfpp"
                elif (
                    interface_details["bandwidth"] == 1_000_000_000
                    and interface_details["name"] == "Management1"
                ):
                    netbox_interface_type = "1000base-t"
                elif interface_details["bandwidth"] == 1_000_000_000:
                    netbox_interface_type = "1000base-x-sfp"
            elif model == "DCS-7280CR3-36S-F":
                if interface_details["bandwidth"] == 400_000_000_000:
                    netbox_interface_type = "400gbase-x-qsfpdd"
                elif interface_details["bandwidth"] == 200_000_000_000:
                    netbox_interface_type = "200gbase-x-qsfp56"
                elif interface_details["bandwidth"] == 100_000_000_000:
                    netbox_interface_type = "100gbase-x-qsfp28"
                elif interface_details["bandwidth"] == 10_000_000_000:
                    netbox_interface_type = "10gbase-x-sfpp"
                elif (
                    interface_details["bandwidth"] == 1_000_000_000
                    and interface_details["name"] == "Management1"
                ):
                    netbox_interface_type = "1000base-t"
                elif interface_details["bandwidth"] == 1_000_000_000:
                    netbox_interface_type = "1000base-x-sfp"
        else:
            logger.warning(f"Unknown eAPI Interface type: {eapi_interface_type!r} for {device_hostname} / {interface_name}")
        netbox_interface_speed = int(interface_details["bandwidth"] / 1_000)
        interface_description = interface_details["description"]

        netbox_interface_mode = None
        tagged_vlans = set()
        untagged_vlan = None
        if (
            interfaces_statuses.get(interface_name, {})
            .get("vlanInformation", {})
            .get("interfaceForwardingModel", "")
            == "bridged"
        ):
            if switchportInfo := interfaces_switchport_response.get(
                interface_name, {}
            ).get("switchportInfo"):
                if switchportInfo.get("mode") == "trunk":
                    netbox_interface_mode = "tagged"
                    tagged_vlans = expand_vlan_id_ranges(
                        switchportInfo.get("trunkAllowedVlans", "")
                    )
                    untagged_vlan = switchportInfo.get("trunkingNativeVlanId")
                elif switchportInfo.get("mode") in ("access", "dot1qTunnel"):
                    netbox_interface_mode = "access"
                    tagged_vlans = set()
                    untagged_vlan = (
                        interfaces_statuses.get(interface_name, {})
                        .get("vlanInformation", {})
                        .get("vlanId")
                    )

        existing_interfaces = list(
            netbox.dcim.interfaces.filter(device=device_hostname, name=interface_name)
        )
        if not existing_interfaces:
            if netbox_interface_type and netbox_interface_speed:
                logger.info(f"Creating interface: {device_hostname} / {interface_name}")
                netbox.dcim.interfaces.create(
                    device={"name": device_hostname},
                    name=interface_name,
                    type=netbox_interface_type,
                    speed=netbox_interface_speed,
                )
        else:
            logger.debug(f"Examining Interface: {device_hostname} / {interface_name}:")
            existing_interface = existing_interfaces[0]

            if existing_interface.speed != netbox_interface_speed:
                logger.info(
                    f"    Updating speed: {existing_interface.speed} -> {netbox_interface_speed}"
                )
                existing_interface.speed = netbox_interface_speed

            if existing_interface.description != interface_description:
                logger.info(
                    f"    Updating description: {existing_interface.description} -> {interface_description}"
                )
                existing_interface.description = interface_description

            if existing_interface.mode:
                existing_mode = existing_interface.mode.value
            else:
                existing_mode = None
            if existing_mode != netbox_interface_mode:
                logger.info(
                    f"    Updating mode: {existing_mode} -> {netbox_interface_mode}"
                )
                existing_interface.mode = netbox_interface_mode

            existing_tagged_vlan_ids = {
                vlan["vid"] for vlan in existing_interface.tagged_vlans
            }
            if existing_tagged_vlan_ids != tagged_vlans:
                logger.info(
                    f"    Updating tagged VLANs: {existing_tagged_vlan_ids} -> {tagged_vlans}"
                )
                if tagged_vlans:
                    existing_interface.tagged_vlans = [
                        exchange_vlan_map[vlan_id].id for vlan_id in tagged_vlans
                    ]
                else:
                    existing_interface.tagged_vlans = []

            if existing_interface.untagged_vlan:
                existing_untagged_vlan_id = existing_interface.untagged_vlan.vid
            else:
                existing_untagged_vlan_id = None

            if existing_untagged_vlan_id != untagged_vlan:
                logger.info(
                    f"    Updating untagged VLAN: {existing_untagged_vlan_id} -> {untagged_vlan}"
                )
                if untagged_vlan:
                    existing_interface.untagged_vlan = exchange_vlan_map[
                        untagged_vlan
                    ].id
                else:
                    existing_interface.untagged_vlan = None

            existing_interface.save()


def update_netbox_peering_port_tags_by_vlan() -> None:
    netbox = netbox_api_client()
    main_peering_vlan = list(
        netbox.ipam.vlans.filter(group="exchange_fabric_vlans", vid=998)
    )[0]
    for interface in netbox.dcim.interfaces.filter(vlan_id=main_peering_vlan.id):
        # Special cases
        if interface.name == "Vxlan1":
            continue
        #
        if interface.description.startswith("pve"):
            for tag_slug in ("peering_port", "ixp_infrastructure"):
                if tag_slug not in [tag["slug"] for tag in interface.tags]:
                    logger.info(
                        f"Adding {tag_slug} tag to {interface.device.name} / {interface.name}"
                    )
                    interface.tags = [{"slug": tag["slug"]} for tag in interface.tags] + [
                        {"slug": tag_slug}
                    ]
                    interface.save()
            continue
        for tag_slug in ("peering_port", "ixp_participant"):
            if tag_slug not in [tag["slug"] for tag in interface.tags]:
                logger.info(
                    f"Adding {tag_slug} tag to {interface.device.name} / {interface.name}"
                )
                interface.tags = [{"slug": tag["slug"]} for tag in interface.tags] + [
                    {"slug": tag_slug}
                ]
                interface.save()
    for interface in netbox.dcim.interfaces.filter(tag="peering_port"):
        interface_vlans = interface.tagged_vlans
        if interface.untagged_vlan:
            interface_vlans.append(interface.untagged_vlan)
        interface_vlan_ids = [vlan.id for vlan in interface_vlans]
        if main_peering_vlan.id not in interface_vlan_ids:
            logger.info(
                f"Removing peering_port tag from {interface.device.name} / {interface.name}"
            )
            interface.tags = [
                {"slug": tag["slug"]}
                for tag in interface.tags
                if tag.slug != "peering_port"
            ]
            interface.save()


def update_netbox_interface_description_asn_participant() -> None:
    netbox = netbox_api_client()
    for interface in netbox.dcim.interfaces.filter(tag="peering_port"):
        asn_from_description = re.search(r"\(AS(\d+)\)", interface.description)
        if asn_from_description:
            asn = asn_from_description.group(1)
            asn_slug = f"as{asn}"
            participants = list(netbox.tenancy.tenants.filter(slug=asn_slug))
            if len(participants) != 1:
                raise ValueError(
                    f"Could not find one participant for ASN {asn} ({asn_slug})"
                )
            participant = participants[0]
            interface.custom_fields["participant"] = participant.id
            interface.save()
        # else:
        #     raise ValueError(f"Could not find ASN in interface description \"{interface.description}\" for {interface.device.name} / {interface.name}")


def update_netbox_peering_switch_interface_ips(peering_switch_hostname: str) -> None:
    netbox = netbox_api_client()
    connection_params = get_eapi_connection_parameters()
    connection_params["host"] = peering_switch_hostname
    switch = pyeapi.connect(**connection_params)
    response = switch.enable(["show ip interface brief"])

    # Track IPs found on device
    device_ips = set()

    for interface_name, interface in response[0]["result"]["interfaces"].items():
        if "interfaceAddress" not in interface:
            continue

        ip_addr = interface["interfaceAddress"]["ipAddr"]
        if ip_addr["address"] == "0.0.0.0":
            continue

        ip_with_mask = f"{ip_addr['address']}/{ip_addr['maskLen']}"
        device_ips.add(ip_with_mask)

        nb_interface = netbox.dcim.interfaces.get(device=peering_switch_hostname, name=interface_name)

        if not nb_interface:
            logger.warning(f"Interface not found in Netbox: {peering_switch_hostname}/{interface_name}")
            continue

        existing_ips = list(netbox.ipam.ip_addresses.filter(address=ip_with_mask))

        if not existing_ips:
            logger.info(f"Creating IP {ip_with_mask} for {peering_switch_hostname}/{interface_name}")
            netbox.ipam.ip_addresses.create(
                address=ip_with_mask,
                assigned_object_type="dcim.interface",
                assigned_object_id=nb_interface.id
            )
        elif len(existing_ips) > 1:
            logger.warning(f"Multiple entries found for IP {ip_with_mask} (here, {peering_switch_hostname}/{interface_name})- skipping update")
            continue
        elif existing_ips[0].assigned_object_id != nb_interface.id:
            logger.info(f"Updating IP {ip_with_mask} assignment to {peering_switch_hostname}/{interface_name}")
            existing_ip = existing_ips[0]
            existing_ip.assigned_object_type = "dcim.interface"
            existing_ip.assigned_object_id = nb_interface.id
            existing_ip.save()

    # Remove IPs from Netbox that are no longer on device
    for nb_interface in netbox.dcim.interfaces.filter(device=peering_switch_hostname):
        for ip in netbox.ipam.ip_addresses.filter(interface_id=nb_interface.id):
            if ip.address not in device_ips:
                logger.info(f"Removing IP {ip.address} from {peering_switch_hostname}/{nb_interface.name}")
                ip.delete()

    # Set the primary IPv4 address of the device to the primary IP address on the Management1 interface
    management1_interface = netbox.dcim.interfaces.get(device=peering_switch_hostname, name="Management1")
    if management1_interface:
        primary_ip = netbox.ipam.ip_addresses.get(interface_id=management1_interface.id, family=4)
        if primary_ip:
            device = netbox.dcim.devices.get(name=peering_switch_hostname)
            logger.info(f"Setting primary IPv4 address of {peering_switch_hostname} to {primary_ip.address}")
            device.primary_ip4 = primary_ip
            device.save()
        else:
            logger.warning(f"No primary IPv4 address found on Management1 interface of {peering_switch_hostname}")
    else:
        logger.warning(f"Management1 interface not found on {peering_switch_hostname}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Network discovery and synchronization script"
    )
    parser.add_argument(
        "--sync-hardware-interfaces",
        action="store_true",
        help="Synchronize hardware interfaces to Netbox",
    )
    parser.add_argument(
        "--sync-peering-port-tags-by-vlan",
        action="store_true",
        help='Synchronize the "peering_port" tag based on VLAN',
    )
    parser.add_argument(
        "--sync-ip-macs",
        action="store_true",
        help="Synchronize IP-MAC mappings to Netbox",
    )
    parser.add_argument(
        "--sync-ip-participant-lag",
        action="store_true",
        help="Synchronize IP-Participant LAG mappings to Netbox",
    )
    parser.add_argument(
        "--sync-interface-description-asn-participant",
        action="store_true",
        help="Synchronize the ASN in the interface description as the participant in Netbox Interface custom field",
    )
    parser.add_argument("--sync-interface-ips", action="store_true", help="Synchronize interface IPs to Netbox")
    parser.add_argument(
        "--device",
        action="append",
        metavar="HOSTNAME",
        help="Limit discovery to specific device(s). Can be specified multiple times.",
    )
    parser.add_argument(
        "--list-devices",
        action="store_true",
        help="List available peering switch hostnames and exit",
    )
    args = parser.parse_args()

    peering_switch_hostnames = list_peering_switch_hostnames()

    if args.list_devices:
        for hostname in sorted(peering_switch_hostnames):
            print(hostname)
        raise SystemExit(0)

    if args.device:
        unknown = set(args.device) - set(peering_switch_hostnames)
        if unknown:
            parser.error(f"Unknown device(s): {', '.join(sorted(unknown))}. Use --list-devices to see available devices.")
        peering_switch_hostnames = [h for h in peering_switch_hostnames if h in args.device]

    if args.sync_hardware_interfaces:
        for peering_switch_hostname in peering_switch_hostnames:
            discover_hardware_interfaces(peering_switch_hostname)
    else:
        logger.info(
            "Skipping hardware interface discovery. To enable: --sync-hardware-interfaces"
        )

    vlan_ip_mac_map: Dict[VLAN_IP, str] = dict()
    for vlan_id, peering_lan_prefix in list_peering_lans():
        vlan_ip_macs = discover_vlan_ip_mac_map(vlan_id, peering_lan_prefix)
        vlan_ip_mac_map.update(vlan_ip_macs)

    if args.sync_ip_macs:
        update_netbox_ip_macs(vlan_ip_mac_map)
    else:
        logger.info("Skipping IP MAC sync. To enable: --sync-ip-macs")

    vlan_mac_port_map: Dict[VLAN_MAC, PORT] = dict()
    for peering_switch_hostname in peering_switch_hostnames:
        _vlan_mac_port_map = discover_vlan_mac_port_map(peering_switch_hostname)
        vlan_mac_port_map.update(_vlan_mac_port_map)

    ip_port_map: Dict[str, PORT] = dict()
    for (vlan, ip), mac in vlan_ip_mac_map.items():
        port = vlan_mac_port_map.get((vlan, mac))
        if not port:
            logger.warning(f"Warning, no port found for {vlan}, {mac} :/ ... Skipping")
            continue
        ip_port_map[ip] = port

    if args.sync_ip_participant_lag:
        update_netbox_ip_participant_lag(ip_port_map)
    else:
        logger.info(
            "Skipping IP participant lag sync. To enable: --sync-ip-participant-lag"
        )

    if args.sync_peering_port_tags_by_vlan:
        update_netbox_peering_port_tags_by_vlan()
    else:
        logger.info(
            "Skipping peering port tag sync. To enable: --sync-peering-port-tags-by-vlan"
        )

    if args.sync_interface_description_asn_participant:
        update_netbox_interface_description_asn_participant()
    else:
        logger.info(
            "Skipping interface description ASN to participant sync. To enable: --sync-interface-description-asn-participant"
        )

    if args.sync_interface_ips:
        for peering_switch_hostname in peering_switch_hostnames:
            update_netbox_peering_switch_interface_ips(peering_switch_hostname)
    else:
        logger.info("Skipping interface IP sync. To enable: --sync-interface-ips")
