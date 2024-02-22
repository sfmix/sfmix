#!/usr/bin/env python3
from typing import Dict, Iterable, List, Tuple
import os
import pynetbox
import ipaddress
import json
import subprocess
import logging

class CustomFormatter(logging.Formatter):
    grey = "\x1b[37;40m"
    green = "\x1b[37;40m"
    yellow = "\x1b[33;40m"
    red = "\x1b[31;40m"
    bold_red = "\x1b[31;101m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

logger = logging.getLogger("mac_discovery")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

def discover_ip_map(peering_lan: str) -> dict[str, str]:
    logger.debug(f"Discovering an IP Map for {peering_lan}")
    lookup_server = lookup_server_for_peering_lan(peering_lan)

    peering_lan_routes_json = subprocess.check_output(
        f"ssh {lookup_server} '"
        f"  ip --json route get {ipaddress.ip_network(peering_lan).network_address}"
        "'",
        shell=True
    ).decode()
    peering_lan_routes = json.loads(peering_lan_routes_json)
    peering_lan_route = peering_lan_routes[0]
    peering_lan_device = peering_lan_route["dev"]

    logger.debug(f"Scanning IPs in {peering_lan}")
    peering_lan_neighbors_json = subprocess.check_output(
        f"ssh {lookup_server} '"
        f"  fping -c 1 {' '.join(list_ips_for_peering_lan(peering_lan))} --quiet >/dev/null 2>&1; "
        f"  ip --json neighbor show dev {peering_lan_device} to {peering_lan}"
        "'",
        shell=True
    ).decode()
    ip_map: Dict[str, str] = {}
    peering_lan_neighbors = json.loads(peering_lan_neighbors_json)
    for peering_lan_neighbor in peering_lan_neighbors:
        if mac := peering_lan_neighbor.get("lladdr"):
            ip_map[peering_lan_neighbor["dst"]] = mac
    return ip_map


def list_ips_for_peering_lan(peering_lan: str) -> List[str]:
    return [
        str(ipaddress.ip_interface(netbox_ip_address.address).ip)
        for netbox_ip_address in netbox_api_client().ipam.ip_addresses.filter(
            parent=peering_lan
        )
    ]


def update_netbox_ip_macs(ip_mac_map: Dict[str, str]) -> None:
    netbox = netbox_api_client()
    for ip, new_mac in ip_mac_map.items():
        try:
            existing_ip = netbox.ipam.ip_addresses.get(address=ip)
        except ValueError as e:
            logger.critical(f"Possible duplicate IP: {ip}")
            raise e
        if not existing_ip:
            raise RuntimeError(
                f"IP {ip} was initially detected, but is now missing from Netbox"
            )
        old_mac = existing_ip.custom_fields['participant_mac_address']
        if old_mac != new_mac:
            logger.info(f"Updating MAC address: {ip} {old_mac} -> {new_mac}")
            existing_ip.custom_fields['participant_mac_address'] = new_mac
            existing_ip.save()
        else:
            logger.debug(f"Existing MAC Matches IP: {ip} -> {new_mac}")


def lookup_server_for_peering_lan(peering_lan: str) -> str:
    """
    For now, we just have the one Linux box and a single peering LAN, but this
    method could be extended in the future to support multiple Peering LANs
    """
    return "mgmt.rs-linux.sfmix.org"


def list_peering_lans() -> List[str]:
    """
    List the Peering LAN VLANs in Netbox, and return a listing of the associated
    peering LAN IP prefixes
    """
    logger.debug("Listing all Peering LANs from Netbox")
    netbox = netbox_api_client()
    peering_lans = []
    for vlan in netbox.ipam.vlans.filter(tag="peering_lan"):
        for ip_prefix in netbox.ipam.prefixes.filter(vlan_id=vlan.id):
            peering_lans.append(ip_prefix.prefix)
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


if __name__ == "__main__":
    ip_mac_map: Dict[str, str] = dict()
    for peering_lan in list_peering_lans():
        ip_mac_map.update(discover_ip_map(peering_lan))
    update_netbox_ip_macs(ip_mac_map)
