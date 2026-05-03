#!/usr/bin/env python3
from abc import ABC, abstractmethod
import argparse
import ipaddress
import json
import logging
import netrc
import re
import os
import subprocess
from typing import Any, Dict, Generator, List, Optional, Set, Tuple, Type

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


# ── Nokia SR-OS constants ─────────────────────────────────────────────

NOKIA_SROS_STATE_NS = "urn:nokia.com:sros:ns:yang:sr:state"
NETCONF_EOM = "]]>]]>"

SROS_PORT_TYPE_MAP = {
    "400-gig-ethernet":        ("400gbase-x-qsfpdd", 400_000_000),
    "100-gig-ethernet":        ("100gbase-x-qsfp28", 100_000_000),
    "40-gig-ethernet":         ("40gbase-x-qsfpp",    40_000_000),
    "25-gig-ethernet":         ("25gbase-x-sfp28",    25_000_000),
    "10-gig-ethernet":         ("10gbase-x-sfpp",     10_000_000),
    "gig-ethernet":            ("1000base-x-sfp",      1_000_000),
    "gig-ethernet-sfp":        ("1000base-x-sfp",      1_000_000),
    "10/100/gig-ethernet-tx":  ("1000base-t",          1_000_000),
    "10/100/gig-ethernet-sfp": ("1000base-x-sfp",      1_000_000),
}

NOKIA_CORE_SAP_NAMES = {"transit-peering-lan", "lag-core-1"}
NOKIA_TENANT_SAP_RE = re.compile(r"^as(\d+)", re.IGNORECASE)


# ── Juniper JunOS constants ───────────────────────────────────────────

JUNIPER_IFACE_TYPE_MAP: Dict[str, Tuple[str, Optional[int]]] = {
    "et-":  ("100gbase-x-qsfp28", 100_000_000),
    "xe-":  ("10gbase-x-sfpp",     10_000_000),
    "ge-":  ("1000base-t",          1_000_000),
    "ae":   ("lag",                      None),
    "irb":  ("virtual",                  None),
    "lo0":  ("virtual",                  None),
    "fxp":  ("1000base-t",          1_000_000),
}

JUNIPER_MGMT_INTERFACES = ("fxp0", "em0", "em1")

JUNIPER_INTERNAL_PREFIXES = (
    "pfe-", "pfh-", "cbp", "dsc", "esi", "gre", "ipip",
    "jsrv", "lsi", "mtun", "pimd", "pime", "pip0", "pp0",
    "rbeb", "tap", "vtep",
)

JUNIPER_BUILTIN_INSTANCES = frozenset({
    "master", "__juniper_private1__", "__juniper_private2__",
    "__juniper_private3__", "__juniper_private4__", "__juniper_mgmt_evo__",
    "mgmt_junos",
})

JUNIPER_TENANT_IFACE_RE = re.compile(r"^as(\d+)", re.IGNORECASE)


# ── EOS constants ─────────────────────────────────────────────────────

CORE_PORT_DESCRIPTION_PREFIXES = ("Core:", "Transport", "Transit:", "Access:")


# ── NetBox API helpers ────────────────────────────────────────────────


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


def _graphql_query(query: str, variables: Optional[Dict] = None) -> Dict:
    """Execute a GraphQL query against the NetBox /graphql/ endpoint."""
    import urllib.request as _urlreq
    endpoint = get_netbox_api_endpoint().rstrip("/") + "/graphql/"
    payload = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = _urlreq.Request(
        endpoint,
        data=payload,
        headers={
            "Authorization": f"Token {get_netbox_api_token()}",
            "Content-Type": "application/json",
        },
    )
    with _urlreq.urlopen(req, timeout=60) as resp:
        result = json.loads(resp.read())
    if "errors" in result:
        raise RuntimeError(f"NetBox GraphQL error: {result['errors']}")
    return result.get("data", {})


def _prefetch_nb_interfaces(netbox: Any, device_name: str) -> Dict[str, Any]:
    """Return {interface_name: pynetbox_object} for all interfaces on device_name (1 API call)."""
    return {
        iface.name: iface
        for iface in netbox.dcim.interfaces.filter(device=device_name)
    }


def _prefetch_device_ips(device_name: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Fetch every interface and its assigned IPs for device_name via a single GraphQL query.

    Returns (ifaces_by_name, ips_by_address):
      ifaces_by_name  — {name: {"id": int}}
      ips_by_address  — {address: {"id": int, "interface_id": int, "interface_name": str}}
    """
    data = _graphql_query(
        """
        query($device: String!) {
          interface_list(filters: { device: { name: { exact: $device } } }) {
            id name
            ip_addresses { id address }
          }
        }
        """,
        {"device": device_name},
    )
    ifaces_by_name: Dict[str, Any] = {}
    ips_by_address: Dict[str, Any] = {}
    for iface in data.get("interface_list", []):
        ifaces_by_name[iface["name"]] = {"id": int(iface["id"])}
        for ip in iface.get("ip_addresses", []):
            ips_by_address[ip["address"]] = {
                "id": int(ip["id"]),
                "interface_id": int(iface["id"]),
                "interface_name": iface["name"],
            }
    return ifaces_by_name, ips_by_address


# ── Credential helpers ────────────────────────────────────────────────


def get_eapi_connection_parameters() -> Dict[str, Any]:
    connection_parameters: Dict[str, Any] = {}
    netrc_file = netrc.netrc()
    NETRC_HOST = "sfmix.org"
    auth_info = netrc_file.authenticators(NETRC_HOST)
    if not auth_info:
        raise ValueError("Couldn't get auth_info from netrc for ", NETRC_HOST)
    username, _, password = auth_info
    if not (username and password):
        raise ValueError("Couldn't get username/password from netrc for ", NETRC_HOST)
    connection_parameters["username"] = username
    connection_parameters["password"] = password
    connection_parameters["transport"] = "https"
    connection_parameters["return_node"] = True
    return connection_parameters


def _get_netconf_ssh_credentials() -> Dict[str, str]:
    """Get SSH credentials for NETCONF devices (Nokia SR-OS, Juniper JunOS).

    Checks NOKIA_SSH_USERNAME / NOKIA_SSH_PASSWORD env vars first,
    then falls back to the 'sfmix.org' netrc entry.
    """
    username = os.environ.get("NOKIA_SSH_USERNAME")
    password = os.environ.get("NOKIA_SSH_PASSWORD")
    if username and password:
        return {"username": username, "password": password}
    netrc_file = netrc.netrc()
    auth_info = netrc_file.authenticators("sfmix.org")
    if not auth_info:
        raise ValueError(
            "No NETCONF SSH credentials found. "
            "Set NOKIA_SSH_USERNAME/NOKIA_SSH_PASSWORD or add sfmix.org to ~/.netrc"
        )
    username, _, password = auth_info
    if not (username and password):
        raise ValueError("Incomplete NETCONF credentials in netrc")
    return {"username": username, "password": password}


# ── VLAN / IP / MAC discovery helpers ────────────────────────────────


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


def update_netbox_ip_macs(
    vlan_ip_mac_map: Dict[VLAN_IP, str], dry_run: bool = False
) -> None:
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
            logger.info(
                f"{'[DRY-RUN] Would update' if dry_run else 'Updating'}"
                f" MAC address: {ip} {old_mac} -> {new_mac}"
            )
            if not dry_run:
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
    """List the Peering LAN VLANs in Netbox with their associated IP prefixes."""
    logger.debug("Listing all Peering LANs from Netbox")
    netbox = netbox_api_client()
    peering_lans = []
    for vlan in netbox.ipam.vlans.filter(tag="peering_lan"):
        for ip_prefix in netbox.ipam.prefixes.filter(vlan_id=vlan.id):
            peering_lans.append((vlan.vid, ip_prefix.prefix))
    return peering_lans


def update_netbox_ip_participant_lag(
    ip_port_map: Dict[str, PORT], dry_run: bool = False
) -> None:
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
                f"{'[DRY-RUN] Would update' if dry_run else 'Updating'}"
                f" participant_lag for IP address:"
                f" {ip} -> {nb_interface.device!r}/{nb_interface!r}"
            )
            if not dry_run:
                nb_ip_address.custom_fields["participant_lag"] = nb_interface.id
                nb_ip_address.save()
        else:
            logger.debug(f"No change for IP address: {ip}")


# ── Nokia NETCONF helpers ─────────────────────────────────────────────


def _nokia_netconf_get_ports(
    management_host: str, username: str, password: str
) -> List[Dict[str, str]]:
    """Query Nokia SR-OS via NETCONF for port state."""
    import xml.etree.ElementTree as ET

    hello = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
        '<capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities>'
        f'</hello>{NETCONF_EOM}'
    )
    rpc = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">'
        '<get><filter type="subtree">'
        f'<state xmlns="{NOKIA_SROS_STATE_NS}"><port/></state>'
        f'</filter></get></rpc>{NETCONF_EOM}'
    )
    close_rpc = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">'
        f'<close-session/></rpc>{NETCONF_EOM}'
    )

    result = subprocess.run(
        [
            "sshpass", f"-p{password}",
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", "830",
            f"{username}@{management_host}",
            "-s", "netconf",
        ],
        input=(hello + rpc + close_rpc).encode(),
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"NETCONF to {management_host} failed: {stderr}")

    output = result.stdout.decode("utf-8", errors="replace")
    parts = output.split(NETCONF_EOM)
    if len(parts) < 2:
        raise RuntimeError(f"NETCONF: no RPC reply from {management_host}")
    reply_xml = parts[1].strip()

    if "<rpc-error>" in reply_xml:
        raise RuntimeError(f"NETCONF RPC error from {management_host}")

    reply_xml = re.sub(r'</?[a-zA-Z0-9_-]+:', '<', reply_xml)
    reply_xml = re.sub(r'xmlns[^"]*"[^"]*"', '', reply_xml)

    m = re.search(r'<data[^>]*>(.*)</data>', reply_xml, re.DOTALL)
    if not m:
        return []
    data_xml = m.group(1).strip()
    if not data_xml:
        return []

    ports = []
    try:
        root = ET.fromstring(f"<root>{data_xml}</root>")
    except ET.ParseError as e:
        logger.error(f"Failed to parse NETCONF XML from {management_host}: {e}")
        return []

    for state_elem in root:
        tag = state_elem.tag.split("}")[-1] if "}" in state_elem.tag else state_elem.tag
        if tag != "state":
            continue
        for port_elem in state_elem:
            ptag = port_elem.tag.split("}")[-1] if "}" in port_elem.tag else port_elem.tag
            if ptag != "port":
                continue
            port_info: Dict[str, str] = {}
            for child in port_elem:
                ctag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if ctag in ("port-id", "oper-state", "port-class", "type") and child.text:
                    port_info[ctag] = child.text.strip()
            if "port-id" in port_info:
                ports.append(port_info)

    return ports


def _nokia_netconf_get_vprn_interfaces(
    management_host: str, username: str, password: str
) -> List[Dict[str, str]]:
    """Query Nokia SR-OS via NETCONF for VPRN service interfaces (SAPs)."""
    import xml.etree.ElementTree as ET

    hello = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
        '<capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities>'
        f'</hello>{NETCONF_EOM}'
    )
    rpc = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">'
        '<get><filter type="subtree">'
        f'<state xmlns="{NOKIA_SROS_STATE_NS}">'
        '<service><vprn><interface/></vprn></service>'
        f'</state>'
        f'</filter></get></rpc>{NETCONF_EOM}'
    )
    close_rpc = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">'
        f'<close-session/></rpc>{NETCONF_EOM}'
    )

    result = subprocess.run(
        [
            "sshpass", f"-p{password}",
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", "830",
            f"{username}@{management_host}",
            "-s", "netconf",
        ],
        input=(hello + rpc + close_rpc).encode(),
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"NETCONF VPRN query to {management_host} failed: {stderr}")

    output = result.stdout.decode("utf-8", errors="replace")
    parts = output.split(NETCONF_EOM)
    if len(parts) < 2:
        raise RuntimeError(f"NETCONF: no RPC reply from {management_host}")
    reply_xml = parts[1].strip()

    if "<rpc-error>" in reply_xml:
        raise RuntimeError(f"NETCONF VPRN RPC error from {management_host}")

    reply_xml = re.sub(r'</?[a-zA-Z0-9_-]+:', '<', reply_xml)
    reply_xml = re.sub(r'xmlns[^"]*"[^"]*"', '', reply_xml)

    m = re.search(r'<data[^>]*>(.*)</data>', reply_xml, re.DOTALL)
    if not m:
        return []
    data_xml = m.group(1).strip()
    if not data_xml:
        return []

    interfaces = []
    try:
        root = ET.fromstring(f"<root>{data_xml}</root>")
    except ET.ParseError as e:
        logger.error(f"Failed to parse VPRN NETCONF XML from {management_host}: {e}")
        return []

    for state_elem in root.iter():
        tag = state_elem.tag.split("}")[-1] if "}" in state_elem.tag else state_elem.tag
        if tag != "vprn":
            continue
        vprn_name = ""
        for child in state_elem:
            ctag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if ctag == "service-name" and child.text:
                vprn_name = child.text.strip()
        if not vprn_name:
            continue
        for child in state_elem:
            ctag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if ctag != "interface":
                continue
            iface_info: Dict[str, str] = {"vprn_name": vprn_name}
            for fc in child:
                ftag = fc.tag.split("}")[-1] if "}" in fc.tag else fc.tag
                if ftag == "interface-name" and fc.text:
                    iface_info["interface_name"] = fc.text.strip()
                elif ftag == "oper-state" and fc.text:
                    iface_info["oper_state"] = fc.text.strip()
                elif ftag == "sap":
                    for sc in fc:
                        stag = sc.tag.split("}")[-1] if "}" in sc.tag else sc.tag
                        if stag == "sap-id" and sc.text:
                            iface_info["sap_id"] = sc.text.strip()
            if "interface_name" in iface_info:
                interfaces.append(iface_info)

    return interfaces


# ── Device discovery class hierarchy ─────────────────────────────────


class DeviceDiscovery(ABC):
    """Abstract base for per-device discovery and NetBox synchronization.

    Class hierarchy is platform-based (how to connect), not role-based.
    Each subclass handles a specific vendor/OS. Role-specific behavior is
    derived from self.role at runtime, allowing the same platform class to
    serve different device roles (e.g., peering switch vs transit router).

    All NetBox-modifying methods accept dry_run=True to log proposed changes
    without writing anything.
    """

    def __init__(self, device_name: str, nb_device: Any) -> None:
        self.device_name = device_name
        self.nb_device = nb_device

    @property
    def role(self) -> str:
        return self.nb_device.role.slug

    @abstractmethod
    def discover_hardware_interfaces(
        self, dry_run: bool = False, delete_interfaces: bool = False
    ) -> None:
        """Sync physical interfaces to NetBox."""

    def discover_logical_interfaces(
        self, dry_run: bool = False, delete_interfaces: bool = False
    ) -> None:
        """Sync logical/virtual interfaces to NetBox. Default: no-op."""

    @abstractmethod
    def sync_port_tags(self, dry_run: bool = False) -> None:
        """Classify and tag interfaces in NetBox."""

    def sync_interface_ips(self, dry_run: bool = False) -> None:
        """Sync interface IP addresses to NetBox. Default: no-op."""

    def get_vlan_mac_port_map(self) -> Dict[VLAN_MAC, PORT]:
        """Return VLAN+MAC → (hostname, interface) mapping. Default: empty dict."""
        return {}


class NetconfSSHDevice(DeviceDiscovery):
    """Shared base for devices accessed via NETCONF over SSH.

    Provides the management IP (from NetBox primary_ip4) and SSH credentials.
    Transport-level sharing only — not role-based.
    """

    @property
    def management_host(self) -> str:
        if not self.nb_device.primary_ip4:
            raise RuntimeError(
                f"No primary IPv4 set in NetBox for {self.device_name}"
            )
        return str(ipaddress.ip_interface(self.nb_device.primary_ip4.address).ip)

    def _get_ssh_credentials(self) -> Dict[str, str]:
        return _get_netconf_ssh_credentials()


# ── Arista EOS ────────────────────────────────────────────────────────


class AristaEOSDevice(DeviceDiscovery):
    """Discovery and NetBox sync for Arista EOS devices."""

    def discover_hardware_interfaces(
        self, dry_run: bool = False, delete_interfaces: bool = False
    ) -> None:
        netbox = netbox_api_client()
        connection_params = get_eapi_connection_parameters()
        connection_params["host"] = self.device_name
        logger.info(f"discover_hardware_interfaces: {self.device_name}")
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

        # Prefetch all existing NetBox interfaces in one call; reused for stale check and per-interface lookup
        nb_ifaces = _prefetch_nb_interfaces(netbox, self.device_name)
        on_device_interfaces = set(interfaces_response.keys())

        for iface_name, netbox_interface in nb_ifaces.items():
            if iface_name not in on_device_interfaces:
                if delete_interfaces:
                    logger.info(
                        f"{'[DRY-RUN] Would delete' if dry_run else 'Deleting'}"
                        f" interface: {netbox_interface.device!r}/{netbox_interface!r}"
                    )
                    if not dry_run:
                        netbox_interface.delete()
                else:
                    logger.debug(
                        f"Stale interface (use --delete-interfaces to remove):"
                        f" {netbox_interface.device!r}/{netbox_interface!r}"
                    )

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
                logger.warning(
                    f"Unknown eAPI Interface type: {eapi_interface_type!r}"
                    f" for {self.device_name} / {interface_name}"
                )
            netbox_interface_speed = int(interface_details["bandwidth"] / 1_000)
            interface_description = interface_details["description"]

            netbox_interface_mode = None
            tagged_vlans: Set[int] = set()
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

            existing_interface = nb_ifaces.get(interface_name)
            if existing_interface is None:
                if netbox_interface_type and netbox_interface_speed:
                    logger.info(
                        f"{'[DRY-RUN] Would create' if dry_run else 'Creating'}"
                        f" interface: {self.device_name} / {interface_name}"
                    )
                    if not dry_run:
                        netbox.dcim.interfaces.create(
                            device={"name": self.device_name},
                            name=interface_name,
                            type=netbox_interface_type,
                            speed=netbox_interface_speed,
                        )
            else:
                logger.debug(f"Examining Interface: {self.device_name} / {interface_name}:")
                changed = False

                if existing_interface.speed != netbox_interface_speed:
                    logger.info(
                        f"    {'[DRY-RUN] Would update' if dry_run else 'Updating'}"
                        f" speed: {existing_interface.speed} -> {netbox_interface_speed}"
                    )
                    if not dry_run:
                        existing_interface.speed = netbox_interface_speed
                    changed = True

                if existing_interface.description != interface_description:
                    logger.info(
                        f"    {'[DRY-RUN] Would update' if dry_run else 'Updating'}"
                        f" description: {existing_interface.description!r}"
                        f" -> {interface_description!r}"
                    )
                    if not dry_run:
                        existing_interface.description = interface_description
                    changed = True

                if existing_interface.mode:
                    existing_mode = existing_interface.mode.value
                else:
                    existing_mode = None
                if existing_mode != netbox_interface_mode:
                    logger.info(
                        f"    {'[DRY-RUN] Would update' if dry_run else 'Updating'}"
                        f" mode: {existing_mode} -> {netbox_interface_mode}"
                    )
                    if not dry_run:
                        existing_interface.mode = netbox_interface_mode
                    changed = True

                existing_tagged_vlan_ids = {
                    vlan["vid"] for vlan in existing_interface.tagged_vlans
                }
                if existing_tagged_vlan_ids != tagged_vlans:
                    logger.info(
                        f"    {'[DRY-RUN] Would update' if dry_run else 'Updating'}"
                        f" tagged VLANs: {existing_tagged_vlan_ids} -> {tagged_vlans}"
                    )
                    if not dry_run:
                        if tagged_vlans:
                            existing_interface.tagged_vlans = [
                                exchange_vlan_map[vlan_id].id for vlan_id in tagged_vlans
                            ]
                        else:
                            existing_interface.tagged_vlans = []
                    changed = True

                if existing_interface.untagged_vlan:
                    existing_untagged_vlan_id = existing_interface.untagged_vlan.vid
                else:
                    existing_untagged_vlan_id = None
                if existing_untagged_vlan_id != untagged_vlan:
                    logger.info(
                        f"    {'[DRY-RUN] Would update' if dry_run else 'Updating'}"
                        f" untagged VLAN: {existing_untagged_vlan_id} -> {untagged_vlan}"
                    )
                    if not dry_run:
                        if untagged_vlan:
                            existing_interface.untagged_vlan = exchange_vlan_map[
                                untagged_vlan
                            ].id
                        else:
                            existing_interface.untagged_vlan = None
                    changed = True

                if changed and not dry_run:
                    existing_interface.save()

    def sync_port_tags(self, dry_run: bool = False) -> None:
        """Add or remove 'core_port' tag on interfaces based on description and name."""
        netbox = netbox_api_client()
        logger.debug(f"Checking core_port tags on {self.device_name}")
        for interface in netbox.dcim.interfaces.filter(device=self.device_name):
            tag_slugs = [tag["slug"] for tag in interface.tags]
            should_be_core = _is_core_interface(
                interface.name, interface.description, tag_slugs
            )
            is_core = "core_port" in tag_slugs

            if should_be_core and not is_core:
                new_tag_slugs = tag_slugs + ["core_port"]
                logger.info(
                    f"{'[DRY-RUN] Would add' if dry_run else 'Adding'} core_port tag to"
                    f" {self.device_name} / {interface.name}"
                    f" (desc: {interface.description!r})"
                )
                if not dry_run:
                    interface.tags = [{"slug": s} for s in new_tag_slugs]
                    interface.save()
            elif not should_be_core and is_core:
                logger.info(
                    f"{'[DRY-RUN] Would remove' if dry_run else 'Removing'} core_port tag from"
                    f" {self.device_name} / {interface.name}"
                    f" (desc: {interface.description!r})"
                )
                if not dry_run:
                    interface.tags = [
                        {"slug": s} for s in tag_slugs if s != "core_port"
                    ]
                    interface.save()

    def sync_interface_ips(self, dry_run: bool = False) -> None:
        """Sync interface IPs from EOS device to NetBox."""
        netbox = netbox_api_client()
        connection_params = get_eapi_connection_parameters()
        connection_params["host"] = self.device_name
        switch = pyeapi.connect(**connection_params)
        response = switch.enable(["show ip interface brief"])

        # One GraphQL call to get all interface IDs and their existing IPs
        nb_ifaces_gql, nb_ips_by_addr = _prefetch_device_ips(self.device_name)

        device_ips: Set[str] = set()

        for interface_name, interface in response[0]["result"]["interfaces"].items():
            if "interfaceAddress" not in interface:
                continue

            ip_addr = interface["interfaceAddress"]["ipAddr"]
            if ip_addr["address"] == "0.0.0.0":
                continue

            ip_with_mask = f"{ip_addr['address']}/{ip_addr['maskLen']}"
            device_ips.add(ip_with_mask)

            nb_iface_info = nb_ifaces_gql.get(interface_name)
            if not nb_iface_info:
                logger.warning(
                    f"Interface not found in Netbox: {self.device_name}/{interface_name}"
                )
                continue
            nb_iface_id = nb_iface_info["id"]

            existing_ip_info = nb_ips_by_addr.get(ip_with_mask)

            if existing_ip_info is None:
                logger.info(
                    f"{'[DRY-RUN] Would create' if dry_run else 'Creating'}"
                    f" IP {ip_with_mask} for {self.device_name}/{interface_name}"
                )
                if not dry_run:
                    netbox.ipam.ip_addresses.create(
                        address=ip_with_mask,
                        assigned_object_type="dcim.interface",
                        assigned_object_id=nb_iface_id,
                    )
            elif existing_ip_info["interface_id"] != nb_iface_id:
                logger.info(
                    f"{'[DRY-RUN] Would update' if dry_run else 'Updating'}"
                    f" IP {ip_with_mask} assignment to {self.device_name}/{interface_name}"
                )
                if not dry_run:
                    existing_ip = netbox.ipam.ip_addresses.get(existing_ip_info["id"])
                    existing_ip.assigned_object_type = "dcim.interface"
                    existing_ip.assigned_object_id = nb_iface_id
                    existing_ip.save()

        # Remove IPs no longer on device — iterate GraphQL data, no extra REST calls
        for ip_address, ip_info in nb_ips_by_addr.items():
            if ip_address not in device_ips:
                logger.info(
                    f"{'[DRY-RUN] Would remove' if dry_run else 'Removing'}"
                    f" IP {ip_address} from {self.device_name}/{ip_info['interface_name']}"
                )
                if not dry_run:
                    ip_obj = netbox.ipam.ip_addresses.get(ip_info["id"])
                    ip_obj.delete()

        mgmt_iface_info = nb_ifaces_gql.get("Management1")
        if mgmt_iface_info:
            primary_ip_info = next(
                (
                    ip for ip, info in nb_ips_by_addr.items()
                    if info["interface_id"] == mgmt_iface_info["id"]
                    and ":" not in ip  # IPv4 only
                ),
                None,
            )
            if primary_ip_info:
                primary_ip_id = nb_ips_by_addr[primary_ip_info]["id"]
                device = netbox.dcim.devices.get(name=self.device_name)
                if not device.primary_ip4 or device.primary_ip4.id != primary_ip_id:
                    logger.info(
                        f"{'[DRY-RUN] Would set' if dry_run else 'Setting'}"
                        f" primary IPv4 of {self.device_name} to {primary_ip_info}"
                    )
                    if not dry_run:
                        device.primary_ip4 = primary_ip_id
                        device.save()
            else:
                logger.warning(
                    f"No primary IPv4 address found on Management1 of {self.device_name}"
                )
        else:
            logger.warning(f"Management1 interface not found on {self.device_name}")

    def get_vlan_mac_port_map(self) -> Dict[VLAN_MAC, PORT]:
        """Query EOS MAC address table and return VLAN+MAC → port mapping."""
        logger.debug(f"Discovering VLAN/MAC to port mapping for {self.device_name}")
        mac_port_map: Dict[VLAN_MAC, PORT] = dict()
        connection_params = get_eapi_connection_parameters()
        connection_params["host"] = self.device_name
        switch = pyeapi.connect(**connection_params)
        response = switch.enable(["show mac address-table"])

        for mac_table_entry in response[0]["result"]["unicastTable"]["tableEntries"]:
            if mac_table_entry["interface"] == "Vxlan1":
                continue
            vlan_mac = (mac_table_entry["vlanId"], mac_table_entry["macAddress"].lower())
            port = (self.device_name, mac_table_entry["interface"])
            mac_port_map[vlan_mac] = port

        return mac_port_map


# ── Nokia SR-OS ───────────────────────────────────────────────────────


class NokiaSROSDevice(NetconfSSHDevice):
    """Discovery and NetBox sync for Nokia SR-OS devices."""

    def discover_hardware_interfaces(
        self, dry_run: bool = False, delete_interfaces: bool = False
    ) -> None:
        netbox = netbox_api_client()
        creds = self._get_ssh_credentials()
        logger.info(
            f"discover_hardware_interfaces: {self.device_name}"
            f" (via {self.management_host})"
        )

        ports = _nokia_netconf_get_ports(
            self.management_host, creds["username"], creds["password"]
        )
        logger.info(f"  Found {len(ports)} ports via NETCONF")

        # Prefetch all NetBox interfaces once; reused for per-port lookup and stale sweep
        nb_ifaces = _prefetch_nb_interfaces(netbox, self.device_name)

        on_device_ports = set()
        for port_info in ports:
            port_id = port_info["port-id"]
            port_class = port_info.get("port-class", "")
            port_type = port_info.get("type", "")

            if port_class == "connector":
                continue

            on_device_ports.add(port_id)
            nb_type, nb_speed = SROS_PORT_TYPE_MAP.get(port_type, ("other", 0))

            iface = nb_ifaces.get(port_id)
            if iface is None:
                logger.info(
                    f"  {'[DRY-RUN] Would create' if dry_run else 'Creating'}"
                    f" interface: {self.device_name} / {port_id} ({nb_type})"
                )
                if not dry_run:
                    netbox.dcim.interfaces.create(
                        device={"name": self.device_name},
                        name=port_id,
                        type=nb_type,
                        speed=nb_speed,
                    )
            else:
                if iface.speed != nb_speed and nb_speed > 0:
                    logger.info(
                        f"  {'[DRY-RUN] Would update' if dry_run else 'Updating'}"
                        f" speed: {self.device_name} / {port_id}:"
                        f" {iface.speed} -> {nb_speed}"
                    )
                    if not dry_run:
                        iface.speed = nb_speed
                        iface.save()
                else:
                    logger.debug(f"  No change for {self.device_name} / {port_id}")

        if delete_interfaces:
            for nb_iface_name, nb_iface in nb_ifaces.items():
                # Only sweep physical ports (no "/"), not VPRN SAPs
                if "/" in nb_iface_name:
                    continue
                if nb_iface_name not in on_device_ports:
                    logger.info(
                        f"  {'[DRY-RUN] Would delete' if dry_run else 'Deleting'}"
                        f" interface: {self.device_name} / {nb_iface_name}"
                    )
                    if not dry_run:
                        nb_iface.delete()

    def discover_logical_interfaces(
        self, dry_run: bool = False, delete_interfaces: bool = False
    ) -> None:
        """Discover VPRN SAP interfaces via NETCONF and sync to NetBox."""
        netbox = netbox_api_client()
        creds = self._get_ssh_credentials()
        logger.info(
            f"discover_logical_interfaces: {self.device_name}"
            f" (via {self.management_host})"
        )

        vprn_ifaces = _nokia_netconf_get_vprn_interfaces(
            self.management_host, creds["username"], creds["password"]
        )
        logger.info(f"  Found {len(vprn_ifaces)} VPRN interfaces via NETCONF")

        # Prefetch all NetBox interfaces once for lookup and stale sweep
        nb_ifaces = _prefetch_nb_interfaces(netbox, self.device_name)

        for iface_info in vprn_ifaces:
            vprn_name = iface_info["vprn_name"]
            iface_name = iface_info["interface_name"]
            nb_name = f"{vprn_name}/{iface_name}"
            sap_id = iface_info.get("sap_id", "")
            desc = f"SAP {sap_id}" if sap_id else ""

            iface = nb_ifaces.get(nb_name)
            if iface is None:
                logger.info(
                    f"  {'[DRY-RUN] Would create' if dry_run else 'Creating'}"
                    f" VPRN interface: {self.device_name} / {nb_name}"
                )
                if not dry_run:
                    netbox.dcim.interfaces.create(
                        device={"name": self.device_name},
                        name=nb_name,
                        type="virtual",
                        description=desc,
                    )
            else:
                if iface.description != desc and desc:
                    logger.info(
                        f"  {'[DRY-RUN] Would update' if dry_run else 'Updating'}"
                        f" description: {nb_name}:"
                        f" {iface.description!r} -> {desc!r}"
                    )
                    if not dry_run:
                        iface.description = desc
                        iface.save()

        if delete_interfaces:
            on_device_names = {
                f"{i['vprn_name']}/{i['interface_name']}" for i in vprn_ifaces
            }
            for nb_iface_name, nb_iface in nb_ifaces.items():
                # Only sweep VPRN SAPs (contain "/"), not physical ports
                if "/" not in nb_iface_name:
                    continue
                if nb_iface_name not in on_device_names:
                    logger.info(
                        f"  {'[DRY-RUN] Would delete' if dry_run else 'Deleting'}"
                        f" VPRN interface: {self.device_name} / {nb_iface_name}"
                    )
                    if not dry_run:
                        nb_iface.delete()

    def sync_port_tags(self, dry_run: bool = False) -> None:
        """Classify and tag Nokia VPRN SAP interfaces in NetBox.

        Physical ports → core_port
        Core SAPs (transit-peering-lan, lag-core-1) → core_port
        Tenant SAPs (as<ASN>-*) → transit_peer + participant custom field
        Others → admin_port
        """
        netbox = netbox_api_client()
        logger.debug(f"Classifying SAP tags on Nokia router {self.device_name}")
        all_tenants = {t.slug: t for t in netbox.tenancy.tenants.all()}
        for interface in netbox.dcim.interfaces.filter(device=self.device_name):
            tag_slugs = [tag["slug"] for tag in interface.tags]
            name = interface.name

            # Physical ports: no "/" OR single-letter prefix (e.g. "1/1/1", "A/1")
            if "/" not in name or (
                name[0].isdigit()
                or (len(name.split("/")[0]) == 1 and name[0].isupper())
            ):
                if "core_port" not in tag_slugs:
                    new_tag_slugs = tag_slugs + ["core_port"]
                    logger.info(
                        f"{'[DRY-RUN] Would set' if dry_run else 'Setting'}"
                        f" tags: [{', '.join(sorted(tag_slugs))}]"
                        f" -> [{', '.join(sorted(new_tag_slugs))}]"
                        f" on {self.device_name} / {name}"
                    )
                    if not dry_run:
                        interface.tags = [{"slug": s} for s in new_tag_slugs]
                        interface.save()
                continue

            # VPRN SAP: "vprn-name/interface-name"
            parts = name.split("/", 1)
            if len(parts) != 2:
                continue
            _vprn_name, iface_name = parts

            if iface_name in NOKIA_CORE_SAP_NAMES:
                desired_tag = "core_port"
                remove_tags = {"admin_port", "transit_peer"}
            else:
                asn_match = NOKIA_TENANT_SAP_RE.match(iface_name)
                if asn_match:
                    asn = int(asn_match.group(1))
                    asn_slug = f"as{asn}"
                    tenant = all_tenants.get(asn_slug)
                    participants = [tenant] if tenant else []
                    if len(participants) == 1:
                        participant = participants[0]
                        if interface.custom_fields.get("participant") != participant.id:
                            old_participant = interface.custom_fields.get("participant")
                            logger.info(
                                f"{'[DRY-RUN] Would set' if dry_run else 'Setting'}"
                                f" participant: {old_participant!r} -> {asn_slug}"
                                f" on {self.device_name} / {name}"
                            )
                            if not dry_run:
                                interface.custom_fields["participant"] = participant.id
                                interface.save()
                    else:
                        logger.warning(
                            f"Could not find unique tenant for {asn_slug}"
                            f" ({len(participants)} results)"
                            f" — skipping participant assignment"
                        )
                    desired_tag = "transit_peer"
                    remove_tags = {"admin_port", "core_port"}
                else:
                    desired_tag = "admin_port"
                    remove_tags = {"core_port", "transit_peer"}

            new_tags = [s for s in tag_slugs if s not in remove_tags]
            if desired_tag not in new_tags:
                new_tags.append(desired_tag)
            if set(new_tags) != set(tag_slugs):
                logger.info(
                    f"{'[DRY-RUN] Would set' if dry_run else 'Setting'}"
                    f" tags: [{', '.join(sorted(tag_slugs))}]"
                    f" -> [{', '.join(sorted(new_tags))}]"
                    f" on {self.device_name} / {name}"
                )
                if not dry_run:
                    interface.tags = [{"slug": s} for s in new_tags]
                    interface.save()


# ── Juniper JunOS ─────────────────────────────────────────────────────


class JuniperJunOSDevice(NetconfSSHDevice):
    """Discovery and NetBox sync for Juniper JunOS devices (MX series)."""

    def _junos_connect(self) -> Any:
        try:
            from jnpr.junos import Device as JunosDevice  # type: ignore[import]
        except ImportError:
            raise RuntimeError(
                "junos-eznc is not installed. Run: pipenv install"
            )
        creds = self._get_ssh_credentials()
        ssh_config = os.path.expanduser("~/.ssh/config")
        dev = JunosDevice(
            host=self.management_host,
            user=creds["username"],
            ssh_config=ssh_config if os.path.exists(ssh_config) else None,
        )
        dev.open()
        return dev

    def _iface_nb_type(
        self, iface_name: str
    ) -> Tuple[Optional[str], Optional[int]]:
        for prefix, (nb_type, speed) in JUNIPER_IFACE_TYPE_MAP.items():
            if iface_name.startswith(prefix):
                return nb_type, speed
        return None, None

    def discover_hardware_interfaces(
        self, dry_run: bool = False, delete_interfaces: bool = False
    ) -> None:
        netbox = netbox_api_client()
        logger.info(
            f"discover_hardware_interfaces: {self.device_name}"
            f" (via {self.management_host})"
        )
        dev = self._junos_connect()
        try:
            iface_info = dev.rpc.get_interface_information(terse=True)
        finally:
            dev.close()

        # Prefetch all NetBox interfaces once for lookup and stale sweep
        nb_ifaces = _prefetch_nb_interfaces(netbox, self.device_name)

        on_device_ifaces = set()
        for phy_iface in iface_info.findall("physical-interface"):
            name = (phy_iface.findtext("name") or "").strip()
            if not name:
                continue
            if any(name.startswith(pfx) for pfx in JUNIPER_INTERNAL_PREFIXES):
                continue

            nb_type, nb_speed = self._iface_nb_type(name)
            if nb_type is None:
                logger.debug(f"  Skipping unknown interface type: {name}")
                continue

            on_device_ifaces.add(name)
            iface = nb_ifaces.get(name)
            if iface is None:
                logger.info(
                    f"  {'[DRY-RUN] Would create' if dry_run else 'Creating'}"
                    f" interface: {self.device_name} / {name} ({nb_type})"
                )
                if not dry_run:
                    create_kwargs: Dict[str, Any] = {
                        "device": {"name": self.device_name},
                        "name": name,
                        "type": nb_type,
                    }
                    if nb_speed is not None:
                        create_kwargs["speed"] = nb_speed
                    netbox.dcim.interfaces.create(**create_kwargs)
            else:
                if nb_speed is not None and iface.speed != nb_speed:
                    logger.info(
                        f"  {'[DRY-RUN] Would update' if dry_run else 'Updating'}"
                        f" speed: {self.device_name} / {name}:"
                        f" {iface.speed} -> {nb_speed}"
                    )
                    if not dry_run:
                        iface.speed = nb_speed
                        iface.save()
                else:
                    logger.debug(f"  No change for {self.device_name} / {name}")

        if delete_interfaces:
            for nb_iface_name, nb_iface in nb_ifaces.items():
                # Only sweep physical interfaces (no "/"), not routing instance ones
                if "/" in nb_iface_name:
                    continue
                if nb_iface_name not in on_device_ifaces:
                    logger.info(
                        f"  {'[DRY-RUN] Would delete' if dry_run else 'Deleting'}"
                        f" interface: {self.device_name} / {nb_iface_name}"
                    )
                    if not dry_run:
                        nb_iface.delete()

    def discover_logical_interfaces(
        self, dry_run: bool = False, delete_interfaces: bool = False
    ) -> None:
        """Discover routing instance interfaces and sync to NetBox as virtual interfaces.

        Analogous to Nokia VPRN SAP discovery. Each interface is stored as
        '{routing_instance}/{interface_name}'.
        """
        netbox = netbox_api_client()
        logger.info(
            f"discover_logical_interfaces: {self.device_name}"
            f" (via {self.management_host})"
        )
        dev = self._junos_connect()
        try:
            ri_info = dev.rpc.get_instance_information(detail=True)
        finally:
            dev.close()

        # Prefetch all NetBox interfaces once for lookup and stale sweep
        nb_ifaces = _prefetch_nb_interfaces(netbox, self.device_name)

        on_device_ri_ifaces = set()
        created = 0
        for instance in ri_info.findall("instance-core"):
            ri_name = (instance.findtext("instance-name") or "").strip()
            if not ri_name or ri_name in JUNIPER_BUILTIN_INSTANCES:
                continue
            for iface_elem in instance.findall("instance-interface"):
                iface_name = (iface_elem.findtext("interface-name") or "").strip()
                if not iface_name:
                    continue
                base_name = iface_name.split(".")[0] if "." in iface_name else iface_name
                nb_name = f"{ri_name}/{base_name}"
                on_device_ri_ifaces.add(nb_name)

                if nb_name not in nb_ifaces:
                    logger.info(
                        f"  {'[DRY-RUN] Would create' if dry_run else 'Creating'}"
                        f" routing instance interface: {self.device_name} / {nb_name}"
                    )
                    if not dry_run:
                        netbox.dcim.interfaces.create(
                            device={"name": self.device_name},
                            name=nb_name,
                            type="virtual",
                        )
                    created += 1
                else:
                    logger.debug(
                        f"  Routing instance interface exists:"
                        f" {self.device_name} / {nb_name}"
                    )

        logger.info(f"  {'Would create' if dry_run else 'Created'} {created} routing instance interfaces")

        if delete_interfaces:
            for nb_iface_name, nb_iface in nb_ifaces.items():
                if "/" not in nb_iface_name:
                    continue
                if nb_iface_name not in on_device_ri_ifaces:
                    logger.info(
                        f"  {'[DRY-RUN] Would delete' if dry_run else 'Deleting'}"
                        f" routing instance interface: {self.device_name} / {nb_iface_name}"
                    )
                    if not dry_run:
                        nb_iface.delete()

    def sync_port_tags(self, dry_run: bool = False) -> None:
        """Tag Juniper interfaces analogously to Nokia SAP classification.

        Physical interfaces (no '/') → core_port
        Routing instance interfaces matching as<ASN>-* → transit_peer + participant
        Others → admin_port
        """
        netbox = netbox_api_client()
        logger.debug(f"Classifying port tags on Juniper device {self.device_name}")
        all_tenants = {t.slug: t for t in netbox.tenancy.tenants.all()}
        for interface in netbox.dcim.interfaces.filter(device=self.device_name):
            tag_slugs = [tag["slug"] for tag in interface.tags]
            name = interface.name

            if "/" not in name:
                if "core_port" not in tag_slugs:
                    new_tag_slugs = tag_slugs + ["core_port"]
                    logger.info(
                        f"{'[DRY-RUN] Would set' if dry_run else 'Setting'}"
                        f" tags: [{', '.join(sorted(tag_slugs))}]"
                        f" -> [{', '.join(sorted(new_tag_slugs))}]"
                        f" on {self.device_name} / {name}"
                    )
                    if not dry_run:
                        interface.tags = [{"slug": s} for s in new_tag_slugs]
                        interface.save()
                continue

            _ri_name, iface_name = name.split("/", 1)

            asn_match = JUNIPER_TENANT_IFACE_RE.match(iface_name)
            if asn_match:
                asn = int(asn_match.group(1))
                asn_slug = f"as{asn}"
                tenant = all_tenants.get(asn_slug)
                participants = [tenant] if tenant else []
                if len(participants) == 1:
                    participant = participants[0]
                    if interface.custom_fields.get("participant") != participant.id:
                        old_participant = interface.custom_fields.get("participant")
                        logger.info(
                            f"{'[DRY-RUN] Would set' if dry_run else 'Setting'}"
                            f" participant: {old_participant!r} -> {asn_slug}"
                            f" on {self.device_name} / {name}"
                        )
                        if not dry_run:
                            interface.custom_fields["participant"] = participant.id
                            interface.save()
                else:
                    logger.warning(
                        f"Could not find unique tenant for {asn_slug}"
                        f" ({len(participants)} results)"
                        f" — skipping participant assignment"
                    )
                desired_tag = "transit_peer"
                remove_tags = {"admin_port", "core_port"}
            else:
                desired_tag = "admin_port"
                remove_tags = {"core_port", "transit_peer"}

            new_tags = [s for s in tag_slugs if s not in remove_tags]
            if desired_tag not in new_tags:
                new_tags.append(desired_tag)
            if set(new_tags) != set(tag_slugs):
                logger.info(
                    f"{'[DRY-RUN] Would set' if dry_run else 'Setting'}"
                    f" tags: [{', '.join(sorted(tag_slugs))}]"
                    f" -> [{', '.join(sorted(new_tags))}]"
                    f" on {self.device_name} / {name}"
                )
                if not dry_run:
                    interface.tags = [{"slug": s} for s in new_tags]
                    interface.save()

    def sync_interface_ips(self, dry_run: bool = False) -> None:
        """Sync interface IP addresses from Juniper device to NetBox."""
        netbox = netbox_api_client()
        logger.info(
            f"sync_interface_ips: {self.device_name} (via {self.management_host})"
        )
        dev = self._junos_connect()
        try:
            iface_info = dev.rpc.get_interface_information(detail=True)
        finally:
            dev.close()

        # One GraphQL call to get all interface IDs and their existing IPs
        nb_ifaces_gql, nb_ips_by_addr = _prefetch_device_ips(self.device_name)

        device_ips: Set[str] = set()

        for phy_iface in iface_info.findall("physical-interface"):
            phy_name = (phy_iface.findtext("name") or "").strip()
            if not phy_name:
                continue

            nb_iface_info = nb_ifaces_gql.get(phy_name)
            if not nb_iface_info:
                logger.debug(
                    f"  Interface not in NetBox, skipping IP sync:"
                    f" {self.device_name}/{phy_name}"
                )
                continue
            nb_iface_id = nb_iface_info["id"]

            for log_iface in phy_iface.findall("logical-interface"):
                for af in log_iface.findall("address-family"):
                    af_name = (af.findtext("address-family-name") or "").strip()
                    if af_name not in ("inet", "inet6"):
                        continue
                    for if_addr in af.findall("interface-address"):
                        addr = (if_addr.findtext("ifa-local") or "").strip()
                        if not addr or addr.startswith("fe80"):
                            continue
                        dest = (if_addr.findtext("ifa-destination") or "").strip()
                        if dest and "/" in dest:
                            prefix_len = dest.split("/", 1)[1]
                            ip_with_mask = f"{addr}/{prefix_len}"
                        else:
                            ip_with_mask = addr
                        device_ips.add(ip_with_mask)

                        existing_ip_info = nb_ips_by_addr.get(ip_with_mask)
                        if existing_ip_info is None:
                            logger.info(
                                f"  {'[DRY-RUN] Would create' if dry_run else 'Creating'}"
                                f" IP {ip_with_mask} for {self.device_name}/{phy_name}"
                            )
                            if not dry_run:
                                netbox.ipam.ip_addresses.create(
                                    address=ip_with_mask,
                                    assigned_object_type="dcim.interface",
                                    assigned_object_id=nb_iface_id,
                                )
                        elif existing_ip_info["interface_id"] != nb_iface_id:
                            logger.info(
                                f"  {'[DRY-RUN] Would update' if dry_run else 'Updating'}"
                                f" IP {ip_with_mask} assignment to"
                                f" {self.device_name}/{phy_name}"
                            )
                            if not dry_run:
                                existing_ip = netbox.ipam.ip_addresses.get(
                                    existing_ip_info["id"]
                                )
                                existing_ip.assigned_object_type = "dcim.interface"
                                existing_ip.assigned_object_id = nb_iface_id
                                existing_ip.save()

        for mgmt_iface_name in JUNIPER_MGMT_INTERFACES:
            mgmt_iface_info = nb_ifaces_gql.get(mgmt_iface_name)
            if not mgmt_iface_info:
                continue
            mgmt_iface_id = mgmt_iface_info["id"]
            primary_ip_addr = next(
                (
                    ip for ip, info in nb_ips_by_addr.items()
                    if info["interface_id"] == mgmt_iface_id and ":" not in ip
                ),
                None,
            )
            if primary_ip_addr:
                primary_ip_id = nb_ips_by_addr[primary_ip_addr]["id"]
                device = netbox.dcim.devices.get(name=self.device_name)
                if not device.primary_ip4 or device.primary_ip4.id != primary_ip_id:
                    logger.info(
                        f"  {'[DRY-RUN] Would set' if dry_run else 'Setting'}"
                        f" primary IPv4 of {self.device_name} to {primary_ip_addr}"
                    )
                    if not dry_run:
                        device.primary_ip4 = primary_ip_id
                        device.save()
            break


# ── Device factory ────────────────────────────────────────────────────

_MANUFACTURER_CLASS_MAP: Dict[str, Type[DeviceDiscovery]] = {
    "Arista": AristaEOSDevice,
    "Nokia": NokiaSROSDevice,
    "Juniper": JuniperJunOSDevice,
}


def enumerate_peering_devices() -> Generator[DeviceDiscovery, None, None]:
    """Yield DeviceDiscovery instances for all devices with the peering_switch role."""
    logger.debug("Enumerating peering devices from NetBox")
    netbox = netbox_api_client()
    for nb_device in netbox.dcim.devices.filter(role="peering_switch"):
        mfr = nb_device.device_type.manufacturer.name
        cls = _MANUFACTURER_CLASS_MAP.get(mfr)
        if cls is None:
            logger.warning(
                f"No discovery class for {nb_device.name} ({mfr}); skipping"
            )
            continue
        yield cls(nb_device.name, nb_device)


# ── Device-agnostic NetBox sync ───────────────────────────────────────


def update_netbox_peering_port_tags_by_vlan(dry_run: bool = False) -> None:
    netbox = netbox_api_client()
    main_peering_vlan = list(
        netbox.ipam.vlans.filter(group="exchange_fabric_vlans", vid=998)
    )[0]
    for interface in netbox.dcim.interfaces.filter(vlan_id=main_peering_vlan.id):
        if interface.name == "Vxlan1":
            continue
        if interface.description.startswith("pve"):
            for tag_slug in ("peering_port", "ixp_infrastructure"):
                if tag_slug not in [tag["slug"] for tag in interface.tags]:
                    logger.info(
                        f"{'[DRY-RUN] Would add' if dry_run else 'Adding'}"
                        f" {tag_slug} tag to"
                        f" {interface.device.name} / {interface.name}"
                    )
                    if not dry_run:
                        interface.tags = [
                            {"slug": tag["slug"]} for tag in interface.tags
                        ] + [{"slug": tag_slug}]
                        interface.save()
            continue
        for tag_slug in ("peering_port", "ixp_participant"):
            if tag_slug not in [tag["slug"] for tag in interface.tags]:
                logger.info(
                    f"{'[DRY-RUN] Would add' if dry_run else 'Adding'}"
                    f" {tag_slug} tag to"
                    f" {interface.device.name} / {interface.name}"
                )
                if not dry_run:
                    interface.tags = [
                        {"slug": tag["slug"]} for tag in interface.tags
                    ] + [{"slug": tag_slug}]
                    interface.save()
    for interface in netbox.dcim.interfaces.filter(tag="peering_port"):
        interface_vlans = interface.tagged_vlans
        if interface.untagged_vlan:
            interface_vlans.append(interface.untagged_vlan)
        interface_vlan_ids = [vlan.id for vlan in interface_vlans]
        if main_peering_vlan.id not in interface_vlan_ids:
            logger.info(
                f"{'[DRY-RUN] Would remove' if dry_run else 'Removing'}"
                f" peering_port tag from"
                f" {interface.device.name} / {interface.name}"
            )
            if not dry_run:
                interface.tags = [
                    {"slug": tag["slug"]}
                    for tag in interface.tags
                    if tag.slug != "peering_port"
                ]
                interface.save()


def _is_core_interface(name: str, description: str, tag_slugs: List[str]) -> bool:
    """Return True if this EOS interface should carry the 'core_port' tag."""
    if "peering_port" in tag_slugs:
        return False
    if name.startswith("Loopback"):
        return True
    desc = description.strip()
    return any(desc.startswith(prefix) for prefix in CORE_PORT_DESCRIPTION_PREFIXES)


def update_netbox_interface_description_asn_participant(
    dry_run: bool = False,
) -> None:
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
            old = interface.custom_fields.get("participant")
            if old != participant.id:
                logger.info(
                    f"{'[DRY-RUN] Would set' if dry_run else 'Setting'}"
                    f" participant: {old!r} -> {asn_slug}"
                    f" on {interface.device.name} / {interface.name}"
                )
                if not dry_run:
                    interface.custom_fields["participant"] = participant.id
                    interface.save()


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
    parser.add_argument(
        "--sync-core-port-tags",
        action="store_true",
        help='Synchronize the "core_port" tag based on interface description',
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without making any modifications",
    )
    parser.add_argument(
        "--sync-interface-ips",
        action="store_true",
        help="Synchronize interface IPs to Netbox",
    )
    parser.add_argument(
        "--device",
        action="append",
        metavar="HOSTNAME",
        help="Limit discovery to specific device(s). Can be specified multiple times.",
    )
    parser.add_argument(
        "--list-devices",
        action="store_true",
        help="List available peering device hostnames and exit",
    )
    parser.add_argument(
        "--delete-interfaces",
        action="store_true",
        help="Delete interfaces in NetBox that no longer exist on the device",
    )
    args = parser.parse_args()

    devices = list(enumerate_peering_devices())

    if args.list_devices:
        missing_ip = []
        for d in sorted(devices, key=lambda d: d.device_name):
            mfr = d.nb_device.device_type.manufacturer.name
            model = d.nb_device.device_type.model
            if d.nb_device.primary_ip4:
                mgmt = str(ipaddress.ip_interface(d.nb_device.primary_ip4.address).ip)
            else:
                mgmt = "NO PRIMARY IP"
                missing_ip.append(d.device_name)
            print(f"{d.device_name}  ({mfr} {model}, role={d.role}, mgmt={mgmt})")
        if missing_ip:
            print(f"\nWARNING: {len(missing_ip)} device(s) have no primary IPv4 set:")
            for name in missing_ip:
                print(f"  {name}")
        raise SystemExit(0)

    if args.device:
        unknown = set(args.device) - {d.device_name for d in devices}
        if unknown:
            parser.error(
                f"Unknown device(s): {', '.join(sorted(unknown))}."
                " Use --list-devices to see available devices."
            )
        devices = [d for d in devices if d.device_name in args.device]

    if args.sync_hardware_interfaces:
        for device in devices:
            device.discover_hardware_interfaces(
                dry_run=args.dry_run,
                delete_interfaces=args.delete_interfaces,
            )
            device.discover_logical_interfaces(
                dry_run=args.dry_run,
                delete_interfaces=args.delete_interfaces,
            )
    else:
        logger.info(
            "Skipping hardware interface discovery. To enable: --sync-hardware-interfaces"
        )

    vlan_ip_mac_map: Dict[VLAN_IP, str] = dict()
    for vlan_id, peering_lan_prefix in list_peering_lans():
        vlan_ip_macs = discover_vlan_ip_mac_map(vlan_id, peering_lan_prefix)
        vlan_ip_mac_map.update(vlan_ip_macs)

    if args.sync_ip_macs:
        update_netbox_ip_macs(vlan_ip_mac_map, dry_run=args.dry_run)
    else:
        logger.info("Skipping IP MAC sync. To enable: --sync-ip-macs")

    # MAC table pipeline — Arista EOS only (non-EOS returns empty map)
    vlan_mac_port_map: Dict[VLAN_MAC, PORT] = dict()
    for device in devices:
        vlan_mac_port_map.update(device.get_vlan_mac_port_map())

    ip_port_map: Dict[str, PORT] = dict()
    for (vlan, ip), mac in vlan_ip_mac_map.items():
        port = vlan_mac_port_map.get((vlan, mac))
        if not port:
            logger.warning(f"Warning, no port found for {vlan}, {mac} :/ ... Skipping")
            continue
        ip_port_map[ip] = port

    if args.sync_ip_participant_lag:
        update_netbox_ip_participant_lag(ip_port_map, dry_run=args.dry_run)
    else:
        logger.info(
            "Skipping IP participant lag sync. To enable: --sync-ip-participant-lag"
        )

    if args.sync_peering_port_tags_by_vlan:
        update_netbox_peering_port_tags_by_vlan(dry_run=args.dry_run)
    else:
        logger.info(
            "Skipping peering port tag sync. To enable: --sync-peering-port-tags-by-vlan"
        )

    if args.sync_core_port_tags:
        for device in devices:
            device.sync_port_tags(dry_run=args.dry_run)
    else:
        logger.info(
            "Skipping core port tag sync. To enable: --sync-core-port-tags"
        )

    if args.sync_interface_description_asn_participant:
        update_netbox_interface_description_asn_participant(dry_run=args.dry_run)
    else:
        logger.info(
            "Skipping interface description ASN to participant sync."
            " To enable: --sync-interface-description-asn-participant"
        )

    if args.sync_interface_ips:
        for device in devices:
            device.sync_interface_ips(dry_run=args.dry_run)
    else:
        logger.info("Skipping interface IP sync. To enable: --sync-interface-ips")
