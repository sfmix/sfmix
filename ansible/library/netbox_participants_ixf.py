#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, SFMIX
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: netbox_participants_ixf
short_description: Generate IXF format participant data from NetBox
description:
  - Converts NetBox data about IXP participants into IXF (Internet Exchange Federation) standard format
  - Queries NetBox API directly to retrieve devices, VLANs, prefixes, participants, and connections
  - Handles special cases for infrastructure and route server participants
options:
  netbox_api_endpoint:
    description: NetBox API endpoint URL
    required: true
    type: str
  netbox_api_token:
    description: NetBox API authentication token
    required: true
    type: str
    no_log: true
  ixp_info:
    description: IXP information dictionary
    required: false
    type: dict
    default:
        shortname: SFMIX
        name: San Francisco Metropolitan Internet Exchange
        ixp_id: 155
        ixf_id: 223
        peeringdb_id: 155
        country: US
        url: https://sfmix.org/
        support_email: tech-c@sfmix.org
        support_phone: "+1 415 634-6712"
            shortname: SFMIX
            name: San Francisco Metropolitan Internet Exchange
            ixp_id: 155
            ixf_id: 223
            peeringdb_id: 155
            country: US
            url: https://sfmix.org/
            support_email: tech-c@sfmix.org
            support_phone: "+1 415 634-6712"
"""

EXAMPLES = r"""
- name: Generate IXF participant data
  netbox_participants_ixf:
    netbox_devices: "{{ netbox_devices }}"
    netbox_sites: "{{ netbox_sites }}"
    exchange_fabric_vlans: "{{ exchange_fabric_vlans }}"
    netbox_prefixes: "{{ netbox_prefixes }}"
    netbox_participants: "{{ netbox_participants }}"
    netbox_peering_port_interfaces: "{{ netbox_peering_port_interfaces }}"
    netbox_participant_ip_addresses: "{{ netbox_participant_ip_addresses }}"
  register: ixf_data
"""

RETURN = r"""
ixf_data:
    description: The generated IXF format data
    returned: always
    type: dict
    sample:
        version: "1.0"
        timestamp: "2024-01-01T00:00:00+0000"
        ixp_list:
            - shortname: SFMIX
              name: San Francisco Metropolitan Internet Exchange
              switch: []
              vlan: []
        member_list: []
"""

from ansible.module_utils.basic import AnsibleModule
from datetime import datetime
import ipaddress
import json
import pynetbox
import sys
import traceback
import urllib.request
import urllib.parse
import urllib.error


# def get_ip_network(prefix_str):
#     """Extract network address from prefix string"""
#     try:
#         network = ipaddress.ip_network(prefix_str, strict=False)
#         return str(network.network_address)
#     except ValueError:
#         return prefix_str.split("/")[0]


# def get_prefix_length(prefix_str):
#     """Extract prefix length from CIDR notation"""
#     if '/' in prefix_str:
#         return int(prefix_str.split('/')[1])
#     return 32 if ':' not in prefix_str else 128


# def get_ip_address(address_str):
#     """Extract IP address from address string"""
#     try:
#         addr = ipaddress.ip_address(address_str.split("/")[0])
#         return str(addr)
#     except ValueError:
#         return address_str.split("/")[0]


# def ip_in_network(ip_str, network_str):
#     """Check if IP address is in network"""
#     try:
#         ip = ipaddress.ip_address(ip_str)
#         network = ipaddress.ip_network(network_str, strict=False)
#         return ip in network
#     except ValueError:
#         return False


# def query_netbox_api(api_endpoint, token, endpoint, filters=None):
#     """Query NetBox API and return all results with pagination"""
#     results = []
#     url = f"{api_endpoint.rstrip('/')}/api/{endpoint.lstrip('/')}/"
    
#     if filters:
#         url += '?' + urllib.parse.urlencode(filters)
    
#     while url:
#         print(f"DEBUG: Querying NetBox API: {url}", file=sys.stderr)
        
#         request = urllib.request.Request(url)
#         request.add_header('Authorization', f'Token {token}')
#         request.add_header('Content-Type', 'application/json')
        
#         try:
#             with urllib.request.urlopen(request) as response:
#                 data = json.loads(response.read().decode('utf-8'))
#                 results.extend(data.get('results', []))
#                 url = data.get('next')  # Handle pagination
#         except urllib.error.HTTPError as e:
#             error_msg = f"HTTP Error {e.code}: {e.reason}"
#             if hasattr(e, 'read'):
#                 error_detail = e.read().decode('utf-8')
#                 error_msg += f" - {error_detail}"
#             raise Exception(f"NetBox API query failed: {error_msg}")
#         except Exception as e:
#             raise Exception(f"NetBox API query failed: {str(e)}")
    
#     print(f"DEBUG: Retrieved {len(results)} items from {endpoint}", file=sys.stderr)
#     return results


# def fetch_netbox_data(api_endpoint, token):
#     """Fetch all required data from NetBox API"""
#     print("DEBUG: Fetching data from NetBox API...", file=sys.stderr)
    
#     # Query all required endpoints
#     devices = query_netbox_api(api_endpoint, token, 'dcim/devices')
#     sites = query_netbox_api(api_endpoint, token, 'dcim/sites')
#     vlans = query_netbox_api(api_endpoint, token, 'ipam/vlans')
#     prefixes = query_netbox_api(api_endpoint, token, 'ipam/prefixes')
    
#     # Query participants (tenants with specific tags)
#     participants = query_netbox_api(api_endpoint, token, 'tenancy/tenants')
    
#     # Query peering port interfaces
#     interfaces = query_netbox_api(api_endpoint, token, 'dcim/interfaces')
    
#     # Query participant IP addresses with tag filter
#     ip_addresses = query_netbox_api(api_endpoint, token, 'ipam/ip-addresses', 
#                                   {'tag': 'ixp_participant'})
    
#     # Convert lists to dictionaries indexed by ID for compatibility
#     data = {
#         'netbox_devices': {item['id']: item for item in devices},
#         'netbox_sites': {item['id']: item for item in sites},
#         'exchange_fabric_vlans': {item['id']: item for item in vlans},
#         'netbox_prefixes': {item['id']: item for item in prefixes},
#         'netbox_participants': {item['id']: item for item in participants},
#         'netbox_peering_port_interfaces': {item['id']: item for item in interfaces},
#         'netbox_participant_ip_addresses': {item['id']: item for item in ip_addresses}
#     }
    
#     print(f"DEBUG: Fetched data - devices: {len(data['netbox_devices'])}, "
#           f"sites: {len(data['netbox_sites'])}, vlans: {len(data['exchange_fabric_vlans'])}, "
#           f"prefixes: {len(data['netbox_prefixes'])}, participants: {len(data['netbox_participants'])}, "
#           f"interfaces: {len(data['netbox_peering_port_interfaces'])}, "
#           f"ip_addresses: {len(data['netbox_participant_ip_addresses'])}", file=sys.stderr)
    
#     return data


# def process_switches(netbox_devices, netbox_sites):
#     """Process NetBox devices to extract peering switches"""
#     switches = []
    
#     # Handle None values
#     if not netbox_devices or not netbox_sites:
#         return switches

#     for device in netbox_devices.values():
#         if device is None:
#             continue
#         if device.get("device_role", {}).get("slug") == "peering_switch":
#             site_id = device.get("site", {}).get("id")
#             site = netbox_sites.get(site_id, {})

#             switch_data = {
#                 "id": device.get("id"),
#                 "name": device.get("name", ""),
#                 "colo": site.get("facility", ""),
#                 "pdb_facility_id": site.get("custom_fields", {}).get(
#                     "peeringdb_facility"
#                 ),
#                 "city": site.get("region", {}).get("name", ""),
#                 "country": "US",
#                 "manufacturer": device.get("device_type", {})
#                 .get("manufacturer", {})
#                 .get("name", ""),
#                 "model": device.get("device_type", {}).get("model", ""),
#             }
#             switches.append(switch_data)

#     return switches


# def process_vlans(exchange_fabric_vlans, netbox_prefixes):
#     """Process VLANs to extract peering LANs"""
#     vlans = []
    
#     # Handle None values
#     if not exchange_fabric_vlans or not netbox_prefixes:
#         return vlans

#     for vlan in exchange_fabric_vlans.values():
#         if vlan is None:
#             continue
#         # Check if VLAN has peering_lan tag
#         is_peering_lan = False
#         for tag in vlan.get("tags", []):
#             if tag is None:
#                 continue
#             if tag.get("slug") == "peering_lan":
#                 is_peering_lan = True
#                 break

#         if not is_peering_lan:
#             continue

#         vlan_data = {"id": vlan.get("id"), "name": vlan.get("name", "")}

#         # Find prefixes for this VLAN
#         for prefix in netbox_prefixes.values():
#             if prefix is None:
#                 continue
#             prefix_vlan = prefix.get("vlan")
#             if prefix_vlan is None:
#                 continue
#             if prefix_vlan.get("id") == vlan.get("id"):
#                 family = prefix.get("family", {}).get("value")
#                 prefix_str = prefix.get("prefix", "")

#                 if family == 4:
#                     vlan_data["ipv4"] = {
#                         "prefix": get_ip_network(prefix_str),
#                         "mask_length": get_prefix_length(prefix_str),
#                     }
#                 elif family == 6:
#                     vlan_data["ipv6"] = {
#                         "prefix": get_ip_network(prefix_str),
#                         "mask_length": get_prefix_length(prefix_str),
#                     }

#         vlans.append(vlan_data)

#     return vlans


# def process_special_participants(participant_id, as_number):
#     """Handle special case participants (AS 12276 and AS 63055)"""
#     if as_number == 12276:
#         return [
#             {
#                 "ixp_id": 155,
#                 "state": "active",
#                 "if_list": [{"switch_id": 59, "if_speed": 1000}],
#                 "vlan_list": [
#                     {
#                         "vlan_id": 1,
#                         "ipv4": {"address": "206.197.187.1"},
#                         "ipv6": {"address": "2001:504:30::ba01:2276:1"},
#                     },
#                     {
#                         "vlan_id": 1,
#                         "ipv4": {"address": "206.197.187.2"},
#                         "ipv6": {"address": "2001:504:30::ba01:2276:2"},
#                     },
#                 ],
#             }
#         ]
#     elif as_number == 63055:
#         return [
#             {
#                 "ixp_id": 155,
#                 "state": "active",
#                 "if_list": [
#                     {"switch_id": 59, "if_speed": 1000},
#                     {"switch_id": 63, "if_speed": 1000},
#                 ],
#                 "vlan_list": [
#                     {
#                         "vlan_id": 1,
#                         "ipv4": {"address": "206.197.187.253"},
#                         "ipv6": {"address": "2001:504:30::ba06:3055:1"},
#                     },
#                     {
#                         "vlan_id": 1,
#                         "ipv4": {"address": "206.197.187.254"},
#                         "ipv6": {"address": "2001:504:30::ba06:3055:2"},
#                     },
#                 ],
#             }
#         ]
#     return None


# def process_participant_connections(
#     participant_id,
#     netbox_peering_port_interfaces,
#     netbox_participant_ip_addresses,
#     exchange_fabric_vlans,
#     netbox_prefixes,
# ):
#     """Process regular participant connections"""
#     connections = []
    
#     # Handle None values
#     if not all([netbox_peering_port_interfaces, netbox_participant_ip_addresses, 
#                 exchange_fabric_vlans, netbox_prefixes]):
#         return connections

#     for peering_port_id, peering_port in netbox_peering_port_interfaces.items():
#         if peering_port is None:
#             continue
#         port_participant = peering_port.get("custom_fields", {}).get("participant")
#         if port_participant is None:
#             continue
#         if port_participant.get("id") != participant_id:
#             continue

#         # Build interface info
#         if_speed = None
#         rate_limit = peering_port.get("custom_fields", {}).get("rate_limit_bps")
#         if rate_limit:
#             if_speed = int(rate_limit / 1000000)
#         elif peering_port.get("speed"):
#             if_speed = int(peering_port.get("speed") / 1000)

#         if_list = [{"switch_id": peering_port.get("device", {}).get("id")}]
#         if if_speed:
#             if_list[0]["if_speed"] = if_speed

#         # Build VLAN mapping
#         vlan_map = {"vlan_ids": {}, "ipv4": {}, "ipv6": {}}

#         for ip_address in netbox_participant_ip_addresses.values():
#             if ip_address is None:
#                 continue
#             participant_lag = ip_address.get("custom_fields", {}).get(
#                 "participant_lag", {}
#             )
#             if participant_lag.get("id") != peering_port_id:
#                 continue

#             ip_addr_str = ip_address.get("address", "")
#             ip_only = get_ip_address(ip_addr_str)

#             # Find matching VLAN and prefix
#             for vlan in exchange_fabric_vlans.values():
#                 if vlan is None:
#                     continue
#                 # Check if VLAN has peering_lan tag
#                 is_peering_lan = False
#                 for tag in vlan.get("tags", []):
#                     if tag.get("slug") == "peering_lan":
#                         is_peering_lan = True
#                         break

#                 if not is_peering_lan:
#                     continue

#                 for prefix in netbox_prefixes.values():
#                     if prefix is None:
#                         continue
#                     if prefix.get("vlan", {}).get("id") == vlan.get(
#                         "id"
#                     ) and ip_in_network(ip_only, prefix.get("prefix", "")):

#                         vlan_id = vlan.get("id")
#                         vlan_map["vlan_ids"][vlan_id] = True

#                         family = ip_address.get("family", {}).get("value")
#                         if family == 4:
#                             vlan_map["ipv4"][vlan_id] = ip_address
#                         elif family == 6:
#                             vlan_map["ipv6"][vlan_id] = ip_address

#         # Build VLAN list
#         vlan_list = []
#         for vlan_id in vlan_map["vlan_ids"]:
#             vlan_entry = {"vlan_id": vlan_id}

#             if vlan_id in vlan_map["ipv4"]:
#                 ip_addr = vlan_map["ipv4"][vlan_id]
#                 ipv4_data = {"address": get_ip_address(ip_addr.get("address", ""))}
#                 mac_addr = ip_addr.get("custom_fields", {}).get(
#                     "participant_mac_address"
#                 )
#                 if mac_addr:
#                     ipv4_data["mac_addresses"] = [mac_addr]
#                 vlan_entry["ipv4"] = ipv4_data

#             if vlan_id in vlan_map["ipv6"]:
#                 ip_addr = vlan_map["ipv6"][vlan_id]
#                 ipv6_data = {"address": get_ip_address(ip_addr.get("address", ""))}
#                 mac_addr = ip_addr.get("custom_fields", {}).get(
#                     "participant_mac_address"
#                 )
#                 if mac_addr:
#                     ipv6_data["mac_addresses"] = [mac_addr]
#                 vlan_entry["ipv6"] = ipv6_data

#             vlan_list.append(vlan_entry)

#         if vlan_list:  # Only add connection if it has VLANs
#             connection = {
#                 "ixp_id": 155,
#                 "state": "active",
#                 "if_list": if_list,
#                 "vlan_list": vlan_list,
#             }
#             connections.append(connection)

#     return connections


# def process_participants(
#     netbox_participants,
#     netbox_peering_port_interfaces,
#     netbox_participant_ip_addresses,
#     exchange_fabric_vlans,
#     netbox_prefixes,
# ):
#     """Process all participants"""
#     members = []
    
#     # Handle None values
#     if not netbox_participants:
#         return members

#     for participant_id, participant in netbox_participants.items():
#         if participant is None:
#             continue
#         # Determine member type
#         participant_type_field = participant.get("custom_fields", {}).get(
#             "participant_type"
#         )
#         member_type = "ixp" if participant_type_field == "Infrastructure" else "peering"

#         as_number = participant.get("custom_fields", {}).get("as_number")

#         member_data = {
#             "asnum": as_number,
#             "member_type": member_type,
#             "name": participant.get("description", ""),
#             "connection_list": [],
#         }

#         # Handle special cases
#         special_connections = process_special_participants(participant_id, as_number)
#         if special_connections:
#             member_data["connection_list"] = special_connections
#         else:
#             # Process regular connections
#             connections = process_participant_connections(
#                 participant_id,
#                 netbox_peering_port_interfaces,
#                 netbox_participant_ip_addresses,
#                 exchange_fabric_vlans,
#                 netbox_prefixes,
#             )
#             member_data["connection_list"] = connections

#         members.append(member_data)

#     return members


def sfmix_ixf_vlans(netbox):
    vlans = []
    netbox.ipam.vlan_groups.filter(group="exchange_fabric_vlans", tag="peering_lan")
    for vlan in netbox.ipam.vlans.all():
        vlan_data = {
            "id": vlan.id,
            "name": vlan.name,
            "prefix": vlan.prefix,
            "vlan_id": vlan.vlan_id,
        }
        vlans.append(vlan_data)
    return vlans


def sfmix_ixf_switches(netbox):
    switches = []
    for switch in netbox.dcim.devices.filter(role="peering_switch"):
        switch_data = {
            "id": switch.id,
            "name": switch.name,
            "colo": switch.site.name,
            "pdb_facility_id": switch.site.custom_fields.get("peeringdb_facility_id"),
            "city": switch.site.region.name,
            "country": "US",
            "manufacturer": switch.device_type.manufacturer.name,
            "model": switch.device_type.model,
        }
        switches.append(switch_data)
    return switches


def main():
    module_args = dict(
        netbox_api_endpoint=dict(type="str", required=True),
        netbox_api_token=dict(type="str", required=True, no_log=True),
        ixp_info=dict(
            type="dict",
            required=False,
            default={
                "shortname": "SFMIX",
                "name": "San Francisco Metropolitan Internet Exchange",
                "ixp_id": 155,
                "ixf_id": 223,
                "peeringdb_id": 155,
                "country": "US",
                "url": "https://sfmix.org/",
                "support_email": "tech-c@sfmix.org",
                "support_phone": "+1 415 634-6712",
            },
        ),
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    try:
        netbox = pynetbox.api(module.params["netbox_api_endpoint"], token=module.params["netbox_api_token"])

        sfmix = {
            "country": module.params["ixp_info"]["country"],
            "ixf_id": module.params["ixp_info"]["ixf_id"],
            "ixp_id": module.params["ixp_info"]["ixp_id"],
            "name": module.params["ixp_info"]["name"],
            "peeringdb_id": module.params["ixp_info"]["peeringdb_id"],
            "shortname": module.params["ixp_info"]["shortname"],
            "support_email": module.params["ixp_info"]["support_email"],
            "support_phone": module.params["ixp_info"]["support_phone"],
            "url": module.params["ixp_info"]["url"],
            "vlan": [],
        }
        sfmix["switch"] = sfmix_ixf_switches(netbox)
        sfmix["vlan"] = sfmix_ixf_vlans(netbox)
        participants = {}
        participants["ixp_list"] = [sfmix]
        participants["member_list"] = []
        participants["timestamp"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z")
        participants["version"] = "1.0"
        module.exit_json(changed=False, ixf_data=participants)
    except Exception as e:
        module.fail_json(msg=str(e))
    #     # Extract parameters with debug logging
    #     print("DEBUG: Starting netbox_participants_ixf module", file=sys.stderr)
        
    #     api_endpoint = module.params["netbox_api_endpoint"]
    #     api_token = module.params["netbox_api_token"]
    #     ixp_info = module.params["ixp_info"]
        
    #     # Fetch data from NetBox API
    #     # netbox_data = fetch_netbox_data(api_endpoint, api_token)
        
    #     # Extract data dictionaries for compatibility with existing processing functions
    #     netbox_devices = netbox_data['netbox_devices']
    #     netbox_sites = netbox_data['netbox_sites']
    #     exchange_fabric_vlans = netbox_data['exchange_fabric_vlans']
    #     netbox_prefixes = netbox_data['netbox_prefixes']
    #     netbox_participants = netbox_data['netbox_participants']
    #     netbox_peering_port_interfaces = netbox_data['netbox_peering_port_interfaces']
    #     netbox_participant_ip_addresses = netbox_data['netbox_participant_ip_addresses']

    #     # Generate timestamp
    #     timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z")
    #     print(f"DEBUG: Generated timestamp: {timestamp}", file=sys.stderr)

    #     # Process switches
    #     print("DEBUG: Processing switches...", file=sys.stderr)
    #     switches = process_switches(netbox_devices, netbox_sites)
    #     print(f"DEBUG: Found {len(switches)} switches", file=sys.stderr)

    #     # Process VLANs
    #     print("DEBUG: Processing VLANs...", file=sys.stderr)
    #     vlans = process_vlans(exchange_fabric_vlans, netbox_prefixes)
    #     print(f"DEBUG: Found {len(vlans)} VLANs", file=sys.stderr)

    #     # Process participants
    #     print("DEBUG: Processing participants...", file=sys.stderr)
    #     members = process_participants(
    #         netbox_participants,
    #         netbox_peering_port_interfaces,
    #         netbox_participant_ip_addresses,
    #         exchange_fabric_vlans,
    #         netbox_prefixes,
    #     )
    #     print(f"DEBUG: Found {len(members)} members", file=sys.stderr)

    #     # Build final result
    #     print("DEBUG: Building final IXF data structure...", file=sys.stderr)
    #     ixp_data = {
    #         "version": "1.0",
    #         "timestamp": timestamp,
    #         "ixp_list": [{**ixp_info, "switch": switches, "vlan": vlans}],
    #         "member_list": members,
    #     }
    #     print("DEBUG: Successfully built IXF data, returning result", file=sys.stderr)

    #     module.exit_json(changed=False, ixf_data=ixp_data)

    # except Exception as e:
    #     # Get detailed traceback information
    #     exc_type, exc_value, exc_traceback = sys.exc_info()
    #     tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    #     full_traceback = ''.join(tb_lines)
        
    #     # Print detailed debug information to stderr
    #     print(f"\nDEBUG: EXCEPTION OCCURRED!", file=sys.stderr)
    #     print(f"DEBUG: Exception type: {exc_type.__name__}", file=sys.stderr)
    #     print(f"DEBUG: Exception message: {str(exc_value)}", file=sys.stderr)
    #     print(f"DEBUG: Full traceback:\n{full_traceback}", file=sys.stderr)
        
    #     # Try to provide context about what was being processed
    #     tb = exc_traceback
    #     while tb:
    #         frame = tb.tb_frame
    #         if frame.f_code.co_name in ['process_switches', 'process_vlans', 'process_participants', 'process_participant_connections']:
    #             local_vars = frame.f_locals
    #             print(f"DEBUG: Error in function '{frame.f_code.co_name}' at line {tb.tb_lineno}", file=sys.stderr)
    #             print(f"DEBUG: Local variables in {frame.f_code.co_name}:", file=sys.stderr)
    #             for var_name, var_value in local_vars.items():
    #                 if var_name in ['device', 'vlan', 'participant', 'peering_port', 'ip_address', 'prefix']:
    #                     print(f"DEBUG:   {var_name}: {type(var_value)} = {var_value}", file=sys.stderr)
    #             break
    #         tb = tb.tb_next
        
    #     module.fail_json(msg=f"Error processing NetBox data: {str(e)}\n\nFull traceback:\n{full_traceback}")


if __name__ == "__main__":
    main()
