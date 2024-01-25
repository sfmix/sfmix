#!/usr/bin/env python3

# Take inputs:
#   New participant ASN name
#   site to connect and desired speed
# Create Netbox Tenant by ASN (lookup ASN name in PeeringDB)
# Find "available" pre-patched ports at that site of the desired speed (looking
#   at Netbox Cables for patching; TBD on how to mark "available")
# Present ports for operator selection
# Assign the Interface to the tenant
# Update interface description
# Enable Interface
# Assign IPv4 and IPv6 from the prefix, using Netbox IPAM to pick next-available
#   v4, templating ASN-in-v6
# (operator then pushes with ansible)

import yaml
import sys
import pynetbox
import requests
from sgqlc.endpoint.http import HTTPEndpoint


def main(
    operator_config,
    new_participant_asn,
    new_participant_site,
    desired_interface_speed_bps,
):
    netbox = netbox_client(operator_config=operator_config)
    netbox_graphql = graphql_endpoint(operator_config=operator_config)
    netbox_port_speed = int(desired_interface_speed_bps / 1_000)
    # Create Netbox Tenant by ASN
    if netbox.tenancy.tenants.filter(slug=f"as{new_participant_asn}"):
        sys.exit(f"Netbox Tenant AS{new_participant_asn} already exists!")
    ## Lookup ASN Name in PeeringDB
    peeringdb_asn_response = requests.get(
        "https://www.peeringdb.com/api/net",
        params={"asn": new_participant_asn},
        headers={
            "Accept": "application/json",
            "Authorization": f"Api-Key {operator_config['peeringdb_api_key']}",
        },
    )
    try:
        peeringdb_asn_response.raise_for_status()
    except:
        sys.exit(
            f"PeeringDB API Response Failure: {peeringdb_asn_response.content.decode('utf-8')}"
        )
    peeringdb_asn_data = peeringdb_asn_response.json()["data"][0]
    peeringdb_asn_name = peeringdb_asn_data["name"]
    netbox_tenant = netbox.tenancy.tenants.create(
        name=f"AS{new_participant_asn}",
        slug=f"as{new_participant_asn}",
        description=peeringdb_asn_name,
    )
    print("New Netbox Tenant Created: ", netbox_tenant["url"])

    # Find pre-patched interfaces in the site
    peering_switches_at_site = netbox.dcim.devices.filter(
        site=new_participant_site, role="peering_switch"
    )
    peering_switch_id_strings = map(
        str, [switch["id"] for switch in peering_switches_at_site]
    )
    peering_switches_ports_query = """
    query($device_ids: [String!]) {
        interface_list(device_id: $device_ids) {
            id
            name
            description
            device {
                id
                name
            }
            custom_fields
            cable {
                terminations {
                    cable_end
                    _device {
                        name
                        role {
                            slug
                        }
                    }
                }
            }
        }
    }
    """
    peering_switches_ports_query_variables = {"device_ids": peering_switch_id_strings}
    peering_switches_ports = netbox_graphql(
        peering_switches_ports_query, peering_switches_ports_query_variables
    )
    patched_and_unassigned_ports = []
    for port in peering_switches_ports["data"]["interface_list"]:
        if port["custom_fields"].get("participant"):
            # Already assigned
            continue
        if not port["cable"]:
            # Not patched
            continue
        if not port["speed"] == netbox_port_speed:
            # Wrong speed
            # FIXME: This really ought to selecting by optic media type, though netbox
            #   doesn't model this well. For example: colored optics or BiDi
            continue
        for termination in port["cable"]["terminations"]:
            if termination["device"]["role"]["slug"] == "patch_panel":
                patched_and_unassigned_ports.append(port)
    print(f"Found {len(patched_and_unassigned_ports)} patched and unassigned ports: ")
    enumerated_patched_and_unassigned_ports = dict(
        enumerate(patched_and_unassigned_ports, start=1)
    )
    for number, port in enumerated_patched_and_unassigned_ports.items():
        print(
            f"  [{number}] - {port['device']['name']}/{port['name']} - {port['description']}"
        )
    while True:
        port_selection_number = input("Your port selection? ")
        try:
            port_selection_number = int(port_selection_number)
        except ValueError:
            print("That doesn't appear to be an integer")
        selected_port = enumerated_patched_and_unassigned_ports.get(
            port_selection_number
        )
        if selected_port:
            break
    exchange_fabric_vlans_group_id = list(
        netbox.ipam.vlan_groups.filter(slug="exchange_fabric_vlans")
    )[0].id
    peering_lan = netbox.ipam.vlans.get(
        group_id=exchange_fabric_vlans_group_id, vid=998
    )
    jumbo_peering_lan = netbox.ipam.vlans.get(
        group_id=exchange_fabric_vlans_group_id, vid=999
    )
    # Next-available Port-Channel
    port_channel_name = next_available_port_channel_for_device_id(
        device_id=selected_port["device"]["id"]
    )
    port_channel_interface = netbox.dcim.interfaces.create(
        device=selected_port["device"]["id"],
        name=port_channel_name,
        enabled=True,
        description=f"Peer: {peeringdb_asn_name} (AS{new_participant_asn})",
        type="lag",
        speed=netbox_port_speed,
        mode="tagged",
        untagged_vlan=peering_lan.id,
        tagged_vlans=[peering_lan.id, jumbo_peering_lan.id],
        tags=[{"slug": "ixp_participant"}, {"slug": "peering_port"}],
        custom_fields={"participant": netbox_tenant.id},
    )
    print(f"Created LAG {port_channel_interface.name} - {port_channel_interface.url}")
    # Assign the Interface to the tenant
    # Update interface description
    # Enable Interface
    peering_port = netbox.dcim.interfaces.get(selected_port["id"])
    peering_port.tags = [{"slug": "peering_port"}, {"slug": "ixp_participant"}]
    peering_port.enabled = True
    peering_port.lag = port_channel_interface.id
    peering_port.description = f"{peeringdb_asn_name} LAG Member (AS{new_participant_asn})"
    peering_port.custom_fields = {"lacp_mode": "on"}
    peering_port.save()
    print(f"Added physical port to {port_channel_name}: {peering_port.url}")

    # IPv4 Next-Available
    raise NotImplementedError
    # list(nb.ipam.prefixes.filter(prefix='206.197.187.0/24'))[0].available_ips.create({'tenant':{'slug': 'as10310','tags':1}})


def graphql_endpoint(operator_config) -> HTTPEndpoint:
    graphql_headers = {"Authorization": f"Token {operator_config['netbox_api_key']}"}
    netbox_graphql_endpoint = HTTPEndpoint(
        f"{operator_config['netbox_api_endpoint']}graphql/",
        base_headers=graphql_headers,
    )
    return netbox_graphql_endpoint


def next_available_port_channel_for_device_id(device_id: int) -> str:
    raise NotImplementedError


def netbox_client(operator_config) -> pynetbox.core.api.API:
    return pynetbox.api(
        operator_config["netbox_api_endpoint"], token=operator_config["netbox_api_key"]
    )


def existing_peering_sites(operator_config):
    netbox = netbox_client(operator_config)
    netbox_graphql_endpoint = graphql_endpoint(operator_config)
    peering_switches_sites_query = """
    {
        device_list(role: "peering_switch") {
            site {
                name
            }
        }
    }
    """
    peering_switches_sites = sorted(
        list(
            set(
                [
                    device["site"]["name"]
                    for device in netbox_graphql_endpoint(peering_switches_sites_query)[
                        "data"
                    ]["device_list"]
                ]
            )
        )
    )
    return peering_switches_sites


if __name__ == "__main__":
    # Check for shared config
    OPERATOR_CONFIG_FILE = "/opt/sfmix/operator_config.yaml"
    with open(OPERATOR_CONFIG_FILE) as f:
        operator_config = yaml.load(f)
    for required_config in [
        "netbox_api_endpoint",
        "netbox_api_key",
        "peeringdb_api_key",
        "ipv4_peering_prefix",
        "ipv6_peering_prefix",
    ]:
        if not operator_config.get(required_config):
            sys.exit(f"No {required_config} in {OPERATOR_CONFIG_FILE}")
    # Take inputs
    new_participant_asn = input("New participant ASN?: ")
    try:
        int(new_participant_asn)
    except ValueError:
        sys.exit("That ASN doesn't appear to be an integer")

    new_participant_port_speed = input('New interface speed? (in Gbit/s; e.g. "10"): ')
    try:
        port_speed_gbps = int(new_participant_port_speed)
    except ValueError:
        sys.exit("That speed doesn't appear to be an integer")
    desired_interface_speed_bps = port_speed_gbps * 1e9
    # Find applicable sites
    existing_sites = existing_peering_sites()
    print("Existing peering sites are: ")
    for site in existing_sites:
        print("    ", site)
    new_participant_site = input("Which site is the participant joining in? ")
    if new_participant_site not in existing_sites:
        sys.exit(
            f'The chosen site "{new_participant_site}" doesn\'t appear to be an existing peering site'
        )
    # Do the thing
    main(
        operator_config=operator_config,
        new_participant_asn=new_participant_asn,
        new_participant_site=new_participant_site,
        desired_interface_speed_bps=desired_interface_speed_bps,
    )
