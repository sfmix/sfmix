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

import os
import yaml
import sys
import pynetbox
import requests
from sgqlc.endpoint.http import HTTPEndpoint
import ipaddress

from rich.console import Console
import questionary

console = Console()


def find_available_port(netbox, netbox_graphql, new_participant_site, netbox_port_speed):
    """Find pre-patched, unassigned ports at the site matching the desired speed."""
    with console.status("[bold blue]Querying peering switch ports..."):
        peering_switches_at_site = netbox.dcim.devices.filter(
            site=new_participant_site, role="peering_switch"
        )
        peering_switch_id_strings = list(
            map(str, [switch["id"] for switch in peering_switches_at_site])
        )
        peering_switches_ports_query = """
        query($device_ids: [String!]) {
            interface_list(device_id: $device_ids) {
                id
                name
                description
                speed
                lag {
                    id
                }
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
        peering_switches_ports = netbox_graphql(
            peering_switches_ports_query, {"device_ids": peering_switch_id_strings}
        )
    patched_and_unassigned_ports = []
    for port in peering_switches_ports["data"]["interface_list"]:
        if port["custom_fields"].get("participant"):
            # Already assigned
            continue
        if port["lag"]:
            # Already in a LAG
            continue
        if not port["cable"]:
            # Not patched
            continue
        if not port["speed"] == netbox_port_speed:
            # Wrong speed
            # FIXME: This really ought to selecting by optic media type, though netbox
            #   doesn't model this well. For example: colored optics or BiDi
            continue
        is_patched_to_patch_panel = False
        for termination in port["cable"]["terminations"]:
            if termination["_device"]["role"]["slug"] == "patch_panel":
                is_patched_to_patch_panel = True
        if is_patched_to_patch_panel:
                patched_and_unassigned_ports.append(port)
    if not patched_and_unassigned_ports:
        console.print("[red bold]No available ports found matching criteria.[/red bold]")
        sys.exit(1)
    console.print(f"Found [green]{len(patched_and_unassigned_ports)}[/green] available ports")
    choices = [
        questionary.Choice(
            title=f"{port['device']['name']}/{port['name']} \u2014 {port['description'] or '(no description)'}",
            value=port,
        )
        for port in patched_and_unassigned_ports
    ]
    selected_port = questionary.select(
        "Select a port:",
        choices=choices,
        use_search_filter=True,
        use_jk_keys=False,
    ).ask()
    if selected_port is None:
        sys.exit(130)
    return selected_port


def find_manual_port(netbox, new_participant_site, device_name, interface_name):
    """Look up a manually specified port, validate it, and return port info dict."""
    with console.status("[bold blue]Validating port..."):
        peering_switches = list(netbox.dcim.devices.filter(
            site=new_participant_site, role="peering_switch"
        ))
        switch_names = [s.name for s in peering_switches]
        if device_name not in switch_names:
            console.print(
                f"[red bold]Device '{device_name}' is not a peering switch at site"
                f" '{new_participant_site}'.[/red bold]\n"
                f"Available switches: {', '.join(switch_names)}"
            )
            sys.exit(1)
        target_device = next(s for s in peering_switches if s.name == device_name)
        candidates = list(netbox.dcim.interfaces.filter(
            device=device_name, name=interface_name
        ))
    if not candidates:
        console.print(f"[red bold]Interface '{interface_name}' not found on device '{device_name}'[/red bold]")
        sys.exit(1)
    port = candidates[0]
    if port.custom_fields.get("participant"):
        console.print(
            f"[red bold]Interface {device_name}/{interface_name} is already assigned"
            f" to participant:[/red bold] {port.custom_fields['participant']}"
        )
        sys.exit(1)
    is_lag = interface_name.startswith("Port-Channel")
    selected_port = {
        "id": port.id,
        "name": port.name,
        "description": port.description,
        "speed": port.speed,
        "device": {"id": target_device.id, "name": target_device.name},
    }
    if is_lag:
        selected_port["is_lag"] = True
        selected_port["existing_lag_id"] = port.id
        console.print(f"[green]Using LAG:[/green] {device_name}/{interface_name}")
    elif port.lag:
        selected_port["existing_lag_id"] = port.lag.id
        console.print(f"[green]Using port:[/green] {device_name}/{interface_name} (in existing LAG {port.lag.name})")
    else:
        console.print(f"[green]Using port:[/green] {device_name}/{interface_name}")
    if port.speed:
        console.print(f"  Speed: {port.speed} kbps")
    return selected_port


def main(
    operator_config,
    new_participant_asn,
    new_participant_site,
    desired_interface_speed_bps=None,
    manual_port_device=None,
    manual_port_interface=None,
):
    netbox = netbox_client(operator_config=operator_config)
    netbox_graphql = graphql_endpoint(operator_config=operator_config)
    # Lookup ASN Name in PeeringDB
    with console.status("[bold blue]Looking up ASN in PeeringDB..."):
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
            console.print(
                f"[red bold]PeeringDB API failure:[/red bold]"
                f" {peeringdb_asn_response.content.decode('utf-8')}"
            )
            sys.exit(1)
        peeringdb_asn_data = peeringdb_asn_response.json()["data"][0]
        peeringdb_asn_name = peeringdb_asn_data["name"]
    console.print(f"PeeringDB name: [bold]{peeringdb_asn_name}[/bold]")
    # Search for existing Tenant or create one
    with console.status("[bold blue]Resolving Netbox tenant..."):
        existing_netbox_tenants = list(netbox.tenancy.tenants.filter(slug=f"as{new_participant_asn}"))
        if existing_netbox_tenants:
            netbox_tenant = existing_netbox_tenants[0]
            tenant_msg = f"Using existing tenant: {netbox_tenant.url}"
        else:
            netbox_tenant = netbox.tenancy.tenants.create(
                name=f"AS{new_participant_asn}",
                slug=f"as{new_participant_asn}",
                description=peeringdb_asn_name,
                tags=[{"slug": "ixp_participant"}],
                custom_fields={"participant_type": "Member", "as_number": int(new_participant_asn)},
            )
            tenant_msg = f"Created new tenant: {netbox_tenant['url']}"
    console.print(tenant_msg)

    # Select port: manual specification or from available pre-patched ports
    if manual_port_device and manual_port_interface:
        selected_port = find_manual_port(
            netbox, new_participant_site, manual_port_device, manual_port_interface
        )
        netbox_port_speed = selected_port["speed"]
    else:
        netbox_port_speed = int(desired_interface_speed_bps / 1_000)
        selected_port = find_available_port(
            netbox, netbox_graphql, new_participant_site, netbox_port_speed
        )
    with console.status("[bold blue]Setting up LAG and port assignment..."):
        exchange_fabric_vlans_group_id = list(
            netbox.ipam.vlan_groups.filter(slug="exchange_fabric_vlans")
        )[0].id
        peering_lan = netbox.ipam.vlans.get(
            group_id=exchange_fabric_vlans_group_id, vid=998
        )
        jumbo_peering_lan = netbox.ipam.vlans.get(
            group_id=exchange_fabric_vlans_group_id, vid=999
        )
        existing_lag_id = selected_port.get("existing_lag_id")
        if existing_lag_id:
            # LAG already exists from device discovery — update it
            port_channel_interface = netbox.dcim.interfaces.get(existing_lag_id)
            port_channel_interface.enabled = True
            port_channel_interface.description = f"Peer: {peeringdb_asn_name} (AS{new_participant_asn})"
            port_channel_interface.speed = netbox_port_speed
            port_channel_interface.mode = "tagged"
            port_channel_interface.untagged_vlan = peering_lan.id
            port_channel_interface.tagged_vlans = [peering_lan.id, jumbo_peering_lan.id]
            port_channel_interface.tags = [{"slug": "ixp_participant"}, {"slug": "peering_port"}]
            port_channel_interface.custom_fields = {"participant": netbox_tenant.id}
            port_channel_interface.save()
            port_channel_name = port_channel_interface.name
        else:
            # Create new Port-Channel
            port_channel_name = next_available_port_channel_for_device_id(netbox=netbox,
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
    if existing_lag_id:
        console.print(f"Updated existing LAG [bold]{port_channel_name}[/bold]: {port_channel_interface.url}")
    else:
        console.print(f"Created LAG [bold]{port_channel_name}[/bold]: {port_channel_interface.url}")
    # Assign the Interface to the tenant
    # Update interface description
    # Enable Interface
    if selected_port.get("is_lag"):
        # Selected a Port-Channel directly — members are already assigned
        peering_port = port_channel_interface
        console.print(f"LAG selected directly; skipping physical port configuration")
    else:
        with console.status("[bold blue]Configuring physical port..."):
            peering_port = netbox.dcim.interfaces.get(selected_port["id"])
            peering_port.enabled = True
            peering_port.lag = port_channel_interface.id
            peering_port.description = (
                f"{peeringdb_asn_name} LAG Member (AS{new_participant_asn})"
            )
            peering_port.custom_fields = {"lacp_mode": "on", "participant": netbox_tenant.id}
            peering_port.save()
        console.print(f"Configured physical port in [bold]{port_channel_name}[/bold]: {peering_port.url}")

    # IPv4 Next-Available
    with console.status("[bold blue]Allocating IP addresses..."):
        next_ipv4_address = list(
            netbox.ipam.prefixes.filter(prefix=operator_config["ipv4_peering_prefix"])
        )[0].available_ips.list()[0].address
        ipv4_address = netbox.ipam.ip_addresses.create(
            address=next_ipv4_address,
            tenant=netbox_tenant.id,
            tags=[{"slug": "ixp_participant"}],
            custom_fields={"participant_lag": port_channel_interface.id},
        )

        # IPv6 Address Templating
        zero_padded_asn = new_participant_asn.zfill(6)
        asn_hex_byte_one = str(zero_padded_asn[0:2])
        asn_hex_byte_two = str(zero_padded_asn[2:4])
        asn_hex_byte_three = str(zero_padded_asn[4:6])
        v6_address = str(
            ipaddress.IPv6Network(operator_config["ipv6_peering_prefix"]).network_address
        )
        v6_address = apply_ipv6_mask(
            v6_address, 10, "ba"
        )  # The "ba" stands for "Bay Area" ;)
        v6_address = apply_ipv6_mask(v6_address, 11, asn_hex_byte_one)
        v6_address = apply_ipv6_mask(v6_address, 12, asn_hex_byte_two)
        v6_address = apply_ipv6_mask(v6_address, 13, asn_hex_byte_three)
        v6_address = apply_ipv6_mask(v6_address, 15, "01")
        ipv6_address = netbox.ipam.ip_addresses.create(
            address=f"{v6_address}/64",
            tenant=netbox_tenant.id,
            tags=[{"slug": "ixp_participant"}],
            custom_fields={"participant_lag": port_channel_interface.id},
        )
    console.print(f"Allocated IPv4: [bold green]{ipv4_address.address}[/bold green]  {ipv4_address.url}")
    console.print(f"Allocated IPv6: [bold green]{ipv6_address.address}[/bold green]  {ipv6_address.url}")

    # Trace patching for LOA landing info
    loa_info = None
    with console.status("[bold blue]Tracing patching for LOA landing info..."):
        for location in reversed(peering_port.trace()):
            if not location:
                continue
            if not isinstance(location, list):
                location = [location]
            for sub_location in location:
                if '/api/dcim/front-ports/' in sub_location.url or '/api/dcim/rear-ports/' in sub_location.url:
                    maybe_patch_panel_device = netbox.dcim.devices.get(sub_location.device.id)
                    if maybe_patch_panel_device.role.slug == "patch_panel":
                        rack_info = None
                        if maybe_patch_panel_device.rack:
                            rack_info = f"{maybe_patch_panel_device.rack.display}, Unit {maybe_patch_panel_device.position}"
                        loa_info = {
                            "patch_panel": maybe_patch_panel_device.name,
                            "rack": rack_info,
                            "ports": " & ".join([sl['name'] for sl in location]),
                        }
                        break
            if loa_info:
                break

    # Summary
    console.print()
    console.print("[bold green]New Participant Provisioned[/bold green]")
    console.print(f"  [bold]Participant:[/bold] {peeringdb_asn_name} (AS{new_participant_asn})")
    console.print(f"  [bold]Site:[/bold] {new_participant_site}")
    console.print(f"  [bold]LAG:[/bold] {selected_port['device']['name']}/{port_channel_interface.name}")
    if not selected_port.get("is_lag"):
        console.print(f"  [bold]Physical Port:[/bold] {selected_port['device']['name']}/{selected_port['name']}")
    console.print(f"  [bold]IPv4:[/bold] {ipv4_address.address}")
    console.print(f"  [bold]IPv6:[/bold] {ipv6_address.address}")
    if loa_info:
        console.print()
        console.print("  [bold]LOA Landing[/bold]")
        console.print(f"    Patch Panel: {loa_info['patch_panel']}")
        if loa_info["rack"]:
            console.print(f"    Rack: {loa_info['rack']}")
        else:
            console.print("    Rack: [yellow]Unknown \u2014 rack this patch panel in Netbox[/yellow]")
        console.print(f"    Ports: {loa_info['ports']}")


def apply_ipv6_mask(ipv6_addr, offset, hex_byte):
    # Convert IPv6 address to integer
    addr_int = int(ipaddress.IPv6Address(ipv6_addr))
    # Convert hex byte to integer
    hex_byte_int = int(hex_byte, 16)
    # Apply the mask
    # Shift the hex byte to the correct position and apply it
    mask = hex_byte_int << (8 * (16 - offset - 1))
    new_addr_int = (addr_int & ~(0xFF << (8 * (16 - offset - 1)))) | mask
    # Convert back to IPv6 address
    return str(ipaddress.IPv6Address(new_addr_int))


def graphql_endpoint(operator_config) -> HTTPEndpoint:
    graphql_headers = {"Authorization": f"Token {operator_config['netbox_api_key']}"}
    netbox_graphql_endpoint = HTTPEndpoint(
        f"{operator_config['netbox_api_endpoint']}graphql/",
        base_headers=graphql_headers,
    )
    return netbox_graphql_endpoint


def next_available_port_channel_for_device_id(
    netbox: pynetbox.core.api.Api, device_id: int
) -> str:
    existing_port_channels = list(
        netbox.dcim.interfaces.filter(device_id=device_id, name__isw="Port-Channel", name__nic=".")
    )
    if not existing_port_channels:
        return "Port-Channel100"
    existing_port_channel_names = [
        port_channel["name"] for port_channel in existing_port_channels
    ]
    numbers = sorted(
        int(pc.split("Port-Channel")[1]) for pc in existing_port_channel_names
    )
    next_number = numbers[0]
    for number in numbers:
        if number != next_number:
            break
        next_number += 1
    return f"Port-Channel{next_number}"


def netbox_client(operator_config) -> pynetbox.core.api.Api:
    return pynetbox.api(
        operator_config["netbox_api_endpoint"], token=operator_config["netbox_api_key"]
    )


def existing_peering_sites(operator_config):
    netbox = netbox_client(operator_config)
    peering_switches = netbox.dcim.devices.filter(role="peering_switch")
    peering_switches_sites = sorted(
        set(device.site.name for device in peering_switches)
    )
    return peering_switches_sites


SFMIX_DEFAULTS = {
    "netbox_api_endpoint": "https://netbox.sfmix.org",
    "ipv4_peering_prefix": "206.197.187.0/24",
    "ipv6_peering_prefix": "2001:504:30::/64",
}


def load_operator_config():
    """Load operator config from env var, ~/.sfmix_operator_config.yaml, or /opt/sfmix/operator_config.yaml.

    Falls back to SFMIX defaults and prompts for missing credentials.
    """
    config_paths = [
        os.environ.get("OPERATOR_CONFIG_FILE"),
        os.path.expanduser("~/.sfmix_operator_config.yaml"),
        "/opt/sfmix/operator_config.yaml",
    ]
    operator_config = {}
    for path in config_paths:
        if path and os.path.isfile(path):
            with open(path) as f:
                operator_config = yaml.safe_load(f) or {}
            console.print(f"Loaded config from [bold]{path}[/bold]")
            break

    # Apply SFMIX defaults for any missing values
    for key, value in SFMIX_DEFAULTS.items():
        operator_config.setdefault(key, value)

    # Prompt for missing credentials
    if not operator_config.get("netbox_api_key"):
        token = questionary.text(
            f"Netbox API token for {operator_config['netbox_api_endpoint']}:",
        ).ask()
        if token is None:
            sys.exit(130)
        operator_config["netbox_api_key"] = token

    if not operator_config.get("peeringdb_api_key"):
        pdb_key = questionary.text("PeeringDB API key:").ask()
        if pdb_key is None:
            sys.exit(130)
        operator_config["peeringdb_api_key"] = pdb_key

    return operator_config


if __name__ == "__main__":
    operator_config = load_operator_config()

    console.print("[bold blue]SFMIX New Participant Setup[/bold blue]\n")

    new_participant_asn = questionary.text(
        "New participant ASN:",
        validate=lambda x: True if x.isdigit() else "ASN must be an integer",
    ).ask()
    if new_participant_asn is None:
        sys.exit(130)

    with console.status("[bold blue]Fetching peering sites..."):
        existing_sites = existing_peering_sites(operator_config=operator_config)

    new_participant_site = questionary.select(
        "Which site is the participant joining in?",
        choices=existing_sites,
        use_search_filter=True,
        use_jk_keys=False,
    ).ask()
    if new_participant_site is None:
        sys.exit(130)

    mode = questionary.select(
        "Port selection mode:",
        choices=[
            questionary.Choice("Select from available pre-patched ports", value="available"),
            questionary.Choice("Specify a port manually (already cabled/discovered)", value="manual"),
        ],
        use_search_filter=True,
        use_jk_keys=False,
    ).ask()
    if mode is None:
        sys.exit(130)

    if mode == "manual":
        netbox = netbox_client(operator_config)
        with console.status("[bold blue]Fetching peering switches..."):
            peering_switches = list(netbox.dcim.devices.filter(
                site=new_participant_site, role="peering_switch"
            ))
        if not peering_switches:
            console.print("[red bold]No peering switches found at this site.[/red bold]")
            sys.exit(1)
        manual_port_device = questionary.select(
            "Device:",
            choices=[s.name for s in peering_switches],
            use_search_filter=True,
            use_jk_keys=False,
        ).ask()
        if manual_port_device is None:
            sys.exit(130)
        with console.status("[bold blue]Fetching interfaces..."):
            device_interfaces = list(netbox.dcim.interfaces.filter(device=manual_port_device))
            non_physical_prefixes = ("Loopback", "Management", "Vlan")
            eligible_interfaces = [
                iface for iface in device_interfaces
                if not iface.name.startswith(non_physical_prefixes)
                and not iface.custom_fields.get("participant")
            ]
        if not eligible_interfaces:
            console.print("[red bold]No eligible interfaces found on this device.[/red bold]")
            sys.exit(1)
        interface_choices = []
        for iface in eligible_interfaces:
            label = f"{iface.name} \u2014 {iface.description or '(no description)'}"
            if iface.speed:
                label += f" [{iface.speed // 1000}G]"
            if iface.name.startswith("Port-Channel"):
                label += " (LAG)"
            interface_choices.append(questionary.Choice(title=label, value=iface.name))
        manual_port_interface = questionary.select(
            "Interface:",
            choices=interface_choices,
            use_search_filter=True,
            use_jk_keys=False,
        ).ask()
        if manual_port_interface is None:
            sys.exit(130)
        main(
            operator_config=operator_config,
            new_participant_asn=new_participant_asn,
            new_participant_site=new_participant_site,
            manual_port_device=manual_port_device,
            manual_port_interface=manual_port_interface,
        )
    else:
        port_speed = questionary.text(
            "Interface speed (Gbit/s):",
            validate=lambda x: True if x.isdigit() else "Speed must be an integer",
        ).ask()
        if port_speed is None:
            sys.exit(130)
        desired_interface_speed_bps = int(port_speed) * 1e9
        main(
            operator_config=operator_config,
            new_participant_asn=new_participant_asn,
            new_participant_site=new_participant_site,
            desired_interface_speed_bps=desired_interface_speed_bps,
        )
