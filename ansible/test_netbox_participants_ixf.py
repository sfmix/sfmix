#!/usr/bin/env python3
"""
Standalone test script for netbox_participants_ixf module.
This allows you to debug the module without running it through Ansible.
"""

import sys
import os
import json
from datetime import datetime

# Add the library directory to the path so we can import the module
sys.path.insert(0, os.path.dirname(__file__))

# Import the module functions directly
from library.netbox_participants_ixf import (
    fetch_netbox_data,
    process_switches,
    process_vlans,
    process_participants
)

def main():
    # Configuration - replace these with your actual NetBox API details
    NETBOX_API_ENDPOINT = "https://netbox.sfmix.org"  # Replace with your NetBox URL
    NETBOX_API_TOKEN = "5add47556d4526eb1e2dfd4428a4dcf069d03262"  # Replace with your API token
    
    # You can also read these from environment variables for security
    if 'NETBOX_API_ENDPOINT' in os.environ:
        NETBOX_API_ENDPOINT = os.environ['NETBOX_API_ENDPOINT']
    if 'NETBOX_API_TOKEN' in os.environ:
        NETBOX_API_TOKEN = os.environ['NETBOX_API_TOKEN']
    
    if NETBOX_API_TOKEN == "your_api_token_here":
        print("ERROR: Please set your NetBox API token!")
        print("Either edit this script or set environment variables:")
        print("  export NETBOX_API_ENDPOINT='https://your-netbox-url'")
        print("  export NETBOX_API_TOKEN='your-token-here'")
        sys.exit(1)
    
    print("DEBUG: Starting standalone NetBox participants IXF test")
    print(f"DEBUG: NetBox API endpoint: {NETBOX_API_ENDPOINT}")
    
    try:
        # Fetch data from NetBox API
        print("DEBUG: Fetching data from NetBox API...")
        netbox_data = fetch_netbox_data(NETBOX_API_ENDPOINT, NETBOX_API_TOKEN)
        
        # Extract data dictionaries
        netbox_devices = netbox_data['netbox_devices']
        netbox_sites = netbox_data['netbox_sites']
        exchange_fabric_vlans = netbox_data['exchange_fabric_vlans']
        netbox_prefixes = netbox_data['netbox_prefixes']
        netbox_participants = netbox_data['netbox_participants']
        netbox_peering_port_interfaces = netbox_data['netbox_peering_port_interfaces']
        netbox_participant_ip_addresses = netbox_data['netbox_participant_ip_addresses']
        
        # Generate timestamp
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        print(f"DEBUG: Generated timestamp: {timestamp}")
        
        # Process switches
        print("DEBUG: Processing switches...")
        switches = process_switches(netbox_devices, netbox_sites)
        print(f"DEBUG: Found {len(switches)} switches")
        
        # Process VLANs
        print("DEBUG: Processing VLANs...")
        vlans = process_vlans(exchange_fabric_vlans, netbox_prefixes)
        print(f"DEBUG: Found {len(vlans)} VLANs")
        
        # Process participants
        print("DEBUG: Processing participants...")
        members = process_participants(
            netbox_participants,
            netbox_peering_port_interfaces,
            netbox_participant_ip_addresses,
            exchange_fabric_vlans,
            netbox_prefixes,
        )
        print(f"DEBUG: Found {len(members)} members")
        
        # Build final result
        print("DEBUG: Building final IXF data structure...")
        ixp_data = {
            "version": "1.0",
            "timestamp": timestamp,
            "ixp_list": [
                {
                    "shortname": "SFMIX",
                    "name": "San Francisco Metropolitan Internet Exchange",
                    "ixp_id": 155,
                    "ixf_id": 223,
                    "peeringdb_id": 155,
                    "country": "US",
                    "url": "https://sfmix.org/",
                    "support_email": "tech-c@sfmix.org",
                    "support_phone": "+1 415 634-6712",
                    "switch": switches,
                    "vlan": vlans,
                    "member_list": members,
                }
            ],
        }
        
        # Save to file
        output_file = "/tmp/participants_ixf_debug.json"
        with open(output_file, 'w') as f:
            json.dump(ixp_data, f, indent=2)
        
        print(f"DEBUG: Successfully generated IXF data!")
        print(f"DEBUG: - Switches: {len(switches)}")
        print(f"DEBUG: - VLANs: {len(vlans)}")
        print(f"DEBUG: - Members: {len(members)}")
        print(f"DEBUG: - Output saved to: {output_file}")
        
        return ixp_data
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
