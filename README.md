# SFMIX

A community-driven and operated Internet Exchange in the San Francisco Bay Area
since 2006.
More information is at https://sfmix.org/

## `ansible/`

Deployment tools and configuration with ansible

## `documentation/`

Public SFMIX documentation information.

Private documentation is in the private repo https://github.com/sfmix/documentation

## `scripts/`
* `new_participant.py`
  * Creates a new Internet Exchange participant inside of Netbox, interactively
    prompting for information, this finds available pre-patched switchports and
    configures them for the incoming participant.
* `route_server_parity.py`
  * Using the birdwatcher and bpglgd JSON APIs that operate along side each
    Route Server, this compares the session states between these Route Servers
    to find participant router-IPs that do not have session parity between the
    two Route Servers
* `mac_discovery.py`
  * Using ARP and ICMPv6 Neighbor Discovery, search for the current MAC address
    bindings for participants and update Netbox with the current values. 
