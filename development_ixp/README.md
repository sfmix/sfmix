# Development IXP

This directory/subproject is meant to provide a way of emulating most of the major functions of the IXP environment, such that developers of software have something to work with while offline, or without access to production hardware.

Sub-directory components in here:
- virtual_network/
  - Emulated network devices
  - Containerlab running Arista cEOS
- netbox-docker/
  - A git subtree of the netbox-community/netbox-docker github project
  - A docker compose environment for a Netbox stack
- monitoring/
  - A monitoring stack with LibreNMS, Grafana
- libreixp/
  - Python libraries used to bootstrap devices and interact with Netbox

## Supported Environments
- Architecture: x86 / x86_64
  - Limited by the only platform supported by container images

## Software Pre-requisites
- Docker Engine
  - `docker version` should show a server version
- Docker CLI / docker compose
  - `docker compose` should show some help text
- containerlab
  - https://containerlab.dev/install/
  - `containerlab` should print some help text

## Bring-up
- Download Arista cEOS image 4.29.2F from Arista and import into Docker Engine
  - `docker import cEOS64-lab-4.29.2F.tar arista_eos:4.29.2F`
  - This is the image referenced by virtual_network/ix.clab.yml

- Start switches
  - `make -C virtual_network up`
- Start netbox
  - `make -C netbox-docker up`
- Visit http://[docker engine IP]:8000 and see a fresh netbox with no data
  - Login: admin/admin
- Bootstrap/onboard switches into Netbox
  - `make -C sfmix bootstrap`

- Visit http://[docker engine IP]:8000 again and see a netbox populated with data
- Print out a Participants YAML List, similar to the old Ansible Inventory
  - `make -C sfmix participants_yaml`


## Tear-down
- Stop netbox / destroy data
  - `make -C netbox-docker down`
- Stop switches
  - `make -C virtual_network down`
