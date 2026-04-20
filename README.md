# 🌉 SFMIX

**San Francisco Metropolitan Internet eXchange** — a community-driven and operated Internet Exchange in the San Francisco Bay Area since 2006. Keeping Bay Area traffic local since before it was cool.

🔗 [sfmix.org](https://sfmix.org/) · 📬 tech-c@sfmix.org

---

## 🌐 Website

The public-facing Hugo static site now lives in its own repo: [sfmix/website](https://github.com/sfmix/website). Deployed to [web.sfmix.org](https://web.sfmix.org/) via GitHub Pages.

## 🔧 `ansible/`

Ansible roles and playbooks that keep the lights on — network devices, servers, and services. Highlights include:

- **`sfmix_arouteserver`** / **`sfmix_route_server_linux`** — route server config generation ([ARouteServer](https://arouteserver.readthedocs.io/)) and BIRD deployment
- **`sfmix_looking_glass`** — looking glass and participant data publishing
- **`sfmix_network_devices`** — peering switch configuration management
- **`sfmix_website`** — provisions the web server (nginx, Let's Encrypt TLS, deploy user for CI/CD)
- **`sfmix_dns`** — authoritative DNS zone management
- **`snappy`** — the speed test stack (LibreSpeed, OpenSpeedTest, TAUC TR-143, iperf3)
- …and more (monitoring, flow collection, RPKI, etc.)

## 🐍 `scripts/`

Handy Python utilities for day-to-day IXP operations:

- **`new_participant.py`** — interactively onboard a new participant in NetBox, finding available pre-patched switchports
- **`discovery.py`** — ARP/NDP MAC discovery, VLAN→interface mapping, and NetBox updates
- **`route_server_parity.py`** — compare BGP session state across route servers to find participants missing parity
- **`participant_speeds.py`** — port speed reporting by site and in total
- **`netbox_ix_lint.py`** — lint and validate NetBox IX data

## 📖 `documentation/`

Public SFMIX docs — BGP community references, Nokia SR OS cheatsheet, NetBox conventions, and design docs. Private documentation lives in [sfmix/documentation](https://github.com/sfmix/documentation).

## 🌡️ `sensors/`

[ESPHome](https://esphome.io/) configs for environmental sensors deployed at IX sites. Because even bits like it cool.
