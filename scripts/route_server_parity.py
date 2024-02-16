#!/usr/bin/env python3
# Check for client configuration parity between route servers
import collections
import requests

BIRDWATCHER_ENDPOINT = "http://mgmt.rs-linux.sfmix.org:29184"
BGPLGD_ENDPOINT = "http://100.64.0.7/api"

ip_session_map = collections.defaultdict(dict)

birdwatcher_protocols_json = requests.get(BIRDWATCHER_ENDPOINT + "/protocols/bgp", headers={"Accept":"application/json"})
birdwatcher_protocols_json.raise_for_status()
birdwatcher_protocols = birdwatcher_protocols_json.json()

bgplgd_neighbors_json = requests.get(BGPLGD_ENDPOINT + "/neighbors", headers={"Accept":"application/json"})
bgplgd_neighbors_json.raise_for_status()
bgplgd_neighbors = bgplgd_neighbors_json.json()

for protocol_name, protocol in birdwatcher_protocols['protocols'].items():
    if existing_asn := ip_session_map[protocol['neighbor_address']].get('asn'):
        if existing_asn != int(protocol['neighbor_as']):
            print(f"[!!] detected existing session for {protocol['neighbor_address']} using asn {existing_asn}, but now sesing asn {protocol['neighbor_as']}")
    else:
        ip_session_map[protocol['neighbor_address']]['asn'] = int(protocol['neighbor_as'])
    
    if protocol['connection'] == "Established":
        ip_session_map[protocol['neighbor_address']]['birdwatcher'] = True
    else:
        ip_session_map[protocol['neighbor_address']]['birdwatcher'] = False

for neighbor in bgplgd_neighbors['neighbors']:
    if existing_asn := ip_session_map[neighbor['remote_addr']].get('asn'):
        if existing_asn != int(neighbor['remote_as']):
            print(f"[!!] detected existing session for {neighbor['remote_addr']} using asn {existing_asn}, but now sesing asn {neighbor['remote_as']}")
    else:
        ip_session_map[neighbor['remote_addr']]['asn'] = int(neighbor['remote_as'])
    
    if neighbor['state'] == "Established":
        ip_session_map[neighbor['remote_addr']]['bgplgd'] = True
    else:
        ip_session_map[neighbor['remote_addr']]['bgplgd'] = False


for ip, session_map in ip_session_map.items():
    bgplgd = session_map.get('bgplgd')
    birdwatcher = session_map.get('birdwatcher')
    if bgplgd and birdwatcher:
        pass
        # print(f"[..] IP {ip} (AS{session_map['asn']}) is Established to both Route Servers")
    elif (not bgplgd) and (not birdwatcher):
        pass
        # print(f"[__] IP {ip} (AS{session_map['asn']} is not Established to either Route Server")
    elif bgplgd and not birdwatcher:
        print(f"[!.] IP {ip} (AS{session_map['asn']}) is Established with OpenBGPD, but _not_ with BIRD!")
    elif (not bgplgd) and birdwatcher:
        print(f"[.!] IP {ip} (AS{session_map['asn']}) is Established with BIRD, but _not_ with OpenBSD!")
