#!/usr/bin/env python
import requests
import collections

def print_site_speeds(participants):
    site_speeds = collections.defaultdict(lambda: collections.defaultdict(int))
    site_port_counts = collections.defaultdict(int)
    switch_id_colo_map = {}
    for switch in participants["ixp_list"][0]["switch"]:
        switch_id_colo_map[switch["id"]] = switch["colo"]
    for participant in participants["member_list"]:
        for connection in participant["connection_list"]:
            for interface in connection["if_list"]:
                speed_bps = interface["if_speed"] * 1_000_000
                colo = switch_id_colo_map[interface["switch_id"]]
                site_speeds[colo][speed_bps] += 1
                site_port_counts[colo] += 1

    for colo, speeds in site_speeds.items():
        print(f"Colo: {colo}")
        for speed, count in sorted(speeds.items()):
            gbit = int(speed / 1_000_000_000)
            percentage = (count / site_port_counts[colo]) * 100
            print(f"   {gbit} G -- {count} ports -- {percentage}%")

def print_total_speeds(participants):
    speed_counts = collections.defaultdict(int)
    for participant in participants["member_list"]:
        for connection in participant["connection_list"]:
            for interface in connection["if_list"]:
                speed_bps = interface["if_speed"] * 1_000_000
                speed_gbit = int(speed_bps / 1_000_000_000)
                speed_counts[speed_gbit] += 1
    print("Port counts by speed: ")
    for speed, count in sorted(speed_counts.items()):
        print(f"  {speed}G -- {count}")


if __name__ == "__main__":
    participants = requests.get("https://lg.sfmix.org/participants.json").json()
    print()
    print_site_speeds(participants=participants)
    print()
    print_total_speeds(participants=participants)
