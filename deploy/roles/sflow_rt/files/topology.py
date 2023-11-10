#!/usr/bin/env python3
import netrc
import pyeapi
import requests
import sys

# eAPI info
EAPI_TRANSPORT = "https"
NETRC_HOST = "oob.sfmix.org"
# FIXME / TODO: The set of devices to discover should come from a Source of
#   Truth, like Netbox
SWITCHES = [
    "switch01.oob.sfo01.sfmix.org",
    "switch02.oob.sfo02.sfmix.org",
    "switch01.oob.sfo02.sfmix.org",
    "switch03.fmt01.sfmix.org",
    "switch02.oob.fmt01.sfmix.org",
    "switch01.oob.fmt01.sfmix.org",
    "switch01.oob.sjc01.sfmix.org",
    "switch02.oob.sjc01.sfmix.org",
    "switch01.oob.scl01.sfmix.org",
    "switch01.oob.scl02.sfmix.org",
]

# sFlow-RT REST API
RT = "http://metrics.sfo02.sfmix.org:8008/topology/json"

netrc_file = netrc.netrc()
auth_info = netrc_file.authenticators(NETRC_HOST)
if not auth_info:
    print("Couldn't get login for %s" % NETRC_HOST)
    sys.exit(1)
else:
    EAPI_USER, _, EAPI_PASSWD = auth_info

nodes = {}
links = {}
topology = {"nodes": nodes, "links": links}

linknames = {}
portGroups = {}


def getInfo(ip):
    commands = [
        "show lldp neighbors",
        "show hostname",
        "show snmp mib ifmib ifindex",
        "show sflow",
        "show interfaces",
    ]

    node = pyeapi.connect(
        host=ip,
        transport=EAPI_TRANSPORT,
        username=EAPI_USER,
        password=EAPI_PASSWD,
        return_node=True,
    )
    response = node.enable(commands)

    lldp = response[0]["result"]["lldpNeighbors"]
    hostname = response[1]["result"]["fqdn"]
    ifIndexes = response[2]["result"]["ifIndex"]
    agentAddr = response[3]["result"]["ipv4Sources"][0]["ipv4Address"]
    ifaces = response[4]["result"]["interfaces"]

    dev = {}
    nodes[hostname] = dev
    dev["agent"] = agentAddr
    ports = {}
    dev["ports"] = ports

    for p in ifIndexes:
        ports[p] = {"ifindex": str(ifIndexes[p])}

    for n in lldp:
        if "%s %s" % (hostname, n["port"]) < "%s %s" % (
            n["neighborDevice"],
            n["neighborPort"],
        ):
            lname = "%s %s" % (hostname, n["port"])
            if linknames.get(lname) == None:
                linknames[lname] = {
                    "node1": hostname,
                    "port1": n["port"],
                    "node2": n["neighborDevice"],
                    "port2": n["neighborPort"],
                }
        else:
            lname = "%s %s" % (n["neighborDevice"], n["neighborPort"])
            if linknames.get(lname) == None:
                linknames[lname] = {
                    "node1": n["neighborDevice"],
                    "port1": n["neighborPort"],
                    "node2": hostname,
                    "port2": n["port"],
                }
    for iface in ifaces:
        members = ifaces[iface].get("memberInterfaces")
        if members == None:
            continue
        for member in members:
            portGroups["%s %s" % (hostname, member)] = {"node": hostname, "port": iface}


def getInternalLinks():
    lagnames = {}
    linkno = 1
    lagno = 1
    for n in linknames:
        entry = linknames[n]
        if nodes.get(entry["node1"]) != None and nodes.get(entry["node2"]) != None:
            links["L%s" % linkno] = entry
            linkno = linkno + 1
            portGroup1 = portGroups.get("%s %s" % (entry["node1"], entry["port1"]))
            portGroup2 = portGroups.get("%s %s" % (entry["node2"], entry["port2"]))
            if portGroup1 != None and portGroup2 != None:
                if "%s %s" % (portGroup1["node"], portGroup1["port"]) < "%s %s" % (
                    portGroup2["node"],
                    portGroup2["port"],
                ):
                    lname = "%s %s" % (portGroup1["node"], portGroup1["port"])
                    if lagnames.get(lname) == None:
                        lentry = {
                            "node1": portGroup1["node"],
                            "port1": portGroup1["port"],
                            "node2": portGroup2["node"],
                            "port2": portGroup2["port"],
                        }
                        lagnames[lname] = lentry
                        links["G%s" % lagno] = lentry
                        lagno = lagno + 1
                else:
                    lname = "%s %s" % (portGroup2["node"], portGroup2["port"])
                    if lagnames.get(lname) == None:
                        lentry = {
                            "node1": portGroup2["node"],
                            "port1": portGroup2["port"],
                            "node2": portGroup1["node"],
                            "port2": portGroup1["port"],
                        }
                        lagnames[lname] = lentry
                        links["G%s" % lagno] = lentry
                        lagno = lagno + 1


for switch in SWITCHES:
    try:
        getInfo(switch)
    except Exception as e:
        print("Exception while connecting to %s: %r" % (switch, e))
        sys.exit(2)

getInternalLinks()

try:
    r = requests.put(RT, json=topology)
    if r.status_code != 204:
        print("Exception connecting to %s: status %s" % (RT, r.status_code))
        sys.exit(3)
except Exception as e:
    print("Exception connecting to %s: %r" % (RT, e))
    sys.exit(4)
