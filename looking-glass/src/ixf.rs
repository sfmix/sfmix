//! IX-F Member Export builder.
//!
//! Produces a JSON value conforming to the IX-F Member Export Schema v1.0
//! (`doc/ixp-member-list.schema.json`). PeeringDB imports it from
//! `https://lg.sfmix.org/api/v1/participants.json`.
//! Used by both the monolith REST frontend and the lg-server RPC endpoint.

use crate::netbox::{NetboxIxpData, NetboxParticipant, ParticipantIp};

/// Build the full IX-F Member Export JSON document.
pub fn build_ixf_export(
    ixp_data: &NetboxIxpData,
    participants: &[NetboxParticipant],
) -> serde_json::Value {
    // Build switch list
    let switches: Vec<serde_json::Value> = ixp_data
        .switches
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "name": s.name,
                "colo": s.colo,
                "pdb_facility_id": s.pdb_facility_id,
                "city": s.city,
                "country": s.country,
                "manufacturer": s.manufacturer,
                "model": s.model,
            })
        })
        .collect();

    // Build VLAN list
    let vlans: Vec<serde_json::Value> = ixp_data
        .vlans
        .iter()
        .map(|v| {
            let mut vlan = serde_json::json!({
                "id": v.id,
                "name": v.name,
            });
            if let (Some(ref prefix), Some(mask)) = (&v.ipv4_prefix, v.ipv4_mask_length) {
                vlan["ipv4"] = serde_json::json!({ "prefix": prefix, "mask_length": mask });
            }
            if let (Some(ref prefix), Some(mask)) = (&v.ipv6_prefix, v.ipv6_mask_length) {
                vlan["ipv6"] = serde_json::json!({ "prefix": prefix, "mask_length": mask });
            }
            vlan
        })
        .collect();

    // Build member list
    // IXP members only (tenants tagged ixp_participant / ixp_infrastructure),
    // and only once one of their IPs is linked to a peering port: a
    // newly-approved joiner whose port isn't turned up yet is left out.
    let mut members: Vec<serde_json::Value> = Vec::new();
    for p in participants.iter().filter(|p| p.ixp_membership.is_some()) {
        let member_type = match p.participant_type.as_deref() {
            Some("Infrastructure") => "ixp",
            _ => "peering",
        };

        let connections = build_connection_list(p, ixp_data);
        if connections.is_empty() {
            continue;
        }
        members.push(serde_json::json!({
            "asnum": p.asn,
            "member_type": member_type,
            "name": p.name,
            "connection_list": connections,
        }));
    }
    members.sort_by_key(|m| m["asnum"].as_u64().unwrap_or(0));

    // RFC 3339 (the schema's `date-time`): "2026-11-21T09:05:11Z".
    let timestamp = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    serde_json::json!({
        "version": "1.0",
        "timestamp": timestamp,
        "ixp_list": [{
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
        }],
        "member_list": members,
    })
}

/// Build the connection_list for a participant in IX-F format: one connection
/// per peering port its IPs are linked to. PeeringDB maps each connection's
/// switch to a facility, so a connection never spans two ports.
fn build_connection_list(p: &NetboxParticipant, ixp_data: &NetboxIxpData) -> Vec<serde_json::Value> {
    let vlan_id = ixp_data.vlans.first().map(|v| v.id).unwrap_or(1);
    let ip_obj = |ip: &ParticipantIp| {
        let mut obj = serde_json::json!({ "address": ip.address });
        if let Some(ref mac) = ip.mac_address {
            obj["mac_addresses"] = serde_json::json!([mac]);
        }
        obj
    };

    let mut connections = Vec::new();
    for port in p.ip_ports(ixp_data) {
        // if_speed: rate_limit_bps/1e6 or speed (already Mbps)
        let if_speed = port.rate_limit_bps.map(|rl| rl / 1_000_000).or(port.speed);
        let mut if_entry = serde_json::json!({ "switch_id": port.device_id });
        if let Some(speed) = if_speed {
            if_entry["if_speed"] = serde_json::json!(speed);
        }

        // Pair this port's addresses up by family: one vlan_list entry per
        // (IPv4, IPv6) pair, so a second address on the same port isn't lost.
        let on_port = |family: &str| -> Vec<&ParticipantIp> {
            p.ip_addresses
                .iter()
                .filter(|ip| ip.participant_lag_id == Some(port.interface_id) && ip.family == family)
                .collect()
        };
        let (v4, v6) = (on_port("IPv4"), on_port("IPv6"));
        let vlan_list: Vec<serde_json::Value> = (0..v4.len().max(v6.len()))
            .map(|i| {
                let mut entry = serde_json::json!({ "vlan_id": vlan_id });
                if let Some(ip) = v4.get(i) {
                    entry["ipv4"] = ip_obj(ip);
                }
                if let Some(ip) = v6.get(i) {
                    entry["ipv6"] = ip_obj(ip);
                }
                entry
            })
            .collect();

        connections.push(serde_json::json!({
            "ixp_id": 155,
            "state": "active",
            "if_list": [if_entry],
            "vlan_list": vlan_list,
        }));
    }
    connections
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netbox::{EnrichedPort, IxpMembership};

    fn port(interface_id: u64, device_id: u64, speed: u64) -> EnrichedPort {
        EnrichedPort {
            device: format!("switch{device_id:02}.tst01"),
            interface: format!("Ethernet{interface_id}"),
            device_id,
            site: "tst01".into(),
            interface_id,
            speed: Some(speed),
            rate_limit_bps: None,
            enabled: true,
            member_interfaces: Vec::new(),
        }
    }

    fn ip(address: &str, port: u64) -> ParticipantIp {
        ParticipantIp {
            address: address.into(),
            family: if address.contains(':') { "IPv6" } else { "IPv4" }.into(),
            mac_address: None,
            status: "active".into(),
            participant_lag_id: Some(port),
        }
    }

    fn participant(
        asn: u32,
        membership: Option<IxpMembership>,
        owned: Vec<EnrichedPort>,
        ip_addresses: Vec<ParticipantIp>,
    ) -> NetboxParticipant {
        NetboxParticipant {
            asn,
            name: format!("Example {asn}"),
            participant_type: None,
            ixp_membership: membership,
            ports: Vec::new(),
            enriched_ports: owned,
            ip_addresses,
        }
    }

    #[test]
    fn connections_follow_ips_onto_shared_trunks() {
        // Port 10 is a member's own port; 20 and 30 are unowned hypervisor
        // trunks on different switches, shared by two infrastructure ASNs.
        let ixp = NetboxIxpData {
            peering_ports: [port(10, 1, 10_000), port(20, 2, 1_000), port(30, 3, 200_000)]
                .into_iter()
                .map(|p| (p.interface_id, p))
                .collect(),
            ..Default::default()
        };
        let ps = vec![
            participant(64512, Some(IxpMembership::Participant), vec![port(10, 1, 10_000)],
                vec![ip("192.0.2.10", 10), ip("2001:db8::10", 10)]),
            // Port turned up, no IP yet: not exported.
            participant(64513, Some(IxpMembership::Participant), vec![port(11, 1, 10_000)], vec![]),
            // Not an IXP member.
            participant(64514, None, vec![], vec![ip("192.0.2.14", 10)]),
            // Two route servers on two trunks: one connection each.
            participant(64515, Some(IxpMembership::Infrastructure), vec![],
                vec![ip("192.0.2.253", 20), ip("2001:db8::253", 20), ip("192.0.2.254", 30), ip("2001:db8::254", 30)]),
            // Two addresses on one trunk: one connection, two vlan_list entries.
            participant(64516, Some(IxpMembership::Infrastructure), vec![],
                vec![ip("192.0.2.1", 20), ip("192.0.2.2", 20), ip("2001:db8::1", 20)]),
        ];
        let v = build_ixf_export(&ixp, &ps);
        let members = v["member_list"].as_array().unwrap();
        let asns: Vec<u64> = members.iter().map(|m| m["asnum"].as_u64().unwrap()).collect();
        assert_eq!(asns, vec![64512, 64515, 64516]);

        let conns = |asn: u64| members.iter().find(|m| m["asnum"] == asn).unwrap()["connection_list"].clone();
        let rs = conns(64515);
        assert_eq!(rs[0]["if_list"], serde_json::json!([{ "switch_id": 2, "if_speed": 1_000 }]));
        assert_eq!(rs[0]["vlan_list"][0]["ipv4"]["address"], "192.0.2.253");
        assert_eq!(rs[1]["if_list"], serde_json::json!([{ "switch_id": 3, "if_speed": 200_000 }]));
        assert_eq!(rs[1]["vlan_list"][0]["ipv6"]["address"], "2001:db8::254");
        let shared = conns(64516);
        assert_eq!(shared.as_array().unwrap().len(), 1);
        assert_eq!(shared[0]["vlan_list"][1]["ipv4"]["address"], "192.0.2.2");
        assert!(shared[0]["vlan_list"][1].get("ipv6").is_none());

        // PeeringDB rejects a connection whose interfaces span facilities.
        for m in members {
            for c in m["connection_list"].as_array().unwrap() {
                assert_eq!(c["if_list"].as_array().unwrap().len(), 1, "{m}");
            }
        }
        let ts = v["timestamp"].as_str().unwrap();
        assert!(ts.ends_with('Z') && ts.len() == 20, "RFC 3339 UTC timestamp, got {ts}");
    }
}
