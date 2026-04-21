//! IX-F Member Export builder.
//!
//! Produces a JSON value conforming to the IX-F Member Export Schema v1.0.
//! Used by both the monolith REST frontend and the lg-server RPC endpoint.

use crate::netbox::{IxpVlan, NetboxIxpData, NetboxParticipant};

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
    let mut members: Vec<serde_json::Value> = Vec::new();
    for p in participants {
        let member_type = match p.participant_type.as_deref() {
            Some("Infrastructure") => "ixp",
            _ => "peering",
        };

        let connections = build_connection_list(p, &ixp_data.vlans);
        members.push(serde_json::json!({
            "asnum": p.asn,
            "member_type": member_type,
            "name": p.name,
            "connection_list": connections,
        }));
    }
    members.sort_by_key(|m| m["asnum"].as_u64().unwrap_or(0));

    let timestamp = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%z")
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

/// Build the connection_list for a participant in IX-F format.
fn build_connection_list(
    p: &NetboxParticipant,
    vlans: &[IxpVlan],
) -> Vec<serde_json::Value> {
    // Special cases from the Jinja2 template
    if p.asn == 12276 {
        return vec![serde_json::json!({
            "ixp_id": 155,
            "state": "active",
            "if_list": [{ "switch_id": 59, "if_speed": 1000 }],
            "vlan_list": [
                { "vlan_id": 1, "ipv4": { "address": "206.197.187.1" }, "ipv6": { "address": "2001:504:30::ba01:2276:1" } },
                { "vlan_id": 1, "ipv4": { "address": "206.197.187.2" }, "ipv6": { "address": "2001:504:30::ba01:2276:2" } },
            ]
        })];
    }
    if p.asn == 63055 {
        return vec![serde_json::json!({
            "ixp_id": 155,
            "state": "active",
            "if_list": [
                { "switch_id": 59, "if_speed": 1000 },
                { "switch_id": 63, "if_speed": 1000 },
            ],
            "vlan_list": [
                { "vlan_id": 1, "ipv4": { "address": "206.197.187.253" }, "ipv6": { "address": "2001:504:30::ba06:3055:1" } },
                { "vlan_id": 1, "ipv4": { "address": "206.197.187.254" }, "ipv6": { "address": "2001:504:30::ba06:3055:2" } },
            ]
        })];
    }

    // Normal participants: one connection per peering port
    let mut connections = Vec::new();
    for port in &p.enriched_ports {
        // Compute if_speed: rate_limit_bps/1e6 or speed (already Mbps)
        let if_speed = if let Some(rl) = port.rate_limit_bps {
            Some(rl / 1_000_000)
        } else {
            port.speed
        };

        let mut if_entry = serde_json::json!({ "switch_id": port.device_id });
        if let Some(speed) = if_speed {
            if_entry["if_speed"] = serde_json::json!(speed);
        }

        // Match IPs to this port via participant_lag_id
        let port_ips: Vec<&crate::netbox::ParticipantIp> = p
            .ip_addresses
            .iter()
            .filter(|ip| ip.participant_lag_id == Some(port.interface_id))
            .collect();

        // Build vlan_list: group IPs by VLAN
        let vlan_list: Vec<serde_json::Value> = if !port_ips.is_empty() {
            let vlan_id = vlans.first().map(|v| v.id).unwrap_or(1);
            let mut ipv4_entries: Vec<serde_json::Value> = Vec::new();
            let mut ipv6_entries: Vec<serde_json::Value> = Vec::new();

            for ip in &port_ips {
                let mut ip_obj = serde_json::json!({ "address": ip.address });
                if let Some(ref mac) = ip.mac_address {
                    ip_obj["mac_addresses"] = serde_json::json!([mac]);
                }
                match ip.family.as_str() {
                    "IPv4" => ipv4_entries.push(ip_obj),
                    "IPv6" => ipv6_entries.push(ip_obj),
                    _ => {}
                }
            }

            let mut vlan_entry = serde_json::json!({ "vlan_id": vlan_id });
            if let Some(v4) = ipv4_entries.first() {
                vlan_entry["ipv4"] = v4.clone();
            }
            if let Some(v6) = ipv6_entries.first() {
                vlan_entry["ipv6"] = v6.clone();
            }
            vec![vlan_entry]
        } else {
            Vec::new()
        };

        let mut conn = serde_json::json!({
            "ixp_id": 155,
            "state": "active",
            "if_list": [if_entry],
        });
        if !vlan_list.is_empty() {
            conn["vlan_list"] = serde_json::json!(vlan_list);
        }
        connections.push(conn);
    }

    connections
}
