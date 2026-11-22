//! Participants table: the public per-port participant list behind
//! sfmix.org/participants/ (`/api/v1/participants-table`).
//!
//! Replaces the Ansible-rendered `participants_table.json`; the shape is kept
//! identical so the website template didn't have to change.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use crate::netbox::{EnrichedPort, IxpMembership, NetboxIxpData, NetboxParticipant};

#[derive(Debug, Serialize)]
pub struct ParticipantsTable {
    pub participants: Vec<TableParticipant>,
}

#[derive(Debug, Serialize)]
pub struct TableParticipant {
    pub as_number: u32,
    /// NetBox `participant_type`: "Member", "Exempt", "Infrastructure".
    pub member_type: Option<String>,
    pub name: String,
    pub peering_ports: Vec<TablePort>,
}

#[derive(Debug, Serialize)]
pub struct TablePort {
    /// e.g. "10 Gbit/s"; null when NetBox has neither speed nor rate limit.
    pub speed: Option<String>,
    pub speed_bps: u64,
    /// Facility of the port's site, e.g. "Hurricane Electric FMT2".
    pub location: String,
    /// Address, or "Pending" when none is assigned yet.
    pub ipv4: String,
    /// Sort key: the IPv4 address as an integer (0 when pending).
    pub ipv4_integer: u32,
    pub ipv6: String,
    /// Sort key: the low 64 bits (host part within the /64) as an integer.
    pub ipv6_integer: u64,
}

const PENDING: &str = "Pending";

pub fn build_participants_table(
    ixp_data: &NetboxIxpData,
    participants: &[NetboxParticipant],
) -> ParticipantsTable {
    let mut members: Vec<&NetboxParticipant> =
        participants.iter().filter(|p| p.ixp_membership.is_some()).collect();
    // Participants first, then infrastructure; each by ASN.
    members.sort_by_key(|p| (p.ixp_membership, p.asn));

    let participants = members
        .into_iter()
        .map(|p| TableParticipant {
            as_number: p.asn,
            member_type: p.participant_type.clone(),
            name: p.name.clone(),
            peering_ports: member_ports(ixp_data, p)
                .into_iter()
                .map(|port| table_port(ixp_data, p, port))
                .collect(),
        })
        .collect();
    ParticipantsTable { participants }
}

fn table_port(ixp_data: &NetboxIxpData, p: &NetboxParticipant, port: &EnrichedPort) -> TablePort {
    let (speed, speed_bps) = if let Some(rl) = port.rate_limit_bps {
        (Some(format!("{} Gbit/s", rl / 1_000_000_000)), rl)
    } else if let Some(mbps) = port.speed {
        (Some(format!("{} Gbit/s", mbps / 1000)), mbps * 1_000_000)
    } else {
        (None, 0)
    };
    // Last address of each family linked to this port (participant_lag).
    let mut ipv4 = None;
    let mut ipv6 = None;
    for ip in p.ip_addresses.iter().filter(|ip| ip.participant_lag_id == Some(port.interface_id)) {
        match ip.family.as_str() {
            "IPv4" => ipv4 = Some(ip.address.as_str()),
            "IPv6" => ipv6 = Some(ip.address.as_str()),
            _ => {}
        }
    }
    let location = ixp_data.site(&port.site).map(|s| s.facility.clone()).unwrap_or_default();
    port_row(speed, speed_bps, location, ipv4, ipv6)
}

fn port_row(
    speed: Option<String>,
    speed_bps: u64,
    location: String,
    ipv4: Option<&str>,
    ipv6: Option<&str>,
) -> TablePort {
    let ipv4_integer = ipv4.and_then(|a| a.parse::<Ipv4Addr>().ok()).map(u32::from).unwrap_or(0);
    let ipv6_integer = ipv6
        .and_then(|a| a.parse::<Ipv6Addr>().ok())
        .map(|a| (u128::from(a) & u128::from(u64::MAX)) as u64)
        .unwrap_or(0);
    TablePort {
        speed,
        speed_bps,
        location,
        ipv4: ipv4.unwrap_or(PENDING).to_string(),
        ipv4_integer,
        ipv6: ipv6.unwrap_or(PENDING).to_string(),
        ipv6_integer,
    }
}

/// A member's own ports in NetBox order, then any other port its IPs are
/// linked to (shared hypervisor trunks). An owned port with none of the
/// member's IPs is shown as "Pending" for a joiner; an infrastructure trunk
/// without one (e.g. a spare hypervisor) is skipped.
fn member_ports<'a>(ixp_data: &'a NetboxIxpData, p: &'a NetboxParticipant) -> Vec<&'a EnrichedPort> {
    let ip_ports = p.ip_ports(ixp_data);
    let has_ip = |id: u64| ip_ports.iter().any(|q| q.interface_id == id);
    let infrastructure = p.ixp_membership == Some(IxpMembership::Infrastructure)
        || p.participant_type.as_deref() == Some("Infrastructure");
    let mut ports: Vec<&EnrichedPort> = p
        .enriched_ports
        .iter()
        .filter(|owned| !infrastructure || has_ip(owned.interface_id))
        .collect();
    for port in &ip_ports {
        if !p.enriched_ports.iter().any(|owned| owned.interface_id == port.interface_id) {
            ports.push(port);
        }
    }
    ports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netbox::{IxpMembership, IxpSite, ParticipantIp};

    fn site(code: &str, facility: &str) -> IxpSite {
        IxpSite {
            code: code.into(),
            site_id: 1,
            status: "active".into(),
            name: String::new(),
            facility: facility.into(),
            street: String::new(),
            city: String::new(),
            metro: None,
            facility_operator: None,
            mmr_portal_url: None,
            cross_connect_from: Vec::new(),
            peeringdb_facility: None,
            latitude: None,
            longitude: None,
        }
    }

    fn participant(asn: u32, membership: Option<IxpMembership>) -> NetboxParticipant {
        NetboxParticipant {
            asn,
            name: format!("Example {asn}"),
            participant_type: Some("Member".into()),
            ixp_membership: membership,
            ports: Vec::new(),
            enriched_ports: Vec::new(),
            ip_addresses: Vec::new(),
        }
    }

    #[test]
    fn rows_ordering_and_fields() {
        let ixp = NetboxIxpData { sites: vec![site("tst01", "Example Facility")], ..Default::default() };
        let mut a = participant(64512, Some(IxpMembership::Participant));
        a.enriched_ports.push(EnrichedPort {
            device: "switch01.tst01".into(),
            interface: "Ethernet1".into(),
            device_id: 1,
            site: "tst01".into(),
            interface_id: 10,
            speed: Some(10_000),
            rate_limit_bps: None,
            enabled: true,
            member_interfaces: Vec::new(),
        });
        a.ip_addresses = vec![
            ParticipantIp { address: "192.0.2.10".into(), family: "IPv4".into(), mac_address: None, status: "active".into(), participant_lag_id: Some(10) },
            ParticipantIp { address: "2001:db8::6:4512:1".into(), family: "IPv6".into(), mac_address: None, status: "active".into(), participant_lag_id: Some(10) },
        ];
        let infra = participant(64500, Some(IxpMembership::Infrastructure));
        let transit_only = participant(64501, None);
        let b = participant(64496, Some(IxpMembership::Participant));

        let t = build_participants_table(&ixp, &[infra, a, transit_only, b]);
        let asns: Vec<u32> = t.participants.iter().map(|p| p.as_number).collect();
        assert_eq!(asns, vec![64496, 64512, 64500]);

        let port = &t.participants[1].peering_ports[0];
        assert_eq!(port.speed.as_deref(), Some("10 Gbit/s"));
        assert_eq!(port.speed_bps, 10_000_000_000);
        assert_eq!(port.location, "Example Facility");
        assert_eq!(port.ipv4_integer, u32::from("192.0.2.10".parse::<Ipv4Addr>().unwrap()));
        assert_eq!(port.ipv6_integer, 0x0006_4512_0001);
        assert!(t.participants[0].peering_ports.is_empty());
    }

    #[test]
    fn rate_limit_wins_and_missing_ips_are_pending() {
        let ixp = NetboxIxpData::default();
        let mut p = participant(64512, Some(IxpMembership::Participant));
        p.enriched_ports.push(EnrichedPort {
            device: "switch01.tst01".into(),
            interface: "Ethernet2".into(),
            device_id: 1,
            site: "nowhere".into(),
            interface_id: 11,
            speed: Some(100_000),
            rate_limit_bps: Some(20_000_000_000),
            enabled: true,
            member_interfaces: Vec::new(),
        });
        let t = build_participants_table(&ixp, &[p]);
        let port = &t.participants[0].peering_ports[0];
        assert_eq!(port.speed.as_deref(), Some("20 Gbit/s"));
        assert_eq!(port.speed_bps, 20_000_000_000);
        assert_eq!((port.ipv4.as_str(), port.ipv4_integer), (PENDING, 0));
        assert_eq!((port.ipv6.as_str(), port.ipv6_integer), (PENDING, 0));
        assert_eq!(port.location, "");
    }
}
