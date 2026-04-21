use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use crate::netbox::NetboxParticipant;

/// A participant's port on a specific device.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ParticipantPort {
    pub device: String,
    pub interface: String,
}

/// A participant's BGP session.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ParticipantSession {
    pub device: String,
    #[serde(default)]
    pub neighbor: Option<String>,
    #[serde(default)]
    pub neighbor_v6: Option<String>,
}

/// A single participant entry.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Participant {
    pub asn: u32,
    pub name: String,
    /// NetBox participant_type: "Member", "Exempt", or "Infrastructure".
    #[serde(default)]
    pub participant_type: Option<String>,
    #[serde(default)]
    pub ports: Vec<ParticipantPort>,
    #[serde(default)]
    pub sessions: Vec<ParticipantSession>,
}

#[derive(Debug, Deserialize)]
struct ParticipantsFile {
    participants: Vec<Participant>,
    #[serde(default)]
    core_ports: Vec<ParticipantPort>,
    #[serde(default)]
    admin_ports: Vec<ParticipantPort>,
}

/// Maps ASNs to their ports and sessions, used by the policy engine
/// to determine which resources an authenticated user may query.
#[derive(Debug)]
pub struct ParticipantMap {
    by_asn: HashMap<u32, Participant>,
}

#[allow(dead_code)]
impl ParticipantMap {
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let file: ParticipantsFile = serde_yaml::from_str(&contents)?;
        let by_asn = file
            .participants
            .into_iter()
            .map(|p| (p.asn, p))
            .collect();
        Ok(Self { by_asn })
    }

    /// Load participants from a YAML file and build both a ParticipantMap
    /// and a PortMap (with core_ports and admin_ports from the file).
    pub fn load_with_port_map(path: &Path) -> Result<(Self, PortMap)> {
        let contents = std::fs::read_to_string(path)?;
        let file: ParticipantsFile = serde_yaml::from_str(&contents)?;

        let core_ports: Vec<(String, String)> = file.core_ports.iter()
            .map(|p| (p.device.clone(), p.interface.clone()))
            .collect();
        let admin_ports: Vec<(String, String)> = file.admin_ports.iter()
            .map(|p| (p.device.clone(), p.interface.clone()))
            .collect();

        // Build NetboxParticipant-compatible entries for PortMap::build
        let nb_participants: Vec<NetboxParticipant> = file.participants.iter().map(|p| {
            NetboxParticipant {
                asn: p.asn,
                name: p.name.clone(),
                participant_type: p.participant_type.clone(),
                ports: p.ports.iter().map(|pp| (pp.device.clone(), pp.interface.clone())).collect(),
                enriched_ports: Vec::new(),
                ip_addresses: Vec::new(),
            }
        }).collect();

        let port_map = PortMap::build(&nb_participants, &core_ports, &admin_ports);

        let by_asn = file.participants.into_iter().map(|p| (p.asn, p)).collect();
        Ok((Self { by_asn }, port_map))
    }

    pub fn empty() -> Self {
        Self {
            by_asn: HashMap::new(),
        }
    }

    /// Build a ParticipantMap from NetBox-fetched participant data.
    pub fn build_from_netbox(entries: &[NetboxParticipant]) -> Self {
        let mut by_asn = HashMap::new();
        for entry in entries {
            by_asn.insert(entry.asn, Participant {
                asn: entry.asn,
                name: entry.name.clone(),
                participant_type: entry.participant_type.clone(),
                ports: entry.ports.iter().map(|(d, i)| ParticipantPort {
                    device: d.clone(),
                    interface: i.clone(),
                }).collect(),
                sessions: Vec::new(),
            });
        }
        Self { by_asn }
    }

    /// Insert a participant into the map.
    pub fn insert(&mut self, participant: Participant) {
        self.by_asn.insert(participant.asn, participant);
    }

    /// Get participant info by ASN.
    pub fn get(&self, asn: u32) -> Option<&Participant> {
        self.by_asn.get(&asn)
    }

    /// Check if a given (device, interface) pair belongs to the specified ASN.
    pub fn port_belongs_to_asn(&self, device: &str, interface: &str, asn: u32) -> bool {
        self.by_asn
            .get(&asn)
            .map(|p| {
                p.ports
                    .iter()
                    .any(|port| port.device == device && port.interface == interface)
            })
            .unwrap_or(false)
    }

    /// Check if a given BGP neighbor address belongs to the specified ASN.
    pub fn session_belongs_to_asn(&self, neighbor_addr: &str, asn: u32) -> bool {
        self.by_asn
            .get(&asn)
            .map(|p| {
                p.sessions.iter().any(|s| {
                    s.neighbor.as_deref() == Some(neighbor_addr)
                        || s.neighbor_v6.as_deref() == Some(neighbor_addr)
                })
            })
            .unwrap_or(false)
    }

    /// Check if a given BGP neighbor address belongs to any participant.
    /// Returns the owning ASN if found.
    pub fn session_owner(&self, neighbor_addr: &str) -> Option<u32> {
        for p in self.by_asn.values() {
            if p.sessions.iter().any(|s| {
                s.neighbor.as_deref() == Some(neighbor_addr)
                    || s.neighbor_v6.as_deref() == Some(neighbor_addr)
            }) {
                return Some(p.asn);
            }
        }
        None
    }

    /// Check if a (device, interface) pair is a participant port (any ASN).
    pub fn is_participant_port(&self, device: &str, interface: &str) -> bool {
        self.by_asn
            .values()
            .any(|p| p.ports.iter().any(|port| port.device == device && port.interface == interface))
    }

    /// List all participants.
    pub fn all(&self) -> impl Iterator<Item = &Participant> {
        self.by_asn.values()
    }
}

// ── Port classification map ────────────────────────────────────────

/// Classification of a port for visibility filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortClass {
    /// Core/infrastructure port — visible to everyone.
    Core,
    /// Participant peering port — visible only to the owning ASN or admins.
    Participant { asn: u32 },
    /// Admin-only port — visible only to IX Administrators.
    AdminOnly,
}

/// Extract the parent connector name from a Nokia breakout port name.
///
/// Nokia breakout ports are named like `1/1/c1/1` where `1/1/c1` is the
/// connector and `/1` is the breakout lane. Returns `Some("1/1/c1")` for
/// `1/1/c1/1`, or `None` if the name doesn't match the breakout pattern.
fn nokia_parent_connector(interface: &str) -> Option<String> {
    // Pattern: digit/digit/cN/digit (e.g., 1/1/c1/1, 1/1/c12/1)
    let parts: Vec<&str> = interface.split('/').collect();
    if parts.len() == 4 && parts[2].starts_with('c') {
        // It's a breakout port — return the connector (first 3 parts)
        Some(format!("{}/{}/{}", parts[0], parts[1], parts[2]))
    } else {
        None
    }
}

/// Allowlist-based port visibility map.
///
/// Built from NetBox data (peering_port, core_port, transit_peer, admin_port
/// tags). Only ports present in this map are shown; everything else is hidden.
/// This eliminates disabled, unconfigured, and untagged interfaces from output.
#[derive(Debug, Clone)]
pub struct PortMap {
    ports: HashMap<(String, String), PortClass>,
}

impl PortMap {
    /// Build a PortMap from NetBox participant data, core port list, and admin port list.
    ///
    /// Priority (highest wins): Core > Participant > AdminOnly.
    pub fn build(
        participants: &[NetboxParticipant],
        core_ports: &[(String, String)],
        admin_ports: &[(String, String)],
    ) -> Self {
        let mut ports = HashMap::new();

        // Insert admin-only ports (lowest priority)
        for (device, iface) in admin_ports {
            ports.insert(
                (device.clone(), iface.clone()),
                PortClass::AdminOnly,
            );
        }

        // Insert participant (peering + transit) ports
        for p in participants {
            for (device, iface) in &p.ports {
                ports.insert(
                    (device.clone(), iface.clone()),
                    PortClass::Participant { asn: p.asn },
                );
            }
        }

        // Insert core ports (highest priority — overwrites everything)
        for (device, iface) in core_ports {
            ports.insert(
                (device.clone(), iface.clone()),
                PortClass::Core,
            );
        }

        PortMap { ports }
    }

    pub fn empty() -> Self {
        PortMap { ports: HashMap::new() }
    }

    /// Classify a (device, interface) pair. Returns `None` if not in the map.
    ///
    /// For Nokia breakout ports (e.g., `1/1/c1/1`), also tries the parent connector
    /// name (`1/1/c1`) if the exact name isn't found.
    pub fn classify(&self, device: &str, interface: &str) -> Option<&PortClass> {
        // Try exact match first
        if let Some(class) = self.ports.get(&(device.to_string(), interface.to_string())) {
            return Some(class);
        }
        // For Nokia breakout ports like "1/1/c1/1", try parent connector "1/1/c1"
        if let Some(parent) = nokia_parent_connector(interface) {
            return self.ports.get(&(device.to_string(), parent));
        }
        None
    }

    /// Total number of classified ports.
    pub fn len(&self) -> usize {
        self.ports.len()
    }

    /// Iterate over all (device, interface) → PortClass entries.
    pub fn iter(&self) -> impl Iterator<Item = (&(String, String), &PortClass)> {
        self.ports.iter()
    }

    /// Check if an interface name exists on any device in the port map.
    pub fn known_interface(&self, interface: &str) -> bool {
        self.ports.keys().any(|(_, iface)| iface == interface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_participants() -> ParticipantMap {
        let entries = vec![
            NetboxParticipant {
                asn: 13335,
                name: "Cloudflare".to_string(),
                participant_type: Some("Member".to_string()),
                ports: vec![
                    ("switch01.sfo02".to_string(), "Ethernet3/1".to_string()),
                    ("switch02.sfo02".to_string(), "Ethernet3/1".to_string()),
                ],
                enriched_ports: Vec::new(),
                ip_addresses: Vec::new(),
            },
            NetboxParticipant {
                asn: 15169,
                name: "Google".to_string(),
                participant_type: Some("Member".to_string()),
                ports: vec![
                    ("switch01.sfo02".to_string(), "Ethernet3/2".to_string()),
                ],
                enriched_ports: Vec::new(),
                ip_addresses: Vec::new(),
            },
        ];
        ParticipantMap::build_from_netbox(&entries)
    }

    #[test]
    fn build_from_netbox_basic() {
        let map = test_participants();
        assert!(map.get(13335).is_some());
        assert!(map.get(15169).is_some());
        assert_eq!(map.get(13335).unwrap().name, "Cloudflare");
        assert_eq!(map.get(13335).unwrap().ports.len(), 2);
        assert_eq!(map.get(15169).unwrap().ports.len(), 1);
    }

    #[test]
    fn port_belongs_to_asn_device_aware() {
        let map = test_participants();
        assert!(map.port_belongs_to_asn("switch01.sfo02", "Ethernet3/1", 13335));
        assert!(!map.port_belongs_to_asn("switch01.sfo02", "Ethernet3/1", 15169));
        assert!(!map.port_belongs_to_asn("switch99", "Ethernet3/1", 13335));
    }

    #[test]
    fn is_participant_port_checks_device() {
        let map = test_participants();
        assert!(map.is_participant_port("switch01.sfo02", "Ethernet3/1"));
        assert!(map.is_participant_port("switch01.sfo02", "Ethernet3/2"));
        assert!(!map.is_participant_port("switch01.sfo02", "Ethernet49/1"));
    }

    #[test]
    fn empty_map() {
        let map = ParticipantMap::empty();
        assert!(map.get(13335).is_none());
        assert!(!map.is_participant_port("switch01", "Ethernet1"));
    }
}
