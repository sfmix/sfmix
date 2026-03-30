use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// A participant's port on a specific device.
#[derive(Debug, Clone, Deserialize)]
pub struct ParticipantPort {
    pub device: String,
    pub interface: String,
}

/// A participant's BGP session.
#[derive(Debug, Clone, Deserialize)]
pub struct ParticipantSession {
    pub device: String,
    #[serde(default)]
    pub neighbor: Option<String>,
    #[serde(default)]
    pub neighbor_v6: Option<String>,
}

/// A single participant entry.
#[derive(Debug, Clone, Deserialize)]
pub struct Participant {
    pub asn: u32,
    pub name: String,
    #[serde(default)]
    pub ports: Vec<ParticipantPort>,
    #[serde(default)]
    pub sessions: Vec<ParticipantSession>,
}

#[derive(Debug, Deserialize)]
struct ParticipantsFile {
    participants: Vec<Participant>,
}

/// Maps ASNs to their ports and sessions, used by the policy engine
/// to determine which resources an authenticated user may query.
#[derive(Debug)]
pub struct ParticipantMap {
    by_asn: HashMap<u32, Participant>,
}

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

    pub fn empty() -> Self {
        Self {
            by_asn: HashMap::new(),
        }
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

    /// Check if an interface name belongs to the given ASN on any device.
    pub fn port_belongs_to_any_device(&self, interface: &str, asn: u32) -> bool {
        self.by_asn
            .get(&asn)
            .map(|p| p.ports.iter().any(|port| port.interface == interface))
            .unwrap_or(false)
    }

    /// Check if an interface name is a participant port (on any device, any ASN).
    pub fn interface_is_participant_port(&self, interface: &str) -> bool {
        self.by_asn
            .values()
            .any(|p| p.ports.iter().any(|port| port.interface == interface))
    }

    /// List all participants.
    pub fn all(&self) -> impl Iterator<Item = &Participant> {
        self.by_asn.values()
    }
}
