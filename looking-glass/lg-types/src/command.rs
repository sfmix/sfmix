use std::fmt;
use serde::{Deserialize, Serialize};

/// Structured command representation.
///
/// Commands are parsed from user input into this structured form before
/// policy evaluation and device dispatch. This prevents injection and
/// enables platform-independent policy checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub verb: Verb,
    pub resource: Resource,
    pub target: Option<String>,
    pub device: Option<String>,
    pub address_family: AddressFamily,
    /// Filter output to ports belonging to this ASN (show interfaces/optics).
    pub filter_asn: Option<u32>,
    /// Filter output to this VLAN ID (show mac address-table).
    pub filter_vlan: Option<String>,
    /// Filter to a specific BGP source name (show bgp routes).
    pub filter_source: Option<String>,
}

/// Parse an Autonomous System Number from user input.
///
/// Accepts a bare integer (`13335`) as well as the `AS<number>` and
/// `ASN<number>` forms (case-insensitive, e.g. `AS13335`, `asn13335`) so
/// values can be copy-pasted directly from peering portals and BGP output.
/// Returns `None` if the remaining text is not a valid `u32`.
pub fn parse_asn(input: &str) -> Option<u32> {
    let s = input.trim();
    let digits = match s.get(..3) {
        Some(p) if p.eq_ignore_ascii_case("asn") => &s[3..],
        _ => match s.get(..2) {
            Some(p) if p.eq_ignore_ascii_case("as") => &s[2..],
            _ => s,
        },
    };
    digits.parse::<u32>().ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    Show,
    Ping,
    Traceroute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    InterfacesStatus,
    InterfaceDetail,
    MacAddressTable,
    LldpNeighbors,
    Optics,
    OpticsDetail,
    /// Transceiver hardware inventory (vendor/model/serial) — admin only
    OpticsInventory,
    Participants,
    /// Flat list of assigned IX IPs with their tenant/ASN
    IxIpAssignments,
    /// Discovered ARP/NDP neighbors heard on the IX fabric
    DiscoveredNeighbors,
    /// Ping/traceroute destination (resource is the destination address)
    NetworkReachability,
    Help,
    /// Authenticate via OIDC device flow
    Login,
    /// Show current identity
    Whoami,
    /// Drop authentication (return to anonymous)
    Logout,
    /// Show NetBox cache status
    NetboxCache,
    /// Show device state cache status
    DeviceCache,
    /// Detail view for a single participant by ASN
    ParticipantDetail,
    /// ARP table (IPv4 neighbor-to-MAC mapping)
    Arp,
    /// IPv6 neighbor table (NDP)
    #[serde(rename = "ipv6_neighbors")]
    IPv6Neighbors,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AddressFamily {
    #[default]
    #[serde(rename = "ipv4")]
    IPv4,
    #[serde(rename = "ipv6")]
    IPv6,
}

/// Result of executing a command against a device.
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandResult {
    /// The device that was queried
    pub device: String,
    /// Structured output from the device
    pub output: crate::structured::CommandOutput,
    /// Whether the command executed successfully
    pub success: bool,
}

/// Whether a resource targets a specific participant port (and thus
/// requires ownership checks for non-admin authenticated users).
impl Resource {
    pub fn is_port_scoped(&self) -> bool {
        matches!(
            self,
            Resource::InterfaceDetail
                | Resource::OpticsDetail
                | Resource::MacAddressTable
        )
    }
}

#[allow(dead_code)]
impl Command {
    /// Whether this command requires authentication to access participant ports.
    /// Core/infrastructure ports are always accessible; participant ports need auth.
    pub fn requires_auth_for_participant_port(&self) -> bool {
        self.resource.is_port_scoped() && self.target.is_some()
    }
}

#[derive(Debug)]
pub enum ParseError {
    Empty,
    UnknownCommand(String),
    AmbiguousCommand(String, Vec<String>),
    MissingArgument(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, ""),
            ParseError::UnknownCommand(cmd) => write!(f, "Unknown command: {cmd}"),
            ParseError::AmbiguousCommand(input, candidates) => {
                write!(f, "Ambiguous command '{}': could be {}", input, candidates.join(", "))
            }
            ParseError::MissingArgument(what) => write!(f, "Missing argument: {what}"),
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::parse_asn;

    #[test]
    fn parses_bare_integer() {
        assert_eq!(parse_asn("13335"), Some(13335));
    }

    #[test]
    fn parses_as_prefix() {
        assert_eq!(parse_asn("AS13335"), Some(13335));
        assert_eq!(parse_asn("as13335"), Some(13335));
        assert_eq!(parse_asn("As13335"), Some(13335));
    }

    #[test]
    fn parses_asn_prefix() {
        assert_eq!(parse_asn("ASN13335"), Some(13335));
        assert_eq!(parse_asn("asn13335"), Some(13335));
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(parse_asn("  AS13335 "), Some(13335));
    }

    #[test]
    fn rejects_non_numeric() {
        assert_eq!(parse_asn(""), None);
        assert_eq!(parse_asn("as"), None);
        assert_eq!(parse_asn("asn"), None);
        assert_eq!(parse_asn("AS"), None);
        assert_eq!(parse_asn("Ethernet1"), None);
        assert_eq!(parse_asn("13335x"), None);
        assert_eq!(parse_asn("AS13335x"), None);
        // No separator/space variants — only the bare prefix is stripped.
        assert_eq!(parse_asn("AS 13335"), None);
    }
}
