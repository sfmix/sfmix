use std::fmt;
use serde::Deserialize;

/// Structured command representation.
///
/// Commands are parsed from user input into this structured form before
/// policy evaluation and device dispatch. This prevents injection and
/// enables platform-independent policy checks.
#[derive(Debug, Clone)]
pub struct Command {
    pub verb: Verb,
    pub resource: Resource,
    pub target: Option<String>,
    pub device: Option<String>,
    pub address_family: AddressFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    Show,
    Ping,
    Traceroute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    InterfacesStatus,
    InterfaceDetail,
    BgpSummary,
    BgpNeighbor,
    MacAddressTable,
    ArpTable,
    NdTable,
    LldpNeighbors,
    Optics,
    OpticsDetail,
    Participants,
    VxlanVtep,
    /// Ping/traceroute destination (resource is the destination address)
    NetworkReachability,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum AddressFamily {
    #[default]
    #[serde(rename = "ipv4")]
    IPv4,
    #[serde(rename = "ipv6")]
    IPv6,
}

/// Result of executing a command against a device.
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// The device that was queried
    pub device: String,
    /// Raw text output from the device
    pub output: String,
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
                | Resource::ArpTable
                | Resource::NdTable
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
