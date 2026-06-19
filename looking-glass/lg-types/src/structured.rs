use serde::{Deserialize, Serialize};

/// Platform-independent structured response types.
///
/// These types represent the canonical data model for all looking glass
/// queries. Drivers parse platform-specific output (EOS JSON, SR-OS JSON)
/// into these types. Frontends render them for display (text tables for
/// telnet/SSH, JSON for MCP).

// ── Interface Status ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStatus {
    pub name: String,
    pub description: String,
    pub link_status: String,
    pub protocol_status: String,
    pub speed: String,
    pub interface_type: String,
    pub vlan: String,
    pub auto_negotiate: bool,
    /// Member interfaces (for LAG/Port-Channel bundles)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub member_interfaces: Vec<String>,
    /// Parent Port-Channel name (for member interfaces of a LAG)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub port_channel: Option<String>,
}

// ── Interface Detail ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceDetail {
    pub name: String,
    pub description: String,
    pub link_status: String,
    pub protocol_status: String,
    pub hardware_type: String,
    pub mac_address: String,
    pub mtu: u32,
    pub speed: String,
    pub bandwidth: String,
    pub counters: InterfaceCounters,
    /// Member interfaces (for LAG/Port-Channel bundles)
    pub member_interfaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceCounters {
    pub in_octets: u64,
    pub in_unicast_packets: u64,
    pub in_multicast_packets: u64,
    pub in_broadcast_packets: u64,
    pub in_discards: u64,
    pub in_errors: u64,
    pub out_octets: u64,
    pub out_unicast_packets: u64,
    pub out_multicast_packets: u64,
    pub out_broadcast_packets: u64,
    pub out_discards: u64,
    pub out_errors: u64,
}

// ── MAC Address Table ───────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MacEntry {
    pub vlan: String,
    pub mac_address: String,
    pub entry_type: String,
    pub interface: String,
    /// RFC3339 timestamp this (vlan, mac, interface) was first observed.
    /// Filled by the MAC-table store; left empty by device drivers.
    pub first_seen: String,
    /// RFC3339 timestamp this entry was most recently observed.
    pub last_seen: String,
}

// ── LLDP Neighbors ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldpNeighbor {
    pub local_interface: String,
    pub neighbor_device: String,
    pub neighbor_port: String,
    pub ttl: String,
}

// ── Optics (Transceiver DOM) ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceOptics {
    pub name: String,
    pub description: String,
    pub link_status: String,
    pub media_type: String,
    pub temperature_c: Option<f64>,
    pub voltage_v: Option<f64>,
    pub lanes: Vec<OpticalLane>,
    /// Whether DOM monitoring is supported by this transceiver
    pub dom_supported: bool,
    /// Parent Port-Channel if this interface is a LAG member
    pub port_channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpticalLane {
    pub lane: u8,
    pub tx_power_dbm: Option<f64>,
    pub rx_power_dbm: Option<f64>,
    pub tx_bias_ma: Option<f64>,
}

// ── Optics Inventory (Transceiver Hardware) ────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpticsInventoryEntry {
    pub name: String,
    pub media_type: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
}

// ── ARP / IPv6 Neighbor Entry ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip_address: String,
    pub mac_address: String,
    pub interface: String,
    /// VPRN name (Nokia) or VRF (Arista)
    pub vrf: Option<String>,
    /// "dynamic", "static", "other"
    pub entry_type: String,
    /// Nokia: timer (remaining TTL); Arista: age in seconds (-1 = permanent → None)
    pub age_secs: Option<u64>,
}

// ── Discovered ARP/NDP Neighbors ────────────────────────────────────
//
// Passively heard on the IX fabric by lg-neighborhood-watch and accumulated
// durably in lg-server. Distinct from `ArpEntry` (the switch ARP/NDP table):
// this tracks *every* MAC heard claiming an IP, so multiple claimants surface
// as a conflict rather than being collapsed to the kernel's single choice.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredMac {
    pub mac: String,
    /// RFC3339, earliest time this (ip, mac) was heard.
    pub first_seen: String,
    /// RFC3339, most recent time this (ip, mac) was heard.
    pub last_seen: String,
}

fn default_assigned() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredNeighbor {
    pub ip: String,
    pub family: String,
    pub asn: Option<u32>,
    pub tenant: Option<String>,
    /// All distinct MACs heard claiming this IP.
    pub macs: Vec<DiscoveredMac>,
    /// True when more than one MAC has been heard for this IP.
    pub conflict: bool,
    /// False when this IP is not an active NetBox assignment: the claimant is
    /// mis-bound to an invalid/disallowed address on the IX. Defaults to true so
    /// pre-existing on-disk store files (all assigned) still deserialize.
    #[serde(default = "default_assigned")]
    pub assigned: bool,
}

// ── CommandOutput enum ──────────────────────────────────────────────

/// The unified output type for all looking glass commands.
///
/// Each variant carries structured, platform-independent data.
/// `StreamLines` is used for completed streaming commands (ping, traceroute)
/// whose output has been collected. Live streaming is handled via SSE events.
#[derive(Debug, Serialize, Deserialize)]
// Central output type matched/constructed across the workspace; boxing the
// large variant to even out sizes isn't worth the churn for a transient value.
#[allow(dead_code, clippy::large_enum_variant)]
pub enum CommandOutput {
    InterfacesStatus(Vec<InterfaceStatus>),
    InterfaceDetail(InterfaceDetail),
    MacAddressTable(Vec<MacEntry>),
    LldpNeighbors(Vec<LldpNeighbor>),
    Optics(Vec<InterfaceOptics>),
    OpticsDetail(Vec<InterfaceOptics>),
    OpticsInventory(Vec<OpticsInventoryEntry>),
    Arp(Vec<ArpEntry>),
    IPv6Neighbors(Vec<ArpEntry>),
    /// Collected streaming output (ping/traceroute lines).
    StreamLines(Vec<String>),
    /// Pre-rendered participant list (local resource, no device dispatch).
    Participants(String),
    /// NetBox cache status (local resource, no device dispatch).
    NetboxStatus(String),
    /// Device state cache status (local resource, no device dispatch).
    DeviceCacheStatus(String),
    /// Device-level error (e.g. SSH failure, timeout).
    Error(String),
}

impl CommandOutput {
    /// Returns true if the output contains no data entries.
    /// Scalar variants (detail, summary, stream) are never considered empty.
    pub fn is_empty(&self) -> bool {
        match self {
            CommandOutput::InterfacesStatus(v) => v.is_empty(),
            CommandOutput::MacAddressTable(v) => v.is_empty(),
            CommandOutput::LldpNeighbors(v) => v.is_empty(),
            CommandOutput::Optics(v) => v.is_empty(),
            CommandOutput::OpticsDetail(v) => v.is_empty(),
            CommandOutput::OpticsInventory(v) => v.is_empty(),
            CommandOutput::Arp(v) => v.is_empty(),
            CommandOutput::IPv6Neighbors(v) => v.is_empty(),
            CommandOutput::Error(_) => true,
            _ => false,
        }
    }
}
