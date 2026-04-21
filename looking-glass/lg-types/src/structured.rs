use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

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

// ── BGP Summary ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpSummary {
    pub router_id: String,
    pub local_as: u32,
    pub peers: Vec<BgpPeerSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpPeerSummary {
    pub neighbor: String,
    pub remote_as: u32,
    pub description: String,
    pub state: String,
    pub uptime: String,
    pub prefixes_received: u32,
    pub msg_received: u64,
    pub msg_sent: u64,
}

// ── BGP Neighbor Detail ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpNeighborDetail {
    pub neighbor: String,
    pub remote_as: u32,
    pub local_as: u32,
    pub description: String,
    pub state: String,
    pub uptime: String,
    pub router_id: String,
    pub hold_time: u32,
    pub keepalive_interval: u32,
    pub prefixes_received: u32,
    pub prefixes_sent: u32,
    pub messages_received: u64,
    pub messages_sent: u64,
}

// ── BGP Route (from BGP sources) ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpRoute {
    pub prefix: String,
    pub next_hop: String,
    pub as_path: Vec<u32>,
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub med: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub local_pref: Option<u32>,
    pub communities: Vec<String>,
    pub large_communities: Vec<String>,
    pub age: String,
    pub source_name: String,
    pub primary: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ovs: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpRouteList {
    pub source_name: String,
    pub neighbor: String,
    pub routes: Vec<BgpRoute>,
    pub filtered_count: u32,
    pub accepted_count: u32,
    pub noexport_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpSourceNeighbor {
    pub address: String,
    pub remote_as: u32,
    pub description: String,
    pub state: String,
    pub uptime: String,
    pub prefixes_received: u32,
    pub prefixes_sent: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpSourceStatus {
    pub name: String,
    pub display_name: String,
    pub source_type: String,
    pub router_id: String,
    pub version: String,
    pub neighbor_count: u32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_refresh: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
}

// ── MAC Address Table ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacEntry {
    pub vlan: String,
    pub mac_address: String,
    pub entry_type: String,
    pub interface: String,
}

// ── ARP Table ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip_address: String,
    pub mac_address: String,
    pub interface: String,
    pub age: String,
}

// ── IPv6 Neighbor (ND) Table ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NdEntry {
    pub ip_address: String,
    pub mac_address: String,
    pub interface: String,
    pub state: String,
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

// ── VXLAN VTEP ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VxlanVtep {
    pub vtep_address: String,
    pub learned_from: String,
}

// ── CommandOutput enum ──────────────────────────────────────────────

/// The unified output type for all looking glass commands.
///
/// Each variant carries structured, platform-independent data.
/// `StreamLines` is used for completed streaming commands (ping, traceroute)
/// whose output has been collected. Live streaming is handled via SSE events.
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum CommandOutput {
    InterfacesStatus(Vec<InterfaceStatus>),
    InterfaceDetail(InterfaceDetail),
    BgpSummary(BgpSummary),
    BgpNeighborDetail(BgpNeighborDetail),
    MacAddressTable(Vec<MacEntry>),
    ArpTable(Vec<ArpEntry>),
    NdTable(Vec<NdEntry>),
    LldpNeighbors(Vec<LldpNeighbor>),
    Optics(Vec<InterfaceOptics>),
    OpticsDetail(Vec<InterfaceOptics>),
    VxlanVtep(Vec<VxlanVtep>),
    /// Collected streaming output (ping/traceroute lines).
    StreamLines(Vec<String>),
    /// Pre-rendered participant list (local resource, no device dispatch).
    Participants(String),
    /// NetBox cache status (local resource, no device dispatch).
    NetboxStatus(String),
    /// BGP source status list (local resource, no device dispatch).
    BgpSources(Vec<BgpSourceStatus>),
    /// BGP route list from a BGP source (local resource, no device dispatch).
    BgpRoutes(BgpRouteList),
    /// BGP route lookup results across all sources.
    BgpRouteLookup(Vec<BgpRoute>),
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
            CommandOutput::ArpTable(v) => v.is_empty(),
            CommandOutput::NdTable(v) => v.is_empty(),
            CommandOutput::LldpNeighbors(v) => v.is_empty(),
            CommandOutput::Optics(v) => v.is_empty(),
            CommandOutput::OpticsDetail(v) => v.is_empty(),
            CommandOutput::VxlanVtep(v) => v.is_empty(),
            CommandOutput::BgpSources(v) => v.is_empty(),
            CommandOutput::BgpRouteLookup(v) => v.is_empty(),
            CommandOutput::Error(_) => true,
            _ => false,
        }
    }
}
