use serde::Serialize;

/// Platform-independent structured response types.
///
/// These types represent the canonical data model for all looking glass
/// queries. Drivers parse platform-specific output (EOS JSON, SR-OS JSON)
/// into these types. Frontends render them for display (text tables for
/// telnet/SSH, JSON for MCP).

// ── Interface Status ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub member_interfaces: Vec<String>,
    /// Parent Port-Channel name (for member interfaces of a LAG)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_channel: Option<String>,
}

// ── Interface Detail ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct BgpSummary {
    pub router_id: String,
    pub local_as: u32,
    pub peers: Vec<BgpPeerSummary>,
}

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
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

// ── MAC Address Table ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct MacEntry {
    pub vlan: String,
    pub mac_address: String,
    pub entry_type: String,
    pub interface: String,
}

// ── ARP Table ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ArpEntry {
    pub ip_address: String,
    pub mac_address: String,
    pub interface: String,
    pub age: String,
}

// ── IPv6 Neighbor (ND) Table ────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct NdEntry {
    pub ip_address: String,
    pub mac_address: String,
    pub interface: String,
    pub state: String,
}

// ── LLDP Neighbors ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct LldpNeighbor {
    pub local_interface: String,
    pub neighbor_device: String,
    pub neighbor_port: String,
    pub ttl: String,
}

// ── Optics (Transceiver DOM) ────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct OpticalLane {
    pub lane: u8,
    pub tx_power_dbm: Option<f64>,
    pub rx_power_dbm: Option<f64>,
    pub tx_bias_ma: Option<f64>,
}

// ── VXLAN VTEP ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct VxlanVtep {
    pub vtep_address: String,
    pub learned_from: String,
}

// ── CommandOutput enum ──────────────────────────────────────────────

/// The unified output type for all looking glass commands.
///
/// Each variant carries structured, platform-independent data.
/// `Stream` is used for long-running commands (ping, traceroute) that
/// produce output incrementally.
#[derive(Debug)]
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
    Stream(tokio::sync::mpsc::Receiver<String>),
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
            _ => false,
        }
    }
}

impl Serialize for CommandOutput {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            CommandOutput::InterfacesStatus(v) => v.serialize(serializer),
            CommandOutput::InterfaceDetail(v) => v.serialize(serializer),
            CommandOutput::BgpSummary(v) => v.serialize(serializer),
            CommandOutput::BgpNeighborDetail(v) => v.serialize(serializer),
            CommandOutput::MacAddressTable(v) => v.serialize(serializer),
            CommandOutput::ArpTable(v) => v.serialize(serializer),
            CommandOutput::NdTable(v) => v.serialize(serializer),
            CommandOutput::LldpNeighbors(v) => v.serialize(serializer),
            CommandOutput::Optics(v) => v.serialize(serializer),
            CommandOutput::OpticsDetail(v) => v.serialize(serializer),
            CommandOutput::VxlanVtep(v) => v.serialize(serializer),
            CommandOutput::Stream(_) => serializer.serialize_str("<streaming>"),
        }
    }
}
