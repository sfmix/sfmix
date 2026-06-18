// Re-export all data structs from lg-types::structured.
pub use lg_types::structured::{
    ArpEntry, DiscoveredMac, DiscoveredNeighbor, InterfaceCounters, InterfaceDetail,
    InterfaceOptics, InterfaceStatus, LldpNeighbor, MacEntry, OpticalLane, OpticsInventoryEntry,
};

/// Per-device snapshot of all cacheable state, populated by the background poller.
///
/// Each resource tracks its own update timestamp independently so partial poll
/// failures (one command times out) are reflected accurately in the status output.
#[derive(Clone, Default)]
pub struct DeviceStateCache {
    pub interfaces:          Vec<InterfaceStatus>,
    pub interfaces_at:       Option<std::time::Instant>,
    pub lldp_neighbors:      Vec<LldpNeighbor>,
    pub lldp_at:             Option<std::time::Instant>,
    pub mac_table:           Vec<MacEntry>,
    pub mac_at:              Option<std::time::Instant>,
    pub optics:              Vec<InterfaceOptics>,
    pub optics_at:           Option<std::time::Instant>,
    pub optics_inventory:    Vec<OpticsInventoryEntry>,
    pub optics_inventory_at: Option<std::time::Instant>,
    pub arp_table:           Vec<ArpEntry>,
    pub arp_at:              Option<std::time::Instant>,
    pub ipv6_neighbors:      Vec<ArpEntry>,
    pub ipv6_neighbors_at:   Option<std::time::Instant>,
    pub last_error:          Option<String>,
}

use serde::Serialize;

// ── CommandOutput enum ──────────────────────────────────────────────

/// The unified output type for all looking glass commands.
///
/// Each variant carries structured, platform-independent data.
/// `Stream` is used for long-running commands (ping, traceroute) that
/// produce output incrementally. This variant is not serializable and
/// exists only in the in-process version (not in lg-types).
#[derive(Debug)]
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
    Stream(tokio::sync::mpsc::Receiver<String>),
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

    /// Convert an RPC-compatible CommandOutput back to the in-process version.
    pub fn from_rpc(rpc: lg_types::structured::CommandOutput) -> Self {
        match rpc {
            lg_types::structured::CommandOutput::InterfacesStatus(v) => CommandOutput::InterfacesStatus(v),
            lg_types::structured::CommandOutput::InterfaceDetail(v) => CommandOutput::InterfaceDetail(v),
            lg_types::structured::CommandOutput::MacAddressTable(v) => CommandOutput::MacAddressTable(v),
            lg_types::structured::CommandOutput::LldpNeighbors(v) => CommandOutput::LldpNeighbors(v),
            lg_types::structured::CommandOutput::Optics(v) => CommandOutput::Optics(v),
            lg_types::structured::CommandOutput::OpticsDetail(v) => CommandOutput::OpticsDetail(v),
            lg_types::structured::CommandOutput::OpticsInventory(v) => CommandOutput::OpticsInventory(v),
            lg_types::structured::CommandOutput::Arp(v) => CommandOutput::Arp(v),
            lg_types::structured::CommandOutput::IPv6Neighbors(v) => CommandOutput::IPv6Neighbors(v),
            lg_types::structured::CommandOutput::StreamLines(lines) => {
                // Convert buffered stream lines into a channel receiver
                let (tx, rx) = tokio::sync::mpsc::channel(lines.len().max(1));
                tokio::spawn(async move {
                    for line in lines {
                        let _ = tx.send(line).await;
                    }
                });
                CommandOutput::Stream(rx)
            }
            lg_types::structured::CommandOutput::Participants(s) => CommandOutput::Participants(s),
            lg_types::structured::CommandOutput::NetboxStatus(s) => CommandOutput::NetboxStatus(s),
            lg_types::structured::CommandOutput::DeviceCacheStatus(s) => CommandOutput::DeviceCacheStatus(s),
            lg_types::structured::CommandOutput::Error(e) => CommandOutput::Error(e),
        }
    }

    /// Convert this in-process CommandOutput to the RPC-compatible version.
    /// Stream variants cannot be converted (returns Error).
    #[allow(dead_code)]
    pub fn into_rpc(self) -> lg_types::structured::CommandOutput {
        match self {
            CommandOutput::InterfacesStatus(v) => lg_types::structured::CommandOutput::InterfacesStatus(v),
            CommandOutput::InterfaceDetail(v) => lg_types::structured::CommandOutput::InterfaceDetail(v),
            CommandOutput::MacAddressTable(v) => lg_types::structured::CommandOutput::MacAddressTable(v),
            CommandOutput::LldpNeighbors(v) => lg_types::structured::CommandOutput::LldpNeighbors(v),
            CommandOutput::Optics(v) => lg_types::structured::CommandOutput::Optics(v),
            CommandOutput::OpticsDetail(v) => lg_types::structured::CommandOutput::OpticsDetail(v),
            CommandOutput::OpticsInventory(v) => lg_types::structured::CommandOutput::OpticsInventory(v),
            CommandOutput::Arp(v) => lg_types::structured::CommandOutput::Arp(v),
            CommandOutput::IPv6Neighbors(v) => lg_types::structured::CommandOutput::IPv6Neighbors(v),
            CommandOutput::Stream(_) => lg_types::structured::CommandOutput::Error("cannot serialize live stream".into()),
            CommandOutput::Participants(s) => lg_types::structured::CommandOutput::Participants(s),
            CommandOutput::NetboxStatus(s) => lg_types::structured::CommandOutput::NetboxStatus(s),
            CommandOutput::DeviceCacheStatus(s) => lg_types::structured::CommandOutput::DeviceCacheStatus(s),
            CommandOutput::Error(e) => lg_types::structured::CommandOutput::Error(e),
        }
    }
}

impl Serialize for CommandOutput {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            CommandOutput::InterfacesStatus(v) => v.serialize(serializer),
            CommandOutput::InterfaceDetail(v) => v.serialize(serializer),
            CommandOutput::MacAddressTable(v) => v.serialize(serializer),
            CommandOutput::LldpNeighbors(v) => v.serialize(serializer),
            CommandOutput::Optics(v) => v.serialize(serializer),
            CommandOutput::OpticsDetail(v) => v.serialize(serializer),
            CommandOutput::OpticsInventory(v) => v.serialize(serializer),
            CommandOutput::Arp(v) => v.serialize(serializer),
            CommandOutput::IPv6Neighbors(v) => v.serialize(serializer),
            CommandOutput::Stream(_) => serializer.serialize_str("<streaming>"),
            CommandOutput::Participants(s) => serializer.serialize_str(s),
            CommandOutput::NetboxStatus(s) => serializer.serialize_str(s),
            CommandOutput::DeviceCacheStatus(s) => serializer.serialize_str(s),
            CommandOutput::Error(e) => {
                let mut map = serializer.serialize_map(Some(1))?;
                use serde::ser::SerializeMap;
                map.serialize_entry("error", e)?;
                map.end()
            }
        }
    }
}
