// Re-export all data structs from lg-types::structured.
pub use lg_types::structured::{
    ArpEntry, BgpNeighborDetail, BgpPeerSummary, BgpRoute, BgpRouteList,
    BgpSourceNeighbor, BgpSourceStatus, BgpSummary, InterfaceCounters,
    InterfaceDetail, InterfaceOptics, InterfaceStatus, LldpNeighbor,
    MacEntry, NdEntry, OpticalLane, VxlanVtep,
};

use serde::Serialize;

// ── CommandOutput enum ──────────────────────────────────────────────

/// The unified output type for all looking glass commands.
///
/// Each variant carries structured, platform-independent data.
/// `Stream` is used for long-running commands (ping, traceroute) that
/// produce output incrementally. This variant is not serializable and
/// exists only in the in-process version (not in lg-types).
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

    /// Convert an RPC-compatible CommandOutput back to the in-process version.
    pub fn from_rpc(rpc: lg_types::structured::CommandOutput) -> Self {
        match rpc {
            lg_types::structured::CommandOutput::InterfacesStatus(v) => CommandOutput::InterfacesStatus(v),
            lg_types::structured::CommandOutput::InterfaceDetail(v) => CommandOutput::InterfaceDetail(v),
            lg_types::structured::CommandOutput::BgpSummary(v) => CommandOutput::BgpSummary(v),
            lg_types::structured::CommandOutput::BgpNeighborDetail(v) => CommandOutput::BgpNeighborDetail(v),
            lg_types::structured::CommandOutput::MacAddressTable(v) => CommandOutput::MacAddressTable(v),
            lg_types::structured::CommandOutput::ArpTable(v) => CommandOutput::ArpTable(v),
            lg_types::structured::CommandOutput::NdTable(v) => CommandOutput::NdTable(v),
            lg_types::structured::CommandOutput::LldpNeighbors(v) => CommandOutput::LldpNeighbors(v),
            lg_types::structured::CommandOutput::Optics(v) => CommandOutput::Optics(v),
            lg_types::structured::CommandOutput::OpticsDetail(v) => CommandOutput::OpticsDetail(v),
            lg_types::structured::CommandOutput::VxlanVtep(v) => CommandOutput::VxlanVtep(v),
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
            lg_types::structured::CommandOutput::BgpSources(v) => CommandOutput::BgpSources(v),
            lg_types::structured::CommandOutput::BgpRoutes(v) => CommandOutput::BgpRoutes(v),
            lg_types::structured::CommandOutput::BgpRouteLookup(v) => CommandOutput::BgpRouteLookup(v),
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
            CommandOutput::BgpSummary(v) => lg_types::structured::CommandOutput::BgpSummary(v),
            CommandOutput::BgpNeighborDetail(v) => lg_types::structured::CommandOutput::BgpNeighborDetail(v),
            CommandOutput::MacAddressTable(v) => lg_types::structured::CommandOutput::MacAddressTable(v),
            CommandOutput::ArpTable(v) => lg_types::structured::CommandOutput::ArpTable(v),
            CommandOutput::NdTable(v) => lg_types::structured::CommandOutput::NdTable(v),
            CommandOutput::LldpNeighbors(v) => lg_types::structured::CommandOutput::LldpNeighbors(v),
            CommandOutput::Optics(v) => lg_types::structured::CommandOutput::Optics(v),
            CommandOutput::OpticsDetail(v) => lg_types::structured::CommandOutput::OpticsDetail(v),
            CommandOutput::VxlanVtep(v) => lg_types::structured::CommandOutput::VxlanVtep(v),
            CommandOutput::Stream(_) => lg_types::structured::CommandOutput::Error("cannot serialize live stream".into()),
            CommandOutput::Participants(s) => lg_types::structured::CommandOutput::Participants(s),
            CommandOutput::NetboxStatus(s) => lg_types::structured::CommandOutput::NetboxStatus(s),
            CommandOutput::BgpSources(v) => lg_types::structured::CommandOutput::BgpSources(v),
            CommandOutput::BgpRoutes(v) => lg_types::structured::CommandOutput::BgpRoutes(v),
            CommandOutput::BgpRouteLookup(v) => lg_types::structured::CommandOutput::BgpRouteLookup(v),
            CommandOutput::Error(e) => lg_types::structured::CommandOutput::Error(e),
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
            CommandOutput::BgpSources(v) => v.serialize(serializer),
            CommandOutput::BgpRoutes(v) => v.serialize(serializer),
            CommandOutput::BgpRouteLookup(v) => v.serialize(serializer),
            CommandOutput::Participants(s) => serializer.serialize_str(s),
            CommandOutput::NetboxStatus(s) => serializer.serialize_str(s),
            CommandOutput::Error(e) => {
                let mut map = serializer.serialize_map(Some(1))?;
                use serde::ser::SerializeMap;
                map.serialize_entry("error", e)?;
                map.end()
            }
        }
    }
}
