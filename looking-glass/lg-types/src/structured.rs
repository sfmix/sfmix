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
    /// True when `last_seen` is older than the configured `mac_ttl_secs`: the MAC
    /// hasn't been heard recently, so it no longer counts toward the live
    /// `conflict` flag. Defaults to false so pre-existing on-disk caches (written
    /// before aging) deserialize unchanged.
    #[serde(default)]
    pub stale: bool,
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

// ── ND Anomaly Events ───────────────────────────────────────────────
//
// A durable record of a new-MAC-on-an-existing-IP event detected while folding
// sensor polls into the discovered-neighbor store. Unlike the live `conflict`
// flag (which latches forever), these events carry rollup state: repeated flaps
// on the same IP within a cooldown window collapse into one event with a rising
// `flap_count`, so a burst of churn becomes a single bounded record rather than
// an event storm. Persisted by `AnomalyStore` (SQLite) in lg-server and served
// over RPC.

/// Event-kind discriminator: a single MAC newly appearing on an existing IP.
pub const EVENT_KIND_NEW_MAC: &str = "new_mac_on_ip";
/// Event-kind discriminator: one MAC claiming many IPs (proxy-ARP / sweep).
pub const EVENT_KIND_MAC_SWEEP: &str = "mac_claims_many_ips";

/// Classification refinement: the event is flood *reflection*, not a claim.
/// A bridging participant re-emitted flooded ND frames verbatim — rewriting only
/// the outer Ethernet source MAC to its own while preserving the original owner's
/// MAC inside the NDP source/target-link-layer-address option (or, for ARP, the
/// sender-hardware-address). Distinguishes benign flap-induced reflection from a
/// genuine impersonation/proxy-ARP sweep, which the raw kind cannot.
pub const EVENT_CLASSIFICATION_REFLECTION: &str = "reflection";

/// Event-kind discriminator: a MAC sourcing a protocol that has no business on
/// an IXP peering LAN (IPv6 RAs, DHCP, IGP hellos, discovery protocols, …) —
/// the "LAN hygiene" / BUM-traffic detections. `new_mac` is the source MAC,
/// `protocol` is a [`BUM_CATALOG`] key.
pub const EVENT_KIND_BUM_PROTOCOL: &str = "bum_protocol";

/// One row of the LAN-hygiene detection catalog. The sensor's classifier, the
/// lg-server store, the CLI and the portal all key off `key`, so this is the
/// single source of truth for what a detection is called, how bad it is, and
/// what to tell the participant to do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BumProto {
    /// Stable snake_case identifier stored in events and metrics.
    pub key: &'static str,
    /// Short human label ("IPv6 Router Advertisement").
    pub label: &'static str,
    /// `critical` (alerts to Slack), `warning`, or `info`.
    pub severity: &'static str,
    /// Why it matters, in one sentence.
    pub why: &'static str,
    /// Vendor-neutral remediation hint; plain text with `;`-separated variants.
    pub remediation: &'static str,
}

pub const BUM_SEVERITY_CRITICAL: &str = "critical";
pub const BUM_SEVERITY_WARNING: &str = "warning";
pub const BUM_SEVERITY_INFO: &str = "info";

/// The LAN-hygiene detection catalog. Order is display order within a severity.
/// Adding a protocol = one row here + one classifier rule + one test in the
/// sensor's `bum.rs`.
pub static BUM_CATALOG: &[BumProto] = &[
    BumProto { key: "ipv6_ra", label: "IPv6 Router Advertisement", severity: "critical",
        why: "Advertises this router as a default gateway to every other member on the exchange (free transit / traffic hijack).",
        remediation: "Arista: ipv6 nd ra disabled all; Cisco: ipv6 nd ra suppress all; Junos: delete protocols router-advertisement interface <ifl>; RouterOS: /ipv6 nd set [find] disabled=yes; Linux: stop radvd on the IX interface" },
    BumProto { key: "dhcpv4", label: "DHCPv4", severity: "critical",
        why: "A DHCP client or server on the exchange lets an untrusted peer hand out addresses and gateways.",
        remediation: "Cisco/Arista: no ip address dhcp and no ip dhcp server on the IX interface; RouterOS: /ip dhcp-client remove [find interface=<ix>] and /ip dhcp-server disable" },
    BumProto { key: "dhcpv6", label: "DHCPv6", severity: "critical",
        why: "Same as DHCPv4: address/gateway assignment from untrusted peers.",
        remediation: "Cisco/Arista: no ipv6 dhcp client / no ipv6 dhcp server on the IX interface; RouterOS: /ipv6 dhcp-client remove [find interface=<ix>]" },
    BumProto { key: "ospf", label: "OSPF hello", severity: "critical",
        why: "Unauthenticated IGP adjacency with a stranger merges internal routing tables.",
        remediation: "Cisco: passive-interface <ix> under router ospf; Arista: ip ospf passive (or ipv6 ospf passive) on the IX interface; Junos: set protocols ospf area <a> interface <ifl> passive" },
    BumProto { key: "isis", label: "IS-IS hello", severity: "critical",
        why: "Unauthenticated IGP adjacency with a stranger merges internal routing tables.",
        remediation: "Cisco: isis passive / remove ip router isis from the IX interface; Junos: set protocols isis interface <ifl> passive; Arista: isis passive" },
    BumProto { key: "eigrp", label: "EIGRP hello", severity: "critical",
        why: "Unauthenticated IGP adjacency with a stranger merges internal routing tables.",
        remediation: "Cisco: passive-interface <ix> under router eigrp" },
    BumProto { key: "rip", label: "RIP / RIPng", severity: "critical",
        why: "Unauthenticated routing exchange with strangers.",
        remediation: "Cisco: passive-interface <ix> under router rip, or no router rip; Linux: stop ripd/ripngd on the IX interface" },
    BumProto { key: "ldp", label: "MPLS LDP hello", severity: "critical",
        why: "Exposes label distribution to untrusted parties.",
        remediation: "Cisco/Arista: no mpls ldp on the IX interface (or mpls ldp passive-interface); Junos: delete protocols ldp interface <ifl>" },
    BumProto { key: "pim", label: "PIM hello", severity: "critical",
        why: "Multicast routing adjacency with strangers.",
        remediation: "Cisco/Arista: no ip pim sparse-mode / no ipv6 pim on the IX interface" },
    BumProto { key: "vrrp", label: "VRRP", severity: "critical",
        why: "Untrusted peers can influence or trigger failover of this router.",
        remediation: "Remove the vrrp group from the IX interface (VRRP redundancy belongs on your own LAN, not the exchange)" },
    BumProto { key: "hsrp", label: "HSRP", severity: "critical",
        why: "Untrusted peers can influence or trigger failover of this router.",
        remediation: "Cisco: no standby <group> on the IX interface" },
    BumProto { key: "glbp", label: "GLBP", severity: "critical",
        why: "Untrusted peers can influence or trigger failover of this router.",
        remediation: "Cisco: no glbp <group> on the IX interface" },
    BumProto { key: "stp", label: "Spanning Tree BPDU", severity: "critical",
        why: "Negotiates a spanning tree with the exchange fabric; can black-hole the port or disrupt neighbors.",
        remediation: "Cisco/Arista: spanning-tree bpdufilter enable on the IX port (or disable STP on it); Junos: set protocols rstp interface <ifl> disable" },
    BumProto { key: "cdp", label: "Cisco Discovery Protocol", severity: "warning",
        why: "Leaks device identity, platform and management addresses to every member.",
        remediation: "Cisco: no cdp enable on the IX interface" },
    BumProto { key: "cisco_l2", label: "Cisco proprietary L2 (VTP/DTP/PAgP/UDLD)", severity: "warning",
        why: "Trunk/VLAN/aggregation negotiation protocols aimed at a stranger's switch; can flap or reconfigure the port.",
        remediation: "Cisco: switchport nonegotiate, no vtp on the IX-facing port, no udld port, and no channel-group towards the exchange" },
    BumProto { key: "lldp", label: "LLDP", severity: "warning",
        why: "Leaks device identity, port names and management addresses to every member.",
        remediation: "Cisco/Arista: no lldp transmit (and no lldp receive) on the IX interface; Junos: delete protocols lldp interface <ifl>" },
    BumProto { key: "mndp", label: "MikroTik Neighbor Discovery", severity: "warning",
        why: "Leaks identity, RouterOS version, platform, uptime and addresses to every member.",
        remediation: "RouterOS: /ip neighbor discovery-settings set discover-interface-list=none (or an interface list that excludes the IX port)" },
    BumProto { key: "romon", label: "MikroTik RoMON", severity: "warning",
        why: "Exposes a layer-2 remote-management plane to untrusted networks.",
        remediation: "RouterOS: /tool romon set enabled=no (or exclude the IX port from the RoMON interface list)" },
    BumProto { key: "mac_telnet", label: "MikroTik MAC-Telnet / Winbox", severity: "warning",
        why: "Exposes a layer-2 management interface to untrusted networks.",
        remediation: "RouterOS: /tool mac-server set allowed-interface-list=none; /tool mac-server mac-winbox set allowed-interface-list=none" },
    BumProto { key: "mdns", label: "Multicast DNS", severity: "warning",
        why: "Service discovery chatter that leaks hostnames and services; wasted broadcast on the fabric.",
        remediation: "Disable avahi / Bonjour / mDNS responders on the IX-facing interface" },
    BumProto { key: "llmnr", label: "LLMNR", severity: "warning",
        why: "Windows name-resolution broadcast leaking hostnames onto the exchange.",
        remediation: "Windows: disable LLMNR (GPO 'Turn off multicast name resolution') or unbind it from the IX adapter" },
    BumProto { key: "ssdp", label: "SSDP / UPnP", severity: "warning",
        why: "Lets untrusted networks discover and possibly configure the device.",
        remediation: "Disable UPnP / SSDP on the IX-facing interface" },
    BumProto { key: "netbios", label: "NetBIOS", severity: "warning",
        why: "Exposes Windows/SMB name service to untrusted networks and leaks hostnames.",
        remediation: "Disable NetBIOS over TCP/IP on the IX-facing adapter" },
    BumProto { key: "igmp_query", label: "IGMP querier", severity: "warning",
        why: "Acting as the multicast querier on the exchange interferes with the fabric's snooping.",
        remediation: "Cisco/Arista: no ip igmp on the IX interface; disable any IGMP snooping querier facing the IX" },
    BumProto { key: "mld_query", label: "MLD querier", severity: "warning",
        why: "Acting as the IPv6 multicast querier on the exchange interferes with the fabric's snooping.",
        remediation: "Cisco/Arista: no ipv6 mld on the IX interface; disable any MLD snooping querier facing the IX" },
    BumProto { key: "ntp_broadcast", label: "Broadcast NTP", severity: "warning",
        why: "Broadcasting time to strangers wastes bandwidth and usually means the device has no good time source.",
        remediation: "Cisco: no ntp broadcast on the IX interface" },
    BumProto { key: "dot1q_tagged", label: "802.1Q-tagged frames", severity: "warning",
        why: "Tagged frames on an untagged exchange port mean a VLAN misconfiguration on the participant side.",
        remediation: "Remove the tag / subinterface facing the IX, or check the switchport trunk configuration on the IX-facing port" },
    BumProto { key: "foreign_arp", label: "ARP for a non-IX network", severity: "warning",
        why: "ARP for addresses outside the exchange prefixes means another LAN is leaking onto the IX port.",
        remediation: "Check for a VLAN leak / bridge / wrong subnet configured on the IX-facing interface" },
    BumProto { key: "foreign_ipv4_broadcast", label: "IPv4 broadcast from a non-IX source", severity: "warning",
        why: "Broadcasts sourced from addresses outside the exchange prefixes mean another LAN is leaking onto the IX port.",
        remediation: "Check for a VLAN leak / bridge / wrong subnet configured on the IX-facing interface" },
    BumProto { key: "bum_flood", label: "Broadcast/multicast flood", severity: "warning",
        why: "Sustained high-rate broadcast/multicast from one MAC — a loop, storm, or misbehaving host.",
        remediation: "Check for a bridging loop or storm behind this MAC; enable storm-control on the IX-facing port" },
    BumProto { key: "ipv6_rs", label: "IPv6 Router Solicitation", severity: "info",
        why: "A host on the exchange is asking for a default router — it will accept anyone's RA.",
        remediation: "Cisco: no ipv6 nd autoconfig default-route; Linux: net.ipv6.conf.<ix>.accept_ra=0 and no autoconf on the IX interface" },
    BumProto { key: "lacp", label: "LACP from a non-infrastructure MAC", severity: "info",
        why: "LACPDUs are link-local; seeing them from a participant means channel-group active on a port that is not a LAG towards the exchange.",
        remediation: "Remove channel-group / aggregated-ether from the IX-facing port unless a LAG was agreed with SFMIX" },
    BumProto { key: "dns_broadcast", label: "DNS query to a broadcast address", severity: "info",
        why: "A resolver is pointed at a broadcast/multicast address; leaks lookups to every member.",
        remediation: "Fix the name-server configuration on the device (remove the broadcast address resolver)" },
    BumProto { key: "icmpv6_echo_allnodes", label: "ICMPv6 echo to all-nodes", severity: "info",
        why: "Pinging ff02::1 makes every member reply — known SONiC neighbor-refresh behaviour.",
        remediation: "Upgrade SONiC / disable the arp_update refresher on the IX interface" },
    BumProto { key: "dec_mop", label: "DEC MOP", severity: "info",
        why: "Legacy DECnet maintenance protocol enabled by default on some Cisco IOS releases.",
        remediation: "Cisco: no mop enabled on the IX interface" },
    BumProto { key: "loop_detect", label: "Vendor loop-detection / keepalive", severity: "info",
        why: "Proprietary loopback keepalives; harmless but wasted broadcast.",
        remediation: "Cisco: no keepalive on the IX interface; Huawei: loop-detect disable" },
    BumProto { key: "unknown_ethertype", label: "Unknown EtherType", severity: "info",
        why: "A non-IP protocol nobody else on the exchange speaks; usually vendor L2 chatter.",
        remediation: "Identify the protocol from the EtherType in the detail and disable it on the IX-facing interface" },
    BumProto { key: "unknown_unicast_flood", label: "Unknown-unicast flood", severity: "info",
        why: "Sustained unicast towards a MAC the fabric has aged out — the destination is down or flapping; the source keeps sending.",
        remediation: "Informational: check the destination participant's link; the sender is usually behaving normally" },
];

/// Look up a catalog row by key.
pub fn bum_proto(key: &str) -> Option<&'static BumProto> {
    BUM_CATALOG.iter().find(|p| p.key == key)
}

fn default_event_kind() -> String {
    EVENT_KIND_NEW_MAC.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvent {
    /// UUID v4 primary key.
    pub id: String,
    /// What kind of anomaly this is: `new_mac_on_ip` (a new MAC appeared on an IP
    /// that already had others) or `mac_claims_many_ips` (one MAC claiming many
    /// IPs — proxy-ARP / impersonation / sweep). Defaults to `new_mac_on_ip` so
    /// rows/payloads written before this field deserialize unchanged.
    #[serde(default = "default_event_kind")]
    pub kind: String,
    /// For `new_mac_on_ip`: the conflicted IP. For `mac_claims_many_ips`: empty
    /// (the MAC is the subject; see `claimed_ips`).
    pub ip: String,
    pub family: String,
    pub asn: Option<u32>,
    pub tenant: Option<String>,
    /// MACs already heard for this IP when the new one appeared (per-IP events).
    pub old_macs: Vec<String>,
    /// `new_mac_on_ip`: the newly-heard MAC. `mac_claims_many_ips`: the offending MAC.
    pub new_mac: String,
    /// `mac_claims_many_ips`: the set of IPs this MAC was heard claiming (capped).
    /// Empty for `new_mac_on_ip`.
    #[serde(default)]
    pub claimed_ips: Vec<String>,
    /// RFC3339, when this event was first opened (window start).
    pub opened_at: String,
    /// RFC3339, the most recent time the conflict was *heard* (window end).
    /// Advanced both by new-MAC flaps and by re-hearing an ongoing conflict, so
    /// it tracks the true duration the anomaly persisted, not just new arrivals.
    pub last_seen: String,
    /// Number of distinct new-MAC arrivals rolled into this event (>= 1).
    pub flap_count: u64,
    /// Links to a sensor pcap snapshot once captured (Phase 2).
    pub evidence_id: Option<String>,
    /// True once the cooldown window has elapsed with no further flaps.
    pub closed: bool,
    /// Interpretation refinement, `None` for a plain event. `Some("reflection")`
    /// when the triggering frames preserved the original owner's MAC in the NDP
    /// link-layer-address option (or ARP sender-hardware-address) while the outer
    /// Ethernet source was rewritten — i.e. a bridging participant re-flooding
    /// fabric traffic verbatim, not spoofing. Defaults to `None` so rows/payloads
    /// written before this field deserialize unchanged.
    #[serde(default)]
    pub classification: Option<String>,
    /// `bum_protocol` events: the [`BUM_CATALOG`] key of the detected protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// `bum_protocol` events: `critical` | `warning` | `info` (from the catalog).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// `bum_protocol` events: sanitized sample details extracted from the frames
    /// (e.g. the advertised prefix, a MikroTik identity). Bounded, ASCII-only.
    #[serde(default)]
    pub detail: Vec<String>,
    /// `bum_protocol` events: true when a small evidence pcap is stored inline in
    /// lg-server (fetched via the event's `/pcap` endpoint).
    #[serde(default)]
    pub has_evidence: bool,
    /// `bum_protocol` events: catalog label / why-it-matters / remediation,
    /// filled from [`BUM_CATALOG`] at read time (never stored).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Metadata for one saved evidence pcap, as exposed by the lg-neighborhood-watch
/// sensor's `GET /evidence` listing. Mirrors the sensor's own `EvidenceMeta` so
/// the CLI can display capture size/frames/time without shipping the pcap bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceMeta {
    pub evidence_id: String,
    pub frame_count: u64,
    pub size_bytes: u64,
    /// RFC3339 modified time of the pcap file.
    pub created_at: String,
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
