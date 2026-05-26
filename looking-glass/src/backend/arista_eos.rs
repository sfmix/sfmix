use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use serde::{de, Deserialize, Deserializer};

use crate::command::{AddressFamily, Command, CommandResult, Resource, Verb};
use crate::config::{DeviceConfig, Platform};
use crate::structured::*;

use super::driver::DeviceDriver;
use super::ssh::{ssh_exec_direct, ssh_exec_stream};

/// Arista EOS device driver.
///
/// Connects to EOS devices via SSH and uses `| json` suffix to get
/// structured JSON output, which is parsed into platform-independent types.
pub struct AristaEosDriver {
    config: DeviceConfig,
}

impl AristaEosDriver {
    pub fn new(config: DeviceConfig) -> Self {
        Self { config }
    }

    /// Execute a CLI command with `| json` suffix and parse the JSON response.
    ///
    /// Uses SSH exec (no PTY) so the output is clean JSON without terminal
    /// escape sequences or shell prompts.
    async fn exec_json<T: for<'de> Deserialize<'de>>(&self, cli: &str) -> Result<T> {
        let cli_command = format!("{cli} | json");
        let raw = ssh_exec_direct(&self.config, &cli_command).await?;
        serde_json::from_str(raw.trim())
            .map_err(|e| anyhow::anyhow!("failed to parse EOS JSON for '{cli}': {e}"))
    }

    fn parse_interfaces_status(
        &self,
        raw: EosInterfaceStatuses,
        port_channel_members: &HashMap<String, Vec<String>>,
    ) -> Vec<InterfaceStatus> {
        // Build reverse map: member interface → parent Port-Channel name
        let mut member_to_port_channel: HashMap<&str, &str> = HashMap::new();
        for (port_channel_name, members) in port_channel_members {
            for member in members {
                member_to_port_channel.insert(member.as_str(), port_channel_name.as_str());
            }
        }

        let mut result: Vec<InterfaceStatus> = raw
            .interface_statuses
            .into_iter()
            .map(|(name, s)| {
                let member_interfaces = port_channel_members.get(&name)
                    .cloned()
                    .unwrap_or_default();
                let port_channel = member_to_port_channel.get(name.as_str()).map(|s| s.to_string());
                InterfaceStatus {
                    name,
                    description: s.description,
                    link_status: s.link_status,
                    protocol_status: s.line_protocol_status,
                    speed: s.bandwidth.map(format_speed).unwrap_or_default(),
                    interface_type: s.interface_type,
                    vlan: s.vlan_information.as_ref()
                        .and_then(|v| v.vlan_id.as_ref())
                        .map(|id| id.to_string())
                        .unwrap_or_default(),
                    auto_negotiate: s.auto_negotiate.unwrap_or(false),
                    member_interfaces,
                    port_channel,
                }
            })
            .collect();
        result.sort_by(|a, b| interface_sort_key(&a.name).cmp(&interface_sort_key(&b.name)));
        result
    }

    fn parse_interface_detail(&self, raw: EosInterfaceDetail) -> Result<InterfaceDetail> {
        let (name, iface) = raw
            .interfaces
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no interface in response"))?;
        let counters = iface.interface_counters.unwrap_or_default();
        Ok(InterfaceDetail {
            name,
            description: iface.description,
            link_status: iface.interface_status.unwrap_or_default(),
            protocol_status: iface.line_protocol_status.unwrap_or_default(),
            hardware_type: iface.hardware.unwrap_or_default(),
            mac_address: iface.physical_address.unwrap_or_default(),
            mtu: iface.mtu.unwrap_or(0),
            speed: iface.bandwidth.map(format_speed).unwrap_or_default(),
            bandwidth: iface.bandwidth.map(format_speed).unwrap_or_default(),
            counters: InterfaceCounters {
                in_octets: counters.in_octets,
                in_unicast_packets: counters.in_unicast_pkts,
                in_multicast_packets: counters.in_multicast_pkts,
                in_broadcast_packets: counters.in_broadcast_pkts,
                in_discards: counters.in_discards,
                in_errors: counters.in_errors,
                out_octets: counters.out_octets,
                out_unicast_packets: counters.out_unicast_pkts,
                out_multicast_packets: counters.out_multicast_pkts,
                out_broadcast_packets: counters.out_broadcast_pkts,
                out_discards: counters.out_discards,
                out_errors: counters.out_errors,
            },
            member_interfaces: {
                let mut members: Vec<String> = iface.member_interfaces.into_keys().collect();
                members.sort_by(|a, b| interface_sort_key(a).cmp(&interface_sort_key(b)));
                members
            },
        })
    }

    fn parse_bgp_summary(&self, raw: EosBgpSummary) -> BgpSummary {
        let mut peers: Vec<BgpPeerSummary> = raw
            .vrf_entry()
            .map(|vrf| {
                vrf.peers
                    .iter()
                    .map(|(addr, p)| BgpPeerSummary {
                        neighbor: addr.clone(),
                        remote_as: p.peer_as.unwrap_or(0),
                        description: p.description.clone().unwrap_or_default(),
                        state: p.peer_state.clone().unwrap_or_default(),
                        uptime: format_uptime_secs(p.updown_time.unwrap_or(0.0)),
                        prefixes_received: p.prefix_received.unwrap_or(0),
                        msg_received: p.msg_received.unwrap_or(0),
                        msg_sent: p.msg_sent.unwrap_or(0),
                    })
                    .collect()
            })
            .unwrap_or_default();
        peers.sort_by(|a, b| a.neighbor.cmp(&b.neighbor));
        BgpSummary {
            router_id: raw
                .vrf_entry()
                .map(|v| v.router_id.clone().unwrap_or_default())
                .unwrap_or_default(),
            local_as: raw
                .vrf_entry()
                .and_then(|v| v.as_number)
                .map(|a| a as u32)
                .unwrap_or(0),
            peers,
        }
    }

    fn parse_bgp_neighbor(&self, raw: EosBgpNeighbors) -> Result<BgpNeighborDetail> {
        let vrf = raw.vrf_entry()
            .ok_or_else(|| anyhow::anyhow!("no VRF in BGP response"))?;
        let (addr, p) = vrf
            .peer_list
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no peer in BGP neighbor response"))?;
        Ok(BgpNeighborDetail {
            neighbor: addr.clone(),
            remote_as: p.peer_as.unwrap_or(0),
            local_as: p.local_as.unwrap_or(0),
            description: p.description.clone().unwrap_or_default(),
            state: p.peer_state.clone().unwrap_or_default(),
            uptime: format_uptime_secs(p.updown_time.unwrap_or(0.0)),
            router_id: p.peer_router_id.clone().unwrap_or_default(),
            hold_time: p.hold_time.unwrap_or(0),
            keepalive_interval: p.keepalive_time.unwrap_or(0),
            prefixes_received: p.prefix_received.unwrap_or(0),
            prefixes_sent: p.prefix_accepted.unwrap_or(0),
            messages_received: p.msg_received.unwrap_or(0),
            messages_sent: p.msg_sent.unwrap_or(0),
        })
    }

    fn parse_mac_table(&self, raw: EosMacTable) -> Vec<MacEntry> {
        let mut entries: Vec<MacEntry> = raw
            .unicast_table
            .table_entries
            .into_iter()
            .map(|e| MacEntry {
                vlan: e.vlan_id.map(|v| v.to_string()).unwrap_or_default(),
                mac_address: e.mac_address,
                entry_type: e.entry_type,
                interface: e.interface,
            })
            .collect();
        entries.sort_by(|a, b| a.mac_address.cmp(&b.mac_address));
        entries
    }

    fn parse_arp_table(&self, raw: EosArpTable) -> Vec<ArpEntry> {
        let mut entries: Vec<ArpEntry> = raw
            .ip_v4_neighbors
            .into_iter()
            .map(|e| ArpEntry {
                ip_address: e.address,
                mac_address: e.hw_address,
                interface: e.interface,
                age: e.age.map(|a| format!("{a}s")).unwrap_or_default(),
            })
            .collect();
        entries.sort_by(|a, b| a.ip_address.cmp(&b.ip_address));
        entries
    }

    fn parse_nd_table(&self, raw: EosNdTable) -> Vec<NdEntry> {
        let mut entries: Vec<NdEntry> = raw
            .ipv6_neighbors
            .into_iter()
            .map(|e| NdEntry {
                ip_address: e.address,
                mac_address: e.hw_address,
                interface: e.interface,
                state: e.state.unwrap_or_default(),
            })
            .collect();
        entries.sort_by(|a, b| a.ip_address.cmp(&b.ip_address));
        entries
    }

    fn parse_lldp_neighbors(&self, raw: EosLldpNeighbors) -> Vec<LldpNeighbor> {
        let mut entries: Vec<LldpNeighbor> = raw
            .lldp_neighbors
            .into_iter()
            .map(|n| LldpNeighbor {
                local_interface: n.port,
                neighbor_device: n.neighbor_device.unwrap_or_default(),
                neighbor_port: n.neighbor_port.unwrap_or_default(),
                ttl: n.ttl.map(|t| t.to_string()).unwrap_or_default(),
            })
            .collect();
        entries.sort_by(|a, b| {
            interface_sort_key(&a.local_interface).cmp(&interface_sort_key(&b.local_interface))
        });
        entries
    }

    /// Fetch optics data by combining transceiver dom + interface status.
    ///
    /// Uses `show interfaces transceiver dom` which provides per-lane
    /// Tx/Rx power, bias, plus aggregate temperature and voltage.
    async fn fetch_optics(&self, target: Option<&str>) -> Result<Vec<InterfaceOptics>> {
        // Fetch interface status for descriptions and link status
        let status_raw: EosInterfaceStatuses =
            self.exec_json("show interfaces status").await?;
        // Fetch transceiver DOM (per-lane power/bias data)
        let transceiver_dom_command = match target {
            Some(t) => format!("show interfaces {t} transceiver dom"),
            None => "show interfaces transceiver dom".to_string(),
        };
        let transceiver_dom: EosTransceiverDom = self.exec_json(&transceiver_dom_command).await?;

        // Fetch port-channel membership for LAG member tracking
        let port_channel_members = match self.exec_json::<EosPortChannelSummary>(
            "show port-channel dense",
        ).await {
            Ok(port_channels) => port_channels.into_member_map(),
            Err(_) => HashMap::new(),
        };
        // Build reverse map: member interface → parent Port-Channel name
        let mut member_to_port_channel: HashMap<&str, &str> = HashMap::new();
        for (port_channel_name, members) in &port_channel_members {
            for member in members {
                member_to_port_channel.insert(member.as_str(), port_channel_name.as_str());
            }
        }

        let mut result: Vec<InterfaceOptics> = Vec::new();

        for (name, transceiver) in &transceiver_dom.interfaces {
            let status = status_raw.interface_statuses.get(name);
            let description = status.map(|s| s.description.clone()).unwrap_or_default();
            let link_status = status.map(|s| s.link_status.clone()).unwrap_or_default();
            let media_type = transceiver.media_type.clone().unwrap_or_else(|| {
                status.map(|s| s.interface_type.clone()).unwrap_or_default()
            });

            let params = transceiver.parameters.as_ref();

            // Temperature and voltage use the "-" (aggregate) channel
            let temperature_c = params
                .and_then(|p| p.temperature.as_ref())
                .and_then(|t| t.channels.get("-").copied().flatten())
                .and_then(|v| non_zero_f64(Some(v)));
            let voltage_v = params
                .and_then(|p| p.voltage.as_ref())
                .and_then(|v| v.channels.get("-").copied().flatten())
                .and_then(|v| non_zero_f64(Some(v)));

            // Per-lane data: channels keyed by "1", "2", etc.
            let lanes = if let Some(p) = params {
                let tx_bias = p.tx_bias.as_ref();
                let tx_power = p.tx_power.as_ref();
                let rx_power = p.rx_power.as_ref();

                // Collect all lane numbers from any parameter
                let mut lane_nums: Vec<u8> = Vec::new();
                for param in [&tx_bias, &tx_power, &rx_power].into_iter().flatten() {
                    for key in param.channels.keys() {
                        if key != "-" {
                            if let Ok(n) = key.parse::<u8>() {
                                if !lane_nums.contains(&n) {
                                    lane_nums.push(n);
                                }
                            }
                        }
                    }
                }
                lane_nums.sort();

                lane_nums
                    .into_iter()
                    .map(|n| {
                        let key = n.to_string();
                        OpticalLane {
                            lane: n,
                            tx_power_dbm: tx_power
                                .and_then(|p| p.channels.get(&key).copied().flatten())
                                .and_then(|v| non_zero_f64(Some(v))),
                            rx_power_dbm: rx_power
                                .and_then(|p| p.channels.get(&key).copied().flatten())
                                .and_then(|v| non_zero_f64(Some(v))),
                            tx_bias_ma: tx_bias
                                .and_then(|p| p.channels.get(&key).copied().flatten())
                                .and_then(|v| non_zero_f64(Some(v))),
                        }
                    })
                    .collect()
            } else {
                vec![]
            };

            let dom_supported = params.is_some()
                && (temperature_c.is_some()
                    || voltage_v.is_some()
                    || lanes.iter().any(|l| {
                        l.tx_power_dbm.is_some()
                            || l.rx_power_dbm.is_some()
                            || l.tx_bias_ma.is_some()
                    }));

            result.push(InterfaceOptics {
                name: name.clone(),
                description,
                link_status,
                media_type,
                temperature_c,
                voltage_v,
                lanes,
                dom_supported,
                port_channel: member_to_port_channel.get(name.as_str()).map(|s| s.to_string()),
            });
        }

        // Add visible interfaces that lack transceiver data (DAC, copper, empty)
        if target.is_none() {
            let transceiver_dom_names: std::collections::HashSet<&String> =
                transceiver_dom.interfaces.keys().collect();
            for (name, status) in &status_raw.interface_statuses {
                if transceiver_dom_names.contains(name) {
                    continue;
                }
                // Skip non-physical interfaces
                if !name.starts_with("Ethernet") {
                    continue;
                }
                result.push(InterfaceOptics {
                    name: name.clone(),
                    description: status.description.clone(),
                    link_status: status.link_status.clone(),
                    media_type: status.interface_type.clone(),
                    temperature_c: None,
                    voltage_v: None,
                    lanes: vec![],
                    dom_supported: false,
                    port_channel: member_to_port_channel.get(name.as_str()).map(|s| s.to_string()),
                });
            }
        }

        result.sort_by(|a, b| interface_sort_key(&a.name).cmp(&interface_sort_key(&b.name)));
        Ok(result)
    }

    fn parse_vxlan_vtep(&self, raw: EosVxlanVtep) -> Vec<VxlanVtep> {
        raw.vteps
            .into_iter()
            .map(|v| VxlanVtep {
                vtep_address: v.address,
                learned_from: v.learned_from.unwrap_or_default(),
            })
            .collect()
    }
}

#[async_trait]
impl DeviceDriver for AristaEosDriver {
    fn platform(&self) -> Platform {
        Platform::AristaEos
    }

    async fn execute(&self, command: &Command) -> Result<CommandResult> {
        let output = match (&command.verb, &command.resource) {
            (Verb::Show, Resource::InterfacesStatus) => {
                let raw: EosInterfaceStatuses =
                    self.exec_json("show interfaces status").await?;
                // Fetch port-channel membership (best-effort)
                let port_channel_members = match self.exec_json::<EosPortChannelSummary>(
                    "show port-channel dense",
                ).await {
                    Ok(summary) => summary.into_member_map(),
                    Err(_) => HashMap::new(),
                };
                CommandOutput::InterfacesStatus(self.parse_interfaces_status(raw, &port_channel_members))
            }
            (Verb::Show, Resource::InterfaceDetail) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("interface name required"))?;
                let raw: EosInterfaceDetail =
                    self.exec_json(&format!("show interfaces {target}")).await?;
                CommandOutput::InterfaceDetail(self.parse_interface_detail(raw)?)
            }
            (Verb::Show, Resource::BgpSummary) => {
                let cli_command = match command.address_family {
                    AddressFamily::IPv4 => "show ip bgp summary",
                    AddressFamily::IPv6 => "show bgp ipv6 unicast summary",
                };
                let raw: EosBgpSummary = self.exec_json(cli_command).await?;
                CommandOutput::BgpSummary(self.parse_bgp_summary(raw))
            }
            (Verb::Show, Resource::BgpNeighbor) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("neighbor address required"))?;
                let raw: EosBgpNeighbors =
                    self.exec_json(&format!("show ip bgp neighbors {target}")).await?;
                CommandOutput::BgpNeighborDetail(self.parse_bgp_neighbor(raw)?)
            }
            (Verb::Show, Resource::MacAddressTable) => {
                let cli_command = match &command.target {
                    Some(interface) => format!("show mac address-table interface {interface}"),
                    None => "show mac address-table".to_string(),
                };
                let raw: EosMacTable = self.exec_json(&cli_command).await?;
                CommandOutput::MacAddressTable(self.parse_mac_table(raw))
            }
            (Verb::Show, Resource::ArpTable) => {
                let cli_command = match &command.target {
                    Some(interface) => format!("show arp interface {interface}"),
                    None => "show arp".to_string(),
                };
                let raw: EosArpTable = self.exec_json(&cli_command).await?;
                CommandOutput::ArpTable(self.parse_arp_table(raw))
            }
            (Verb::Show, Resource::NdTable) => {
                let cli_command = match &command.target {
                    Some(interface) => format!("show ipv6 neighbors interface {interface}"),
                    None => "show ipv6 neighbors".to_string(),
                };
                let raw: EosNdTable = self.exec_json(&cli_command).await?;
                CommandOutput::NdTable(self.parse_nd_table(raw))
            }
            (Verb::Show, Resource::LldpNeighbors) => {
                let raw: EosLldpNeighbors =
                    self.exec_json("show lldp neighbors").await?;
                CommandOutput::LldpNeighbors(self.parse_lldp_neighbors(raw))
            }
            (Verb::Show, Resource::Optics) => {
                let optics = self.fetch_optics(None).await?;
                CommandOutput::Optics(optics)
            }
            (Verb::Show, Resource::OpticsDetail) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("interface name required"))?;
                let optics = self.fetch_optics(Some(target)).await?;
                CommandOutput::OpticsDetail(optics)
            }
            (Verb::Show, Resource::VxlanVtep) => {
                let raw: EosVxlanVtep =
                    self.exec_json("show vxlan vtep").await?;
                CommandOutput::VxlanVtep(self.parse_vxlan_vtep(raw))
            }
            (Verb::Ping, Resource::NetworkReachability) | (Verb::Traceroute, Resource::NetworkReachability) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("destination required"))?;
                let cli_command = match command.verb {
                    Verb::Ping => format!("ping {target}"),
                    Verb::Traceroute => format!("traceroute {target}"),
                    _ => unreachable!(),
                };
                let rx = ssh_exec_stream(&self.config, &cli_command).await?;
                CommandOutput::Stream(rx)
            }
            _ => anyhow::bail!("unsupported command for Arista EOS"),
        };

        Ok(CommandResult {
            device: self.config.name.clone(),
            output,
            success: true,
        })
    }

    async fn is_alive(&self) -> bool {
        false
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }

}

// ── EOS JSON deserialization types (private) ─────────────────────────

/// Strip ANSI escapes and leading/trailing whitespace from SSH output
/// to get clean JSON.
fn normalize_eos_json(raw: &str) -> String {
    let no_cr = raw.replace('\r', "");
    let mut out = String::with_capacity(no_cr.len());
    let mut chars = no_cr.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    // CSI sequence: ESC [ … terminated by a byte in 0x40–0x7E.
                    chars.next();
                    while let Some(&ch) = chars.peek() {
                        chars.next();
                        if ch >= '@' && ch <= '~' {
                            break;
                        }
                    }
                }
                Some(']') | Some('P') | Some('^') | Some('_') | Some('X') => {
                    // OSC / DCS / PM / APC / SOS: ESC ] (or P/^/_/X) … ST or BEL.
                    chars.next();
                    while let Some(ch) = chars.next() {
                        if ch == '\x07' {
                            break;
                        }
                        if ch == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    // Two-character escape sequence (ESC =, ESC >, ESC 7, ESC M, …).
                    // Consume the second byte; it is not printable content.
                    chars.next();
                }
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out.trim().to_string()
}

/// Convert a 0.0 value to None (EOS uses 0.0 for "not available").
fn non_zero_f64(v: Option<f64>) -> Option<f64> {
    v.filter(|&x| x != 0.0)
}

/// Format bandwidth in bits/sec to a human-readable speed string.
fn format_speed(bps: u64) -> String {
    if bps >= 100_000_000_000 {
        format!("{}Gbps", bps / 1_000_000_000)
    } else if bps >= 1_000_000_000 {
        format!("{}Gbps", bps / 1_000_000_000)
    } else if bps >= 1_000_000 {
        format!("{}Mbps", bps / 1_000_000)
    } else if bps >= 1_000 {
        format!("{}Kbps", bps / 1_000)
    } else {
        format!("{bps}bps")
    }
}

/// Format seconds since epoch or duration to human-readable uptime.
fn format_uptime_secs(secs: f64) -> String {
    let s = secs.abs() as u64;
    if s >= 86400 {
        let days = s / 86400;
        let hours = (s % 86400) / 3600;
        format!("{days}d{hours}h")
    } else if s >= 3600 {
        let hours = s / 3600;
        let mins = (s % 3600) / 60;
        format!("{hours}h{mins}m")
    } else if s >= 60 {
        let mins = s / 60;
        let secs = s % 60;
        format!("{mins}m{secs}s")
    } else {
        format!("{s}s")
    }
}

/// Sort key for interface names (Ethernet1 < Ethernet2 < Ethernet10 < Ethernet50/1).
fn interface_sort_key(name: &str) -> (u8, u32, u32) {
    let prefix_order = if name.starts_with("Ethernet") {
        0
    } else if name.starts_with("Loopback") {
        1
    } else if name.starts_with("Management") {
        2
    } else if name.starts_with("Port-Channel") {
        3
    } else if name.starts_with("Vlan") {
        4
    } else if name.starts_with("Vxlan") {
        5
    } else {
        6
    };
    // Extract numeric parts after the prefix
    let num_part = name
        .trim_start_matches(|c: char| c.is_alphabetic() || c == '-');
    let parts: Vec<&str> = num_part.split('/').collect();
    let major = parts.first().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let minor = parts.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    (prefix_order, major, minor)
}

// ── show interfaces status ──────────────────────────────────────────

#[derive(Deserialize)]
struct EosInterfaceStatuses {
    #[serde(rename = "interfaceStatuses")]
    interface_statuses: HashMap<String, EosInterfaceStatusEntry>,
}

#[derive(Deserialize)]
struct EosInterfaceStatusEntry {
    #[serde(default)]
    description: String,
    #[serde(rename = "linkStatus", default)]
    link_status: String,
    #[serde(rename = "lineProtocolStatus", default)]
    line_protocol_status: String,
    #[serde(rename = "bandwidth", default)]
    bandwidth: Option<u64>,
    #[serde(rename = "interfaceType", default)]
    interface_type: String,
    #[serde(rename = "vlanInformation", default)]
    vlan_information: Option<EosVlanInfo>,
    #[serde(rename = "autoNegotiate", default)]
    auto_negotiate: Option<bool>,
}

#[derive(Deserialize)]
struct EosVlanInfo {
    #[serde(rename = "vlanId", default)]
    vlan_id: Option<u32>,
}

// ── show port-channel dense ─────────────────────────────────────────

#[derive(Deserialize)]
struct EosPortChannelSummary {
    #[serde(rename = "portChannels", default)]
    port_channels: HashMap<String, EosPortChannelEntry>,
}

#[derive(Deserialize)]
struct EosPortChannelEntry {
    #[serde(default)]
    ports: HashMap<String, serde_json::Value>,
}

impl EosPortChannelSummary {
    /// Build a map from Port-Channel name → sorted list of member interface names.
    fn into_member_map(self) -> HashMap<String, Vec<String>> {
        self.port_channels
            .into_iter()
            .map(|(port_channel_name, entry)| {
                let mut members: Vec<String> = entry.ports.into_keys().collect();
                members.sort_by(|a, b| interface_sort_key(a).cmp(&interface_sort_key(b)));
                (port_channel_name, members)
            })
            .collect()
    }
}

// ── show interfaces <name> ──────────────────────────────────────────

#[derive(Deserialize)]
struct EosInterfaceDetail {
    interfaces: HashMap<String, EosInterfaceDetailEntry>,
}

#[derive(Deserialize)]
struct EosInterfaceDetailEntry {
    #[serde(default)]
    description: String,
    #[serde(rename = "interfaceStatus", default)]
    interface_status: Option<String>,
    #[serde(rename = "lineProtocolStatus", default)]
    line_protocol_status: Option<String>,
    #[serde(default)]
    hardware: Option<String>,
    #[serde(rename = "physicalAddress", default)]
    physical_address: Option<String>,
    #[serde(default)]
    mtu: Option<u32>,
    #[serde(default)]
    bandwidth: Option<u64>,
    #[serde(rename = "interfaceCounters", default)]
    interface_counters: Option<EosCounters>,
    #[serde(rename = "memberInterfaces", default)]
    member_interfaces: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize, Default)]
struct EosCounters {
    #[serde(rename = "inOctets", default)]
    in_octets: u64,
    #[serde(rename = "inUcastPkts", default)]
    in_unicast_pkts: u64,
    #[serde(rename = "inMulticastPkts", default)]
    in_multicast_pkts: u64,
    #[serde(rename = "inBroadcastPkts", default)]
    in_broadcast_pkts: u64,
    #[serde(rename = "inDiscards", default)]
    in_discards: u64,
    #[serde(rename = "inErrors", default)]
    in_errors: u64,
    #[serde(rename = "outOctets", default)]
    out_octets: u64,
    #[serde(rename = "outUcastPkts", default)]
    out_unicast_pkts: u64,
    #[serde(rename = "outMulticastPkts", default)]
    out_multicast_pkts: u64,
    #[serde(rename = "outBroadcastPkts", default)]
    out_broadcast_pkts: u64,
    #[serde(rename = "outDiscards", default)]
    out_discards: u64,
    #[serde(rename = "outErrors", default)]
    out_errors: u64,
}

// EOS sometimes returns ASN fields as quoted strings instead of integers.
fn deserialize_optional_asn<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde_json::Value;
    let v = Option::<Value>::deserialize(deserializer)?;
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(Some).ok_or_else(|| de::Error::custom("invalid ASN")),
        Some(Value::String(s)) => s.parse::<u64>().map(Some).map_err(de::Error::custom),
        _ => Err(de::Error::custom("expected number or string for ASN")),
    }
}

// ── show ip bgp summary ─────────────────────────────────────────────

#[derive(Deserialize)]
struct EosBgpSummary {
    #[serde(rename = "vrfs", default)]
    vrfs: HashMap<String, EosBgpVrfSummary>,
}

impl EosBgpSummary {
    fn vrf_entry(&self) -> Option<&EosBgpVrfSummary> {
        self.vrfs.get("default").or_else(|| self.vrfs.values().next())
    }
}

#[derive(Deserialize)]
struct EosBgpVrfSummary {
    #[serde(rename = "routerId", default)]
    router_id: Option<String>,
    #[serde(rename = "asn", default, deserialize_with = "deserialize_optional_asn")]
    as_number: Option<u64>,
    #[serde(default)]
    peers: HashMap<String, EosBgpPeerSummaryEntry>,
}

#[derive(Deserialize)]
struct EosBgpPeerSummaryEntry {
    #[serde(rename = "peerAs", default)]
    peer_as: Option<u32>,
    #[serde(default)]
    description: Option<String>,
    #[serde(rename = "peerState", default)]
    peer_state: Option<String>,
    #[serde(rename = "upDownTime", default)]
    updown_time: Option<f64>,
    #[serde(rename = "prefixReceived", default)]
    prefix_received: Option<u32>,
    #[serde(rename = "msgReceived", default)]
    msg_received: Option<u64>,
    #[serde(rename = "msgSent", default)]
    msg_sent: Option<u64>,
}

// ── show ip bgp neighbors <addr> ────────────────────────────────────

#[derive(Deserialize)]
struct EosBgpNeighbors {
    #[serde(rename = "vrfs", default)]
    vrfs: HashMap<String, EosBgpVrfNeighbors>,
}

impl EosBgpNeighbors {
    fn vrf_entry(&self) -> Option<&EosBgpVrfNeighbors> {
        self.vrfs.get("default").or_else(|| self.vrfs.values().next())
    }
}

#[derive(Deserialize)]
struct EosBgpVrfNeighbors {
    #[serde(rename = "peerList", default)]
    peer_list: HashMap<String, EosBgpNeighborEntry>,
}

#[derive(Deserialize)]
struct EosBgpNeighborEntry {
    #[serde(rename = "peerAs", default)]
    peer_as: Option<u32>,
    #[serde(rename = "localAs", default)]
    local_as: Option<u32>,
    #[serde(default)]
    description: Option<String>,
    #[serde(rename = "peerState", default)]
    peer_state: Option<String>,
    #[serde(rename = "upDownTime", default)]
    updown_time: Option<f64>,
    #[serde(rename = "peerRouterId", default)]
    peer_router_id: Option<String>,
    #[serde(rename = "holdTime", default)]
    hold_time: Option<u32>,
    #[serde(rename = "keepaliveTime", default)]
    keepalive_time: Option<u32>,
    #[serde(rename = "prefixReceived", default)]
    prefix_received: Option<u32>,
    #[serde(rename = "prefixAccepted", default)]
    prefix_accepted: Option<u32>,
    #[serde(rename = "msgReceived", default)]
    msg_received: Option<u64>,
    #[serde(rename = "msgSent", default)]
    msg_sent: Option<u64>,
}

// ── show mac address-table ──────────────────────────────────────────

#[derive(Deserialize)]
struct EosMacTable {
    #[serde(rename = "unicastTable", default)]
    unicast_table: EosMacUnicastTable,
}

#[derive(Deserialize, Default)]
struct EosMacUnicastTable {
    #[serde(rename = "tableEntries", default)]
    table_entries: Vec<EosMacTableEntry>,
}

#[derive(Deserialize)]
struct EosMacTableEntry {
    #[serde(rename = "vlanId", default)]
    vlan_id: Option<u32>,
    #[serde(rename = "macAddress", default)]
    mac_address: String,
    #[serde(rename = "entryType", default)]
    entry_type: String,
    #[serde(default)]
    interface: String,
}

// ── show arp ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct EosArpTable {
    #[serde(rename = "ipV4Neighbors", default)]
    ip_v4_neighbors: Vec<EosArpEntry>,
}

#[derive(Deserialize)]
struct EosArpEntry {
    #[serde(default)]
    address: String,
    #[serde(rename = "hwAddress", default)]
    hw_address: String,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    age: Option<f64>,
}

// ── show ipv6 neighbors ─────────────────────────────────────────────

#[derive(Deserialize)]
struct EosNdTable {
    #[serde(rename = "ipV6Neighbors", default)]
    ipv6_neighbors: Vec<EosNdEntry>,
}

#[derive(Deserialize)]
struct EosNdEntry {
    #[serde(default)]
    address: String,
    #[serde(rename = "hwAddress", default)]
    hw_address: String,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    state: Option<String>,
}

// ── show lldp neighbors ─────────────────────────────────────────────

#[derive(Deserialize)]
struct EosLldpNeighbors {
    #[serde(rename = "lldpNeighbors", default)]
    lldp_neighbors: Vec<EosLldpNeighborEntry>,
}

#[derive(Deserialize)]
struct EosLldpNeighborEntry {
    #[serde(default)]
    port: String,
    #[serde(rename = "neighborDevice", default)]
    neighbor_device: Option<String>,
    #[serde(rename = "neighborPort", default)]
    neighbor_port: Option<String>,
    #[serde(default)]
    ttl: Option<u32>,
}

// ── show interfaces transceiver dom ─────────────────────────────────

#[derive(Deserialize)]
struct EosTransceiverDom {
    #[serde(default)]
    interfaces: HashMap<String, EosTransceiverDomInterface>,
}

#[derive(Deserialize)]
struct EosTransceiverDomInterface {
    #[serde(rename = "mediaType", default)]
    media_type: Option<String>,
    #[serde(default)]
    parameters: Option<EosTransceiverDomParams>,
}

#[derive(Deserialize)]
struct EosTransceiverDomParams {
    #[serde(default)]
    temperature: Option<EosTransceiverDomParam>,
    #[serde(default)]
    voltage: Option<EosTransceiverDomParam>,
    #[serde(rename = "txBias", default)]
    tx_bias: Option<EosTransceiverDomParam>,
    #[serde(rename = "txPower", default)]
    tx_power: Option<EosTransceiverDomParam>,
    #[serde(rename = "rxPower", default)]
    rx_power: Option<EosTransceiverDomParam>,
}

#[derive(Deserialize)]
struct EosTransceiverDomParam {
    #[serde(default)]
    channels: HashMap<String, Option<f64>>,
}

// ── show vxlan vtep ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct EosVxlanVtep {
    #[serde(default)]
    vteps: Vec<EosVtepEntry>,
}

#[derive(Deserialize)]
struct EosVtepEntry {
    #[serde(default)]
    address: String,
    #[serde(rename = "learnedFrom", default)]
    learned_from: Option<String>,
}

// ── Unit tests ───────────────────────────────────────────────────────
//
// Test vectors were captured from a real Arista EOS PTY session via SSH.
// The raw byte stream includes:
//   - Terminal init CSI sequences  (\x1b[?1049h, \x1b[?1h, …)
//   - OSC window-title sequences   (\x1b]0;hostname\x07)
//   - CSI colour codes around the prompt  (\x1b[32m … \x1b[0m)
//   - The JSON payload (unescaped plain text)
//   - A trailing prompt
//
// To capture fresh vectors: set RUST_LOG=debug and grep for
// "SSH exec" lines, or add a temporary eprintln!(…) in exec_json.
#[cfg(test)]
mod tests {
    use super::*;

    // ── normalize_eos_json ─────────────────────────────────────────

    #[test]
    fn test_normalize_plain_json() {
        let input = r#"{"vrfs":{}}"#;
        assert_eq!(normalize_eos_json(input), r#"{"vrfs":{}}"#);
    }

    #[test]
    fn test_normalize_strips_csi_color_codes() {
        // EOS wraps prompt text in CSI SGR (Select Graphic Rendition) codes.
        // The text itself ("switch01#") survives because CSI only strips the
        // escape sequence bytes, not the surrounding characters.
        let input = "\x1b[32mswitch01\x1b[0m#";
        assert_eq!(normalize_eos_json(input), "switch01#");
    }

    #[test]
    fn test_normalize_strips_osc_bel_title() {
        // OSC 0 sets the window/icon title; EOS uses this for the hostname.
        // Terminated with BEL (\x07).
        let input = "\x1b]0;switch01.sfo01.sfmix.org\x07";
        assert_eq!(normalize_eos_json(input), "");
    }

    #[test]
    fn test_normalize_strips_osc_st_title() {
        // OSC terminated with ST (ESC \) instead of BEL — both forms appear
        // in real EOS sessions depending on client negotiation.
        let input = "\x1b]0;switch01.sfo01.sfmix.org\x1b\\";
        assert_eq!(normalize_eos_json(input), "");
    }

    #[test]
    fn test_normalize_removes_cr() {
        // SSH PTY sessions use CRLF line endings; normalize to LF only.
        let input = "{\r\n  \"key\": 1\r\n}";
        let out = normalize_eos_json(input);
        assert!(!out.contains('\r'));
        assert_eq!(out, "{\n  \"key\": 1\n}");
    }

    #[test]
    fn test_normalize_eos_pty_session() {
        // Realistic EOS PTY session fixture.
        //
        // EOS sends:
        //   1. Terminal-mode CSI init sequences  (stripped)
        //   2. OSC window-title with the hostname (stripped)
        //   3. CSI-coloured prompt text — the hostname survives stripping because
        //      CSI codes wrap only the ANSI colour; the text itself is kept.
        //   4. The JSON command output (kept verbatim)
        //   5. A trailing prompt (hostname text again)
        //
        // After stripping and trimming the result must be parseable as JSON.
        // The prompt text before/after the JSON means normalize_eos_json alone
        // does NOT produce pure JSON — callers must handle a leading prompt line
        // and trailing prompt. This test documents the *actual* behaviour so
        // that a future fix to extract only the JSON object can be verified.
        let eos_pty = concat!(
            // Terminal init
            "\x1b[?1049h\x1b[?1h\x1b=\r\x1b[H\x1b[J",
            // OSC window-title (stripped entirely)
            "\x1b]0;switch01.sfo01.sfmix.org\x07",
            // Prompt (CSI colour codes stripped, hostname text kept)
            "\x1b[32mswitch01.sfo01\x1b[0m\x1b[1m#\x1b[0m ",
            // Command echo + newline
            "show arp | json\r\n",
            // JSON payload
            "{\r\n  \"ipV4Neighbors\": []\r\n}\r\n",
            // Trailing prompt
            "\x1b[32mswitch01.sfo01\x1b[0m\x1b[1m#\x1b[0m ",
        );
        let out = normalize_eos_json(eos_pty);
        // Prompt text is present — JSON is not at column 0.
        assert!(out.contains("\"ipV4Neighbors\""));
        // No ANSI escape bytes remain.
        assert!(!out.contains('\x1b'));
        // No carriage returns remain.
        assert!(!out.contains('\r'));
    }

    #[test]
    fn test_normalize_only_ansi_gives_empty() {
        // If the SSH channel returns only terminal init sequences before
        // closing (e.g., auth succeeded but command produced no output),
        // normalize returns an empty string → serde_json fails with
        // "expected value at line 1 column 1".  This test documents that
        // failure mode so the error message makes sense in context.
        let only_ansi = "\x1b[?1049h\x1b[?1h\x1b=\r\x1b[H\x1b[J\x1b]0;host\x07";
        assert_eq!(normalize_eos_json(only_ansi), "");
    }

    // ── BGP summary deserialization ────────────────────────────────

    fn parse_bgp(json: &str) -> EosBgpSummary {
        serde_json::from_str(json).expect("parse failed")
    }

    #[test]
    fn test_bgp_asn_as_integer() {
        // Newer EOS versions send the local ASN as a JSON integer.
        let raw = r#"{"vrfs":{"default":{"routerId":"10.0.0.1","asn":40271,"peers":{}}}}"#;
        let s = parse_bgp(raw);
        assert_eq!(s.vrf_entry().unwrap().as_number, Some(40271));
    }

    #[test]
    fn test_bgp_asn_as_string() {
        // Older EOS versions send the local ASN as a quoted string.
        // This was the source of the "invalid type: string, expected u64" error.
        let raw = r#"{"vrfs":{"default":{"routerId":"10.0.0.1","asn":"40271","peers":{}}}}"#;
        let s = parse_bgp(raw);
        assert_eq!(s.vrf_entry().unwrap().as_number, Some(40271));
    }

    #[test]
    fn test_bgp_asn_missing_defaults_to_none() {
        let raw = r#"{"vrfs":{"default":{"routerId":"10.0.0.1","peers":{}}}}"#;
        let s = parse_bgp(raw);
        assert_eq!(s.vrf_entry().unwrap().as_number, None);
    }

    #[test]
    fn test_bgp_asn_null_gives_none() {
        let raw = r#"{"vrfs":{"default":{"routerId":"10.0.0.1","asn":null,"peers":{}}}}"#;
        let s = parse_bgp(raw);
        assert_eq!(s.vrf_entry().unwrap().as_number, None);
    }

    #[test]
    fn test_bgp_empty_vrfs_no_bgp_configured() {
        // Switches that don't run BGP return an empty vrfs map.
        let raw = r#"{"vrfs":{}}"#;
        let s = parse_bgp(raw);
        assert!(s.vrf_entry().is_none());
    }

    #[test]
    fn test_bgp_with_established_peer() {
        let raw = r#"{
            "vrfs": {
                "default": {
                    "routerId": "10.100.1.1",
                    "asn": "12276",
                    "peers": {
                        "10.255.0.10": {
                            "peerAs": 64496,
                            "description": "Mapple",
                            "peerState": "Established",
                            "upDownTime": 86523.0,
                            "prefixReceived": 1,
                            "msgReceived": 1440,
                            "msgSent": 1438
                        }
                    }
                }
            }
        }"#;
        let s = parse_bgp(raw);
        let vrf = s.vrf_entry().unwrap();
        assert_eq!(vrf.as_number, Some(12276));
        let peer = vrf.peers.get("10.255.0.10").unwrap();
        assert_eq!(peer.peer_as, Some(64496));
        assert_eq!(peer.peer_state.as_deref(), Some("Established"));
        assert_eq!(peer.prefix_received, Some(1));
    }

    // ── ARP table deserialization ──────────────────────────────────

    #[test]
    fn test_arp_table_entries() {
        let raw = r#"{
            "ipV4Neighbors": [
                {
                    "address": "206.197.187.10",
                    "hwAddress": "aa:bb:cc:dd:ee:ff",
                    "interface": "Vlan998",
                    "age": 120.5
                },
                {
                    "address": "206.197.187.11",
                    "hwAddress": "11:22:33:44:55:66",
                    "interface": "Vlan998",
                    "age": null
                }
            ]
        }"#;
        let t: EosArpTable = serde_json::from_str(raw).unwrap();
        assert_eq!(t.ip_v4_neighbors.len(), 2);
        assert_eq!(t.ip_v4_neighbors[0].address, "206.197.187.10");
        assert_eq!(t.ip_v4_neighbors[1].age, None);
    }

    // ── Interface status deserialization ───────────────────────────

    #[test]
    fn test_interface_status_connected() {
        let raw = r#"{
            "interfaceStatuses": {
                "Ethernet43": {
                    "description": "Peer: SFMIX (AS12276) Infrastructure:pve01",
                    "linkStatus": "connected",
                    "lineProtocolStatus": "up",
                    "bandwidth": 1000000000,
                    "interfaceType": "1000BASE-T",
                    "autoNegotiate": false
                }
            }
        }"#;
        let s: EosInterfaceStatuses = serde_json::from_str(raw).unwrap();
        let iface = s.interface_statuses.get("Ethernet43").unwrap();
        assert_eq!(iface.link_status, "connected");
        assert_eq!(iface.bandwidth, Some(1_000_000_000));
    }
}
