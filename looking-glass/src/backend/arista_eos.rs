use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;

use crate::command::{Command, CommandResult, Resource, Verb};
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

    fn parse_arp(&self, raw: EosArpTable) -> Vec<ArpEntry> {
        let mut entries: Vec<ArpEntry> = raw
            .neighbors
            .into_iter()
            .map(|e| ArpEntry {
                ip_address: e.address,
                mac_address: e.hw_address,
                interface: e.interface,
                vrf: None,
                entry_type: e.neighbor_type,
                age_secs: e.age.filter(|&a| a >= 0).map(|a| a as u64),
            })
            .collect();
        entries.sort_by(|a, b| a.ip_address.cmp(&b.ip_address));
        entries
    }

    fn parse_ipv6_neighbors(&self, raw: EosIPv6Neighbors) -> Vec<ArpEntry> {
        let mut entries: Vec<ArpEntry> = raw
            .neighbors
            .into_iter()
            .map(|e| ArpEntry {
                ip_address: e.address,
                mac_address: e.hw_address,
                interface: e.interface,
                vrf: None,
                entry_type: e.neighbor_type,
                age_secs: e.age.filter(|&a| a >= 0).map(|a| a as u64),
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

            // For breakout ports, EOS reports DOM data under the physical parent
            // (e.g. "Ethernet25") while the logical sub-interfaces ("Ethernet25/1"
            // through "Ethernet25/4") appear only in interface status.  When the
            // parent has no direct status entry but sub-interfaces exist, distribute
            // the DOM data to each sub-interface keyed by its lane number.
            let sub_pattern = format!("{}/", name);
            let mut sub_ifaces: Vec<(&String, &EosInterfaceStatusEntry)> = status_raw
                .interface_statuses
                .iter()
                .filter(|(n, _)| n.starts_with(&sub_pattern))
                .collect();
            sub_ifaces.sort_by_key(|(n, _)| *n);

            if status.is_none() && !sub_ifaces.is_empty() {
                for (sub_name, sub_status) in &sub_ifaces {
                    let lane_num: Option<u8> =
                        sub_name.rsplit('/').next().and_then(|s| s.parse().ok());
                    let sub_lanes: Vec<OpticalLane> = match lane_num {
                        Some(ln) => lanes.iter().filter(|l| l.lane == ln).cloned().collect(),
                        None => lanes.clone(),
                    };
                    let sub_dom_supported = dom_supported
                        && (!sub_lanes.is_empty()
                            || temperature_c.is_some()
                            || voltage_v.is_some());
                    result.push(InterfaceOptics {
                        name: (*sub_name).clone(),
                        description: sub_status.description.clone(),
                        link_status: sub_status.link_status.clone(),
                        media_type: media_type.clone(),
                        temperature_c,
                        voltage_v,
                        lanes: sub_lanes,
                        dom_supported: sub_dom_supported,
                        port_channel: member_to_port_channel
                            .get(sub_name.as_str())
                            .map(|s| s.to_string()),
                    });
                }
            } else {
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
        }

        // Add visible interfaces that lack transceiver data (DAC, copper, empty).
        // Skip breakout sub-interfaces whose parent already has DOM data — those
        // were handled in the loop above.
        if target.is_none() {
            let transceiver_dom_names: std::collections::HashSet<&String> =
                transceiver_dom.interfaces.keys().collect();
            for (name, status) in &status_raw.interface_statuses {
                if transceiver_dom_names.contains(name) {
                    continue;
                }
                if !name.starts_with("Ethernet") {
                    continue;
                }
                // Skip sub-interfaces whose parent has DOM data (already redistributed above)
                if let Some(slash_pos) = name.rfind('/') {
                    let parent = name[..slash_pos].to_owned();
                    if transceiver_dom_names.contains(&parent) {
                        continue;
                    }
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

    /// Fetch transceiver hardware inventory (vendor/model/serial).
    ///
    /// Uses two commands and joins by slot number:
    ///   - `show inventory | json` for vendor/model/serial (keyed by integer slot number)
    ///   - `show interfaces transceiver | json` for interface name and media type
    ///
    /// Per-lane interfaces (e.g. "Ethernet49/1"…"Ethernet49/4") each carry a `slot`
    /// field pointing at the shared physical transceiver ("Et49" or "Ethernet49"
    /// depending on EOS version). We strip all leading alphabetic chars to normalise
    /// both forms to the slot number ("49"), then look up xcvrSlots["49"]. The original
    /// interface key is kept as the inventory entry name so it matches the PortMap.
    async fn fetch_optics_inventory(&self) -> Result<Vec<OpticsInventoryEntry>> {
        let inventory: EosInventory = self.exec_json("show inventory").await?;
        let transceiver_info: EosTransceiverInfo =
            self.exec_json("show interfaces transceiver").await?;

        let mut result: Vec<OpticsInventoryEntry> = Vec::new();

        for (iface_name, xcvr) in &transceiver_info.interfaces {
            // Derive slot number from the `slot` field.
            // EOS versions differ: abbreviated "Et49" vs full "Ethernet49".
            // Stripping all leading alphabetic chars handles both: "Et49"→"49", "Ethernet13"→"13".
            // Normalise the slot field to a plain integer key for xcvrSlots lookup.
            // EOS versions differ in what they report:
            //   "Et49"       → strip alpha  → "49"
            //   "Ethernet49" → strip alpha  → "49"
            //   "Et49/1"     → strip alpha  → "49/1" → strip lane → "49"
            //   "49/1"       → no alpha     → "49/1" → strip lane → "49"
            let slot_num = match xcvr.slot.as_deref().filter(|s| !s.is_empty()) {
                Some(s) => {
                    let after_alpha = s.chars().skip_while(|c| c.is_alphabetic()).collect::<String>();
                    // Strip any trailing lane suffix (e.g. "25/1" → "25")
                    after_alpha.split('/').next().unwrap_or("").to_string()
                }
                None => continue, // empty slot field means no transceiver
            };
            if slot_num.is_empty() {
                continue;
            }

            let slot_entry = inventory.xcvr_slots.get(&slot_num);

            let vendor = slot_entry
                .and_then(|s| s.mfg_name.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != "Not Present")
                .map(|s| s.to_string());

            // Skip absent or "Not Present" slots
            if vendor.is_none()
                && slot_entry.map(|s| s.model_name.as_deref().unwrap_or("").trim().is_empty()).unwrap_or(true)
                && slot_entry.map(|s| s.serial_num.as_deref().unwrap_or("").trim().is_empty()).unwrap_or(true)
            {
                continue;
            }

            let model = slot_entry
                .and_then(|s| s.model_name.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let serial_number = slot_entry
                .and_then(|s| s.serial_num.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            result.push(OpticsInventoryEntry {
                name: iface_name.clone(),
                media_type: xcvr.media_type.clone().unwrap_or_default(),
                vendor,
                model,
                serial_number,
            });
        }

        // Second pass: propagate inventory to sub-interfaces that share a physical
        // transceiver with a sibling that already has an inventory entry.
        //
        // On some EOS versions, `show interfaces transceiver` returns breakout
        // sub-interfaces (e.g. Ethernet13/2, Ethernet13/3) with an empty slot
        // field even when the /1 sibling has slot="Et13" and full inventory.
        // Since all lanes of a breakout QSFP share one physical transceiver,
        // they all have the same vendor/model/serial.
        {
            // Build a map: base_name (e.g. "Ethernet13") → inventory entry
            let mut base_inventory: std::collections::HashMap<String, &OpticsInventoryEntry> =
                std::collections::HashMap::new();
            for entry in &result {
                if let Some(slash) = entry.name.rfind('/') {
                    let base = &entry.name[..slash];
                    base_inventory.entry(base.to_owned()).or_insert(entry);
                }
            }

            // Find sub-interfaces not yet in result that share a base with an
            // existing inventory entry.
            let result_names: std::collections::HashSet<&str> =
                result.iter().map(|e| e.name.as_str()).collect();

            let mut additions: Vec<OpticsInventoryEntry> = Vec::new();
            for iface_name in transceiver_info.interfaces.keys() {
                if result_names.contains(iface_name.as_str()) {
                    continue; // already has inventory
                }
                if let Some(slash) = iface_name.rfind('/') {
                    let base = &iface_name[..slash];
                    if let Some(sibling) = base_inventory.get(base) {
                        additions.push(OpticsInventoryEntry {
                            name: iface_name.clone(),
                            media_type: sibling.media_type.clone(),
                            vendor: sibling.vendor.clone(),
                            model: sibling.model.clone(),
                            serial_number: sibling.serial_number.clone(),
                        });
                    }
                }
            }
            result.extend(additions);
        }

        result.sort_by(|a, b| interface_sort_key(&a.name).cmp(&interface_sort_key(&b.name)));
        Ok(result)
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
            (Verb::Show, Resource::MacAddressTable) => {
                let cli_command = match &command.target {
                    Some(interface) => format!("show mac address-table interface {interface}"),
                    None => "show mac address-table".to_string(),
                };
                let raw: EosMacTable = self.exec_json(&cli_command).await?;
                CommandOutput::MacAddressTable(self.parse_mac_table(raw))
            }
            (Verb::Show, Resource::LldpNeighbors) => {
                let raw: EosLldpNeighbors =
                    self.exec_json("show lldp neighbors").await?;
                CommandOutput::LldpNeighbors(self.parse_lldp_neighbors(raw))
            }
            (Verb::Show, Resource::Arp) => {
                let raw: EosArpTable = self.exec_json("show arp").await?;
                CommandOutput::Arp(self.parse_arp(raw))
            }
            (Verb::Show, Resource::IPv6Neighbors) => {
                let raw: EosIPv6Neighbors = self.exec_json("show ipv6 neighbors").await?;
                CommandOutput::IPv6Neighbors(self.parse_ipv6_neighbors(raw))
            }
            (Verb::Show, Resource::OpticsInventory) => {
                let inventory = self.fetch_optics_inventory().await?;
                CommandOutput::OpticsInventory(inventory)
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
    neighbors: Vec<EosArpEntry>,
}

#[derive(Deserialize)]
struct EosArpEntry {
    address: String,
    #[serde(rename = "hwAddress", default)]
    hw_address: String,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    age: Option<i64>,  // -1 means permanent
    #[serde(rename = "neighborType", default)]
    neighbor_type: String,
}

// ── show ipv6 neighbors ─────────────────────────────────────────────

#[derive(Deserialize)]
struct EosIPv6Neighbors {
    #[serde(rename = "ipV6Neighbors", default)]
    neighbors: Vec<EosIPv6NeighborEntry>,
}

#[derive(Deserialize)]
struct EosIPv6NeighborEntry {
    address: String,
    #[serde(rename = "hwAddress", default)]
    hw_address: String,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    age: Option<i64>,
    #[serde(rename = "neighborType", default)]
    neighbor_type: String,
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

// ── show inventory ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct EosInventory {
    #[serde(rename = "xcvrSlots", default)]
    xcvr_slots: HashMap<String, EosXcvrSlot>,
}

#[derive(Deserialize)]
struct EosXcvrSlot {
    #[serde(rename = "mfgName", default)]
    mfg_name: Option<String>,
    #[serde(rename = "modelName", default)]
    model_name: Option<String>,
    #[serde(rename = "serialNum", default)]
    serial_num: Option<String>,
}

// ── show interfaces transceiver (without dom) ───────────────────────

#[derive(Deserialize)]
struct EosTransceiverInfo {
    #[serde(default)]
    interfaces: HashMap<String, EosTransceiverInfoEntry>,
}

#[derive(Deserialize)]
struct EosTransceiverInfoEntry {
    #[serde(default)]
    slot: Option<String>,
    #[serde(rename = "mediaType", default)]
    media_type: Option<String>,
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
