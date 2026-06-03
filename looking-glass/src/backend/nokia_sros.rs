use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::command::{Command, CommandResult, Resource, Verb};
use crate::config::{DeviceConfig, Platform};
use crate::structured::*;

use super::driver::DeviceDriver;
use super::ssh::{ssh_exec, ssh_exec_stream};

/// Nokia SR-OS MD-CLI device driver.
///
/// Connects to SR-OS devices via SSH and uses `info json /state <path>` to get
/// structured JSON output, which is parsed into platform-independent types.
pub struct NokiaSrosDriver {
    config: DeviceConfig,
}

impl NokiaSrosDriver {
    pub fn new(config: DeviceConfig) -> Self {
        Self { config }
    }

    /// Execute `info json /state <path>` and parse the JSON response.
    /// The `| no-more` pipe disables pagination.
    #[allow(dead_code)]
    async fn exec_json<T: for<'de> Deserialize<'de>>(&self, state_path: &str) -> Result<T> {
        let cli_command = format!("info json /state {state_path} | no-more");
        let raw = ssh_exec(&self.config, &cli_command).await?;
        let clean = extract_sros_json(&raw);
        serde_json::from_str(&clean)
            .map_err(|e| anyhow::anyhow!("failed to parse SR-OS JSON for '/state {state_path}': {e}"))
    }

    /// Execute `info json /state <path>` and return raw Value for
    /// commands where the schema varies or is deeply nested.
    /// Note: Uses PTY mode for Nokia SR-OS compatibility.
    /// The `| no-more` pipe disables pagination.
    async fn exec_json_value(&self, state_path: &str) -> Result<Value> {
        let cli_command = format!("info json /state {state_path} | no-more");
        let raw = ssh_exec(&self.config, &cli_command).await?;
        let clean = extract_sros_json(&raw);
        serde_json::from_str(&clean)
            .map_err(|e| anyhow::anyhow!("failed to parse SR-OS JSON for '/state {state_path}': {e}"))
    }

    fn parse_interfaces_status(&self, val: &Value) -> Vec<InterfaceStatus> {
        let mut result = Vec::new();

        // SR-OS JSON from "info json /state router interface *" has structure:
        // { "nokia-state:interface": [ { "interface-name": "...", ... }, ... ] }
        // Note: JSON pointer can't handle colons, so use direct key access
        let interface_list = if let Some(arr) = val.get("nokia-state:interface").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(arr) = val.get("interface").and_then(|v| v.as_array()) {
            arr.clone()
        } else {
            // Try top-level array
            val.as_array().cloned().unwrap_or_default()
        };

        for interface_entry in &interface_list {
            let name = json_str(interface_entry, "interface-name");
            let oper_state = json_str(interface_entry, "oper-state");
            let protocol = json_str(interface_entry, "protocol");
            let mtu = interface_entry.get("oper-ip-mtu")
                .and_then(|v| v.as_u64())
                .map(|m| m.to_string())
                .unwrap_or_default();

            result.push(InterfaceStatus {
                name,
                description: String::new(), // description is config-only in SR-OS
                link_status: oper_state,
                protocol_status: protocol,
                speed: mtu, // Using MTU as "speed" field for router interfaces
                interface_type: String::from("router-interface"),
                vlan: String::new(),
                auto_negotiate: false,
                member_interfaces: vec![],
                port_channel: None,
            });
        }
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result
    }

    /// Parse physical port status from `info json /state port *` output.
    fn parse_ports_status(&self, val: &Value) -> Vec<InterfaceStatus> {
        let port_list = if let Some(arr) = val.get("nokia-state:port").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(arr) = val.pointer("/port").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(obj) = val.pointer("/port").and_then(|v| v.as_object()) {
            vec![Value::Object(obj.clone())]
        } else {
            Vec::new()
        };

        let mut result = Vec::new();
        for port in &port_list {
            let name = json_str(port, "port-id");
            if name.is_empty() {
                continue;
            }
            let description = json_str(port, "description");
            let link_status = json_str(port, "oper-state");
            let protocol_status = json_str(port, "admin-state");
            let speed = port.pointer("/ethernet/oper-speed")
                .and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_u64().map(|n| n.to_string())))
                .unwrap_or_default();
            let port_channel = port.get("lag-id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string);

            result.push(InterfaceStatus {
                name,
                description,
                link_status,
                protocol_status,
                speed,
                interface_type: "physical-port".to_string(),
                vlan: String::new(),
                auto_negotiate: false,
                member_interfaces: vec![],
                port_channel,
            });
        }
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result
    }

    /// Parse VPRN service interface status from `info json /state service vprn * interface *`.
    fn parse_vprn_interfaces_status(&self, val: &Value) -> Vec<InterfaceStatus> {
        let vprn_list = if let Some(arr) = val.get("nokia-state:vprn").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(arr) = val.pointer("/vprn").and_then(|v| v.as_array()) {
            arr.clone()
        } else {
            Vec::new()
        };

        let mut result = Vec::new();
        for vprn in &vprn_list {
            let service_name = json_str(vprn, "service-name");
            let interface_type = if service_name.is_empty() {
                "vprn-interface".to_string()
            } else {
                format!("vprn:{service_name}")
            };

            let interface_list = vprn.get("interface")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            for iface in &interface_list {
                let name = json_str(iface, "interface-name");
                if name.is_empty() {
                    continue;
                }
                let mtu = iface.get("oper-ip-mtu")
                    .and_then(|v| v.as_u64())
                    .map(|m| m.to_string())
                    .unwrap_or_default();
                result.push(InterfaceStatus {
                    name,
                    description: String::new(),
                    link_status: json_str(iface, "oper-state"),
                    protocol_status: json_str(iface, "protocol"),
                    speed: mtu,
                    interface_type: interface_type.clone(),
                    vlan: String::new(),
                    auto_negotiate: false,
                    member_interfaces: vec![],
                    port_channel: None,
                });
            }
        }
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result
    }

    fn parse_interface_detail(&self, val: &Value) -> Result<InterfaceDetail> {
        let port = val.pointer("/port")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .or(val.pointer("/port").filter(|v| v.is_object()))
            .ok_or_else(|| anyhow::anyhow!("no port in response"))?;

        let counters = port.pointer("/statistics/ethernet")
            .or(port.pointer("/statistics"));

        Ok(InterfaceDetail {
            name: json_str(port, "port-id"),
            description: json_str(port, "description"),
            link_status: json_str(port, "oper-state"),
            protocol_status: json_str(port, "admin-state"),
            hardware_type: port.pointer("/ethernet/oper-speed")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            mac_address: json_str(port, "hardware-mac-address"),
            mtu: port.get("oper-mtu")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            speed: json_str(port, "oper-speed"),
            bandwidth: json_str(port, "oper-speed"),
            counters: InterfaceCounters {
                in_octets: json_u64(counters, "in-octets"),
                in_unicast_packets: json_u64(counters, "in-unicast-packets"),
                in_multicast_packets: json_u64(counters, "in-multicast-packets"),
                in_broadcast_packets: json_u64(counters, "in-broadcast-packets"),
                in_discards: json_u64(counters, "in-discards"),
                in_errors: json_u64(counters, "in-errors"),
                out_octets: json_u64(counters, "out-octets"),
                out_unicast_packets: json_u64(counters, "out-unicast-packets"),
                out_multicast_packets: json_u64(counters, "out-multicast-packets"),
                out_broadcast_packets: json_u64(counters, "out-broadcast-packets"),
                out_discards: json_u64(counters, "out-discards"),
                out_errors: json_u64(counters, "out-errors"),
            },
            member_interfaces: vec![],
        })
    }

    fn parse_mac_table(&self, val: &Value) -> Vec<MacEntry> {
        let entries = val.pointer("/fdb/mac")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut result: Vec<MacEntry> = entries.iter().map(|e| MacEntry {
            vlan: json_str(e, "service-id"),
            mac_address: json_str(e, "address"),
            entry_type: json_str(e, "type"),
            interface: json_str(e, "sap"),
        }).collect();
        result.sort_by(|a, b| a.mac_address.cmp(&b.mac_address));
        result
    }

    fn parse_lldp_neighbors(&self, val: &Value) -> Vec<LldpNeighbor> {
        let neighbors = val.pointer("/system/lldp/remote-system")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut result: Vec<LldpNeighbor> = neighbors.iter().map(|n| LldpNeighbor {
            local_interface: json_str(n, "local-port"),
            neighbor_device: json_str(n, "system-name"),
            neighbor_port: json_str(n, "remote-port-description"),
            ttl: n.get("remaining-life-time")
                .and_then(|v| v.as_u64())
                .map(|t| t.to_string())
                .unwrap_or_default(),
        }).collect();
        result.sort_by(|a, b| a.local_interface.cmp(&b.local_interface));
        result
    }

    async fn fetch_optics(&self, target: Option<&str>) -> Result<Vec<InterfaceOptics>> {
        // Use the transceiver subtree: connector ports (1/1/c1) have DOM data,
        // lane ports (1/1/c1/1) returned by bare `port *` have no transceiver info.
        let path = match target {
            Some(t) => format!("port {t} transceiver"),
            None => "port * transceiver".to_string(),
        };
        let val = self.exec_json_value(&path).await?;

        let port_list = if let Some(arr) = val.get("nokia-state:port").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(arr) = val.pointer("/port").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(obj) = val.pointer("/port").and_then(|v| v.as_object()) {
            vec![Value::Object(obj.clone())]
        } else {
            Vec::new()
        };

        let mut result = Vec::new();
        for port in &port_list {
            let name = json_str(port, "port-id");
            let description = json_str(port, "description");
            let link_status = json_str(port, "oper-state");

            let transceiver = port.pointer("/transceiver");

            // Skip ports with no equipped transceiver
            let equipped = transceiver
                .and_then(|t| t.get("equipped"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !equipped {
                continue;
            }

            let media_type = transceiver
                .and_then(|x| x.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let temperature = transceiver
                .and_then(|x| x.get("temperature"))
                .and_then(|v| v.as_f64());
            let voltage = transceiver
                .and_then(|x| x.get("supply-voltage"))
                .and_then(|v| v.as_f64());

            // Parse per-lane data from transceiver/channel or digital-diagnostic-monitoring
            let diagnostic_monitoring = transceiver.and_then(|x| x.get("digital-diagnostic-monitoring"));
            let lanes_arr = diagnostic_monitoring
                .and_then(|d| d.get("lane"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            let lanes: Vec<OpticalLane> = if lanes_arr.is_empty() {
                // Single-lane: check top-level diagnostic monitoring
                let tx_power = diagnostic_monitoring.and_then(|d| d.get("tx-output-power")).and_then(|v| v.as_f64());
                let rx_power = diagnostic_monitoring.and_then(|d| d.get("rx-optical-power")).and_then(|v| v.as_f64());
                let tx_bias = diagnostic_monitoring.and_then(|d| d.get("tx-bias-current")).and_then(|v| v.as_f64());
                if tx_power.is_some() || rx_power.is_some() || tx_bias.is_some() {
                    vec![OpticalLane {
                        lane: 1,
                        tx_power_dbm: tx_power,
                        rx_power_dbm: rx_power,
                        tx_bias_ma: tx_bias,
                    }]
                } else {
                    vec![]
                }
            } else {
                lanes_arr.iter().enumerate().map(|(i, l)| {
                    OpticalLane {
                        lane: l.get("lane-id")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(i as u64 + 1) as u8,
                        tx_power_dbm: l.get("tx-output-power").and_then(|v| v.as_f64()),
                        rx_power_dbm: l.get("rx-optical-power").and_then(|v| v.as_f64()),
                        tx_bias_ma: l.get("tx-bias-current").and_then(|v| v.as_f64()),
                    }
                }).collect()
            };

            let dom_supported = !lanes.is_empty()
                && lanes.iter().any(|l| {
                    l.tx_power_dbm.is_some()
                        || l.rx_power_dbm.is_some()
                        || l.tx_bias_ma.is_some()
                });

            result.push(InterfaceOptics {
                name,
                description,
                link_status,
                media_type,
                temperature_c: temperature,
                voltage_v: voltage,
                lanes,
                dom_supported,
                port_channel: None, // Nokia SR-OS LAG membership not yet implemented
            });
        }

        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    /// Parse ARP or IPv6 neighbor entries from VPRN neighbor-discovery JSON.
    ///
    /// `ipv6`: if true, parse `ipv6.neighbor-discovery.neighbor[]`; otherwise
    ///         parse `ipv4.neighbor-discovery.neighbor[]`.
    fn parse_vprn_arp(&self, val: &Value, ipv6: bool) -> Vec<ArpEntry> {
        let vprn_list = if let Some(arr) = val.get("nokia-state:vprn").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(arr) = val.pointer("/vprn").and_then(|v| v.as_array()) {
            arr.clone()
        } else {
            Vec::new()
        };

        let mut result = Vec::new();
        for vprn in &vprn_list {
            let service_name = json_str(vprn, "service-name");
            let interface_list = vprn.get("interface")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            for iface in &interface_list {
                let interface_name = json_str(iface, "interface-name");
                if interface_name.is_empty() {
                    continue;
                }

                let neighbor_arr = if ipv6 {
                    iface.pointer("/ipv6/neighbor-discovery/neighbor")
                } else {
                    iface.pointer("/ipv4/neighbor-discovery/neighbor")
                };

                let neighbors = neighbor_arr
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                for neighbor in &neighbors {
                    let ip_address = if ipv6 {
                        json_str(neighbor, "ipv6-address")
                    } else {
                        json_str(neighbor, "ipv4-address")
                    };
                    if ip_address.is_empty() {
                        continue;
                    }
                    let mac_address = json_str(neighbor, "mac-address");
                    let entry_type = json_str(neighbor, "type");
                    let age_secs = neighbor.get("timer")
                        .and_then(|v| v.as_u64());

                    result.push(ArpEntry {
                        ip_address,
                        mac_address,
                        interface: interface_name.clone(),
                        vrf: if service_name.is_empty() { None } else { Some(service_name.clone()) },
                        entry_type,
                        age_secs,
                    });
                }
            }
        }
        result.sort_by(|a, b| a.ip_address.cmp(&b.ip_address));
        result
    }

    /// Fetch transceiver hardware inventory (model/serial number).
    ///
    /// Uses `info json /state port * transceiver` which returns connector-level
    /// ports (1/1/c1) with transceiver data. `port *` alone returns lane-level
    /// ports (1/1/c1/1) which have no transceiver subtree.
    async fn fetch_optics_inventory(&self) -> Result<Vec<OpticsInventoryEntry>> {
        let val = self.exec_json_value("port * transceiver").await?;

        // JSON wrapper may be "nokia-state:port" or "port" depending on context
        let port_list = if let Some(arr) = val.get("nokia-state:port").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(arr) = val.pointer("/port").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(obj) = val.pointer("/port").and_then(|v| v.as_object()) {
            vec![Value::Object(obj.clone())]
        } else {
            Vec::new()
        };

        let mut result = Vec::new();
        for port in &port_list {
            let name = json_str(port, "port-id");
            let transceiver = port.get("transceiver");

            // Skip unequipped ports
            let equipped = transceiver
                .and_then(|t| t.get("equipped"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !equipped {
                continue;
            }

            let model = transceiver
                .and_then(|t| t.get("vendor-part-number"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let serial_number = transceiver
                .and_then(|t| t.get("vendor-serial-number"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let media_type = transceiver
                .and_then(|t| t.get("optical-compliance-extension"))
                .and_then(|v| v.as_u64())
                .map(sff8024_media_type)
                .filter(|s| !s.is_empty())
                .unwrap_or("")
                .to_string();

            let vendor = transceiver
                .and_then(|t| t.get("vendor-name"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            result.push(OpticsInventoryEntry {
                name,
                media_type,
                vendor,
                model,
                serial_number,
            });
        }

        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

}

#[async_trait]
impl DeviceDriver for NokiaSrosDriver {
    fn platform(&self) -> Platform {
        Platform::NokiaSros
    }

    async fn execute(&self, command: &Command) -> Result<CommandResult> {
        let output = match (&command.verb, &command.resource) {
            (Verb::Show, Resource::InterfacesStatus) => {
                // Base router L3 interfaces
                let val = self.exec_json_value("router interface *").await?;
                let mut interfaces = self.parse_interfaces_status(&val);

                // Physical ports (best-effort; absence is non-fatal)
                match self.exec_json_value("port *").await {
                    Ok(port_val) => interfaces.extend(self.parse_ports_status(&port_val)),
                    Err(e) => tracing::warn!(device = self.config.name, error = %e, "interfaces: port * failed"),
                }

                // VPRN service interfaces — wildcard enumerates all VPRNs dynamically
                match self.exec_json_value("service vprn * interface * oper-state").await {
                    Ok(vprn_val) => {
                        let vprn_ifaces = self.parse_vprn_interfaces_status(&vprn_val);
                        tracing::debug!(device = self.config.name, count = vprn_ifaces.len(), "Nokia VPRN interfaces");
                        interfaces.extend(vprn_ifaces);
                    }
                    Err(e) => tracing::warn!(device = self.config.name, error = %e, "interfaces: vprn query failed"),
                }

                interfaces.sort_by(|a, b| a.name.cmp(&b.name));
                CommandOutput::InterfacesStatus(interfaces)
            }
            (Verb::Show, Resource::InterfaceDetail) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("interface name required"))?;
                let val = self.exec_json_value(&format!("router interface \"{target}\"")).await?;
                CommandOutput::InterfaceDetail(self.parse_interface_detail(&val)?)
            }
            (Verb::Show, Resource::MacAddressTable) => {
                // Nokia SR-OS transit routers don't have a meaningful L2 FDB.
                // The `service fdb-mac *` YANG path is not valid on these devices.
                CommandOutput::MacAddressTable(vec![])
            }
            (Verb::Show, Resource::LldpNeighbors) => {
                // LLDP is per-port - wildcard required for list
                let val = self.exec_json_value("port *").await?;
                CommandOutput::LldpNeighbors(self.parse_lldp_neighbors(&val))
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
                    .ok_or_else(|| anyhow::anyhow!("port name required"))?;
                let optics = self.fetch_optics(Some(target)).await?;
                CommandOutput::OpticsDetail(optics)
            }
            (Verb::Show, Resource::Arp) => {
                let val = self.exec_json_value("service vprn * interface * ipv4 neighbor-discovery").await?;
                CommandOutput::Arp(self.parse_vprn_arp(&val, false))
            }
            (Verb::Show, Resource::IPv6Neighbors) => {
                let val = self.exec_json_value("service vprn * interface * ipv6 neighbor-discovery").await?;
                CommandOutput::IPv6Neighbors(self.parse_vprn_arp(&val, true))
            }
            (Verb::Ping, Resource::NetworkReachability) | (Verb::Traceroute, Resource::NetworkReachability) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("destination required"))?;
                // Ping/traceroute are streaming commands - output streams directly
                let cli_command = match command.verb {
                    Verb::Ping => format!("ping {target}"),
                    Verb::Traceroute => format!("traceroute {target}"),
                    _ => unreachable!(),
                };
                let rx = ssh_exec_stream(&self.config, &cli_command).await?;
                CommandOutput::Stream(rx)
            }
            _ => anyhow::bail!("unsupported command for Nokia SR-OS"),
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

// ── SR-OS JSON helpers ──────────────────────────────────────────────

/// Strip ANSI escape codes from a string.
fn strip_ansi(s: &str) -> String {
    // Match ANSI escape sequences: ESC [ ... (letter or ~)
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip ESC and following sequence
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                // Skip until we hit a letter or ~
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next.is_ascii_alphabetic() || next == '~' {
                        break;
                    }
                }
            }
        } else if c == '\r' {
            // Skip carriage returns
        } else {
            result.push(c);
        }
    }
    result
}

/// Extract JSON from SR-OS SSH output.
/// SR-OS MD-CLI `info json` may include leading/trailing text around the JSON.
/// With PTY mode, output includes ANSI escape codes, prompts, and command echo.
fn extract_sros_json(raw: &str) -> String {
    // First strip ANSI escape codes
    let clean = strip_ansi(raw);
    let trimmed = clean.trim();
    
    // Nokia SR-OS JSON output starts with `{` for objects or `[` for arrays,
    // but the prompt `[/]` also contains `[`. We need to find the actual JSON.
    // JSON from `info json` typically starts with `{\n    "nokia-state:` or similar.
    // Look for `{` followed by a newline and whitespace (JSON object start)
    // or `[\n` followed by content (JSON array start, but not `[/]` prompt)
    
    // First try to find a JSON object start
    if let Some(obj_start) = trimmed.find("{\n") {
        // Find the matching closing brace
        if let Some(obj_end) = trimmed.rfind('}') {
            if obj_start <= obj_end {
                return trimmed[obj_start..=obj_end].to_string();
            }
        }
    }
    
    // Try to find a JSON array that's not the [/] prompt
    // Look for `[\n    {` pattern which indicates a real JSON array
    if let Some(arr_start) = trimmed.find("[\n") {
        // Make sure it's not just `[/]` prompt
        let after_bracket = &trimmed[arr_start..];
        if after_bracket.starts_with("[\n    ") || after_bracket.starts_with("[\n{") {
            if let Some(arr_end) = trimmed.rfind(']') {
                if arr_start <= arr_end {
                    return trimmed[arr_start..=arr_end].to_string();
                }
            }
        }
    }
    
    // Fallback: look for `{` or `[` but skip `[/]` patterns
    let mut search_start = 0;
    loop {
        let start = trimmed[search_start..].find(|c| c == '{' || c == '[');
        match start {
            Some(s) => {
                let abs_pos = search_start + s;
                let ch = trimmed.chars().nth(abs_pos).unwrap();
                // Skip `[/]` and `[context]` prompts
                if ch == '[' {
                    if let Some(close) = trimmed[abs_pos..].find(']') {
                        let bracket_content = &trimmed[abs_pos + 1..abs_pos + close];
                        // If it looks like a prompt (short, contains / or letters only), skip it
                        if bracket_content.len() < 20 && !bracket_content.contains('"') {
                            search_start = abs_pos + close + 1;
                            continue;
                        }
                    }
                }
                // Found a real JSON start
                let end = trimmed.rfind(|c| c == '}' || c == ']');
                if let Some(e) = end {
                    if abs_pos <= e {
                        return trimmed[abs_pos..=e].to_string();
                    }
                }
                break;
            }
            None => break,
        }
    }
    
    tracing::warn!("No JSON found in SR-OS output, raw length: {}", raw.len());
    trimmed.to_string()
}

/// Extract a string value from a JSON object by key.
fn json_str(val: &Value, key: &str) -> String {
    val.get(key)
        .and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => v.as_str().map(|s| s.to_string()),
        })
        .unwrap_or_default()
}

/// Extract a u64 value from an optional JSON object by key.
fn json_u64(val: Option<&Value>, key: &str) -> u64 {
    val.and_then(|v| v.get(key))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

/// Decode an SFF-8024 Table 4-4 optical compliance extension code to a human-readable media type.
fn sff8024_media_type(code: u64) -> &'static str {
    match code {
        1  => "100G AOC",
        2  => "100GBASE-SR4",
        3  => "100GBASE-LR4",
        4  => "100GBASE-ER4 Lite",
        11 => "100GBASE-CWDM4",
        25 => "400GBASE-SR4",
        26 => "400GBASE-SR8",
        _  => "",
    }
}
