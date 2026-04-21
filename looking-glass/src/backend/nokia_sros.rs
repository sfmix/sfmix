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
        let cmd = format!("info json /state {state_path} | no-more");
        let raw = ssh_exec(&self.config, &cmd).await?;
        let clean = extract_sros_json(&raw);
        serde_json::from_str(&clean)
            .map_err(|e| anyhow::anyhow!("failed to parse SR-OS JSON for '/state {state_path}': {e}"))
    }

    /// Execute `info json /state <path>` and return raw Value for
    /// commands where the schema varies or is deeply nested.
    /// Note: Uses PTY mode for Nokia SR-OS compatibility.
    /// The `| no-more` pipe disables pagination.
    async fn exec_json_value(&self, state_path: &str) -> Result<Value> {
        let cmd = format!("info json /state {state_path} | no-more");
        let raw = ssh_exec(&self.config, &cmd).await?;
        let clean = extract_sros_json(&raw);
        serde_json::from_str(&clean)
            .map_err(|e| anyhow::anyhow!("failed to parse SR-OS JSON for '/state {state_path}': {e}"))
    }

    fn parse_interfaces_status(&self, val: &Value) -> Vec<InterfaceStatus> {
        let mut result = Vec::new();

        // SR-OS JSON from "info json /state router interface *" has structure:
        // { "nokia-state:interface": [ { "interface-name": "...", ... }, ... ] }
        // Note: JSON pointer can't handle colons, so use direct key access
        let iface_list = if let Some(arr) = val.get("nokia-state:interface").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(arr) = val.get("interface").and_then(|v| v.as_array()) {
            arr.clone()
        } else {
            // Try top-level array
            val.as_array().cloned().unwrap_or_default()
        };

        for iface in &iface_list {
            let name = json_str(iface, "interface-name");
            let oper_state = json_str(iface, "oper-state");
            let protocol = json_str(iface, "protocol");
            let mtu = iface.get("oper-ip-mtu")
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

    fn parse_bgp_summary(&self, val: &Value) -> BgpSummary {
        let bgp = val.pointer("/router/0/bgp")
            .or(val.pointer("/router/bgp"))
            .unwrap_or(val);

        let router_id = bgp.pointer("/oper-router-id")
            .or(val.pointer("/router/0/oper-router-id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let local_as = bgp.pointer("/oper-as")
            .or(val.pointer("/router/0/autonomous-system"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let neighbor_list = bgp.pointer("/neighbor")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut peers: Vec<BgpPeerSummary> = neighbor_list.iter().map(|n| {
            BgpPeerSummary {
                neighbor: json_str(n, "ip-address"),
                remote_as: n.get("peer-as").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                description: json_str(n, "description"),
                state: json_str(n, "session-state"),
                uptime: json_str(n, "last-established"),
                prefixes_received: n.pointer("/statistics/received-routes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                msg_received: json_u64(n.pointer("/statistics"), "received-messages"),
                msg_sent: json_u64(n.pointer("/statistics"), "sent-messages"),
            }
        }).collect();
        peers.sort_by(|a, b| a.neighbor.cmp(&b.neighbor));

        BgpSummary {
            router_id,
            local_as,
            peers,
        }
    }

    fn parse_bgp_neighbor(&self, val: &Value) -> Result<BgpNeighborDetail> {
        let bgp = val.pointer("/router/0/bgp")
            .or(val.pointer("/router/bgp"))
            .unwrap_or(val);

        let n = bgp.pointer("/neighbor")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .or(bgp.pointer("/neighbor").filter(|v| v.is_object()))
            .ok_or_else(|| anyhow::anyhow!("no neighbor in BGP response"))?;

        Ok(BgpNeighborDetail {
            neighbor: json_str(n, "ip-address"),
            remote_as: n.get("peer-as").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            local_as: bgp.get("oper-as")
                .or(val.pointer("/router/0/autonomous-system"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            description: json_str(n, "description"),
            state: json_str(n, "session-state"),
            uptime: json_str(n, "last-established"),
            router_id: json_str(n, "peer-router-id"),
            hold_time: n.get("hold-time").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            keepalive_interval: n.get("keepalive").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            prefixes_received: n.pointer("/statistics/received-routes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            prefixes_sent: n.pointer("/statistics/sent-routes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            messages_received: json_u64(n.pointer("/statistics"), "received-messages"),
            messages_sent: json_u64(n.pointer("/statistics"), "sent-messages"),
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

    fn parse_arp_table(&self, val: &Value) -> Vec<ArpEntry> {
        let entries = val.pointer("/router/0/interface")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut result = Vec::new();
        for iface in &entries {
            let iface_name = json_str(iface, "interface-name");
            let neighbors = iface.pointer("/ipv4/neighbor")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for n in &neighbors {
                result.push(ArpEntry {
                    ip_address: json_str(n, "ipv4-address"),
                    mac_address: json_str(n, "mac-address"),
                    interface: iface_name.clone(),
                    age: json_str(n, "expiry-time"),
                });
            }
        }
        result.sort_by(|a, b| a.ip_address.cmp(&b.ip_address));
        result
    }

    fn parse_nd_table(&self, val: &Value) -> Vec<NdEntry> {
        let entries = val.pointer("/router/0/interface")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut result = Vec::new();
        for iface in &entries {
            let iface_name = json_str(iface, "interface-name");
            let neighbors = iface.pointer("/ipv6/neighbor")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for n in &neighbors {
                result.push(NdEntry {
                    ip_address: json_str(n, "ipv6-address"),
                    mac_address: json_str(n, "mac-address"),
                    interface: iface_name.clone(),
                    state: json_str(n, "state"),
                });
            }
        }
        result.sort_by(|a, b| a.ip_address.cmp(&b.ip_address));
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
        // Get port details including transceiver info
        let path = match target {
            Some(t) => format!("port {t}"),
            None => "port *".to_string(),
        };
        let val = self.exec_json_value(&path).await?;

        let port_list = if let Some(arr) = val.pointer("/port").and_then(|v| v.as_array()) {
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

            let xcvr = port.pointer("/transceiver");
            let media_type = xcvr
                .and_then(|x| x.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let temperature = xcvr
                .and_then(|x| x.get("temperature"))
                .and_then(|v| v.as_f64());
            let voltage = xcvr
                .and_then(|x| x.get("supply-voltage"))
                .and_then(|v| v.as_f64());

            // Parse per-lane data from transceiver/channel or digital-diagnostic-monitoring
            let ddm = xcvr.and_then(|x| x.get("digital-diagnostic-monitoring"));
            let lanes_arr = ddm
                .and_then(|d| d.get("lane"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            let lanes: Vec<OpticalLane> = if lanes_arr.is_empty() {
                // Single-lane: check top-level DDM
                let tx_power = ddm.and_then(|d| d.get("tx-output-power")).and_then(|v| v.as_f64());
                let rx_power = ddm.and_then(|d| d.get("rx-optical-power")).and_then(|v| v.as_f64());
                let tx_bias = ddm.and_then(|d| d.get("tx-bias-current")).and_then(|v| v.as_f64());
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

    fn parse_vxlan_vtep(&self, val: &Value) -> Vec<VxlanVtep> {
        let vteps = val.pointer("/service/vxlan-instance/vtep")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        vteps.iter().map(|v| VxlanVtep {
            vtep_address: json_str(v, "address"),
            learned_from: json_str(v, "learned-from"),
        }).collect()
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
                // Router interfaces from base router - wildcard required for list
                let val = self.exec_json_value("router interface *").await?;
                CommandOutput::InterfacesStatus(self.parse_interfaces_status(&val))
            }
            (Verb::Show, Resource::InterfaceDetail) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("interface name required"))?;
                let val = self.exec_json_value(&format!("router interface \"{target}\"")).await?;
                CommandOutput::InterfaceDetail(self.parse_interface_detail(&val)?)
            }
            (Verb::Show, Resource::BgpSummary) => {
                // BGP neighbors from base router - wildcard required for list
                let val = self.exec_json_value("router bgp neighbor *").await?;
                CommandOutput::BgpSummary(self.parse_bgp_summary(&val))
            }
            (Verb::Show, Resource::BgpNeighbor) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("neighbor address required"))?;
                let val = self.exec_json_value(&format!("router bgp neighbor \"{target}\"")).await?;
                CommandOutput::BgpNeighborDetail(self.parse_bgp_neighbor(&val)?)
            }
            (Verb::Show, Resource::MacAddressTable) => {
                // FDB from service context - wildcard required for list
                let val = self.exec_json_value("service fdb-mac *").await?;
                CommandOutput::MacAddressTable(self.parse_mac_table(&val))
            }
            (Verb::Show, Resource::ArpTable) => {
                // ARP from router interfaces - wildcard required for list
                let val = self.exec_json_value("router interface *").await?;
                CommandOutput::ArpTable(self.parse_arp_table(&val))
            }
            (Verb::Show, Resource::NdTable) => {
                // ND from router interfaces - wildcard required for list
                let val = self.exec_json_value("router interface *").await?;
                CommandOutput::NdTable(self.parse_nd_table(&val))
            }
            (Verb::Show, Resource::LldpNeighbors) => {
                // LLDP is per-port - wildcard required for list
                let val = self.exec_json_value("port *").await?;
                CommandOutput::LldpNeighbors(self.parse_lldp_neighbors(&val))
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
            (Verb::Show, Resource::VxlanVtep) => {
                let val = self.exec_json_value("service vprn * vxlan-instance *").await?;
                CommandOutput::VxlanVtep(self.parse_vxlan_vtep(&val))
            }
            (Verb::Ping, Resource::NetworkReachability) | (Verb::Traceroute, Resource::NetworkReachability) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("destination required"))?;
                // Ping/traceroute are streaming commands - output streams directly
                let cmd = match command.verb {
                    Verb::Ping => format!("ping {target}"),
                    Verb::Traceroute => format!("traceroute {target}"),
                    _ => unreachable!(),
                };
                let rx = ssh_exec_stream(&self.config, &cmd).await?;
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
