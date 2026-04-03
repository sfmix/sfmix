use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::command::{AddressFamily, Command, CommandResult, Resource, Verb};
use crate::config::{DeviceConfig, Platform};
use crate::structured::*;

use super::driver::DeviceDriver;
use super::ssh::{ssh_exec, ssh_exec_stream};

/// Nokia SR-OS MD-CLI device driver.
///
/// Connects to SR-OS devices via SSH and uses `| as-json` suffix to get
/// structured JSON output, which is parsed into platform-independent types.
pub struct NokiaSrosDriver {
    config: DeviceConfig,
}

impl NokiaSrosDriver {
    pub fn new(config: DeviceConfig) -> Self {
        Self { config }
    }

    /// Execute a MD-CLI command with `| as-json` and parse the JSON response.
    #[allow(dead_code)]
    async fn exec_json<T: for<'de> Deserialize<'de>>(&self, cli: &str) -> Result<T> {
        let cmd = format!("environment no more\n{cli} | as-json");
        let raw = ssh_exec(&self.config, &cmd).await?;
        let clean = extract_sros_json(&raw);
        serde_json::from_str(&clean)
            .map_err(|e| anyhow::anyhow!("failed to parse SR-OS JSON for '{cli}': {e}"))
    }

    /// Execute a MD-CLI command with `| as-json` and return raw Value for
    /// commands where the schema varies or is deeply nested.
    async fn exec_json_value(&self, cli: &str) -> Result<Value> {
        let cmd = format!("environment no more\n{cli} | as-json");
        let raw = ssh_exec(&self.config, &cmd).await?;
        let clean = extract_sros_json(&raw);
        serde_json::from_str(&clean)
            .map_err(|e| anyhow::anyhow!("failed to parse SR-OS JSON for '{cli}': {e}"))
    }

    fn parse_interfaces_status(&self, val: &Value) -> Vec<InterfaceStatus> {
        let mut result = Vec::new();

        // SR-OS JSON from "show port" wraps data in various ways
        // Try to navigate to the port list
        let port_list = if let Some(arr) = val.pointer("/port").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(obj) = val.pointer("/port").and_then(|v| v.as_object()) {
            vec![Value::Object(obj.clone())]
        } else {
            // Try top-level array
            val.as_array().cloned().unwrap_or_default()
        };

        for port in &port_list {
            let name = json_str(port, "port-id");
            let description = json_str(port, "description");
            let oper_state = json_str(port, "oper-state");
            let admin_state = json_str(port, "admin-state");
            let speed = json_str(port, "oper-speed");
            let iface_type = port.pointer("/ethernet")
                .and_then(|e| e.get("oper-speed"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            result.push(InterfaceStatus {
                name,
                description,
                link_status: oper_state,
                protocol_status: admin_state,
                speed,
                interface_type: iface_type,
                vlan: String::new(),
                auto_negotiate: port.pointer("/ethernet/autonegotiate")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
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
        let cmd = match target {
            Some(t) => format!("show port {t}"),
            None => "show port".to_string(),
        };
        let val = self.exec_json_value(&cmd).await?;

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
                let val = self.exec_json_value("show port").await?;
                CommandOutput::InterfacesStatus(self.parse_interfaces_status(&val))
            }
            (Verb::Show, Resource::InterfaceDetail) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("port name required"))?;
                let val = self.exec_json_value(&format!("show port {target} detail")).await?;
                CommandOutput::InterfaceDetail(self.parse_interface_detail(&val)?)
            }
            (Verb::Show, Resource::BgpSummary) => {
                let cmd = match command.address_family {
                    AddressFamily::IPv4 => "show router bgp summary",
                    AddressFamily::IPv6 => "show router bgp summary family ipv6",
                };
                let val = self.exec_json_value(cmd).await?;
                CommandOutput::BgpSummary(self.parse_bgp_summary(&val))
            }
            (Verb::Show, Resource::BgpNeighbor) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("neighbor address required"))?;
                let val = self.exec_json_value(&format!("show router bgp neighbor {target}")).await?;
                CommandOutput::BgpNeighborDetail(self.parse_bgp_neighbor(&val)?)
            }
            (Verb::Show, Resource::MacAddressTable) => {
                let val = self.exec_json_value("show service fdb-mac").await?;
                CommandOutput::MacAddressTable(self.parse_mac_table(&val))
            }
            (Verb::Show, Resource::ArpTable) => {
                let cmd = match &command.target {
                    Some(intf) => format!("show router interface {intf} arp"),
                    None => "show router arp".to_string(),
                };
                let val = self.exec_json_value(&cmd).await?;
                CommandOutput::ArpTable(self.parse_arp_table(&val))
            }
            (Verb::Show, Resource::NdTable) => {
                let cmd = match &command.target {
                    Some(intf) => format!("show router interface {intf} ipv6 neighbor"),
                    None => "show router neighbor".to_string(),
                };
                let val = self.exec_json_value(&cmd).await?;
                CommandOutput::NdTable(self.parse_nd_table(&val))
            }
            (Verb::Show, Resource::LldpNeighbors) => {
                let val = self.exec_json_value("show system lldp neighbor").await?;
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
                let val = self.exec_json_value("show service id 1 vxlan-instance all").await?;
                CommandOutput::VxlanVtep(self.parse_vxlan_vtep(&val))
            }
            (Verb::Ping, Resource::NetworkReachability) | (Verb::Traceroute, Resource::NetworkReachability) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("destination required"))?;
                let cmd = match command.verb {
                    Verb::Ping => format!("ping {target}"),
                    Verb::Traceroute => format!("traceroute {target}"),
                    _ => unreachable!(),
                };
                // Ping/traceroute are streaming, no | as-json
                let full_cmd = format!("environment no more\n{cmd}");
                let rx = ssh_exec_stream(&self.config, &full_cmd).await?;
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

/// Extract JSON from SR-OS SSH output.
/// SR-OS MD-CLI `| as-json` may include leading/trailing text around the JSON.
fn extract_sros_json(raw: &str) -> String {
    let trimmed = raw.trim();
    // Find the first `{` or `[` and the last `}` or `]`
    let start = trimmed.find(|c| c == '{' || c == '[');
    let end = trimmed.rfind(|c| c == '}' || c == ']');
    match (start, end) {
        (Some(s), Some(e)) if s <= e => trimmed[s..=e].to_string(),
        _ => trimmed.to_string(),
    }
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
