use anyhow::Result;
use async_trait::async_trait;

use crate::command::{AddressFamily, Command, CommandResult, Resource, Verb};
use crate::config::{DeviceConfig, Platform};

use super::driver::DeviceDriver;
use super::ssh::ssh_exec;

/// Arista EOS device driver.
///
/// Connects to EOS devices via SSH and translates structured commands
/// into EOS CLI syntax. Uses `exec` channel with a shell command that
/// disables pagination before running the query.
pub struct AristaEosDriver {
    config: DeviceConfig,
}

impl AristaEosDriver {
    pub fn new(config: DeviceConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl DeviceDriver for AristaEosDriver {
    fn platform(&self) -> Platform {
        Platform::AristaEos
    }

    fn translate(&self, command: &Command) -> Result<String> {
        let cli = match (&command.verb, &command.resource) {
            (Verb::Show, Resource::InterfacesStatus) => "show interfaces status".to_string(),
            (Verb::Show, Resource::InterfaceDetail) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("interface name required"))?;
                format!("show interfaces {target}")
            }
            (Verb::Show, Resource::BgpSummary) => match command.address_family {
                AddressFamily::IPv4 => "show ip bgp summary".to_string(),
                AddressFamily::IPv6 => "show bgp ipv6 unicast summary".to_string(),
            },
            (Verb::Show, Resource::BgpNeighbor) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("neighbor address required"))?;
                format!("show ip bgp neighbor {target}")
            }
            (Verb::Show, Resource::MacAddressTable) => match &command.target {
                Some(intf) => format!("show mac address-table interface {intf}"),
                None => "show mac address-table".to_string(),
            },
            (Verb::Show, Resource::ArpTable) => match &command.target {
                Some(intf) => format!("show arp interface {intf}"),
                None => "show arp".to_string(),
            },
            (Verb::Show, Resource::NdTable) => match &command.target {
                Some(intf) => format!("show ipv6 neighbors interface {intf}"),
                None => "show ipv6 neighbors".to_string(),
            },
            (Verb::Show, Resource::LldpNeighbors) => "show lldp neighbors".to_string(),
            (Verb::Show, Resource::Optics) => "show interfaces transceiver".to_string(),
            (Verb::Show, Resource::OpticsDetail) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("interface name required"))?;
                format!("show interfaces {target} transceiver")
            }
            (Verb::Show, Resource::VxlanVtep) => "show vxlan vtep".to_string(),
            (Verb::Ping, Resource::NetworkReachability) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("destination required"))?;
                format!("ping {target}")
            }
            (Verb::Traceroute, Resource::NetworkReachability) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("destination required"))?;
                format!("traceroute {target}")
            }
            _ => anyhow::bail!("unsupported command for Arista EOS"),
        };
        Ok(cli)
    }

    async fn execute(&self, command: &Command) -> Result<CommandResult> {
        let cli = self.translate(command)?;

        // EOS SSH exec channel lands directly in EOS CLI.
        // Pagination is not active in non-interactive exec mode.
        let full_cmd = cli;

        match ssh_exec(&self.config, &full_cmd).await {
            Ok(output) => Ok(CommandResult {
                device: self.config.name.clone(),
                output,
                success: true,
            }),
            Err(e) => Ok(CommandResult {
                device: self.config.name.clone(),
                output: format!("SSH error: {e}"),
                success: false,
            }),
        }
    }

    async fn is_alive(&self) -> bool {
        false
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}
