use anyhow::Result;
use async_trait::async_trait;

use crate::command::{AddressFamily, Command, CommandResult, Resource, Verb};
use crate::config::{DeviceConfig, Platform};

use super::driver::DeviceDriver;
use super::ssh::ssh_exec;

/// Nokia SR-OS device driver.
///
/// Connects to SR-OS devices via SSH and translates structured commands
/// into SR-OS classic CLI syntax.
pub struct NokiaSrosDriver {
    config: DeviceConfig,
}

impl NokiaSrosDriver {
    pub fn new(config: DeviceConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl DeviceDriver for NokiaSrosDriver {
    fn platform(&self) -> Platform {
        Platform::NokiaSros
    }

    fn translate(&self, command: &Command) -> Result<String> {
        let cli = match (&command.verb, &command.resource) {
            (Verb::Show, Resource::InterfacesStatus) => "show port".to_string(),
            (Verb::Show, Resource::InterfaceDetail) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("port name required"))?;
                format!("show port {target} detail")
            }
            (Verb::Show, Resource::BgpSummary) => match command.address_family {
                AddressFamily::IPv4 => "show router bgp summary".to_string(),
                AddressFamily::IPv6 => "show router bgp summary family ipv6".to_string(),
            },
            (Verb::Show, Resource::BgpNeighbor) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("neighbor address required"))?;
                format!("show router bgp neighbor {target}")
            }
            (Verb::Show, Resource::MacAddressTable) => "show service fdb-mac".to_string(),
            (Verb::Show, Resource::ArpTable) => "show router arp".to_string(),
            (Verb::Show, Resource::NdTable) => "show router neighbor".to_string(),
            (Verb::Show, Resource::LldpNeighbors) => "show system lldp neighbor".to_string(),
            (Verb::Show, Resource::Optics) => "show port detail".to_string(),
            (Verb::Show, Resource::OpticsDetail) => {
                let target = command
                    .target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("port name required"))?;
                format!("show port {target} optical")
            }
            (Verb::Show, Resource::VxlanVtep) => {
                "show service id 1 vxlan-instance all".to_string()
            }
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
            _ => anyhow::bail!("unsupported command for Nokia SR-OS"),
        };
        Ok(cli)
    }

    async fn execute(&self, command: &Command) -> Result<CommandResult> {
        let cli = self.translate(command)?;

        // SR-OS: "environment no more" disables pagination.
        // Chain with the actual command via newline in exec channel.
        let full_cmd = format!("environment no more\n{cli}");

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
