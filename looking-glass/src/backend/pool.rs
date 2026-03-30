use std::collections::HashMap;

use anyhow::{Result, anyhow};
use tracing::{debug, warn};

use crate::command::{Command, Resource};
use crate::config::{DeviceConfig, Platform};
use super::arista_eos::AristaEosDriver;
use super::nokia_sros::NokiaSrosDriver;
use super::driver::DeviceDriver;

/// Manages a pool of device configurations and dispatches commands.
///
/// For Phase 1, connections are established on-demand per command.
/// A future version will maintain persistent SSH sessions.
pub struct DevicePool {
    devices: HashMap<String, DeviceConfig>,
}

impl DevicePool {
    pub fn new(devices: Vec<DeviceConfig>) -> Self {
        let map: HashMap<String, DeviceConfig> = devices
            .into_iter()
            .map(|d| (d.name.clone(), d))
            .collect();
        Self { devices: map }
    }

    pub fn empty() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }

    /// Execute a command, dispatching to the appropriate device(s).
    ///
    /// If the command specifies a device, query only that device.
    /// Otherwise, pick the first available device (for commands like
    /// "show interfaces status" that apply to any switch).
    pub async fn execute(&self, command: &Command) -> Result<String> {
        // Commands that don't need a device
        if matches!(command.resource, Resource::Help | Resource::Participants) {
            return Err(anyhow!("command should be handled locally, not dispatched to device"));
        }

        // Find target device
        let device_config = if let Some(ref name) = command.device {
            self.devices.get(name)
                .ok_or_else(|| anyhow!("unknown device: {name}"))?
        } else {
            // Pick first device (in a real deployment, could round-robin or fan out)
            self.devices.values().next()
                .ok_or_else(|| anyhow!("no devices configured"))?
        };

        debug!(device = device_config.name, "dispatching command to device");

        let driver = self.create_driver(device_config);
        match driver.execute(command).await {
            Ok(result) => {
                if result.success {
                    Ok(result.output)
                } else {
                    Ok(format!("[{}] {}", result.device, result.output))
                }
            }
            Err(e) => {
                warn!(device = device_config.name, error = %e, "device command failed");
                Err(e)
            }
        }
    }

    /// List configured device names.
    pub fn device_names(&self) -> Vec<&str> {
        self.devices.keys().map(|s| s.as_str()).collect()
    }

    fn create_driver(&self, config: &DeviceConfig) -> Box<dyn DeviceDriver> {
        match config.platform {
            Platform::AristaEos => Box::new(AristaEosDriver::new(config.clone())),
            Platform::NokiaSros => Box::new(NokiaSrosDriver::new(config.clone())),
        }
    }
}
