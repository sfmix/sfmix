use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::command::{Command, Resource};
use crate::config::{DeviceConfig, Platform};
use super::arista_eos::AristaEosDriver;
use super::nokia_sros::NokiaSrosDriver;
use super::driver::DeviceDriver;

/// Manages a pool of device configurations and dispatches commands.
///
/// Each device has a concurrency semaphore that limits how many commands
/// can be in flight to that device simultaneously, preventing the looking
/// glass from overwhelming a network device's SSH/CLI capacity.
pub struct DevicePool {
    devices: HashMap<String, DeviceConfig>,
    /// Per-device concurrency semaphores
    device_semaphores: HashMap<String, Arc<Semaphore>>,
}

impl DevicePool {
    pub fn new(devices: Vec<DeviceConfig>, per_device_concurrent: u32) -> Self {
        let map: HashMap<String, DeviceConfig> = devices
            .into_iter()
            .map(|d| (d.name.clone(), d))
            .collect();
        let semaphores: HashMap<String, Arc<Semaphore>> = map
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    Arc::new(Semaphore::new(per_device_concurrent as usize)),
                )
            })
            .collect();
        Self {
            devices: map,
            device_semaphores: semaphores,
        }
    }

    /// Execute a command, dispatching to one or all devices.
    ///
    /// When `command.device` is `Some`, targets that specific device.
    /// When `None`, fans out to **all** configured devices concurrently
    /// and returns combined output with per-device headers.
    ///
    /// Acquires per-device concurrency permits before executing, ensuring
    /// no single device is overwhelmed by concurrent SSH sessions.
    pub async fn execute(&self, command: &Command) -> Result<String> {
        // Commands that don't need a device
        if matches!(command.resource, Resource::Help | Resource::Participants) {
            return Err(anyhow!("command should be handled locally, not dispatched to device"));
        }

        if let Some(ref name) = command.device {
            // Targeted single-device execution
            let config = self.devices.get(name)
                .ok_or_else(|| anyhow!("unknown device: {name}"))?;
            return self.execute_on_device(config, command).await;
        }

        // Fan out to all devices concurrently
        let mut device_names: Vec<&String> = self.devices.keys().collect();
        device_names.sort();

        if device_names.is_empty() {
            return Err(anyhow!("no devices configured"));
        }

        // Single device — no header needed
        if device_names.len() == 1 {
            let config = &self.devices[device_names[0]];
            return self.execute_on_device(config, command).await;
        }

        // Multiple devices — spawn concurrent tasks, collect in order
        let mut handles = Vec::with_capacity(device_names.len());
        for name in &device_names {
            let config = self.devices[*name].clone();
            let semaphore = self.device_semaphores[*name].clone();
            let cmd = command.clone();
            let platform = config.platform;
            handles.push(tokio::spawn(async move {
                let _permit = semaphore.acquire_owned().await
                    .map_err(|_| anyhow!("device concurrency semaphore closed"))?;
                let driver: Box<dyn super::driver::DeviceDriver> = match platform {
                    Platform::AristaEos => Box::new(AristaEosDriver::new(config)),
                    Platform::NokiaSros => Box::new(NokiaSrosDriver::new(config)),
                };
                driver.execute(&cmd).await
            }));
        }

        let mut output = String::new();
        for (i, handle) in handles.into_iter().enumerate() {
            let name = device_names[i];
            output.push_str(&format!("--- {} ---\n", name));
            match handle.await {
                Ok(Ok(result)) => {
                    output.push_str(&result.output);
                    if !result.output.ends_with('\n') {
                        output.push('\n');
                    }
                }
                Ok(Err(e)) => {
                    warn!(device = %name, error = %e, "device command failed");
                    output.push_str(&format!("Error: {e}\n"));
                }
                Err(e) => {
                    output.push_str(&format!("Error: {e}\n"));
                }
            }
            if i < device_names.len() - 1 {
                output.push('\n');
            }
        }

        Ok(output)
    }

    /// Execute a command on a single specific device.
    async fn execute_on_device(&self, config: &DeviceConfig, command: &Command) -> Result<String> {
        let semaphore = self.device_semaphores
            .get(&config.name)
            .ok_or_else(|| anyhow!("no semaphore for device: {}", config.name))?;

        let _permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("device concurrency semaphore closed"))?;

        debug!(
            device = config.name,
            available_permits = semaphore.available_permits(),
            "dispatching command to device"
        );

        let driver = self.create_driver(config);
        match driver.execute(command).await {
            Ok(result) => {
                if result.success {
                    Ok(result.output)
                } else {
                    Ok(format!("[{}] {}", result.device, result.output))
                }
            }
            Err(e) => {
                warn!(device = config.name, error = %e, "device command failed");
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
