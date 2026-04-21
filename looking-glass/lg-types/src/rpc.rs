use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandResult};
use crate::identity::Identity;

/// RPC request to execute a command.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub command: Command,
    pub identity: Identity,
    /// Key used for per-user rate limiting (e.g. email or IP).
    pub rate_key: String,
}

/// A single device result emitted as an SSE `result` event.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceResultEvent {
    pub device: String,
    pub success: bool,
    pub output: crate::structured::CommandOutput,
}

impl From<CommandResult> for DeviceResultEvent {
    fn from(r: CommandResult) -> Self {
        Self {
            device: r.device,
            success: r.success,
            output: r.output,
        }
    }
}

/// A single streaming line emitted as an SSE `stream_line` event.
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamLineEvent {
    pub device: String,
    pub line: String,
}

/// Emitted as an SSE `stream_end` event when a device finishes streaming.
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamEndEvent {
    pub device: String,
}

/// Emitted as an SSE `error` event.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorEvent {
    pub code: String,
    pub message: String,
}

/// Device info returned by GET /rpc/v1/devices.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
}

/// Service info returned by GET /rpc/v1/service-info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub admin_group: String,
    pub device_count: usize,
}
