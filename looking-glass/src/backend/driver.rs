use anyhow::Result;
use async_trait::async_trait;

use crate::command::{Command, CommandResult};
use crate::config::Platform;

/// Trait for platform-specific device drivers.
///
/// Each driver translates structured `Command` objects into the platform's
/// native automation interface (EOS `| json`, SR-OS `| as-json`), parses
/// the response into platform-independent structured types, and returns
/// a `CommandResult` carrying a `CommandOutput` variant.
#[async_trait]
#[allow(dead_code)]
pub trait DeviceDriver: Send + Sync {
    /// The platform this driver handles.
    fn platform(&self) -> Platform;

    /// Execute a command on the device and return structured output.
    async fn execute(&self, command: &Command) -> Result<CommandResult>;

    /// Check if the driver's connection is still alive.
    async fn is_alive(&self) -> bool;

    /// Close the connection.
    async fn close(&self) -> Result<()>;

}
