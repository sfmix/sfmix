use anyhow::Result;
use async_trait::async_trait;

use crate::command::{Command, CommandResult};
use crate::config::Platform;

/// Trait for platform-specific device drivers.
///
/// Each driver translates structured `Command` objects into the platform's
/// native CLI syntax, executes them over an SSH session, and returns the
/// raw text output.
#[async_trait]
#[allow(dead_code)]
pub trait DeviceDriver: Send + Sync {
    /// The platform this driver handles.
    fn platform(&self) -> Platform;

    /// Translate a structured command into platform-native CLI string(s).
    fn translate(&self, command: &Command) -> Result<String>;

    /// Execute a command on the device and return the output.
    async fn execute(&self, command: &Command) -> Result<CommandResult>;

    /// Check if the driver's connection is still alive.
    async fn is_alive(&self) -> bool;

    /// Close the connection.
    async fn close(&self) -> Result<()>;
}
