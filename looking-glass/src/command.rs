// Re-export shared types from lg-types (except CommandResult, which
// is defined locally to reference the crate-local CommandOutput that
// includes the Stream variant).
pub use lg_types::command::{
    AddressFamily, Command, ParseError, Resource, Verb,
};

/// Result of executing a command against a device.
///
/// This local version references the crate-local `CommandOutput` which
/// includes the `Stream` variant (not serializable, not in lg-types).
#[derive(Debug)]
pub struct CommandResult {
    /// The device that was queried
    pub device: String,
    /// Structured output from the device
    pub output: crate::structured::CommandOutput,
    /// Whether the command executed successfully
    pub success: bool,
}
