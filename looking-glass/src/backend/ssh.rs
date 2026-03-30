use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::client;
use russh::client::KeyboardInteractiveAuthResponse;
use russh::{ChannelMsg, Disconnect};
use russh::keys::key;
use tokio::time::timeout;
use tracing::{debug, trace};

use crate::config::{DeviceAuthMethod, DeviceConfig};

/// Timeout for SSH connect + auth.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for command execution (output collection).
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// A thin wrapper around a russh SSH session that can execute a single
/// CLI command and return the collected output.
///
/// For Phase 1, sessions are ephemeral: connect → exec → collect → disconnect.
/// A future version may pool persistent sessions.

struct ClientHandler;

#[async_trait::async_trait]
impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept all host keys for now.
        // TODO: verify against known_hosts or configured fingerprint.
        Ok(true)
    }
}

/// Execute a single CLI command on a device via SSH, returning the output text.
///
/// This connects, authenticates, opens a channel, sends the command, and
/// collects all stdout data until the channel closes or EOF.
pub async fn ssh_exec(config: &DeviceConfig, cli_command: &str) -> Result<String> {
    debug!(
        device = config.name,
        host = config.host,
        command = cli_command,
        "SSH exec"
    );

    let russh_config = client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    };

    // Connect
    let mut session = timeout(
        CONNECT_TIMEOUT,
        client::connect(Arc::new(russh_config), (config.host.as_str(), config.port), ClientHandler),
    )
    .await
    .context("SSH connect timed out")?
    .context("SSH connect failed")?;

    // Authenticate
    let authenticated = match config.auth_method {
        DeviceAuthMethod::SshKey => {
            let key_path = config
                .ssh_key
                .as_deref()
                .unwrap_or("/etc/looking-glass/device_key");
            let key = russh_keys::load_secret_key(key_path, None)
                .map_err(|e| anyhow::anyhow!("failed to load SSH key {key_path}: {e}"))?;
            session
                .authenticate_publickey(&config.username, Arc::new(key))
                .await
                .context("SSH public key auth failed")?
        }
        DeviceAuthMethod::Password => {
            let password = std::env::var("LG_DEVICE_PASSWORD")
                .context("LG_DEVICE_PASSWORD not set for password auth")?;

            // Most network devices (EOS, SR-OS) use keyboard-interactive
            // rather than plain password auth. Try keyboard-interactive first,
            // fall back to password.
            let ki_result = session
                .authenticate_keyboard_interactive_start(&config.username, None::<String>)
                .await
                .context("SSH keyboard-interactive start failed")?;

            match ki_result {
                KeyboardInteractiveAuthResponse::Success => true,
                KeyboardInteractiveAuthResponse::Failure => {
                    debug!(device = config.name, "keyboard-interactive rejected, trying password");
                    session
                        .authenticate_password(&config.username, &password)
                        .await
                        .context("SSH password auth failed")?
                }
                KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                    let responses: Vec<String> = prompts.iter().map(|_| password.clone()).collect();
                    let reply = session
                        .authenticate_keyboard_interactive_respond(responses)
                        .await
                        .context("SSH keyboard-interactive respond failed")?;
                    match reply {
                        KeyboardInteractiveAuthResponse::Success => true,
                        KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } if prompts.is_empty() => {
                            // Some devices (EOS) send an empty InfoRequest after
                            // accepting the password; respond to finalize.
                            let final_reply = session
                                .authenticate_keyboard_interactive_respond(vec![])
                                .await
                                .context("SSH keyboard-interactive final respond failed")?;
                            matches!(final_reply, KeyboardInteractiveAuthResponse::Success)
                        }
                        _ => false,
                    }
                }
            }
        }
    };

    if !authenticated {
        anyhow::bail!("SSH authentication failed for {}", config.name);
    }

    debug!(device = config.name, "SSH authenticated");

    // Open a session channel and execute the command
    let mut channel = session
        .channel_open_session()
        .await
        .context("failed to open SSH channel")?;

    // The caller (driver) prepends the appropriate pagination-disable
    // preamble (e.g. "terminal length 0 ; " for EOS).
    channel
        .exec(true, cli_command)
        .await
        .context("failed to exec command")?;

    // Collect output
    let mut output = Vec::new();
    let collect_result = timeout(COMMAND_TIMEOUT, async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data, .. }) => {
                    trace!(bytes = data.len(), "SSH channel data");
                    output.extend_from_slice(&data);
                }
                Some(ChannelMsg::ExtendedData { data, ext }) => {
                    if ext == 1 {
                        trace!(bytes = data.len(), "SSH channel stderr");
                        output.extend_from_slice(&data);
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    trace!(exit_status, "SSH channel exit status");
                }
                Some(ChannelMsg::Eof) => {
                    trace!("SSH channel EOF");
                    break;
                }
                None => {
                    break;
                }
                _ => {}
            }
        }
    })
    .await;

    if collect_result.is_err() {
        anyhow::bail!("command timed out after {}s on {}", COMMAND_TIMEOUT.as_secs(), config.name);
    }

    // Close session (best-effort)
    let _ = session
        .disconnect(Disconnect::ByApplication, "done", "en")
        .await;

    let text = String::from_utf8_lossy(&output).to_string();
    Ok(text)
}
