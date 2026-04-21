use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::client;
use russh::client::KeyboardInteractiveAuthResponse;
use russh::{ChannelMsg, Disconnect};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

use crate::config::{DeviceAuthMethod, DeviceConfig};

/// Timeout for SSH connect + auth.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for streaming commands (ping/traceroute) — per-line idle timeout.
const STREAM_LINE_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall timeout for streaming commands.
const STREAM_TOTAL_TIMEOUT: Duration = Duration::from_secs(60);

/// A thin wrapper around a russh SSH session that can execute a single
/// CLI command and return the collected output.
///
/// Sessions are ephemeral: connect → exec → collect → disconnect.
/// A future version may pool persistent sessions.

struct ClientHandler {
    /// If set, the server's host key SHA-256 fingerprint (as "SHA256:base64...")
    /// must match this value. Obtained via `ssh-keygen -lf /path/to/key`.
    expected_fingerprint: Option<String>,
}

impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        match &self.expected_fingerprint {
            Some(expected) => {
                // Compute SHA-256 fingerprint; Display impl gives "SHA256:base64..."
                let actual = server_public_key
                    .fingerprint(russh::keys::HashAlg::Sha256)
                    .to_string();
                if actual == *expected {
                    Ok(true)
                } else {
                    warn!(
                        expected = expected,
                        actual = actual,
                        "SSH host key fingerprint mismatch"
                    );
                    Ok(false)
                }
            }
            None => {
                // No fingerprint configured — accept all (TOFU model)
                Ok(true)
            }
        }
    }
}

/// Connect and authenticate an SSH session to a device.
async fn ssh_connect(config: &DeviceConfig) -> Result<client::Handle<ClientHandler>> {
    debug!(
        device = config.name,
        host = config.host,
        "SSH connect"
    );

    // Use the device's command timeout for SSH inactivity timeout.
    // Nokia SR-OS `show port | as-json` can take 30+ seconds to produce output,
    // during which no SSH protocol messages are exchanged.
    let inactivity_timeout = Duration::from_secs(config.command_timeout_secs);
    let russh_config = client::Config {
        inactivity_timeout: Some(inactivity_timeout),
        ..Default::default()
    };

    let mut session = timeout(
        CONNECT_TIMEOUT,
        client::connect(
            Arc::new(russh_config),
            (config.host.as_str(), config.port),
            ClientHandler {
                expected_fingerprint: config.host_key_fingerprint.clone(),
            },
        ),
    )
    .await
    .context("SSH connect timed out")?
    .context("SSH connect failed")?;

    let authenticated = match config.auth_method {
        DeviceAuthMethod::SshKey => {
            let key_path = config
                .ssh_key
                .as_deref()
                .unwrap_or("/etc/looking-glass/device_key");
            let key = russh::keys::load_secret_key(key_path, None)
                .map_err(|e| anyhow::anyhow!("failed to load SSH key {key_path}: {e}"))?;
            let key_with_hash = russh::keys::PrivateKeyWithHashAlg::new(
                Arc::new(key),
                None,
            );
            session
                .authenticate_publickey(&config.username, key_with_hash)
                .await
                .context("SSH public key auth failed")?
                .success()
        }
        DeviceAuthMethod::Password => {
            let password = std::env::var("LG_DEVICE_PASSWORD")
                .context("LG_DEVICE_PASSWORD not set for password auth")?;

            let ki_result = session
                .authenticate_keyboard_interactive_start(&config.username, None::<String>)
                .await
                .context("SSH keyboard-interactive start failed")?;

            match ki_result {
                KeyboardInteractiveAuthResponse::Success => true,
                KeyboardInteractiveAuthResponse::Failure { .. } => {
                    debug!(device = config.name, "keyboard-interactive rejected, trying password");
                    session
                        .authenticate_password(&config.username, &password)
                        .await
                        .context("SSH password auth failed")?
                        .success()
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
    Ok(session)
}

/// Execute a single CLI command on a device via SSH, returning the output text.
///
/// Connects, authenticates, opens a channel, sends the command, and
/// collects all stdout data until the channel closes or EOF.
///
/// Note: Some devices (e.g., Nokia SR-OS) require a PTY for command execution.
/// We request a PTY and use shell mode with the command followed by exit.
pub async fn ssh_exec(config: &DeviceConfig, cli_command: &str) -> Result<String> {
    debug!(
        device = config.name,
        command = cli_command,
        "SSH exec"
    );

    let session = ssh_connect(config).await?;

    let mut channel = session
        .channel_open_session()
        .await
        .context("failed to open SSH channel")?;

    // Request PTY - required for Nokia SR-OS and some other devices
    // Use large terminal dimensions (65535 rows) to avoid pagination
    channel
        .request_pty(false, "xterm", 0, 0, 65535, 65535, &[])
        .await
        .context("failed to request PTY")?;

    // Use shell mode and send command + exit
    channel
        .request_shell(true)
        .await
        .context("failed to request shell")?;

    // Send the command followed by exit
    let cmd_with_exit = format!("{}\nexit\n", cli_command);
    channel
        .data(cmd_with_exit.as_bytes())
        .await
        .context("failed to send command")?;

    let cmd_timeout = Duration::from_secs(config.command_timeout_secs);
    // Idle timeout to detect when command output is complete
    // Nokia SR-OS can have pauses between data bursts, so use 5 seconds
    let idle_timeout = Duration::from_secs(5);
    let mut output = Vec::new();
    let mut last_data_time = tokio::time::Instant::now();
    let mut got_data = false;
    
    let collect_result = timeout(cmd_timeout, async {
        loop {
            let wait_result = timeout(idle_timeout, channel.wait()).await;
            match wait_result {
                Err(_) => {
                    // Idle timeout - if we've received data, assume command is done
                    if got_data {
                        trace!("SSH idle timeout after receiving data - command complete");
                        break;
                    }
                    // No data yet, keep waiting
                }
                Ok(Some(ChannelMsg::Data { data, .. })) => {
                    trace!(bytes = data.len(), "SSH channel data");
                    output.extend_from_slice(&data);
                    last_data_time = tokio::time::Instant::now();
                    got_data = true;
                }
                Ok(Some(ChannelMsg::ExtendedData { data, ext })) => {
                    if ext == 1 {
                        trace!(bytes = data.len(), "SSH channel stderr");
                        output.extend_from_slice(&data);
                        last_data_time = tokio::time::Instant::now();
                        got_data = true;
                    }
                }
                Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                    trace!(exit_status, "SSH channel exit status");
                }
                Ok(Some(ChannelMsg::Eof)) => {
                    trace!("SSH channel EOF");
                    break;
                }
                Ok(None) => {
                    break;
                }
                _ => {}
            }
        }
    })
    .await;

    let _ = last_data_time; // suppress unused warning
    
    if collect_result.is_err() {
        anyhow::bail!("command timed out after {}s on {}", cmd_timeout.as_secs(), config.name);
    }

    let _ = session
        .disconnect(Disconnect::ByApplication, "done", "en")
        .await;

    let text = String::from_utf8_lossy(&output).to_string();
    Ok(text)
}

/// Execute a CLI command and stream output line-by-line via an mpsc channel.
///
/// Returns a `Receiver<String>` that yields lines as they arrive from the
/// SSH channel. The connection is managed by a background task that
/// automatically disconnects when the channel closes or timeouts occur.
///
/// Used for long-running commands like ping and traceroute where the user
/// should see incremental output rather than waiting for completion.
///
/// Note: Uses PTY + shell mode for Nokia SR-OS compatibility.
pub async fn ssh_exec_stream(
    config: &DeviceConfig,
    cli_command: &str,
) -> Result<mpsc::Receiver<String>> {
    debug!(
        device = config.name,
        command = cli_command,
        "SSH exec stream"
    );

    let session = ssh_connect(config).await?;

    let mut channel = session
        .channel_open_session()
        .await
        .context("failed to open SSH channel")?;

    // Request PTY - required for Nokia SR-OS and some other devices
    channel
        .request_pty(false, "xterm", 0, 0, 0, 0, &[])
        .await
        .context("failed to request PTY")?;

    // Use shell mode and send command
    channel
        .request_shell(true)
        .await
        .context("failed to request shell")?;

    // Send the command (no exit for streaming - let it run)
    let cmd_line = format!("{}\n", cli_command);
    channel
        .data(cmd_line.as_bytes())
        .await
        .context("failed to send command")?;

    let (tx, rx) = mpsc::channel::<String>(64);
    let device_name = config.name.clone();

    tokio::spawn(async move {
        let mut line_buf = Vec::new();
        let start = tokio::time::Instant::now();

        loop {
            if start.elapsed() > STREAM_TOTAL_TIMEOUT {
                let _ = tx.send(format!(
                    "[timed out after {}s]",
                    STREAM_TOTAL_TIMEOUT.as_secs()
                )).await;
                break;
            }

            let msg = timeout(STREAM_LINE_TIMEOUT, channel.wait()).await;
            match msg {
                Err(_) => {
                    // Per-line idle timeout — flush any partial line and stop
                    if !line_buf.is_empty() {
                        let line = String::from_utf8_lossy(&line_buf).to_string();
                        let _ = tx.send(line).await;
                        line_buf.clear();
                    }
                    let _ = tx.send("[timed out waiting for output]".to_string()).await;
                    break;
                }
                Ok(Some(ChannelMsg::Data { data, .. })) => {
                    // Buffer bytes and emit complete lines
                    for &byte in data.iter() {
                        if byte == b'\n' {
                            let line = String::from_utf8_lossy(&line_buf).to_string();
                            let line = line.trim_end_matches('\r').to_string();
                            if tx.send(line).await.is_err() {
                                // Receiver dropped
                                break;
                            }
                            line_buf.clear();
                        } else {
                            line_buf.push(byte);
                        }
                    }
                }
                Ok(Some(ChannelMsg::ExtendedData { data, ext })) if ext == 1 => {
                    for &byte in data.iter() {
                        if byte == b'\n' {
                            let line = String::from_utf8_lossy(&line_buf).to_string();
                            let line = line.trim_end_matches('\r').to_string();
                            let _ = tx.send(line).await;
                            line_buf.clear();
                        } else {
                            line_buf.push(byte);
                        }
                    }
                }
                Ok(Some(ChannelMsg::Eof)) | Ok(None) => {
                    // Flush any remaining partial line
                    if !line_buf.is_empty() {
                        let line = String::from_utf8_lossy(&line_buf).to_string();
                        let line = line.trim_end_matches('\r').to_string();
                        let _ = tx.send(line).await;
                    }
                    break;
                }
                _ => {}
            }
        }

        trace!(device = device_name, "SSH stream task done");
        let _ = session
            .disconnect(Disconnect::ByApplication, "done", "en")
            .await;
    });

    Ok(rx)
}
