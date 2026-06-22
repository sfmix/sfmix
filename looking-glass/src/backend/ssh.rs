use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::client;
use russh::client::KeyboardInteractiveAuthResponse;
use russh::{Channel, ChannelMsg};
use russh::client::Msg;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

use russh::client::AuthResult;
use russh::MethodKind;

use crate::config::{DeviceAuthMethod, DeviceConfig, Platform};

use super::ssh_pool::{ConnectFn, IsClosedFn, OpError, Pool, ProbeFn};

/// Timeout for SSH connect + auth.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for streaming commands (ping/traceroute) — per-line idle timeout.
const STREAM_LINE_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall timeout for streaming commands.
const STREAM_TOTAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Transport-level keepalive interval. The russh session sends an SSH global
/// keepalive this often; the server's reply is received data, which resets the
/// inactivity timer. This (a) keeps an idle *pooled* connection alive between
/// commands/probes, (b) keeps NAT/firewall state warm, and (c) makes
/// `Handle::is_closed()` reliably trip on a dead peer. It is a transport message,
/// **not** a CLI command, so it adds no device command-log noise.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Close the connection after this many unanswered keepalives (~90s to detect a
/// dead peer at the interval above).
const KEEPALIVE_MAX: usize = 3;

/// Floor for the russh inactivity timeout. Must comfortably exceed
/// `KEEPALIVE_INTERVAL` so keepalive replies reset the timer on an idle pooled
/// connection (and during a long, output-silent command). The per-device command
/// timeout raises this further when larger.
const INACTIVITY_FLOOR_SECS: u64 = 90;

/// Timeout for the CLI freshness probe — a tiny command, should return promptly.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Production connection pool: pools authenticated russh sessions per device and
/// reuses them across commands. See [`super::ssh_pool`] for the pooling/freshness
/// model.
pub(crate) type ConnectionPool = Pool<client::Handle<ClientHandler>>;

/// A reusable russh client session that executes CLI commands on a device.
///
/// Connections are **pooled** ([`ConnectionPool`]): one authenticated session per
/// device, reused across commands (each command runs on a fresh channel), held
/// open between uses and verified by a transport keepalive plus an idle CLI probe.
/// This replaced the previous connect → exec → disconnect-per-command model, which
/// flooded device logs with auth churn.

pub(crate) struct ClientHandler {
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
pub(crate) async fn ssh_connect(config: &DeviceConfig) -> Result<client::Handle<ClientHandler>> {
    debug!(
        device = config.name,
        host = config.host,
        "SSH connect"
    );

    // Inactivity timeout for a pooled, possibly-idle connection. Keepalives
    // (KEEPALIVE_INTERVAL) exchange transport messages well within this window —
    // the server's keepalive reply counts as received data and resets the timer —
    // so an idle connection survives, and a long output-silent command (e.g. Nokia
    // SR-OS `show port` taking 30s+) no longer trips it. We also keep it at least as
    // large as the per-device command timeout.
    let inactivity_timeout =
        Duration::from_secs(config.command_timeout_secs.max(INACTIVITY_FLOOR_SECS));
    let russh_config = client::Config {
        inactivity_timeout: Some(inactivity_timeout),
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
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

    // Probe the server's advertised auth methods with a "none" request.
    // This avoids triggering spurious auth-failure logs on devices that
    // don't support a method we'd otherwise try (e.g. keyboard-interactive
    // on Nokia SR OS, which only advertises publickey+password).
    let server_methods = match session
        .authenticate_none(&config.username)
        .await
        .context("SSH none-auth probe failed")?
    {
        AuthResult::Success => {
            // Server accepted "none" auth (unlikely but valid).
            debug!(device = config.name, "SSH authenticated via none");
            return Ok(session);
        }
        AuthResult::Failure {
            remaining_methods, ..
        } => {
            debug!(
                device = config.name,
                methods = ?remaining_methods,
                "server advertised auth methods"
            );
            remaining_methods
        }
    };

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

            // Try keyboard-interactive first, but only if the server advertises it.
            let ki_success = if server_methods.contains(&MethodKind::KeyboardInteractive) {
                let ki_result = session
                    .authenticate_keyboard_interactive_start(&config.username, None::<String>)
                    .await
                    .context("SSH keyboard-interactive start failed")?;

                match ki_result {
                    KeyboardInteractiveAuthResponse::Success => true,
                    KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                        let responses: Vec<String> =
                            prompts.iter().map(|_| password.clone()).collect();
                        let reply = session
                            .authenticate_keyboard_interactive_respond(responses)
                            .await
                            .context("SSH keyboard-interactive respond failed")?;
                        match reply {
                            KeyboardInteractiveAuthResponse::Success => true,
                            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. }
                                if prompts.is_empty() =>
                            {
                                let final_reply = session
                                    .authenticate_keyboard_interactive_respond(vec![])
                                    .await
                                    .context("SSH keyboard-interactive final respond failed")?;
                                matches!(final_reply, KeyboardInteractiveAuthResponse::Success)
                            }
                            _ => false,
                        }
                    }
                    KeyboardInteractiveAuthResponse::Failure { .. } => false,
                }
            } else {
                debug!(
                    device = config.name,
                    "server does not advertise keyboard-interactive, skipping"
                );
                false
            };

            if ki_success {
                true
            } else if server_methods.contains(&MethodKind::Password) {
                debug!(device = config.name, "trying password auth");
                session
                    .authenticate_password(&config.username, &password)
                    .await
                    .context("SSH password auth failed")?
                    .success()
            } else {
                false
            }
        }
    };

    if !authenticated {
        anyhow::bail!("SSH authentication failed for {}", config.name);
    }

    debug!(device = config.name, "SSH authenticated");
    Ok(session)
}

// ── Channel-level command execution (no connect/disconnect — pooled) ─────────
//
// These run a command on a *channel* over an already-pooled, authenticated
// connection and return the collected output. They never open or close the
// connection itself; the pool owns its lifetime. Errors are classified as
// `OpError::Retryable` (channel/transport setup failed → the pooled connection is
// presumed dead, reconnect+retry once) vs `OpError::Fatal` (command timed out → the
// connection is fine, do not retry).

/// Execute a CLI command via SSH exec (no PTY, no shell) and collect the output.
///
/// Runs the command directly via the SSH "exec" subsystem. Output is clean: no
/// terminal escape sequences, no echoed input, no shell prompts. Used for
/// structured-output commands (e.g. Arista EOS `| json`). Unlike the PTY+shell
/// path this avoids the DSR/terminal handshakes some EOS versions wait on.
async fn exec_collect(
    handle: &client::Handle<ClientHandler>,
    config: &DeviceConfig,
    cli: &str,
    cmd_timeout: Duration,
) -> Result<String, OpError> {
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| OpError::Retryable(anyhow::anyhow!("failed to open SSH channel: {e}")))?;

    channel
        .exec(true, cli)
        .await
        .map_err(|e| OpError::Retryable(anyhow::anyhow!("failed to exec SSH command: {e}")))?;

    let mut output = Vec::new();
    let collect_result = timeout(cmd_timeout, async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data, .. }) => {
                    trace!(bytes = data.len(), "SSH channel data");
                    output.extend_from_slice(&data);
                }
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                    trace!(bytes = data.len(), "SSH channel stderr");
                    output.extend_from_slice(&data);
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    trace!(exit_status, "SSH channel exit status");
                }
                Some(ChannelMsg::Eof) | None => break,
                _ => {}
            }
        }
    })
    .await;

    if collect_result.is_err() {
        return Err(OpError::Fatal(anyhow::anyhow!(
            "command timed out after {}s on {}",
            cmd_timeout.as_secs(),
            config.name
        )));
    }

    Ok(String::from_utf8_lossy(&output).to_string())
}

/// Execute a CLI command via SSH PTY+shell and collect the output.
///
/// Some devices (e.g. Nokia SR-OS) require a PTY. We request a PTY and use shell
/// mode with the command followed by `exit`, collecting stdout until EOF or an
/// idle gap that indicates the command finished.
async fn shell_collect(
    handle: &client::Handle<ClientHandler>,
    config: &DeviceConfig,
    cli: &str,
    cmd_timeout: Duration,
) -> Result<String, OpError> {
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| OpError::Retryable(anyhow::anyhow!("failed to open SSH channel: {e}")))?;

    // Request PTY - required for Nokia SR-OS and some other devices.
    // Use large terminal dimensions (65535 rows) to avoid pagination.
    channel
        .request_pty(false, "xterm", 0, 0, 65535, 65535, &[])
        .await
        .map_err(|e| OpError::Retryable(anyhow::anyhow!("failed to request PTY: {e}")))?;

    channel
        .request_shell(true)
        .await
        .map_err(|e| OpError::Retryable(anyhow::anyhow!("failed to request shell: {e}")))?;

    // Send the command followed by exit.
    let cmd_with_exit = format!("{}\nexit\n", cli);
    channel
        .data(cmd_with_exit.as_bytes())
        .await
        .map_err(|e| OpError::Retryable(anyhow::anyhow!("failed to send command: {e}")))?;

    // Idle timeout to detect when command output is complete.
    // Nokia SR-OS can have pauses between data bursts, so use 5 seconds.
    let idle_timeout = Duration::from_secs(5);
    let mut output = Vec::new();
    let mut got_data = false;

    let collect_result = timeout(cmd_timeout, async {
        loop {
            let wait_result = timeout(idle_timeout, channel.wait()).await;
            match wait_result {
                Err(_) => {
                    // Idle timeout - if we've received data, assume command is done.
                    if got_data {
                        trace!("SSH idle timeout after receiving data - command complete");
                        break;
                    }
                    // No data yet, keep waiting.
                }
                Ok(Some(ChannelMsg::Data { data, .. })) => {
                    trace!(bytes = data.len(), "SSH channel data");
                    output.extend_from_slice(&data);
                    got_data = true;
                }
                Ok(Some(ChannelMsg::ExtendedData { data, ext })) => {
                    if ext == 1 {
                        trace!(bytes = data.len(), "SSH channel stderr");
                        output.extend_from_slice(&data);
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
                Ok(None) => break,
                _ => {}
            }
        }
    })
    .await;

    if collect_result.is_err() {
        return Err(OpError::Fatal(anyhow::anyhow!(
            "command timed out after {}s on {}",
            cmd_timeout.as_secs(),
            config.name
        )));
    }

    Ok(String::from_utf8_lossy(&output).to_string())
}

/// Open a PTY+shell channel for a streaming command (ping/traceroute) and send
/// the command (no `exit` — let it run). Returns the channel; the caller streams
/// from it.
async fn open_stream_channel(
    handle: &client::Handle<ClientHandler>,
    cli: &str,
) -> Result<Channel<Msg>, OpError> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| OpError::Retryable(anyhow::anyhow!("failed to open SSH channel: {e}")))?;

    channel
        .request_pty(false, "xterm", 0, 0, 0, 0, &[])
        .await
        .map_err(|e| OpError::Retryable(anyhow::anyhow!("failed to request PTY: {e}")))?;

    channel
        .request_shell(true)
        .await
        .map_err(|e| OpError::Retryable(anyhow::anyhow!("failed to request shell: {e}")))?;

    let cmd_line = format!("{}\n", cli);
    channel
        .data(cmd_line.as_bytes())
        .await
        .map_err(|e| OpError::Retryable(anyhow::anyhow!("failed to send command: {e}")))?;

    Ok(channel)
}

// ── Public, pooled entry points ──────────────────────────────────────────────

/// Whether a device permits reusing one SSH connection for multiple sequential
/// channels. Nokia SR-OS refuses a second channel on an existing connection
/// (`AdministrativelyProhibited`), so its connections must be single-use —
/// otherwise every command after the first fails channel-open and triggers a
/// reconnect storm. Arista EOS multiplexes channels fine.
fn reuse_connection(config: &DeviceConfig) -> bool {
    !matches!(config.platform, Platform::NokiaSros)
}

/// Execute a CLI command via SSH exec (no PTY) over a pooled connection.
pub(crate) async fn ssh_exec_direct(
    pool: &ConnectionPool,
    config: &DeviceConfig,
    cli: &str,
) -> Result<String> {
    debug!(device = config.name, command = cli, "SSH exec (direct, pooled)");
    let cmd_timeout = Duration::from_secs(config.command_timeout_secs);
    pool.run(config, reuse_connection(config), move |handle| async move {
        exec_collect(&handle, config, cli, cmd_timeout).await
    })
    .await
}

/// Execute a CLI command via SSH PTY+shell over a (possibly single-use) connection.
pub(crate) async fn ssh_exec(pool: &ConnectionPool, config: &DeviceConfig, cli: &str) -> Result<String> {
    debug!(device = config.name, command = cli, "SSH exec (pooled)");
    let cmd_timeout = Duration::from_secs(config.command_timeout_secs);
    pool.run(config, reuse_connection(config), move |handle| async move {
        shell_collect(&handle, config, cli, cmd_timeout).await
    })
    .await
}

/// Execute a CLI command and stream output line-by-line via an mpsc channel.
///
/// Returns a `Receiver<String>` that yields lines as they arrive. A background
/// task streams from the channel and **holds the pooled `Arc<Handle>` for the
/// stream's lifetime** (so the connection stays alive), then simply drops it —
/// never disconnecting, since other commands share the connection.
///
/// Uses PTY + shell mode for Nokia SR-OS compatibility. Long-running commands like
/// ping/traceroute stream incrementally.
pub(crate) async fn ssh_exec_stream(
    pool: &ConnectionPool,
    config: &DeviceConfig,
    cli: &str,
) -> Result<mpsc::Receiver<String>> {
    debug!(device = config.name, command = cli, "SSH exec stream (pooled)");

    // Acquire a handle and open the stream channel, reconnecting once if the
    // pooled connection turns out to be dead at channel-open time.
    let reuse = reuse_connection(config);
    let mut handle = pool.stream_handle(config, reuse).await?;
    let channel = match open_stream_channel(&handle, cli).await {
        Ok(ch) => ch,
        Err(OpError::Retryable(_)) => {
            pool.invalidate(&config.name, &handle).await;
            handle = pool.stream_handle(config, reuse).await?;
            open_stream_channel(&handle, cli)
                .await
                .map_err(OpError::into_inner)?
        }
        Err(OpError::Fatal(e)) => return Err(e),
    };

    let (tx, rx) = mpsc::channel::<String>(64);
    let device_name = config.name.clone();

    tokio::spawn(async move {
        // Keep the pooled connection alive for the stream's duration; dropped (not
        // disconnected) when the task ends.
        let _conn = handle;
        let mut channel = channel;
        let mut line_buf = Vec::new();
        let start = tokio::time::Instant::now();

        loop {
            if start.elapsed() > STREAM_TOTAL_TIMEOUT {
                let _ = tx
                    .send(format!("[timed out after {}s]", STREAM_TOTAL_TIMEOUT.as_secs()))
                    .await;
                break;
            }

            let msg = timeout(STREAM_LINE_TIMEOUT, channel.wait()).await;
            match msg {
                Err(_) => {
                    // Per-line idle timeout — flush any partial line and stop.
                    if !line_buf.is_empty() {
                        let line = String::from_utf8_lossy(&line_buf).to_string();
                        let _ = tx.send(line).await;
                        line_buf.clear();
                    }
                    let _ = tx.send("[timed out waiting for output]".to_string()).await;
                    break;
                }
                Ok(Some(ChannelMsg::Data { data, .. })) => {
                    for &byte in data.iter() {
                        if byte == b'\n' {
                            let line = String::from_utf8_lossy(&line_buf).to_string();
                            let line = line.trim_end_matches('\r').to_string();
                            if tx.send(line).await.is_err() {
                                break;
                            }
                            line_buf.clear();
                        } else {
                            line_buf.push(byte);
                        }
                    }
                }
                Ok(Some(ChannelMsg::ExtendedData { data, ext: 1 })) => {
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
        // `_conn` (Arc<Handle>) drops here — connection returns to the pool, NOT
        // disconnected.
    });

    Ok(rx)
}

// ── CLI freshness probe + pool construction ──────────────────────────────────

/// Run a tiny, side-effect-free command over the connection to confirm the device
/// CLI (not just the transport) is responsive. Used by the pool's idle freshness
/// task.
async fn probe_command(handle: &client::Handle<ClientHandler>, config: &DeviceConfig) -> Result<()> {
    let output = match config.platform {
        // EOS exec mode: one command per channel, clean output.
        Platform::AristaEos => exec_collect(handle, config, "show clock", PROBE_TIMEOUT).await,
        // SR-OS needs PTY+shell.
        Platform::NokiaSros => shell_collect(handle, config, "show system time", PROBE_TIMEOUT).await,
    }
    .map_err(OpError::into_inner)?;

    if output.trim().is_empty() {
        anyhow::bail!("freshness probe returned no output for {}", config.name);
    }
    Ok(())
}

/// Build the production connection pool (russh-backed) and start its background
/// freshness/keepalive task.
///
/// `probe_interval` of zero disables the idle CLI probe (rely on transport
/// keepalive + reconnect-on-use). `max_idle` of `None` keeps connections warm
/// indefinitely while probes pass.
pub(crate) fn build_pool(
    probe_interval: Duration,
    max_idle: Option<Duration>,
) -> Arc<ConnectionPool> {
    let connect: ConnectFn<client::Handle<ClientHandler>> =
        Box::new(|cfg: DeviceConfig| Box::pin(async move { ssh_connect(&cfg).await }));
    let is_closed: IsClosedFn<client::Handle<ClientHandler>> =
        Box::new(|h: &client::Handle<ClientHandler>| h.is_closed());
    let probe: ProbeFn<client::Handle<ClientHandler>> =
        Box::new(|h: Arc<client::Handle<ClientHandler>>, cfg: DeviceConfig| {
            Box::pin(async move { probe_command(&h, &cfg).await })
        });

    let pool = Arc::new(ConnectionPool::new(
        connect,
        is_closed,
        probe,
        probe_interval,
        max_idle,
    ));
    pool.clone().spawn_freshness_task();
    pool
}
