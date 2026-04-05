use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::{info, warn};

use crate::identity::Identity;
use crate::service::LookingGlass;

use super::common::{
    CommandAction, LineEditor, LineEvent, SessionWriter, PROMPT,
};

// Telnet protocol constants
const IAC: u8 = 255;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const SB: u8 = 250;
const SE: u8 = 240;
const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3; // Suppress Go-Ahead

/// Transform \n to \r\n for telnet output.
fn to_crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 40);
    for &b in data {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

/// SessionWriter implementation for the telnet OwnedWriteHalf.
/// Transforms \n → \r\n at the output boundary.
struct TelnetWriter<'a> {
    inner: &'a mut OwnedWriteHalf,
}

impl<'a> SessionWriter for TelnetWriter<'a> {
    async fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        let transformed = to_crlf(data);
        self.inner.write_all(&transformed).await?;
        self.inner.flush().await?;
        Ok(())
    }
}

/// Telnet frontend server.
///
/// Provides unauthenticated, public-tier access to the looking glass.
/// Presents a simple text menu and accepts line-oriented commands.
pub struct TelnetServer {
    bind_addr: String,
    lg: Arc<LookingGlass>,
}

impl TelnetServer {
    pub fn new(bind_addr: String, lg: Arc<LookingGlass>) -> Self {
        Self { bind_addr, lg }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        info!("Telnet server listening on {}", self.bind_addr);

        loop {
            let (mut socket, addr) = listener.accept().await?;
            let source_key = crate::ratelimit::ip_to_rate_key(addr.ip());
            let lg = self.lg.clone();

            // Connection gating — reject before spawning session task
            let conn_guard = match lg.connection_tracker.try_admit(&source_key) {
                Ok(guard) => guard,
                Err(e) => {
                    warn!("Telnet connection rejected from {}: {}", addr, e);
                    let _ = socket.write_all(format!("\r\n{e}\r\n").as_bytes()).await;
                    continue;
                }
            };

            info!("Telnet connection from {}", addr);
            tokio::spawn(async move {
                let _conn_guard = conn_guard;
                if let Err(e) = handle_telnet_session(socket, addr, lg).await {
                    warn!("Telnet session error from {}: {}", addr, e);
                }
                info!("Telnet session ended for {}", addr);
            });
        }
    }
}

async fn handle_telnet_session(
    socket: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    lg: Arc<LookingGlass>,
) -> Result<()> {
    let (mut reader, mut writer) = socket.into_split();
    let mut identity = Identity::anonymous();

    // Negotiate character mode: WILL ECHO + WILL SGA
    writer
        .write_all(&[IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA])
        .await?;
    writer.flush().await?;

    // Banner
    let banner = format!(
        "\n{}\nType 'help' or '?' for available commands.\n\n",
        crate::format::format_banner(&lg.service_name)
    );
    writer.write_all(&to_crlf(banner.as_bytes())).await?;

    let mut editor = LineEditor::new();

    loop {
        // Prompt
        writer.write_all(PROMPT.as_bytes()).await?;
        writer.flush().await?;

        // Interactive line editor — read char by char
        let line = match read_line(&mut reader, &mut writer, &mut editor).await? {
            Some(line) => line,
            None => break, // EOF / Ctrl+D
        };

        let rate_key = crate::ratelimit::ip_to_rate_key(peer_addr.ip());
        let mut tw = TelnetWriter { inner: &mut writer };

        match super::common::dispatch_command(&line, &lg, &identity, &rate_key, crate::format::ColorMode::Color, &mut tw).await? {
            CommandAction::Quit => break,
            CommandAction::Login => {
                handle_telnet_login(&lg, &mut identity, &mut writer).await?;
            }
            CommandAction::Continue => {}
        }
    }

    Ok(())
}

/// Handle the OIDC login flow for telnet (session-only, no certs).
async fn handle_telnet_login(
    lg: &LookingGlass,
    identity: &mut Identity,
    writer: &mut OwnedWriteHalf,
) -> Result<()> {
    if identity.authenticated {
        let email = identity.email.as_deref().unwrap_or("unknown");
        let msg = format!("Already authenticated as {email}\n");
        writer.write_all(&to_crlf(msg.as_bytes())).await?;
        writer.flush().await?;
        return Ok(());
    }
    let oidc = match &lg.oidc_client {
        Some(c) => c.clone(),
        None => {
            writer.write_all(&to_crlf(b"OIDC authentication not configured.\n")).await?;
            writer.flush().await?;
            return Ok(());
        }
    };
    let auth_state = match oidc.start_device_auth().await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("Failed to start authentication: {e}\n");
            writer.write_all(&to_crlf(msg.as_bytes())).await?;
            writer.flush().await?;
            return Ok(());
        }
    };
    let msg = format!(
        "\nTo authenticate, visit: {}\nEnter code: {}\nWaiting for authentication...\n",
        auth_state.verification_uri, auth_state.user_code
    );
    writer.write_all(&to_crlf(msg.as_bytes())).await?;
    writer.flush().await?;

    match oidc.poll_for_token(&auth_state).await {
        Ok(claims) => {
            *identity = Identity::from_oidc_claims(
                claims.email.clone(),
                claims.groups.clone(),
                &lg.group_prefix,
            );
            let asn_list: Vec<String> = identity.asns.iter().map(|a| format!("AS{a}")).collect();
            let asn_display = if asn_list.is_empty() {
                String::new()
            } else {
                format!(" ({})", asn_list.join(", "))
            };
            let msg = format!(
                "\nAuthenticated as {}{asn_display}\n(Session-only \u{2014} no certificate issued for telnet)\n",
                claims.email
            );
            writer.write_all(&to_crlf(msg.as_bytes())).await?;
        }
        Err(e) => {
            let msg = format!("\nAuthentication failed: {e}\n");
            writer.write_all(&to_crlf(msg.as_bytes())).await?;
        }
    }
    writer.flush().await?;
    Ok(())
}

/// Interactive line reader with Tab completion and ? help (IOS-style).
///
/// Reads from the telnet socket one byte at a time (character mode).
/// Returns `Some(line)` on Enter, `None` on EOF/Ctrl+D.
///
/// Telnet-specific concerns (IAC handling, CR consumption) are handled
/// here; all other byte processing is delegated to the shared LineEditor.
async fn read_line(
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
    editor: &mut LineEditor,
) -> Result<Option<String>> {
    let mut byte = [0u8; 1];
    editor.clear();

    loop {
        if reader.read(&mut byte).await? == 0 {
            return Ok(None); // EOF
        }

        match byte[0] {
            // --- Telnet IAC sequence (telnet-specific, not in LineEditor) ---
            IAC => {
                let mut cmd = [0u8; 1];
                if reader.read_exact(&mut cmd).await.is_err() {
                    return Ok(None);
                }
                match cmd[0] {
                    WILL | WONT | DO | DONT => {
                        let mut opt = [0u8; 1];
                        let _ = reader.read_exact(&mut opt).await;
                    }
                    SB => {
                        loop {
                            let mut sb = [0u8; 1];
                            if reader.read_exact(&mut sb).await.is_err() {
                                return Ok(None);
                            }
                            if sb[0] == IAC {
                                let mut se = [0u8; 1];
                                if reader.read_exact(&mut se).await.is_err() {
                                    return Ok(None);
                                }
                                if se[0] == SE {
                                    break;
                                }
                            }
                        }
                    }
                    IAC => {
                        // Escaped 0xFF — feed as data byte
                        let mut output = Vec::new();
                        let _ = editor.feed_byte(0xFF, &mut output);
                        if !output.is_empty() {
                            writer.write_all(&to_crlf(&output)).await?;
                            writer.flush().await?;
                        }
                    }
                    _ => {}
                }
            }

            // --- CR: consume optional trailing LF/NUL, then delegate ---
            0x0D => {
                let mut peek = [0u8; 1];
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(50),
                    reader.read_exact(&mut peek),
                )
                .await;
                // Delegate CR as the newline trigger
                let mut output = Vec::new();
                match editor.feed_byte(0x0D, &mut output) {
                    LineEvent::Line(line) => {
                        writer.write_all(&to_crlf(&output)).await?;
                        writer.flush().await?;
                        return Ok(Some(line));
                    }
                    LineEvent::Eof => {
                        writer.write_all(&to_crlf(&output)).await?;
                        return Ok(None);
                    }
                    LineEvent::Continue => {
                        if !output.is_empty() {
                            writer.write_all(&to_crlf(&output)).await?;
                            writer.flush().await?;
                        }
                    }
                }
            }

            // --- All other bytes: delegate to shared LineEditor ---
            b => {
                let mut output = Vec::new();
                match editor.feed_byte(b, &mut output) {
                    LineEvent::Line(line) => {
                        writer.write_all(&to_crlf(&output)).await?;
                        writer.flush().await?;
                        return Ok(Some(line));
                    }
                    LineEvent::Eof => {
                        writer.write_all(&to_crlf(&output)).await?;
                        return Ok(None);
                    }
                    LineEvent::Continue => {
                        if !output.is_empty() {
                            writer.write_all(&to_crlf(&output)).await?;
                            writer.flush().await?;
                        }
                    }
                }
            }
        }
    }
}
