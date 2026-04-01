use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::{info, warn};

use crate::command::{parse_command, ParseError, Resource};
use crate::completion;
use crate::identity::Identity;
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::participants::ParticipantMap;
use crate::ratelimit::RateLimiter;
use crate::backend::pool::DevicePool;

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

/// Shared state passed to each frontend session.
pub struct TelnetState {
    pub service_name: String,
    pub policy: PolicyEngine,
    pub rate_limiter: RateLimiter,
    pub participants: ParticipantMap,
    pub device_pool: DevicePool,
    /// OIDC group prefix for extracting ASN from group names (e.g. "as")
    pub group_prefix: String,
}

pub const HELP_TEXT: &str = "\
Available commands:
  show interfaces status          Interface summary (name, status, speed)
  show interface <port>           Detailed interface counters
  show optics                     Transceiver DOM levels (all ports)
  show optics <port>              Detailed DOM for a specific port
  show ip bgp summary             BGP IPv4 peer summary
  show bgp ipv6 unicast summary   BGP IPv6 peer summary
  show lldp neighbors              LLDP neighbor table
  show arp                         ARP table
  show ipv6 neighbors              IPv6 neighbor table
  show participants                IXP participant list
  ping <destination>               Ping from the looking glass host
  traceroute <destination>         Traceroute from the looking glass host
  help                             Show this help
  quit / exit                      Disconnect
";

pub fn format_participants(participants: &ParticipantMap) -> String {
    let mut output = String::new();
    output.push_str("ASN      | Name\r\n");
    output.push_str("---------+-------------------------------\r\n");
    let mut entries: Vec<_> = participants.all().collect();
    entries.sort_by_key(|p| p.asn);
    for p in entries {
        output.push_str(&format!("AS{:<6} | {}\r\n", p.asn, p.name));
    }
    output
}

/// Telnet frontend server.
///
/// Provides unauthenticated, public-tier access to the looking glass.
/// Presents a simple text menu and accepts line-oriented commands.
pub struct TelnetServer {
    bind_addr: String,
    state: Arc<TelnetState>,
}

impl TelnetServer {
    pub fn new(bind_addr: String, state: Arc<TelnetState>) -> Self {
        Self { bind_addr, state }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        info!("Telnet server listening on {}", self.bind_addr);

        loop {
            let (socket, addr) = listener.accept().await?;
            info!("Telnet connection from {}", addr);
            let state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_telnet_session(socket, addr, state).await {
                    warn!("Telnet session error from {}: {}", addr, e);
                }
                info!("Telnet session ended for {}", addr);
            });
        }
    }
}

/// Split input into (completed_tokens, partial_token) for completion.
/// If input ends with whitespace, partial is empty.
fn split_for_completion(input: &str) -> (Vec<&str>, &str) {
    if input.is_empty() || input.ends_with(' ') {
        let tokens: Vec<&str> = input.split_whitespace().collect();
        (tokens, "")
    } else {
        let tokens: Vec<&str> = input.split_whitespace().collect();
        if tokens.is_empty() {
            (vec![], "")
        } else {
            let partial = tokens[tokens.len() - 1];
            (tokens[..tokens.len() - 1].to_vec(), partial)
        }
    }
}

/// Format completions as a two-column IOS-style help table.
fn format_completions(completions: &[completion::Completion]) -> String {
    let mut out = String::new();
    for c in completions {
        out.push_str(&format!("  {:<20} {}\r\n", c.keyword, c.help));
    }
    out
}

async fn handle_telnet_session(
    socket: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    state: Arc<TelnetState>,
) -> Result<()> {
    let (mut reader, mut writer) = socket.into_split();
    let identity = Identity::anonymous();
    let prompt = "> ";

    // Negotiate character mode: WILL ECHO + WILL SGA
    writer
        .write_all(&[IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA])
        .await?;
    writer.flush().await?;

    // Banner
    writer
        .write_all(
            format!(
                "\r\n{}\r\nType 'help' or '?' for available commands.\r\n\r\n",
                state.service_name
            )
            .as_bytes(),
        )
        .await?;

    let mut line_buf = String::new();

    loop {
        // Prompt
        writer.write_all(prompt.as_bytes()).await?;
        writer.flush().await?;
        line_buf.clear();

        // Interactive line editor — read char by char
        let line = match read_line(&mut reader, &mut writer, &mut line_buf, prompt).await? {
            Some(line) => line,
            None => break, // EOF / Ctrl+D
        };

        let line = line.trim().to_string();

        // Quit commands (with abbreviation support)
        let lower = line.to_lowercase();
        if ("quit".starts_with(&lower) && !lower.is_empty())
            || ("exit".starts_with(&lower) && lower.starts_with("ex"))
        {
            writer.write_all(b"Goodbye.\r\n").await?;
            break;
        }

        // Parse command
        let command = match parse_command(&line) {
            Ok(cmd) => cmd,
            Err(ParseError::Empty) => continue,
            Err(e) => {
                writer
                    .write_all(format!("{e}\r\n").as_bytes())
                    .await?;
                continue;
            }
        };

        // Handle help locally
        if command.resource == Resource::Help {
            writer.write_all(HELP_TEXT.as_bytes()).await?;
            continue;
        }

        // Handle participants locally
        if command.resource == Resource::Participants {
            let output = format_participants(&state.participants);
            writer.write_all(output.as_bytes()).await?;
            continue;
        }

        // Policy check
        match state
            .policy
            .evaluate(&command, &identity, &state.participants)
        {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny { reason } => {
                writer
                    .write_all(format!("Denied: {reason}\r\n").as_bytes())
                    .await?;
                continue;
            }
        }

        // Rate limit
        let rate_key = crate::ratelimit::ip_to_rate_key(peer_addr.ip());
        let _guard = match state.rate_limiter.acquire(&rate_key).await {
            Ok(guard) => guard,
            Err(e) => {
                writer
                    .write_all(format!("Rate limited: {e}\r\n").as_bytes())
                    .await?;
                continue;
            }
        };

        // Dispatch to device backend
        let result = state.device_pool.execute(&command).await;
        match result {
            Ok(output) => {
                writer.write_all(output.as_bytes()).await?;
                if !output.ends_with('\n') {
                    writer.write_all(b"\r\n").await?;
                }
            }
            Err(e) => {
                writer
                    .write_all(format!("Error: {e}\r\n").as_bytes())
                    .await?;
            }
        }
    }

    Ok(())
}

/// Interactive line reader with Tab completion and ? help (IOS-style).
///
/// Reads from the telnet socket one byte at a time (character mode).
/// Returns `Some(line)` on Enter, `None` on EOF/Ctrl+D.
async fn read_line(
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
    buf: &mut String,
    prompt: &str,
) -> Result<Option<String>> {
    let mut byte = [0u8; 1];

    loop {
        if reader.read(&mut byte).await? == 0 {
            return Ok(None); // EOF
        }

        match byte[0] {
            // --- Telnet IAC sequence ---
            IAC => {
                let mut cmd = [0u8; 1];
                if reader.read_exact(&mut cmd).await.is_err() {
                    return Ok(None);
                }
                match cmd[0] {
                    WILL | WONT | DO | DONT => {
                        // Read and discard the option byte
                        let mut opt = [0u8; 1];
                        let _ = reader.read_exact(&mut opt).await;
                    }
                    SB => {
                        // Skip until IAC SE
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
                        // Escaped 0xFF — treat as data
                        buf.push(0xFF as char);
                        writer.write_all(&[0xFF]).await?;
                    }
                    _ => {} // Unknown, skip
                }
            }

            // --- Enter (CR) ---
            0x0D => {
                // Consume optional LF or NUL after CR
                let mut peek = [0u8; 1];
                // Use a small timeout so we don't hang if no follow-up byte
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(50),
                    reader.read_exact(&mut peek),
                )
                .await;
                writer.write_all(b"\r\n").await?;
                writer.flush().await?;
                return Ok(Some(buf.clone()));
            }

            // --- LF alone ---
            0x0A => {
                writer.write_all(b"\r\n").await?;
                writer.flush().await?;
                return Ok(Some(buf.clone()));
            }

            // --- Backspace / DEL ---
            0x08 | 0x7F => {
                if !buf.is_empty() {
                    buf.pop();
                    // Move cursor back, overwrite with space, move back again
                    writer.write_all(b"\x08 \x08").await?;
                    writer.flush().await?;
                }
            }

            // --- Tab (completion) ---
            0x09 => {
                let (tokens, partial) = split_for_completion(buf);
                let token_refs: Vec<&str> = tokens.iter().map(|s| s.as_ref()).collect();

                if let Some(suffix) = completion::tab_complete(&token_refs, partial) {
                    // Unambiguous — append completion
                    buf.push_str(&suffix);
                    writer.write_all(suffix.as_bytes()).await?;
                    writer.flush().await?;
                } else {
                    // Ambiguous — show options, then redisplay prompt + buffer
                    let completions = completion::get_completions(&token_refs, partial);
                    if !completions.is_empty() {
                        writer.write_all(b"\r\n").await?;
                        writer
                            .write_all(format_completions(&completions).as_bytes())
                            .await?;
                        // Redisplay prompt and current buffer
                        writer
                            .write_all(format!("{prompt}{buf}").as_bytes())
                            .await?;
                        writer.flush().await?;
                    }
                }
            }

            // --- ? (inline help) ---
            0x3F => {
                // IOS-style: ? shows help without being added to the buffer.
                // If preceded by a non-space char, show matches for that partial.
                // If preceded by space (or empty), show all next-level options.
                let (tokens, partial) = split_for_completion(buf);
                let token_refs: Vec<&str> = tokens.iter().map(|s| s.as_ref()).collect();
                let completions = completion::get_completions(&token_refs, partial);

                writer.write_all(b"\r\n").await?;
                if completions.is_empty() {
                    writer.write_all(b"  No completions available\r\n").await?;
                } else {
                    writer
                        .write_all(format_completions(&completions).as_bytes())
                        .await?;
                }
                // Redisplay prompt and current buffer
                writer
                    .write_all(format!("{prompt}{buf}").as_bytes())
                    .await?;
                writer.flush().await?;
            }

            // --- Ctrl+C ---
            0x03 => {
                writer.write_all(b"^C\r\n").await?;
                buf.clear();
                // Redisplay prompt
                writer.write_all(prompt.as_bytes()).await?;
                writer.flush().await?;
            }

            // --- Ctrl+D ---
            0x04 => {
                if buf.is_empty() {
                    writer.write_all(b"\r\n").await?;
                    return Ok(None);
                }
                // Non-empty buffer: ignore Ctrl+D (IOS behavior)
            }

            // --- Escape sequences (arrow keys, etc.) ---
            0x1B => {
                // Read [ and the direction byte, discard
                let mut seq = [0u8; 2];
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(50),
                    reader.read_exact(&mut seq),
                )
                .await;
                // Ignore arrow keys for now (no cursor movement support)
            }

            // --- Printable characters ---
            c if c >= 0x20 && c < 0x7F => {
                buf.push(c as char);
                writer.write_all(&[c]).await?;
                writer.flush().await?;
            }

            // --- Everything else: ignore ---
            _ => {}
        }
    }
}
