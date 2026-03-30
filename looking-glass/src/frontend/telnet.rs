use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::command::{parse_command, ParseError, Resource};
use crate::identity::Identity;
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::participants::ParticipantMap;
use crate::ratelimit::RateLimiter;
use crate::backend::pool::DevicePool;

/// Shared state passed to each telnet session.
pub struct TelnetState {
    pub service_name: String,
    pub policy: PolicyEngine,
    pub rate_limiter: RateLimiter,
    pub participants: ParticipantMap,
    pub device_pool: DevicePool,
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
                if let Err(e) = handle_telnet_session(socket, state).await {
                    warn!("Telnet session error from {}: {}", addr, e);
                }
                info!("Telnet session ended for {}", addr);
            });
        }
    }
}

const HELP_TEXT: &str = "\
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

async fn handle_telnet_session(
    socket: tokio::net::TcpStream,
    state: Arc<TelnetState>,
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut lines = BufReader::new(reader).lines();
    let identity = Identity::anonymous();

    // Banner
    writer.write_all(format!(
        "\r\n{}\r\nType 'help' for available commands.\r\n\r\n",
        state.service_name
    ).as_bytes()).await?;

    loop {
        // Prompt
        writer.write_all(b"> ").await?;
        writer.flush().await?;

        // Read line
        let line = match lines.next_line().await? {
            Some(line) => line,
            None => break, // EOF
        };

        let line = line.trim().to_string();

        // Quit commands
        if line.eq_ignore_ascii_case("quit") || line.eq_ignore_ascii_case("exit") {
            writer.write_all(b"Goodbye.\r\n").await?;
            break;
        }

        // Parse command
        let command = match parse_command(&line) {
            Ok(cmd) => cmd,
            Err(ParseError::Empty) => continue,
            Err(e) => {
                writer.write_all(format!("{e}\r\n", ).as_bytes()).await?;
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
        match state.policy.evaluate(&command, &identity, &state.participants) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny { reason } => {
                writer.write_all(format!("Denied: {reason}\r\n").as_bytes()).await?;
                continue;
            }
        }

        // Rate limit
        let _guard = match state.rate_limiter.acquire("global", "anonymous").await {
            Ok(guard) => guard,
            Err(e) => {
                writer.write_all(format!("Rate limited: {e}\r\n").as_bytes()).await?;
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
                writer.write_all(format!("Error: {e}\r\n").as_bytes()).await?;
            }
        }
    }

    Ok(())
}

fn format_participants(participants: &ParticipantMap) -> String {
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
