use std::sync::Arc;

use anyhow::Result;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, CryptoVec};
use russh::keys::key;
use tokio::net::TcpListener;
use tracing::{debug, info};

use crate::command::{parse_command, ParseError, Resource};
use crate::identity::Identity;
use crate::policy::PolicyDecision;
use crate::participants::ParticipantMap;
use crate::frontend::telnet::TelnetState;

/// SSH frontend server.
///
/// Provides authenticated access to the looking glass.
/// For Phase 2, accepts public key auth and extracts identity from
/// the SSH certificate extensions (opkssh embeds OIDC claims).
/// Falls back to accepting all keys with anonymous identity for now.
pub struct SshFrontend {
    bind_addr: String,
    state: Arc<TelnetState>,
    config: Arc<server::Config>,
}

impl SshFrontend {
    pub fn new(bind_addr: String, host_key_path: &str, state: Arc<TelnetState>) -> Result<Self> {
        let key = russh_keys::load_secret_key(host_key_path, None)
            .map_err(|e| anyhow::anyhow!("failed to load SSH host key {host_key_path}: {e}"))?;

        let config = server::Config {
            methods: russh::MethodSet::PUBLICKEY | russh::MethodSet::KEYBOARD_INTERACTIVE,
            keys: vec![key],
            inactivity_timeout: Some(std::time::Duration::from_secs(600)),
            auth_rejection_time: std::time::Duration::from_secs(1),
            ..Default::default()
        };

        Ok(Self {
            bind_addr,
            state,
            config: Arc::new(config),
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        info!("SSH server listening on {}", self.bind_addr);

        let mut server_impl = SshServerImpl {
            state: self.state.clone(),
        };
        server_impl.run_on_socket(self.config.clone(), &listener).await?;
        Ok(())
    }
}

/// russh Server trait implementation — factory for per-client handlers.
struct SshServerImpl {
    state: Arc<TelnetState>,
}

impl server::Server for SshServerImpl {
    type Handler = SshSessionHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        info!("SSH connection from {:?}", peer_addr);
        SshSessionHandler {
            state: self.state.clone(),
            peer_addr,
            identity: Identity::anonymous(),
            line_buf: String::new(),
            channel_id: None,
        }
    }
}

const SSH_HELP_TEXT: &str = "\
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

/// Per-client session handler.
struct SshSessionHandler {
    state: Arc<TelnetState>,
    peer_addr: Option<std::net::SocketAddr>,
    identity: Identity,
    line_buf: String,
    channel_id: Option<ChannelId>,
}

impl SshSessionHandler {
    /// Extract identity from an SSH public key.
    ///
    /// For opkssh certificates, the OIDC claims (email, groups) are embedded
    /// in certificate extensions. For now, we accept all keys as anonymous.
    /// TODO: Parse opkssh certificate extensions for real OIDC identity.
    fn extract_identity(&self, _public_key: &key::PublicKey) -> Identity {
        // TODO: When opkssh integration is complete, extract claims from
        // certificate critical options / extensions:
        //   - "email" → identity email
        //   - "groups" → comma-separated group list including "as{ASN}"
        // For now, treat SSH users as authenticated but without ASN claims.
        Identity::anonymous()
    }

    async fn write_data(&self, session: &mut Session, data: &[u8]) {
        if let Some(ch) = self.channel_id {
            session.data(ch, CryptoVec::from_slice(data));
        }
    }

    async fn process_line(&mut self, session: &mut Session) {
        let line = self.line_buf.trim().to_string();
        self.line_buf.clear();

        if line.is_empty() {
            self.write_data(session, b"\r\n> ").await;
            return;
        }

        if line.eq_ignore_ascii_case("quit") || line.eq_ignore_ascii_case("exit") {
            self.write_data(session, b"Goodbye.\r\n").await;
            if let Some(ch) = self.channel_id {
                session.close(ch);
            }
            return;
        }

        let command = match parse_command(&line) {
            Ok(cmd) => cmd,
            Err(ParseError::Empty) => {
                self.write_data(session, b"> ").await;
                return;
            }
            Err(e) => {
                let msg = format!("{e}\r\n> ");
                self.write_data(session, msg.as_bytes()).await;
                return;
            }
        };

        // Handle help locally
        if command.resource == Resource::Help {
            let mut out = SSH_HELP_TEXT.to_string();
            out.push_str("> ");
            self.write_data(session, out.as_bytes()).await;
            return;
        }

        // Handle participants locally
        if command.resource == Resource::Participants {
            let output = format_participants(&self.state.participants);
            let mut out = output;
            out.push_str("> ");
            self.write_data(session, out.as_bytes()).await;
            return;
        }

        // Policy check
        match self.state.policy.evaluate(&command, &self.identity, &self.state.participants) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny { reason } => {
                let msg = format!("Denied: {reason}\r\n> ");
                self.write_data(session, msg.as_bytes()).await;
                return;
            }
        }

        // Rate limit
        let user_key = self.peer_addr
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let _guard = match self.state.rate_limiter.acquire("global", &user_key).await {
            Ok(guard) => guard,
            Err(e) => {
                let msg = format!("Rate limited: {e}\r\n> ");
                self.write_data(session, msg.as_bytes()).await;
                return;
            }
        };

        // Dispatch to device backend
        let result = self.state.device_pool.execute(&command).await;
        let output = match result {
            Ok(output) => output,
            Err(e) => format!("Error: {e}"),
        };

        let mut response = output;
        if !response.ends_with('\n') {
            response.push_str("\r\n");
        }
        response.push_str("> ");
        self.write_data(session, response.as_bytes()).await;
    }
}

#[async_trait::async_trait]
impl server::Handler for SshSessionHandler {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: &key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        // Accept all offered keys (signature will be verified by russh)
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        debug!(user, "SSH public key auth accepted");
        self.identity = self.extract_identity(public_key);
        Ok(Auth::Accept)
    }

    async fn auth_keyboard_interactive(
        &mut self,
        _user: &str,
        _submethods: &str,
        _response: Option<server::Response<'async_trait>>,
    ) -> Result<Auth, Self::Error> {
        // Reject keyboard-interactive for now — we want pubkey (opkssh) auth
        Ok(Auth::Reject {
            proceed_with_methods: Some(russh::MethodSet::PUBLICKEY),
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        debug!("SSH channel opened");
        self.channel_id = Some(channel.id());
        Ok(true)
    }

    async fn shell_request(
        &mut self,
        _channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("SSH shell request");
        // Send banner and prompt
        let banner = format!(
            "\r\n{}\r\nType 'help' for available commands.\r\n\r\n> ",
            self.state.service_name
        );
        self.write_data(session, banner.as_bytes()).await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Single command execution (e.g. `ssh -p 2222 lg.sfmix.org "show interfaces status"`)
        let cmd_str = String::from_utf8_lossy(data).to_string();
        debug!(command = cmd_str, "SSH exec request");

        self.line_buf = cmd_str;
        self.channel_id = Some(channel);
        self.process_line(session).await;

        // Close channel after exec
        session.close(channel);
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Interactive shell: accumulate bytes until newline
        for &byte in data {
            match byte {
                b'\r' | b'\n' => {
                    // Echo the newline
                    self.write_data(session, b"\r\n").await;
                    self.process_line(session).await;
                }
                127 | 8 => {
                    // Backspace / DEL
                    if !self.line_buf.is_empty() {
                        self.line_buf.pop();
                        // Echo backspace-space-backspace to erase character
                        self.write_data(session, b"\x08 \x08").await;
                    }
                }
                3 => {
                    // Ctrl-C: clear line
                    self.line_buf.clear();
                    self.write_data(session, b"^C\r\n> ").await;
                }
                4 => {
                    // Ctrl-D: disconnect
                    self.write_data(session, b"\r\nGoodbye.\r\n").await;
                    if let Some(ch) = self.channel_id {
                        session.close(ch);
                    }
                }
                b if b >= 0x20 => {
                    // Printable character
                    self.line_buf.push(byte as char);
                    // Echo back
                    self.write_data(session, &[byte]).await;
                }
                _ => {} // Ignore other control characters
            }
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("SSH PTY request");
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("SSH channel EOF");
        session.close(channel);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("SSH session ended for {:?}", self.peer_addr);
        Ok(())
    }
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
