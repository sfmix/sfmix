use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use anyhow::Result;
use clap::Parser;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodKind};
use russh::keys::{Certificate, PublicKey};
use russh::keys::ssh_key::{self, Fingerprint, HashAlg};
use tracing::{debug, info, warn};

use looking_glass::frontend::common::{
    CommandAction, LineEditor, LineEvent, SessionWriter, PROMPT,
};
use looking_glass::format::ColorMode;
use looking_glass::identity::Identity;
use looking_glass::oidc::OidcClient;

mod dispatch;

use dispatch::ServiceContext;

#[derive(Parser)]
#[command(name = "lg-cli", about = "Looking glass CLI frontend (telnet + SSH)")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/looking-glass/lg-cli.yml")]
    config: PathBuf,
}

/// Configuration for lg-cli.
#[derive(Debug, serde::Deserialize)]
struct CliConfig {
    /// RPC backend URL (e.g. "http://127.0.0.1:9090")
    rpc_url: String,
    /// Env var name holding the shared secret for RPC authentication
    #[serde(default = "default_rpc_secret_env")]
    rpc_secret_env: String,
    /// Telnet listen config
    #[serde(default)]
    telnet: Option<TelnetConfig>,
    /// SSH listen config
    #[serde(default)]
    ssh: Option<SshConfig>,
    /// OIDC config for login command
    #[serde(default)]
    auth: Option<looking_glass::config::AuthConfig>,
}

#[derive(Debug, serde::Deserialize)]
struct TelnetConfig {
    #[serde(default = "default_telnet_bind")]
    bind: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, serde::Deserialize)]
struct SshConfig {
    #[serde(default = "default_ssh_bind")]
    bind: String,
    #[serde(default = "default_true")]
    enabled: bool,
    host_key: String,
    #[serde(default)]
    ca_key: Option<String>,
}

fn default_rpc_secret_env() -> String {
    "LG_RPC_SECRET".to_string()
}
fn default_telnet_bind() -> String {
    "[::]:23".to_string()
}
fn default_ssh_bind() -> String {
    "[::]:2222".to_string()
}
fn default_true() -> bool {
    true
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    info!("Loading configuration from {}", cli.config.display());
    let contents = std::fs::read_to_string(&cli.config)?;
    let config: CliConfig = serde_yaml::from_str(&contents)?;

    // Connect to lg-server RPC backend
    info!("Connecting to RPC backend at {}", config.rpc_url);
    let rpc_secret = std::env::var(&config.rpc_secret_env).unwrap_or_else(|_| {
        tracing::warn!("RPC secret env var '{}' not set", config.rpc_secret_env);
        String::new()
    });
    let ctx = Arc::new(ServiceContext::connect(&config.rpc_url, &rpc_secret).await?);
    info!(
        "Connected to {} ({} devices)",
        ctx.info.name, ctx.info.device_count
    );

    // Build OIDC client if configured
    let oidc_client = config.auth.as_ref().and_then(|auth| {
        match OidcClient::new(&auth.oidc) {
            Ok(c) => {
                info!("OIDC client configured for {}", auth.oidc.issuer);
                Some(c)
            }
            Err(e) => {
                tracing::warn!("Failed to create OIDC client: {e}");
                None
            }
        }
    });

    // Start telnet server
    if let Some(ref telnet_config) = config.telnet {
        if telnet_config.enabled {
            let bind = telnet_config.bind.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = run_telnet_server(&bind, ctx).await {
                    tracing::error!("Telnet server error: {e}");
                }
            });
        }
    }

    // Start SSH server
    if let Some(ref ssh_config) = config.ssh {
        if ssh_config.enabled {
            let bind = ssh_config.bind.clone();
            let host_key_path = ssh_config.host_key.clone();
            let ca_key_path = ssh_config.ca_key.clone();
            let ctx = ctx.clone();
            let oidc = oidc_client.clone();
            let cert_lifetime = config
                .auth
                .as_ref()
                .map(|a| a.oidc.cert_lifetime_secs)
                .unwrap_or(43200);
            let group_prefix = config
                .auth
                .as_ref()
                .map(|a| a.oidc.group_prefix.clone())
                .unwrap_or_else(|| "as".to_string());
            let admin_group = config
                .auth
                .as_ref()
                .map(|a| a.oidc.admin_group.clone())
                .unwrap_or_else(|| "IX Administrators".to_string());

            tokio::spawn(async move {
                if let Err(e) = run_ssh_server(
                    &bind,
                    &host_key_path,
                    ca_key_path.as_deref(),
                    oidc,
                    cert_lifetime,
                    group_prefix,
                    admin_group,
                    ctx,
                )
                .await
                {
                    tracing::error!("SSH server error: {e}");
                }
            });
        }
    }

    info!("lg-cli ready");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down");

    Ok(())
}

// ---------------------------------------------------------------------------
// SSH server — adapted from looking_glass::frontend::ssh
// ---------------------------------------------------------------------------

use tokio::net::TcpListener;

/// Transform \n to \r\n for SSH PTY output, without double-transforming \r\n.
fn transform_line_endings(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 40);
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\n' && (i == 0 || data[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

/// Encode a byte slice as an SSH wire-format string (uint32 length + data).
fn encode_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Check if a terminal type string indicates a rich/modern terminal.
fn term_supports_rich(term: &str) -> bool {
    let t = term.to_lowercase();
    t.contains("256color")
        || t.contains("truecolor")
        || t.contains("24bit")
        || t.contains("kitty")
        || t.contains("alacritty")
        || t.contains("wezterm")
        || t.contains("ghostty")
        || t.contains("foot")
        || t.contains("rio")
        || t.contains("contour")
}

async fn run_ssh_server(
    bind_addr: &str,
    host_key_path: &str,
    ca_key_path: Option<&str>,
    oidc_client: Option<OidcClient>,
    cert_lifetime_secs: u64,
    group_prefix: String,
    admin_group: String,
    ctx: Arc<ServiceContext>,
) -> Result<()> {
    let key = russh::keys::load_secret_key(host_key_path, None)
        .map_err(|e| anyhow::anyhow!("failed to load SSH host key {host_key_path}: {e}"))?;

    // Load CA key if configured
    let (ca_key, ca_fingerprint) = if let Some(path) = ca_key_path {
        let ca = russh::keys::load_secret_key(path, None)
            .map_err(|e| anyhow::anyhow!("failed to load SSH CA key {path}: {e}"))?;
        let fp = ca.fingerprint(HashAlg::Sha256);
        info!(fingerprint = %fp, "loaded SSH CA key");
        (Some(Arc::new(ca)), Some(fp))
    } else {
        info!("no SSH CA key configured, certificate issuance disabled");
        (None, None)
    };

    let mut methods = russh::MethodSet::empty();
    methods.push(MethodKind::PublicKey);
    methods.push(MethodKind::KeyboardInteractive);

    let config = server::Config {
        methods,
        keys: vec![key],
        inactivity_timeout: Some(std::time::Duration::from_secs(300)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        ..Default::default()
    };

    let listener = TcpListener::bind(bind_addr).await?;
    info!("SSH server listening on {}", bind_addr);

    let mut server_impl = SshServerImpl {
        ctx,
        ca_key,
        ca_fingerprint,
        oidc_client,
        cert_lifetime_secs,
        group_prefix,
        admin_group,
    };
    server_impl
        .run_on_socket(Arc::new(config), &listener)
        .await?;
    Ok(())
}

/// russh Server trait implementation — factory for per-client handlers.
struct SshServerImpl {
    ctx: Arc<ServiceContext>,
    ca_key: Option<Arc<ssh_key::PrivateKey>>,
    ca_fingerprint: Option<Fingerprint>,
    oidc_client: Option<OidcClient>,
    cert_lifetime_secs: u64,
    group_prefix: String,
    admin_group: String,
}

impl server::Server for SshServerImpl {
    type Handler = SshSessionHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        info!("SSH connection from {:?}", peer_addr);
        SshSessionHandler {
            ctx: self.ctx.clone(),
            ca_key: self.ca_key.clone(),
            ca_fingerprint: self.ca_fingerprint,
            oidc_client: self.oidc_client.clone(),
            cert_lifetime_secs: self.cert_lifetime_secs,
            group_prefix: self.group_prefix.clone(),
            admin_group: self.admin_group.clone(),
            peer_addr,
            identity: Arc::new(std::sync::Mutex::new(Identity::anonymous())),
            cert_info: None,
            login_in_progress: Arc::new(AtomicBool::new(false)),
            editor: LineEditor::new(),
            channel_id: None,
            session_handle: None,
            term: None,
        }
    }
}

/// Certificate metadata captured during auth for display in the welcome banner.
#[allow(dead_code)]
struct CertInfo {
    valid_after: u64,
    valid_before: u64,
}

/// Per-client session handler.
struct SshSessionHandler {
    ctx: Arc<ServiceContext>,
    ca_key: Option<Arc<ssh_key::PrivateKey>>,
    ca_fingerprint: Option<Fingerprint>,
    oidc_client: Option<OidcClient>,
    cert_lifetime_secs: u64,
    group_prefix: String,
    admin_group: String,
    peer_addr: Option<std::net::SocketAddr>,
    identity: Arc<std::sync::Mutex<Identity>>,
    cert_info: Option<CertInfo>,
    login_in_progress: Arc<AtomicBool>,
    editor: LineEditor,
    channel_id: Option<ChannelId>,
    #[allow(dead_code)]
    session_handle: Option<server::Handle>,
    term: Option<String>,
}

impl SshSessionHandler {
    fn color_mode(&self) -> ColorMode {
        match self.term.as_deref() {
            Some(t) if term_supports_rich(t) => ColorMode::Rich,
            _ => ColorMode::Color,
        }
    }

    fn extract_identity_from_key(&self, _public_key: &PublicKey) -> Identity {
        Identity::anonymous()
    }

    fn verify_and_extract_cert_identity(&self, certificate: &Certificate) -> Option<Identity> {
        if let Some(ref ca_fp) = self.ca_fingerprint {
            let ca_fps = [*ca_fp];
            if let Err(e) = certificate.validate(ca_fps.iter()) {
                warn!(error = %e, "SSH certificate validation failed");
                return None;
            }
            debug!("SSH certificate validated against CA");
        } else {
            debug!("no CA key configured, accepting certificate without validation");
        }

        let email = certificate.key_id().to_string();
        if email.is_empty() {
            warn!("SSH certificate has empty key_id (expected email)");
            return None;
        }
        let groups: Vec<String> = certificate
            .valid_principals()
            .iter()
            .map(|p| p.to_string())
            .collect();

        info!(email, groups = ?groups, "extracted identity from SSH certificate");
        Some(Identity::from_oidc_claims(email, groups, &self.group_prefix))
    }

    async fn start_login(&mut self, session: &mut Session) {
        let already_auth = {
            let id = self.identity.lock().unwrap();
            id.authenticated
                .then(|| id.email.as_deref().unwrap_or("unknown").to_string())
        };
        if let Some(email) = already_auth {
            let msg = format!("Already authenticated as {email}\n{PROMPT}");
            self.write_data(session, msg.as_bytes()).await;
            return;
        }

        if self.login_in_progress.swap(true, Ordering::SeqCst) {
            self.write_data(
                session,
                format!("Login already in progress...\n{PROMPT}").as_bytes(),
            )
            .await;
            return;
        }

        let oidc = match &self.oidc_client {
            Some(c) => c.clone(),
            None => {
                self.login_in_progress.store(false, Ordering::SeqCst);
                self.write_data(
                    session,
                    format!("OIDC authentication not configured.\n{PROMPT}").as_bytes(),
                )
                .await;
                return;
            }
        };

        let handle = session.handle();
        let channel_id = match self.channel_id {
            Some(id) => id,
            None => return,
        };
        let ca_key = self.ca_key.clone();
        let cert_lifetime_secs = self.cert_lifetime_secs;
        let group_prefix = self.group_prefix.clone();
        let identity = self.identity.clone();
        let login_in_progress = self.login_in_progress.clone();

        self.write_data(session, b"\nStarting authentication...\n")
            .await;

        tokio::spawn(async move {
            async fn write(handle: &server::Handle, channel_id: ChannelId, data: &[u8]) {
                let transformed = transform_line_endings(data);
                let _ = handle
                    .data(channel_id, CryptoVec::from_slice(&transformed))
                    .await;
            }

            let auth_state = match oidc.start_device_auth().await {
                Ok(s) => s,
                Err(e) => {
                    let msg = format!("Failed to start authentication: {e}\n> ");
                    write(&handle, channel_id, msg.as_bytes()).await;
                    login_in_progress.store(false, Ordering::SeqCst);
                    return;
                }
            };

            let msg = format!(
                "\nTo authenticate, visit: {}\nEnter code: {}\nWaiting for authentication...\n",
                auth_state.verification_uri, auth_state.user_code
            );
            write(&handle, channel_id, msg.as_bytes()).await;

            let claims = match oidc.poll_for_token(&auth_state).await {
                Ok(c) => c,
                Err(e) => {
                    let msg = format!("\nAuthentication failed: {e}\n> ");
                    write(&handle, channel_id, msg.as_bytes()).await;
                    login_in_progress.store(false, Ordering::SeqCst);
                    return;
                }
            };

            let new_identity =
                Identity::from_oidc_claims(claims.email.clone(), claims.groups.clone(), &group_prefix);
            let asn_list: Vec<String> = new_identity.asns.iter().map(|a| format!("AS{a}")).collect();
            let asn_display = if asn_list.is_empty() {
                String::new()
            } else {
                format!(" ({})", asn_list.join(", "))
            };
            *identity.lock().unwrap() = new_identity;

            let msg = format!("\nAuthenticated as {}{asn_display}\n", claims.email);
            write(&handle, channel_id, msg.as_bytes()).await;

            if let Some(ca_key) = ca_key {
                match inject_agent_cert(&handle, &ca_key, &claims, cert_lifetime_secs).await {
                    Ok(true) => {
                        let hrs = cert_lifetime_secs / 3600;
                        let msg = format!("Certificate added to SSH agent (valid {hrs} hours)\n");
                        write(&handle, channel_id, msg.as_bytes()).await;
                    }
                    Ok(false) => {
                        write(
                            &handle,
                            channel_id,
                            b"(No SSH agent detected \xe2\x80\x94 session-only auth, no certificate issued)\n",
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to inject certificate into SSH agent");
                        let msg = format!("(Could not inject certificate: {e})\n");
                        write(&handle, channel_id, msg.as_bytes()).await;
                    }
                }
            } else {
                write(
                    &handle,
                    channel_id,
                    b"(SSH CA not configured \xe2\x80\x94 session-only auth)\n",
                )
                .await;
            }

            let prompt_msg = format!("\n{PROMPT}");
            write(&handle, channel_id, prompt_msg.as_bytes()).await;
            login_in_progress.store(false, Ordering::SeqCst);
        });
    }

    async fn write_data(&self, session: &mut Session, data: &[u8]) {
        if let Some(ch) = self.channel_id {
            let transformed = transform_line_endings(data);
            let _ = session.data(ch, CryptoVec::from_slice(&transformed));
        }
    }

    async fn process_line(&mut self, line: &str, session: &mut Session) -> CommandAction {
        let identity = self.identity.lock().unwrap().clone();
        let rate_key = if identity.authenticated {
            identity
                .email
                .clone()
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            self.peer_addr
                .map(|a| format!("ssh:{}", a.ip()))
                .unwrap_or_else(|| "unknown".to_string())
        };

        let mut writer = SshWriter {
            channel_id: self.channel_id,
            session,
        };

        match dispatch::dispatch_command(line, &self.ctx, &identity, &rate_key, self.color_mode(), &mut writer)
            .await
        {
            Ok(CommandAction::Quit) => {
                if let Some(ch) = self.channel_id {
                    let _ = writer.session.close(ch);
                }
                CommandAction::Quit
            }
            Ok(CommandAction::Login) => {
                drop(writer);
                self.start_login(session).await;
                CommandAction::Login
            }
            Ok(CommandAction::Logout) => {
                let was_auth = {
                    let mut id = self.identity.lock().unwrap();
                    let was = id.authenticated;
                    *id = Identity::anonymous();
                    was
                };
                drop(writer);
                if was_auth {
                    self.write_data(session, b"Logged out. Returned to public tier.\n")
                        .await;
                } else {
                    self.write_data(session, b"Not authenticated.\n").await;
                }
                CommandAction::Continue
            }
            Ok(CommandAction::Continue) => CommandAction::Continue,
            Err(e) => {
                warn!(error = %e, "dispatch_command error");
                CommandAction::Continue
            }
        }
    }
}

struct SshWriter<'a> {
    channel_id: Option<ChannelId>,
    session: &'a mut Session,
}

impl<'a> SessionWriter for SshWriter<'a> {
    async fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        if let Some(ch) = self.channel_id {
            let transformed = transform_line_endings(data);
            let _ = self.session.data(ch, CryptoVec::from_slice(&transformed));
        }
        Ok(())
    }
}

impl server::Handler for SshSessionHandler {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        debug!(user, "SSH public key auth accepted");
        *self.identity.lock().unwrap() = self.extract_identity_from_key(public_key);
        Ok(Auth::Accept)
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        match self.verify_and_extract_cert_identity(certificate) {
            Some(identity) => {
                debug!(user, email = ?identity.email, "SSH certificate auth accepted");
                self.cert_info = Some(CertInfo {
                    valid_after: certificate.valid_after(),
                    valid_before: certificate.valid_before(),
                });
                *self.identity.lock().unwrap() = identity;
                Ok(Auth::Accept)
            }
            None => {
                debug!(user, "SSH certificate auth rejected (validation failed)");
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                })
            }
        }
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        _response: Option<server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let mut methods = russh::MethodSet::empty();
        methods.push(MethodKind::PublicKey);
        Ok(Auth::Reject {
            proceed_with_methods: Some(methods),
            partial_success: false,
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        debug!("SSH channel opened");
        self.channel_id = Some(channel.id());
        self.session_handle = Some(session.handle());
        Ok(true)
    }

    async fn shell_request(
        &mut self,
        _channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("SSH shell request");
        let mut banner = format!(
            "\n{}\n",
            looking_glass::format::format_banner(&self.ctx.info.name)
        );
        let identity = self.identity.lock().unwrap().clone();
        if identity.authenticated {
            if let Some(ref ci) = self.cert_info {
                banner.push('\n');
                banner.push_str(&looking_glass::format::format_auth_banner(
                    &identity,
                    Some(ci.valid_before),
                    &self.admin_group,
                ));
            }
        }
        banner.push_str("Type 'help' for available commands.\n\n> ");
        self.write_data(session, banner.as_bytes()).await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd_str = String::from_utf8_lossy(data).to_string();
        debug!(command = cmd_str, "SSH exec request");

        self.channel_id = Some(channel);
        self.process_line(&cmd_str, session).await;

        let _ = session.close(channel);
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut output = Vec::new();
        let mut lines: Vec<String> = Vec::new();
        let mut got_eof = false;

        for &byte in data {
            match self.editor.feed_byte(byte, &mut output) {
                LineEvent::Line(line) => {
                    lines.push(line);
                }
                LineEvent::Eof => {
                    got_eof = true;
                    break;
                }
                LineEvent::Continue => {}
            }
        }

        if !output.is_empty() {
            self.write_data(session, &output).await;
        }

        for line in lines {
            let action = self.process_line(&line, session).await;
            if matches!(action, CommandAction::Continue) {
                self.write_data(session, PROMPT.as_bytes()).await;
            }
        }

        if got_eof {
            self.write_data(session, b"Goodbye.\n").await;
            if let Some(ch) = self.channel_id {
                let _ = session.close(ch);
            }
        }

        Ok(())
    }

    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!(term, "SSH PTY request");
        self.term = Some(term.to_string());
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("SSH channel EOF");
        let _ = session.close(channel);
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

/// Generate an SSH certificate and inject it into the user's forwarded agent.
async fn inject_agent_cert(
    handle: &server::Handle,
    ca_key: &ssh_key::PrivateKey,
    claims: &looking_glass::oidc::OidcClaims,
    cert_lifetime_secs: u64,
) -> Result<bool> {
    let agent_channel = match handle.channel_open_agent().await {
        Ok(ch) => ch,
        Err(e) => {
            debug!(error = %e, "no agent forwarding available");
            return Ok(false);
        }
    };

    let ephemeral_key = ssh_key::PrivateKey::random(&mut rand::thread_rng(), ssh_key::Algorithm::Ed25519)
        .map_err(|e| anyhow::anyhow!("failed to generate ephemeral key: {e}"))?;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let valid_before = now + cert_lifetime_secs;

    let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
        &mut rand::thread_rng(),
        ephemeral_key.public_key().key_data().clone(),
        now,
        valid_before,
    )
    .map_err(|e| anyhow::anyhow!("cert builder: {e}"))?;
    builder
        .cert_type(ssh_key::certificate::CertType::User)
        .map_err(|e| anyhow::anyhow!("cert type: {e}"))?;
    builder
        .key_id(&claims.email)
        .map_err(|e| anyhow::anyhow!("key id: {e}"))?;
    for group in &claims.groups {
        builder
            .valid_principal(group)
            .map_err(|e| anyhow::anyhow!("principal {group}: {e}"))?;
    }
    builder
        .extension("permit-pty", "")
        .map_err(|e| anyhow::anyhow!("ext permit-pty: {e}"))?;
    let cert = builder
        .sign(ca_key)
        .map_err(|e| anyhow::anyhow!("cert sign: {e}"))?;

    let cert_blob = cert
        .to_bytes()
        .map_err(|e| anyhow::anyhow!("cert encode: {e}"))?;

    let ed25519_kp = ephemeral_key
        .key_data()
        .ed25519()
        .ok_or_else(|| anyhow::anyhow!("ephemeral key is not Ed25519"))?;
    let seed = ed25519_kp.private.to_bytes();
    let pubkey_bytes: &[u8] = ed25519_kp.public.as_ref();
    let mut sk64 = Vec::with_capacity(64);
    sk64.extend_from_slice(&seed);
    sk64.extend_from_slice(pubkey_bytes);

    let lifetime = cert_lifetime_secs.min(u32::MAX as u64) as u32;
    let comment = format!("looking-glass:{}", claims.email);

    let mut body = Vec::new();
    body.push(25u8); // SSH_AGENTC_ADD_ID_CONSTRAINED
    encode_string(&mut body, b"ssh-ed25519-cert-v01@openssh.com");
    encode_string(&mut body, &cert_blob);
    encode_string(&mut body, pubkey_bytes);
    encode_string(&mut body, &sk64);
    encode_string(&mut body, comment.as_bytes());
    body.push(1u8); // CONSTRAIN_LIFETIME
    body.extend_from_slice(&lifetime.to_be_bytes());

    let mut msg = Vec::with_capacity(4 + body.len());
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes());
    msg.extend_from_slice(&body);

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = agent_channel.into_stream();
    stream
        .write_all(&msg)
        .await
        .map_err(|e| anyhow::anyhow!("agent write failed: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| anyhow::anyhow!("agent flush failed: {e}"))?;

    let mut resp_len = [0u8; 4];
    stream
        .read_exact(&mut resp_len)
        .await
        .map_err(|e| anyhow::anyhow!("agent read failed: {e}"))?;
    let rlen = u32::from_be_bytes(resp_len) as usize;
    let mut resp_body = vec![0u8; rlen];
    stream
        .read_exact(&mut resp_body)
        .await
        .map_err(|e| anyhow::anyhow!("agent read body failed: {e}"))?;

    if resp_body.first() == Some(&6) {
        info!(email = claims.email, "injected SSH certificate into user agent");
        Ok(true)
    } else {
        Err(anyhow::anyhow!(
            "SSH agent rejected certificate (response: {:?})",
            resp_body.first()
        ))
    }
}

// ---------------------------------------------------------------------------
// Telnet server — adapted from looking_glass::frontend::telnet
// ---------------------------------------------------------------------------

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;

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

// Telnet protocol constants
const IAC: u8 = 255;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const SB: u8 = 250;
const SE: u8 = 240;
const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3;

async fn run_telnet_server(bind_addr: &str, ctx: Arc<ServiceContext>) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    info!("Telnet server listening on {}", bind_addr);

    loop {
        let (socket, addr) = listener.accept().await?;
        let ctx = ctx.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_telnet_session(socket, addr, ctx).await {
                tracing::debug!("Telnet session from {addr} ended: {e}");
            }
        });
    }
}

async fn handle_telnet_session(
    socket: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    ctx: Arc<ServiceContext>,
) -> Result<()> {
    let (mut reader, mut writer) = socket.into_split();

    // Send telnet negotiation: WILL ECHO, WILL SGA
    writer
        .write_all(&[IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA])
        .await?;

    // Send banner + prompt
    let banner = format!(
        "\n{} Looking Glass\n\nType 'help' for available commands.\n\n{}",
        ctx.info.name, PROMPT,
    );
    writer.write_all(to_crlf(banner.as_bytes()).as_slice()).await?;

    let identity = Identity::anonymous();
    let rate_key = format!("telnet:{}", addr.ip());
    let mut line_editor = LineEditor::new();
    let mut in_iac = false;
    let mut iac_state = 0u8;
    let mut buf = [0u8; 1024];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        for i in 0..n {
            let byte = buf[i];

            // Simple telnet IAC state machine
            if in_iac {
                match iac_state {
                    0 => {
                        // First byte after IAC
                        match byte {
                            WILL | WONT | DO | DONT => {
                                iac_state = 1;
                                continue;
                            }
                            SB => {
                                iac_state = 2;
                                continue;
                            }
                            _ => {
                                in_iac = false;
                                iac_state = 0;
                                continue;
                            }
                        }
                    }
                    1 => {
                        // Option byte after WILL/WONT/DO/DONT
                        in_iac = false;
                        iac_state = 0;
                        continue;
                    }
                    2 => {
                        // Inside subnegotiation, wait for IAC SE
                        if byte == IAC {
                            iac_state = 3;
                        }
                        continue;
                    }
                    3 => {
                        if byte == SE {
                            in_iac = false;
                            iac_state = 0;
                        } else {
                            iac_state = 2;
                        }
                        continue;
                    }
                    _ => {
                        in_iac = false;
                        iac_state = 0;
                    }
                }
            }

            if byte == IAC {
                in_iac = true;
                iac_state = 0;
                continue;
            }

            let mut echo = Vec::new();
            match line_editor.feed_byte(byte, &mut echo) {
                LineEvent::Continue => {
                    if !echo.is_empty() {
                        writer.write_all(&to_crlf(&echo)).await?;
                        writer.flush().await?;
                    }
                }
                LineEvent::Line(line) => {
                    if !echo.is_empty() {
                        writer.write_all(&to_crlf(&echo)).await?;
                    }
                    let mut tw = TelnetWriter { inner: &mut writer };
                    let action = dispatch::dispatch_command(
                        &line,
                        &ctx,
                        &identity,
                        &rate_key,
                        ColorMode::Plain,
                        &mut tw,
                    )
                    .await?;

                    match action {
                        CommandAction::Continue => {
                            writer
                                .write_all(to_crlf(PROMPT.as_bytes()).as_slice())
                                .await?;
                        }
                        CommandAction::Quit => return Ok(()),
                        CommandAction::Login => {
                            // TODO: OIDC login via RPC or local
                            writer
                                .write_all(
                                    to_crlf(b"Login not yet supported in lg-cli.\n")
                                        .as_slice(),
                                )
                                .await?;
                            writer
                                .write_all(to_crlf(PROMPT.as_bytes()).as_slice())
                                .await?;
                        }
                        CommandAction::Logout => {
                            writer
                                .write_all(to_crlf(PROMPT.as_bytes()).as_slice())
                                .await?;
                        }
                    }
                }
                LineEvent::Eof => return Ok(()),
            }
        }
    }

    Ok(())
}
