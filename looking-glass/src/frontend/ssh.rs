use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use anyhow::Result;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodKind};
use russh::keys::{Certificate, PublicKey};
use russh::keys::ssh_key::{self, Fingerprint, HashAlg};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::identity::Identity;
use crate::oidc::OidcClient;

use crate::service::LookingGlass;

use super::common::{
    CommandAction, LineEditor, LineEvent, SessionWriter, PROMPT,
};

/// SSH frontend server.
///
/// Provides authenticated access via SSH certificates signed by
/// the LG's own CA key. Users can authenticate via OIDC device flow
/// ("login" command) and receive certificates injected into their
/// SSH agent for fast re-authentication.
pub struct SshFrontend {
    bind_addr: String,
    lg: Arc<LookingGlass>,
    config: Arc<server::Config>,
    /// CA private key for signing user certificates (None = cert issuance disabled)
    ca_key: Option<Arc<ssh_key::PrivateKey>>,
    /// Fingerprint of the CA public key for cert verification
    ca_fingerprint: Option<Fingerprint>,
    /// OIDC client for device auth flow (None = login command disabled)
    oidc_client: Option<OidcClient>,
    /// Certificate lifetime in seconds
    cert_lifetime_secs: u64,
}

impl SshFrontend {
    pub fn new(
        bind_addr: String,
        host_key_path: &str,
        ca_key_path: Option<&str>,
        oidc_client: Option<OidcClient>,
        cert_lifetime_secs: u64,
        lg: Arc<LookingGlass>,
    ) -> Result<Self> {
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
            inactivity_timeout: Some(lg.connection_tracker.idle_timeout),
            auth_rejection_time: std::time::Duration::from_secs(1),
            ..Default::default()
        };

        Ok(Self {
            bind_addr,
            lg,
            config: Arc::new(config),
            ca_key,
            ca_fingerprint,
            oidc_client,
            cert_lifetime_secs,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        info!("SSH server listening on {}", self.bind_addr);

        let mut server_impl = SshServerImpl {
            lg: self.lg.clone(),
            ca_key: self.ca_key.clone(),
            ca_fingerprint: self.ca_fingerprint,
            oidc_client: self.oidc_client.clone(),
            cert_lifetime_secs: self.cert_lifetime_secs,
        };
        server_impl.run_on_socket(self.config.clone(), &listener).await?;
        Ok(())
    }
}

/// russh Server trait implementation — factory for per-client handlers.
struct SshServerImpl {
    lg: Arc<LookingGlass>,
    ca_key: Option<Arc<ssh_key::PrivateKey>>,
    ca_fingerprint: Option<Fingerprint>,
    oidc_client: Option<OidcClient>,
    cert_lifetime_secs: u64,
}

impl server::Server for SshServerImpl {
    type Handler = SshSessionHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        info!("SSH connection from {:?}", peer_addr);
        SshSessionHandler {
            lg: self.lg.clone(),
            ca_key: self.ca_key.clone(),
            ca_fingerprint: self.ca_fingerprint,
            oidc_client: self.oidc_client.clone(),
            cert_lifetime_secs: self.cert_lifetime_secs,
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
    lg: Arc<LookingGlass>,
    ca_key: Option<Arc<ssh_key::PrivateKey>>,
    ca_fingerprint: Option<Fingerprint>,
    oidc_client: Option<OidcClient>,
    cert_lifetime_secs: u64,
    peer_addr: Option<std::net::SocketAddr>,
    identity: Arc<std::sync::Mutex<Identity>>,
    cert_info: Option<CertInfo>,
    login_in_progress: Arc<AtomicBool>,
    editor: LineEditor,
    channel_id: Option<ChannelId>,
    session_handle: Option<server::Handle>,
    /// Terminal type from PTY request (e.g. "xterm-256color").
    term: Option<String>,
}

impl SshSessionHandler {
    /// Determine the ColorMode based on the client's terminal type.
    ///
    /// Terminals that advertise 256-color or truecolor support (xterm-256color,
    /// screen-256color, tmux-256color, etc.) get Rich mode with emoji.
    /// Other PTY terminals get Color mode. No PTY (exec) gets Color.
    fn color_mode(&self) -> crate::format::ColorMode {
        match self.term.as_deref() {
            Some(t) if term_supports_rich(t) => crate::format::ColorMode::Rich,
            _ => crate::format::ColorMode::Color,
        }
    }

    /// Extract identity from an SSH public key (plain key auth).
    fn extract_identity_from_key(&self, _public_key: &PublicKey) -> Identity {
        // Plain public key auth — no OIDC claims available.
        Identity::anonymous()
    }

    /// Verify an SSH certificate against the CA fingerprint and extract identity.
    fn verify_and_extract_cert_identity(&self, certificate: &Certificate) -> Option<Identity> {
        // Verify the certificate is signed by our CA
        if let Some(ref ca_fp) = self.ca_fingerprint {
            let ca_fps = [*ca_fp];
            if let Err(e) = certificate.validate(ca_fps.iter()) {
                warn!(error = %e, "SSH certificate validation failed");
                return None;
            }
            debug!("SSH certificate validated against CA");
        } else {
            // No CA configured — accept all certs (dev mode)
            debug!("no CA key configured, accepting certificate without validation");
        }

        // Extract identity: email from key_id, groups from principals
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
        Some(Identity::from_oidc_claims(email, groups, &self.lg.group_prefix))
    }

    /// Kick off the OIDC login flow in a background task.
    ///
    /// Spawns a tokio task so the russh event loop can flush output to the
    /// client while the OIDC device-code poll loop runs.  The task uses
    /// `Handle::data()` (which works outside the handler) instead of
    /// `Session::data()` (which only queues data until the handler returns).
    async fn start_login(&mut self, session: &mut Session) {
        // Already authenticated?
        let already_auth = {
            let id = self.identity.lock().unwrap();
            id.authenticated.then(|| {
                id.email.as_deref().unwrap_or("unknown").to_string()
            })
        };
        if let Some(email) = already_auth {
            let msg = format!("Already authenticated as {email}\n{PROMPT}");
            self.write_data(session, msg.as_bytes()).await;
            return;
        }

        // Prevent concurrent login attempts
        if self.login_in_progress.swap(true, Ordering::SeqCst) {
            self.write_data(session, format!("Login already in progress...\n{PROMPT}").as_bytes()).await;
            return;
        }

        let oidc = match &self.oidc_client {
            Some(c) => c.clone(),
            None => {
                self.login_in_progress.store(false, Ordering::SeqCst);
                self.write_data(session, format!("OIDC authentication not configured.\n{PROMPT}").as_bytes()).await;
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
        let group_prefix = self.lg.group_prefix.clone();
        let identity = self.identity.clone();
        let login_in_progress = self.login_in_progress.clone();

        // "Starting..." is queued on Session and flushed when handler returns.
        self.write_data(session, b"\nStarting authentication...\n").await;

        tokio::spawn(async move {
            // Helper to write with line-ending transformation (can't use self.write_data in spawned task)
            async fn write(handle: &server::Handle, channel_id: ChannelId, data: &[u8]) {
                let transformed = transform_line_endings(data);
                let _ = handle.data(channel_id, CryptoVec::from_slice(&transformed)).await;
            }

            // Start device authorization flow
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

            // Poll for token
            let claims = match oidc.poll_for_token(&auth_state).await {
                Ok(c) => c,
                Err(e) => {
                    let msg = format!("\nAuthentication failed: {e}\n> ");
                    write(&handle, channel_id, msg.as_bytes()).await;
                    login_in_progress.store(false, Ordering::SeqCst);
                    return;
                }
            };

            // Upgrade session identity
            let new_identity = Identity::from_oidc_claims(
                claims.email.clone(),
                claims.groups.clone(),
                &group_prefix,
            );
            let asn_list: Vec<String> = new_identity.asns.iter().map(|a| format!("AS{a}")).collect();
            let asn_display = if asn_list.is_empty() {
                String::new()
            } else {
                format!(" ({})", asn_list.join(", "))
            };
            *identity.lock().unwrap() = new_identity;

            let msg = format!(
                "\nAuthenticated as {}{asn_display}\n",
                claims.email
            );
            write(&handle, channel_id, msg.as_bytes()).await;

            // Try to inject certificate into SSH agent
            if let Some(ca_key) = ca_key {
                match inject_agent_cert(&handle, &ca_key, &claims, cert_lifetime_secs).await {
                    Ok(true) => {
                        let hrs = cert_lifetime_secs / 3600;
                        let msg = format!("Certificate added to SSH agent (valid {hrs} hours)\n");
                        write(&handle, channel_id, msg.as_bytes()).await;
                    }
                    Ok(false) => {
                        write(&handle, channel_id, b"(No SSH agent detected \xe2\x80\x94 session-only auth, no certificate issued)\n").await;
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to inject certificate into SSH agent");
                        let msg = format!("(Could not inject certificate: {e})\n");
                        write(&handle, channel_id, msg.as_bytes()).await;
                    }
                }
            } else {
                write(&handle, channel_id, b"(SSH CA not configured \xe2\x80\x94 session-only auth)\n").await;
            }

            let prompt_msg = format!("\n{PROMPT}");
            write(&handle, channel_id, prompt_msg.as_bytes()).await;
            login_in_progress.store(false, Ordering::SeqCst);
        });
    }

    /// Write data to the SSH channel, converting \n to \r\n for PTY.
    ///
    /// All internal text uses Unix line endings (\n). This method transforms
    /// to the \r\n required by SSH PTY at the output boundary, so callers
    /// don't need to worry about line endings.
    async fn write_data(&self, session: &mut Session, data: &[u8]) {
        if let Some(ch) = self.channel_id {
            // Transform \n to \r\n, but don't double-transform \r\n
            let transformed = transform_line_endings(data);
            let _ = session.data(ch, CryptoVec::from_slice(&transformed));
        }
    }

    /// Process a completed line using the shared dispatch_command.
    /// Returns the CommandAction so caller can decide whether to show prompt.
    async fn process_line(&mut self, line: &str, session: &mut Session) -> CommandAction {
        let identity = self.identity.lock().unwrap().clone();
        let rate_key = if identity.authenticated {
            identity.email.clone().unwrap_or_else(|| "unknown".to_string())
        } else {
            self.peer_addr
                .map(|a| crate::ratelimit::ip_to_rate_key(a.ip()))
                .unwrap_or_else(|| "unknown".to_string())
        };

        let mut writer = SshWriter {
            channel_id: self.channel_id,
            session,
        };

        match super::common::dispatch_command(line, &self.lg, &identity, &rate_key, self.color_mode(), &mut writer).await {
            Ok(CommandAction::Quit) => {
                if let Some(ch) = self.channel_id {
                    let _ = writer.session.close(ch);
                }
                CommandAction::Quit
            }
            Ok(CommandAction::Login) => {
                // writer borrows session; drop it before start_login
                drop(writer);
                self.start_login(session).await;
                CommandAction::Login
            }
            Ok(CommandAction::Continue) => CommandAction::Continue,
            Err(e) => {
                warn!(error = %e, "dispatch_command error");
                CommandAction::Continue
            }
        }
    }
}

/// SessionWriter implementation for SSH.
/// Delegates to write_data which transforms \n → \r\n.
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
        // Accept all offered keys (signature will be verified by russh)
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
        // Reject keyboard-interactive — we want pubkey (opkssh) auth
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
        // Send service banner
        let mut banner = format!(
            "\n{}\n",
            crate::format::format_banner(&self.lg.service_name)
        );
        // If authenticated via certificate, show identity/permissions banner
        let identity = self.identity.lock().unwrap().clone();
        if identity.authenticated {
            if let Some(ref ci) = self.cert_info {
                banner.push('\n');
                banner.push_str(&crate::format::format_auth_banner(
                    &identity,
                    ci.valid_before,
                    self.lg.admin_group(),
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
        // Single command execution (e.g. `ssh -p 2222 lg.sfmix.org "show interfaces status"`)
        let cmd_str = String::from_utf8_lossy(data).to_string();
        debug!(command = cmd_str, "SSH exec request");

        self.channel_id = Some(channel);
        self.process_line(&cmd_str, session).await;

        // Close channel after exec
        let _ = session.close(channel);
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Interactive shell: feed bytes through shared LineEditor
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

        // Flush accumulated echo/output
        if !output.is_empty() {
            self.write_data(session, &output).await;
        }

        // Process any completed lines (interactive shell shows prompt after each)
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

/// Encode a byte slice as an SSH wire-format string (uint32 length + data).
fn encode_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Check if a terminal type string indicates a rich/modern terminal
/// capable of displaying emoji and Unicode box drawing.
///
/// Matches common 256-color and truecolor terminal types:
/// xterm-256color, screen-256color, tmux-256color, alacritty, kitty,
/// wezterm, ghostty, foot, etc.
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

/// Transform \n to \r\n for SSH PTY output, without double-transforming \r\n.
fn transform_line_endings(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 40); // estimate ~2.5% growth
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

/// Generate an SSH certificate and inject it into the user's forwarded agent.
/// Returns Ok(true) if injected, Ok(false) if no agent available.
///
/// This is a free function (not a method) so it can be called from the
/// spawned login task which only has a Handle, not a Session.
async fn inject_agent_cert(
    handle: &server::Handle,
    ca_key: &ssh_key::PrivateKey,
    claims: &crate::oidc::OidcClaims,
    cert_lifetime_secs: u64,
) -> Result<bool> {
    // Try to open agent channel
    let agent_channel = match handle.channel_open_agent().await {
        Ok(ch) => ch,
        Err(e) => {
            debug!(error = %e, "no agent forwarding available");
            return Ok(false);
        }
    };

    // Generate ephemeral Ed25519 keypair
    let ephemeral_key = ssh_key::PrivateKey::random(
        &mut rand::thread_rng(),
        ssh_key::Algorithm::Ed25519,
    ).map_err(|e| anyhow::anyhow!("failed to generate ephemeral key: {e}"))?;

    // Build certificate
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
    ).map_err(|e| anyhow::anyhow!("cert builder: {e}"))?;
    builder.cert_type(ssh_key::certificate::CertType::User)
        .map_err(|e| anyhow::anyhow!("cert type: {e}"))?;
    builder.key_id(&claims.email)
        .map_err(|e| anyhow::anyhow!("key id: {e}"))?;
    // Groups encoded as principals (conventional SSH cert practice)
    for group in &claims.groups {
        builder.valid_principal(group)
            .map_err(|e| anyhow::anyhow!("principal {group}: {e}"))?;
    }
    builder.extension("permit-pty", "")
        .map_err(|e| anyhow::anyhow!("ext permit-pty: {e}"))?;
    let cert = builder.sign(ca_key)
        .map_err(|e| anyhow::anyhow!("cert sign: {e}"))?;

    // Build the SSH agent protocol message manually, because russh's
    // AgentClient::add_identity doesn't support certificate identities.
    //
    // Wire format for SSH_AGENTC_ADD_ID_CONSTRAINED with Ed25519 cert:
    //   uint32  message_length
    //   byte    25 (SSH_AGENTC_ADD_ID_CONSTRAINED)
    //   string  "ssh-ed25519-cert-v01@openssh.com"
    //   string  certificate_blob
    //   string  ed25519_public_key (32 bytes)
    //   string  ed25519_private_key (64 bytes: seed || public)
    //   string  comment
    //   byte    1 (CONSTRAIN_LIFETIME)
    //   uint32  seconds
    let cert_blob = cert.to_bytes()
        .map_err(|e| anyhow::anyhow!("cert encode: {e}"))?;

    let ed25519_kp = ephemeral_key.key_data().ed25519()
        .ok_or_else(|| anyhow::anyhow!("ephemeral key is not Ed25519"))?;
    let seed = ed25519_kp.private.to_bytes();
    let pubkey_bytes: &[u8] = ed25519_kp.public.as_ref();
    // OpenSSH agent expects 64-byte "secret key" = seed || public
    let mut sk64 = Vec::with_capacity(64);
    sk64.extend_from_slice(&seed);
    sk64.extend_from_slice(pubkey_bytes);

    let lifetime = cert_lifetime_secs.min(u32::MAX as u64) as u32;
    let comment = format!("looking-glass:{}", claims.email);

    // Build message body (after length prefix)
    let mut body = Vec::new();
    body.push(25u8); // SSH_AGENTC_ADD_ID_CONSTRAINED
    encode_string(&mut body, b"ssh-ed25519-cert-v01@openssh.com");
    encode_string(&mut body, &cert_blob);
    encode_string(&mut body, pubkey_bytes);
    encode_string(&mut body, &sk64);
    encode_string(&mut body, comment.as_bytes());
    // Constraint: key lifetime
    body.push(1u8); // CONSTRAIN_LIFETIME
    body.extend_from_slice(&lifetime.to_be_bytes());

    // Prepend length prefix
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes());
    msg.extend_from_slice(&body);

    // Send via agent channel and read response
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = agent_channel.into_stream();
    stream.write_all(&msg).await
        .map_err(|e| anyhow::anyhow!("agent write failed: {e}"))?;
    stream.flush().await
        .map_err(|e| anyhow::anyhow!("agent flush failed: {e}"))?;

    // Read response: 4-byte length + 1-byte status
    let mut resp_len = [0u8; 4];
    stream.read_exact(&mut resp_len).await
        .map_err(|e| anyhow::anyhow!("agent read failed: {e}"))?;
    let rlen = u32::from_be_bytes(resp_len) as usize;
    let mut resp_body = vec![0u8; rlen];
    stream.read_exact(&mut resp_body).await
        .map_err(|e| anyhow::anyhow!("agent read body failed: {e}"))?;

    // SSH_AGENT_SUCCESS = 6, SSH_AGENT_FAILURE = 5
    if resp_body.first() == Some(&6) {
        info!(email = claims.email, "injected SSH certificate into user agent");
        Ok(true)
    } else {
        Err(anyhow::anyhow!("SSH agent rejected certificate (response: {:?})", resp_body.first()))
    }
}
