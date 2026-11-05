use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;

use crate::ratelimit::ConnectionTracker;

use crate::command::{ParseError, Resource};
use crate::format::ColorMode;
use crate::grammar::{self, parse_command};
use crate::identity::Identity;
use crate::service::{self, LookingGlass};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const PROMPT: &str = "> ";

/// Message shown just before an idle telnet/SSH session is disconnected.
pub fn idle_disconnect_notice(timeout: std::time::Duration) -> String {
    let secs = timeout.as_secs();
    let human = if secs >= 60 && secs.is_multiple_of(60) {
        format!("{} min", secs / 60)
    } else {
        format!("{secs}s")
    };
    format!("\n\nIdle timeout ({human} without input) \u{2014} disconnecting.\n")
}

/// `idle_timeout_secs` as an optional Duration (0 = disabled).
pub fn idle_timeout_from_secs(secs: u64) -> Option<std::time::Duration> {
    (secs > 0).then(|| std::time::Duration::from_secs(secs))
}

/// User-idle tracking for an interactive SSH shell.
///
/// russh's own `inactivity_timeout` resets on *any* client packet (including
/// ServerAliveInterval keepalives), so it can't see an idle user. This tracks
/// keystrokes instead; time spent running a command (`set_busy`) or waiting on
/// an OIDC login doesn't count. The watchdog task is aborted on drop.
pub struct IdleWatch {
    last_input: Arc<Mutex<tokio::time::Instant>>,
    busy: Arc<AtomicBool>,
    task: Option<tokio::task::AbortHandle>,
}

impl Default for IdleWatch {
    fn default() -> Self {
        Self {
            last_input: Arc::new(Mutex::new(tokio::time::Instant::now())),
            busy: Arc::new(AtomicBool::new(false)),
            task: None,
        }
    }
}

impl Drop for IdleWatch {
    fn drop(&mut self) {
        if let Some(t) = &self.task {
            t.abort();
        }
    }
}

impl IdleWatch {
    /// Record user input (or the end of a command).
    pub fn touch(&self) {
        *self.last_input.lock().unwrap() = tokio::time::Instant::now();
    }

    /// Mark a command as running (true) or finished (false; also touches).
    pub fn set_busy(&self, busy: bool) {
        if !busy {
            self.touch();
        }
        self.busy.store(busy, Ordering::SeqCst);
    }

    /// Start the watchdog: after `idle` without input, print a notice on
    /// `channel` and disconnect the session.
    pub fn start(
        &mut self,
        handle: russh::server::Handle,
        channel: russh::ChannelId,
        idle: std::time::Duration,
        login_in_progress: Arc<AtomicBool>,
    ) {
        self.touch();
        let last_input = self.last_input.clone();
        let busy = self.busy.clone();
        let task = tokio::spawn(async move {
            loop {
                let deadline = *last_input.lock().unwrap() + idle;
                tokio::time::sleep_until(deadline).await;
                let now = tokio::time::Instant::now();
                if busy.load(Ordering::SeqCst) || login_in_progress.load(Ordering::SeqCst) {
                    *last_input.lock().unwrap() = now;
                    continue;
                }
                if *last_input.lock().unwrap() + idle > now {
                    continue; // input arrived while we slept
                }
                tracing::info!(idle_secs = idle.as_secs(), "SSH session idle timeout");
                let notice = idle_disconnect_notice(idle).replace('\n', "\r\n");
                let _ = handle.data(channel, notice.into_bytes()).await;
                let _ = handle
                    .disconnect(
                        russh::Disconnect::ByApplication,
                        "idle timeout".into(),
                        "en".into(),
                    )
                    .await;
                return;
            }
        });
        if let Some(old) = self.task.replace(task.abort_handle()) {
            old.abort();
        }
    }
}

/// russh server config's transport `inactivity_timeout`: a backstop for dead
/// connections, a minute past the user-idle timeout so the watchdog's notice
/// wins the race.
pub fn ssh_inactivity_timeout(idle: Option<std::time::Duration>) -> Option<std::time::Duration> {
    idle.map(|d| d + std::time::Duration::from_secs(60))
}

/// Accept SSH connections, enforcing `tracker`'s connection limits before the
/// handshake (russh's `run_on_socket` has no admission hook).
pub async fn serve_ssh_with_limits<S>(
    listener: tokio::net::TcpListener,
    config: Arc<russh::server::Config>,
    tracker: &ConnectionTracker,
    server_impl: &mut S,
) -> Result<()>
where
    S: russh::server::Server,
    S::Handler: Send + 'static,
    <S::Handler as russh::server::Handler>::Error: std::fmt::Debug,
{
    use tokio::io::AsyncWriteExt;
    loop {
        let (mut socket, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "SSH accept failed");
                continue;
            }
        };
        let source_key = crate::ratelimit::ip_to_rate_key(addr.ip());
        let conn_guard = match tracker.try_admit(&source_key) {
            Ok(guard) => guard,
            Err(e) => {
                tracing::warn!("SSH connection rejected from {}: {}", addr, e);
                // Pre-version-exchange text is permitted by RFC 4253 §4.2;
                // `ssh -v` shows it.
                let _ = socket.write_all(format!("{e}\r\n").as_bytes()).await;
                continue;
            }
        };
        let config = config.clone();
        let handler = server_impl.new_client(Some(addr));
        tokio::spawn(async move {
            let _conn_guard = conn_guard;
            match russh::server::run_stream(config, socket, handler).await {
                Ok(session) => {
                    if let Err(e) = session.await {
                        tracing::debug!("SSH session from {} ended with error: {:?}", addr, e);
                    }
                }
                Err(e) => tracing::debug!("SSH connection setup from {} failed: {:?}", addr, e),
            }
        });
    }
}

pub const HELP_TEXT: &str = "\
Available commands:
  show interfaces status          Interface summary (name, status, speed)
  show interfaces <asn>           Filter interfaces by participant ASN
  show optics                     Transceiver DOM levels (all ports)
  show optics <asn>               Filter optics by participant ASN
  show optics inventory           Transceiver inventory (vendor/model/serial) [admin]
  show mac address-table          MAC address table
  show mac vlan <id>              Filter MAC table by VLAN ID
  show arp                         ARP table (IPv4 neighbor-to-MAC mapping)
  show ipv6 neighbors              IPv6 neighbor table (NDP)
  show lldp neighbors              LLDP neighbor table
  show participants                IXP participant list
  show participants <asn>         Detail for a specific participant
  show netbox                      NetBox cache status
  ping <destination>               Ping from the looking glass host
  traceroute <destination>         Traceroute from the looking glass host
  login                            Authenticate via OIDC (opens browser)
  whoami                           Show current identity and permissions
  logout                           Drop authentication (return to public tier)
  terminal length <n|0|auto>       Pager page length (0 = no paging; auto = window size)
  help                             Show this help
  quit / exit                      Disconnect

Device targeting:
  @<device> anywhere in command   Target a specific device (e.g. show int @switch01)
                                  Without @device, commands run on all devices
                                  (ping/traceroute run once, from the looking glass host)
";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------


/// Split input into (completed_tokens, partial_token) for completion.
/// If input ends with whitespace, partial is empty.
pub fn split_for_completion(input: &str) -> (Vec<&str>, &str) {
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
/// Uses \n line endings — each frontend transforms at the output boundary.
pub fn format_completions(completions: &[grammar::Completion]) -> String {
    let mut out = String::new();
    for c in completions {
        out.push_str(&format!("  {:<20} {}\n", c.keyword, c.help));
    }
    out
}

/// Check if `line` is a quit/exit command (with IOS-style abbreviation).
pub fn is_quit(line: &str) -> bool {
    let lower = line.to_lowercase();
    ("quit".starts_with(&lower) && !lower.is_empty())
        || ("exit".starts_with(&lower) && lower.starts_with("ex"))
}

// ---------------------------------------------------------------------------
// LineEditor — shared byte-at-a-time input processor
// ---------------------------------------------------------------------------

/// Events returned by `LineEditor::feed_byte`.
pub enum LineEvent {
    /// Byte consumed; keep reading. Output buffer may have echo data.
    Continue,
    /// A complete line is ready to process.
    Line(String),
    /// User requested disconnect (Ctrl+D on empty line).
    Eof,
}

enum EscState {
    Normal,
    Escape,        // saw 0x1B
    EscapeBracket, // saw 0x1B 0x5B
}

const HISTORY_MAX: usize = 100;

/// Hard cap on a single input line, in bytes.
///
/// Shared by the SSH and telnet frontends; telnet is the motivating case since
/// it is anonymous and public. The editor accumulates printable bytes until it
/// sees a newline — so without a cap one connection
/// that streams bytes and never presses Enter grows `buf` (and, once it does
/// press Enter, a `history` entry) without bound. The connection tracker caps
/// how MANY sessions an address gets, not how much memory each one may claim.
/// 4 KiB is far beyond any real command; input past it is dropped silently
/// rather than echoed, so a normal typist can never reach it.
const MAX_LINE_LEN: usize = 4096;

pub struct LineEditor {
    buf: String,
    esc_state: EscState,
    csi_byte_count: u8,
    history: Vec<String>,
    history_idx: Option<usize>,
    history_scratch: String,
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl LineEditor {
    pub fn new() -> Self {
        Self {
            buf: String::new(),
            esc_state: EscState::Normal,
            csi_byte_count: 0,
            history: Vec::new(),
            history_idx: None,
            history_scratch: String::new(),
        }
    }

    /// Access the current line buffer contents.
    pub fn buf(&self) -> &str {
        &self.buf
    }

    /// Clear the line buffer (used after processing a line externally).
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    fn replace_line(&mut self, new_buf: String, output: &mut Vec<u8>) {
        for _ in 0..self.buf.len() {
            output.extend_from_slice(b"\x08 \x08");
        }
        output.extend_from_slice(new_buf.as_bytes());
        self.buf = new_buf;
    }

    fn history_prev(&mut self, output: &mut Vec<u8>) {
        if self.history.is_empty() {
            return;
        }
        let new_idx = match self.history_idx {
            None => {
                self.history_scratch = self.buf.clone();
                self.history.len() - 1
            }
            Some(0) => 0,
            Some(idx) => idx - 1,
        };
        self.history_idx = Some(new_idx);
        let new_buf = self.history[new_idx].clone();
        self.replace_line(new_buf, output);
    }

    fn history_next(&mut self, output: &mut Vec<u8>) {
        let idx = match self.history_idx {
            None => return,
            Some(idx) => idx,
        };
        if idx + 1 < self.history.len() {
            let new_idx = idx + 1;
            self.history_idx = Some(new_idx);
            let new_buf = self.history[new_idx].clone();
            self.replace_line(new_buf, output);
        } else {
            self.history_idx = None;
            let scratch = self.history_scratch.clone();
            self.replace_line(scratch, output);
        }
    }

    fn push_history(&mut self) {
        let trimmed = self.buf.trim().to_string();
        if !trimmed.is_empty() && self.history.last().map(|s| s.as_str()) != Some(&trimmed) {
            if self.history.len() >= HISTORY_MAX {
                self.history.remove(0);
            }
            self.history.push(trimmed);
        }
        self.history_idx = None;
    }

    /// Process a single input byte. Echo/output bytes are appended to `output`
    /// using `\n` line endings (each frontend transforms to `\r\n` at output).
    ///
    /// Returns a `LineEvent` indicating what happened.
    pub fn feed_byte(&mut self, byte: u8, output: &mut Vec<u8>) -> LineEvent {
        // Escape sequence state machine
        match self.esc_state {
            EscState::Escape => {
                if byte == b'[' {
                    self.esc_state = EscState::EscapeBracket;
                    self.csi_byte_count = 0;
                } else {
                    self.esc_state = EscState::Normal;
                }
                return LineEvent::Continue;
            }
            EscState::EscapeBracket => {
                if (0x40..=0x7E).contains(&byte) {
                    // Terminal byte — act only on bare (no-parameter) sequences
                    if self.csi_byte_count == 0 {
                        match byte {
                            b'A' => self.history_prev(output), // up arrow
                            b'B' => self.history_next(output), // down arrow
                            _ => {}
                        }
                    }
                    self.esc_state = EscState::Normal;
                } else {
                    self.csi_byte_count = self.csi_byte_count.saturating_add(1);
                }
                return LineEvent::Continue;
            }
            EscState::Normal => {} // fall through to main match
        }

        match byte {
            // --- Enter (CR / LF) ---
            0x0D | 0x0A => {
                self.push_history();
                output.extend_from_slice(b"\n");
                let line = self.buf.clone();
                self.buf.clear();
                LineEvent::Line(line)
            }

            // --- Backspace / DEL ---
            0x08 | 0x7F => {
                if !self.buf.is_empty() {
                    self.buf.pop();
                    output.extend_from_slice(b"\x08 \x08");
                }
                LineEvent::Continue
            }

            // --- Tab (completion) ---
            0x09 => {
                let (tokens, partial) = split_for_completion(&self.buf);
                let token_refs: Vec<&str> = tokens.iter().map(|s| s.as_ref()).collect();

                if let Some(suffix) = grammar::tab_complete(&token_refs, partial) {
                    self.buf.push_str(&suffix);
                    output.extend_from_slice(suffix.as_bytes());
                } else {
                    let completions = grammar::get_completions(&token_refs, partial);
                    if !completions.is_empty() {
                        output.extend_from_slice(b"\n");
                        output.extend_from_slice(format_completions(&completions).as_bytes());
                        // Redisplay prompt and current buffer
                        output.extend_from_slice(PROMPT.as_bytes());
                        output.extend_from_slice(self.buf.as_bytes());
                    }
                }
                LineEvent::Continue
            }

            // --- ? (inline help) ---
            0x3F => {
                let (tokens, partial) = split_for_completion(&self.buf);
                let token_refs: Vec<&str> = tokens.iter().map(|s| s.as_ref()).collect();
                let completions = grammar::get_completions(&token_refs, partial);

                output.extend_from_slice(b"\n");
                if completions.is_empty() {
                    output.extend_from_slice(b"  No completions available\n");
                } else {
                    output.extend_from_slice(format_completions(&completions).as_bytes());
                }
                // Redisplay prompt and current buffer
                output.extend_from_slice(PROMPT.as_bytes());
                output.extend_from_slice(self.buf.as_bytes());
                LineEvent::Continue
            }

            // --- Ctrl+W (delete word) ---
            0x17 => {
                if !self.buf.is_empty() {
                    let orig_len = self.buf.len();
                    let trimmed = self.buf.trim_end().len();
                    let spaces_removed = orig_len - trimmed;
                    self.buf.truncate(trimmed);
                    let word_start = self.buf.rfind(' ').map(|i| i + 1).unwrap_or(0);
                    let chars_removed = self.buf.len() - word_start + spaces_removed;
                    self.buf.truncate(word_start);
                    for _ in 0..chars_removed {
                        output.extend_from_slice(b"\x08 \x08");
                    }
                }
                LineEvent::Continue
            }

            // --- Ctrl+U (delete line) ---
            0x15 => {
                if !self.buf.is_empty() {
                    let len = self.buf.len();
                    self.buf.clear();
                    for _ in 0..len {
                        output.extend_from_slice(b"\x08 \x08");
                    }
                }
                LineEvent::Continue
            }

            // --- Ctrl+C ---
            0x03 => {
                self.buf.clear();
                self.history_idx = None;
                output.extend_from_slice(b"^C\n");
                output.extend_from_slice(PROMPT.as_bytes());
                LineEvent::Continue
            }

            // --- Ctrl+P (previous history) ---
            0x10 => {
                self.history_prev(output);
                LineEvent::Continue
            }

            // --- Ctrl+N (next history) ---
            0x0E => {
                self.history_next(output);
                LineEvent::Continue
            }

            // --- Ctrl+D ---
            0x04 => {
                if self.buf.is_empty() {
                    output.extend_from_slice(b"\n");
                    LineEvent::Eof
                } else {
                    // Non-empty buffer: ignore (IOS behavior)
                    LineEvent::Continue
                }
            }

            // --- Escape ---
            0x1B => {
                self.esc_state = EscState::Escape;
                LineEvent::Continue
            }

            // --- Printable characters ---
            c if (0x20..0x7F).contains(&c) => {
                // Drop (don't echo) anything past the cap: echoing would let the
                // peer keep costing us output bytes for input we discard.
                if self.buf.len() < MAX_LINE_LEN {
                    self.buf.push(c as char);
                    output.push(c);
                }
                LineEvent::Continue
            }

            // --- Everything else: ignore ---
            _ => LineEvent::Continue,
        }
    }
}

// ---------------------------------------------------------------------------
// SessionWriter trait + dispatch_command
// ---------------------------------------------------------------------------

/// Minimal async write trait implemented by each frontend.
/// Data uses `\n` line endings; implementations transform to `\r\n`.
pub trait SessionWriter: Send {
    fn write_bytes(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Result of `dispatch_command` telling the frontend what to do next.
pub enum CommandAction {
    /// Command handled, show prompt and continue.
    Continue,
    /// User requested quit/exit.
    Quit,
    /// User requested login — frontend handles this its own way.
    Login,
    /// User requested logout — frontend resets identity to anonymous.
    Logout,
}

/// Shared command dispatch: parse → delegate to `LookingGlass::execute()` → render.
///
/// Login is NOT handled here — the frontend does that after receiving
/// `CommandAction::Login`.
pub async fn dispatch_command<W: SessionWriter>(
    line: &str,
    lg: &LookingGlass,
    identity: &Identity,
    rate_key: &str,
    color: ColorMode,
    writer: &mut W,
) -> Result<CommandAction> {
    let line = line.trim();

    if line.is_empty() {
        return Ok(CommandAction::Continue);
    }

    // Quit (with abbreviation)
    if is_quit(line) {
        writer.write_bytes(b"Goodbye.\n").await?;
        return Ok(CommandAction::Quit);
    }

    // Parse
    let command = match parse_command(line) {
        Ok(cmd) => cmd,
        Err(ParseError::Empty) => {
            return Ok(CommandAction::Continue);
        }
        Err(e) => {
            let msg = format!("{e}\n");
            writer.write_bytes(msg.as_bytes()).await?;
            return Ok(CommandAction::Continue);
        }
    };

    // Login — delegate to frontend
    if command.resource == Resource::Login {
        return Ok(CommandAction::Login);
    }

    // Logout — delegate to frontend (it owns the identity)
    if command.resource == Resource::Logout {
        return Ok(CommandAction::Logout);
    }

    // Whoami — show current identity
    if command.resource == Resource::Whoami {
        if identity.authenticated {
            let banner = crate::format::format_auth_banner(identity, None, lg.admin_group());
            writer.write_bytes(banner.as_bytes()).await?;
        } else {
            writer.write_bytes(b"Not authenticated. Use 'login' to authenticate.\n").await?;
        }
        return Ok(CommandAction::Continue);
    }

    // Help
    if command.resource == Resource::Help {
        writer.write_bytes(HELP_TEXT.as_bytes()).await?;
        return Ok(CommandAction::Continue);
    }

    // Participants
    if command.resource == Resource::Participants {
        let out = crate::format::format_participants(&lg.participants(), color);
        writer.write_bytes(out.as_bytes()).await?;
        return Ok(CommandAction::Continue);
    }

    // Participant detail
    if command.resource == Resource::ParticipantDetail {
        let asn: u32 = match command.target.as_deref().and_then(crate::command::parse_asn) {
            Some(n) => n,
            None => {
                writer.write_bytes(b"Invalid ASN\n").await?;
                return Ok(CommandAction::Continue);
            }
        };
        let pmap = lg.participants();
        let netbox_participants = lg.netbox_participants.load();
        match pmap.get(asn) {
            Some(p) => {
                let enriched = netbox_participants
                    .iter()
                    .find(|np| np.asn == asn)
                    .map(|np| np.enriched_ports.as_slice())
                    .unwrap_or(&[]);
                let out = crate::format::format_participant_detail(p, enriched, color);
                writer.write_bytes(out.as_bytes()).await?;
            }
            None => {
                writer.write_bytes(format!("AS{asn} is not a participant\n").as_bytes()).await?;
            }
        }
        return Ok(CommandAction::Continue);
    }

    // NetBox cache status
    if command.resource == Resource::NetboxCache {
        let status = lg.netbox_status.load();
        let out = crate::format::format_netbox_status(&status, color);
        writer.write_bytes(out.as_bytes()).await?;
        return Ok(CommandAction::Continue);
    }

    // Delegate to the service layer
    let multi_device =
        command.device.is_none() && !command.runs_on_lg_host() && lg.device_count() > 1;
    let has_filter = command.filter_asn.is_some() || command.filter_vlan.is_some();

    let req = service::Request {
        command,
        identity: identity.clone(),
        rate_key: rate_key.to_string(),
    };

    match lg.execute(req).await {
        Ok(results) => {
            for r in results {
                // When a filter is active, skip devices with empty results
                if has_filter && r.output.is_empty() {
                    continue;
                }
                if multi_device {
                    let header = crate::format::format_device_header(&r.device, color);
                    writer.write_bytes(header.as_bytes()).await?;
                }
                match r.output {
                    crate::structured::CommandOutput::Stream(mut stream_rx) => {
                        while let Some(line) = stream_rx.recv().await {
                            writer.write_bytes(line.as_bytes()).await?;
                            writer.write_bytes(b"\n").await?;
                        }
                    }
                    other => {
                        let text = crate::format::render(&other, color);
                        if text.is_empty() || text.trim().is_empty() {
                            writer.write_bytes(b"  [No data]\n").await?;
                        } else {
                            writer.write_bytes(text.as_bytes()).await?;
                            if !text.ends_with('\n') {
                                writer.write_bytes(b"\n").await?;
                            }
                        }
                    }
                }
            }
        }
        Err(service::Error::PolicyDenied(reason)) => {
            let msg = format!("Denied: {reason}\n");
            writer.write_bytes(msg.as_bytes()).await?;
        }
        Err(service::Error::RateLimited(reason)) => {
            let msg = format!("Rate limited: {reason}\n");
            writer.write_bytes(msg.as_bytes()).await?;
        }
        Err(e) => {
            let msg = format!("Error: {e}\n");
            writer.write_bytes(msg.as_bytes()).await?;
        }
    }

    Ok(CommandAction::Continue)
}

#[cfg(test)]
mod tests {

    use crate::structured::*;

    fn iface(name: &str) -> InterfaceStatus {
        InterfaceStatus {
            name: name.to_string(),
            description: String::new(),
            link_status: "connected".to_string(),
            protocol_status: "up".to_string(),
            speed: "100Gbps".to_string(),
            interface_type: "100GBASE-LR".to_string(),
            vlan: String::new(),
            auto_negotiate: false,
            member_interfaces: vec![],
            port_channel: None,
        }
    }

    fn mac_entry(vlan: &str, mac: &str, iface: &str) -> MacEntry {
        MacEntry {
            vlan: vlan.to_string(),
            mac_address: mac.to_string(),
            entry_type: "Dynamic".to_string(),
            interface: iface.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn is_empty_interfaces() {
        assert!(CommandOutput::InterfacesStatus(vec![]).is_empty());
        assert!(!CommandOutput::InterfacesStatus(vec![iface("Ethernet1")]).is_empty());
    }

    #[test]
    fn is_empty_mac() {
        assert!(CommandOutput::MacAddressTable(vec![]).is_empty());
        assert!(!CommandOutput::MacAddressTable(vec![
            mac_entry("998", "aa:bb:cc:dd:ee:01", "Ethernet1"),
        ]).is_empty());
    }

    #[test]
    fn is_empty_optics() {
        assert!(CommandOutput::Optics(vec![]).is_empty());
    }

    #[test]
    fn test_line_editor_caps_line_length() {
        use super::{LineEditor, MAX_LINE_LEN};
        // The telnet frontend is anonymous: a peer that streams printable bytes
        // and never sends a newline must not be able to grow the editor buffer
        // (and thus the process) without bound.
        let mut ed = LineEditor::new();
        let mut out = Vec::new();
        for _ in 0..(MAX_LINE_LEN + 5000) {
            ed.feed_byte(b'a', &mut out);
        }
        assert_eq!(ed.buf().len(), MAX_LINE_LEN, "buffer must stop at the cap");
        // Over-cap input is dropped, not echoed, so it costs no output either.
        assert_eq!(out.len(), MAX_LINE_LEN, "over-cap bytes must not be echoed");
    }
}
