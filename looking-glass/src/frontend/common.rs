use anyhow::Result;

use crate::command::{ParseError, Resource};
use crate::format::ColorMode;
use crate::grammar::{self, parse_command};
use crate::identity::Identity;
use crate::service::{self, LookingGlass};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const PROMPT: &str = "> ";

pub const HELP_TEXT: &str = "\
Available commands:
  show interfaces status          Interface summary (name, status, speed)
  show interfaces <asn>           Filter interfaces by participant ASN
  show optics                     Transceiver DOM levels (all ports)
  show optics <asn>               Filter optics by participant ASN
  show mac address-table          MAC address table
  show mac vlan <id>              Filter MAC table by VLAN ID
  show ip bgp summary             BGP IPv4 peer summary
  show bgp ipv6 unicast summary   BGP IPv6 peer summary
  show bgp neighbor <address>     BGP neighbor detail
  show lldp neighbors              LLDP neighbor table
  show arp                         ARP table
  show ipv6 neighbors              IPv6 neighbor table
  show participants                IXP participant list
  show vxlan vtep                  VXLAN VTEP table
  show netbox                      NetBox cache status
  ping <destination>               Ping from the looking glass host
  traceroute <destination>         Traceroute from the looking glass host
  login                            Authenticate via OIDC (opens browser)
  whoami                           Show current identity and permissions
  logout                           Drop authentication (return to public tier)
  help                             Show this help
  quit / exit                      Disconnect
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

pub struct LineEditor {
    buf: String,
    esc_state: EscState,
}

impl LineEditor {
    pub fn new() -> Self {
        Self {
            buf: String::new(),
            esc_state: EscState::Normal,
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
                } else {
                    // Not a CSI sequence — discard and return to normal
                    self.esc_state = EscState::Normal;
                }
                return LineEvent::Continue;
            }
            EscState::EscapeBracket => {
                // Terminal byte of CSI is 0x40..=0x7E
                if byte >= 0x40 && byte <= 0x7E {
                    self.esc_state = EscState::Normal;
                }
                // Intermediate bytes (0x20..=0x3F) stay in EscapeBracket
                return LineEvent::Continue;
            }
            EscState::Normal => {} // fall through to main match
        }

        match byte {
            // --- Enter (CR / LF) ---
            0x0D | 0x0A => {
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
                output.extend_from_slice(b"^C\n");
                output.extend_from_slice(PROMPT.as_bytes());
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
            c if c >= 0x20 && c < 0x7F => {
                self.buf.push(c as char);
                output.push(c);
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

    // NetBox cache status
    if command.resource == Resource::NetboxCache {
        let status = lg.netbox_status.load();
        let out = crate::format::format_netbox_status(&status, color);
        writer.write_bytes(out.as_bytes()).await?;
        return Ok(CommandAction::Continue);
    }

    // Delegate to the service layer
    let multi_device = command.device.is_none() && lg.device_count() > 1;
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
}
