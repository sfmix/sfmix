use anyhow::Result;
use arc_swap::ArcSwap;

use crate::command::{ParseError, Resource};
use crate::format::ColorMode;
use crate::grammar::{self, parse_command};
use crate::identity::Identity;
use crate::oidc::OidcClient;
use crate::participants::{ParticipantMap, PortMap};
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::ratelimit::{ConnectionTracker, DeviceRateLimiter, RateLimiter};
use crate::backend::pool::DevicePool;

// ---------------------------------------------------------------------------
// Shared state (used by telnet, SSH, and MCP frontends)
// ---------------------------------------------------------------------------

/// Shared state passed to each frontend session.
pub struct SharedState {
    pub service_name: String,
    pub policy: PolicyEngine,
    pub rate_limiter: RateLimiter,
    pub device_rate_limiter: DeviceRateLimiter,
    pub connection_tracker: ConnectionTracker,
    pub participants: ArcSwap<ParticipantMap>,
    pub port_map: ArcSwap<PortMap>,
    pub device_pool: DevicePool,
    /// OIDC group prefix for extracting ASN from group names (e.g. "as")
    pub group_prefix: String,
    /// OIDC client for device auth flow (None = login command disabled)
    pub oidc_client: Option<OidcClient>,
    /// VLAN IDs visible to all users in MAC address table output.
    pub public_vlans: Vec<String>,
}

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
  ping <destination>               Ping from the looking glass host
  traceroute <destination>         Traceroute from the looking glass host
  login                            Authenticate via OIDC (opens browser)
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
}

/// Shared command dispatch: parse, check policy, rate-limit, execute, render.
///
/// Login is NOT handled here — the frontend does that after receiving
/// `CommandAction::Login`.
pub async fn dispatch_command<W: SessionWriter>(
    line: &str,
    state: &SharedState,
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

    // Help
    if command.resource == Resource::Help {
        writer.write_bytes(HELP_TEXT.as_bytes()).await?;
        return Ok(CommandAction::Continue);
    }

    // Participants
    if command.resource == Resource::Participants {
        let out = crate::format::format_participants(&state.participants.load(), color);
        writer.write_bytes(out.as_bytes()).await?;
        return Ok(CommandAction::Continue);
    }

    // Policy check
    match state.policy.evaluate(&command, identity, &state.participants.load()) {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny { reason } => {
            let msg = format!("Denied: {reason}\n");
            writer.write_bytes(msg.as_bytes()).await?;
            return Ok(CommandAction::Continue);
        }
    }

    // Rate limit
    let _guard = match state.rate_limiter.acquire(rate_key).await {
        Ok(guard) => guard,
        Err(e) => {
            let msg = format!("Rate limited: {e}\n");
            writer.write_bytes(msg.as_bytes()).await?;
            return Ok(CommandAction::Continue);
        }
    };

    // Dispatch to device backend
    let multi_device = command.device.is_none() && state.device_pool.device_count() > 1;
    let mut rx = match state
        .device_pool
        .execute(&command, identity, &state.device_rate_limiter, state.policy.admin_group(), &state.port_map.load(), &state.public_vlans)
        .await
    {
        Ok(rx) => rx,
        Err(e) => {
            let msg = format!("Error: {e}\n");
            writer.write_bytes(msg.as_bytes()).await?;
            return Ok(CommandAction::Continue);
        }
    };

    let has_filter = command.filter_asn.is_some() || command.filter_vlan.is_some();

    while let Some(mut r) = rx.recv().await {
        // Post-filter: ASN scoping for interfaces/optics
        if let Some(asn) = command.filter_asn {
            let pmap = state.port_map.load();
            r.output = apply_asn_filter(r.output, &r.device, asn, &pmap);
        }
        // Post-filter: VLAN scoping for MAC table
        if let Some(ref vlan) = command.filter_vlan {
            r.output = apply_vlan_filter(r.output, vlan);
        }
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

    Ok(CommandAction::Continue)
}

/// Filter interfaces/optics output to only ports belonging to the given ASN.
fn apply_asn_filter(
    output: crate::structured::CommandOutput,
    device: &str,
    asn: u32,
    pmap: &PortMap,
) -> crate::structured::CommandOutput {
    use crate::participants::PortClass;
    use crate::structured::CommandOutput;

    let matches_asn = |name: &str| -> bool {
        matches!(pmap.classify(device, name), Some(PortClass::Participant { asn: a }) if *a == asn)
    };

    match output {
        CommandOutput::InterfacesStatus(mut entries) => {
            // First pass: find Port-Channels (including subinterfaces) that match the ASN.
            // Collect both the full name and the base name (without .VLAN suffix) so that
            // member interfaces referencing "Port-Channel114" are found when the PortMap
            // entry is "Port-Channel114.998".
            let mut matched_pcs: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for e in entries.iter() {
                if e.name.starts_with("Port-Channel") && matches_asn(&e.name) {
                    matched_pcs.insert(e.name.clone());
                    // Also insert base name (strip .VLAN suffix)
                    if let Some(base) = e.name.split('.').next() {
                        matched_pcs.insert(base.to_string());
                    }
                }
            }

            // Keep entries that match the ASN directly OR are members of a matched PC
            entries.retain(|e| {
                matches_asn(&e.name)
                    || e.port_channel.as_ref().is_some_and(|pc| matched_pcs.contains(pc))
            });
            CommandOutput::InterfacesStatus(entries)
        }
        CommandOutput::Optics(mut entries) => {
            // Same Port-Channel member logic as InterfacesStatus
            let mut matched_pcs: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for e in entries.iter() {
                // Optics entries don't have Port-Channel entries themselves,
                // but we need to find which Port-Channels match the ASN
                // by checking if any entry's port_channel matches
                if let Some(ref pc) = e.port_channel {
                    if matches_asn(pc) {
                        matched_pcs.insert(pc.clone());
                        if let Some(base) = pc.split('.').next() {
                            matched_pcs.insert(base.to_string());
                        }
                    }
                }
            }
            // Also check the PortMap directly for Port-Channels belonging to this ASN
            for (key, class) in pmap.iter() {
                if key.0 == device {
                    if let PortClass::Participant { asn: a } = *class {
                        if a == asn && key.1.starts_with("Port-Channel") {
                            matched_pcs.insert(key.1.clone());
                            if let Some(base) = key.1.split('.').next() {
                                matched_pcs.insert(base.to_string());
                            }
                        }
                    }
                }
            }
            entries.retain(|e| {
                matches_asn(&e.name)
                    || e.port_channel.as_ref().is_some_and(|pc| matched_pcs.contains(pc))
            });
            CommandOutput::Optics(entries)
        }
        CommandOutput::OpticsDetail(mut entries) => {
            // Same logic for OpticsDetail
            let mut matched_pcs: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for (key, class) in pmap.iter() {
                if key.0 == device {
                    if let PortClass::Participant { asn: a } = *class {
                        if a == asn && key.1.starts_with("Port-Channel") {
                            matched_pcs.insert(key.1.clone());
                            if let Some(base) = key.1.split('.').next() {
                                matched_pcs.insert(base.to_string());
                            }
                        }
                    }
                }
            }
            entries.retain(|e| {
                matches_asn(&e.name)
                    || e.port_channel.as_ref().is_some_and(|pc| matched_pcs.contains(pc))
            });
            CommandOutput::OpticsDetail(entries)
        }
        other => other,
    }
}

/// Filter MAC table output to only entries matching the given VLAN.
fn apply_vlan_filter(
    output: crate::structured::CommandOutput,
    vlan: &str,
) -> crate::structured::CommandOutput {
    use crate::structured::CommandOutput;

    match output {
        CommandOutput::MacAddressTable(mut entries) => {
            entries.retain(|e| e.vlan == vlan);
            CommandOutput::MacAddressTable(entries)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netbox::NetboxParticipant;
    use crate::participants::PortMap;
    use crate::structured::*;

    const DEVICE: &str = "switch03.fmt01.sfmix.org";

    fn test_port_map() -> PortMap {
        let participants = vec![
            NetboxParticipant {
                asn: 6939,
                name: "Hurricane Electric".to_string(),
                participant_type: Some("Member".to_string()),
                ports: vec![
                    (DEVICE.to_string(), "Port-Channel101".to_string()),
                ],
            },
            NetboxParticipant {
                asn: 6140,
                name: "Two P".to_string(),
                participant_type: Some("Member".to_string()),
                ports: vec![
                    ("switch01.fmt01.sfmix.org".to_string(), "Port-Channel114.998".to_string()),
                ],
            },
            NetboxParticipant {
                asn: 13335,
                name: "Cloudflare".to_string(),
                participant_type: Some("Member".to_string()),
                ports: vec![
                    (DEVICE.to_string(), "Ethernet5/1".to_string()),
                ],
            },
        ];
        let core_ports = vec![
            (DEVICE.to_string(), "Ethernet50/1".to_string()),
            (DEVICE.to_string(), "Ethernet51/1".to_string()),
        ];
        PortMap::build(&participants, &core_ports)
    }

    fn iface(name: &str, desc: &str, port_channel: Option<&str>) -> InterfaceStatus {
        InterfaceStatus {
            name: name.to_string(),
            description: desc.to_string(),
            link_status: "connected".to_string(),
            protocol_status: "up".to_string(),
            speed: "100Gbps".to_string(),
            interface_type: "100GBASE-LR".to_string(),
            vlan: String::new(),
            auto_negotiate: false,
            member_interfaces: vec![],
            port_channel: port_channel.map(|s| s.to_string()),
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

    fn optic(name: &str) -> InterfaceOptics {
        optic_with_pc(name, None)
    }

    fn optic_with_pc(name: &str, port_channel: Option<&str>) -> InterfaceOptics {
        InterfaceOptics {
            name: name.to_string(),
            description: String::new(),
            link_status: "connected".to_string(),
            media_type: "100GBASE-LR".to_string(),
            temperature_c: None,
            voltage_v: None,
            lanes: vec![],
            dom_supported: false,
            port_channel: port_channel.map(|s| s.to_string()),
        }
    }

    // ── ASN filter: basic ──────────────────────────────────────────

    #[test]
    fn asn_filter_keeps_matching_port() {
        let pmap = test_port_map();
        let output = CommandOutput::InterfacesStatus(vec![
            iface("Ethernet5/1", "Peer: Cloudflare (AS13335)", None),
            iface("Ethernet50/1", "Core: transport", None),
            iface("Ethernet6/1", "Peer: Someone else", None),
        ]);
        let filtered = apply_asn_filter(output, DEVICE, 13335, &pmap);
        match filtered {
            CommandOutput::InterfacesStatus(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].name, "Ethernet5/1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn asn_filter_empty_when_no_match() {
        let pmap = test_port_map();
        let output = CommandOutput::InterfacesStatus(vec![
            iface("Ethernet50/1", "Core: transport", None),
        ]);
        let filtered = apply_asn_filter(output, DEVICE, 13335, &pmap);
        match filtered {
            CommandOutput::InterfacesStatus(v) => assert!(v.is_empty()),
            _ => panic!("wrong variant"),
        }
    }

    // ── ASN filter: Port-Channel + members ─────────────────────────

    #[test]
    fn asn_filter_includes_port_channel_and_members() {
        let pmap = test_port_map();
        let output = CommandOutput::InterfacesStatus(vec![
            iface("Ethernet1/1", "LAG: Hurricane Electric (AS6939)", Some("Port-Channel101")),
            iface("Ethernet2/1", "LAG: Hurricane Electric (AS6939)", Some("Port-Channel101")),
            iface("Port-Channel101", "Peer: Hurricane Electric (AS6939)", None),
            iface("Ethernet50/1", "Core: transport", None),
        ]);
        let filtered = apply_asn_filter(output, DEVICE, 6939, &pmap);
        match filtered {
            CommandOutput::InterfacesStatus(v) => {
                let names: Vec<&str> = v.iter().map(|e| e.name.as_str()).collect();
                assert_eq!(names, &["Ethernet1/1", "Ethernet2/1", "Port-Channel101"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── ASN filter: subinterface Port-Channel (the bug fix) ────────

    #[test]
    fn asn_filter_includes_members_of_subinterface_port_channel() {
        // Port-Channel114.998 is in the PortMap for AS6140.
        // Member interfaces reference "Port-Channel114" (base name).
        let pmap = test_port_map();
        let device = "switch01.fmt01.sfmix.org";
        let output = CommandOutput::InterfacesStatus(vec![
            iface("Ethernet7", "LAG: Two P (AS6140)", Some("Port-Channel114")),
            iface("Ethernet8", "LAG: Two P (AS6140)", Some("Port-Channel114")),
            iface("Port-Channel114.998", "Peer: Two P (AS6140)", None),
            iface("Ethernet50/1", "Core: transport", None),
        ]);
        let filtered = apply_asn_filter(output, device, 6140, &pmap);
        match filtered {
            CommandOutput::InterfacesStatus(v) => {
                let names: Vec<&str> = v.iter().map(|e| e.name.as_str()).collect();
                assert_eq!(names, &["Ethernet7", "Ethernet8", "Port-Channel114.998"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn asn_filter_subinterface_no_false_positives() {
        // Members of a DIFFERENT Port-Channel should not leak through
        let pmap = test_port_map();
        let device = "switch01.fmt01.sfmix.org";
        let output = CommandOutput::InterfacesStatus(vec![
            iface("Ethernet7", "LAG: Two P", Some("Port-Channel114")),
            iface("Port-Channel114.998", "Peer: Two P (AS6140)", None),
            iface("Ethernet9", "LAG: Other", Some("Port-Channel200")),
            iface("Port-Channel200", "Other peer", None),
        ]);
        let filtered = apply_asn_filter(output, device, 6140, &pmap);
        match filtered {
            CommandOutput::InterfacesStatus(v) => {
                let names: Vec<&str> = v.iter().map(|e| e.name.as_str()).collect();
                assert_eq!(names, &["Ethernet7", "Port-Channel114.998"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── ASN filter: optics ────────────────────────────────────────

    #[test]
    fn asn_filter_optics() {
        let pmap = test_port_map();
        let output = CommandOutput::Optics(vec![
            optic("Ethernet5/1"),
            optic("Ethernet50/1"),
        ]);
        let filtered = apply_asn_filter(output, DEVICE, 13335, &pmap);
        match filtered {
            CommandOutput::Optics(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].name, "Ethernet5/1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn asn_filter_optics_includes_lag_members() {
        // AS6939 has Port-Channel101 in the PortMap.
        // Physical member interfaces (Ethernet1/1, Ethernet2/1) should be included
        // when they have port_channel set to "Port-Channel101".
        let pmap = test_port_map();
        let output = CommandOutput::Optics(vec![
            optic_with_pc("Ethernet1/1", Some("Port-Channel101")),
            optic_with_pc("Ethernet2/1", Some("Port-Channel101")),
            optic("Ethernet50/1"), // core port, no PC membership
            optic("Ethernet6/1"),  // unrelated port
        ]);
        let filtered = apply_asn_filter(output, DEVICE, 6939, &pmap);
        match filtered {
            CommandOutput::Optics(v) => {
                let names: Vec<&str> = v.iter().map(|e| e.name.as_str()).collect();
                assert_eq!(names, vec!["Ethernet1/1", "Ethernet2/1"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── VLAN filter ───────────────────────────────────────────────

    #[test]
    fn vlan_filter_keeps_matching() {
        let output = CommandOutput::MacAddressTable(vec![
            mac_entry("998", "aa:bb:cc:dd:ee:01", "Ethernet1"),
            mac_entry("999", "aa:bb:cc:dd:ee:02", "Ethernet2"),
            mac_entry("998", "aa:bb:cc:dd:ee:03", "Ethernet3"),
        ]);
        let filtered = apply_vlan_filter(output, "998");
        match filtered {
            CommandOutput::MacAddressTable(v) => {
                assert_eq!(v.len(), 2);
                assert!(v.iter().all(|e| e.vlan == "998"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn vlan_filter_empty_when_no_match() {
        let output = CommandOutput::MacAddressTable(vec![
            mac_entry("999", "aa:bb:cc:dd:ee:01", "Ethernet1"),
        ]);
        let filtered = apply_vlan_filter(output, "100");
        match filtered {
            CommandOutput::MacAddressTable(v) => assert!(v.is_empty()),
            _ => panic!("wrong variant"),
        }
    }

    // ── is_empty ──────────────────────────────────────────────────

    #[test]
    fn is_empty_interfaces() {
        assert!(CommandOutput::InterfacesStatus(vec![]).is_empty());
        assert!(!CommandOutput::InterfacesStatus(vec![
            iface("Ethernet1", "", None),
        ]).is_empty());
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

    // ── Passthrough for non-matching variants ─────────────────────

    #[test]
    fn asn_filter_passes_through_mac_table() {
        let pmap = test_port_map();
        let output = CommandOutput::MacAddressTable(vec![
            mac_entry("998", "aa:bb:cc:dd:ee:01", "Ethernet1"),
        ]);
        let filtered = apply_asn_filter(output, DEVICE, 13335, &pmap);
        match filtered {
            CommandOutput::MacAddressTable(v) => assert_eq!(v.len(), 1),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn vlan_filter_passes_through_interfaces() {
        let output = CommandOutput::InterfacesStatus(vec![
            iface("Ethernet1", "test", None),
        ]);
        let filtered = apply_vlan_filter(output, "998");
        match filtered {
            CommandOutput::InterfacesStatus(v) => assert_eq!(v.len(), 1),
            _ => panic!("wrong variant"),
        }
    }
}
