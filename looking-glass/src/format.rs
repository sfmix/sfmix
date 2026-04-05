use std::fmt::Write;

use owo_colors::OwoColorize;
use tabled::builder::Builder;
use tabled::settings::Style;
use tabled::settings::style::HorizontalLine;

use tokio::sync::mpsc;

use crate::structured::*;

/// Whether to emit ANSI color codes in rendered output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    /// Full ANSI color + emoji + Unicode box drawing (rich terminals)
    Rich,
    /// ANSI color, ASCII-safe table borders (SSH default)
    Color,
    /// Plain text, no escape codes (telnet / MCP)
    Plain,
}

/// Apply table border style based on color mode.
fn apply_style(table: &mut tabled::Table, mode: ColorMode) {
    match mode {
        ColorMode::Rich | ColorMode::Color => {
            // Style::rounded() uses Unicode box drawing
            table.with(Style::rounded());
        }
        ColorMode::Plain => {
            table.with(
                Style::empty()
                    .top('-')
                    .bottom('-')
                    .left('|')
                    .right('|')
                    .vertical('|')
                    .corner_top_left('+')
                    .corner_top_right('+')
                    .corner_bottom_left('+')
                    .corner_bottom_right('+')
                    .intersection_top('+')
                    .intersection_bottom('+')
                    .horizontals([(1, HorizontalLine::full('-', '+', '+', '+'))])
            );
        }
    }
}

/// Colorize a link/protocol status string.
fn color_status(s: &str, mode: ColorMode) -> String {
    if mode == ColorMode::Plain { return s.to_string(); }
    // Rich and Color both get ANSI colors
    let lower = s.to_lowercase();
    if lower == "connected" || lower == "up" {
        format!("{}", s.green())
    } else if lower == "down" || lower == "notconnect" || lower == "disabled" || lower == "errdisabled" {
        format!("{}", s.red())
    } else {
        format!("{}", s.yellow())
    }
}

/// Colorize a BGP session state string.
fn color_bgp_state(s: &str, mode: ColorMode) -> String {
    if mode == ColorMode::Plain { return s.to_string(); }
    // Rich and Color both get ANSI colors
    if s == "Established" {
        format!("{}", s.green())
    } else if s == "Idle" || s == "Active" || s == "Connect" || s == "OpenSent" || s == "OpenConfirm" {
        format!("{}", s.red())
    } else {
        format!("{}", s.yellow())
    }
}

/// Colorize a counter that represents errors or discards (red if >0).
fn color_errors(v: u64, mode: ColorMode) -> String {
    let s = format_count(v);
    if mode == ColorMode::Plain || v == 0 { return s; }
    format!("{}", s.red())
}

/// Colorize an optical Rx power reading based on thresholds.
fn color_rx_power(dbm: Option<f64>, mode: ColorMode) -> String {
    let s = fmt_dbm(dbm);
    if mode == ColorMode::Plain { return s; }
    match dbm {
        Some(v) if v < -30.0 => format!("{}", s.red()),
        Some(v) if v < -10.0 => format!("{}", s.yellow()),
        Some(_) => format!("{}", s.green()),
        None => s,
    }
}

/// Bold a string in color mode.
fn bold_str(s: &str, mode: ColorMode) -> String {
    if mode == ColorMode::Plain { s.to_string() } else { format!("{}", s.bold()) }
}

/// Map participant_type to an emoji prefix (Rich mode only).
fn participant_type_emoji(participant_type: Option<&str>) -> &'static str {
    match participant_type {
        Some("Exempt") => "\u{2764}\u{FE0F} ",  // ❤️
        Some("Infrastructure") => "\u{1F3DB}\u{FE0F} ", // 🏛️
        _ => "",
    }
}

/// Render NetBox cache status as a diagnostic summary.
pub fn format_netbox_status(status: &crate::netbox::NetboxStatus, mode: ColorMode) -> String {
    let mut out = String::new();

    if !status.configured {
        return "NetBox is not configured as a participant source.\n".to_string();
    }

    let _ = writeln!(out, "{}", bold_str("NetBox Cache Status", mode));
    let _ = writeln!(out, "  URL:             {}", status.url.as_deref().unwrap_or("(unknown)"));
    let _ = writeln!(out, "  Participants:    {}", status.participant_count);
    let _ = writeln!(out, "  Peering ports:   {}", status.peering_port_count);
    let _ = writeln!(out, "  Core ports:      {}", status.core_port_count);
    let _ = writeln!(out, "  PortMap entries:  {}", status.port_map_size);

    let age_str = match status.age_secs() {
        Some(secs) => {
            let h = secs / 3600;
            let m = (secs % 3600) / 60;
            let s = secs % 60;
            if h > 0 {
                format!("{h}h {m}m {s}s ago")
            } else if m > 0 {
                format!("{m}m {s}s ago")
            } else {
                format!("{s}s ago")
            }
        }
        None => "never".to_string(),
    };
    let _ = writeln!(out, "  Last success:    {}", age_str);

    if let Some(ref err) = status.last_error {
        let err_str = if mode == ColorMode::Plain {
            err.clone()
        } else {
            format!("{}", err.red())
        };
        let _ = writeln!(out, "  Last error:      {}", err_str);
    }

    let refresh = if status.refresh_interval_secs > 0 {
        format!("{}s", status.refresh_interval_secs)
    } else {
        "disabled".to_string()
    };
    let _ = writeln!(out, "  Refresh:         {}", refresh);

    out
}

/// Render the participant list as a table.
///
/// In `Rich` mode, participant_type is shown as an emoji prefix on the name.
/// In `Color` mode, bold headers with rounded borders.
/// In `Plain` mode, ASCII borders, no formatting.
pub fn format_participants(participants: &crate::participants::ParticipantMap, mode: ColorMode) -> String {
    let mut entries: Vec<_> = participants.all().collect();
    entries.sort_by_key(|p| p.asn);

    if entries.is_empty() {
        return "No participants configured.\n".to_string();
    }

    let mut builder = Builder::default();
    builder.push_record([bold_str("ASN", mode), bold_str("Name", mode)]);
    for p in &entries {
        let name = if mode == ColorMode::Rich {
            let emoji = participant_type_emoji(p.participant_type.as_deref());
            format!("{}{}", emoji, p.name)
        } else {
            p.name.clone()
        };
        builder.push_record([format!("AS{}", p.asn), name]);
    }
    let mut table = builder.build();
    apply_style(&mut table, mode);
    format!("{table}\n")
}

/// Render a device header with Unicode box drawing.
///
/// Example: `╭─── switch03.fmt01.sfmix.org ───╮`
pub fn format_device_header(device: &str, mode: ColorMode) -> String {
    let name = if mode == ColorMode::Plain {
        device.to_string()
    } else {
        format!("{}", device.bold().cyan())
    };
    
    // Unicode box drawing for all modes
    let dashes = "\u{2500}\u{2500}\u{2500}"; // ───
    if mode == ColorMode::Plain {
        format!("\u{256d}{}\u{2500} {} \u{2500}{}\u{256e}\n", dashes, name, dashes)
    } else {
        format!("{}{}\u{2500} {} \u{2500}{}{}\n",
            "\u{256d}".dimmed(),  // ╭
            dashes.dimmed(),
            name,
            dashes.dimmed(),
            "\u{256e}".dimmed())  // ╮
    }
}

/// Render the service name banner with SFMIX brand rainbow colors.
/// Each letter of "SFMIX" gets its logo color; the rest is bold.
pub fn format_banner(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("SFMIX") {
        format!("{}{}{}{}{}{}",
            "S".truecolor(139, 47, 201).bold(),   // purple
            "F".truecolor(59, 125, 216).bold(),    // blue
            "M".truecolor(160, 200, 20).bold(),    // green-yellow
            "I".truecolor(232, 176, 0).bold(),     // yellow-orange
            "X".truecolor(212, 32, 32).bold(),     // red-orange
            rest.bold(),
        )
    } else {
        format!("{}", name.bold())
    }
}

/// Render a `CommandOutput` as a human-readable text table.
///
/// Returns a `String` suitable for telnet/SSH display.
/// For `Stream` variants, returns an empty string — callers must
/// handle streaming separately.
pub fn render(output: &CommandOutput, color: ColorMode) -> String {
    match output {
        CommandOutput::InterfacesStatus(entries) => render_interfaces_status(entries, color),
        CommandOutput::InterfaceDetail(detail) => render_interface_detail(detail, color),
        CommandOutput::BgpSummary(summary) => render_bgp_summary(summary, color),
        CommandOutput::BgpNeighborDetail(detail) => render_bgp_neighbor_detail(detail, color),
        CommandOutput::MacAddressTable(entries) => render_mac_table(entries, color),
        CommandOutput::ArpTable(entries) => render_arp_table(entries, color),
        CommandOutput::NdTable(entries) => render_nd_table(entries, color),
        CommandOutput::LldpNeighbors(entries) => render_lldp_neighbors(entries, color),
        CommandOutput::Optics(entries) => render_optics(entries, color),
        CommandOutput::OpticsDetail(entries) => render_optics_detail(entries, color),
        CommandOutput::VxlanVtep(entries) => render_vxlan_vtep(entries, color),
        CommandOutput::Stream(_) => String::new(),
        CommandOutput::Participants(s) => s.clone(),
        CommandOutput::NetboxStatus(s) => s.clone(),
        CommandOutput::Error(e) => match color {
            ColorMode::Plain => format!("Error: {e}\n"),
            _ => format!("{}\n", format!("Error: {e}").red()),
        },
    }
}

// ── Interfaces Status ───────────────────────────────────────────────

fn render_interfaces_status(entries: &[InterfaceStatus], color: ColorMode) -> String {
    if entries.is_empty() {
        return "No interfaces found.\n".to_string();
    }

    // Only show Port-Channel column if any entry has one
    let show_pc_col = entries.iter().any(|e| e.port_channel.is_some());

    let mut builder = Builder::default();
    let mut header = vec![bold_str("Interface", color), bold_str("Description", color), bold_str("Status", color), bold_str("Speed", color), bold_str("Type", color)];
    if show_pc_col {
        header.push(bold_str("Port-Channel", color));
    }
    builder.push_record(header);
    for e in entries {
        let mut row = vec![
            e.name.clone(),
            e.description.clone(),
            color_status(&e.link_status, color),
            e.speed.clone(),
            e.interface_type.clone(),
        ];
        if show_pc_col {
            row.push(e.port_channel.clone().unwrap_or_default());
        }
        builder.push_record(row);
    }
    let mut table = builder.build();
    apply_style(&mut table, color);
    format!("{table}\n")
}

// ── Interface Detail ────────────────────────────────────────────────

fn render_interface_detail(d: &InterfaceDetail, color: ColorMode) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}: {}", bold_str("Interface", color), d.name);
    let _ = writeln!(out, "  Description:     {}", d.description);
    let _ = writeln!(out, "  Link Status:     {}", color_status(&d.link_status, color));
    let _ = writeln!(out, "  Protocol Status: {}", color_status(&d.protocol_status, color));
    let _ = writeln!(out, "  Hardware:        {}", d.hardware_type);
    let _ = writeln!(out, "  MAC Address:     {}", d.mac_address);
    let _ = writeln!(out, "  MTU:             {}", d.mtu);
    let _ = writeln!(out, "  Speed:           {}", d.speed);
    let _ = writeln!(out, "  Bandwidth:       {}", d.bandwidth);
    let _ = writeln!(out, "  Counters:");
    let c = &d.counters;
    let _ = writeln!(out, "    In:  {} octets, {} unicast, {} multicast, {} broadcast",
        format_count(c.in_octets), format_count(c.in_unicast_packets),
        format_count(c.in_multicast_packets), format_count(c.in_broadcast_packets));
    let _ = writeln!(out, "         {} discards, {} errors",
        color_errors(c.in_discards, color), color_errors(c.in_errors, color));
    let _ = writeln!(out, "    Out: {} octets, {} unicast, {} multicast, {} broadcast",
        format_count(c.out_octets), format_count(c.out_unicast_packets),
        format_count(c.out_multicast_packets), format_count(c.out_broadcast_packets));
    let _ = writeln!(out, "         {} discards, {} errors",
        color_errors(c.out_discards, color), color_errors(c.out_errors, color));
    if !d.member_interfaces.is_empty() {
        let _ = writeln!(out, "  Members:         {}", d.member_interfaces.join(", "));
    }
    out
}

// ── BGP Summary ─────────────────────────────────────────────────────

fn render_bgp_summary(s: &BgpSummary, color: ColorMode) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Router ID: {}  Local AS: {}", s.router_id, s.local_as);
    if s.peers.is_empty() {
        let _ = writeln!(out, "No BGP peers.\n");
        return out;
    }
    let _ = writeln!(out);

    let mut builder = Builder::default();
    builder.push_record([bold_str("Neighbor", color), bold_str("AS", color), bold_str("Description", color), bold_str("State", color), bold_str("Uptime", color), bold_str("PfxRcvd", color), bold_str("MsgRcvd", color), bold_str("MsgSent", color)]);
    for p in &s.peers {
        builder.push_record([
            p.neighbor.clone(),
            p.remote_as.to_string(),
            p.description.clone(),
            color_bgp_state(&p.state, color),
            p.uptime.clone(),
            p.prefixes_received.to_string(),
            p.msg_received.to_string(),
            p.msg_sent.to_string(),
        ]);
    }
    let mut table = builder.build();
    apply_style(&mut table, color);
    let _ = write!(out, "{table}\n");
    out
}

// ── BGP Neighbor Detail ─────────────────────────────────────────────

fn render_bgp_neighbor_detail(d: &BgpNeighborDetail, color: ColorMode) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}: {}", bold_str("BGP Neighbor", color), d.neighbor);
    let _ = writeln!(out, "  Remote AS:       {}", d.remote_as);
    let _ = writeln!(out, "  Local AS:        {}", d.local_as);
    let _ = writeln!(out, "  Description:     {}", d.description);
    let _ = writeln!(out, "  State:           {}", color_bgp_state(&d.state, color));
    let _ = writeln!(out, "  Uptime:          {}", d.uptime);
    let _ = writeln!(out, "  Router ID:       {}", d.router_id);
    let _ = writeln!(out, "  Hold Time:       {}s", d.hold_time);
    let _ = writeln!(out, "  Keepalive:       {}s", d.keepalive_interval);
    let _ = writeln!(out, "  Prefixes Rcvd:   {}", d.prefixes_received);
    let _ = writeln!(out, "  Prefixes Sent:   {}", d.prefixes_sent);
    let _ = writeln!(out, "  Messages Rcvd:   {}", d.messages_received);
    let _ = writeln!(out, "  Messages Sent:   {}", d.messages_sent);
    out
}

// ── MAC Address Table ───────────────────────────────────────────────

fn render_mac_table(entries: &[MacEntry], color: ColorMode) -> String {
    if entries.is_empty() {
        return "No MAC entries found.\n".to_string();
    }

    let mut builder = Builder::default();
    builder.push_record([bold_str("VLAN", color), bold_str("MAC Address", color), bold_str("Type", color), bold_str("Interface", color)]);
    for e in entries {
        builder.push_record([
            e.vlan.clone(),
            e.mac_address.clone(),
            e.entry_type.clone(),
            e.interface.clone(),
        ]);
    }
    let mut table = builder.build();
    apply_style(&mut table, color);
    format!("{table}\n")
}

// ── ARP Table ───────────────────────────────────────────────────────

fn render_arp_table(entries: &[ArpEntry], color: ColorMode) -> String {
    if entries.is_empty() {
        return "No ARP entries found.\n".to_string();
    }

    let mut builder = Builder::default();
    builder.push_record([bold_str("IP Address", color), bold_str("MAC Address", color), bold_str("Interface", color), bold_str("Age", color)]);
    for e in entries {
        builder.push_record([
            e.ip_address.clone(),
            e.mac_address.clone(),
            e.interface.clone(),
            humanize_seconds(&e.age),
        ]);
    }
    let mut table = builder.build();
    apply_style(&mut table, color);
    format!("{table}\n")
}

// ── ND Table ────────────────────────────────────────────────────────

fn render_nd_table(entries: &[NdEntry], color: ColorMode) -> String {
    if entries.is_empty() {
        return "No IPv6 neighbor entries found.\n".to_string();
    }

    let mut builder = Builder::default();
    builder.push_record([bold_str("IPv6 Address", color), bold_str("MAC Address", color), bold_str("Interface", color), bold_str("State", color)]);
    for e in entries {
        builder.push_record([
            e.ip_address.clone(),
            e.mac_address.clone(),
            e.interface.clone(),
            e.state.clone(),
        ]);
    }
    let mut table = builder.build();
    apply_style(&mut table, color);
    format!("{table}\n")
}

// ── LLDP Neighbors ──────────────────────────────────────────────────

fn render_lldp_neighbors(entries: &[LldpNeighbor], color: ColorMode) -> String {
    if entries.is_empty() {
        return "No LLDP neighbors found.\n".to_string();
    }

    let mut builder = Builder::default();
    builder.push_record([bold_str("Local Interface", color), bold_str("Neighbor Device", color), bold_str("Neighbor Port", color), bold_str("TTL", color)]);
    for e in entries {
        builder.push_record([
            e.local_interface.clone(),
            e.neighbor_device.clone(),
            e.neighbor_port.clone(),
            e.ttl.clone(),
        ]);
    }
    let mut table = builder.build();
    apply_style(&mut table, color);
    format!("{table}\n")
}

// ── Optics (summary view) ───────────────────────────────────────────

fn render_optics(entries: &[InterfaceOptics], color: ColorMode) -> String {
    if entries.is_empty() {
        return "No optics data found.\n".to_string();
    }

    let mut builder = Builder::default();
    builder.push_record([bold_str("Interface", color), bold_str("Description", color), bold_str("Status", color), bold_str("Media", color), bold_str("Temp", color), bold_str("Voltage", color), bold_str("TxPower", color), bold_str("RxPower", color), bold_str("TxBias", color)]);

    for e in entries {
        if !e.dom_supported {
            let note = if e.media_type.is_empty() {
                "no transceiver".to_string()
            } else {
                e.media_type.clone()
            };
            builder.push_record([
                e.name.clone(),
                e.description.clone(),
                color_status(&e.link_status, color),
                note,
                String::new(), String::new(), String::new(), String::new(), String::new(),
            ]);
            continue;
        }

        let temp = e.temperature_c.map(|t| format!("{:.1}C", t)).unwrap_or_default();
        let volt = e.voltage_v.map(|v| format!("{:.2}V", v)).unwrap_or_default();

        if e.lanes.len() <= 1 {
            let lane = e.lanes.first();
            builder.push_record([
                e.name.clone(),
                e.description.clone(),
                color_status(&e.link_status, color),
                e.media_type.clone(),
                temp,
                volt,
                fmt_dbm(lane.and_then(|l| l.tx_power_dbm)),
                color_rx_power(lane.and_then(|l| l.rx_power_dbm), color),
                fmt_ma(lane.and_then(|l| l.tx_bias_ma)),
            ]);
        } else {
            // Multi-lane: header row
            builder.push_record([
                e.name.clone(),
                e.description.clone(),
                color_status(&e.link_status, color),
                e.media_type.clone(),
                temp,
                volt,
                String::new(), String::new(), String::new(),
            ]);
            // Per-lane rows
            for lane in &e.lanes {
                builder.push_record([
                    format!("  Lane {}", lane.lane),
                    String::new(), String::new(), String::new(), String::new(), String::new(),
                    fmt_dbm(lane.tx_power_dbm),
                    color_rx_power(lane.rx_power_dbm, color),
                    fmt_ma(lane.tx_bias_ma),
                ]);
            }
        }
    }
    let mut table = builder.build();
    apply_style(&mut table, color);
    format!("{table}\n")
}

// ── Optics Detail ───────────────────────────────────────────────────

fn render_optics_detail(entries: &[InterfaceOptics], color: ColorMode) -> String {
    if entries.is_empty() {
        return "No optics data found.\n".to_string();
    }

    let mut out = String::new();
    for e in entries {
        let _ = writeln!(out, "{}: {}", bold_str("Interface", color), e.name);
        let _ = writeln!(out, "  Description:  {}", e.description);
        let _ = writeln!(out, "  Link Status:  {}", color_status(&e.link_status, color));
        let _ = writeln!(out, "  Media Type:   {}", e.media_type);
        if let Some(t) = e.temperature_c {
            let _ = writeln!(out, "  Temperature:  {:.1} C", t);
        }
        if let Some(v) = e.voltage_v {
            let _ = writeln!(out, "  Voltage:      {:.3} V", v);
        }
        if !e.lanes.is_empty() {
            let _ = writeln!(out, "  Lanes:");
            for lane in &e.lanes {
                let _ = writeln!(
                    out,
                    "    Lane {}: Tx={} Rx={} Bias={}",
                    lane.lane,
                    fmt_dbm(lane.tx_power_dbm),
                    color_rx_power(lane.rx_power_dbm, color),
                    fmt_ma(lane.tx_bias_ma),
                );
            }
        } else if !e.dom_supported {
            let _ = writeln!(out, "  DOM: not supported");
        }
    }
    out
}

// ── VXLAN VTEP ──────────────────────────────────────────────────────

fn render_vxlan_vtep(entries: &[VxlanVtep], color: ColorMode) -> String {
    if entries.is_empty() {
        return "No VTEPs found.\n".to_string();
    }

    let mut builder = Builder::default();
    builder.push_record([bold_str("VTEP Address", color), bold_str("Learned From", color)]);
    for e in entries {
        builder.push_record([
            e.vtep_address.clone(),
            e.learned_from.clone(),
        ]);
    }
    let mut table = builder.build();
    apply_style(&mut table, color);
    format!("{table}\n")
}

// ── Helpers ─────────────────────────────────────────────────────────

fn humanize_seconds(s: &str) -> String {
    let raw = s.strip_suffix('s').unwrap_or(s);
    let secs = match raw.parse::<f64>() {
        Ok(v) => v as u64,
        Err(_) => return s.to_string(),
    };
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let sec = secs % 60;
    if h > 0 {
        format!("{h}h {m}m {sec}s")
    } else if m > 0 {
        format!("{m}m {sec}s")
    } else {
        format!("{sec}s")
    }
}

fn fmt_dbm(v: Option<f64>) -> String {
    match v {
        Some(val) => format!("{:.2}dBm", val),
        None => "-".to_string(),
    }
}

fn fmt_ma(v: Option<f64>) -> String {
    match v {
        Some(val) => format!("{:.1}mA", val),
        None => "-".to_string(),
    }
}

fn format_count(v: u64) -> String {
    if v >= 1_000_000_000 {
        format!("{:.1}G", v as f64 / 1_000_000_000.0)
    } else if v >= 1_000_000 {
        format!("{:.1}M", v as f64 / 1_000_000.0)
    } else if v >= 1_000 {
        format!("{:.1}K", v as f64 / 1_000.0)
    } else {
        v.to_string()
    }
}

/// Render an authentication banner showing identity, role, ASNs, and
/// optionally certificate validity in a colored Unicode box-drawing frame.
///
/// Used by the SSH login banner (with cert validity) and `whoami` (without).
/// Pass `valid_before = None` when there is no certificate context.
pub fn format_auth_banner(
    identity: &crate::identity::Identity,
    valid_before: Option<u64>,
    admin_group: &str,
) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let email = identity.email.as_deref().unwrap_or("unknown");
    let is_admin = identity.is_admin(admin_group);

    // Role line
    let role_label = if is_admin { "IX Administrator" } else if !identity.asns.is_empty() { "Participant" } else { "Authenticated" };
    let role_colored = if is_admin {
        format!("{}", role_label.green().bold())
    } else if !identity.asns.is_empty() {
        format!("{}", role_label.yellow())
    } else {
        format!("{}", role_label.white())
    };

    // ASN line
    let mut asn_list: Vec<u32> = identity.asns.iter().copied().collect();
    asn_list.sort();
    let asn_display = if asn_list.is_empty() {
        String::new()
    } else {
        let asns: Vec<String> = asn_list.iter().map(|a| format!("{}", format!("AS{a}").bold())).collect();
        asns.join(", ")
    };

    // Build content lines (plain text for width calc, colored for display)
    let check = "\u{2714}"; // ✔
    let line1_plain = format!("  {} Authenticated as {}", check, email);
    let line2_plain = format!("  Role: {}", role_label);
    let line3_plain = if !asn_display.is_empty() { format!("  ASNs: {}", asn_list.iter().map(|a| format!("AS{a}")).collect::<Vec<_>>().join(", ")) } else { String::new() };

    // Cert validity line (only when cert context is available)
    let line4_plain = valid_before.map(|vb| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let remaining = vb.saturating_sub(now);
        let hours = remaining / 3600;
        let mins = (remaining % 3600) / 60;
        format!("  Certificate valid for {}", if remaining == 0 { "expired".to_string() } else if hours == 0 { format!("{mins}m") } else { format!("{hours}h {mins}m") })
    });

    let mut plains: Vec<&str> = vec![&line1_plain, &line2_plain];
    if !line3_plain.is_empty() { plains.push(&line3_plain); }
    if let Some(ref l4) = line4_plain { plains.push(l4); }
    let width = plains.iter().map(|l| l.chars().count()).max().unwrap_or(40) + 2;

    let line1 = format!("  {} Authenticated as {}",
        check.green().bold(),
        email.cyan().bold());
    let line2 = format!("  Role: {}", role_colored);
    let line3 = if !asn_display.is_empty() { format!("  ASNs: {}", asn_display) } else { String::new() };
    let line4 = valid_before.map(|vb| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let remaining = vb.saturating_sub(now);
        let hours = remaining / 3600;
        let mins = (remaining % 3600) / 60;
        let validity_str = if remaining == 0 {
            format!("{}", "expired".red().bold())
        } else if hours == 0 {
            format!("{}", format!("{mins}m").yellow())
        } else {
            format!("{}", format!("{hours}h {mins}m").green())
        };
        format!("  Certificate valid for {}", validity_str)
    });

    // Box drawing
    let dim = |s: &str| format!("{}", s.dimmed());
    let top = format!("{}{}{}", dim("\u{256d}"), dim(&"\u{2500}".repeat(width)), dim("\u{256e}"));
    let bot = format!("{}{}{}", dim("\u{2570}"), dim(&"\u{2500}".repeat(width)), dim("\u{256f}"));
    let bar_l = dim("\u{2502}");
    let bar_r = dim("\u{2502}");

    let pad = |plain: &str| " ".repeat(width.saturating_sub(plain.chars().count()));

    let mut out = String::new();
    out.push_str(&top);
    out.push('\n');
    out.push_str(&format!("{bar_l}{line1}{}{bar_r}\n", pad(&line1_plain)));
    out.push_str(&format!("{bar_l}{line2}{}{bar_r}\n", pad(&line2_plain)));
    if !line3.is_empty() {
        out.push_str(&format!("{bar_l}{line3}{}{bar_r}\n", pad(&line3_plain)));
    }
    if let (Some(ref l4), Some(ref l4p)) = (&line4, &line4_plain) {
        out.push_str(&format!("{bar_l}{l4}{}{bar_r}\n", pad(l4p)));
    }
    out.push_str(&bot);
    out.push('\n');
    out
}

/// Drain a streaming command receiver into a single collected string.
///
/// Used for `CommandOutput::Stream` (ping, traceroute) where the backend
/// yields output line-by-line via an mpsc channel.
pub async fn drain_stream(rx: &mut mpsc::Receiver<String>) -> String {
    let mut lines = Vec::new();
    while let Some(line) = rx.recv().await {
        lines.push(line);
    }
    lines.join("\n")
}
