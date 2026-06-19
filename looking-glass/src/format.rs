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

/// Colorize a counter that represents errors or discards (red if >0).
fn color_errors(v: u64, mode: ColorMode) -> String {
    let s = format_count(v);
    if mode == ColorMode::Plain || v == 0 { return s; }
    format!("{}", s.red())
}

/// Per-media-type RX power specs: (rx_min_bad, rx_min_warn, rx_max_warn, rx_max_bad).
/// Sources: IEEE 802.3 per-lane receiver sensitivity and overload points.
/// Warn zone is ~1.5 dB inside the bad boundary on each side.
fn optic_rx_spec(media_type: &str) -> (f64, f64, f64, f64) {
    match media_type {
        // 1G
        "1000BASE-T"  => (-30.0, -30.0, 30.0, 30.0), // copper — always ok
        "1000BASE-LX" => (-19.0, -17.5, -0.5,  0.5),
        "1000BASE-SX" => (-17.0, -15.5, -2.0, -0.5),
        // 10G
        "10GBASE-SR" => (-11.1,  -9.6, -0.5, 1.0),
        "10GBASE-LR" => (-14.4, -12.9, -0.5, 0.5),
        "10GBASE-ER" => (-15.8, -14.3, -0.5, 1.0),
        // 40G
        "40GBASE-SR4"  => ( -9.5,  -8.0, -0.5, 1.0),
        "40GBASE-LR4"  => (-13.7, -12.2,  1.5, 2.3),
        "40GBASE-PSM4" => (-13.0, -11.5,  1.5, 2.5),
        // 100G
        "100GBASE-SR4" => (-10.3,  -8.8, 1.5, 2.4),
        "100GBASE-LR4" => (-10.6,  -9.1, 1.5, 2.4),
        "100GBASE-ER4" => (-13.5, -12.0, 1.5, 2.4),
        "100GBASE-LR"  => (-10.6,  -9.1, 1.5, 2.4),
        "100GBASE-CR4" => (-30.0, -30.0, 30.0, 30.0), // DAC — always ok
        // 400G
        "400GBASE-SR8" => (-10.3,  -8.8, 1.5, 2.4),
        "400GBASE-DR4" => (-10.6,  -9.1, 1.5, 2.4),
        "400GBASE-FR4" => (-10.6,  -9.1, 1.5, 2.4),
        "400GBASE-LR8" => (-10.6,  -9.1, 1.5, 2.4),
        "400GBASE-ZR"  => (-18.0, -16.5, 2.0, 3.5),
        "400GBASE-ZRP" => (-18.0, -16.5, 2.0, 3.5),
        // Fallback for unknown types
        _ => (-14.0, -12.0, 1.5, 3.0),
    }
}

/// Colorize an optical Rx power reading using per-media-type thresholds.
fn color_rx_power(dbm: Option<f64>, media_type: &str, mode: ColorMode) -> String {
    let s = fmt_dbm(dbm);
    if mode == ColorMode::Plain { return s; }
    match dbm {
        Some(v) => {
            let (min_bad, min_warn, max_warn, max_bad) = optic_rx_spec(media_type);
            if v < min_bad || v > max_bad {
                format!("{}", s.red())
            } else if v < min_warn || v > max_warn {
                format!("{}", s.yellow())
            } else {
                format!("{}", s.green())
            }
        }
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

/// Render device state cache status as a diagnostic summary.
pub fn format_device_cache_status(
    cache: &std::collections::HashMap<String, crate::structured::DeviceStateCache>,
    cfg: &crate::config::DeviceCacheConfig,
    mode: ColorMode,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", bold_str("Device State Cache", mode));

    let interval = if cfg.poll_interval_secs > 0 {
        format!("{}s", cfg.poll_interval_secs)
    } else {
        "disabled".to_string()
    };
    let _ = writeln!(out, "  Poll interval:   {interval}");
    let _ = writeln!(out, "  TTL (default):   {}s", cfg.ttl.default);

    if cache.is_empty() {
        let _ = writeln!(out, "  (no data — cache is cold or polling is disabled)");
        return out;
    }

    let _ = writeln!(out);

    let mut names: Vec<&str> = cache.keys().map(|s| s.as_str()).collect();
    names.sort_unstable();

    for name in names {
        let entry = &cache[name];
        let _ = writeln!(out, "  {}", bold_str(name, mode));

        let age = |t: Option<std::time::Instant>| -> String {
            match t {
                None => "never".to_string(),
                Some(t) => {
                    let secs = t.elapsed().as_secs();
                    if secs < 60 { format!("{secs}s ago") }
                    else { format!("{}m {}s ago", secs / 60, secs % 60) }
                }
            }
        };

        let _ = writeln!(out, "    interfaces:      {:12}  ({} entries)", age(entry.interfaces_at), entry.interfaces.len());
        let _ = writeln!(out, "    optics:          {:12}  ({} entries)", age(entry.optics_at), entry.optics.len());
        let _ = writeln!(out, "    optics-inventory:{:12}  ({} entries)", age(entry.optics_inventory_at), entry.optics_inventory.len());
        let _ = writeln!(out, "    lldp:            {:12}  ({} entries)", age(entry.lldp_at), entry.lldp_neighbors.len());
        let _ = writeln!(out, "    mac:             {:12}  ({} entries)", age(entry.mac_at), entry.mac_table.len());
        let _ = writeln!(out, "    arp:             {:12}  ({} entries)", age(entry.arp_at), entry.arp_table.len());
        let _ = writeln!(out, "    ipv6-neighbors:  {:12}  ({} entries)", age(entry.ipv6_neighbors_at), entry.ipv6_neighbors.len());

        if let Some(ref err) = entry.last_error {
            let err_str = if mode == ColorMode::Plain {
                err.clone()
            } else {
                format!("{}", err.red())
            };
            let _ = writeln!(out, "    Last error:   {err_str}");
        }
    }

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

/// Render the flat list of assigned IX IPs with their tenant/ASN.
pub fn format_ix_ip_assignments(
    participants: &[crate::netbox::NetboxParticipant],
    filter_asn: Option<u32>,
    mode: ColorMode,
) -> String {
    let mut rows: Vec<(&str, &str, u32, &str, &str)> = participants
        .iter()
        .filter(|p| filter_asn.is_none_or(|a| p.asn == a))
        .flat_map(|p| {
            p.ip_addresses.iter().map(move |ip| {
                (
                    ip.address.as_str(),
                    ip.family.as_str(),
                    p.asn,
                    p.name.as_str(),
                    ip.status.as_str(),
                )
            })
        })
        .collect();
    rows.sort_by(|a, b| a.0.cmp(b.0));

    if rows.is_empty() {
        return "No IX IP assignments.\n".to_string();
    }

    let mut builder = Builder::default();
    builder.push_record([
        bold_str("IP", mode),
        bold_str("Family", mode),
        bold_str("ASN", mode),
        bold_str("Tenant", mode),
        bold_str("Status", mode),
    ]);
    for (ip, family, asn, name, status) in &rows {
        builder.push_record([
            ip.to_string(),
            family.to_string(),
            format!("AS{asn}"),
            name.to_string(),
            status.to_string(),
        ]);
    }
    let mut table = builder.build();
    apply_style(&mut table, mode);
    format!("{table}\n")
}

/// Render discovered ARP/NDP neighbors — one row per heard MAC. Conflicts and
/// IPs not assigned on the IX (the claimant is mis-bound to an invalid address)
/// are flagged.
pub fn format_discovered_neighbors(
    neighbors: &[DiscoveredNeighbor],
    filter_asn: Option<u32>,
    mode: ColorMode,
) -> String {
    let mut entries: Vec<_> = neighbors
        .iter()
        .filter(|n| filter_asn.is_none_or(|a| n.asn == Some(a)))
        .collect();
    entries.sort_by(|a, b| a.ip.cmp(&b.ip));

    if entries.is_empty() {
        return "No discovered neighbors.\n".to_string();
    }

    let mut builder = Builder::default();
    builder.push_record([
        bold_str("IP", mode),
        bold_str("MAC", mode),
        bold_str("ASN", mode),
        bold_str("Last seen", mode),
        bold_str("Flags", mode),
    ]);
    for n in &entries {
        // Unassigned IPs carry no ASN; show a dash so the empty cell reads as
        // intentional rather than missing data.
        let asn = if n.assigned {
            n.asn.map(|a| format!("AS{a}")).unwrap_or_default()
        } else {
            "—".to_string()
        };
        let mut flags: Vec<&str> = Vec::new();
        if !n.assigned {
            flags.push("UNASSIGNED");
        }
        if n.conflict {
            flags.push("CONFLICT");
        }
        let flag = if flags.is_empty() {
            String::new()
        } else if mode == ColorMode::Plain {
            flags.join(" ")
        } else {
            format!("{}", flags.join(" ").red())
        };
        for m in &n.macs {
            builder.push_record([
                n.ip.clone(),
                m.mac.clone(),
                asn.clone(),
                m.last_seen.clone(),
                flag.clone(),
            ]);
        }
    }
    let mut table = builder.build();
    apply_style(&mut table, mode);
    format!("{table}\n")
}

/// Render detail for a single participant — ports (including LAG members) and BGP sessions.
pub fn format_participant_detail(
    p: &crate::participants::Participant,
    enriched_ports: &[crate::netbox::EnrichedPort],
    mode: ColorMode,
) -> String {
    let mut out = String::new();

    let ptype = p.participant_type.as_deref().unwrap_or("Member");
    let asn_str = format!("AS{}", p.asn);
    let header = format!("{asn_str}  {}  [{ptype}]", p.name);
    let sep = "─".repeat(header.chars().count().min(72));

    if mode == ColorMode::Plain {
        out.push_str(&format!("{header}\n{sep}\n\n"));
    } else {
        out.push_str(&format!("{}\n{sep}\n\n", bold_str(&header, mode)));
    }

    // Ports — iterate enriched_ports (peering-tagged only), not p.ports
    // which now also includes physical LAG members.
    if enriched_ports.is_empty() && p.ports.is_empty() {
        out.push_str("  No ports configured.\n");
    } else if !enriched_ports.is_empty() {
        out.push_str(&format!("{}:\n", bold_str("Ports", mode)));
        for ep in enriched_ports {
            let speed_str = ep.speed
                .map(|s| format!("  {}G", s / 1000))
                .unwrap_or_default();
            let disabled = if ep.enabled {
                String::new()
            } else if mode == ColorMode::Plain {
                "  [disabled]".to_string()
            } else {
                format!("  {}", "[disabled]".red())
            };
            let iface_col = if mode == ColorMode::Plain {
                ep.interface.clone()
            } else {
                bold_str(&ep.interface, mode)
            };
            out.push_str(&format!("  {iface_col}  {}{speed_str}{disabled}\n", ep.device));

            let members = &ep.member_interfaces;
            for (i, (mdev, miface)) in members.iter().enumerate() {
                let is_last = i == members.len() - 1;
                let branch = if is_last { "└─" } else { "├─" };
                out.push_str(&format!("    {branch} {miface}  {mdev}\n"));
            }
        }
    } else {
        // Fallback: no enriched data (YAML-loaded participant)
        out.push_str(&format!("{}:\n", bold_str("Ports", mode)));
        for port in &p.ports {
            out.push_str(&format!("  {}  {}\n", port.interface, port.device));
        }
    }

    if !p.sessions.is_empty() {
        out.push('\n');
        out.push_str(&format!("{}:\n", bold_str("BGP sessions", mode)));
        for s in &p.sessions {
            if let Some(ref v4) = s.neighbor {
                out.push_str(&format!("  {v4:<40} {}  (IPv4)\n", s.device));
            }
            if let Some(ref v6) = s.neighbor_v6 {
                out.push_str(&format!("  {v6:<40} {}  (IPv6)\n", s.device));
            }
        }
    }

    out
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
    
    if mode == ColorMode::Plain {
        let dashes = "---";
        format!("+{}- {} -{}\n", dashes, name, dashes)
    } else {
        let dashes = "\u{2500}\u{2500}\u{2500}"; // ───
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
        CommandOutput::MacAddressTable(entries) => render_mac_table(entries, color),
        CommandOutput::LldpNeighbors(entries) => render_lldp_neighbors(entries, color),
        CommandOutput::Optics(entries) => render_optics(entries, color),
        CommandOutput::OpticsDetail(entries) => render_optics_detail(entries, color),
        CommandOutput::OpticsInventory(entries) => render_optics_inventory(entries, color),
        CommandOutput::Arp(entries) => render_arp(entries, color),
        CommandOutput::IPv6Neighbors(entries) => render_arp(entries, color),
        CommandOutput::Stream(_) => String::new(),
        CommandOutput::Participants(s) => s.clone(),
        CommandOutput::NetboxStatus(s) => s.clone(),
        CommandOutput::DeviceCacheStatus(s) => s.clone(),
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
                color_rx_power(lane.and_then(|l| l.rx_power_dbm), &e.media_type, color),
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
                    color_rx_power(lane.rx_power_dbm, &e.media_type, color),
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
                    color_rx_power(lane.rx_power_dbm, &e.media_type, color),
                    fmt_ma(lane.tx_bias_ma),
                );
            }
        } else if !e.dom_supported {
            let _ = writeln!(out, "  DOM: not supported");
        }
    }
    out
}

// ── Optics Inventory ───────────────────────────────────────────────

fn render_optics_inventory(entries: &[OpticsInventoryEntry], color: ColorMode) -> String {
    if entries.is_empty() {
        return "No optics inventory data found.\n".to_string();
    }

    let mut builder = Builder::default();
    builder.push_record([
        bold_str("Interface", color),
        bold_str("Media", color),
        bold_str("Vendor", color),
        bold_str("Model", color),
        bold_str("Serial", color),
    ]);

    for e in entries {
        builder.push_record([
            e.name.clone(),
            e.media_type.clone(),
            e.vendor.clone().unwrap_or_else(|| "-".to_string()),
            e.model.clone().unwrap_or_else(|| "-".to_string()),
            e.serial_number.clone().unwrap_or_else(|| "-".to_string()),
        ]);
    }
    let mut table = builder.build();
    apply_style(&mut table, color);
    format!("{table}\n")
}

// ── ARP / IPv6 Neighbors ────────────────────────────────────────────

fn render_arp(entries: &[ArpEntry], color: ColorMode) -> String {
    if entries.is_empty() {
        return "No ARP entries found.\n".to_string();
    }

    // Only show VRF column if any entry has a VRF
    let show_vrf = entries.iter().any(|e| e.vrf.is_some());

    let mut builder = Builder::default();
    let mut header = vec![
        bold_str("IP Address", color),
        bold_str("MAC Address", color),
        bold_str("Interface", color),
    ];
    if show_vrf {
        header.push(bold_str("VRF", color));
    }
    header.push(bold_str("Type", color));
    header.push(bold_str("Age(s)", color));
    builder.push_record(header);

    for e in entries {
        let age = e.age_secs.map(|a| a.to_string()).unwrap_or_else(|| "-".to_string());
        let mut row = vec![
            e.ip_address.clone(),
            e.mac_address.clone(),
            e.interface.clone(),
        ];
        if show_vrf {
            row.push(e.vrf.clone().unwrap_or_default());
        }
        row.push(e.entry_type.clone());
        row.push(age);
        builder.push_record(row);
    }
    let mut table = builder.build();
    apply_style(&mut table, color);
    format!("{table}\n")
}

// ── Helpers ─────────────────────────────────────────────────────────

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

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(mac: &str) -> DiscoveredMac {
        DiscoveredMac {
            mac: mac.to_string(),
            first_seen: "2026-06-18T00:00:00Z".to_string(),
            last_seen: "2026-06-18T00:05:00Z".to_string(),
        }
    }

    #[test]
    fn discovered_neighbors_flag_unassigned_and_conflict() {
        let neighbors = vec![
            DiscoveredNeighbor {
                ip: "192.0.2.10".to_string(),
                family: "IPv4".to_string(),
                asn: Some(64500),
                tenant: Some("Acme".to_string()),
                macs: vec![mac("aa:aa:aa:aa:aa:aa")],
                conflict: false,
                assigned: true,
            },
            DiscoveredNeighbor {
                ip: "192.0.2.250".to_string(),
                family: "IPv4".to_string(),
                asn: None,
                tenant: None,
                macs: vec![mac("bb:bb:bb:bb:bb:bb"), mac("cc:cc:cc:cc:cc:cc")],
                conflict: true,
                assigned: false,
            },
        ];
        let out = format_discovered_neighbors(&neighbors, None, ColorMode::Plain);
        // The unassigned IP is flagged (and as a conflict), with a dash for ASN.
        assert!(out.contains("UNASSIGNED"), "unassigned IP must be flagged:\n{out}");
        assert!(out.contains("CONFLICT"), "conflict still flagged:\n{out}");
        assert!(out.contains("—"), "unassigned ASN cell shows a dash:\n{out}");
        // The assigned IP keeps its ASN and is not flagged unassigned.
        assert!(out.contains("AS64500"));
    }

    #[test]
    fn discovered_neighbors_asn_filter_excludes_unassigned() {
        let neighbors = vec![DiscoveredNeighbor {
            ip: "192.0.2.250".to_string(),
            family: "IPv4".to_string(),
            asn: None,
            tenant: None,
            macs: vec![mac("bb:bb:bb:bb:bb:bb")],
            conflict: false,
            assigned: false,
        }];
        // Filtering by an ASN drops IPs that carry no ASN (unassigned).
        let out = format_discovered_neighbors(&neighbors, Some(64500), ColorMode::Plain);
        assert_eq!(out, "No discovered neighbors.\n");
    }
}
