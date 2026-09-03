//! LAN-hygiene classifier + aggregate table for broadcast/unknown-multicast
//! ("BUM") frames that have no business on an IXP peering LAN.
//!
//! `classify` is a pure, bounded decode of one frame into at most one
//! [`Detection`] keyed by a [`lg_types::structured::BUM_CATALOG`] entry
//! (IPv6 RA, DHCP, IGP hellos, discovery protocols, …). Frames that are normal
//! IX traffic — ARP for in-prefix addresses, NS/NA, MLD/IGMP reports — decode
//! to `None`. Everything read from the frame is attacker-controlled: every walk
//! is length-checked, TLV loops are iteration-capped, and any text we keep as
//! a "detail" goes through [`sanitize`].
//!
//! The aggregate writer folds detections into one row per `(src_mac, protocol)`
//! with first/last-seen, a count, a few distinct details and the first few raw
//! frames (served as a tiny pcap for evidence). Rows decay after `ttl_secs`
//! and the table is capped, so a flood of spoofed sources cannot grow memory.
//! Per-source frame rates arrive as one message per second per capture thread
//! and synthesize the two rate-based detections (`bum_flood`,
//! `unknown_unicast_flood`).

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use lg_types::structured::{bum_proto, BumProto};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::afpacket::fmt_mac;
use crate::ringbuf::CapturedFrame;

/// Distinct `(src_mac, protocol)` rows retained. Oldest-by-last_seen evicted.
pub const MAX_KEYS: usize = 2048;
/// Raw frames kept per row as evidence.
pub const MAX_FRAMES: usize = 8;
/// Bytes kept per evidence frame.
pub const FRAME_SNAPLEN: usize = 512;
/// Distinct detail strings kept per row.
pub const MAX_DETAILS: usize = 8;
/// Max bytes of any single detail string.
const MAX_DETAIL_LEN: usize = 64;
/// Max TLV iterations per walk.
const MAX_TLVS: usize = 32;
/// Rate window for the synthetic flood detections.
const RATE_WINDOW_SECS: i64 = 60;

// ── Context ─────────────────────────────────────────────────────────

/// Everything `classify` needs besides the frame. Swapped atomically when the
/// lg-server poll refreshes the IX prefixes.
#[derive(Debug, Clone, Default)]
pub struct ClassifyCtx {
    /// IX IPv4 prefixes as (network, mask) in host order. Empty = unknown, and
    /// the "foreign" heuristics stay off (never false-positive on cold start).
    pub ix_v4: Vec<(u32, u32)>,
    /// IX IPv6 prefixes as (network, mask).
    pub ix_v6: Vec<(u128, u128)>,
    /// Source MACs to never classify (own MAC, SFMIX infrastructure, sibling RS).
    pub ignore_src_macs: HashSet<[u8; 6]>,
}

impl ClassifyCtx {
    pub fn in_ix_v4(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        self.ix_v4.iter().any(|(net, mask)| v & mask == *net)
    }
    /// Parse `"a.b.c.d"`, mask length pairs into the v4 list (invalid ignored).
    pub fn set_v4(&mut self, prefixes: &[(String, u32)]) {
        self.ix_v4 = prefixes
            .iter()
            .filter_map(|(p, len)| {
                let ip: Ipv4Addr = p.parse().ok()?;
                let mask = if *len == 0 { 0 } else { u32::MAX << (32 - (*len).min(32)) };
                Some((u32::from(ip) & mask, mask))
            })
            .collect();
    }
    pub fn set_v6(&mut self, prefixes: &[(String, u32)]) {
        self.ix_v6 = prefixes
            .iter()
            .filter_map(|(p, len)| {
                let ip: Ipv6Addr = p.parse().ok()?;
                let mask = if *len == 0 { 0 } else { u128::MAX << (128 - (*len).min(128)) };
                Some((u128::from(ip) & mask, mask))
            })
            .collect();
    }
}

// ── Classification ──────────────────────────────────────────────────

/// One classified frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub proto: &'static BumProto,
    pub detail: Option<String>,
}

fn det(key: &'static str, detail: Option<String>) -> Option<Detection> {
    bum_proto(key).map(|proto| Detection { proto, detail })
}

fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]))
}
fn be32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*b.get(off)?, *b.get(off + 1)?, *b.get(off + 2)?, *b.get(off + 3)?]))
}
fn v4(b: &[u8], off: usize) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::new(*b.get(off)?, *b.get(off + 1)?, *b.get(off + 2)?, *b.get(off + 3)?))
}
fn v6(b: &[u8], off: usize) -> Option<Ipv6Addr> {
    let s = b.get(off..off + 16)?;
    let mut a = [0u8; 16];
    a.copy_from_slice(s);
    Some(Ipv6Addr::from(a))
}

/// Keep only printable ASCII (else `?`), capped at `max` bytes. Attacker-
/// controlled text never reaches a log line or a web page unsanitized.
pub fn sanitize(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '?' })
        .collect()
}

fn is_bum_dst(dst: &[u8]) -> bool {
    dst.first().is_some_and(|b| b & 1 == 1)
}
fn is_bcast(dst: &[u8]) -> bool {
    dst.len() >= 6 && dst[..6] == [0xff; 6]
}

/// Classify one Ethernet frame. `None` = nothing wrong with it (or ignored source).
pub fn classify(frame: &[u8], ctx: &ClassifyCtx) -> Option<Detection> {
    if frame.len() < 14 {
        return None;
    }
    let dst = &frame[0..6];
    let mut src = [0u8; 6];
    src.copy_from_slice(&frame[6..12]);
    if ctx.ignore_src_macs.contains(&src) {
        return None;
    }
    let ethertype = be16(frame, 12)?;

    // Tagged frames on the untagged IX port: report the VID, don't dig further.
    if ethertype == 0x8100 || ethertype == 0x88a8 {
        let vid = be16(frame, 14).map(|t| t & 0x0fff);
        return det("dot1q_tagged", vid.map(|v| format!("vid {v}")));
    }

    let payload = &frame[14..];
    match ethertype {
        0x0806 => classify_arp(payload, ctx),
        0x0800 => classify_ipv4(dst, payload, ctx),
        0x86dd => classify_ipv6(dst, payload),
        0x88cc => det("lldp", lldp_system_name(payload)),
        0x8809 => det("lacp", None),
        0x88bf => det("romon", None),
        0x6001 | 0x6002 => det("dec_mop", None),
        0x9000 | 0x8899 => det("loop_detect", Some(format!("ethertype 0x{ethertype:04x}"))),
        t if t <= 0x05dc => classify_llc(dst, payload),
        t => {
            // Unknown protocols are only interesting when flooded to everyone;
            // unicast we happen to see in promiscuous mode is someone's business.
            if is_bum_dst(dst) {
                det("unknown_ethertype", Some(format!("ethertype 0x{t:04x}")))
            } else {
                None
            }
        }
    }
}

fn classify_arp(p: &[u8], ctx: &ClassifyCtx) -> Option<Detection> {
    // htype(2) ptype(2) hlen(1) plen(1) oper(2) sha(6) spa(4) ...
    if be16(p, 2)? != 0x0800 || *p.get(5)? != 4 {
        return None;
    }
    let spa = v4(p, 14)?;
    if spa.is_unspecified() || ctx.ix_v4.is_empty() || ctx.in_ix_v4(spa) {
        return None;
    }
    det("foreign_arp", Some(format!("sender {spa}")))
}

fn classify_llc(dst: &[u8], p: &[u8]) -> Option<Detection> {
    let dsap = *p.first()?;
    let ssap = *p.get(1)?;
    if dsap == 0x42 && ssap == 0x42 && dst == [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00] {
        return det("stp", stp_root(p.get(3..)?));
    }
    if dsap == 0xfe && ssap == 0xfe {
        return det("isis", None);
    }
    if dsap == 0xaa && ssap == 0xaa {
        // SNAP: ctrl(1) oui(3) pid(2) payload
        let oui = (be16(p, 3)? as u32) << 8 | *p.get(5)? as u32;
        let pid = be16(p, 6)?;
        let body = p.get(8..)?;
        if oui == 0x00000c {
            return match pid {
                0x2000 => det("cdp", cdp_device_id(body)),
                0x010b => det("stp", stp_root(body.get(3..)?)),
                0x2003 => det("cisco_l2", Some("VTP".into())),
                0x2004 => det("cisco_l2", Some("DTP".into())),
                0x0104 => det("cisco_l2", Some("PAgP".into())),
                0x0111 => det("cisco_l2", Some("UDLD".into())),
                _ => det("cisco_l2", Some(format!("SNAP PID 0x{pid:04x}"))),
            };
        }
        if is_bum_dst(dst) {
            return det("unknown_ethertype", Some(format!("SNAP {oui:06x}/0x{pid:04x}")));
        }
        return None;
    }
    if is_bum_dst(dst) {
        return det("unknown_ethertype", Some(format!("LLC dsap 0x{dsap:02x}")));
    }
    None
}

/// STP BPDU: protocol id(2) version(1) type(1) flags(1) root id(8)…
fn stp_root(b: &[u8]) -> Option<String> {
    let bpdu_type = *b.get(3)?;
    let root = b.get(5..13)?;
    Some(format!(
        "type 0x{bpdu_type:02x} root {:04x}.{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        u16::from_be_bytes([root[0], root[1]]),
        root[2], root[3], root[4], root[5], root[6], root[7]
    ))
}

/// CDP: version(1) ttl(1) checksum(2) then TLVs type(2) len(2 incl. header).
fn cdp_device_id(b: &[u8]) -> Option<String> {
    let mut off = 4;
    for _ in 0..MAX_TLVS {
        let t = be16(b, off)?;
        let l = be16(b, off + 2)? as usize;
        if l < 4 {
            return None;
        }
        if t == 0x0001 {
            return Some(format!("device {}", sanitize(b.get(off + 4..off + l)?, MAX_DETAIL_LEN)));
        }
        off += l;
    }
    None
}

/// LLDP TLVs: 7-bit type + 9-bit length. System Name = type 5.
fn lldp_system_name(b: &[u8]) -> Option<String> {
    let mut off = 0;
    for _ in 0..MAX_TLVS {
        let hdr = be16(b, off)?;
        let t = hdr >> 9;
        let l = (hdr & 0x1ff) as usize;
        if t == 0 {
            return None;
        }
        if t == 5 {
            return Some(format!("system {}", sanitize(b.get(off + 2..off + 2 + l)?, MAX_DETAIL_LEN)));
        }
        off += 2 + l;
    }
    None
}

fn classify_ipv4(dst_mac: &[u8], p: &[u8], ctx: &ClassifyCtx) -> Option<Detection> {
    let ihl = (*p.first()? & 0x0f) as usize * 4;
    if ihl < 20 {
        return None;
    }
    let proto = *p.get(9)?;
    let src = v4(p, 12)?;
    let dst = v4(p, 16)?;
    let l4 = p.get(ihl..)?;
    let foreign = |ctx: &ClassifyCtx| -> Option<Detection> {
        if is_bcast(dst_mac) && !src.is_unspecified() && !ctx.ix_v4.is_empty() && !ctx.in_ix_v4(src) {
            det("foreign_ipv4_broadcast", Some(format!("source {src}")))
        } else {
            None
        }
    };
    match proto {
        89 => det("ospf", ospf_detail(l4)),
        88 => det("eigrp", None),
        103 => det("pim", None),
        112 => det("vrrp", vrrp_detail(l4)),
        2 => {
            if *l4.first()? == 0x11 {
                det("igmp_query", None)
            } else {
                None // membership reports are normal
            }
        }
        17 => {
            let dport = be16(l4, 2)?;
            let body = l4.get(8..).unwrap_or(&[]);
            let to_group = dst.is_broadcast() || dst.is_multicast() || is_bum_dst(dst_mac);
            match dport {
                67 => det("dhcpv4", dhcp_hostname(body).or(Some("client discover/request".into()))),
                68 => det("dhcpv4", Some("server offer/ack".into())),
                5678 => det("mndp", mndp_detail(body)),
                20561 => det("mac_telnet", None),
                5353 => det("mdns", None),
                5355 => det("llmnr", None),
                1900 => det("ssdp", None),
                137 | 138 => det("netbios", None),
                520 => det("rip", None),
                646 => det("ldp", None),
                1985 | 2029 => det("hsrp", hsrp_detail(body)),
                3222 => det("glbp", None),
                123 if to_group => det("ntp_broadcast", None),
                53 if to_group => det("dns_broadcast", None),
                _ => foreign(ctx),
            }
        }
        _ => foreign(ctx),
    }
}

fn ospf_detail(l4: &[u8]) -> Option<String> {
    let ver = *l4.first()?;
    let rid = v4(l4, 4)?;
    let area = be32(l4, 8)?;
    Some(format!("v{ver} router-id {rid} area {area}"))
}
fn vrrp_detail(l4: &[u8]) -> Option<String> {
    Some(format!("vrid {} prio {}", *l4.get(1)?, *l4.get(2)?))
}
/// HSRP v1: version(1) op(1) state(1) hello(1) hold(1) prio(1) group(1) …
fn hsrp_detail(b: &[u8]) -> Option<String> {
    Some(format!("group {} prio {}", *b.get(6)?, *b.get(5)?))
}

/// DHCPv4 option 12 (host name) from the options field after the magic cookie.
fn dhcp_hostname(b: &[u8]) -> Option<String> {
    if b.get(236..240)? != [0x63, 0x82, 0x53, 0x63] {
        return None;
    }
    let mut off = 240;
    for _ in 0..MAX_TLVS {
        let t = *b.get(off)?;
        if t == 0xff {
            return None;
        }
        if t == 0 {
            off += 1;
            continue;
        }
        let l = *b.get(off + 1)? as usize;
        if t == 12 {
            return Some(format!("hostname {}", sanitize(b.get(off + 2..off + 2 + l)?, MAX_DETAIL_LEN)));
        }
        off += 2 + l;
    }
    None
}

/// MNDP: header(4) then TLVs type(2) len(2). 5 = identity, 7 = version, 8 = platform.
fn mndp_detail(b: &[u8]) -> Option<String> {
    let mut off = 4;
    let mut identity = None;
    let mut platform = None;
    let mut version = None;
    for _ in 0..MAX_TLVS {
        let Some(t) = be16(b, off) else { break };
        let Some(l) = be16(b, off + 2).map(|v| v as usize) else { break };
        let Some(val) = b.get(off + 4..off + 4 + l) else { break };
        match t {
            5 => identity = Some(sanitize(val, 24)),
            7 => version = Some(sanitize(val, 12)),
            8 => platform = Some(sanitize(val, 16)),
            _ => {}
        }
        off += 4 + l;
    }
    let parts: Vec<String> = [identity.map(|s| format!("identity {s}")), platform, version]
        .into_iter()
        .flatten()
        .collect();
    if parts.is_empty() { None } else { Some(parts.join(" ")) }
}

fn classify_ipv6(dst_mac: &[u8], p: &[u8]) -> Option<Detection> {
    let mut nh = *p.get(6)?;
    let dst = v6(p, 24)?;
    let mut off = 40usize;
    // Skip up to two extension headers (MLD carries a Hop-by-Hop router alert).
    for _ in 0..2 {
        if matches!(nh, 0 | 43 | 60) {
            nh = *p.get(off)?;
            off += (*p.get(off + 1)? as usize + 1) * 8;
        } else {
            break;
        }
    }
    let l4 = p.get(off..)?;
    match nh {
        58 => match *l4.first()? {
            134 => det("ipv6_ra", ra_detail(l4)),
            133 => det("ipv6_rs", None),
            130 => det("mld_query", None),
            128 if dst == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1) => det("icmpv6_echo_allnodes", None),
            _ => None,
        },
        89 => det("ospf", ospf_detail(l4)),
        88 => det("eigrp", None),
        103 => det("pim", None),
        112 => det("vrrp", vrrp_detail(l4)),
        17 => {
            let dport = be16(l4, 2)?;
            let _ = dst_mac;
            match dport {
                546 | 547 => det("dhcpv6", None),
                5353 => det("mdns", None),
                5355 => det("llmnr", None),
                1900 => det("ssdp", None),
                521 => det("rip", None),
                646 => det("ldp", None),
                _ => None,
            }
        }
        _ => None,
    }
}

/// RA: type code cksum(4) hop(1) flags(1) lifetime(2) reachable(4) retrans(4) options.
/// Options: type(1) len(1 in 8-octet units). PIO (3): prefix len at +2, prefix at +16.
fn ra_detail(l4: &[u8]) -> Option<String> {
    let flags = *l4.get(5)?;
    let lifetime = be16(l4, 6)?;
    let mut s = format!("lifetime {lifetime}s");
    if flags & 0x80 != 0 {
        s.push_str(" M");
    }
    if flags & 0x40 != 0 {
        s.push_str(" O");
    }
    let mut off = 16;
    for _ in 0..MAX_TLVS {
        let Some(t) = l4.get(off) else { break };
        let Some(l) = l4.get(off + 1).map(|v| *v as usize * 8) else { break };
        if l == 0 {
            break;
        }
        if *t == 3 {
            if let (Some(plen), Some(prefix)) = (l4.get(off + 2), v6(l4, off + 16)) {
                s.push_str(&format!(" prefix {prefix}/{plen}"));
            }
            break;
        }
        off += l;
    }
    Some(s)
}

// ── Aggregate table ─────────────────────────────────────────────────

/// A classified frame handed from a capture thread to the writer.
pub struct BumObservation {
    pub src_mac: [u8; 6],
    pub iface: String,
    pub detection: Detection,
    /// First `FRAME_SNAPLEN` bytes of the frame, for evidence.
    pub frame: Vec<u8>,
    pub ts_sec: u32,
    pub ts_usec: u32,
}

/// Per-source frame counts accumulated by a capture thread over ~1 s.
pub struct RateSample {
    pub iface: String,
    /// (src_mac, broadcast/multicast frames, unknown-unicast frames)
    pub counts: Vec<([u8; 6], u32, u32)>,
}

pub enum BumMsg {
    Hit(Box<BumObservation>),
    Rates(RateSample),
}

/// One published row: a `(src_mac, protocol)` pairing with its sightings.
#[derive(Debug, Clone, Serialize)]
pub struct BumRow {
    pub src_mac: String,
    pub protocol: &'static str,
    pub severity: &'static str,
    pub iface: String,
    pub first_seen: String,
    pub last_seen: String,
    pub count: u64,
    pub details: Vec<String>,
    pub frame_count: usize,
}

/// Lock-free snapshot served by HTTP. `by_protocol` are process-lifetime
/// monotonic counters (per protocol), stable even as rows expire.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BumSnapshot {
    pub rows: Vec<BumRow>,
    pub by_protocol: Vec<(&'static str, &'static str, u64)>,
    pub observation_count: u64,
}

pub type FrameStore = Arc<Mutex<HashMap<(String, &'static str), Vec<CapturedFrame>>>>;

struct Row {
    proto: &'static BumProto,
    iface: String,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    count: u64,
    details: Vec<String>,
    frame_count: usize,
}

struct RateState {
    window_start: DateTime<Utc>,
    bum: u64,
    uu: u64,
    iface: String,
}

/// Drain classifier output, maintaining the table and republishing on a tick.
pub async fn run_writer(
    mut rx: mpsc::Receiver<BumMsg>,
    table: Arc<ArcSwap<BumSnapshot>>,
    frames: FrameStore,
    ttl_secs: u64,
    flood_pps: u32,
) {
    let mut t = Table::new(ttl_secs, flood_pps, frames);
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            maybe = rx.recv() => {
                let Some(msg) = maybe else { break };
                let now = Utc::now();
                match msg {
                    BumMsg::Hit(obs) => t.hit(*obs, now),
                    BumMsg::Rates(sample) => t.rates(sample, now),
                }
            }
            _ = tick.tick() => {
                let now = Utc::now();
                t.prune(now);
                if t.dirty {
                    table.store(Arc::new(t.snapshot()));
                    t.dirty = false;
                }
            }
        }
    }
}

/// The writer's state, split out so it can be driven with an injected clock.
struct Table {
    rows: HashMap<(String, &'static str), Row>,
    rates: HashMap<[u8; 6], RateState>,
    by_protocol: HashMap<&'static str, (&'static str, u64)>,
    frames: FrameStore,
    ttl: chrono::Duration,
    flood_pps: u32,
    total: u64,
    dirty: bool,
}

impl Table {
    fn new(ttl_secs: u64, flood_pps: u32, frames: FrameStore) -> Self {
        Self {
            rows: HashMap::new(),
            rates: HashMap::new(),
            by_protocol: HashMap::new(),
            frames,
            ttl: chrono::Duration::seconds(ttl_secs.max(1) as i64),
            flood_pps,
            total: 0,
            dirty: false,
        }
    }

    fn hit(&mut self, obs: BumObservation, now: DateTime<Utc>) {
        self.total += 1;
        let proto = obs.detection.proto;
        self.by_protocol
            .entry(proto.key)
            .and_modify(|e| e.1 += 1)
            .or_insert((proto.severity, 1));
        let key = (fmt_mac(&obs.src_mac), proto.key);
        let row = self.rows.entry(key.clone()).or_insert_with(|| Row {
            proto,
            iface: obs.iface.clone(),
            first_seen: now,
            last_seen: now,
            count: 0,
            details: Vec::new(),
            frame_count: 0,
        });
        row.last_seen = now;
        row.count += 1;
        row.iface = obs.iface;
        if let Some(d) = obs.detection.detail {
            if !row.details.contains(&d) && row.details.len() < MAX_DETAILS {
                row.details.push(d);
            }
        }
        if row.frame_count < MAX_FRAMES && !obs.frame.is_empty() {
            row.frame_count += 1;
            if let Ok(mut f) = self.frames.lock() {
                f.entry(key).or_default().push(CapturedFrame {
                    ts_sec: obs.ts_sec,
                    ts_usec: obs.ts_usec,
                    data: obs.frame,
                });
            }
        }
        self.cap();
        self.dirty = true;
    }

    fn rates(&mut self, sample: RateSample, now: DateTime<Utc>) {
        for (mac, bum, uu) in sample.counts {
            let st = self.rates.entry(mac).or_insert_with(|| RateState {
                window_start: now,
                bum: 0,
                uu: 0,
                iface: sample.iface.clone(),
            });
            st.bum += bum as u64;
            st.uu += uu as u64;
            let elapsed = (now - st.window_start).num_seconds();
            if elapsed >= RATE_WINDOW_SECS {
                let bum_pps = st.bum / elapsed.max(1) as u64;
                let uu_pps = st.uu / elapsed.max(1) as u64;
                let iface = st.iface.clone();
                st.window_start = now;
                st.bum = 0;
                st.uu = 0;
                if bum_pps >= self.flood_pps as u64 {
                    self.synth(mac, &iface, "bum_flood", format!("{bum_pps} frames/s"), now);
                }
                if uu_pps >= self.flood_pps as u64 {
                    self.synth(mac, &iface, "unknown_unicast_flood", format!("{uu_pps} frames/s"), now);
                }
            }
        }
        // Bound the rate map like the rows: drop sources quiet for a window.
        if self.rates.len() > MAX_KEYS {
            let cutoff = now - chrono::Duration::seconds(RATE_WINDOW_SECS);
            self.rates.retain(|_, s| s.window_start >= cutoff);
        }
    }

    fn synth(&mut self, mac: [u8; 6], iface: &str, key: &'static str, detail: String, now: DateTime<Utc>) {
        if let Some(proto) = bum_proto(key) {
            self.hit(
                BumObservation {
                    src_mac: mac,
                    iface: iface.to_string(),
                    detection: Detection { proto, detail: Some(detail) },
                    frame: Vec::new(),
                    ts_sec: 0,
                    ts_usec: 0,
                },
                now,
            );
        }
    }

    /// Drop rows unheard for `ttl`; returns true if anything changed.
    fn prune(&mut self, now: DateTime<Utc>) -> bool {
        let cutoff = now - self.ttl;
        let before = self.rows.len();
        let mut removed = Vec::new();
        self.rows.retain(|k, r| {
            let keep = r.last_seen >= cutoff;
            if !keep {
                removed.push(k.clone());
            }
            keep
        });
        self.forget_frames(&removed);
        let changed = self.rows.len() != before;
        if changed {
            self.dirty = true;
        }
        changed
    }

    /// Evict oldest rows beyond `MAX_KEYS`.
    fn cap(&mut self) {
        let mut removed = Vec::new();
        while self.rows.len() > MAX_KEYS {
            let oldest = self.rows.iter().min_by_key(|(_, r)| r.last_seen).map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.rows.remove(&k);
                    removed.push(k);
                }
                None => break,
            }
        }
        self.forget_frames(&removed);
    }

    fn forget_frames(&self, keys: &[(String, &'static str)]) {
        if keys.is_empty() {
            return;
        }
        if let Ok(mut f) = self.frames.lock() {
            for k in keys {
                f.remove(k);
            }
        }
    }

    fn snapshot(&self) -> BumSnapshot {
        let mut rows: Vec<BumRow> = self
            .rows
            .iter()
            .map(|((mac, _), r)| BumRow {
                src_mac: mac.clone(),
                protocol: r.proto.key,
                severity: r.proto.severity,
                iface: r.iface.clone(),
                first_seen: r.first_seen.to_rfc3339(),
                last_seen: r.last_seen.to_rfc3339(),
                count: r.count,
                details: r.details.clone(),
                frame_count: r.frame_count,
            })
            .collect();
        rows.sort_by(|a, b| a.src_mac.cmp(&b.src_mac).then(a.protocol.cmp(b.protocol)));
        let mut by_protocol: Vec<(&'static str, &'static str, u64)> =
            self.by_protocol.iter().map(|(k, (sev, n))| (*k, *sev, *n)).collect();
        by_protocol.sort();
        BumSnapshot { rows, by_protocol, observation_count: self.total }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    const SRC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01];
    const BCAST: [u8; 6] = [0xff; 6];

    fn ctx() -> ClassifyCtx {
        let mut c = ClassifyCtx::default();
        c.set_v4(&[("206.197.187.0".into(), 24)]);
        c.set_v6(&[("2001:504:30::".into(), 64)]);
        c
    }

    fn eth(dst: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&dst);
        f.extend_from_slice(&SRC);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }
    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(l4);
        p
    }
    fn udp(dport: u16, body: &[u8]) -> Vec<u8> {
        let mut u = vec![0x30, 0x39];
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&[0, 0, 0, 0]);
        u.extend_from_slice(body);
        u
    }
    fn ipv6(nh: u8, dst: [u8; 16], l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, 0, 0, nh, 255];
        let mut src = [0u8; 16];
        src[0] = 0xfe;
        src[1] = 0x80;
        src[15] = 1;
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(l4);
        p
    }
    fn ff02(last: u8) -> [u8; 16] {
        let mut d = [0u8; 16];
        d[0] = 0xff;
        d[1] = 0x02;
        d[15] = last;
        d
    }
    fn mcast_mac_v6(last: u8) -> [u8; 6] {
        [0x33, 0x33, 0, 0, 0, last]
    }
    fn key(frame: &[u8]) -> Option<&'static str> {
        classify(frame, &ctx()).map(|d| d.proto.key)
    }

    #[test]
    fn ipv6_ra_with_prefix_option() {
        // RA: type 134, flags M, lifetime 1800, then PIO for 2001:db8:beef::/64.
        let mut ra = vec![134, 0, 0, 0, 64, 0x80, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0];
        ra.extend_from_slice(&[3, 4, 64, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        ra.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let f = eth(mcast_mac_v6(1), 0x86dd, &ipv6(58, ff02(1), &ra));
        let d = classify(&f, &ctx()).expect("RA");
        assert_eq!(d.proto.key, "ipv6_ra");
        assert_eq!(d.proto.severity, "critical");
        assert_eq!(d.detail.as_deref(), Some("lifetime 1800s M prefix 2001:db8:beef::/64"));
    }

    #[test]
    fn icmpv6_types() {
        let rs = eth(mcast_mac_v6(2), 0x86dd, &ipv6(58, ff02(2), &[133, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(key(&rs), Some("ipv6_rs"));
        let ns = eth(mcast_mac_v6(0xff), 0x86dd, &ipv6(58, ff02(1), &[135, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(key(&ns), None, "NS is normal");
        let na = eth(mcast_mac_v6(1), 0x86dd, &ipv6(58, ff02(1), &[136, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(key(&na), None, "NA is normal");
        let echo = eth(mcast_mac_v6(1), 0x86dd, &ipv6(58, ff02(1), &[128, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(key(&echo), Some("icmpv6_echo_allnodes"));
        // MLD query behind a hop-by-hop header (router alert), like real ones.
        let mut hbh = vec![58, 0, 5, 2, 0, 0, 1, 0]; // next=ICMPv6, len 0 (8 bytes)
        hbh.extend_from_slice(&[130, 0, 0, 0, 0, 0, 0, 0]);
        let mldq = eth(mcast_mac_v6(1), 0x86dd, &ipv6(0, ff02(1), &hbh));
        assert_eq!(key(&mldq), Some("mld_query"));
        let mut hbh_rep = vec![58, 0, 5, 2, 0, 0, 1, 0];
        hbh_rep.extend_from_slice(&[143, 0, 0, 0, 0, 0, 0, 0]);
        let mldr = eth(mcast_mac_v6(0x16), 0x86dd, &ipv6(0, ff02(0x16), &hbh_rep));
        assert_eq!(key(&mldr), None, "MLDv2 report is normal");
    }

    #[test]
    fn ipv4_routing_and_redundancy_protocols() {
        let m = [0x01, 0x00, 0x5e, 0, 0, 5];
        let ospf = eth(m, 0x0800, &ipv4(89, [206, 197, 187, 9], [224, 0, 0, 5], &[2, 1, 0, 44, 10, 0, 0, 1, 0, 0, 0, 0]));
        let d = classify(&ospf, &ctx()).unwrap();
        assert_eq!(d.proto.key, "ospf");
        assert_eq!(d.detail.as_deref(), Some("v2 router-id 10.0.0.1 area 0"));
        assert_eq!(key(&eth(m, 0x0800, &ipv4(88, [10, 0, 0, 1], [224, 0, 0, 10], &[0; 20]))), Some("eigrp"));
        assert_eq!(key(&eth(m, 0x0800, &ipv4(103, [10, 0, 0, 1], [224, 0, 0, 13], &[0; 8]))), Some("pim"));
        let vrrp = eth(m, 0x0800, &ipv4(112, [10, 0, 0, 1], [224, 0, 0, 18], &[0x21, 7, 100, 1, 0, 0, 0, 0]));
        let d = classify(&vrrp, &ctx()).unwrap();
        assert_eq!(d.proto.key, "vrrp");
        assert_eq!(d.detail.as_deref(), Some("vrid 7 prio 100"));
        assert_eq!(key(&eth(m, 0x0800, &ipv4(2, [10, 0, 0, 1], [224, 0, 0, 1], &[0x11, 0, 0, 0, 0, 0, 0, 0]))), Some("igmp_query"));
        assert_eq!(key(&eth(m, 0x0800, &ipv4(2, [10, 0, 0, 1], [224, 0, 0, 22], &[0x22, 0, 0, 0, 0, 0, 0, 0]))), None, "IGMPv3 report is normal");
    }

    #[test]
    fn udp_protocols() {
        let cases: &[(u16, [u8; 4], &str)] = &[
            (67, [255, 255, 255, 255], "dhcpv4"),
            (68, [255, 255, 255, 255], "dhcpv4"),
            (5678, [255, 255, 255, 255], "mndp"),
            (20561, [255, 255, 255, 255], "mac_telnet"),
            (5353, [224, 0, 0, 251], "mdns"),
            (5355, [224, 0, 0, 252], "llmnr"),
            (1900, [239, 255, 255, 250], "ssdp"),
            (137, [255, 255, 255, 255], "netbios"),
            (138, [255, 255, 255, 255], "netbios"),
            (520, [224, 0, 0, 9], "rip"),
            (646, [224, 0, 0, 2], "ldp"),
            (1985, [224, 0, 0, 2], "hsrp"),
            (3222, [224, 0, 0, 102], "glbp"),
            (123, [255, 255, 255, 255], "ntp_broadcast"),
            (53, [255, 255, 255, 255], "dns_broadcast"),
        ];
        for (port, dst, want) in cases {
            let f = eth(BCAST, 0x0800, &ipv4(17, [206, 197, 187, 9], *dst, &udp(*port, &[0; 16])));
            assert_eq!(key(&f), Some(*want), "udp/{port}");
        }
        // Unicast NTP/DNS from an IX address are not flagged.
        let f = eth([0x02, 0, 0, 0, 0, 9], 0x0800, &ipv4(17, [206, 197, 187, 9], [206, 197, 187, 10], &udp(53, &[0; 16])));
        assert_eq!(key(&f), None);
        // IPv6 UDP.
        let f = eth(mcast_mac_v6(2), 0x86dd, &ipv6(17, ff02(2), &udp(547, &[0; 8])));
        assert_eq!(key(&f), Some("dhcpv6"));
    }

    #[test]
    fn mndp_identity_is_extracted_and_sanitized() {
        let mut body = vec![0, 0, 0, 0];
        body.extend_from_slice(&[0, 5, 0, 7]);
        body.extend_from_slice(b"rtr-\xff01"); // non-ASCII byte becomes '?'
        body.extend_from_slice(&[0, 8, 0, 3]);
        body.extend_from_slice(b"CCR");
        body.extend_from_slice(&[0, 7, 0, 5]);
        body.extend_from_slice(b"7.15.");
        let f = eth(BCAST, 0x0800, &ipv4(17, [10, 0, 0, 1], [255, 255, 255, 255], &udp(5678, &body)));
        let d = classify(&f, &ctx()).unwrap();
        assert_eq!(d.proto.key, "mndp");
        assert_eq!(d.detail.as_deref(), Some("identity rtr-?01 CCR 7.15."));
    }

    #[test]
    fn dhcp_hostname_option() {
        let mut body = vec![0u8; 236];
        body.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        body.extend_from_slice(&[53, 1, 1, 12, 4]);
        body.extend_from_slice(b"host");
        body.push(0xff);
        let f = eth(BCAST, 0x0800, &ipv4(17, [0, 0, 0, 0], [255, 255, 255, 255], &udp(67, &body)));
        let d = classify(&f, &ctx()).unwrap();
        assert_eq!(d.detail.as_deref(), Some("hostname host"));
    }

    #[test]
    fn l2_protocols() {
        // STP BPDU via LLC 0x42.
        let mut stp = vec![0x42, 0x42, 0x03, 0, 0, 0, 0, 0];
        stp.extend_from_slice(&[0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        stp.extend_from_slice(&[0; 20]);
        let f = eth([0x01, 0x80, 0xc2, 0, 0, 0], 0x0026, &stp);
        let d = classify(&f, &ctx()).unwrap();
        assert_eq!(d.proto.key, "stp");
        assert_eq!(d.detail.as_deref(), Some("type 0x00 root 8000.00:11:22:33:44:55"));
        // IS-IS.
        assert_eq!(key(&eth([0x01, 0x80, 0xc2, 0, 0, 0x14], 0x0050, &[0xfe, 0xfe, 0x03, 0x83, 0, 0, 0, 0])), Some("isis"));
        // CDP via SNAP.
        let mut cdp = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00];
        cdp.extend_from_slice(&[2, 180, 0, 0]);
        cdp.extend_from_slice(&[0x00, 0x01, 0x00, 0x09]);
        cdp.extend_from_slice(b"core1");
        let d = classify(&eth([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc], 0x0040, &cdp), &ctx()).unwrap();
        assert_eq!(d.proto.key, "cdp");
        assert_eq!(d.detail.as_deref(), Some("device core1"));
        // PVST+ is STP; VTP is cisco_l2.
        let mut pvst = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x01, 0x0b];
        pvst.extend_from_slice(&[0; 40]);
        assert_eq!(key(&eth([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd], 0x0040, &pvst)), Some("stp"));
        let vtp = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x03, 0, 0, 0, 0];
        assert_eq!(key(&eth([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc], 0x0040, &vtp)), Some("cisco_l2"));
        // LLDP with system name TLV.
        let mut lldp = vec![0x02, 0x07, 0x04, 1, 2, 3, 4, 5, 6]; // chassis id
        lldp.extend_from_slice(&[0x0a, 0x04]); // type 5, len 4
        lldp.extend_from_slice(b"edge");
        lldp.extend_from_slice(&[0, 0]);
        let d = classify(&eth([0x01, 0x80, 0xc2, 0, 0, 0x0e], 0x88cc, &lldp), &ctx()).unwrap();
        assert_eq!(d.proto.key, "lldp");
        assert_eq!(d.detail.as_deref(), Some("system edge"));
        assert_eq!(key(&eth([0x01, 0x80, 0xc2, 0, 0, 2], 0x8809, &[1, 1, 0])), Some("lacp"));
        assert_eq!(key(&eth(BCAST, 0x88bf, &[0; 8])), Some("romon"));
        assert_eq!(key(&eth([0xab, 0, 0, 2, 0, 0], 0x6002, &[0; 8])), Some("dec_mop"));
        assert_eq!(key(&eth(BCAST, 0x9000, &[0; 8])), Some("loop_detect"));
        let d = classify(&eth(BCAST, 0x8137, &[0; 8]), &ctx()).unwrap();
        assert_eq!(d.proto.key, "unknown_ethertype");
        assert_eq!(d.detail.as_deref(), Some("ethertype 0x8137"));
        assert_eq!(key(&eth([0x02, 0, 0, 0, 0, 9], 0x8137, &[0; 8])), None, "unicast unknown is not ours to judge");
    }

    #[test]
    fn tagged_and_foreign_heuristics() {
        let d = classify(&eth(BCAST, 0x8100, &[0x00, 0x64, 0x08, 0x06, 0, 0]), &ctx()).unwrap();
        assert_eq!(d.proto.key, "dot1q_tagged");
        assert_eq!(d.detail.as_deref(), Some("vid 100"));
        // ARP inside the IX prefix is fine; outside it is a leak.
        let arp = |spa: [u8; 4]| {
            let mut a = vec![0, 1, 8, 0, 6, 4, 0, 1];
            a.extend_from_slice(&SRC);
            a.extend_from_slice(&spa);
            a.extend_from_slice(&[0; 10]);
            eth(BCAST, 0x0806, &a)
        };
        assert_eq!(key(&arp([206, 197, 187, 5])), None);
        let d = classify(&arp([192, 168, 1, 5]), &ctx()).unwrap();
        assert_eq!(d.proto.key, "foreign_arp");
        assert_eq!(d.detail.as_deref(), Some("sender 192.168.1.5"));
        // With no prefixes known, never flag.
        assert_eq!(classify(&arp([192, 168, 1, 5]), &ClassifyCtx::default()), None);
        // IPv4 broadcast from an off-net source, otherwise unremarkable.
        let f = eth(BCAST, 0x0800, &ipv4(17, [192, 168, 1, 5], [255, 255, 255, 255], &udp(9999, &[0; 4])));
        assert_eq!(key(&f), Some("foreign_ipv4_broadcast"));
        let f = eth(BCAST, 0x0800, &ipv4(17, [206, 197, 187, 5], [255, 255, 255, 255], &udp(9999, &[0; 4])));
        assert_eq!(key(&f), None);
    }

    #[test]
    fn ignored_sources_and_garbage_never_panic() {
        let mut c = ctx();
        c.ignore_src_macs.insert(SRC);
        let ra = eth(mcast_mac_v6(1), 0x86dd, &ipv6(58, ff02(1), &[134, 0, 0, 0, 64, 0, 0, 0]));
        assert_eq!(classify(&ra, &c), None);
        // Truncated everything.
        for n in 0..ra.len() {
            let _ = classify(&ra[..n], &ctx());
        }
        // TLV walkers with bogus lengths.
        let mut cdp = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00, 2, 180, 0, 0];
        cdp.extend_from_slice(&[0x00, 0x02, 0xff, 0xff, 1, 2]);
        let _ = classify(&eth([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc], 0x0040, &cdp), &ctx());
        let lldp = [0x0a, 0xff, b'x'];
        let _ = classify(&eth([0x01, 0x80, 0xc2, 0, 0, 0x0e], 0x88cc, &lldp), &ctx());
        assert_eq!(sanitize(b"ab\x00\xffcd", 3), "ab?");
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }
    fn obs(mac: [u8; 6], key: &str, detail: Option<&str>) -> BumObservation {
        BumObservation {
            src_mac: mac,
            iface: "ens19".into(),
            detection: Detection { proto: bum_proto(key).unwrap(), detail: detail.map(str::to_string) },
            frame: vec![1, 2, 3],
            ts_sec: 1,
            ts_usec: 0,
        }
    }

    #[test]
    fn table_folds_details_frames_and_prunes() {
        let frames: FrameStore = Arc::new(Mutex::new(HashMap::new()));
        let mut t = Table::new(7200, 50, frames.clone());
        let t0 = at("2026-09-02T00:00:00Z");
        for i in 0..20u8 {
            t.hit(obs(SRC, "ipv6_ra", Some(if i % 2 == 0 { "a" } else { "b" })), t0 + chrono::Duration::seconds(i as i64));
        }
        let snap = t.snapshot();
        assert_eq!(snap.rows.len(), 1);
        let r = &snap.rows[0];
        assert_eq!(r.count, 20);
        assert_eq!(r.details, vec!["a", "b"]);
        assert_eq!(r.frame_count, MAX_FRAMES);
        assert_eq!(frames.lock().unwrap()[&(r.src_mac.clone(), "ipv6_ra")].len(), MAX_FRAMES);
        assert_eq!(snap.by_protocol, vec![("ipv6_ra", "critical", 20)]);
        // Prune after TTL.
        assert!(!t.prune(t0 + chrono::Duration::seconds(3600)));
        assert!(t.prune(t0 + chrono::Duration::seconds(7300)));
        assert!(t.snapshot().rows.is_empty());
        assert!(frames.lock().unwrap().is_empty(), "frames dropped with the row");
        assert_eq!(t.snapshot().by_protocol, vec![("ipv6_ra", "critical", 20)], "lifetime counters survive");
    }

    #[test]
    fn table_caps_distinct_keys() {
        let frames: FrameStore = Arc::new(Mutex::new(HashMap::new()));
        let mut t = Table::new(7200, 50, frames);
        let t0 = at("2026-09-02T00:00:00Z");
        for i in 0..(MAX_KEYS + 10) {
            let mut mac = SRC;
            mac[4] = (i >> 8) as u8;
            mac[5] = i as u8;
            t.hit(obs(mac, "mdns", None), t0 + chrono::Duration::seconds(i as i64));
        }
        assert_eq!(t.rows.len(), MAX_KEYS);
        assert!(!t.rows.contains_key(&(fmt_mac(&SRC), "mdns")), "oldest evicted");
    }

    #[test]
    fn flood_rates_synthesize_rows_after_a_window() {
        let frames: FrameStore = Arc::new(Mutex::new(HashMap::new()));
        let mut t = Table::new(7200, 50, frames);
        let t0 = at("2026-09-02T00:00:00Z");
        for s in 0..=60 {
            t.rates(
                RateSample { iface: "ens19".into(), counts: vec![(SRC, 100, 3)] },
                t0 + chrono::Duration::seconds(s),
            );
        }
        let snap = t.snapshot();
        assert_eq!(snap.rows.len(), 1);
        assert_eq!(snap.rows[0].protocol, "bum_flood");
        assert_eq!(snap.rows[0].details, vec!["101 frames/s"]);
    }
}
