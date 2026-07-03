//! Passive ARP/NDP capture via AF_PACKET (pnet).
//!
//! One blocking capture loop runs per interface on a dedicated OS thread and
//! hands parsed observations to the async writer via a bounded channel. We only
//! read frames — nothing is transmitted here. Promiscuous mode is left OFF:
//! broadcast ARP, multicast NDP, and replies to our own kernel-issued solicits
//! are delivered without it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use pnet::datalink::{self, Channel, Config};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::icmpv6::ndp::{
    NdpOption, NdpOptionType, NdpOptionTypes, NeighborAdvertPacket, NeighborSolicitPacket,
};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::ringbuf::CapturedFrame;
use crate::store::Observation;

/// Spawn a dedicated OS thread capturing on `iface`. Returns immediately.
/// When `ring_tx` is `Some`, every ARP/NDP frame's raw bytes are also teed to the
/// ring buffer for later evidence extraction.
pub fn spawn_capture(
    iface: String,
    tx: mpsc::Sender<Observation>,
    dropped: Arc<AtomicU64>,
    ring_tx: Option<std::sync::mpsc::SyncSender<CapturedFrame>>,
) {
    std::thread::Builder::new()
        .name(format!("capture-{iface}"))
        .spawn(move || {
            if let Err(e) = capture_loop(&iface, &tx, &dropped, ring_tx.as_ref()) {
                warn!("capture on {iface} stopped: {e}");
            }
        })
        .expect("spawn capture thread");
}

fn capture_loop(
    iface: &str,
    tx: &mpsc::Sender<Observation>,
    dropped: &Arc<AtomicU64>,
    ring_tx: Option<&std::sync::mpsc::SyncSender<CapturedFrame>>,
) -> anyhow::Result<()> {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == iface)
        .ok_or_else(|| anyhow::anyhow!("interface {iface} not found"))?;

    // Default config: promiscuous OFF, read-only use of the channel.
    let cfg = Config { promiscuous: false, ..Default::default() };
    let mut rx = match datalink::channel(&interface, cfg) {
        Ok(Channel::Ethernet(_tx, rx)) => rx,
        Ok(_) => anyhow::bail!("unsupported channel type on {iface}"),
        Err(e) => anyhow::bail!("opening channel on {iface}: {e}"),
    };
    info!("capturing ARP/NDP on {iface}");

    loop {
        match rx.next() {
            Ok(frame) => {
                // Tee raw ARP/NDP frames to the ring buffer (incl. ARP requests
                // and DAD probes that `parse_frame` discards — they're the
                // "who was asking" context evidence needs). Never block: drop on
                // backpressure (ring writer is best-effort).
                if let Some(ring) = ring_tx {
                    if is_arp_or_ndp(frame) {
                        let (ts_sec, ts_usec) = now_ts();
                        let _ = ring.try_send(CapturedFrame { ts_sec, ts_usec, data: frame.to_vec() });
                    }
                }
                if let Some(obs) = parse_frame(frame, iface) {
                    // Never block the capture thread: drop and count on backpressure.
                    if tx.try_send(obs).is_err() {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(e) => {
                warn!("capture read error on {iface}: {e}");
            }
        }
    }
}

/// Wall-clock now split into the (seconds, microseconds) a pcap record wants.
fn now_ts() -> (u32, u32) {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() as u32, d.subsec_micros())
}

/// True for ARP frames and IPv6 ICMPv6 NDP frames (RS/RA/NS/NA/Redirect) — the
/// frame classes worth keeping in the ring buffer.
fn is_arp_or_ndp(frame: &[u8]) -> bool {
    let Some(eth) = EthernetPacket::new(frame) else { return false };
    match eth.get_ethertype() {
        EtherTypes::Arp => true,
        EtherTypes::Ipv6 => {
            let Some(ip6) = Ipv6Packet::new(eth.payload()) else { return false };
            if ip6.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
                return false;
            }
            match Icmpv6Packet::new(ip6.payload()).map(|i| i.get_icmpv6_type()) {
                Some(t) => matches!(
                    t,
                    Icmpv6Types::RouterSolicit
                        | Icmpv6Types::RouterAdvert
                        | Icmpv6Types::NeighborSolicit
                        | Icmpv6Types::NeighborAdvert
                        | Icmpv6Types::Redirect
                ),
                None => false,
            }
        }
        _ => false,
    }
}

/// The MAC carried in the first source/target link-layer-address NDP option, if
/// present. For these options pnet strips the 2-byte option header, so `data` is
/// exactly the 6 address octets; guard the length so a truncated/malformed option
/// can never panic the capture thread.
fn lladdr_option_mac(options: &[NdpOption], want: NdpOptionType) -> Option<MacAddr> {
    options
        .iter()
        .find(|o| o.option_type == want && o.data.len() >= 6)
        .map(|o| MacAddr::new(o.data[0], o.data[1], o.data[2], o.data[3], o.data[4], o.data[5]))
}

/// Parse one Ethernet frame into an observation, if it's an ARP or NDP message
/// that asserts an (ip, mac) binding. `mismatched_mac` is set when the frame's
/// two MAC assertions disagree — the fingerprint of a re-flooded (reflected)
/// frame, whose outer Ethernet source was rewritten but whose link-layer option
/// (or ARP sender-hardware-address) still names the original owner.
fn parse_frame(frame: &[u8], iface: &str) -> Option<Observation> {
    let eth = EthernetPacket::new(frame)?;
    match eth.get_ethertype() {
        EtherTypes::Arp => {
            let arp = ArpPacket::new(eth.payload())?;
            // Sender fields carry the claim, for both requests and replies
            // (incl. gratuitous ARP). Skip the unspecified 0.0.0.0 announcer.
            let ip = arp.get_sender_proto_addr();
            if ip.is_unspecified() {
                return None;
            }
            // The claim is the ARP sender-hardware-address; a frame re-flooded by a
            // bridge keeps that but rewrites the outer Ethernet source, so a
            // disagreement names the reflector.
            let sender_hw = arp.get_sender_hw_addr();
            let eth_src = eth.get_source();
            Some(Observation {
                ip: ip.to_string(),
                family: "IPv4".to_string(),
                mac: sender_hw.to_string(),
                iface: iface.to_string(),
                mismatched_mac: (sender_hw != eth_src).then(|| eth_src.to_string()),
            })
        }
        EtherTypes::Ipv6 => {
            let ip6 = Ipv6Packet::new(eth.payload())?;
            if ip6.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
                return None;
            }
            let icmp = Icmpv6Packet::new(ip6.payload())?;
            match icmp.get_icmpv6_type() {
                // Neighbor Advertisement: the sender owns the target address, and
                // the Ethernet source is its MAC.
                Icmpv6Types::NeighborAdvert => {
                    let na = NeighborAdvertPacket::new(ip6.payload())?;
                    let target = na.get_target_addr();
                    if target.is_unspecified() || is_link_local(&target) {
                        return None;
                    }
                    // A normal NA's target-link-layer-address option repeats the
                    // sender's own MAC (the Ethernet source). A reflected NA keeps
                    // the original owner's MAC in that option while the outer source
                    // is the reflector's — that disagreement is the tell.
                    let eth_src = eth.get_source();
                    let mismatched_mac = lladdr_option_mac(&na.get_options(), NdpOptionTypes::TargetLLAddr)
                        .filter(|opt| *opt != eth_src)
                        .map(|opt| opt.to_string());
                    Some(Observation {
                        ip: target.to_string(),
                        family: "IPv6".to_string(),
                        mac: eth_src.to_string(),
                        iface: iface.to_string(),
                        mismatched_mac,
                    })
                }
                // Neighbor Solicitation: the source address (when set) belongs to
                // the soliciting node; DAD probes use the unspecified source.
                Icmpv6Types::NeighborSolicit => {
                    let src = ip6.get_source();
                    if src.is_unspecified() || is_link_local(&src) {
                        return None;
                    }
                    // Same reflection tell as NA, via the source-link-layer-address
                    // option: a re-flooded NS preserves the soliciting node's own
                    // MAC there while the outer source is the reflector's.
                    let ns = NeighborSolicitPacket::new(ip6.payload())?;
                    let eth_src = eth.get_source();
                    let mismatched_mac = lladdr_option_mac(&ns.get_options(), NdpOptionTypes::SourceLLAddr)
                        .filter(|opt| *opt != eth_src)
                        .map(|opt| opt.to_string());
                    Some(Observation {
                        ip: src.to_string(),
                        family: "IPv6".to_string(),
                        mac: eth_src.to_string(),
                        iface: iface.to_string(),
                        mismatched_mac,
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_link_local(addr: &std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    // A global IPv6 address 2001:db8::<tag> (non-link-local, non-unspecified).
    fn addr6(tag: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = 0x20;
        a[1] = 0x01;
        a[2] = 0x0d;
        a[3] = 0xb8;
        a[15] = tag;
        a
    }

    /// Build an Ethernet+IPv6 frame carrying an ICMPv6 NDP message. `icmp_body` is
    /// the ICMPv6 payload (type byte first); `ip6_src` is the IPv6 source.
    fn ipv6_frame(eth_src: [u8; 6], ip6_src: [u8; 16], icmp_body: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]); // dst (multicast)
        f.extend_from_slice(&eth_src); // src
        f.extend_from_slice(&[0x86, 0xdd]); // ethertype IPv6
        f.push(0x60); // version 6
        f.extend_from_slice(&[0x00, 0x00, 0x00]); // tc/flow
        f.extend_from_slice(&(icmp_body.len() as u16).to_be_bytes()); // payload_length
        f.push(58); // next header = ICMPv6
        f.push(255); // hop limit
        f.extend_from_slice(&ip6_src);
        f.extend_from_slice(&addr6(0)); // dst (unspecified is fine for parsing)
        f.extend_from_slice(icmp_body);
        f
    }

    /// ICMPv6 Neighbor Advertisement body for `target`, optionally with a
    /// target-link-layer-address option naming `opt_mac`.
    fn na_body(target: [u8; 16], opt_mac: Option<[u8; 6]>) -> Vec<u8> {
        let mut b = vec![136, 0, 0, 0]; // type, code, checksum(0)
        b.extend_from_slice(&[0x20, 0, 0, 0]); // flags (override) + reserved
        b.extend_from_slice(&target);
        if let Some(m) = opt_mac {
            b.push(2); // TargetLLAddr
            b.push(1); // length (8 octets)
            b.extend_from_slice(&m);
        }
        b
    }

    /// ICMPv6 Neighbor Solicitation body for `target`, with a source-link-layer
    /// option naming `opt_mac`.
    fn ns_body(target: [u8; 16], opt_mac: [u8; 6]) -> Vec<u8> {
        let mut b = vec![135, 0, 0, 0]; // type, code, checksum(0)
        b.extend_from_slice(&[0, 0, 0, 0]); // reserved
        b.extend_from_slice(&target);
        b.push(1); // SourceLLAddr
        b.push(1); // length
        b.extend_from_slice(&opt_mac);
        b
    }

    /// Build an ARP frame (reply) claiming `spa` from `sender_hw`, transmitted with
    /// Ethernet source `eth_src`.
    fn arp_frame(eth_src: [u8; 6], sender_hw: [u8; 6], spa: [u8; 4]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst
        f.extend_from_slice(&eth_src);
        f.extend_from_slice(&[0x08, 0x06]); // ethertype ARP
        f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]); // htype/ptype/hlen/plen/oper=reply
        f.extend_from_slice(&sender_hw);
        f.extend_from_slice(&spa);
        f.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // target hw
        f.extend_from_slice(&[10, 0, 0, 254]); // target proto
        f
    }

    const REFLECTOR: [u8; 6] = [0x0a, 0x00, 0x05, 0x18, 0x9d, 0x49];
    const OWNER: [u8; 6] = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01];

    #[test]
    fn clean_ns_has_no_mismatch() {
        // Soliciting node's SLLA option matches the Ethernet source.
        let frame = ipv6_frame(OWNER, addr6(1), &ns_body(addr6(9), OWNER));
        let obs = parse_frame(&frame, "vlan998").expect("NS parses");
        assert_eq!(obs.mac, "aa:bb:cc:00:00:01");
        assert_eq!(obs.mismatched_mac, None);
    }

    #[test]
    fn reflected_ns_flags_the_original_owner() {
        // Outer source is the reflector; the SLLA option still names the owner.
        let frame = ipv6_frame(REFLECTOR, addr6(1), &ns_body(addr6(9), OWNER));
        let obs = parse_frame(&frame, "vlan998").expect("NS parses");
        assert_eq!(obs.mac, "0a:00:05:18:9d:49", "mac is the outer (reflector) source");
        assert_eq!(obs.mismatched_mac.as_deref(), Some("aa:bb:cc:00:00:01"), "option preserves the owner");
    }

    #[test]
    fn reflected_na_flags_the_original_owner() {
        let frame = ipv6_frame(REFLECTOR, addr6(1), &na_body(addr6(9), Some(OWNER)));
        let obs = parse_frame(&frame, "vlan998").expect("NA parses");
        assert_eq!(obs.mac, "0a:00:05:18:9d:49");
        assert_eq!(obs.mismatched_mac.as_deref(), Some("aa:bb:cc:00:00:01"));
    }

    #[test]
    fn na_without_options_is_still_an_observation() {
        let frame = ipv6_frame(OWNER, addr6(1), &na_body(addr6(9), None));
        let obs = parse_frame(&frame, "vlan998").expect("optionless NA parses");
        assert_eq!(obs.mac, "aa:bb:cc:00:00:01");
        assert_eq!(obs.mismatched_mac, None, "no option → no mismatch signal");
    }

    #[test]
    fn arp_sender_hw_vs_ethernet_source_mismatch() {
        // ARP sender-hardware-address is the owner; the frame was re-transmitted by
        // the reflector, so the Ethernet source differs.
        let frame = arp_frame(REFLECTOR, OWNER, [10, 0, 0, 1]);
        let obs = parse_frame(&frame, "vlan998").expect("ARP parses");
        assert_eq!(obs.mac, "aa:bb:cc:00:00:01", "claim is the sender-hw-addr");
        assert_eq!(obs.mismatched_mac.as_deref(), Some("0a:00:05:18:9d:49"), "reflector is the outer source");
    }

    #[test]
    fn clean_arp_has_no_mismatch() {
        let frame = arp_frame(OWNER, OWNER, [10, 0, 0, 1]);
        let obs = parse_frame(&frame, "vlan998").expect("ARP parses");
        assert_eq!(obs.mismatched_mac, None);
    }
}
