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
use pnet::packet::icmpv6::ndp::NeighborAdvertPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::store::Observation;

/// Spawn a dedicated OS thread capturing on `iface`. Returns immediately.
pub fn spawn_capture(iface: String, tx: mpsc::Sender<Observation>, dropped: Arc<AtomicU64>) {
    std::thread::Builder::new()
        .name(format!("capture-{iface}"))
        .spawn(move || {
            if let Err(e) = capture_loop(&iface, &tx, &dropped) {
                warn!("capture on {iface} stopped: {e}");
            }
        })
        .expect("spawn capture thread");
}

fn capture_loop(
    iface: &str,
    tx: &mpsc::Sender<Observation>,
    dropped: &Arc<AtomicU64>,
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

/// Parse one Ethernet frame into an observation, if it's an ARP or NDP message
/// that asserts an (ip, mac) binding.
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
            Some(Observation {
                ip: ip.to_string(),
                family: "IPv4".to_string(),
                mac: arp.get_sender_hw_addr().to_string(),
                iface: iface.to_string(),
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
                    Some(Observation {
                        ip: target.to_string(),
                        family: "IPv6".to_string(),
                        mac: eth.get_source().to_string(),
                        iface: iface.to_string(),
                    })
                }
                // Neighbor Solicitation: the source address (when set) belongs to
                // the soliciting node; DAD probes use the unspecified source.
                Icmpv6Types::NeighborSolicit => {
                    let src = ip6.get_source();
                    if src.is_unspecified() || is_link_local(&src) {
                        return None;
                    }
                    Some(Observation {
                        ip: src.to_string(),
                        family: "IPv6".to_string(),
                        mac: eth.get_source().to_string(),
                        iface: iface.to_string(),
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
