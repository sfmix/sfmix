//! Kernel-only neighbor solicitation.
//!
//! To stimulate ARP/NDP we send ordinary ICMP/ICMPv6 echo requests to each
//! assigned IP and let the *kernel* resolve the on-link neighbor (issuing the
//! ARP request / NDP Neighbor Solicitation itself). We never craft or transmit
//! L2 ARP/NDP frames — that is the safety guarantee against polluting the IX.
//!
//! We don't read the echo replies; the passive capture path observes whatever
//! ARP replies / Neighbor Advertisements the solicitation provokes.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::{debug, warn};

/// Periodically sweep the current target set, pacing each send.
pub async fn run(targets: Arc<ArcSwap<Vec<String>>>, interval_secs: u64, pace_ms: u64) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs.max(1)));
    loop {
        tick.tick().await;
        let ips = targets.load();
        if ips.is_empty() {
            continue;
        }
        let mut sent = 0u64;
        for ip_str in ips.iter() {
            let Ok(addr) = ip_str.parse::<IpAddr>() else { continue };
            if let Err(e) = solicit(addr) {
                debug!("solicit {ip_str} failed: {e}");
            } else {
                sent += 1;
            }
            if pace_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(pace_ms)).await;
            }
        }
        debug!("solicit sweep: {sent}/{} targets", ips.len());
    }
}

/// Send a single ICMP/ICMPv6 echo request via a raw socket. The kernel handles
/// neighbor resolution; we discard the result.
fn solicit(addr: IpAddr) -> Result<()> {
    let (domain, proto, packet) = match addr {
        IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4, echo_packet(false)),
        IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6, echo_packet(true)),
    };
    let socket = Socket::new(domain, Type::RAW, Some(proto)).context("creating ICMP socket")?;
    let dest: SocketAddr = SocketAddr::new(addr, 0);
    socket.send_to(&packet, &dest.into()).context("sending echo")?;
    Ok(())
}

/// Build a minimal ICMP echo-request packet with a zero checksum.
///
/// The kernel recomputes/validates checksums for ICMPv6 raw sockets (it has the
/// pseudo-header); for IPv4 ICMP a zero checksum is tolerated by Linux for raw
/// sends. Either way our goal is only to make the kernel resolve the neighbor.
fn echo_packet(v6: bool) -> Vec<u8> {
    // type, code, checksum(2), identifier(2), sequence(2)
    let icmp_type = if v6 { 128u8 } else { 8u8 }; // Echo Request
    vec![icmp_type, 0, 0, 0, 0, 1, 0, 1]
}

/// Log once at startup if raw sockets are unavailable (missing CAP_NET_RAW),
/// so the failure mode is obvious rather than silent per-send debug noise.
pub fn preflight() {
    match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(_) => {}
        Err(e) => warn!(
            "cannot open raw ICMP socket ({e}); solicitation disabled — \
             ensure the container has CAP_NET_RAW"
        ),
    }
}
