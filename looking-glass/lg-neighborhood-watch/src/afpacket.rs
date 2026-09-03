//! Minimal AF_PACKET receive socket.
//!
//! pnet's datalink channel gives us frames but hides the file descriptor, so we
//! could neither join the promiscuous/all-multicast membership ourselves nor
//! attach an in-kernel filter. Both matter for the LAN-hygiene classifier:
//!
//! - **Membership.** With promiscuous mode off the NIC only delivers unicast to
//!   our own MAC, broadcast, and the multicast groups the host joined — so CDP,
//!   LLDP, STP, OSPF, mDNS and friends (all to well-known multicast MACs) would
//!   never reach us. `PACKET_MR_PROMISC` / `PACKET_MR_ALLMULTI` are per-socket
//!   memberships and need only `CAP_NET_RAW` (unlike `SIOCSIFFLAGS`).
//! - **Prefilter.** A classic-BPF program drops, in the kernel, every unicast
//!   frame addressed to *this host* that is not ARP or ICMPv6 — i.e. the route
//!   server's own BGP and management traffic never crosses into userspace.
//!   That is what keeps this sensor cheap on a host that also runs BIRD.
//!
//! Receive-only: nothing here can transmit.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result};
use serde::Deserialize;

/// How the socket subscribes to frames the NIC would otherwise filter out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RxMode {
    /// No membership: own-MAC unicast, broadcast and joined multicast only
    /// (the pre-hygiene behaviour). Useful as a load-comparison baseline.
    Unicast,
    /// All multicast + broadcast. Sees every catalog protocol; still drops
    /// unknown-unicast flooding at the NIC.
    AllMulti,
    /// Everything on the wire, including unknown-unicast flooding.
    Promisc,
}

impl RxMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RxMode::Unicast => "unicast",
            RxMode::AllMulti => "allmulti",
            RxMode::Promisc => "promisc",
        }
    }
}

const ETH_P_ALL: u16 = 0x0003;
const SOL_PACKET: libc::c_int = 263;
const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
const PACKET_STATISTICS: libc::c_int = 6;
const PACKET_MR_PROMISC: libc::c_ushort = 1;
const PACKET_MR_ALLMULTI: libc::c_ushort = 2;

#[repr(C)]
struct PacketMreq {
    mr_ifindex: libc::c_int,
    mr_type: libc::c_ushort,
    mr_alen: libc::c_ushort,
    mr_address: [u8; 8],
}

#[repr(C)]
#[derive(Default)]
struct TpacketStats {
    tp_packets: libc::c_uint,
    tp_drops: libc::c_uint,
}

/// A bound, filtered AF_PACKET socket on one interface.
pub struct RawSocket {
    fd: OwnedFd,
    own_mac: [u8; 6],
}

impl RawSocket {
    pub fn open(iface: &str, mode: RxMode) -> Result<Self> {
        let ifindex = if_index(iface)?;
        let own_mac = read_own_mac(iface)?;

        // SAFETY: plain libc socket creation; the fd is owned immediately below.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                ETH_P_ALL.to_be() as libc::c_int,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()).context("socket(AF_PACKET)");
        }
        // SAFETY: `raw` is a valid, freshly created fd we exclusively own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // Bind to the interface so we only see its frames.
        // SAFETY: sockaddr_ll is POD; zero-init then set the fields we need.
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as libc::c_ushort;
        sll.sll_protocol = ETH_P_ALL.to_be();
        sll.sll_ifindex = ifindex;
        // SAFETY: valid fd, valid pointer/length for sockaddr_ll.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("bind({iface})"));
        }

        // Membership (per-socket; released automatically when the fd closes).
        let mr_type = match mode {
            RxMode::Unicast => None,
            RxMode::AllMulti => Some(PACKET_MR_ALLMULTI),
            RxMode::Promisc => Some(PACKET_MR_PROMISC),
        };
        if let Some(t) = mr_type {
            let mreq = PacketMreq { mr_ifindex: ifindex, mr_type: t, mr_alen: 0, mr_address: [0; 8] };
            // SAFETY: valid fd; pointer/length describe the repr(C) struct.
            let rc = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    SOL_PACKET,
                    PACKET_ADD_MEMBERSHIP,
                    &mreq as *const PacketMreq as *const libc::c_void,
                    std::mem::size_of::<PacketMreq>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("PACKET_ADD_MEMBERSHIP({}) on {iface}", mode.as_str()));
            }
        }

        // Kernel prefilter.
        let prog = prefilter(mode, own_mac);
        let fprog = libc::sock_fprog {
            len: prog.len() as libc::c_ushort,
            filter: prog.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: valid fd; `prog` outlives the call (the kernel copies it).
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &fprog as *const libc::sock_fprog as *const libc::c_void,
                std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("SO_ATTACH_FILTER");
        }

        // A bigger receive buffer rides out short bursts (a flood) without the
        // kernel dropping; drops are still counted via PACKET_STATISTICS.
        let rcvbuf: libc::c_int = 2 * 1024 * 1024;
        // SAFETY: valid fd; c_int by pointer/size.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        // Wake the blocking recv once a second even on a silent wire so the
        // capture loop can flush its per-second rate samples and stats.
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        // SAFETY: valid fd; timeval by pointer/size.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        Ok(Self { fd, own_mac })
    }

    /// Blocking receive of one frame into `buf`. Returns `Ok(Some(len))` for a
    /// frame (truncated to `buf.len()`), `Ok(None)` on the 1 s receive timeout.
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        // SAFETY: valid fd; buf pointer/len are a live mutable slice.
        let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            return match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted => Ok(None),
                _ => Err(e),
            };
        }
        Ok(Some(n as usize))
    }

    /// Kernel-side counters since the last call: (frames delivered to the
    /// socket, frames dropped for lack of buffer). Resets on read.
    pub fn stats(&self) -> std::io::Result<(u64, u64)> {
        let mut st = TpacketStats::default();
        let mut len = std::mem::size_of::<TpacketStats>() as libc::socklen_t;
        // SAFETY: valid fd; out-pointer/len describe the repr(C) struct.
        let rc = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_STATISTICS,
                &mut st as *mut TpacketStats as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((st.tp_packets as u64, st.tp_drops as u64))
    }

    pub fn own_mac(&self) -> [u8; 6] {
        self.own_mac
    }
}

fn if_index(iface: &str) -> Result<libc::c_int> {
    let c = std::ffi::CString::new(iface).context("interface name")?;
    // SAFETY: valid NUL-terminated string.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        anyhow::bail!("interface {iface} not found");
    }
    Ok(idx as libc::c_int)
}

/// The interface's own MAC, from sysfs (no ioctl privileges needed).
fn read_own_mac(iface: &str) -> Result<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .with_context(|| format!("reading MAC of {iface}"))?;
    parse_mac(s.trim()).ok_or_else(|| anyhow::anyhow!("unparseable MAC for {iface}: {s:?}"))
}

/// Parse `aa:bb:cc:dd:ee:ff`.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for b in out.iter_mut() {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

pub fn fmt_mac(m: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

// Classic BPF opcodes.
const LDB_ABS: u16 = 0x30; // BPF_LD | BPF_B | BPF_ABS
const LDH_ABS: u16 = 0x28; // BPF_LD | BPF_H | BPF_ABS
const LDW_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
const RET_K: u16 = 0x06; // BPF_RET | BPF_K

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Build the in-kernel prefilter. Accepts (returns 0xffff) any frame that is:
/// broadcast/multicast; ARP (unicast replies to our kernel-issued solicits);
/// 802.1Q/802.1ad tagged; IPv6 ICMPv6 (unicast NA replies, RAs); and, in
/// promiscuous mode, unicast whose destination is not our own MAC (unknown-
/// unicast flooding). Everything else — the host's own unicast IP traffic — is
/// dropped before it leaves the kernel.
pub fn prefilter(mode: RxMode, own_mac: [u8; 6]) -> Vec<libc::sock_filter> {
    let promisc = mode == RxMode::Promisc;
    // Layout (indices):
    //  0 ldb [0]              dst[0]
    //  1 jset #1 → ACC
    //  2 ldh [12]             ethertype
    //  3 jeq 0x0806 → ACC
    //  4 jeq 0x8100 → ACC
    //  5 jeq 0x88a8 → ACC
    //  6 jeq 0x86dd → 7, else → OTHER
    //  7 ldb [20]             ipv6 next header
    //  8 jeq 58 → ACC, else → OTHER
    //  promisc: OTHER =
    //  9 ldw [2]              dst[2..6]
    // 10 jeq own_lo → 11, else → ACC
    // 11 ldh [0]              dst[0..2]
    // 12 jeq own_hi → DROP, else → ACC
    // 13 ACC: ret 0xffff
    // 14 DROP: ret 0
    //  non-promisc: OTHER = DROP; 9 ACC, 10 DROP
    let (acc, drop, other) = if promisc { (13u8, 14u8, 9u8) } else { (9u8, 10u8, 10u8) };
    let j = |from: u8, to: u8| -> u8 { to - (from + 1) };
    let mut p = vec![
        insn(LDB_ABS, 0, 0, 0),
        insn(JSET_K, j(1, acc), 0, 0x01),
        insn(LDH_ABS, 0, 0, 12),
        insn(JEQ_K, j(3, acc), 0, 0x0806),
        insn(JEQ_K, j(4, acc), 0, 0x8100),
        insn(JEQ_K, j(5, acc), 0, 0x88a8),
        insn(JEQ_K, 0, j(6, other), 0x86dd),
        insn(LDB_ABS, 0, 0, 20),
        insn(JEQ_K, j(8, acc), j(8, other), 58),
    ];
    if promisc {
        let own_lo = u32::from_be_bytes([own_mac[2], own_mac[3], own_mac[4], own_mac[5]]);
        let own_hi = u32::from(u16::from_be_bytes([own_mac[0], own_mac[1]]));
        p.push(insn(LDW_ABS, 0, 0, 2));
        p.push(insn(JEQ_K, 0, j(10, acc), own_lo));
        p.push(insn(LDH_ABS, 0, 0, 0));
        p.push(insn(JEQ_K, j(12, drop), j(12, acc), own_hi));
    }
    p.push(insn(RET_K, 0, 0, 0xffff));
    p.push(insn(RET_K, 0, 0, 0));
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny cBPF interpreter (the subset our program uses) so the filter can be
    /// tested against frames without a socket.
    fn run(prog: &[libc::sock_filter], pkt: &[u8]) -> u32 {
        let mut pc = 0usize;
        let mut a: u32 = 0;
        let load = |off: usize, n: usize| -> Option<u32> {
            if off + n > pkt.len() {
                return None;
            }
            let mut v = 0u32;
            for b in &pkt[off..off + n] {
                v = (v << 8) | *b as u32;
            }
            Some(v)
        };
        loop {
            let i = &prog[pc];
            // Out-of-bounds loads make the kernel return 0 (drop); mirror that.
            match i.code {
                LDB_ABS | LDH_ABS | LDW_ABS => {
                    let n = match i.code { LDB_ABS => 1, LDH_ABS => 2, _ => 4 };
                    match load(i.k as usize, n) {
                        Some(v) => a = v,
                        None => return 0,
                    }
                }
                JEQ_K => {
                    pc += if a == i.k { i.jt as usize } else { i.jf as usize };
                }
                JSET_K => {
                    pc += if a & i.k != 0 { i.jt as usize } else { i.jf as usize };
                }
                RET_K => return i.k,
                _ => panic!("unexpected opcode"),
            }
            pc += 1;
            if pc >= prog.len() {
                return 0;
            }
        }
    }
    const OWN: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const OTHER: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

    fn frame(dst: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&dst);
        f.extend_from_slice(&OTHER);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }
    fn ipv6(nh: u8) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, 0, 0, nh, 255];
        p.extend_from_slice(&[0u8; 32]);
        p
    }

    #[test]
    fn accepts_bum_arp_tagged_icmpv6_and_drops_own_unicast_ip() {
        for mode in [RxMode::Unicast, RxMode::AllMulti, RxMode::Promisc] {
            let p = prefilter(mode, OWN);
            assert_eq!(run(&p, &frame([0xff; 6], 0x0800, &[0; 40])), 0xffff, "broadcast");
            assert_eq!(run(&p, &frame([0x01, 0x80, 0xc2, 0, 0, 0], 0x0026, &[0x42; 40])), 0xffff, "multicast");
            assert_eq!(run(&p, &frame(OWN, 0x0806, &[0; 28])), 0xffff, "unicast ARP reply to us");
            assert_eq!(run(&p, &frame(OWN, 0x8100, &[0; 40])), 0xffff, "tagged");
            assert_eq!(run(&p, &frame(OWN, 0x86dd, &ipv6(58))), 0xffff, "unicast ICMPv6 to us");
            assert_eq!(run(&p, &frame(OWN, 0x86dd, &ipv6(6))), 0, "our own TCP/IPv6 (BGP) is dropped");
            assert_eq!(run(&p, &frame(OWN, 0x0800, &[0; 40])), 0, "our own IPv4 is dropped");
        }
    }

    #[test]
    fn promisc_accepts_unknown_unicast_but_not_own() {
        let p = prefilter(RxMode::Promisc, OWN);
        assert_eq!(run(&p, &frame(OTHER, 0x0800, &[0; 40])), 0xffff, "unicast to someone else");
        assert_eq!(run(&p, &frame(OTHER, 0x86dd, &ipv6(6))), 0xffff, "IPv6 TCP to someone else");
        assert_eq!(run(&p, &frame(OWN, 0x0800, &[0; 40])), 0, "still drops our own");
        let p = prefilter(RxMode::AllMulti, OWN);
        assert_eq!(run(&p, &frame(OTHER, 0x0800, &[0; 40])), 0, "non-promisc drops unicast to others");
    }

    #[test]
    fn parses_and_formats_macs() {
        assert_eq!(parse_mac("02:00:00:00:00:01"), Some(OWN));
        assert_eq!(parse_mac("02:00:00:00:00"), None);
        assert_eq!(fmt_mac(&OWN), "02:00:00:00:00:01");
    }
}
