//! Filtered evidence extraction from the ring buffer.
//!
//! On an anomaly, lg-server POSTs the conflicting MACs + a time window. We scan
//! the ring buffer ([`crate::ringbuf`]) for that window and write a small pcap
//! containing only the relevant frames: anything to/from a conflicting MAC, plus
//! all L2 broadcast (ARP requests) and all IPv6 multicast (NDP) so the "who was
//! asking" context is preserved — and nothing else.
//!
//! Extraction is expensive (scans the whole ring), so it is guarded: idempotent
//! by `event_id`, in-flight de-duplicated, globally concurrency-limited, and
//! deadline-bounded.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::Semaphore;
use tracing::warn;

use crate::ringbuf::{scan_window, PcapWriter};

/// At most this many extractions run at once (disk I/O is the bottleneck).
const MAX_CONCURRENT_EXTRACTIONS: usize = 1;
/// Hard per-extraction deadline; partial output is discarded on timeout.
const EXTRACTION_DEADLINE: Duration = Duration::from_secs(90);

/// Metadata for one saved evidence pcap.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceMeta {
    pub evidence_id: String,
    pub frame_count: u64,
    pub size_bytes: u64,
    /// RFC3339 modified time of the pcap file.
    pub created_at: String,
}

/// Result of a snapshot request, mapped to HTTP status by the handler.
pub enum SnapshotOutcome {
    /// Freshly extracted (200).
    Done(EvidenceMeta),
    /// Already existed; returned without re-extracting (200, idempotent).
    Existing(EvidenceMeta),
    /// An extraction for this event_id is already running (409).
    InProgress,
    /// Concurrency limit reached; retry later (503 + Retry-After).
    Busy,
}

/// Manages the ring buffer's evidence-extraction side: filtered extraction,
/// idempotency, concurrency control, and bounded on-disk storage.
pub struct EvidenceStore {
    dir: PathBuf,
    ring_dir: PathBuf,
    max_bytes: u64,
    sem: Semaphore,
    inflight: Mutex<HashSet<String>>,
}

impl EvidenceStore {
    pub fn new(dir: PathBuf, ring_dir: PathBuf, max_bytes: u64) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            ring_dir,
            max_bytes,
            sem: Semaphore::new(MAX_CONCURRENT_EXTRACTIONS),
            inflight: Mutex::new(HashSet::new()),
        })
    }

    fn pcap_path(&self, evidence_id: &str) -> PathBuf {
        self.dir.join(format!("{evidence_id}.pcap"))
    }

    /// Extract a filtered pcap for `event_id` over `[start_sec, end_sec]`,
    /// keeping only frames touching `macs` plus broadcast/IPv6-multicast.
    pub async fn snapshot(
        &self,
        event_id: &str,
        macs: &[String],
        start_sec: u32,
        end_sec: u32,
    ) -> SnapshotOutcome {
        let path = self.pcap_path(event_id);

        // Idempotency + in-flight de-dup under one lock, so concurrent requests
        // for the same event_id resolve deterministically.
        {
            let mut inflight = self.inflight.lock().unwrap();
            if let Some(meta) = meta_for(&path) {
                return SnapshotOutcome::Existing(meta);
            }
            if inflight.contains(event_id) {
                return SnapshotOutcome::InProgress;
            }
            inflight.insert(event_id.to_string());
        }

        // From here, ensure we always clear the in-flight marker.
        let outcome = self.run_extraction(event_id, macs, start_sec, end_sec, &path).await;
        self.inflight.lock().unwrap().remove(event_id);
        outcome
    }

    async fn run_extraction(
        &self,
        event_id: &str,
        macs: &[String],
        start_sec: u32,
        end_sec: u32,
        path: &std::path::Path,
    ) -> SnapshotOutcome {
        let Ok(_permit) = self.sem.try_acquire() else {
            return SnapshotOutcome::Busy;
        };

        let mac_set: HashSet<[u8; 6]> = macs.iter().filter_map(|m| parse_mac(m)).collect();
        let ring_dir = self.ring_dir.clone();
        let tmp = path.with_extension("pcap.tmp");
        let out = path.to_path_buf();
        let tmp_for_task = tmp.clone();

        let job = tokio::task::spawn_blocking(move || {
            extract(&ring_dir, &mac_set, start_sec, end_sec, &tmp_for_task)
        });

        match tokio::time::timeout(EXTRACTION_DEADLINE, job).await {
            Ok(Ok(Ok((frames, bytes)))) => {
                if let Err(e) = std::fs::rename(&tmp, &out) {
                    warn!("finalizing evidence {event_id}: {e}");
                    let _ = std::fs::remove_file(&tmp);
                    return SnapshotOutcome::Busy; // transient; caller may retry
                }
                self.prune();
                SnapshotOutcome::Done(EvidenceMeta {
                    evidence_id: event_id.to_string(),
                    frame_count: frames,
                    size_bytes: bytes,
                    created_at: Utc::now().to_rfc3339(),
                })
            }
            Ok(Ok(Err(e))) => {
                warn!("extracting evidence {event_id}: {e}");
                let _ = std::fs::remove_file(&tmp);
                SnapshotOutcome::Busy
            }
            Ok(Err(e)) => {
                warn!("evidence extraction task for {event_id} panicked: {e}");
                let _ = std::fs::remove_file(&tmp);
                SnapshotOutcome::Busy
            }
            Err(_) => {
                warn!("evidence extraction for {event_id} exceeded deadline; abandoning");
                let _ = std::fs::remove_file(&tmp);
                SnapshotOutcome::Busy
            }
        }
    }

    /// Path to a saved evidence pcap, if it exists (for streaming download).
    pub fn evidence_path(&self, evidence_id: &str) -> Option<PathBuf> {
        // Guard against path traversal: evidence_id must be a bare token.
        if !is_safe_id(evidence_id) {
            return None;
        }
        let p = self.pcap_path(evidence_id);
        p.is_file().then_some(p)
    }

    /// List saved evidence with metadata, newest-first.
    pub fn list(&self) -> Vec<EvidenceMeta> {
        let mut metas: Vec<EvidenceMeta> = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return metas };
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("pcap") {
                if let Some(m) = meta_for(&p) {
                    metas.push(m);
                }
            }
        }
        metas.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        metas
    }

    /// Prune oldest evidence pcaps until under the byte cap.
    fn prune(&self) {
        let mut files: Vec<(std::time::SystemTime, u64, PathBuf)> = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("pcap") {
                if let Ok(meta) = e.metadata() {
                    let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
                    files.push((mtime, meta.len(), p));
                }
            }
        }
        files.sort(); // oldest-first
        let mut total: u64 = files.iter().map(|(_, len, _)| len).sum();
        for (_, len, p) in &files {
            if total <= self.max_bytes {
                break;
            }
            if std::fs::remove_file(p).is_ok() {
                total = total.saturating_sub(*len);
            }
        }
    }
}

/// Build metadata for a saved pcap by reading its size + counting records.
fn meta_for(path: &std::path::Path) -> Option<EvidenceMeta> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let evidence_id = path.file_stem()?.to_str()?.to_string();
    let created_at: DateTime<Utc> = meta.modified().ok()?.into();
    Some(EvidenceMeta {
        evidence_id,
        frame_count: count_frames(path),
        size_bytes: meta.len(),
        created_at: created_at.to_rfc3339(),
    })
}

/// Count records in a pcap (over the whole file).
fn count_frames(path: &std::path::Path) -> u64 {
    let mut n = 0u64;
    if let Ok(bytes) = std::fs::read(path) {
        // global header 24, then 16-byte record headers; walk incl_len.
        let mut i = 24usize;
        while i + 16 <= bytes.len() {
            let incl = u32::from_le_bytes([bytes[i + 8], bytes[i + 9], bytes[i + 10], bytes[i + 11]]) as usize;
            let next = i + 16 + incl;
            if next > bytes.len() {
                break;
            }
            n += 1;
            i = next;
        }
    }
    n
}

/// Run the filtered extraction synchronously; returns (frame_count, byte_count).
fn extract(
    ring_dir: &std::path::Path,
    macs: &HashSet<[u8; 6]>,
    start_sec: u32,
    end_sec: u32,
    out_tmp: &std::path::Path,
) -> std::io::Result<(u64, u64)> {
    let file = std::fs::File::create(out_tmp)?;
    let mut writer = PcapWriter::new(std::io::BufWriter::new(file))?;
    scan_window(ring_dir, start_sec, end_sec, |ts_sec, ts_usec, frame| {
        if keep_frame(frame, macs) {
            let _ = writer.write_frame(ts_sec, ts_usec, frame);
        }
    });
    writer.flush()?;
    Ok((writer.frames, writer.bytes))
}

/// Keep a frame if it touches a conflicting MAC, is L2 broadcast, or is IPv6
/// multicast (33:33:*). Frames shorter than an Ethernet header are dropped.
fn keep_frame(frame: &[u8], macs: &HashSet<[u8; 6]>) -> bool {
    if frame.len() < 14 {
        return false;
    }
    let dst: [u8; 6] = frame[0..6].try_into().unwrap();
    let src: [u8; 6] = frame[6..12].try_into().unwrap();
    if dst == [0xff; 6] {
        return true; // L2 broadcast (ARP requests)
    }
    if dst[0] == 0x33 && dst[1] == 0x33 {
        return true; // IPv6 multicast (NDP)
    }
    macs.contains(&src) || macs.contains(&dst)
}

/// Parse "aa:bb:cc:dd:ee:ff" into raw bytes.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for b in out.iter_mut() {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None; // too many octets
    }
    Some(out)
}

/// Evidence ids are UUIDs from lg-server; allow only token chars to block path
/// traversal in the download handler.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macs() {
        assert_eq!(parse_mac("0a:00:05:18:9d:49"), Some([0x0a, 0x00, 0x05, 0x18, 0x9d, 0x49]));
        assert_eq!(parse_mac("ff:ff:ff:ff:ff:ff"), Some([0xff; 6]));
        assert_eq!(parse_mac("nope"), None);
        assert_eq!(parse_mac("00:11:22:33:44:55:66"), None);
    }

    #[test]
    fn keeps_broadcast_multicast_and_matching_macs() {
        let mac = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01];
        let macs: HashSet<[u8; 6]> = [mac].into_iter().collect();
        let mut bcast = vec![0xff; 6];
        bcast.extend_from_slice(&[0x0a, 0, 0, 0, 0, 0x02]);
        bcast.extend_from_slice(&[0x08, 0x06]); // ARP ethertype
        assert!(keep_frame(&bcast, &macs));

        let mut mcast = vec![0x33, 0x33, 0, 0, 0, 0x01];
        mcast.extend_from_slice(&[0x0a, 0, 0, 0, 0, 0x03]);
        mcast.extend_from_slice(&[0x86, 0xdd]);
        assert!(keep_frame(&mcast, &macs));

        // Unicast to/from our MAC.
        let mut hit = vec![0x0a, 0, 0, 0, 0, 0x04];
        hit.extend_from_slice(&mac); // src = conflicting MAC
        hit.extend_from_slice(&[0x08, 0x06]);
        assert!(keep_frame(&hit, &macs));

        // Unrelated unicast between two other hosts → dropped.
        let mut miss = vec![0x0a, 0, 0, 0, 0, 0x05];
        miss.extend_from_slice(&[0x0a, 0, 0, 0, 0, 0x06]);
        miss.extend_from_slice(&[0x08, 0x06]);
        assert!(!keep_frame(&miss, &macs));
    }

    #[test]
    fn rejects_unsafe_ids() {
        assert!(is_safe_id("3b9b0e2e-1c2d-4f5a-9e6b-7a8c9d0e1f23"));
        assert!(!is_safe_id("../etc/passwd"));
        assert!(!is_safe_id("a/b"));
        assert!(!is_safe_id(""));
    }

    // Build a minimal Ethernet frame: dst(6) + src(6) + ethertype(2) + 2 pad.
    fn frame(dst: [u8; 6], src: [u8; 6], ethertype: [u8; 2]) -> Vec<u8> {
        let mut f = Vec::with_capacity(16);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&ethertype);
        f.extend_from_slice(&[0xde, 0xad]);
        f
    }

    #[tokio::test]
    async fn ring_to_filtered_extraction_round_trip() {
        use crate::ringbuf::{run_ring_writer, CapturedFrame, RingConfig};

        let tmp = tempfile::tempdir().unwrap();
        let ring_dir = tmp.path().join("ring");
        let snap_dir = tmp.path().join("snap");

        let rogue = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01];
        let other_a = [0x0a, 0, 0, 0, 0, 0x10];
        let other_b = [0x0a, 0, 0, 0, 0, 0x11];
        let arp = [0x08, 0x06];
        let v6 = [0x86, 0xdd];

        // Feed frames through the ring writer, then close the channel so it drains.
        let (tx, rx) = std::sync::mpsc::sync_channel::<CapturedFrame>(64);
        // In window (ts 1000), kept: rogue unicast, broadcast, IPv6 multicast.
        tx.send(CapturedFrame { ts_sec: 1000, ts_usec: 0, data: frame(other_a, rogue, arp) }).unwrap();
        tx.send(CapturedFrame { ts_sec: 1000, ts_usec: 1, data: frame([0xff; 6], other_a, arp) }).unwrap();
        tx.send(CapturedFrame { ts_sec: 1000, ts_usec: 2, data: frame([0x33, 0x33, 0, 0, 0, 1], other_a, v6) }).unwrap();
        // In window but unrelated unicast → dropped by filter.
        tx.send(CapturedFrame { ts_sec: 1000, ts_usec: 3, data: frame(other_a, other_b, arp) }).unwrap();
        // Matches the MAC but OUTSIDE the window → dropped by time.
        tx.send(CapturedFrame { ts_sec: 5000, ts_usec: 0, data: frame(other_a, rogue, arp) }).unwrap();
        drop(tx);
        run_ring_writer(rx, RingConfig::new(ring_dir.clone(), 3600, 100 << 20));

        let store = EvidenceStore::new(snap_dir, ring_dir, 500 << 20).unwrap();
        let macs = vec!["aa:bb:cc:00:00:01".to_string()];
        match store.snapshot("evt-1", &macs, 900, 1100).await {
            SnapshotOutcome::Done(meta) => {
                assert_eq!(meta.frame_count, 3, "rogue-unicast + broadcast + multicast kept; rest filtered");
                assert_eq!(meta.evidence_id, "evt-1");
            }
            _ => panic!("expected a fresh extraction"),
        }

        // Idempotent: a second request returns the existing snapshot, no re-extract.
        match store.snapshot("evt-1", &macs, 900, 1100).await {
            SnapshotOutcome::Existing(meta) => assert_eq!(meta.frame_count, 3),
            _ => panic!("expected the existing snapshot"),
        }

        // The pcap is retrievable and listed.
        assert!(store.evidence_path("evt-1").is_some());
        assert_eq!(store.list().len(), 1);
        assert!(store.evidence_path("../escape").is_none(), "path traversal blocked");
    }
}
