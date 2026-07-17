//! Rolling on-disk pcap ring buffer of raw ARP/NDP frames.
//!
//! The capture threads tee every ARP/NDP frame here (bytes + capture timestamp).
//! Frames are appended to size/age-rotated classic-pcap chunk files; chunks older
//! than `retain_secs` (by mtime) or beyond a byte cap are pruned. On an anomaly,
//! [`crate::evidence`] scans these chunks for a time window and extracts a small
//! filtered pcap.
//!
//! We write classic libpcap (not pcapng): a 24-byte global header per file then
//! 16-byte record headers, link type `LINKTYPE_ETHERNET`. Readers tolerate a
//! truncated trailing record (the current chunk may be mid-append).

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use tracing::{debug, warn};

/// libpcap classic magic (microsecond, host byte order — we always emit LE).
const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
const LINKTYPE_ETHERNET: u32 = 1;
const SNAPLEN: u32 = 65535;
const GLOBAL_HEADER_LEN: usize = 24;
const RECORD_HEADER_LEN: usize = 16;

/// One captured frame: capture time (split for the pcap record header) + bytes.
pub struct CapturedFrame {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub data: Vec<u8>,
}

/// Tuning for the ring buffer.
#[derive(Clone)]
pub struct RingConfig {
    pub dir: PathBuf,
    pub retain_secs: u64,
    pub max_bytes: u64,
    /// Rotate the current chunk once it reaches this size.
    pub chunk_max_bytes: u64,
}

impl RingConfig {
    pub fn new(dir: PathBuf, retain_secs: u64, max_bytes: u64) -> Self {
        // Keep chunks small enough that pruning is granular, but not so small that
        // we churn files: a quarter of the byte budget, capped at 8 MiB.
        let chunk_max_bytes = (max_bytes / 4).clamp(1 << 20, 8 << 20);
        Self { dir, retain_secs, max_bytes, chunk_max_bytes }
    }
}

/// Write the 24-byte classic-pcap global header.
fn write_global_header(w: &mut impl Write) -> std::io::Result<()> {
    w.write_all(&PCAP_MAGIC.to_le_bytes())?;
    w.write_all(&2u16.to_le_bytes())?; // version major
    w.write_all(&4u16.to_le_bytes())?; // version minor
    w.write_all(&0i32.to_le_bytes())?; // thiszone
    w.write_all(&0u32.to_le_bytes())?; // sigfigs
    w.write_all(&SNAPLEN.to_le_bytes())?;
    w.write_all(&LINKTYPE_ETHERNET.to_le_bytes())?;
    Ok(())
}

/// Append one packet record (16-byte header + bytes).
fn write_record(w: &mut impl Write, ts_sec: u32, ts_usec: u32, data: &[u8]) -> std::io::Result<()> {
    let len = data.len() as u32;
    w.write_all(&ts_sec.to_le_bytes())?;
    w.write_all(&ts_usec.to_le_bytes())?;
    w.write_all(&len.to_le_bytes())?; // incl_len
    w.write_all(&len.to_le_bytes())?; // orig_len
    w.write_all(data)?;
    Ok(())
}

/// A pcap writer for one output file (used by evidence extraction).
pub struct PcapWriter<W: Write> {
    inner: W,
    pub frames: u64,
    pub bytes: u64,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut inner: W) -> std::io::Result<Self> {
        write_global_header(&mut inner)?;
        Ok(Self { inner, frames: 0, bytes: GLOBAL_HEADER_LEN as u64 })
    }

    /// Wrap a writer already positioned at the end of an existing pcap (its
    /// global header is assumed present). Used to append records to an evidence
    /// pcap as an anomaly's sweep grows. `frames`/`bytes` count only what this
    /// appender writes, not what was already in the file.
    pub fn append(inner: W) -> Self {
        Self { inner, frames: 0, bytes: 0 }
    }

    pub fn write_frame(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) -> std::io::Result<()> {
        write_record(&mut self.inner, ts_sec, ts_usec, data)?;
        self.frames += 1;
        self.bytes += (RECORD_HEADER_LEN + data.len()) as u64;
        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Invoke `visit(ts_sec, ts_usec, frame_bytes)` for each record in a chunk file
/// whose record timestamp falls in `[start_sec, end_sec]`. Stops cleanly on a
/// truncated trailing record (a chunk may be mid-append).
fn scan_chunk(
    path: &Path,
    start_sec: u32,
    end_sec: u32,
    visit: &mut impl FnMut(u32, u32, &[u8]),
) -> std::io::Result<()> {
    let mut f = File::open(path)?;
    let mut header = [0u8; GLOBAL_HEADER_LEN];
    if f.read_exact(&mut header).is_err() {
        return Ok(()); // empty/short file
    }
    if u32::from_le_bytes([header[0], header[1], header[2], header[3]]) != PCAP_MAGIC {
        warn!("ring chunk {} has unexpected magic; skipping", path.display());
        return Ok(());
    }
    loop {
        let mut rec = [0u8; RECORD_HEADER_LEN];
        if f.read_exact(&mut rec).is_err() {
            break; // EOF or truncated header
        }
        let ts_sec = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
        let ts_usec = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
        let incl_len = u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]) as usize;
        if incl_len > SNAPLEN as usize {
            warn!("ring chunk {} record len {incl_len} exceeds snaplen; stopping", path.display());
            break;
        }
        let mut buf = vec![0u8; incl_len];
        if f.read_exact(&mut buf).is_err() {
            break; // truncated trailing record
        }
        if ts_sec >= start_sec && ts_sec <= end_sec {
            visit(ts_sec, ts_usec, &buf);
        }
    }
    Ok(())
}

/// Chunk files in the ring directory, sorted oldest-first by (mtime, name).
fn chunk_paths(dir: &Path) -> Vec<PathBuf> {
    let mut chunks: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else { return Vec::new() };
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) == Some("pcap")
            && p.file_name().and_then(|s| s.to_str()).is_some_and(|n| n.starts_with("chunk-"))
        {
            let mtime = e.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
            chunks.push((mtime, p));
        }
    }
    chunks.sort();
    chunks.into_iter().map(|(_, p)| p).collect()
}

/// Scan all ring chunks for frames in `[start_sec, end_sec]`, oldest-first.
pub fn scan_window(
    dir: &Path,
    start_sec: u32,
    end_sec: u32,
    mut visit: impl FnMut(u32, u32, &[u8]),
) {
    for chunk in chunk_paths(dir) {
        if let Err(e) = scan_chunk(&chunk, start_sec, end_sec, &mut visit) {
            warn!("scanning ring chunk {}: {e}", chunk.display());
        }
    }
}

/// The active chunk being appended to.
struct CurrentChunk {
    writer: BufWriter<File>,
    path: PathBuf,
    bytes: u64,
}

/// Drain captured frames onto the rolling ring buffer until the channel closes.
/// Runs on a dedicated OS thread (blocking file I/O).
pub fn run_ring_writer(rx: std::sync::mpsc::Receiver<CapturedFrame>, cfg: RingConfig) {
    if let Err(e) = fs::create_dir_all(&cfg.dir) {
        warn!("cannot create ring buffer dir {}: {e}; evidence capture disabled", cfg.dir.display());
        return;
    }
    let mut seq: u64 = 0;
    let mut current: Option<CurrentChunk> = None;

    for frame in rx {
        // (Re)open a chunk if needed.
        if current.is_none() {
            match open_chunk(&cfg.dir, &mut seq, frame.ts_sec) {
                Ok(c) => current = Some(c),
                Err(e) => {
                    warn!("opening ring chunk: {e}");
                    continue;
                }
            }
        }
        let chunk = current.as_mut().unwrap();
        if write_record(&mut chunk.writer, frame.ts_sec, frame.ts_usec, &frame.data).is_ok() {
            chunk.bytes += (RECORD_HEADER_LEN + frame.data.len()) as u64;
            // Flush so extraction sees frames promptly and reads aren't torn.
            let _ = chunk.writer.flush();
        }
        // Rotate on size, then prune the ring to its limits.
        if chunk.bytes >= cfg.chunk_max_bytes {
            debug!("rotating ring chunk {} ({} bytes)", chunk.path.display(), chunk.bytes);
            current = None;
            prune(&cfg);
        }
    }
}

fn open_chunk(dir: &Path, seq: &mut u64, ts_sec: u32) -> std::io::Result<CurrentChunk> {
    *seq += 1;
    let path = dir.join(format!("chunk-{ts_sec:010}-{seq:06}.pcap"));
    let file = OpenOptions::new().create(true).write(true).truncate(true).open(&path)?;
    let mut writer = BufWriter::new(file);
    write_global_header(&mut writer)?;
    writer.flush()?;
    Ok(CurrentChunk { writer, path, bytes: GLOBAL_HEADER_LEN as u64 })
}

/// Drop chunks older than `retain_secs` (by mtime), then oldest-first until the
/// total is under `max_bytes`.
fn prune(cfg: &RingConfig) {
    let now = std::time::SystemTime::now();
    let chunks = chunk_paths(&cfg.dir);

    // Age-based pruning.
    for chunk in &chunks {
        if let Ok(mtime) = chunk.metadata().and_then(|m| m.modified()) {
            if let Ok(age) = now.duration_since(mtime) {
                if age.as_secs() > cfg.retain_secs {
                    let _ = fs::remove_file(chunk);
                }
            }
        }
    }

    // Byte-cap pruning (oldest-first).
    let mut remaining: Vec<PathBuf> = chunk_paths(&cfg.dir);
    let mut total: u64 = remaining
        .iter()
        .map(|p| fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .sum();
    let mut idx = 0;
    while total > cfg.max_bytes && idx < remaining.len() {
        let size = fs::metadata(&remaining[idx]).map(|m| m.len()).unwrap_or(0);
        if fs::remove_file(&remaining[idx]).is_ok() {
            total = total.saturating_sub(size);
        }
        idx += 1;
    }
    remaining.drain(0..idx);
}
