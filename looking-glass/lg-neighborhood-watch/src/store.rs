//! In-memory observation table.
//!
//! Capture threads emit [`Observation`]s onto a channel; a single writer task
//! owns the authoritative map and republishes a lock-free [`Snapshot`] for the
//! HTTP interface. There is no persistence and no time-based decay here — the
//! durable accumulation (and tenant-change eviction) lives in lg-server. If this
//! process restarts it simply re-learns from the fabric.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::mpsc;

/// Maximum distinct MACs retained per IP, bounding per-IP memory against an
/// attacker flooding spoofed MACs on the segment. Keeps the most-recently-heard,
/// evicts the oldest. (lg-server applies the same cap downstream. The sensor's
/// total-IP dimension is bounded by the unit's MemoryMax, not this.)
const MAX_MACS_PER_IP: usize = 100;

/// One frame parsed off the wire: a MAC heard claiming an IP.
#[derive(Debug, Clone)]
pub struct Observation {
    pub ip: String,
    pub family: String,
    pub mac: String,
    pub iface: String,
}

/// One published row: a distinct (ip, mac) pairing with sighting times.
#[derive(Debug, Clone, Serialize)]
pub struct NeighborRow {
    pub ip: String,
    pub family: String,
    pub mac: String,
    /// RFC3339, earliest sighting since this process started.
    pub first_heard: String,
    /// RFC3339, most recent sighting.
    pub last_heard: String,
    pub iface: String,
    pub count: u64,
}

/// Lock-free snapshot served by the HTTP interface.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Snapshot {
    pub rows: Vec<NeighborRow>,
    pub ip_count: usize,
    pub conflict_count: usize,
    pub observation_count: u64,
}

#[derive(Debug, Clone)]
struct Entry {
    first_heard: String,
    last_heard: String,
    iface: String,
    count: u64,
}

/// Drain observations, maintaining the table and republishing on a tick.
pub async fn run_writer(mut rx: mpsc::Receiver<Observation>, table: Arc<ArcSwap<Snapshot>>) {
    // ip -> (family, mac -> Entry)
    let mut map: HashMap<String, (String, HashMap<String, Entry>)> = HashMap::new();
    let mut total: u64 = 0;
    let mut dirty = false;
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));

    loop {
        tokio::select! {
            maybe = rx.recv() => {
                let Some(obs) = maybe else { break };
                let now = Utc::now().to_rfc3339();
                total += 1;
                let (fam, macs) = map
                    .entry(obs.ip)
                    .or_insert_with(|| (obs.family.clone(), HashMap::new()));
                *fam = obs.family;
                macs.entry(obs.mac)
                    .and_modify(|e| {
                        e.last_heard = now.clone();
                        e.iface = obs.iface.clone();
                        e.count += 1;
                    })
                    .or_insert(Entry {
                        first_heard: now.clone(),
                        last_heard: now,
                        iface: obs.iface,
                        count: 1,
                    });
                cap_macs(macs);
                dirty = true;
            }
            _ = tick.tick() => {
                if dirty {
                    table.store(Arc::new(build_snapshot(&map, total)));
                    dirty = false;
                }
            }
        }
    }
}

/// Evict oldest-by-last_heard MACs until the per-IP cap is satisfied.
fn cap_macs(macs: &mut HashMap<String, Entry>) {
    while macs.len() > MAX_MACS_PER_IP {
        let oldest = macs
            .iter()
            .min_by(|a, b| ts_cmp(&a.1.last_heard, &b.1.last_heard))
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => {
                macs.remove(&k);
            }
            None => break,
        }
    }
}

/// Order two RFC3339 timestamps (lexical fallback for unparseable input).
fn ts_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    match (DateTime::parse_from_rfc3339(a), DateTime::parse_from_rfc3339(b)) {
        (Ok(ta), Ok(tb)) => ta.cmp(&tb),
        _ => a.cmp(b),
    }
}

fn build_snapshot(map: &HashMap<String, (String, HashMap<String, Entry>)>, total: u64) -> Snapshot {
    let mut rows = Vec::new();
    let mut conflict_count = 0;
    for (ip, (family, macs)) in map {
        if macs.len() > 1 {
            conflict_count += 1;
        }
        for (mac, e) in macs {
            rows.push(NeighborRow {
                ip: ip.clone(),
                family: family.clone(),
                mac: mac.clone(),
                first_heard: e.first_heard.clone(),
                last_heard: e.last_heard.clone(),
                iface: e.iface.clone(),
                count: e.count,
            });
        }
    }
    rows.sort_by(|a, b| a.ip.cmp(&b.ip).then(a.mac.cmp(&b.mac)));
    Snapshot {
        rows,
        ip_count: map.len(),
        conflict_count,
        observation_count: total,
    }
}
