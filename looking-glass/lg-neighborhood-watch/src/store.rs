//! In-memory observation table.
//!
//! Capture threads emit [`Observation`]s onto a channel; a single writer task
//! owns the authoritative map and republishes a lock-free [`Snapshot`] for the
//! HTTP interface. There is no persistence here — the durable accumulation (and
//! tenant-change eviction) lives in lg-server. If this process restarts it
//! simply re-learns from the fabric.
//!
//! Time-based decay is optional (`sensor_ttl_secs`): when enabled, a (ip, mac)
//! entry not re-heard within the TTL is dropped, so `/neighbors` reflects only
//! *currently-live* MACs. This keeps the sensor from feeding stale MACs (e.g. a
//! migrated-away router's old address) to lg-server forever, and bounds memory.
//! The TTL must be set well above lg-server's poll interval so a real conflict
//! is seen in many polls before it ages out — it governs liveness, not detection.

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
    /// Set when this frame's two MAC assertions disagreed — the NDP source/target
    /// link-layer-address option (or, for ARP, the sender-hardware-address) named
    /// a different MAC than the outer Ethernet source. `mac` is always the outer
    /// Ethernet source (the transmitter); this is the *other* MAC (the original
    /// owner whose frame was re-flooded). The fingerprint of verbatim reflection.
    pub mismatched_mac: Option<String>,
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
    /// Times this (ip, mac) was seen sourced by a frame whose link-layer option
    /// (NDP) or sender-hardware-address (ARP) named a different MAC than the outer
    /// Ethernet source — the reflection fingerprint. Zero for normal traffic.
    #[serde(default)]
    pub mismatch_count: u64,
    /// The most recent counterpart MAC from those mismatching frames (the original
    /// owner whose frame this MAC re-flooded). `None` when never mismatched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mismatched_mac: Option<String>,
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
    mismatch_count: u64,
    last_mismatched_mac: Option<String>,
}

/// Drain observations, maintaining the table and republishing on a tick.
/// When `ttl_secs` is set, entries not re-heard within the TTL are decayed.
pub async fn run_writer(
    mut rx: mpsc::Receiver<Observation>,
    table: Arc<ArcSwap<Snapshot>>,
    ttl_secs: Option<u64>,
) {
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
                let mismatched = obs.mismatched_mac;
                macs.entry(obs.mac)
                    .and_modify(|e| {
                        e.last_heard = now.clone();
                        e.iface = obs.iface.clone();
                        e.count += 1;
                        if let Some(m) = &mismatched {
                            e.mismatch_count += 1;
                            e.last_mismatched_mac = Some(m.clone());
                        }
                    })
                    .or_insert(Entry {
                        first_heard: now.clone(),
                        last_heard: now,
                        iface: obs.iface,
                        count: 1,
                        mismatch_count: if mismatched.is_some() { 1 } else { 0 },
                        last_mismatched_mac: mismatched,
                    });
                cap_macs(macs);
                dirty = true;
            }
            _ = tick.tick() => {
                // Decay stale entries even when no new observations arrive, so a
                // gone-quiet conflict drops out of `/neighbors` on time.
                if let Some(ttl) = ttl_secs {
                    if prune_stale(&mut map, ttl, Utc::now()) {
                        dirty = true;
                    }
                }
                if dirty {
                    table.store(Arc::new(build_snapshot(&map, total)));
                    dirty = false;
                }
            }
        }
    }
}

/// Drop (ip, mac) entries whose `last_heard` is older than `ttl_secs`, then any
/// IP left with no MACs. Returns true if anything was removed.
fn prune_stale(
    map: &mut HashMap<String, (String, HashMap<String, Entry>)>,
    ttl_secs: u64,
    now: DateTime<Utc>,
) -> bool {
    let cutoff = now - chrono::Duration::seconds(ttl_secs as i64);
    let mut removed = false;
    map.retain(|_ip, (_fam, macs)| {
        macs.retain(|_mac, e| {
            let fresh = DateTime::parse_from_rfc3339(&e.last_heard)
                .map(|t| t.with_timezone(&Utc) >= cutoff)
                .unwrap_or(true); // keep unparseable rather than silently drop
            if !fresh {
                removed = true;
            }
            fresh
        });
        !macs.is_empty()
    });
    removed
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
                mismatch_count: e.mismatch_count,
                mismatched_mac: e.last_mismatched_mac.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(last_heard: &str) -> Entry {
        Entry {
            first_heard: last_heard.to_string(),
            last_heard: last_heard.to_string(),
            iface: "vlan998".into(),
            count: 1,
            mismatch_count: 0,
            last_mismatched_mac: None,
        }
    }

    #[test]
    fn mismatch_counters_fold_and_carry_to_the_row() {
        let obs = |mac: &str, mismatched: Option<&str>| Observation {
            ip: "2001:db8::1".into(),
            family: "IPv6".into(),
            mac: mac.into(),
            iface: "vlan998".into(),
            mismatched_mac: mismatched.map(str::to_string),
        };
        // Two mismatching sightings of the reflector and one clean sighting of the
        // real owner fold into one map; the reflector row carries mismatch_count=2.
        let mut map: HashMap<String, (String, HashMap<String, Entry>)> = HashMap::new();
        for o in [
            obs("0a:00:05:18:9d:49", Some("aa:bb:cc:00:00:01")),
            obs("0a:00:05:18:9d:49", Some("aa:bb:cc:00:00:01")),
            obs("aa:bb:cc:00:00:01", None),
        ] {
            let now = "2026-06-19T00:00:00Z".to_string();
            let (_fam, macs) = map.entry(o.ip).or_insert_with(|| (o.family.clone(), HashMap::new()));
            let mismatched = o.mismatched_mac;
            macs.entry(o.mac)
                .and_modify(|e| {
                    e.count += 1;
                    if let Some(m) = &mismatched {
                        e.mismatch_count += 1;
                        e.last_mismatched_mac = Some(m.clone());
                    }
                })
                .or_insert(Entry {
                    first_heard: now.clone(),
                    last_heard: now,
                    iface: o.iface,
                    count: 1,
                    mismatch_count: if mismatched.is_some() { 1 } else { 0 },
                    last_mismatched_mac: mismatched,
                });
        }
        let snap = build_snapshot(&map, 3);
        let reflector = snap.rows.iter().find(|r| r.mac == "0a:00:05:18:9d:49").unwrap();
        assert_eq!(reflector.mismatch_count, 2);
        assert_eq!(reflector.mismatched_mac.as_deref(), Some("aa:bb:cc:00:00:01"));
        let owner = snap.rows.iter().find(|r| r.mac == "aa:bb:cc:00:00:01").unwrap();
        assert_eq!(owner.mismatch_count, 0, "the clean owner row carries no mismatch");
        assert_eq!(owner.mismatched_mac, None);
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn prune_drops_only_stale_macs_and_empty_ips() {
        let mut map: HashMap<String, (String, HashMap<String, Entry>)> = HashMap::new();
        // IP with one fresh + one stale MAC (a migration in progress).
        let mut macs = HashMap::new();
        macs.insert("aa:aa".to_string(), entry("2026-06-18T23:50:00Z")); // stale (40m old)
        macs.insert("bb:bb".to_string(), entry("2026-06-19T00:25:00Z")); // fresh (5m old)
        map.insert("10.0.0.1".to_string(), ("IPv4".to_string(), macs));
        // IP whose only MAC is stale -> the whole IP should drop.
        let mut macs2 = HashMap::new();
        macs2.insert("cc:cc".to_string(), entry("2026-06-18T23:50:00Z"));
        map.insert("10.0.0.2".to_string(), ("IPv4".to_string(), macs2));

        // TTL 1800s (30m); now is 30m past the stale entries, 5m past the fresh one.
        let removed = prune_stale(&mut map, 1800, at("2026-06-19T00:30:00Z"));
        assert!(removed);
        // 10.0.0.1 keeps only the fresh MAC.
        let (_f, macs) = &map["10.0.0.1"];
        assert_eq!(macs.len(), 1);
        assert!(macs.contains_key("bb:bb"));
        // 10.0.0.2 is gone entirely.
        assert!(!map.contains_key("10.0.0.2"));
    }

    #[test]
    fn prune_is_a_noop_when_all_fresh() {
        let mut map: HashMap<String, (String, HashMap<String, Entry>)> = HashMap::new();
        let mut macs = HashMap::new();
        macs.insert("aa:aa".to_string(), entry("2026-06-19T00:29:30Z"));
        map.insert("10.0.0.1".to_string(), ("IPv4".to_string(), macs));
        assert!(!prune_stale(&mut map, 1800, at("2026-06-19T00:30:00Z")));
        assert_eq!(map["10.0.0.1"].1.len(), 1);
    }
}
