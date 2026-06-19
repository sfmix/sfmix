//! Durable discovered-neighbor store.
//!
//! `lg-neighborhood-watch` (a thin sensor on the route server) passively hears
//! ARP/NDP on the IX fabric and reports the MACs it currently knows for each IP.
//! That sensor is stateless; *this* store is the source of truth: it folds each
//! poll in, preserving `first_seen`/`last_seen` per (ip, mac), and persists across
//! restarts so history survives even when the sensor is restarted.
//!
//! Unlike the MAC-table store ([`crate::mac_table`]) it does not age entries out
//! by time. The eviction trigger is a **tenant change**: when an IP is reassigned
//! to a different participant, its observed-MAC history is cleared and starts
//! fresh, because it is effectively a new IP. IPs no longer assigned at all are
//! dropped.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::structured::{DiscoveredMac, DiscoveredNeighbor};

/// Maximum distinct MACs retained per IP. A legitimate IP has one (a real
/// conflict a handful); this is generous headroom for flapping/history while
/// still bounding memory and response size against an attacker flooding spoofed
/// MACs for an assigned IP. The conflict flag still fires (it only needs >1), so
/// the spoofing signal is preserved; we keep the most-recently-heard and evict
/// the oldest. Assigned IPs are bounded by the assignment set (~214 * this);
/// the unassigned bucket is bounded by [`MAX_UNASSIGNED_IPS`] (also * this).
const MAX_MACS_PER_IP: usize = 100;

/// Maximum number of *unassigned* IPs retained. Unlike assigned IPs (bounded by
/// NetBox), an unassigned IP is anything a host claims via ARP/NDP, so a
/// misbehaving/spoofing host could otherwise grow this set without limit. We keep
/// the most-recently-heard and evict the oldest by `last_seen`.
const MAX_UNASSIGNED_IPS: usize = 256;

/// How long an unassigned IP record is kept after it was last heard. Assigned
/// IPs never age out (tenant change is their only eviction); unassigned ones are
/// transient mis-configurations, so they expire once the host stops claiming the
/// address.
const UNASSIGNED_TTL_SECS: i64 = 24 * 60 * 60;

/// One row as reported by the sensor's `GET /neighbors`.
#[derive(Debug, Clone, Deserialize)]
pub struct SensorObservation {
    pub ip: String,
    #[serde(default)]
    pub family: String,
    pub mac: String,
    /// RFC3339; the sensor's earliest sighting in its (volatile) memory.
    #[serde(default)]
    pub first_heard: String,
    /// RFC3339; the sensor's most recent sighting.
    #[serde(default)]
    pub last_heard: String,
}

/// An IP→tenant assignment, as resolved from the NetBox participant cache.
#[derive(Debug, Clone)]
pub struct Assignment {
    pub ip: String,
    pub family: String,
    pub asn: Option<u32>,
    pub tenant: Option<String>,
}

/// Published, lock-free-readable view served over RPC/REST.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveredCache {
    pub neighbors: Vec<DiscoveredNeighbor>,
    /// RFC3339 of the last successful sensor poll.
    pub fetched_at: Option<String>,
    /// Last sensor-fetch error, if the most recent poll failed.
    pub last_error: Option<String>,
}

impl DiscoveredCache {
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Times a given MAC has been heard claiming an IP (RFC3339 strings).
#[derive(Debug, Clone)]
struct MacTimes {
    first_seen: String,
    last_seen: String,
}

/// Everything known about one IP: its current tenant and the MACs heard for it.
#[derive(Debug, Clone)]
struct IpRecord {
    family: String,
    asn: Option<u32>,
    tenant: Option<String>,
    macs: HashMap<String, MacTimes>,
}

/// In-memory store, owned by the poll loop (no shared locking).
pub struct DiscoveredNeighborStore {
    path: Option<PathBuf>,
    /// ip → record
    records: HashMap<String, IpRecord>,
    fetched_at: Option<String>,
    last_error: Option<String>,
}

impl DiscoveredNeighborStore {
    /// Load from disk. Returns an empty store if the path is unset, the file is
    /// missing, or it fails to parse (warn-and-continue).
    pub fn load(path: Option<PathBuf>) -> Self {
        let mut store = Self { path, records: HashMap::new(), fetched_at: None, last_error: None };
        let Some(path) = store.path.clone() else { return store };
        match std::fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<DiscoveredCache>(&contents) {
                Ok(cache) => {
                    for n in cache.neighbors {
                        let macs = n
                            .macs
                            .into_iter()
                            .map(|m| (m.mac, MacTimes { first_seen: m.first_seen, last_seen: m.last_seen }))
                            .collect();
                        store.records.insert(
                            n.ip,
                            IpRecord { family: n.family, asn: n.asn, tenant: n.tenant, macs },
                        );
                    }
                    store.fetched_at = cache.fetched_at;
                    info!(
                        "Loaded discovered-neighbor store from {} ({} IPs)",
                        path.display(),
                        store.records.len()
                    );
                }
                Err(e) => warn!("Failed to parse discovered-neighbor store {}: {e}", path.display()),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!("No discovered-neighbor store at {}, starting fresh", path.display());
            }
            Err(e) => warn!("Failed to read discovered-neighbor store {}: {e}", path.display()),
        }
        store
    }

    /// Fold a fresh sensor poll into the store against the current assignments.
    pub fn update(&mut self, sensor: &[SensorObservation], assignments: &[Assignment]) {
        self.update_at(sensor, assignments, Utc::now());
    }

    /// Testable core of [`update`] with an injected clock.
    fn update_at(&mut self, sensor: &[SensorObservation], assignments: &[Assignment], now: DateTime<Utc>) {
        let now_str = now.to_rfc3339();

        // Index assignments by IP and reconcile tenant changes / removals first.
        let mut assigned: HashMap<&str, &Assignment> = HashMap::new();
        for a in assignments {
            assigned.insert(a.ip.as_str(), a);
        }

        // Keep assigned IPs and any unassigned records (asn == None). An IP that
        // was assigned but has left the assignment set is dropped here (dealloc /
        // tenant-change wipe); if it is still being heard it re-enters below as a
        // fresh unassigned record.
        self.records
            .retain(|ip, rec| assigned.contains_key(ip.as_str()) || rec.asn.is_none());

        // Apply tenant changes (clear history) and refresh tenant/family metadata.
        for (ip, a) in &assigned {
            match self.records.get_mut(*ip) {
                Some(rec) => {
                    if rec.asn != a.asn || rec.tenant != a.tenant {
                        // Reassigned: treat as a brand-new IP.
                        rec.macs.clear();
                        rec.asn = a.asn;
                        rec.tenant = a.tenant.clone();
                    }
                    rec.family = a.family.clone();
                }
                None => {
                    self.records.insert(
                        (*ip).to_string(),
                        IpRecord {
                            family: a.family.clone(),
                            asn: a.asn,
                            tenant: a.tenant.clone(),
                            macs: HashMap::new(),
                        },
                    );
                }
            }
        }

        // Fold in observations, preserving the earliest first_seen and advancing
        // last_seen. Assigned IPs already have a record; an IP not in the
        // assignment set is recorded as unassigned (asn/tenant None) so a host
        // mis-bound to an invalid/disallowed address is surfaced rather than
        // silently dropped.
        for obs in sensor {
            let rec = self.records.entry(obs.ip.clone()).or_insert_with(|| IpRecord {
                family: obs.family.clone(),
                asn: None,
                tenant: None,
                macs: HashMap::new(),
            });
            let first = if obs.first_heard.is_empty() { now_str.clone() } else { obs.first_heard.clone() };
            let last = if obs.last_heard.is_empty() { now_str.clone() } else { obs.last_heard.clone() };
            rec.macs
                .entry(obs.mac.clone())
                .and_modify(|t| {
                    t.first_seen = min_ts(&t.first_seen, &first);
                    t.last_seen = max_ts(&t.last_seen, &last);
                })
                .or_insert(MacTimes { first_seen: first, last_seen: last });
            cap_macs(&mut rec.macs);
        }

        // Bound the unassigned bucket: expire stale records, then cap the count.
        self.prune_unassigned(now);

        self.fetched_at = Some(now_str);
        self.last_error = None;
    }

    /// Age out unassigned records last heard more than [`UNASSIGNED_TTL_SECS`]
    /// ago, then evict the oldest-by-`last_seen` until at most
    /// [`MAX_UNASSIGNED_IPS`] remain. Assigned records (asn present) are never
    /// touched here.
    fn prune_unassigned(&mut self, now: DateTime<Utc>) {
        let cutoff = now - chrono::Duration::seconds(UNASSIGNED_TTL_SECS);
        self.records.retain(|_, rec| {
            if rec.asn.is_some() {
                return true;
            }
            // Newest MAC sighting on this IP; keep while still within the TTL.
            rec.macs
                .values()
                .filter_map(|t| DateTime::parse_from_rfc3339(&t.last_seen).ok())
                .map(|t| t.with_timezone(&Utc))
                .max()
                .is_some_and(|last| last >= cutoff)
        });

        let unassigned = self.records.values().filter(|r| r.asn.is_none()).count();
        if unassigned <= MAX_UNASSIGNED_IPS {
            return;
        }
        // Sort unassigned IPs by most-recent sighting and drop the oldest excess.
        let mut by_recency: Vec<(String, String)> = self
            .records
            .iter()
            .filter(|(_, r)| r.asn.is_none())
            .map(|(ip, r)| {
                let newest = r.macs.values().map(|t| t.last_seen.clone()).max().unwrap_or_default();
                (ip.clone(), newest)
            })
            .collect();
        by_recency.sort_by(|a, b| ts_cmp(&a.1, &b.1));
        let drop_n = unassigned - MAX_UNASSIGNED_IPS;
        for (ip, _) in by_recency.into_iter().take(drop_n) {
            self.records.remove(&ip);
        }
        warn!(
            "Unassigned discovered-neighbor bucket exceeded {MAX_UNASSIGNED_IPS}; evicted {drop_n} oldest IP(s)"
        );
    }

    /// Record a failed sensor poll without disturbing the retained data.
    pub fn set_error(&mut self, err: impl Into<String>) {
        self.last_error = Some(err.into());
    }

    /// Build the published, sorted view (with conflict flags) for the ArcSwap.
    pub fn snapshot(&self) -> DiscoveredCache {
        let mut neighbors: Vec<DiscoveredNeighbor> = self
            .records
            .iter()
            .map(|(ip, rec)| {
                let mut macs: Vec<DiscoveredMac> = rec
                    .macs
                    .iter()
                    .map(|(mac, t)| DiscoveredMac {
                        mac: mac.clone(),
                        first_seen: t.first_seen.clone(),
                        last_seen: t.last_seen.clone(),
                    })
                    .collect();
                macs.sort_by(|a, b| a.mac.cmp(&b.mac));
                DiscoveredNeighbor {
                    ip: ip.clone(),
                    family: rec.family.clone(),
                    asn: rec.asn,
                    tenant: rec.tenant.clone(),
                    conflict: macs.len() > 1,
                    // asn is None exactly for IPs not in the NetBox assignment set.
                    assigned: rec.asn.is_some(),
                    macs,
                }
            })
            .collect();
        neighbors.sort_by(|a, b| a.ip.cmp(&b.ip));
        DiscoveredCache {
            neighbors,
            fetched_at: self.fetched_at.clone(),
            last_error: self.last_error.clone(),
        }
    }

    /// Persist the snapshot to disk (atomic write via temp file + rename). No-op
    /// when no path is configured.
    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating discovered-neighbor store directory {}", parent.display()))?;
        }
        let tmp = path.with_extension("tmp");
        let json = serde_json::to_string_pretty(&self.snapshot())
            .context("serializing discovered-neighbor store")?;
        std::fs::write(&tmp, &json)
            .with_context(|| format!("writing temp store file {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
        Ok(())
    }
}

/// Spawn the background poll loop: fetch the sensor, reconcile against current
/// IX IP assignments, publish into `lg.discovered`, and persist. Used by both the
/// `lg-server` binary and the root binary (call from each `main`).
pub fn spawn_poll_loop(
    lg: std::sync::Arc<crate::service::LookingGlass>,
    cfg: &crate::config::DiscoveredNeighborsConfig,
) {
    if cfg.poll_interval_secs == 0 {
        return;
    }
    let mut store = DiscoveredNeighborStore::load(cfg.state_file.clone().map(PathBuf::from));
    // Publish whatever survived the last restart right away.
    lg.discovered.store(std::sync::Arc::new(store.snapshot()));

    let sensor_url = cfg.sensor_url.clone();
    let interval_secs = cfg.poll_interval_secs;
    info!(
        "Discovered-neighbor poll enabled (sensor: {sensor_url}, interval: {interval_secs}s)"
    );
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        loop {
            tick.tick().await;
            let assignments = assignments_from_participants(&lg.netbox_participants.load());
            if assignments.is_empty() {
                // Cold start (NetBox not loaded yet) or NetBox unavailable. Skipping
                // avoids wiping retained history against an empty assignment set.
                tracing::debug!("discovered-neighbor poll skipped: no IX IP assignments yet");
                continue;
            }
            match fetch_sensor(&sensor_url).await {
                Ok(obs) => {
                    store.update(&obs, &assignments);
                    tracing::debug!("discovered-neighbor poll: {} observations", obs.len());
                }
                Err(e) => {
                    tracing::warn!("discovered-neighbor sensor poll failed: {e}");
                    store.set_error(e.to_string());
                }
            }
            lg.discovered.store(std::sync::Arc::new(store.snapshot()));
            if let Err(e) = store.save() {
                tracing::warn!("Failed to save discovered-neighbor store: {e}");
            }
        }
    });
}

/// Flatten the NetBox participant cache into IP→tenant assignments.
pub fn assignments_from_participants(
    participants: &[crate::netbox::NetboxParticipant],
) -> Vec<Assignment> {
    participants
        .iter()
        .flat_map(|p| {
            p.ip_addresses.iter().map(move |ip| Assignment {
                ip: ip.address.clone(),
                family: ip.family.clone(),
                asn: Some(p.asn),
                tenant: Some(p.name.clone()),
            })
        })
        .collect()
}

/// Fetch current observations from the sensor's `GET /neighbors`.
pub async fn fetch_sensor(base_url: &str) -> Result<Vec<SensorObservation>> {
    let url = format!("{}/neighbors", base_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("building HTTP client")?;
    let resp = client.get(&url).send().await.with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("sensor returned {} for {url}", resp.status());
    }
    let observations: Vec<SensorObservation> = resp.json().await.context("decoding sensor response")?;
    Ok(observations)
}

/// Evict oldest-by-last_seen MACs until the per-IP cap is satisfied.
fn cap_macs(macs: &mut HashMap<String, MacTimes>) {
    while macs.len() > MAX_MACS_PER_IP {
        let oldest = macs
            .iter()
            .min_by(|a, b| ts_cmp(&a.1.last_seen, &b.1.last_seen))
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

/// Compare two RFC3339 timestamps, returning the earlier (string preserved).
fn min_ts(a: &str, b: &str) -> String {
    match (DateTime::parse_from_rfc3339(a), DateTime::parse_from_rfc3339(b)) {
        (Ok(ta), Ok(tb)) => if ta <= tb { a.to_string() } else { b.to_string() },
        // Prefer a parseable value; otherwise keep the existing one.
        (Ok(_), Err(_)) => a.to_string(),
        (Err(_), Ok(_)) => b.to_string(),
        (Err(_), Err(_)) => a.to_string(),
    }
}

/// Compare two RFC3339 timestamps, returning the later (string preserved).
fn max_ts(a: &str, b: &str) -> String {
    match (DateTime::parse_from_rfc3339(a), DateTime::parse_from_rfc3339(b)) {
        (Ok(ta), Ok(tb)) => if ta >= tb { a.to_string() } else { b.to_string() },
        (Ok(_), Err(_)) => a.to_string(),
        (Err(_), Ok(_)) => b.to_string(),
        (Err(_), Err(_)) => a.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(ip: &str, mac: &str, first: &str, last: &str) -> SensorObservation {
        SensorObservation {
            ip: ip.to_string(),
            family: "IPv4".to_string(),
            mac: mac.to_string(),
            first_heard: first.to_string(),
            last_heard: last.to_string(),
        }
    }

    fn assign(ip: &str, asn: u32, tenant: &str) -> Assignment {
        Assignment {
            ip: ip.to_string(),
            family: "IPv4".to_string(),
            asn: Some(asn),
            tenant: Some(tenant.to_string()),
        }
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn neighbor<'a>(cache: &'a DiscoveredCache, ip: &str) -> &'a DiscoveredNeighbor {
        cache.neighbors.iter().find(|n| n.ip == ip).expect("ip present")
    }

    #[test]
    fn first_seen_preserved_last_seen_advances() {
        let mut store = DiscoveredNeighborStore::load(None);
        let a = vec![assign("10.0.0.1", 64500, "Acme")];
        store.update_at(
            &[obs("10.0.0.1", "aa:aa", "2026-06-18T00:00:00Z", "2026-06-18T00:00:00Z")],
            &a,
            at("2026-06-18T00:00:00Z"),
        );
        store.update_at(
            &[obs("10.0.0.1", "aa:aa", "2026-06-18T01:00:00Z", "2026-06-18T01:00:00Z")],
            &a,
            at("2026-06-18T01:00:00Z"),
        );
        let snap = store.snapshot();
        let n = neighbor(&snap, "10.0.0.1");
        assert_eq!(n.macs.len(), 1);
        assert!(n.macs[0].first_seen.starts_with("2026-06-18T00:00:00"));
        assert!(n.macs[0].last_seen.starts_with("2026-06-18T01:00:00"));
        assert!(!n.conflict);
    }

    #[test]
    fn two_macs_for_one_ip_is_a_conflict() {
        let mut store = DiscoveredNeighborStore::load(None);
        let a = vec![assign("10.0.0.1", 64500, "Acme")];
        store.update_at(
            &[
                obs("10.0.0.1", "aa:aa", "2026-06-18T00:00:00Z", "2026-06-18T00:00:00Z"),
                obs("10.0.0.1", "bb:bb", "2026-06-18T00:00:01Z", "2026-06-18T00:00:01Z"),
            ],
            &a,
            at("2026-06-18T00:00:01Z"),
        );
        let snap = store.snapshot();
        let n = neighbor(&snap, "10.0.0.1");
        assert_eq!(n.macs.len(), 2);
        assert!(n.conflict);
    }

    #[test]
    fn tenant_change_wipes_history() {
        let mut store = DiscoveredNeighborStore::load(None);
        store.update_at(
            &[obs("10.0.0.1", "aa:aa", "2026-06-18T00:00:00Z", "2026-06-18T00:00:00Z")],
            &[assign("10.0.0.1", 64500, "Acme")],
            at("2026-06-18T00:00:00Z"),
        );
        // Reassigned to a different ASN: prior MACs should be cleared.
        store.update_at(
            &[obs("10.0.0.1", "bb:bb", "2026-06-18T02:00:00Z", "2026-06-18T02:00:00Z")],
            &[assign("10.0.0.1", 64501, "Globex")],
            at("2026-06-18T02:00:00Z"),
        );
        let snap = store.snapshot();
        let n = neighbor(&snap, "10.0.0.1");
        assert_eq!(n.asn, Some(64501));
        assert_eq!(n.macs.len(), 1);
        assert_eq!(n.macs[0].mac, "bb:bb");
    }

    #[test]
    fn unassigned_ip_is_retained_and_flagged() {
        let mut store = DiscoveredNeighborStore::load(None);
        // An IP heard on the fabric that is not in the assignment set.
        store.update_at(
            &[obs("10.9.9.9", "aa:aa", "2026-06-18T00:00:00Z", "2026-06-18T00:00:00Z")],
            &[assign("10.0.0.1", 64500, "Acme")],
            at("2026-06-18T00:00:00Z"),
        );
        let snap = store.snapshot();
        let n = neighbor(&snap, "10.9.9.9");
        assert!(!n.assigned, "unassigned IP must be flagged");
        assert_eq!(n.asn, None);
        assert_eq!(n.macs.len(), 1);
        // The assigned IP is still assigned.
        assert!(neighbor(&snap, "10.0.0.1").assigned);
    }

    #[test]
    fn unassigned_ip_ages_out() {
        let mut store = DiscoveredNeighborStore::load(None);
        store.update_at(
            &[obs("10.9.9.9", "aa:aa", "2026-06-18T00:00:00Z", "2026-06-18T00:00:00Z")],
            &[assign("10.0.0.1", 64500, "Acme")],
            at("2026-06-18T00:00:00Z"),
        );
        // A later poll, past the TTL, with the IP no longer heard: it expires.
        // The assigned IP (never heard either) stays.
        store.update_at(&[], &[assign("10.0.0.1", 64500, "Acme")], at("2026-06-19T01:00:00Z"));
        let snap = store.snapshot();
        assert!(snap.neighbors.iter().all(|n| n.ip != "10.9.9.9"), "stale unassigned IP must age out");
        assert!(neighbor(&snap, "10.0.0.1").assigned, "assigned IP never ages out");
    }

    #[test]
    fn assigned_ip_deallocated_then_reheard_becomes_unassigned() {
        let mut store = DiscoveredNeighborStore::load(None);
        store.update_at(
            &[obs("10.0.0.1", "aa:aa", "2026-06-18T00:00:00Z", "2026-06-18T00:00:00Z")],
            &[assign("10.0.0.1", 64500, "Acme")],
            at("2026-06-18T00:00:00Z"),
        );
        // IP deallocated (gone from assignments) but still heard from a new MAC.
        store.update_at(
            &[obs("10.0.0.1", "bb:bb", "2026-06-18T00:05:00Z", "2026-06-18T00:05:00Z")],
            &[],
            at("2026-06-18T00:05:00Z"),
        );
        let snap = store.snapshot();
        let n = neighbor(&snap, "10.0.0.1");
        assert!(!n.assigned, "deallocated IP becomes unassigned");
        // Old-tenant history was wiped; only the freshly-heard MAC remains.
        assert_eq!(n.macs.len(), 1);
        assert_eq!(n.macs[0].mac, "bb:bb");
    }

    #[test]
    fn unassigned_bucket_count_is_capped_keeping_newest() {
        let mut store = DiscoveredNeighborStore::load(None);
        let n_flood = MAX_UNASSIGNED_IPS + 10;
        let obs: Vec<SensorObservation> = (0..n_flood)
            .map(|i| obs(
                &format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256),
                "aa:aa",
                &format!("2026-06-18T{:02}:{:02}:00Z", i / 60, i % 60),
                &format!("2026-06-18T{:02}:{:02}:00Z", i / 60, i % 60),
            ))
            .collect();
        store.update_at(&obs, &[], at("2026-06-18T12:00:00Z"));
        let snap = store.snapshot();
        let kept = snap.neighbors.len();
        assert_eq!(kept, MAX_UNASSIGNED_IPS, "unassigned bucket must be capped");
        // The newest IP survives; the oldest is evicted.
        assert!(snap.neighbors.iter().any(|n| n.ip == format!("10.{}.{}.{}", (n_flood - 1) / 65536, ((n_flood - 1) / 256) % 256, (n_flood - 1) % 256)));
        assert!(snap.neighbors.iter().all(|n| n.ip != "10.0.0.0"), "oldest evicted");
    }

    #[test]
    fn macs_per_ip_are_capped_keeping_newest() {
        let mut store = DiscoveredNeighborStore::load(None);
        // Flood more than the cap for one assigned IP, each newer than the last.
        let n_flood = MAX_MACS_PER_IP + 12;
        let mac = |i: usize| format!("aa:bb:cc:dd:{:02x}:{:02x}", (i >> 8) & 0xff, i & 0xff);
        let obs: Vec<SensorObservation> = (0..n_flood)
            .map(|i| obs(
                "10.0.0.1",
                &mac(i),
                &format!("2026-06-18T{:02}:{:02}:00Z", i / 60, i % 60),
                &format!("2026-06-18T{:02}:{:02}:00Z", i / 60, i % 60),
            ))
            .collect();
        store.update_at(&obs, &[assign("10.0.0.1", 64500, "Acme")], at("2026-06-18T05:00:00Z"));
        let snap = store.snapshot();
        let n = neighbor(&snap, "10.0.0.1");
        assert_eq!(n.macs.len(), MAX_MACS_PER_IP, "must cap MACs per IP");
        assert!(n.conflict, "conflict signal preserved despite cap");
        // The newest MAC must survive; the oldest must be evicted.
        let kept: Vec<&str> = n.macs.iter().map(|m| m.mac.as_str()).collect();
        assert!(kept.contains(&mac(n_flood - 1).as_str()), "newest kept");
        assert!(!kept.contains(&mac(0).as_str()), "oldest evicted");
    }

    #[tokio::test]
    async fn fetch_sensor_parses_real_shaped_output_into_a_conflict() {
        use axum::{routing::get, Json, Router};

        // Exactly the shape lg-neighborhood-watch's GET /neighbors emits
        // (extra fields iface/count are ignored by SensorObservation).
        let payload = serde_json::json!([
            {"ip": "206.197.187.62", "family": "IPv4", "mac": "aa:bb:cc:00:00:01",
             "first_heard": "2026-06-19T03:00:00+00:00", "last_heard": "2026-06-19T03:05:00+00:00",
             "iface": "vlan998", "count": 7},
            {"ip": "206.197.187.62", "family": "IPv4", "mac": "aa:bb:cc:99:99:99",
             "first_heard": "2026-06-19T03:02:00+00:00", "last_heard": "2026-06-19T03:04:00+00:00",
             "iface": "vlan998", "count": 2}
        ]);
        let app = Router::new().route(
            "/neighbors",
            get(move || {
                let p = payload.clone();
                async move { Json(p) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let obs = fetch_sensor(&format!("http://{addr}")).await.unwrap();
        assert_eq!(obs.len(), 2);

        let mut store = DiscoveredNeighborStore::load(None);
        store.update(&obs, &[assign("206.197.187.62", 64500, "Acme")]);
        let snap = store.snapshot();
        let n = neighbor(&snap, "206.197.187.62");
        assert_eq!(n.asn, Some(64500));
        assert_eq!(n.macs.len(), 2);
        assert!(n.conflict, "two MACs for one IP must flag a conflict");
    }

    #[test]
    fn fetch_failure_retains_data() {
        let mut store = DiscoveredNeighborStore::load(None);
        store.update_at(
            &[obs("10.0.0.1", "aa:aa", "2026-06-18T00:00:00Z", "2026-06-18T00:00:00Z")],
            &[assign("10.0.0.1", 64500, "Acme")],
            at("2026-06-18T00:00:00Z"),
        );
        store.set_error("connection refused");
        let snap = store.snapshot();
        assert_eq!(snap.neighbors.len(), 1);
        assert_eq!(snap.last_error.as_deref(), Some("connection refused"));
    }
}
