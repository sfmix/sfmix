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
    /// Times the sensor saw this (ip, mac) sourced by a frame whose two MAC
    /// assertions disagreed (the NDP link-layer-address option, or the ARP
    /// sender-hardware-address, named a different MAC than the outer Ethernet
    /// source). Nonzero is the fingerprint of verbatim flood *reflection*.
    #[serde(default)]
    pub mismatch_count: u64,
    /// The counterpart MAC from those mismatching frames: for an NDP row (`mac`
    /// is the Ethernet source) this is the option's MAC — the *original owner*
    /// whose frame was re-flooded. `None` when no mismatch was seen.
    #[serde(default)]
    pub mismatched_mac: Option<String>,
}

/// A newly-opened anomaly event that warrants a pcap snapshot. Returned from
/// [`DiscoveredNeighborStore::update`] so the poll loop can trigger evidence
/// capture out-of-band (a flap into an existing event yields nothing here).
#[derive(Debug, Clone)]
pub struct NewAnomaly {
    pub event_id: String,
    /// MACs to filter the pcap on (the conflicting MACs, or the offending MAC).
    pub macs: Vec<String>,
    /// Event time, used to centre the extraction window.
    pub at: DateTime<Utc>,
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
    /// MAC liveness/staleness window (seconds). When set, a MAC not heard within
    /// this window is marked `stale` and excluded from the conflict flag, and the
    /// same window decides whether a conflict is still "live" for anomaly
    /// rollup. `None` disables aging (all heard MACs count, as before).
    mac_ttl_secs: Option<i64>,
    /// Cardinality threshold for one-MAC-many-IP sweep detection (count of
    /// unassigned IPs claimed by a single MAC). 0 disables the cardinality trigger
    /// (cross-tenant claims still fire).
    max_ips_per_mac: usize,
}

impl DiscoveredNeighborStore {
    /// Load from disk. Returns an empty store if the path is unset, the file is
    /// missing, or it fails to parse (warn-and-continue).
    pub fn load(path: Option<PathBuf>) -> Self {
        let mut store = Self {
            path,
            records: HashMap::new(),
            fetched_at: None,
            last_error: None,
            mac_ttl_secs: None,
            max_ips_per_mac: 8,
        };
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

    /// Set the MAC liveness/staleness TTL (seconds). `None`/`Some(0)` disables aging.
    pub fn with_mac_ttl(mut self, secs: Option<u64>) -> Self {
        self.mac_ttl_secs = secs.filter(|s| *s > 0).map(|s| s as i64);
        self
    }

    /// Set the one-MAC-many-IP cardinality threshold (unassigned IPs per MAC).
    pub fn with_max_ips_per_mac(mut self, n: u64) -> Self {
        self.max_ips_per_mac = n as usize;
        self
    }

    /// Fold a fresh sensor poll into the store against the current assignments.
    /// `anomaly`, when present, records new-MAC-on-an-existing-IP events. Returns
    /// the events newly opened this poll (for evidence-snapshot triggering).
    pub fn update(
        &mut self,
        sensor: &[SensorObservation],
        assignments: &[Assignment],
        anomaly: Option<&crate::anomaly::AnomalyStore>,
    ) -> Vec<NewAnomaly> {
        self.update_at(sensor, assignments, anomaly, Utc::now())
    }

    /// Testable core of [`update`] with an injected clock.
    fn update_at(
        &mut self,
        sensor: &[SensorObservation],
        assignments: &[Assignment],
        anomaly: Option<&crate::anomaly::AnomalyStore>,
        now: DateTime<Utc>,
    ) -> Vec<NewAnomaly> {
        let mut new_anomalies: Vec<NewAnomaly> = Vec::new();
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

        // Liveness window for anomaly rollup: a MAC counts as live this poll only
        // if its sensor `last_heard` is within this window. Uses the MAC TTL when
        // aging is on, else the rollup cooldown. `None` when no anomaly store.
        let live_cutoff: Option<DateTime<Utc>> = anomaly.map(|store| {
            let window = self
                .mac_ttl_secs
                .map(chrono::Duration::seconds)
                .unwrap_or_else(|| store.cooldown());
            now - window
        });
        // Distinct MACs *heard this poll* (and fresh) per IP. Keying liveness on
        // the current observations — not the un-aged retained record — is what
        // lets a migration close: once only one MAC is still being heard, the
        // conflict stops being touched and its event closes after the cooldown.
        let mut live_macs: HashMap<&str, std::collections::HashSet<&str>> = HashMap::new();
        // The inverse — distinct fresh IPs claimed per MAC this poll — drives
        // one-MAC-many-IP (proxy-ARP) sweep detection.
        let mut mac_ips: HashMap<&str, std::collections::HashSet<&str>> = HashMap::new();
        // Reflector MAC → (victim IPs it was heard re-flooding, family). A reflected
        // frame preserves the true owner's MAC inside its link-layer option while
        // rewriting the outer source to the reflector, so it is *not* a claim: it is
        // excluded from the conflict/liveness/sweep folds above and rolled up here
        // into a single reflection event attributed to the reflector.
        let mut reflections: HashMap<&str, (std::collections::HashSet<&str>, &str)> = HashMap::new();
        // MAC → its owning participant, learned from the MAC's own clean (non-
        // reflected) sightings on assigned IPs. Used to attribute the reflection
        // event to the reflector's participant.
        let mut mac_owner: HashMap<&str, (Option<u32>, Option<&str>)> = HashMap::new();

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

            // Reflection: this frame's outer source (`obs.mac`) differs from the MAC
            // its link-layer option named (`obs.mismatched_mac`), and that named MAC
            // is one already legitimately heard for this IP. That is verbatim
            // re-flooding, not a new claim — so peel it off before the conflict
            // check: it must not open a new-MAC event against the victim, latch the
            // victim's live conflict flag, or feed sweep detection. It is rolled up
            // per reflector after the loop instead. (A mismatch whose inner MAC is
            // *not* an existing owner is a forged option, not a reflection; it falls
            // through to normal handling below.)
            let reflected = obs
                .mismatched_mac
                .as_deref()
                .is_some_and(|inner| rec.macs.keys().any(|k| k.eq_ignore_ascii_case(inner)));
            if reflected {
                let e = reflections
                    .entry(obs.mac.as_str())
                    .or_insert_with(|| (std::collections::HashSet::new(), obs.family.as_str()));
                e.0.insert(obs.ip.as_str());
                continue;
            }

            // Learn this MAC's own participant from its clean sightings on assigned
            // IPs, so a reflection event can be attributed to the reflector.
            if let Some(a) = assigned.get(obs.ip.as_str()) {
                mac_owner
                    .entry(obs.mac.as_str())
                    .or_insert((a.asn, a.tenant.as_deref()));
            }

            // A new MAC arriving on an IP that already has other MAC(s) is the
            // anomaly: record it (with rollup) before folding it into the record.
            // The first MAC ever heard for an IP is not a conflict.
            if let Some(store) = anomaly {
                if !rec.macs.is_empty() && !rec.macs.contains_key(&obs.mac) {
                    let old_macs: Vec<String> = rec.macs.keys().cloned().collect();
                    if let Some(record) = store.record_conflict(
                        &obs.ip,
                        &rec.family,
                        rec.asn,
                        rec.tenant.as_deref(),
                        &old_macs,
                        &obs.mac,
                        now,
                    ) {
                        if record.is_new {
                            let mut macs = old_macs;
                            macs.push(obs.mac.clone());
                            new_anomalies.push(NewAnomaly { event_id: record.event_id, macs, at: now });
                        }
                    }
                }
            }
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

            // Record this MAC as live-this-poll if its sighting is fresh. An empty
            // `last_heard` means the sensor heard it just now → always fresh.
            if let Some(cutoff) = live_cutoff {
                let fresh = obs.last_heard.is_empty()
                    || DateTime::parse_from_rfc3339(&obs.last_heard)
                        .map(|x| x.with_timezone(&Utc) >= cutoff)
                        .unwrap_or(true);
                if fresh {
                    live_macs.entry(obs.ip.as_str()).or_default().insert(obs.mac.as_str());
                    mac_ips.entry(obs.mac.as_str()).or_default().insert(obs.ip.as_str());
                }
            }
        }

        // Extend open anomaly windows for conflicts heard live this poll (≥2
        // distinct fresh MACs). `touch_conflict` is a no-op when no event is open.
        if let Some(store) = anomaly {
            for (ip, macs) in &live_macs {
                if macs.len() > 1 {
                    store.touch_conflict(ip, now);
                }
            }
        }

        // One-MAC-many-IP (proxy-ARP / sweep) detection. For each MAC heard this
        // poll, evaluate two triggers against the NetBox assignments:
        //   - cross-tenant: the MAC claims IPs of ≥2 distinct ASNs (a member's own
        //     IPv4+IPv6 is one ASN, so this is the low-false-positive smoking gun);
        //   - cardinality: the MAC claims more than `max_ips_per_mac` *unassigned*
        //     IPs (blanket proxy-ARP over idle space, where there's no owner).
        if let Some(store) = anomaly {
            for (mac, ips) in &mac_ips {
                let mut asns: std::collections::HashSet<u32> = std::collections::HashSet::new();
                let mut unassigned = 0usize;
                for ip in ips {
                    match assigned.get(*ip).and_then(|a| a.asn) {
                        Some(asn) => {
                            asns.insert(asn);
                        }
                        None => unassigned += 1,
                    }
                }
                let cross_tenant = asns.len() >= 2;
                let big_unassigned = self.max_ips_per_mac > 0 && unassigned > self.max_ips_per_mac;
                if cross_tenant || big_unassigned {
                    let claimed: Vec<String> = ips.iter().map(|s| s.to_string()).collect();
                    let (asn, tenant) = mac_owner.get(mac).copied().unwrap_or((None, None));
                    if let Some(record) = store.record_mac_sweep(mac, "", asn, tenant, &claimed, None, now) {
                        if record.is_new {
                            new_anomalies.push(NewAnomaly {
                                event_id: record.event_id,
                                macs: vec![(*mac).to_string()],
                                at: now,
                            });
                        }
                    }
                }
            }
        }

        // Reflection rollup: one event per reflector MAC, attributed to the
        // reflector's participant, listing the victim IPs it re-flooded. Keyed on
        // the MAC in the same sweep store, so repeated reflection bursts within the
        // cooldown collapse into one growing event (and merge with any genuine sweep
        // for the same MAC, keeping the reflection classification).
        if let Some(store) = anomaly {
            for (reflector_mac, (victim_ips, family)) in &reflections {
                let (asn, tenant) = mac_owner.get(reflector_mac).copied().unwrap_or((None, None));
                let claimed: Vec<String> = victim_ips.iter().map(|s| s.to_string()).collect();
                if let Some(record) = store.record_mac_sweep(
                    reflector_mac,
                    family,
                    asn,
                    tenant,
                    &claimed,
                    Some(lg_types::structured::EVENT_CLASSIFICATION_REFLECTION),
                    now,
                ) {
                    if record.is_new {
                        new_anomalies.push(NewAnomaly {
                            event_id: record.event_id,
                            macs: vec![(*reflector_mac).to_string()],
                            at: now,
                        });
                    }
                }
            }
        }

        // Bound the unassigned bucket: expire stale records, then cap the count.
        self.prune_unassigned(now);

        self.fetched_at = Some(now_str);
        self.last_error = None;
        new_anomalies
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
        self.snapshot_at(Utc::now())
    }

    /// Testable core of [`snapshot`] with an injected clock. When `mac_ttl_secs`
    /// is set, MACs not heard within the TTL are flagged `stale` and excluded
    /// from the `conflict` flag, so a resolved conflict (e.g. a completed
    /// migration whose old MAC has gone quiet) stops reading as active. With no
    /// TTL, every MAC counts and nothing is stale (original behavior).
    fn snapshot_at(&self, now: DateTime<Utc>) -> DiscoveredCache {
        let stale_cutoff = self.mac_ttl_secs.map(|s| now - chrono::Duration::seconds(s));
        let mut neighbors: Vec<DiscoveredNeighbor> = self
            .records
            .iter()
            .map(|(ip, rec)| {
                let mut macs: Vec<DiscoveredMac> = rec
                    .macs
                    .iter()
                    .map(|(mac, t)| {
                        let stale = stale_cutoff.is_some_and(|cutoff| {
                            DateTime::parse_from_rfc3339(&t.last_seen)
                                .map(|x| x.with_timezone(&Utc) < cutoff)
                                .unwrap_or(false)
                        });
                        DiscoveredMac {
                            mac: mac.clone(),
                            first_seen: t.first_seen.clone(),
                            last_seen: t.last_seen.clone(),
                            stale,
                        }
                    })
                    .collect();
                macs.sort_by(|a, b| a.mac.cmp(&b.mac));
                // Conflict is computed on non-stale MACs only: >1 MAC heard
                // recently. A single live MAC alongside aged-out history is not
                // a live conflict.
                let live_macs = macs.iter().filter(|m| !m.stale).count();
                DiscoveredNeighbor {
                    ip: ip.clone(),
                    family: rec.family.clone(),
                    asn: rec.asn,
                    tenant: rec.tenant.clone(),
                    conflict: live_macs > 1,
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
    let mut store = DiscoveredNeighborStore::load(cfg.state_file.clone().map(PathBuf::from))
        .with_mac_ttl(cfg.mac_ttl_secs)
        .with_max_ips_per_mac(cfg.max_ips_per_mac);
    // Publish whatever survived the last restart right away.
    lg.discovered.store(std::sync::Arc::new(store.snapshot()));

    let sensor_url = cfg.sensor_url.clone();
    let interval_secs = cfg.poll_interval_secs;
    info!(
        "Discovered-neighbor poll enabled (sensor: {sensor_url}, interval: {interval_secs}s)"
    );

    // Evidence-snapshot trigger worker: a single serialized consumer so a burst of
    // new anomalies paces to the sensor's one-at-a-time extraction (no 503 storm).
    // Only runs when the anomaly store is configured.
    let snap_tx = lg.anomaly.as_ref().map(|_| {
        let (tx, rx) = tokio::sync::mpsc::channel::<NewAnomaly>(256);
        spawn_snapshot_worker(sensor_url.clone(), lg.clone(), rx);
        tx
    });

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
                    let new_anomalies = store.update(&obs, &assignments, lg.anomaly.as_deref());
                    tracing::debug!("discovered-neighbor poll: {} observations", obs.len());
                    // Hand newly-opened events to the snapshot worker (best-effort:
                    // drop if its queue is saturated rather than stalling the poll).
                    if let Some(ref tx) = snap_tx {
                        for ev in new_anomalies {
                            if tx.try_send(ev).is_err() {
                                tracing::warn!("evidence-snapshot queue full; dropping a trigger");
                            }
                        }
                    }
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

/// Serialized worker that POSTs evidence-snapshot requests to the sensor and
/// links the returned `evidence_id` back onto the event. One request at a time
/// matches the sensor's extraction concurrency and avoids hammering it.
fn spawn_snapshot_worker(
    sensor_url: String,
    lg: std::sync::Arc<crate::service::LookingGlass>,
    mut rx: tokio::sync::mpsc::Receiver<NewAnomaly>,
) {
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("evidence-snapshot client build failed: {e}");
                return;
            }
        };
        let url = format!("{}/evidence/snapshot", sensor_url.trim_end_matches('/'));
        while let Some(ev) = rx.recv().await {
            // ±5 minutes around the event.
            let window = chrono::Duration::minutes(5);
            let body = serde_json::json!({
                "event_id": ev.event_id,
                "macs": ev.macs,
                "time_start": (ev.at - window).to_rfc3339(),
                "time_end": (ev.at + window).to_rfc3339(),
            });
            match client.post(&url).json(&body).send().await {
                Ok(resp) if resp.status().is_success() => {
                    // 200: extraction done (or already existed) — link the evidence.
                    if let Ok(meta) = resp.json::<serde_json::Value>().await {
                        if let Some(evidence_id) = meta.get("evidence_id").and_then(|v| v.as_str()) {
                            if let Some(store) = lg.anomaly.as_ref() {
                                if let Err(e) = store.set_evidence(&ev.event_id, evidence_id) {
                                    tracing::warn!("linking evidence {evidence_id} to {}: {e}", ev.event_id);
                                }
                            }
                        }
                    }
                }
                Ok(resp) => {
                    // 409 (in progress) / 503 (busy) / 501 (disabled): not linked now.
                    tracing::debug!("evidence snapshot for {} returned {}", ev.event_id, resp.status());
                }
                Err(e) => tracing::warn!("evidence snapshot POST for {} failed: {e}", ev.event_id),
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
            mismatch_count: 0,
            mismatched_mac: None,
        }
    }

    /// A reflected sighting: `mac` (outer Ethernet source) re-flooded a frame that
    /// still named `inner` (the true owner) in its link-layer option.
    fn refl_obs(ip: &str, mac: &str, inner: &str, at: &str) -> SensorObservation {
        SensorObservation {
            ip: ip.to_string(),
            family: "IPv6".to_string(),
            mac: mac.to_string(),
            first_heard: at.to_string(),
            last_heard: at.to_string(),
            mismatch_count: 1,
            mismatched_mac: Some(inner.to_string()),
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
            None,
            at("2026-06-18T00:00:00Z"),
        );
        store.update_at(
            &[obs("10.0.0.1", "aa:aa", "2026-06-18T01:00:00Z", "2026-06-18T01:00:00Z")],
            &a,
            None,
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
            None,
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
            None,
            at("2026-06-18T00:00:00Z"),
        );
        // Reassigned to a different ASN: prior MACs should be cleared.
        store.update_at(
            &[obs("10.0.0.1", "bb:bb", "2026-06-18T02:00:00Z", "2026-06-18T02:00:00Z")],
            &[assign("10.0.0.1", 64501, "Globex")],
            None,
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
            None,
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
            None,
            at("2026-06-18T00:00:00Z"),
        );
        // A later poll, past the TTL, with the IP no longer heard: it expires.
        // The assigned IP (never heard either) stays.
        store.update_at(&[], &[assign("10.0.0.1", 64500, "Acme")], None, at("2026-06-19T01:00:00Z"));
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
            None,
            at("2026-06-18T00:00:00Z"),
        );
        // IP deallocated (gone from assignments) but still heard from a new MAC.
        store.update_at(
            &[obs("10.0.0.1", "bb:bb", "2026-06-18T00:05:00Z", "2026-06-18T00:05:00Z")],
            &[],
            None,
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
        store.update_at(&obs, &[], None, at("2026-06-18T12:00:00Z"));
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
        store.update_at(&obs, &[assign("10.0.0.1", 64500, "Acme")], None, at("2026-06-18T05:00:00Z"));
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
        store.update(&obs, &[assign("206.197.187.62", 64500, "Acme")], None);
        let snap = store.snapshot();
        let n = neighbor(&snap, "206.197.187.62");
        assert_eq!(n.asn, Some(64500));
        assert_eq!(n.macs.len(), 2);
        assert!(n.conflict, "two MACs for one IP must flag a conflict");
    }

    #[test]
    fn update_records_new_mac_anomaly() {
        use crate::anomaly::AnomalyStore;
        // In-memory SQLite store; 600s cooldown.
        let anomaly = AnomalyStore::open(std::path::Path::new(":memory:"), 600).unwrap();
        let mut store = DiscoveredNeighborStore::load(None);
        let a = vec![assign("10.0.0.1", 64500, "Acme")];

        // First MAC for the IP: not a conflict, no event.
        store.update_at(
            &[obs("10.0.0.1", "aa:aa", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z")],
            &a,
            Some(&anomaly),
            at("2026-06-19T00:00:00Z"),
        );
        assert!(anomaly.list_events(None, None, 10, 0, at("2026-06-19T00:00:00Z")).unwrap().is_empty());

        // A second, different MAC on the same IP: anomaly recorded.
        store.update_at(
            &[obs("10.0.0.1", "bb:bb", "2026-06-19T00:01:00Z", "2026-06-19T00:01:00Z")],
            &a,
            Some(&anomaly),
            at("2026-06-19T00:01:00Z"),
        );
        let events = anomaly.list_events(None, None, 10, 0, at("2026-06-19T00:01:00Z")).unwrap();
        assert_eq!(events.len(), 1, "new MAC on existing IP must record one event");
        assert_eq!(events[0].ip, "10.0.0.1");
        assert_eq!(events[0].asn, Some(64500));
        assert_eq!(events[0].new_mac, "bb:bb");
        assert_eq!(events[0].old_macs, vec!["aa:aa".to_string()]);
        assert_eq!(events[0].flap_count, 1);

        // Re-hearing BOTH known MACs (the conflict is still live on the wire)
        // adds no new event but extends the open one's window.
        store.update_at(
            &[
                obs("10.0.0.1", "aa:aa", "2026-06-19T00:02:00Z", "2026-06-19T00:02:00Z"),
                obs("10.0.0.1", "bb:bb", "2026-06-19T00:02:00Z", "2026-06-19T00:02:00Z"),
            ],
            &a,
            Some(&anomaly),
            at("2026-06-19T00:02:00Z"),
        );
        let events = anomaly.list_events(None, None, 10, 0, at("2026-06-19T00:02:00Z")).unwrap();
        assert_eq!(events.len(), 1, "re-hearing known MACs must not open a new event");
        assert_eq!(events[0].flap_count, 1, "re-hearing must not bump flap_count");
        assert_eq!(
            events[0].last_seen,
            at("2026-06-19T00:02:00Z").to_rfc3339(),
            "re-hearing a live conflict (both MACs) extends the event window"
        );
        assert!(!events[0].closed, "still-heard conflict stays open");
    }

    #[test]
    fn migration_event_auto_closes_once_old_mac_goes_stale() {
        // The canonical false-positive this project exists to kill: a member swaps
        // hardware (old MAC -> new MAC). The sensor has no decay, so it keeps
        // re-emitting the stale old MAC forever. The event must still CLOSE once
        // the old MAC's sightings age past the freshness window — otherwise the
        // latched-conflict warning just moves to the events page.
        use crate::anomaly::AnomalyStore;
        let anomaly = AnomalyStore::open(std::path::Path::new(":memory:"), 600).unwrap();
        let mut store = DiscoveredNeighborStore::load(None);
        let a = vec![assign("10.0.0.1", 64500, "Acme")];

        // t0: old MAC only.
        store.update_at(
            &[obs("10.0.0.1", "aa:aa", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z")],
            &a,
            Some(&anomaly),
            at("2026-06-19T00:00:00Z"),
        );
        // t0+60s: new MAC appears -> conflict event opens. The sensor still
        // reports the old MAC with its FROZEN last_heard (t0).
        store.update_at(
            &[
                obs("10.0.0.1", "aa:aa", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"),
                obs("10.0.0.1", "bb:bb", "2026-06-19T00:01:00Z", "2026-06-19T00:01:00Z"),
            ],
            &a,
            Some(&anomaly),
            at("2026-06-19T00:01:00Z"),
        );
        assert_eq!(anomaly.list_events(None, None, 10, 0, at("2026-06-19T00:01:00Z")).unwrap().len(), 1);

        // Poll every minute for 40 minutes. The old device is gone, so the sensor
        // keeps emitting aa:aa with its frozen last_heard=t0 while bb:bb stays live.
        for m in 2..=40 {
            store.update_at(
                &[
                    obs("10.0.0.1", "aa:aa", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"),
                    obs(
                        "10.0.0.1",
                        "bb:bb",
                        "2026-06-19T00:01:00Z",
                        &format!("2026-06-19T00:{m:02}:00Z"),
                    ),
                ],
                &a,
                Some(&anomaly),
                at(&format!("2026-06-19T00:{m:02}:00Z")),
            );
        }

        // No second event opened (bb:bb was only ever one new MAC).
        let events = anomaly.list_events(None, None, 10, 0, at("2026-06-19T00:40:00Z")).unwrap();
        assert_eq!(events.len(), 1, "no duplicate events for a single migration");
        // The window stopped extending once aa:aa aged out (its last_heald froze
        // at t0, so it left the 600s freshness window ~10 min in).
        assert!(
            events[0].last_seen.as_str() <= "2026-06-19T00:11:00+00:00",
            "window must stop extending once the old MAC goes stale, got {}",
            events[0].last_seen
        );
        assert!(events[0].closed, "a completed migration's event must close, not latch open");
    }

    #[test]
    fn brief_conflict_is_recorded_durably_even_after_it_clears() {
        // Don't-miss guard: a conflict present for a single poll is recorded and
        // survives, even after both MACs age out and the live conflict flag clears.
        use crate::anomaly::AnomalyStore;
        let anomaly = AnomalyStore::open(std::path::Path::new(":memory:"), 600).unwrap();
        let mut store = DiscoveredNeighborStore::load(None).with_mac_ttl(Some(1800));
        let a = vec![assign("10.0.0.1", 64500, "Acme")];

        // First MAC.
        store.update_at(
            &[obs("10.0.0.1", "aa:aa", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z")],
            &a,
            Some(&anomaly),
            at("2026-06-19T00:00:00Z"),
        );
        // Brief conflict: a second MAC appears in one poll.
        store.update_at(
            &[obs("10.0.0.1", "bb:bb", "2026-06-19T00:01:00Z", "2026-06-19T00:01:00Z")],
            &a,
            Some(&anomaly),
            at("2026-06-19T00:01:00Z"),
        );
        // Then silence (empty polls) for well over an hour.
        for t in ["2026-06-19T00:10:00Z", "2026-06-19T00:30:00Z", "2026-06-19T01:30:00Z"] {
            store.update_at(&[], &a, Some(&anomaly), at(t));
        }

        // The durable event is still there (closed, but recorded).
        let events = anomaly.list_events(None, None, 10, 0, at("2026-06-19T02:00:00Z")).unwrap();
        assert_eq!(events.len(), 1, "the brief conflict must be recorded durably");
        assert_eq!(events[0].new_mac, "bb:bb");
        assert!(events[0].closed, "long-quiet conflict reads closed");
        // And the live snapshot no longer flags a conflict (both MACs now stale).
        let snap = store.snapshot_at(at("2026-06-19T02:00:00Z"));
        assert!(!neighbor(&snap, "10.0.0.1").conflict, "aged-out conflict clears from live table");
    }

    #[test]
    fn stale_mac_is_flagged_and_excluded_from_conflict() {
        // With a TTL set, a MAC unheard past the TTL is marked stale and no longer
        // counts toward the conflict flag.
        let mut store = DiscoveredNeighborStore::load(None).with_mac_ttl(Some(1800));
        let a = vec![assign("10.0.0.1", 64500, "Acme")];
        // Old MAC heard at t0; new MAC appears at t0+1min (conflict). The new MAC
        // keeps being heard (00:35) while the old one goes quiet — a migration.
        store.update_at(
            &[obs("10.0.0.1", "aa:aa", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z")],
            &a,
            None,
            at("2026-06-19T00:00:00Z"),
        );
        store.update_at(
            &[obs("10.0.0.1", "bb:bb", "2026-06-19T00:01:00Z", "2026-06-19T00:01:00Z")],
            &a,
            None,
            at("2026-06-19T00:01:00Z"),
        );
        store.update_at(
            &[obs("10.0.0.1", "bb:bb", "2026-06-19T00:35:00Z", "2026-06-19T00:35:00Z")],
            &a,
            None,
            at("2026-06-19T00:35:00Z"),
        );
        // Read at 00:40: aa:aa (last_seen 00:00) is >30min stale; bb:bb (00:35) fresh.
        let snap = store.snapshot_at(at("2026-06-19T00:40:00Z"));
        let n = neighbor(&snap, "10.0.0.1");
        assert_eq!(n.macs.len(), 2, "both MACs retained in the snapshot");
        let aa = n.macs.iter().find(|m| m.mac == "aa:aa").unwrap();
        let bb = n.macs.iter().find(|m| m.mac == "bb:bb").unwrap();
        assert!(aa.stale, "old MAC past TTL is stale");
        assert!(!bb.stale, "recently-heard MAC is not stale");
        assert!(!n.conflict, "one live MAC + one stale MAC is not a live conflict");
    }

    #[test]
    fn fresh_two_macs_still_conflict_under_ttl() {
        let mut store = DiscoveredNeighborStore::load(None).with_mac_ttl(Some(1800));
        let a = vec![assign("10.0.0.1", 64500, "Acme")];
        store.update_at(
            &[
                obs("10.0.0.1", "aa:aa", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"),
                obs("10.0.0.1", "bb:bb", "2026-06-19T00:00:30Z", "2026-06-19T00:00:30Z"),
            ],
            &a,
            None,
            at("2026-06-19T00:00:30Z"),
        );
        // Both heard within the TTL window → still a live conflict.
        let snap = store.snapshot_at(at("2026-06-19T00:05:00Z"));
        let n = neighbor(&snap, "10.0.0.1");
        assert!(n.macs.iter().all(|m| !m.stale));
        assert!(n.conflict, "two recently-heard MACs are a live conflict");
    }

    #[test]
    fn no_ttl_means_nothing_is_stale() {
        // Default (no TTL): the original behavior — all MACs count, none stale.
        let mut store = DiscoveredNeighborStore::load(None);
        let a = vec![assign("10.0.0.1", 64500, "Acme")];
        store.update_at(
            &[obs("10.0.0.1", "aa:aa", "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z")],
            &a,
            None,
            at("2020-01-01T00:00:00Z"),
        );
        store.update_at(
            &[obs("10.0.0.1", "bb:bb", "2020-01-01T00:01:00Z", "2020-01-01T00:01:00Z")],
            &a,
            None,
            at("2020-01-01T00:01:00Z"),
        );
        let snap = store.snapshot(); // real now, years later
        let n = neighbor(&snap, "10.0.0.1");
        assert!(n.macs.iter().all(|m| !m.stale), "no TTL → never stale");
        assert!(n.conflict, "no TTL → all MACs count toward conflict");
    }

    // ── Phase 6: one-MAC-many-IP (proxy-ARP) sweep detection ─────────────

    fn sweep_events(anomaly: &crate::anomaly::AnomalyStore, now: &str) -> Vec<lg_types::structured::AnomalyEvent> {
        anomaly
            .list_events(None, None, 100, 0, at(now))
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == lg_types::structured::EVENT_KIND_MAC_SWEEP)
            .collect()
    }

    #[test]
    fn cross_tenant_mac_claim_opens_one_sweep_event() {
        use crate::anomaly::AnomalyStore;
        let anomaly = AnomalyStore::open(std::path::Path::new(":memory:"), 600).unwrap();
        let mut store = DiscoveredNeighborStore::load(None).with_mac_ttl(Some(1800));
        // Two IPs owned by two *different* ASNs.
        let assignments = vec![assign("10.0.0.1", 64500, "Acme"), assign("10.0.0.2", 64501, "Globex")];
        // One rogue MAC answers for both → cross-tenant smoking gun.
        store.update_at(
            &[
                obs("10.0.0.1", "0a:rogue", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"),
                obs("10.0.0.2", "0a:rogue", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"),
            ],
            &assignments,
            Some(&anomaly),
            at("2026-06-19T00:00:00Z"),
        );
        let sweeps = sweep_events(&anomaly, "2026-06-19T00:00:00Z");
        assert_eq!(sweeps.len(), 1, "cross-tenant claim → one sweep event");
        assert_eq!(sweeps[0].new_mac, "0a:rogue");
        assert_eq!(sweeps[0].claimed_ips, vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn cardinality_over_unassigned_space_opens_one_sweep_event() {
        use crate::anomaly::AnomalyStore;
        let anomaly = AnomalyStore::open(std::path::Path::new(":memory:"), 600).unwrap();
        // Threshold 8; no assignments (all IPs are unassigned/idle space).
        let mut store = DiscoveredNeighborStore::load(None).with_max_ips_per_mac(8);
        let obs_batch: Vec<SensorObservation> = (1..=20)
            .map(|i| obs(&format!("10.0.0.{i}"), "0a:rogue", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"))
            .collect();
        store.update_at(&obs_batch, &[], Some(&anomaly), at("2026-06-19T00:00:00Z"));
        let sweeps = sweep_events(&anomaly, "2026-06-19T00:00:00Z");
        assert_eq!(sweeps.len(), 1, "blanket claim over unassigned space → one sweep event");
        assert_eq!(sweeps[0].claimed_ips.len(), 20);
    }

    #[test]
    fn member_own_v4_and_v6_is_not_a_sweep() {
        use crate::anomaly::AnomalyStore;
        let anomaly = AnomalyStore::open(std::path::Path::new(":memory:"), 600).unwrap();
        let mut store = DiscoveredNeighborStore::load(None).with_max_ips_per_mac(8);
        // One member, one ASN, its IPv4 + IPv6, answered by its own single MAC.
        let assignments = vec![
            Assignment { ip: "10.0.0.1".into(), family: "IPv4".into(), asn: Some(64500), tenant: Some("Acme".into()) },
            Assignment { ip: "2001:db8::1".into(), family: "IPv6".into(), asn: Some(64500), tenant: Some("Acme".into()) },
        ];
        store.update_at(
            &[
                obs("10.0.0.1", "0a:acme", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"),
                obs("2001:db8::1", "0a:acme", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"),
            ],
            &assignments,
            Some(&anomaly),
            at("2026-06-19T00:00:00Z"),
        );
        assert!(sweep_events(&anomaly, "2026-06-19T00:00:00Z").is_empty(), "own v4+v6 (one ASN) is not a sweep");
    }

    #[test]
    fn sweep_grows_one_rolling_event_across_polls() {
        use crate::anomaly::AnomalyStore;
        let anomaly = AnomalyStore::open(std::path::Path::new(":memory:"), 600).unwrap();
        let mut store = DiscoveredNeighborStore::load(None).with_max_ips_per_mac(8);
        // Poll 1: rogue sweeps 10 unassigned IPs.
        let batch1: Vec<SensorObservation> = (1..=10)
            .map(|i| obs(&format!("10.0.0.{i}"), "0a:rogue", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"))
            .collect();
        store.update_at(&batch1, &[], Some(&anomaly), at("2026-06-19T00:00:00Z"));
        // Poll 2 (within cooldown): more IPs from the same MAC.
        let batch2: Vec<SensorObservation> = (11..=20)
            .map(|i| obs(&format!("10.0.0.{i}"), "0a:rogue", "2026-06-19T00:01:00Z", "2026-06-19T00:01:00Z"))
            .collect();
        store.update_at(&batch2, &[], Some(&anomaly), at("2026-06-19T00:01:00Z"));
        let sweeps = sweep_events(&anomaly, "2026-06-19T00:01:00Z");
        assert_eq!(sweeps.len(), 1, "one rolling sweep across polls, not one-per-poll");
        assert_eq!(sweeps[0].claimed_ips.len(), 20, "claimed-IP set accumulates across polls");
        assert_eq!(sweeps[0].flap_count, 2);
    }

    fn new_mac_events(anomaly: &crate::anomaly::AnomalyStore, now: &str) -> Vec<lg_types::structured::AnomalyEvent> {
        anomaly
            .list_events(None, None, 100, 0, at(now))
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == lg_types::structured::EVENT_KIND_NEW_MAC)
            .collect()
    }

    #[test]
    fn reflected_frame_rolls_up_to_the_reflector_not_the_victims() {
        use crate::anomaly::AnomalyStore;
        let anomaly = AnomalyStore::open(std::path::Path::new(":memory:"), 600).unwrap();
        let mut store = DiscoveredNeighborStore::load(None).with_max_ips_per_mac(8);
        // Victim IP owned by its real MAC; the reflector owns a separate IP.
        let assignments = vec![
            assign("2001:db8::victim", 64500, "Acme"),
            assign("2001:db8::reflector", 26415, "Verisign"),
        ];
        // Poll 1: establish both legitimate bindings (victim's real MAC on its IP,
        // reflector's own MAC on its own IP — the latter is how we attribute).
        store.update_at(
            &[
                obs("2001:db8::victim", "aa:bb:cc:00:00:01", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"),
                obs("2001:db8::reflector", "0a:00:05:18:9d:49", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"),
            ],
            &assignments,
            Some(&anomaly),
            at("2026-06-19T00:00:00Z"),
        );
        assert!(new_mac_events(&anomaly, "2026-06-19T00:00:00Z").is_empty());

        // Poll 2: the reflector re-floods the victim's frame verbatim — outer src is
        // the reflector, but the link-layer option still names the victim's MAC.
        store.update_at(
            &[
                obs("2001:db8::reflector", "0a:00:05:18:9d:49", "2026-06-19T00:01:00Z", "2026-06-19T00:01:00Z"),
                refl_obs("2001:db8::victim", "0a:00:05:18:9d:49", "aa:bb:cc:00:00:01", "2026-06-19T00:01:00Z"),
            ],
            &assignments,
            Some(&anomaly),
            at("2026-06-19T00:01:00Z"),
        );

        // No new-MAC event was opened against the victim: reflection is not a claim.
        let new_macs = new_mac_events(&anomaly, "2026-06-19T00:01:00Z");
        assert!(new_macs.is_empty(), "a reflected frame must not open a victim new-MAC event");
        // The victim's live conflict flag did not latch (reflector not added to it).
        let snap = store.snapshot();
        assert!(!neighbor(&snap, "2001:db8::victim").conflict, "victim conflict flag must not latch");

        // Exactly one reflection event, attributed to the reflector's participant.
        let sweeps = sweep_events(&anomaly, "2026-06-19T00:01:00Z");
        assert_eq!(sweeps.len(), 1, "one rolled-up reflection event");
        let e = &sweeps[0];
        assert_eq!(e.classification.as_deref(), Some("reflection"));
        assert_eq!(e.new_mac, "0a:00:05:18:9d:49", "keyed on the reflector MAC");
        assert_eq!(e.asn, Some(26415), "attributed to the reflector, not the victim");
        assert_eq!(e.claimed_ips, vec!["2001:db8::victim"], "victim IP listed as reflected");
    }

    #[test]
    fn multiple_victims_roll_into_one_reflection_event() {
        use crate::anomaly::AnomalyStore;
        let anomaly = AnomalyStore::open(std::path::Path::new(":memory:"), 600).unwrap();
        let mut store = DiscoveredNeighborStore::load(None).with_max_ips_per_mac(8);
        let assignments = vec![
            assign("2001:db8::v1", 64500, "Acme"),
            assign("2001:db8::v2", 64501, "Globex"),
            assign("2001:db8::reflector", 26415, "Verisign"),
        ];
        // Establish the two victims' real MACs and the reflector's own identity.
        store.update_at(
            &[
                obs("2001:db8::v1", "aa:bb:cc:00:00:01", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"),
                obs("2001:db8::v2", "aa:bb:cc:00:00:02", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"),
                obs("2001:db8::reflector", "0a:00:05:18:9d:49", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z"),
            ],
            &assignments,
            Some(&anomaly),
            at("2026-06-19T00:00:00Z"),
        );
        // The reflector re-floods both victims' frames in one poll.
        store.update_at(
            &[
                obs("2001:db8::reflector", "0a:00:05:18:9d:49", "2026-06-19T00:01:00Z", "2026-06-19T00:01:00Z"),
                refl_obs("2001:db8::v1", "0a:00:05:18:9d:49", "aa:bb:cc:00:00:01", "2026-06-19T00:01:00Z"),
                refl_obs("2001:db8::v2", "0a:00:05:18:9d:49", "aa:bb:cc:00:00:02", "2026-06-19T00:01:00Z"),
            ],
            &assignments,
            Some(&anomaly),
            at("2026-06-19T00:01:00Z"),
        );
        // One reflection event listing both victims — not a cross-tenant sweep alarm.
        let sweeps = sweep_events(&anomaly, "2026-06-19T00:01:00Z");
        assert_eq!(sweeps.len(), 1);
        assert_eq!(sweeps[0].classification.as_deref(), Some("reflection"));
        assert_eq!(sweeps[0].claimed_ips, vec!["2001:db8::v1", "2001:db8::v2"]);
        assert!(new_mac_events(&anomaly, "2026-06-19T00:01:00Z").is_empty());
    }

    #[test]
    fn forged_link_layer_option_is_not_a_reflection() {
        use crate::anomaly::AnomalyStore;
        let anomaly = AnomalyStore::open(std::path::Path::new(":memory:"), 600).unwrap();
        let mut store = DiscoveredNeighborStore::load(None).with_max_ips_per_mac(8);
        let assignments = vec![assign("2001:db8::victim", 64500, "Acme")];
        // Establish the victim's real MAC.
        store.update_at(
            &[obs("2001:db8::victim", "aa:bb:cc:00:00:01", "2026-06-19T00:00:00Z", "2026-06-19T00:00:00Z")],
            &assignments,
            Some(&anomaly),
            at("2026-06-19T00:00:00Z"),
        );
        // A frame whose option names a MAC that was NEVER an owner of this IP is a
        // forged/crafted option, not verbatim reflection — it must fall through to
        // normal new-MAC handling, opening a conflict with no reflection tag.
        store.update_at(
            &[refl_obs("2001:db8::victim", "de:ad:be:ef:00:01", "de:ad:be:ef:99:99", "2026-06-19T00:01:00Z")],
            &assignments,
            Some(&anomaly),
            at("2026-06-19T00:01:00Z"),
        );
        assert!(sweep_events(&anomaly, "2026-06-19T00:01:00Z").is_empty(), "forged option is not a reflection");
        let new_macs = new_mac_events(&anomaly, "2026-06-19T00:01:00Z");
        assert_eq!(new_macs.len(), 1, "forged option falls through to a normal new-MAC event");
        assert_eq!(new_macs[0].classification, None);
        assert_eq!(new_macs[0].new_mac, "de:ad:be:ef:00:01");
    }

    #[test]
    fn fetch_failure_retains_data() {
        let mut store = DiscoveredNeighborStore::load(None);
        store.update_at(
            &[obs("10.0.0.1", "aa:aa", "2026-06-18T00:00:00Z", "2026-06-18T00:00:00Z")],
            &[assign("10.0.0.1", 64500, "Acme")],
            None,
            at("2026-06-18T00:00:00Z"),
        );
        store.set_error("connection refused");
        let snap = store.snapshot();
        assert_eq!(snap.neighbors.len(), 1);
        assert_eq!(snap.last_error.as_deref(), Some("connection refused"));
    }
}
