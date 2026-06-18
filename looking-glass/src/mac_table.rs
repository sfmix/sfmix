//! Persistent MAC-table store.
//!
//! The background poller rebuilds device state from scratch every cycle, but the
//! MAC table is special: we want to remember *when* each (vlan, mac, interface)
//! was first and last observed, keep that across process restarts, and serve the
//! last-known table for a device that is unreachable right after a restart.
//!
//! Rather than layering a separate history alongside the ephemeral cache, this
//! store is the source of truth for MAC data. Each poll feeds observed entries
//! through [`MacTableStore::update`], which stamps `first_seen`/`last_seen` onto
//! the live [`MacEntry`]s and persists the result. Keying on the interface means
//! a MAC that moves to a different port is a new entry with a fresh `first_seen`.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::structured::{DeviceStateCache, MacEntry};

/// Identity of a learned MAC. Interface is part of the key so a MAC seen on a
/// new port counts as a new sighting (fresh `first_seen`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MacKey {
    vlan: String,
    mac_address: String,
    interface: String,
}

impl MacKey {
    fn of(entry: &MacEntry) -> Self {
        Self {
            vlan: entry.vlan.clone(),
            mac_address: entry.mac_address.clone(),
            interface: entry.interface.clone(),
        }
    }
}

/// On-disk form: device → its known MAC entries. `MacEntry` already carries the
/// key fields plus the timestamps, so a flat list round-trips cleanly.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedStore {
    entries: HashMap<String, Vec<MacEntry>>,
}

/// In-memory MAC-table store, owned by the poller task (no shared locking).
pub struct MacTableStore {
    /// Where to persist. `None` keeps the store in-memory only.
    path: Option<PathBuf>,
    /// Drop entries not seen within this many seconds. 0 disables pruning.
    retention_secs: i64,
    /// device → key → entry (with `first_seen`/`last_seen` populated).
    entries: HashMap<String, HashMap<MacKey, MacEntry>>,
}

impl MacTableStore {
    /// Load the store from disk. Returns an empty store if the path is unset,
    /// the file is missing, or it fails to parse (warn-and-continue).
    pub fn load(path: Option<PathBuf>, retention_secs: i64) -> Self {
        let mut store = Self { path, retention_secs, entries: HashMap::new() };
        let Some(path) = store.path.clone() else { return store };
        match std::fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<PersistedStore>(&contents) {
                Ok(persisted) => {
                    let mut total = 0;
                    for (device, list) in persisted.entries {
                        let map: HashMap<MacKey, MacEntry> =
                            list.into_iter().map(|e| (MacKey::of(&e), e)).collect();
                        total += map.len();
                        store.entries.insert(device, map);
                    }
                    info!("Loaded MAC-table store from {} ({total} entries)", path.display());
                }
                Err(e) => warn!("Failed to parse MAC-table store {}: {e}", path.display()),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!("No MAC-table store at {}, starting fresh", path.display());
            }
            Err(e) => warn!("Failed to read MAC-table store {}: {e}", path.display()),
        }
        store
    }

    /// Fold a fresh poll into the store, stamping timestamps onto the live cache.
    pub fn update(&mut self, fresh: &mut HashMap<String, DeviceStateCache>) {
        self.update_at(fresh, Utc::now());
    }

    /// Testable core of [`update`] with an injected clock.
    fn update_at(&mut self, fresh: &mut HashMap<String, DeviceStateCache>, now: DateTime<Utc>) {
        // Prune first so expired entries are never served as stale data below.
        self.prune(now);
        let now_str = now.to_rfc3339();
        for (device, cache) in fresh.iter_mut() {
            let dev_map = self.entries.entry(device.clone()).or_default();
            if cache.mac_at.is_some() {
                // Successful poll: stamp each observed entry, preserving the
                // original first_seen for keys we already know.
                for entry in cache.mac_table.iter_mut() {
                    let key = MacKey::of(entry);
                    entry.first_seen = dev_map
                        .get(&key)
                        .map(|prev| prev.first_seen.clone())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| now_str.clone());
                    entry.last_seen = now_str.clone();
                    dev_map.insert(key, entry.clone());
                }
            } else {
                // Failed poll: serve the last-known entries as stale data. Leave
                // mac_at as None so downstream staleness reporting stays honest.
                let mut stale: Vec<MacEntry> = dev_map.values().cloned().collect();
                stale.sort_by(|a, b| a.mac_address.cmp(&b.mac_address));
                cache.mac_table = stale;
            }
        }
    }

    /// Drop entries whose `last_seen` is older than the retention window. This
    /// also gives flap tolerance: a MAC absent for a poll or two keeps its
    /// first_seen if it returns within the window.
    fn prune(&mut self, now: DateTime<Utc>) {
        if self.retention_secs <= 0 {
            return;
        }
        let cutoff = now - Duration::seconds(self.retention_secs);
        for dev_map in self.entries.values_mut() {
            dev_map.retain(|_, e| match DateTime::parse_from_rfc3339(&e.last_seen) {
                Ok(seen) => seen.with_timezone(&Utc) >= cutoff,
                Err(_) => true, // keep unparseable timestamps rather than lose data
            });
        }
        self.entries.retain(|_, dev_map| !dev_map.is_empty());
    }

    /// Persist the store to disk (atomic write via temp file + rename). No-op
    /// when no path is configured.
    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating MAC-table store directory {}", parent.display()))?;
        }
        let persisted = PersistedStore {
            entries: self
                .entries
                .iter()
                .map(|(dev, map)| (dev.clone(), map.values().cloned().collect()))
                .collect(),
        };
        let tmp = path.with_extension("tmp");
        let json = serde_json::to_string_pretty(&persisted).context("serializing MAC-table store")?;
        std::fs::write(&tmp, &json)
            .with_context(|| format!("writing temp store file {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(vlan: &str, mac: &str, iface: &str) -> MacEntry {
        MacEntry {
            vlan: vlan.to_string(),
            mac_address: mac.to_string(),
            entry_type: "dynamic".to_string(),
            interface: iface.to_string(),
            ..Default::default()
        }
    }

    fn polled(entries: Vec<MacEntry>) -> DeviceStateCache {
        DeviceStateCache {
            mac_table: entries,
            mac_at: Some(std::time::Instant::now()),
            ..Default::default()
        }
    }

    fn failed() -> DeviceStateCache {
        DeviceStateCache { mac_at: None, ..Default::default() }
    }

    fn fresh(device: &str, cache: DeviceStateCache) -> HashMap<String, DeviceStateCache> {
        HashMap::from([(device.to_string(), cache)])
    }

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn new_mac_gets_equal_first_and_last_seen() {
        let mut store = MacTableStore::load(None, 0);
        let mut f = fresh("sw1", polled(vec![mac("100", "aa:aa", "Et1")]));
        store.update_at(&mut f, t("2026-06-18T00:00:00Z"));

        let e = &f["sw1"].mac_table[0];
        assert_eq!(e.first_seen, "2026-06-18T00:00:00+00:00");
        assert_eq!(e.last_seen, "2026-06-18T00:00:00+00:00");
    }

    #[test]
    fn reobserved_mac_keeps_first_seen_advances_last_seen() {
        let mut store = MacTableStore::load(None, 0);
        let mut f1 = fresh("sw1", polled(vec![mac("100", "aa:aa", "Et1")]));
        store.update_at(&mut f1, t("2026-06-18T00:00:00Z"));

        let mut f2 = fresh("sw1", polled(vec![mac("100", "aa:aa", "Et1")]));
        store.update_at(&mut f2, t("2026-06-18T01:00:00Z"));

        let e = &f2["sw1"].mac_table[0];
        assert_eq!(e.first_seen, "2026-06-18T00:00:00+00:00");
        assert_eq!(e.last_seen, "2026-06-18T01:00:00+00:00");
    }

    #[test]
    fn mac_moving_interface_gets_fresh_first_seen() {
        let mut store = MacTableStore::load(None, 0);
        let mut f1 = fresh("sw1", polled(vec![mac("100", "aa:aa", "Et1")]));
        store.update_at(&mut f1, t("2026-06-18T00:00:00Z"));

        let mut f2 = fresh("sw1", polled(vec![mac("100", "aa:aa", "Et2")]));
        store.update_at(&mut f2, t("2026-06-18T01:00:00Z"));

        let e = &f2["sw1"].mac_table[0];
        assert_eq!(e.interface, "Et2");
        assert_eq!(e.first_seen, "2026-06-18T01:00:00+00:00");
        assert_eq!(e.last_seen, "2026-06-18T01:00:00+00:00");
    }

    #[test]
    fn failed_poll_serves_last_known_entries() {
        let mut store = MacTableStore::load(None, 0);
        let mut f1 = fresh("sw1", polled(vec![mac("100", "aa:aa", "Et1")]));
        store.update_at(&mut f1, t("2026-06-18T00:00:00Z"));

        let mut f2 = fresh("sw1", failed());
        store.update_at(&mut f2, t("2026-06-18T00:01:00Z"));

        let table = &f2["sw1"].mac_table;
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].mac_address, "aa:aa");
        assert_eq!(table[0].first_seen, "2026-06-18T00:00:00+00:00");
        assert!(f2["sw1"].mac_at.is_none()); // still flagged stale
    }

    #[test]
    fn entries_past_retention_are_pruned() {
        let mut store = MacTableStore::load(None, 3600); // 1h retention
        let mut f1 = fresh("sw1", polled(vec![mac("100", "aa:aa", "Et1")]));
        store.update_at(&mut f1, t("2026-06-18T00:00:00Z"));

        // Two hours later, the MAC is gone; a failed poll should now serve nothing.
        let mut f2 = fresh("sw1", failed());
        store.update_at(&mut f2, t("2026-06-18T02:00:00Z"));

        assert!(f2["sw1"].mac_table.is_empty());
    }
}
