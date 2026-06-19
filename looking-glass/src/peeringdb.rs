use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const PEERINGDB_API_BASE: &str = "https://www.peeringdb.com/api/net";
const BATCH_SIZE: usize = 150;
const INTER_BATCH_DELAY_SECS: u64 = 2;
const USER_AGENT: &str = "sfmix-looking-glass/0.1";

/// Cached PeeringDB network record (subset of /api/net fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeeringdbNetwork {
    pub asn: u32,
    pub name: String,
    pub website: String,
    pub irr_as_set: String,
    pub info_type: String,
    pub policy_general: String,
    pub info_prefixes4: u32,
    pub info_prefixes6: u32,
    /// True if the network declares it never peers via route servers.
    /// `serde(default)` keeps older on-disk caches (written before this field
    /// existed) loadable; they read back as `false` until the next refresh.
    #[serde(default)]
    pub info_never_via_route_servers: bool,
    /// When this entry was fetched (RFC 3339).
    pub fetched_at: String,
}

/// The full cache: ASN → PeeringdbNetwork, with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeeringdbCache {
    /// When the cache was last successfully refreshed (RFC 3339).
    pub last_refresh: Option<String>,
    pub networks: HashMap<u32, PeeringdbNetwork>,
}

impl PeeringdbCache {
    pub fn empty() -> Self {
        Self {
            last_refresh: None,
            networks: HashMap::new(),
        }
    }
}

impl Default for PeeringdbCache {
    fn default() -> Self {
        Self::empty()
    }
}

/// Load a PeeringDB cache from a JSON file. Returns empty cache if file doesn't exist.
pub fn load_cache(path: &Path) -> PeeringdbCache {
    match std::fs::read_to_string(path) {
        Ok(contents) => match serde_json::from_str(&contents) {
            Ok(cache) => {
                info!("Loaded PeeringDB cache from {} ({} entries)", path.display(), cache_len(&cache));
                cache
            }
            Err(e) => {
                warn!("Failed to parse PeeringDB cache {}: {e}", path.display());
                PeeringdbCache::empty()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("No PeeringDB cache file at {}, starting fresh", path.display());
            PeeringdbCache::empty()
        }
        Err(e) => {
            warn!("Failed to read PeeringDB cache {}: {e}", path.display());
            PeeringdbCache::empty()
        }
    }
}

fn cache_len(cache: &PeeringdbCache) -> usize {
    cache.networks.len()
}

/// Save a PeeringDB cache to a JSON file (atomic write via temp file + rename).
fn save_cache(cache: &PeeringdbCache, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating cache directory {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    let json = serde_json::to_string_pretty(cache)
        .context("serializing PeeringDB cache")?;
    std::fs::write(&tmp, &json)
        .with_context(|| format!("writing temp cache file {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Refresh the PeeringDB cache: fetch missing/stale entries, prune departed ASNs.
///
/// Returns the updated cache. On fetch failure, returns the original cache
/// with stale data intact (graceful degradation).
pub async fn refresh_cache(
    current: &PeeringdbCache,
    participant_asns: &[u32],
    ttl_secs: u64,
    cache_file: &Path,
) -> PeeringdbCache {
    let now = Utc::now();
    let cutoff = now - chrono::Duration::seconds(ttl_secs as i64);

    // Collect ASNs needing refresh
    let stale_asns: Vec<u32> = participant_asns
        .iter()
        .filter(|&&asn| {
            match current.networks.get(&asn) {
                None => true,
                Some(entry) => {
                    chrono::DateTime::parse_from_rfc3339(&entry.fetched_at)
                        .map(|t| t < cutoff)
                        .unwrap_or(true)
                }
            }
        })
        .copied()
        .collect();

    if stale_asns.is_empty() {
        // Prune only — no fetch needed
        let mut cache = current.clone();
        let before = cache.networks.len();
        let asn_set: std::collections::HashSet<u32> = participant_asns.iter().copied().collect();
        cache.networks.retain(|asn, _| asn_set.contains(asn));
        if cache.networks.len() < before {
            info!("PeeringDB: pruned {} departed ASNs", before - cache.networks.len());
        }
        if let Err(e) = save_cache(&cache, cache_file) {
            warn!("Failed to save PeeringDB cache: {e}");
        }
        return cache;
    }

    info!("PeeringDB: refreshing {} ASNs ({} total participants)",
        stale_asns.len(), participant_asns.len());

    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    let mut merged = current.clone();
    let now_str = now.to_rfc3339();
    let mut fetched_asns = std::collections::HashSet::new();

    for (i, chunk) in stale_asns.chunks(BATCH_SIZE).enumerate() {
        if i > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(INTER_BATCH_DELAY_SECS)).await;
        }

        let csv: String = chunk.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",");
        let url = format!("{}?asn__in={}", PEERINGDB_API_BASE, csv);

        match fetch_batch(&client, &url).await {
            Ok(networks) => {
                for net in networks {
                    fetched_asns.insert(net.asn);
                    merged.networks.insert(net.asn, PeeringdbNetwork {
                        asn: net.asn,
                        name: net.name,
                        website: net.website,
                        irr_as_set: net.irr_as_set,
                        info_type: net.info_type,
                        policy_general: net.policy_general,
                        info_prefixes4: net.info_prefixes4,
                        info_prefixes6: net.info_prefixes6,
                        info_never_via_route_servers: net.info_never_via_route_servers,
                        fetched_at: now_str.clone(),
                    });
                }
            }
            Err(e) => {
                warn!("PeeringDB batch fetch failed: {e}");
                // Graceful degradation: keep stale data
                return merged;
            }
        }
    }

    // Store tombstones for ASNs not returned by PeeringDB (private networks)
    for &asn in &stale_asns {
        if !fetched_asns.contains(&asn) && !merged.networks.contains_key(&asn) {
            merged.networks.insert(asn, PeeringdbNetwork {
                asn,
                name: String::new(),
                website: String::new(),
                irr_as_set: String::new(),
                info_type: String::new(),
                policy_general: String::new(),
                info_prefixes4: 0,
                info_prefixes6: 0,
                info_never_via_route_servers: false,
                fetched_at: now_str.clone(),
            });
        }
    }

    // Prune ASNs no longer in participant list
    let asn_set: std::collections::HashSet<u32> = participant_asns.iter().copied().collect();
    merged.networks.retain(|asn, _| asn_set.contains(asn));

    merged.last_refresh = Some(now_str);

    info!("PeeringDB: cache now has {} entries (fetched {}, total participants {})",
        merged.networks.len(), fetched_asns.len(), participant_asns.len());

    if let Err(e) = save_cache(&merged, cache_file) {
        warn!("Failed to save PeeringDB cache: {e}");
    }

    merged
}

/// PeeringDB API response wrapper.
#[derive(Debug, Deserialize)]
struct PeeringdbApiResponse {
    data: Vec<PeeringdbApiNetwork>,
}

/// A single network record from the PeeringDB API.
#[derive(Debug, Deserialize)]
struct PeeringdbApiNetwork {
    #[serde(default)]
    asn: u32,
    #[serde(default)]
    name: String,
    #[serde(default)]
    website: String,
    #[serde(default)]
    irr_as_set: String,
    #[serde(default)]
    info_type: String,
    #[serde(default)]
    policy_general: String,
    #[serde(default, deserialize_with = "null_as_zero")]
    info_prefixes4: u32,
    #[serde(default, deserialize_with = "null_as_zero")]
    info_prefixes6: u32,
    #[serde(default)]
    info_never_via_route_servers: bool,
}

fn null_as_zero<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    Option::<u32>::deserialize(d).map(|o| o.unwrap_or(0))
}

async fn fetch_batch(client: &reqwest::Client, url: &str) -> Result<Vec<PeeringdbApiNetwork>> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("requesting {url}"))?;

    if !resp.status().is_success() {
        anyhow::bail!("PeeringDB returned HTTP {}", resp.status());
    }

    let body: PeeringdbApiResponse = resp
        .json()
        .await
        .context("parsing PeeringDB response")?;

    Ok(body.data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache_roundtrip() {
        let cache = PeeringdbCache::empty();
        let json = serde_json::to_string(&cache).unwrap();
        let parsed: PeeringdbCache = serde_json::from_str(&json).unwrap();
        assert!(parsed.networks.is_empty());
        assert!(parsed.last_refresh.is_none());
    }

    #[test]
    fn cache_with_entries_roundtrip() {
        let mut cache = PeeringdbCache::empty();
        cache.networks.insert(6939, PeeringdbNetwork {
            asn: 6939,
            name: "Hurricane Electric".to_string(),
            website: "https://he.net".to_string(),
            irr_as_set: "AS-HURRICANE".to_string(),
            info_type: "NSP".to_string(),
            policy_general: "Open".to_string(),
            info_prefixes4: 200000,
            info_prefixes6: 100000,
            info_never_via_route_servers: true,
            fetched_at: "2026-06-08T00:00:00+00:00".to_string(),
        });
        cache.last_refresh = Some("2026-06-08T00:00:00+00:00".to_string());

        let json = serde_json::to_string(&cache).unwrap();
        let parsed: PeeringdbCache = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.networks.len(), 1);
        assert_eq!(parsed.networks[&6939].website, "https://he.net");
        assert!(parsed.networks[&6939].info_never_via_route_servers);
    }

    #[test]
    fn legacy_cache_without_flag_loads_as_false() {
        // An on-disk entry written before info_never_via_route_servers existed
        // must still deserialize, defaulting the missing flag to false.
        let json = r#"{
            "last_refresh": null,
            "networks": {
                "6939": {
                    "asn": 6939, "name": "HE", "website": "", "irr_as_set": "",
                    "info_type": "", "policy_general": "",
                    "info_prefixes4": 0, "info_prefixes6": 0,
                    "fetched_at": "2026-06-08T00:00:00+00:00"
                }
            }
        }"#;
        let parsed: PeeringdbCache = serde_json::from_str(json).unwrap();
        assert!(!parsed.networks[&6939].info_never_via_route_servers);
    }

    #[test]
    fn load_nonexistent_file() {
        let cache = load_cache(Path::new("/tmp/nonexistent-peeringdb-cache.json"));
        assert!(cache.networks.is_empty());
    }

    #[test]
    fn save_and_load_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peeringdb-cache.json");

        let mut cache = PeeringdbCache::empty();
        cache.networks.insert(13335, PeeringdbNetwork {
            asn: 13335,
            name: "Cloudflare".to_string(),
            website: "https://cloudflare.com".to_string(),
            irr_as_set: "AS-CLOUDFLARE".to_string(),
            info_type: "Content".to_string(),
            policy_general: "Open".to_string(),
            info_prefixes4: 3000,
            info_prefixes6: 1000,
            info_never_via_route_servers: false,
            fetched_at: "2026-06-08T12:00:00+00:00".to_string(),
        });
        cache.last_refresh = Some("2026-06-08T12:00:00+00:00".to_string());

        save_cache(&cache, &path).unwrap();
        let loaded = load_cache(&path);
        assert_eq!(loaded.networks.len(), 1);
        assert_eq!(loaded.networks[&13335].name, "Cloudflare");
    }

    #[tokio::test]
    async fn refresh_prunes_departed_asns() {
        let mut cache = PeeringdbCache::empty();
        // Entry for ASN that's no longer a participant
        cache.networks.insert(99999, PeeringdbNetwork {
            asn: 99999,
            name: "Gone Network".to_string(),
            website: String::new(),
            irr_as_set: String::new(),
            info_type: String::new(),
            policy_general: String::new(),
            info_prefixes4: 0,
            info_prefixes6: 0,
            info_never_via_route_servers: false,
            fetched_at: Utc::now().to_rfc3339(),
        });
        // Fresh entry for current participant
        cache.networks.insert(6939, PeeringdbNetwork {
            asn: 6939,
            name: "Hurricane Electric".to_string(),
            website: "https://he.net".to_string(),
            irr_as_set: String::new(),
            info_type: String::new(),
            policy_general: String::new(),
            info_prefixes4: 0,
            info_prefixes6: 0,
            info_never_via_route_servers: false,
            fetched_at: Utc::now().to_rfc3339(),
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-cache.json");

        // Only 6939 is still a participant
        let result = refresh_cache(&cache, &[6939], 86400, &path).await;
        assert!(result.networks.contains_key(&6939));
        assert!(!result.networks.contains_key(&99999));
    }
}
