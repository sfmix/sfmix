//! bgplgd (OpenBGPD) HTTP API client.
//!
//! Implements the `BgpSource` trait for bgplgd instances.
//!
//! API base: e.g. `http://mgmt.rs-openbsd.sfmix.org/api/`
//! Key endpoints:
//!   GET /neighbors                          → {neighbors: [...]}
//!   GET /rib?neighbor=<addr>                → {rib: [...]}  (all routes)
//!   GET /rib?neighbor=<addr>&filtered=1     → {rib: [...]}  (filtered)
//!   GET /rib?prefix=<cidr>                  → {rib: [...]}  (prefix lookup)

use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use crate::structured::{BgpRoute, BgpSourceNeighbor, BgpSourceStatus};
use super::BgpSource;

pub struct BgplgdSource {
    name: String,
    display_name: String,
    api_base: String,
    client: Client,
}

impl BgplgdSource {
    pub fn new(name: String, display_name: String, api_base: String) -> Self {
        let api_base = api_base.trim_end_matches('/').to_string();
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self { name, display_name, api_base, client }
    }

    async fn fetch_rib(&self, query: &str) -> Result<Vec<BgpRoute>> {
        let url = format!("{}/rib?{}", self.api_base, query);
        let resp: BgplgdRibResponse = self.client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("bgplgd request to {url} failed"))?
            .json()
            .await
            .with_context(|| format!("bgplgd JSON parse for {url} failed"))?;
        Ok(resp.rib.into_iter().map(|r| self.normalize_route(r)).collect())
    }

    fn normalize_route(&self, r: BgplgdRoute) -> BgpRoute {
        let as_path: Vec<u32> = r.aspath
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();

        BgpRoute {
            prefix: r.prefix,
            next_hop: r.exit_nexthop,
            as_path,
            origin: r.origin.unwrap_or_default(),
            med: if r.metric > 0 { Some(r.metric) } else { None },
            local_pref: if r.localpref > 0 { Some(r.localpref) } else { None },
            communities: r.communities.unwrap_or_default(),
            large_communities: r.large_communities.unwrap_or_default(),
            age: r.last_update.unwrap_or_default(),
            source_name: self.name.clone(),
            primary: r.best.unwrap_or(false),
            ovs: r.ovs,
        }
    }
}

#[async_trait]
impl BgpSource for BgplgdSource {
    fn name(&self) -> &str { &self.name }
    fn display_name(&self) -> &str { &self.display_name }
    fn source_type(&self) -> &str { "bgplgd" }

    async fn status(&self) -> Result<BgpSourceStatus> {
        let neighbors = self.neighbors().await.unwrap_or_default();
        Ok(BgpSourceStatus {
            name: self.name.clone(),
            display_name: self.display_name.clone(),
            source_type: "bgplgd".to_string(),
            router_id: String::new(),
            version: String::new(),
            neighbor_count: neighbors.len() as u32,
            last_refresh: None,
            error: None,
        })
    }

    async fn neighbors(&self) -> Result<Vec<BgpSourceNeighbor>> {
        let url = format!("{}/neighbors", self.api_base);
        let resp: BgplgdNeighborsResponse = self.client
            .get(&url)
            .send()
            .await
            .context("bgplgd neighbors request failed")?
            .json()
            .await
            .context("bgplgd neighbors JSON parse failed")?;

        let mut neighbors: Vec<BgpSourceNeighbor> = resp.neighbors.into_iter().map(|n| {
            let state = n.state.clone();
            BgpSourceNeighbor {
                address: n.remote_addr,
                remote_as: n.remote_as.parse().unwrap_or(0),
                description: n.description.unwrap_or_default(),
                state,
                uptime: n.last_updown.unwrap_or_default(),
                prefixes_received: n.stats.as_ref()
                    .and_then(|s| s.prefixes.as_ref())
                    .map(|p| p.received)
                    .unwrap_or(0),
                prefixes_sent: n.stats.as_ref()
                    .and_then(|s| s.prefixes.as_ref())
                    .map(|p| p.sent)
                    .unwrap_or(0),
            }
        }).collect();
        neighbors.sort_by(|a, b| a.address.cmp(&b.address));
        Ok(neighbors)
    }

    async fn routes_accepted(&self, neighbor: &str) -> Result<Vec<BgpRoute>> {
        self.fetch_rib(&format!("neighbor={neighbor}")).await
    }

    async fn routes_filtered(&self, neighbor: &str) -> Result<Vec<BgpRoute>> {
        self.fetch_rib(&format!("neighbor={neighbor}&filtered=1")).await
    }

    async fn routes_noexport(&self, _neighbor: &str) -> Result<Vec<BgpRoute>> {
        // bgplgd does not track not-exported routes
        Ok(Vec::new())
    }

    async fn route_lookup(&self, prefix: &str) -> Result<Vec<BgpRoute>> {
        self.fetch_rib(&format!("prefix={prefix}")).await
    }
}

// ── bgplgd JSON response types ──────────────────────────────────

#[derive(Deserialize)]
struct BgplgdNeighborsResponse {
    neighbors: Vec<BgplgdNeighbor>,
}

#[derive(Deserialize)]
struct BgplgdNeighbor {
    remote_as: String,
    remote_addr: String,
    #[serde(default)]
    description: Option<String>,
    state: String,
    #[serde(default)]
    last_updown: Option<String>,
    #[serde(default)]
    stats: Option<BgplgdStats>,
}

#[derive(Deserialize)]
struct BgplgdStats {
    #[serde(default)]
    prefixes: Option<BgplgdPrefixStats>,
}

#[derive(Deserialize)]
struct BgplgdPrefixStats {
    #[serde(default)]
    sent: u32,
    #[serde(default)]
    received: u32,
}

#[derive(Deserialize)]
struct BgplgdRibResponse {
    #[serde(default)]
    rib: Vec<BgplgdRoute>,
}

#[derive(Deserialize)]
struct BgplgdRoute {
    prefix: String,
    #[serde(default)]
    aspath: String,
    #[serde(default)]
    exit_nexthop: String,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    metric: u32,
    #[serde(default)]
    localpref: u32,
    #[serde(default)]
    communities: Option<Vec<String>>,
    #[serde(default)]
    large_communities: Option<Vec<String>>,
    #[serde(default)]
    last_update: Option<String>,
    #[serde(default)]
    best: Option<bool>,
    #[serde(default)]
    ovs: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_bgplgd_route() {
        let source = BgplgdSource::new(
            "test".to_string(),
            "Test".to_string(),
            "http://localhost/api".to_string(),
        );
        let raw = BgplgdRoute {
            prefix: "38.111.220.0/24".to_string(),
            aspath: "10111".to_string(),
            exit_nexthop: "206.197.187.86".to_string(),
            origin: Some("IGP".to_string()),
            metric: 0,
            localpref: 100,
            communities: Some(vec!["64512:11".to_string(), "64512:21".to_string()]),
            large_communities: Some(vec!["63055:1000:2".to_string()]),
            last_update: Some("6d00h01m".to_string()),
            best: Some(true),
            ovs: Some("not-found".to_string()),
        };
        let route = source.normalize_route(raw);
        assert_eq!(route.prefix, "38.111.220.0/24");
        assert_eq!(route.as_path, vec![10111]);
        assert_eq!(route.local_pref, Some(100));
        assert_eq!(route.communities, vec!["64512:11", "64512:21"]);
        assert!(route.primary);
        assert_eq!(route.ovs, Some("not-found".to_string()));
    }

    #[test]
    fn normalize_empty_aspath() {
        let source = BgplgdSource::new(
            "test".to_string(),
            "Test".to_string(),
            "http://localhost/api".to_string(),
        );
        let raw = BgplgdRoute {
            prefix: "10.0.0.0/8".to_string(),
            aspath: String::new(),
            exit_nexthop: "0.0.0.0".to_string(),
            origin: None,
            metric: 0,
            localpref: 0,
            communities: None,
            large_communities: None,
            last_update: None,
            best: None,
            ovs: None,
        };
        let route = source.normalize_route(raw);
        assert!(route.as_path.is_empty());
        assert_eq!(route.local_pref, None);
        assert!(!route.primary);
    }
}
