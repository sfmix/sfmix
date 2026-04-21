//! BIRDWatcher HTTP API client.
//!
//! Implements the `BgpSource` trait for BIRDWatcher instances
//! (JSON API for BIRD routing daemon).
//!
//! API base: e.g. `http://mgmt.rs-linux.sfmix.org:29184/`
//! Key endpoints:
//!   GET /status                      → {status: {router_id, version, ...}}
//!   GET /protocols/bgp               → {protocols: {<name>: {neighbor_address, ...}}}
//!   GET /routes/protocol/<name>      → {routes: [...]}  (accepted)
//!   GET /routes/filtered/<name>      → {routes: [...]}  (filtered)
//!   GET /routes/noexport/<name>      → {routes: [...]}  (not-exported)
//!   GET /routes/prefix?prefix=<cidr> → {routes: [...]}  (prefix lookup)

use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

use crate::structured::{BgpRoute, BgpSourceNeighbor, BgpSourceStatus};
use super::BgpSource;

pub struct BirdwatcherSource {
    name: String,
    display_name: String,
    api_base: String,
    client: Client,
}

impl BirdwatcherSource {
    pub fn new(name: String, display_name: String, api_base: String) -> Self {
        let api_base = api_base.trim_end_matches('/').to_string();
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self { name, display_name, api_base, client }
    }

    /// Resolve a neighbor address to its BIRD protocol name.
    /// BIRDWatcher indexes routes by protocol name, not by neighbor IP.
    async fn resolve_protocol_name(&self, neighbor_addr: &str) -> Result<String> {
        let protocols = self.fetch_protocols().await?;
        for (proto_name, proto) in &protocols {
            if proto.neighbor_address == neighbor_addr {
                return Ok(proto_name.clone());
            }
        }
        anyhow::bail!("no protocol found for neighbor {neighbor_addr}");
    }

    async fn fetch_protocols(&self) -> Result<HashMap<String, BwProtocol>> {
        let url = format!("{}/protocols/bgp", self.api_base);
        let resp: BwProtocolsResponse = self.client
            .get(&url)
            .send()
            .await
            .context("BIRDWatcher protocols request failed")?
            .json()
            .await
            .context("BIRDWatcher protocols JSON parse failed")?;
        Ok(resp.protocols)
    }

    async fn fetch_routes(&self, path: &str) -> Result<Vec<BgpRoute>> {
        let url = format!("{}{}", self.api_base, path);
        let resp: BwRoutesResponse = self.client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("BIRDWatcher request to {path} failed"))?
            .json()
            .await
            .with_context(|| format!("BIRDWatcher JSON parse for {path} failed"))?;
        Ok(resp.routes.into_iter().map(|r| self.normalize_route(r)).collect())
    }

    fn normalize_route(&self, r: BwRoute) -> BgpRoute {
        let as_path = r.bgp.as_path.unwrap_or_default();
        let communities = r.bgp.communities.unwrap_or_default()
            .into_iter()
            .map(|pair| {
                if pair.len() == 2 { format!("{}:{}", pair[0], pair[1]) }
                else { format!("{:?}", pair) }
            })
            .collect();
        let large_communities = r.bgp.large_communities.unwrap_or_default()
            .into_iter()
            .map(|triple| {
                if triple.len() == 3 { format!("{}:{}:{}", triple[0], triple[1], triple[2]) }
                else { format!("{:?}", triple) }
            })
            .collect();
        let local_pref = r.bgp.local_pref
            .and_then(|v| v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64().map(|n| n as u32)));

        BgpRoute {
            prefix: r.network,
            next_hop: r.bgp.next_hop.unwrap_or_default(),
            as_path,
            origin: r.bgp.origin.unwrap_or_default(),
            med: None,
            local_pref,
            communities,
            large_communities,
            age: r.age.unwrap_or_default(),
            source_name: self.name.clone(),
            primary: r.primary.unwrap_or(false),
            ovs: None,
        }
    }
}

#[async_trait]
impl BgpSource for BirdwatcherSource {
    fn name(&self) -> &str { &self.name }
    fn display_name(&self) -> &str { &self.display_name }
    fn source_type(&self) -> &str { "birdwatcher" }

    async fn status(&self) -> Result<BgpSourceStatus> {
        let url = format!("{}/status", self.api_base);
        let resp: BwStatusResponse = self.client
            .get(&url)
            .send()
            .await
            .context("BIRDWatcher status request failed")?
            .json()
            .await
            .context("BIRDWatcher status JSON parse failed")?;

        let protocols = self.fetch_protocols().await.unwrap_or_default();
        let neighbor_count = protocols.len() as u32;

        Ok(BgpSourceStatus {
            name: self.name.clone(),
            display_name: self.display_name.clone(),
            source_type: "birdwatcher".to_string(),
            router_id: resp.status.router_id,
            version: resp.status.version,
            neighbor_count,
            last_refresh: None,
            error: None,
        })
    }

    async fn neighbors(&self) -> Result<Vec<BgpSourceNeighbor>> {
        let protocols = self.fetch_protocols().await?;
        let mut neighbors = Vec::with_capacity(protocols.len());
        for (_name, proto) in protocols {
            let state = if proto.state == "UP" || proto.bgp_state == "Established" {
                "Established".to_string()
            } else {
                proto.bgp_state.clone()
            };
            neighbors.push(BgpSourceNeighbor {
                address: proto.neighbor_address.clone(),
                remote_as: proto.neighbor_as,
                description: proto.description.unwrap_or_default(),
                state,
                uptime: proto.state_changed.unwrap_or_default(),
                prefixes_received: proto.routes.as_ref().map(|r| r.imported).unwrap_or(0),
                prefixes_sent: proto.routes.as_ref().map(|r| r.exported).unwrap_or(0),
            });
        }
        neighbors.sort_by(|a, b| a.address.cmp(&b.address));
        Ok(neighbors)
    }

    async fn routes_accepted(&self, neighbor: &str) -> Result<Vec<BgpRoute>> {
        let proto_name = self.resolve_protocol_name(neighbor).await?;
        self.fetch_routes(&format!("/routes/protocol/{proto_name}")).await
    }

    async fn routes_filtered(&self, neighbor: &str) -> Result<Vec<BgpRoute>> {
        let proto_name = self.resolve_protocol_name(neighbor).await?;
        self.fetch_routes(&format!("/routes/filtered/{proto_name}")).await
    }

    async fn routes_noexport(&self, neighbor: &str) -> Result<Vec<BgpRoute>> {
        let proto_name = self.resolve_protocol_name(neighbor).await?;
        self.fetch_routes(&format!("/routes/noexport/{proto_name}")).await
    }

    async fn route_lookup(&self, prefix: &str) -> Result<Vec<BgpRoute>> {
        self.fetch_routes(&format!("/routes/prefix?prefix={prefix}")).await
    }
}

// ── BIRDWatcher JSON response types ─────────────────────────────

#[derive(Deserialize)]
struct BwStatusResponse {
    status: BwStatus,
}

#[derive(Deserialize)]
struct BwStatus {
    router_id: String,
    version: String,
}

#[derive(Deserialize)]
struct BwProtocolsResponse {
    protocols: HashMap<String, BwProtocol>,
}

#[derive(Deserialize)]
struct BwProtocol {
    neighbor_address: String,
    neighbor_as: u32,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    bgp_state: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    state_changed: Option<String>,
    #[serde(default)]
    routes: Option<BwRouteStats>,
}

#[derive(Deserialize)]
struct BwRouteStats {
    #[serde(default)]
    imported: u32,
    #[serde(default)]
    exported: u32,
    #[serde(default)]
    filtered: u32,
}

#[derive(Deserialize)]
struct BwRoutesResponse {
    #[serde(default)]
    routes: Vec<BwRoute>,
}

#[derive(Deserialize)]
struct BwRoute {
    network: String,
    #[serde(default)]
    bgp: BwBgp,
    #[serde(default)]
    primary: Option<bool>,
    #[serde(default)]
    age: Option<String>,
}

#[derive(Deserialize, Default)]
struct BwBgp {
    #[serde(default)]
    as_path: Option<Vec<u32>>,
    #[serde(default)]
    next_hop: Option<String>,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    local_pref: Option<serde_json::Value>,
    #[serde(default)]
    communities: Option<Vec<Vec<u32>>>,
    #[serde(default)]
    large_communities: Option<Vec<Vec<u32>>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_birdwatcher_route() {
        let source = BirdwatcherSource::new(
            "test".to_string(),
            "Test".to_string(),
            "http://localhost:29184".to_string(),
        );
        let raw = BwRoute {
            network: "10.0.0.0/24".to_string(),
            bgp: BwBgp {
                as_path: Some(vec![65000, 65001]),
                next_hop: Some("192.168.1.1".to_string()),
                origin: Some("IGP".to_string()),
                local_pref: Some(serde_json::json!("100")),
                communities: Some(vec![vec![65000, 100]]),
                large_communities: Some(vec![vec![65000, 1, 2]]),
            },
            primary: Some(true),
            age: Some("2025-01-01 00:00:00".to_string()),
        };
        let route = source.normalize_route(raw);
        assert_eq!(route.prefix, "10.0.0.0/24");
        assert_eq!(route.as_path, vec![65000, 65001]);
        assert_eq!(route.local_pref, Some(100));
        assert_eq!(route.communities, vec!["65000:100"]);
        assert_eq!(route.large_communities, vec!["65000:1:2"]);
        assert!(route.primary);
    }

    #[test]
    fn normalize_local_pref_as_number() {
        let source = BirdwatcherSource::new(
            "test".to_string(),
            "Test".to_string(),
            "http://localhost:29184".to_string(),
        );
        let raw = BwRoute {
            network: "10.0.0.0/24".to_string(),
            bgp: BwBgp {
                local_pref: Some(serde_json::json!(200)),
                ..Default::default()
            },
            primary: None,
            age: None,
        };
        let route = source.normalize_route(raw);
        assert_eq!(route.local_pref, Some(200));
    }
}
