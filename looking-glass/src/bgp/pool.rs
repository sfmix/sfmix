//! BGP source pool — manages multiple BGP data sources and dispatches queries.

use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::{BgpSourceConfig, BgpSourceType};
use crate::structured::{BgpRoute, BgpRouteList, BgpSourceNeighbor, BgpSourceStatus};
use super::BgpSource;
use super::birdwatcher::BirdwatcherSource;
use super::bgplgd::BgplgdSource;

/// Cached neighbor list for a single source.
struct CachedSource {
    source: Box<dyn BgpSource>,
    neighbors: RwLock<Vec<BgpSourceNeighbor>>,
    status: RwLock<BgpSourceStatus>,
    refresh_interval_secs: u64,
}

/// Pool of BGP data sources with cached neighbor lists.
pub struct BgpSourcePool {
    sources: Vec<Arc<CachedSource>>,
}

impl BgpSourcePool {
    /// Create a new pool from config entries.
    pub fn new(configs: Vec<BgpSourceConfig>) -> Self {
        let sources: Vec<Arc<CachedSource>> = configs.into_iter().map(|cfg| {
            let display = cfg.display_name.clone()
                .unwrap_or_else(|| cfg.name.clone());
            let source: Box<dyn BgpSource> = match cfg.source_type {
                BgpSourceType::Birdwatcher => Box::new(BirdwatcherSource::new(
                    cfg.name.clone(),
                    display.clone(),
                    cfg.api.clone(),
                )),
                BgpSourceType::Bgplgd => Box::new(BgplgdSource::new(
                    cfg.name.clone(),
                    display.clone(),
                    cfg.api.clone(),
                )),
            };
            let initial_status = BgpSourceStatus {
                name: cfg.name.clone(),
                display_name: display,
                source_type: match cfg.source_type {
                    BgpSourceType::Birdwatcher => "birdwatcher".to_string(),
                    BgpSourceType::Bgplgd => "bgplgd".to_string(),
                },
                router_id: String::new(),
                version: String::new(),
                neighbor_count: 0,
                last_refresh: None,
                error: Some("not yet refreshed".to_string()),
            };
            Arc::new(CachedSource {
                source,
                neighbors: RwLock::new(Vec::new()),
                status: RwLock::new(initial_status),
                refresh_interval_secs: cfg.refresh_interval_secs,
            })
        }).collect();

        Self { sources }
    }

    /// Start background refresh tasks for all sources.
    pub fn start_background_refresh(self: &Arc<Self>) {
        for cached in &self.sources {
            let cached = cached.clone();
            tokio::spawn(async move {
                loop {
                    Self::refresh_source(&cached).await;
                    tokio::time::sleep(std::time::Duration::from_secs(
                        cached.refresh_interval_secs,
                    )).await;
                }
            });
        }
    }

    async fn refresh_source(cached: &CachedSource) {
        let name = cached.source.name().to_string();
        match cached.source.status().await {
            Ok(mut status) => {
                status.last_refresh = Some(Utc::now());
                status.error = None;
                *cached.status.write().await = status;

                match cached.source.neighbors().await {
                    Ok(neighbors) => {
                        let count = neighbors.len();
                        *cached.neighbors.write().await = neighbors;
                        let mut s = cached.status.write().await;
                        s.neighbor_count = count as u32;
                        info!("BGP source {name}: refreshed {count} neighbors");
                    }
                    Err(e) => {
                        warn!("BGP source {name}: neighbor refresh failed: {e}");
                        let mut s = cached.status.write().await;
                        s.error = Some(format!("neighbor refresh: {e}"));
                    }
                }
            }
            Err(e) => {
                warn!("BGP source {name}: status refresh failed: {e}");
                let mut s = cached.status.write().await;
                s.last_refresh = Some(Utc::now());
                s.error = Some(format!("status: {e}"));
            }
        }
    }

    /// Get status of all configured BGP sources.
    pub async fn sources_status(&self) -> Vec<BgpSourceStatus> {
        let mut results = Vec::with_capacity(self.sources.len());
        for cached in &self.sources {
            results.push(cached.status.read().await.clone());
        }
        results
    }

    /// Get neighbors from all sources, or a specific one.
    pub async fn neighbors(&self, source_filter: Option<&str>) -> Vec<(String, Vec<BgpSourceNeighbor>)> {
        let mut results = Vec::new();
        for cached in &self.sources {
            if let Some(filter) = source_filter {
                if cached.source.name() != filter {
                    continue;
                }
            }
            let neighbors = cached.neighbors.read().await.clone();
            results.push((cached.source.name().to_string(), neighbors));
        }
        results
    }

    /// Fetch routes from a specific neighbor. Queries the source that has this neighbor.
    /// If source_filter is provided, only queries that source.
    pub async fn routes_for_neighbor(
        &self,
        neighbor: &str,
        source_filter: Option<&str>,
    ) -> Result<Vec<BgpRouteList>> {
        let mut results = Vec::new();
        for cached in &self.sources {
            if let Some(filter) = source_filter {
                if cached.source.name() != filter {
                    continue;
                }
            }
            // Check if this source has this neighbor
            let has_neighbor = {
                let neighbors = cached.neighbors.read().await;
                neighbors.iter().any(|n| n.address == neighbor)
            };
            if !has_neighbor && source_filter.is_none() {
                continue;
            }

            let source_name = cached.source.name().to_string();

            let (accepted, filtered, noexport) = tokio::join!(
                cached.source.routes_accepted(neighbor),
                cached.source.routes_filtered(neighbor),
                cached.source.routes_noexport(neighbor),
            );

            let accepted = accepted.unwrap_or_default();
            let filtered = filtered.unwrap_or_default();
            let noexport = noexport.unwrap_or_default();

            results.push(BgpRouteList {
                source_name,
                neighbor: neighbor.to_string(),
                accepted_count: accepted.len() as u32,
                filtered_count: filtered.len() as u32,
                noexport_count: noexport.len() as u32,
                routes: accepted,
            });
        }
        Ok(results)
    }

    /// Prefix lookup across all sources (or a specific one).
    pub async fn route_lookup(
        &self,
        prefix: &str,
        source_filter: Option<&str>,
    ) -> Result<Vec<BgpRoute>> {
        let mut all_routes = Vec::new();
        for cached in &self.sources {
            if let Some(filter) = source_filter {
                if cached.source.name() != filter {
                    continue;
                }
            }
            match cached.source.route_lookup(prefix).await {
                Ok(routes) => all_routes.extend(routes),
                Err(e) => {
                    warn!("BGP source {}: prefix lookup failed: {e}", cached.source.name());
                }
            }
        }
        Ok(all_routes)
    }

    /// Number of configured sources.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
}
