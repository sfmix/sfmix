//! BGP source backends — HTTP API clients for route server looking glasses.
//!
//! These backends fetch BGP neighbor lists and route tables from external
//! HTTP APIs (BIRDWatcher, bgplgd) and normalize them into the shared
//! structured types defined in `crate::structured`.

pub mod birdwatcher;
pub mod bgplgd;
pub mod pool;

use anyhow::Result;
use async_trait::async_trait;

use crate::structured::{BgpRoute, BgpSourceNeighbor, BgpSourceStatus};

/// A BGP data source that can provide neighbor lists and route tables.
#[async_trait]
pub trait BgpSource: Send + Sync {
    /// Human-readable name of this source.
    fn name(&self) -> &str;

    /// Display name (may differ from name).
    fn display_name(&self) -> &str;

    /// Source type identifier (e.g. "birdwatcher", "bgplgd").
    fn source_type(&self) -> &str;

    /// Fetch current status (router ID, version, neighbor count).
    async fn status(&self) -> Result<BgpSourceStatus>;

    /// Fetch the neighbor list (cached if available).
    async fn neighbors(&self) -> Result<Vec<BgpSourceNeighbor>>;

    /// Fetch accepted routes from a specific neighbor.
    async fn routes_accepted(&self, neighbor: &str) -> Result<Vec<BgpRoute>>;

    /// Fetch filtered (rejected) routes for a specific neighbor.
    async fn routes_filtered(&self, neighbor: &str) -> Result<Vec<BgpRoute>>;

    /// Fetch routes not exported to a specific neighbor.
    /// Returns empty vec if the backend doesn't support this.
    async fn routes_noexport(&self, neighbor: &str) -> Result<Vec<BgpRoute>>;

    /// Prefix lookup across all neighbors.
    async fn route_lookup(&self, prefix: &str) -> Result<Vec<BgpRoute>>;
}
