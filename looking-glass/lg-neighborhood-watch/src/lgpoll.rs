//! Fetch the assigned-IP list from lg-server (internal RPC).
//!
//! This is the inbound half of the bidirectional relationship: the sensor asks
//! lg-server which IX IPs exist so it knows what to solicit. lg-server, in turn,
//! polls this sensor's `/neighbors`. We talk to lg-server directly over RPC
//! (X-RPC-Secret) — lg-http is the public edge and not on this path.

use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::Utc;
use lg_client::client::RpcClient;
use tracing::{info, warn};

/// Periodically refresh the solicit target set from `/rpc/v1/ix-ip-assignments`.
pub async fn run(
    rpc: RpcClient,
    targets: Arc<ArcSwap<Vec<String>>>,
    last_sync: Arc<ArcSwap<Option<String>>>,
    interval_secs: u64,
) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs.max(1)));
    loop {
        tick.tick().await;
        match rpc.get_json("/rpc/v1/ix-ip-assignments").await {
            Ok(value) => {
                let ips = extract_ips(&value);
                info!("refreshed IX IP assignments: {} addresses", ips.len());
                targets.store(Arc::new(ips));
                last_sync.store(Arc::new(Some(Utc::now().to_rfc3339())));
            }
            Err(e) => warn!("failed to fetch IX IP assignments: {e}"),
        }
    }
}

/// Pull the `ip` field out of each assignment row.
fn extract_ips(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r.get("ip").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
