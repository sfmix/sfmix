//! Fetch the assigned-IP list and the IX prefixes from lg-server (internal RPC).
//!
//! This is the inbound half of the bidirectional relationship: the sensor asks
//! lg-server which IX IPs exist so it knows what to solicit, and which prefixes
//! the peering LAN uses so the hygiene classifier can tell "foreign" ARP and
//! broadcasts from normal ones. lg-server, in turn, polls this sensor's
//! `/neighbors` and `/bum`. We talk to lg-server directly over RPC
//! (X-RPC-Secret) — lg-http is the public edge and not on this path.

use std::collections::HashSet;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::Utc;
use lg_client::client::RpcClient;
use tracing::{info, warn};

use crate::bum::ClassifyCtx;

/// Periodically refresh the solicit target set from `/rpc/v1/ix-ip-assignments`
/// and the classifier context (IX prefixes) from `/rpc/v1/peering-vlans`.
pub async fn run(
    rpc: RpcClient,
    targets: Arc<ArcSwap<Vec<String>>>,
    last_sync: Arc<ArcSwap<Option<String>>>,
    interval_secs: u64,
    ctx: Arc<ArcSwap<ClassifyCtx>>,
    ignore_src_macs: HashSet<[u8; 6]>,
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
        match rpc.get_json("/rpc/v1/peering-vlans").await {
            Ok(value) => {
                let (v4, v6) = extract_prefixes(&value);
                let mut c = ClassifyCtx { ignore_src_macs: ignore_src_macs.clone(), ..Default::default() };
                c.set_v4(&v4);
                c.set_v6(&v6);
                info!("refreshed IX prefixes: {} v4, {} v6", c.ix_v4.len(), c.ix_v6.len());
                ctx.store(Arc::new(c));
            }
            Err(e) => warn!("failed to fetch peering VLANs: {e}"),
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

/// (network, mask length) pairs.
type Prefixes = Vec<(String, u32)>;

/// `{"vlans":[{ipv4_prefix, ipv4_mask_length, ipv6_prefix, ipv6_mask_length}]}`
/// → (v4 prefixes, v6 prefixes).
fn extract_prefixes(value: &serde_json::Value) -> (Prefixes, Prefixes) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for vlan in value.get("vlans").and_then(|v| v.as_array()).into_iter().flatten() {
        let pick = |p: &str, m: &str| -> Option<(String, u32)> {
            let net = vlan.get(p)?.as_str()?.to_string();
            let len = vlan.get(m)?.as_u64()? as u32;
            Some((net, len))
        };
        if let Some(p) = pick("ipv4_prefix", "ipv4_mask_length") {
            v4.push(p);
        }
        if let Some(p) = pick("ipv6_prefix", "ipv6_mask_length") {
            v6.push(p);
        }
    }
    (v4, v6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_prefixes_from_peering_vlans() {
        let v = serde_json::json!({"vlans": [
            {"vid": 998, "ipv4_prefix": "206.197.187.0", "ipv4_mask_length": 24,
             "ipv6_prefix": "2001:504:30::", "ipv6_mask_length": 64},
            {"vid": 999}
        ]});
        let (v4, v6) = extract_prefixes(&v);
        assert_eq!(v4, vec![("206.197.187.0".to_string(), 24)]);
        assert_eq!(v6, vec![("2001:504:30::".to_string(), 64)]);
    }
}
