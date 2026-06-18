//! Internal HTTP/JSON query + metrics interface (no auth; bound internally).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};

use crate::store::Snapshot;

#[derive(Clone)]
pub struct AppState {
    pub table: Arc<ArcSwap<Snapshot>>,
    pub targets: Arc<ArcSwap<Vec<String>>>,
    pub last_lg_sync: Arc<ArcSwap<Option<String>>>,
    pub dropped: Arc<AtomicU64>,
    pub ifaces: Vec<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/neighbors", get(neighbors))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .with_state(state)
}

/// All currently-heard (ip, mac) rows.
async fn neighbors(State(state): State<AppState>) -> impl IntoResponse {
    let snap = state.table.load();
    Json(snap.rows.clone())
}

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let snap = state.table.load();
    let last_sync = state.last_lg_sync.load();
    Json(serde_json::json!({
        "status": "ok",
        "last_lg_sync": (**last_sync).clone(),
        "target_ip_count": state.targets.load().len(),
        "record_count": snap.ip_count,
        "conflict_count": snap.conflict_count,
        "capture_ifaces": state.ifaces,
    }))
}

/// Prometheus exposition.
async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let snap = state.table.load();
    let dropped = state.dropped.load(Ordering::Relaxed);
    let body = format!(
        "# HELP neighwatch_records Distinct IPs currently heard.\n\
         # TYPE neighwatch_records gauge\n\
         neighwatch_records {}\n\
         # HELP neighwatch_conflicts IPs with more than one MAC heard.\n\
         # TYPE neighwatch_conflicts gauge\n\
         neighwatch_conflicts {}\n\
         # HELP neighwatch_target_ips Assigned IPs being solicited.\n\
         # TYPE neighwatch_target_ips gauge\n\
         neighwatch_target_ips {}\n\
         # HELP neighwatch_observations_total Frames parsed into observations.\n\
         # TYPE neighwatch_observations_total counter\n\
         neighwatch_observations_total {}\n\
         # HELP neighwatch_dropped_observations_total Observations dropped on backpressure.\n\
         # TYPE neighwatch_dropped_observations_total counter\n\
         neighwatch_dropped_observations_total {}\n",
        snap.ip_count, snap.conflict_count, state.targets.load().len(), snap.observation_count, dropped,
    );
    ([("content-type", "text/plain; version=0.0.4")], body)
}
