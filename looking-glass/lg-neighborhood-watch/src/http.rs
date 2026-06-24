//! Internal HTTP/JSON query + metrics interface (no auth; bound internally).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use crate::evidence::{EvidenceStore, SnapshotOutcome};
use crate::store::Snapshot;

#[derive(Clone)]
pub struct AppState {
    pub table: Arc<ArcSwap<Snapshot>>,
    pub targets: Arc<ArcSwap<Vec<String>>>,
    pub last_lg_sync: Arc<ArcSwap<Option<String>>>,
    pub dropped: Arc<AtomicU64>,
    pub ifaces: Vec<String>,
    /// Evidence extraction store; `None` when `evidence_dir` is unconfigured.
    pub evidence: Option<Arc<EvidenceStore>>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/neighbors", get(neighbors))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/evidence", get(evidence_list))
        .route("/evidence/snapshot", post(evidence_snapshot))
        .route("/evidence/{id}", get(evidence_get))
        .with_state(state)
}

/// Body of `POST /evidence/snapshot`.
#[derive(Debug, Deserialize)]
struct SnapshotRequest {
    event_id: String,
    macs: Vec<String>,
    /// RFC3339 window bounds.
    time_start: String,
    time_end: String,
}

/// POST /evidence/snapshot — extract a filtered pcap for an anomaly.
async fn evidence_snapshot(
    State(state): State<AppState>,
    Json(req): Json<SnapshotRequest>,
) -> impl IntoResponse {
    let Some(store) = state.evidence.clone() else {
        return (StatusCode::NOT_IMPLEMENTED, "evidence capture not configured").into_response();
    };
    let (Ok(start), Ok(end)) = (
        chrono::DateTime::parse_from_rfc3339(&req.time_start),
        chrono::DateTime::parse_from_rfc3339(&req.time_end),
    ) else {
        return (StatusCode::BAD_REQUEST, "time_start/time_end must be RFC3339").into_response();
    };
    let start_sec = start.timestamp().max(0) as u32;
    let end_sec = end.timestamp().max(0) as u32;

    match store.snapshot(&req.event_id, &req.macs, start_sec, end_sec).await {
        SnapshotOutcome::Done(meta) | SnapshotOutcome::Existing(meta) => Json(meta).into_response(),
        SnapshotOutcome::InProgress => {
            (StatusCode::CONFLICT, "snapshot in progress").into_response()
        }
        SnapshotOutcome::Busy => (
            StatusCode::SERVICE_UNAVAILABLE,
            [("retry-after", "5")],
            "extraction concurrency limit reached",
        )
            .into_response(),
    }
}

/// GET /evidence — list saved evidence pcaps with metadata.
async fn evidence_list(State(state): State<AppState>) -> impl IntoResponse {
    match state.evidence {
        Some(store) => Json(store.list()).into_response(),
        None => (StatusCode::NOT_IMPLEMENTED, "evidence capture not configured").into_response(),
    }
}

/// GET /evidence/{id} — stream a saved pcap.
async fn evidence_get(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let Some(store) = state.evidence else {
        return (StatusCode::NOT_IMPLEMENTED, "evidence capture not configured").into_response();
    };
    let Some(path) = store.evidence_path(&id) else {
        return (StatusCode::NOT_FOUND, "evidence not found").into_response();
    };
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            [
                ("content-type", "application/vnd.tcpdump.pcap".to_string()),
                ("content-disposition", format!("attachment; filename=\"{id}.pcap\"")),
            ],
            bytes,
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("reading evidence: {e}")).into_response(),
    }
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
