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

use crate::bum::{BumSnapshot, FrameStore};
use crate::evidence::{EvidenceStore, SnapshotOutcome};
use crate::ringbuf::PcapWriter;
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
    /// LAN-hygiene (BUM) detections and their evidence frames.
    pub bum: Arc<ArcSwap<BumSnapshot>>,
    pub bum_frames: FrameStore,
    pub bum_dropped: Arc<AtomicU64>,
    pub kernel_frames: Arc<AtomicU64>,
    pub kernel_drops: Arc<AtomicU64>,
    pub capture_mode: &'static str,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/neighbors", get(neighbors))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/evidence", get(evidence_list))
        .route("/evidence/snapshot", post(evidence_snapshot))
        .route("/evidence/{id}", get(evidence_get))
        .route("/bum", get(bum_rows))
        .route("/bum/{mac}/{protocol}/pcap", get(bum_pcap))
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

/// GET /bum — current LAN-hygiene detections, one row per (src_mac, protocol).
async fn bum_rows(State(state): State<AppState>) -> impl IntoResponse {
    let snap = state.bum.load();
    Json(snap.rows.clone())
}

/// GET /bum/{mac}/{protocol}/pcap — the first few frames stored for a detection,
/// as a tiny classic pcap. Inputs are validated against the MAC syntax and the
/// catalog before touching the frame store.
async fn bum_pcap(
    State(state): State<AppState>,
    Path((mac, protocol)): Path<(String, String)>,
) -> impl IntoResponse {
    let Some(mac_bytes) = crate::afpacket::parse_mac(&mac) else {
        return (StatusCode::BAD_REQUEST, "bad mac").into_response();
    };
    let Some(proto) = lg_types::structured::bum_proto(&protocol) else {
        return (StatusCode::BAD_REQUEST, "unknown protocol").into_response();
    };
    let key = (crate::afpacket::fmt_mac(&mac_bytes), proto.key);
    let frames = match state.bum_frames.lock() {
        Ok(f) => f.get(&key).map(|v| v.iter().map(|c| (c.ts_sec, c.ts_usec, c.data.clone())).collect::<Vec<_>>()),
        Err(_) => None,
    };
    let Some(frames) = frames.filter(|f| !f.is_empty()) else {
        return (StatusCode::NOT_FOUND, "no frames stored for this detection").into_response();
    };
    let mut w = match PcapWriter::new(Vec::new()) {
        Ok(w) => w,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("pcap: {e}")).into_response(),
    };
    for (s, us, data) in &frames {
        if let Err(e) = w.write_frame(*s, *us, data) {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("pcap: {e}")).into_response();
        }
    }
    let bytes = w.into_inner();
    (
        [
            ("content-type", "application/vnd.tcpdump.pcap".to_string()),
            ("content-disposition", format!("attachment; filename=\"bum-{}-{}.pcap\"", key.0.replace(':', ""), proto.key)),
        ],
        bytes,
    )
        .into_response()
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
        "capture_mode": state.capture_mode,
        "bum_rows": state.bum.load().rows.len(),
    }))
}

/// Prometheus exposition.
async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    use std::fmt::Write as _;
    let snap = state.table.load();
    let bum = state.bum.load();
    let dropped = state.dropped.load(Ordering::Relaxed);
    let mut body = format!(
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
         neighwatch_dropped_observations_total {}\n\
         # HELP neighwatch_capture_frames_total Frames the kernel delivered to the capture socket.\n\
         # TYPE neighwatch_capture_frames_total counter\n\
         neighwatch_capture_frames_total {}\n\
         # HELP neighwatch_capture_kernel_drops_total Frames the kernel dropped for lack of socket buffer.\n\
         # TYPE neighwatch_capture_kernel_drops_total counter\n\
         neighwatch_capture_kernel_drops_total {}\n\
         # HELP neighwatch_bum_dropped_observations_total Hygiene detections dropped on backpressure.\n\
         # TYPE neighwatch_bum_dropped_observations_total counter\n\
         neighwatch_bum_dropped_observations_total {}\n\
         # HELP neighwatch_bum_observations_total Frames classified as a LAN-hygiene detection.\n\
         # TYPE neighwatch_bum_observations_total counter\n\
         neighwatch_bum_observations_total {}\n",
        snap.ip_count,
        snap.conflict_count,
        state.targets.load().len(),
        snap.observation_count,
        dropped,
        state.kernel_frames.load(Ordering::Relaxed),
        state.kernel_drops.load(Ordering::Relaxed),
        state.bum_dropped.load(Ordering::Relaxed),
        bum.observation_count,
    );
    // Per-protocol lifetime counters (stable series; use these for alerting).
    body.push_str(
        "# HELP neighwatch_bum_frames_by_protocol_total Hygiene detections since start, per protocol.\n\
         # TYPE neighwatch_bum_frames_by_protocol_total counter\n",
    );
    for (proto, sev, n) in &bum.by_protocol {
        let _ = writeln!(body, "neighwatch_bum_frames_by_protocol_total{{protocol=\"{proto}\",severity=\"{sev}\"}} {n}");
    }
    // Per-source rows (expire with the row; for attribution).
    body.push_str(
        "# HELP neighwatch_bum_frames_total Hygiene detections per source MAC and protocol (current rows).\n\
         # TYPE neighwatch_bum_frames_total counter\n",
    );
    for r in &bum.rows {
        let _ = writeln!(
            body,
            "neighwatch_bum_frames_total{{protocol=\"{}\",severity=\"{}\",src_mac=\"{}\"}} {}",
            r.protocol, r.severity, r.src_mac, r.count
        );
    }
    body.push_str(
        "# HELP neighwatch_bum_sources Distinct source MACs currently flagged, per protocol.\n\
         # TYPE neighwatch_bum_sources gauge\n",
    );
    let mut per_proto: std::collections::BTreeMap<(&str, &str), u64> = std::collections::BTreeMap::new();
    for r in &bum.rows {
        *per_proto.entry((r.protocol, r.severity)).or_default() += 1;
    }
    for ((proto, sev), n) in per_proto {
        let _ = writeln!(body, "neighwatch_bum_sources{{protocol=\"{proto}\",severity=\"{sev}\"}} {n}");
    }
    ([("content-type", "text/plain; version=0.0.4")], body)
}
