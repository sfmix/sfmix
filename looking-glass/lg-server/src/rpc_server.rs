use std::sync::Arc;

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, Sse},
        IntoResponse, Json,
    },
    routing::{get, post},
};
use tokio_stream::wrappers::ReceiverStream;

use lg_types::rpc::{
    DeviceInfo, DeviceResultEvent, ErrorEvent, ExecuteRequest,
    ServiceInfo, StreamEndEvent, StreamLineEvent,
};
use looking_glass::service::{self, LookingGlass};
use looking_glass::structured::CommandOutput;

/// Shared state for the RPC server.
pub struct RpcState {
    pub lg: Arc<LookingGlass>,
    pub rpc_secret: String,
}

/// Build the axum router for the RPC server.
pub fn router(state: Arc<RpcState>) -> Router {
    Router::new()
        .route("/rpc/v1/execute", post(execute))
        .route("/rpc/v1/devices", get(list_devices))
        .route("/rpc/v1/service-info", get(service_info))
        .route("/rpc/v1/participants.json", get(ixf_member_export))
        .route("/rpc/v1/participants/{asn}", get(participant_detail))
        .route("/rpc/v1/netbox/status", get(netbox_status))
        .with_state(state)
}

/// Check X-RPC-Secret header. Returns Err(response) if invalid.
fn check_secret(headers: &HeaderMap, expected: &str) -> Result<(), (StatusCode, &'static str)> {
    match headers.get("X-RPC-Secret") {
        Some(val) if val.as_bytes() == expected.as_bytes() => Ok(()),
        _ => Err((StatusCode::UNAUTHORIZED, "invalid or missing X-RPC-Secret")),
    }
}

/// POST /rpc/v1/execute — execute a command, streaming results as SSE.
async fn execute(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
    Json(req): Json<ExecuteRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_secret(&headers, &state.rpc_secret) {
        return e.into_response();
    }

    let svc_req = service::Request {
        command: req.command,
        identity: req.identity,
        rate_key: req.rate_key,
    };

    // Execute through the LookingGlass pipeline
    let results = match state.lg.execute(svc_req).await {
        Ok(r) => r,
        Err(e) => {
            let code = match &e {
                service::Error::PolicyDenied(_) => "policy_denied",
                service::Error::RateLimited(_) => "rate_limited",
                service::Error::DeviceError(_) => "device_error",
                service::Error::BadRequest(_) => "bad_request",
            };
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(2);
            let err_event = ErrorEvent {
                code: code.to_string(),
                message: e.to_string(),
            };
            let _ = tx
                .send(Ok(Event::default()
                    .event("error")
                    .json_data(&err_event)
                    .unwrap()))
                .await;
            let _ = tx
                .send(Ok(Event::default().event("done").data("{}")))
                .await;
            drop(tx);
            return Sse::new(ReceiverStream::new(rx)).into_response();
        }
    };

    // Stream results as SSE events
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(64);

    tokio::spawn(async move {
        for result in results {
            match result.output {
                CommandOutput::Stream(mut stream_rx) => {
                    while let Some(line) = stream_rx.recv().await {
                        let ev = StreamLineEvent {
                            device: result.device.clone(),
                            line,
                        };
                        if tx
                            .send(Ok(Event::default()
                                .event("stream_line")
                                .json_data(&ev)
                                .unwrap()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    let ev = StreamEndEvent {
                        device: result.device.clone(),
                    };
                    let _ = tx
                        .send(Ok(Event::default()
                            .event("stream_end")
                            .json_data(&ev)
                            .unwrap()))
                        .await;
                }
                other => {
                    let ev = DeviceResultEvent {
                        device: result.device,
                        success: result.success,
                        output: other.into_rpc(),
                    };
                    if tx
                        .send(Ok(Event::default()
                            .event("result")
                            .json_data(&ev)
                            .unwrap()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
        let _ = tx
            .send(Ok(Event::default().event("done").data("{}")))
            .await;
    });

    Sse::new(ReceiverStream::new(rx)).into_response()
}

/// GET /rpc/v1/devices
async fn list_devices(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_secret(&headers, &state.rpc_secret) {
        return e.into_response();
    }
    let names = state.lg.device_pool.device_names();
    let devices: Vec<DeviceInfo> = names
        .into_iter()
        .map(|n| DeviceInfo { name: n.to_string() })
        .collect();
    Json(devices).into_response()
}

/// GET /rpc/v1/service-info
async fn service_info(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_secret(&headers, &state.rpc_secret) {
        return e.into_response();
    }
    let info = ServiceInfo {
        name: state.lg.service_name.clone(),
        admin_group: state.lg.admin_group().to_string(),
        device_count: state.lg.device_count(),
    };
    Json(info).into_response()
}

/// GET /rpc/v1/participants.json — IX-F Member Export
async fn ixf_member_export(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_secret(&headers, &state.rpc_secret) {
        return e.into_response();
    }
    let ixp_data = state.lg.ixp_data.load();
    let nb_participants = state.lg.netbox_participants.load();
    Json(looking_glass::ixf::build_ixf_export(&ixp_data, &nb_participants)).into_response()
}

/// GET /rpc/v1/participants/{asn} — participant detail
async fn participant_detail(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
    Path(asn): Path<u32>,
) -> impl IntoResponse {
    if let Err(e) = check_secret(&headers, &state.rpc_secret) {
        return e.into_response();
    }
    let nb_participants = state.lg.netbox_participants.load();
    match nb_participants.iter().find(|p| p.asn == asn) {
        Some(p) => Json(serde_json::to_value(p).unwrap_or_default()).into_response(),
        None => (StatusCode::NOT_FOUND, "participant not found").into_response(),
    }
}

/// GET /rpc/v1/netbox/status — NetBox cache health
async fn netbox_status(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_secret(&headers, &state.rpc_secret) {
        return e.into_response();
    }
    let status = state.lg.netbox_status.load();
    Json(serde_json::json!({
        "configured": status.configured,
        "participant_count": status.participant_count,
        "peering_port_count": status.peering_port_count,
        "core_port_count": status.core_port_count,
        "port_map_size": status.port_map_size,
        "age_secs": status.age_secs(),
        "last_error": status.last_error,
        "refresh_interval_secs": status.refresh_interval_secs,
        "url": status.url,
    }))
    .into_response()
}
