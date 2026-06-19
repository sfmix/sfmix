use std::sync::Arc;

use axum::{
    Router,
    extract::{Path, Query, State},
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
use looking_glass::participants::PortClass;
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
        .route("/rpc/v1/participants", get(participants_list))
        .route("/rpc/v1/participants.json", get(ixf_member_export))
        .route("/rpc/v1/participants/{asn}", get(participant_detail))
        .route("/rpc/v1/participant-ports", get(participant_ports))
        .route("/rpc/v1/ix-ip-assignments", get(ix_ip_assignments))
        .route("/rpc/v1/discovered-neighbors", get(discovered_neighbors))
        .route("/rpc/v1/netbox/status", get(netbox_status))
        .route("/rpc/v1/device-cache/status", get(device_cache_status))
        .route("/rpc/v1/peeringdb-cache", get(peeringdb_cache))
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

/// GET /rpc/v1/participants — flat list of NetBox participants
async fn participants_list(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_secret(&headers, &state.rpc_secret) {
        return e.into_response();
    }
    let nb_participants = state.lg.netbox_participants.load();
    Json(serde_json::to_value(&*nb_participants).unwrap_or_default()).into_response()
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

/// GET /rpc/v1/participant-ports — all participant (device, interface, asn, name) tuples
async fn participant_ports(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_secret(&headers, &state.rpc_secret) {
        return e.into_response();
    }
    let port_map = state.lg.port_map.load();
    let participants = state.lg.participants();
    let mut entries: Vec<serde_json::Value> = port_map
        .iter()
        .filter_map(|((device, interface), class)| {
            if let PortClass::Participant { asn } = class {
                let name = participants
                    .get(*asn)
                    .map(|p| p.name.clone())
                    .unwrap_or_default();
                Some(serde_json::json!({
                    "device": device,
                    "interface": interface,
                    "asn": asn,
                    "name": name,
                }))
            } else {
                None
            }
        })
        .collect();
    entries.sort_by(|a, b| {
        a["asn"].as_u64().cmp(&b["asn"].as_u64())
            .then(a["device"].as_str().cmp(&b["device"].as_str()))
            .then(a["interface"].as_str().cmp(&b["interface"].as_str()))
    });
    Json(entries).into_response()
}

/// Optional `?asn=` filter for assignment/neighbor listings. `?unassigned=true`
/// (discovered-neighbors only) narrows to IPs not in the NetBox assignment set.
#[derive(serde::Deserialize)]
struct AsnFilter {
    asn: Option<u32>,
    #[serde(default)]
    unassigned: Option<bool>,
}

/// GET /rpc/v1/ix-ip-assignments — flat list of assigned IX IPs with tenant/ASN.
///
/// Sourced from the NetBox participant cache. Consumed internally by
/// lg-neighborhood-watch (to know which IPs to solicit) and proxied publicly by
/// lg-http. `?asn=` narrows to one participant.
async fn ix_ip_assignments(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
    Query(filter): Query<AsnFilter>,
) -> impl IntoResponse {
    if let Err(e) = check_secret(&headers, &state.rpc_secret) {
        return e.into_response();
    }
    let nb_participants = state.lg.netbox_participants.load();
    let mut entries: Vec<serde_json::Value> = nb_participants
        .iter()
        .filter(|p| filter.asn.is_none_or(|a| p.asn == a))
        .flat_map(|p| {
            p.ip_addresses.iter().map(move |ip| {
                serde_json::json!({
                    "ip": ip.address,
                    "family": ip.family,
                    "asn": p.asn,
                    "tenant_name": p.name,
                    "status": ip.status,
                })
            })
        })
        .collect();
    entries.sort_by(|a, b| {
        a["ip"].as_str().cmp(&b["ip"].as_str())
    });
    Json(entries).into_response()
}

/// GET /rpc/v1/discovered-neighbors — ARP/NDP neighbors heard on the IX fabric.
///
/// Accumulated from the lg-neighborhood-watch sensor. `?asn=` narrows to one
/// participant's IPs.
async fn discovered_neighbors(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
    Query(filter): Query<AsnFilter>,
) -> impl IntoResponse {
    if let Err(e) = check_secret(&headers, &state.rpc_secret) {
        return e.into_response();
    }
    let cache = state.lg.discovered.load();
    // `unassigned=true` takes precedence: return only IPs not in the assignment
    // set (a participant mis-bound to an invalid/disallowed address). These have
    // no ASN, so the `?asn=` filter alone could never surface them.
    if filter.unassigned == Some(true) {
        let filtered: Vec<_> = cache.neighbors.iter().filter(|n| !n.assigned).cloned().collect();
        return Json(serde_json::json!({
            "neighbors": filtered,
            "fetched_at": cache.fetched_at,
            "last_error": cache.last_error,
        }))
        .into_response();
    }
    match filter.asn {
        Some(asn) => {
            let filtered: Vec<_> = cache
                .neighbors
                .iter()
                .filter(|n| n.asn == Some(asn))
                .cloned()
                .collect();
            Json(serde_json::json!({
                "neighbors": filtered,
                "fetched_at": cache.fetched_at,
                "last_error": cache.last_error,
            }))
            .into_response()
        }
        None => Json(serde_json::to_value(&**cache).unwrap_or_default()).into_response(),
    }
}

/// GET /rpc/v1/device-cache/status — per-device background cache freshness
async fn device_cache_status(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_secret(&headers, &state.rpc_secret) {
        return e.into_response();
    }
    let cache = state.lg.device_state_cache.load();
    let poll_interval_secs = state.lg.device_cache_cfg.poll_interval_secs;
    let mut entries: Vec<serde_json::Value> = cache
        .iter()
        .map(|(device, dc)| {
            serde_json::json!({
                "device": device,
                "poll_interval_secs": poll_interval_secs,
                "interfaces":      { "age_secs": dc.interfaces_at.map(|t| t.elapsed().as_secs()),      "count": dc.interfaces.len() },
                "lldp_neighbors":  { "age_secs": dc.lldp_at.map(|t| t.elapsed().as_secs()),            "count": dc.lldp_neighbors.len() },
                "mac_table":       { "age_secs": dc.mac_at.map(|t| t.elapsed().as_secs()),              "count": dc.mac_table.len() },
                "optics":          { "age_secs": dc.optics_at.map(|t| t.elapsed().as_secs()),           "count": dc.optics.len() },
                "optics_inventory":{ "age_secs": dc.optics_inventory_at.map(|t| t.elapsed().as_secs()), "count": dc.optics_inventory.len() },
                "arp_table":       { "age_secs": dc.arp_at.map(|t| t.elapsed().as_secs()),              "count": dc.arp_table.len() },
                "ipv6_neighbors":  { "age_secs": dc.ipv6_neighbors_at.map(|t| t.elapsed().as_secs()),   "count": dc.ipv6_neighbors.len() },
                "last_error": dc.last_error,
            })
        })
        .collect();
    entries.sort_by(|a, b| {
        a["device"].as_str().unwrap_or("").cmp(b["device"].as_str().unwrap_or(""))
    });
    Json(entries).into_response()
}

/// GET /rpc/v1/peeringdb-cache — PeeringDB network cache
async fn peeringdb_cache(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_secret(&headers, &state.rpc_secret) {
        return e.into_response();
    }
    let cache = state.lg.peeringdb_cache.load();
    Json(serde_json::to_value(&**cache).unwrap_or_default()).into_response()
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
