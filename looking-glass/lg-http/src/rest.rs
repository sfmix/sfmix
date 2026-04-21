//! REST API frontend that proxies commands through the RPC backend.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};

use lg_client::client::{ExecuteEvent, RpcClient};
use lg_types::rpc::ServiceInfo;
use looking_glass::command::{AddressFamily, Command, Resource, Verb};
use looking_glass::identity::Identity;
use looking_glass::oidc::OidcClient;
use looking_glass::structured::CommandOutput;

/// State shared across REST API handlers.
#[derive(Clone)]
pub struct HttpState {
    pub rpc: RpcClient,
    pub info: ServiceInfo,
    pub oidc_client: Option<OidcClient>,
    pub group_prefix: String,
    pub admin_group: String,
    pub service_tokens: Vec<String>,
}

/// Per-request identity extracted from Bearer token.
#[derive(Clone)]
struct RequestIdentity(Identity);

/// Per-request rate limit key.
#[derive(Clone)]
struct RateLimitKey(String);

/// Authentication middleware: verify Bearer token via OIDC.
async fn auth_middleware(
    State(state): State<HttpState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let (identity, rate_key) = looking_glass::frontend::auth::resolve_identity(
        request.headers(),
        &state.oidc_client,
        &state.group_prefix,
        &state.admin_group,
        &state.service_tokens,
        "REST",
    )
    .await;

    request.extensions_mut().insert(RequestIdentity(identity));
    request.extensions_mut().insert(RateLimitKey(rate_key));
    next.run(request).await
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

impl ApiError {
    fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
        }
    }
}

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ApiError>)>;

fn api_err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError::new(msg)))
}

// ---------------------------------------------------------------------------
// Generic RPC execute helper
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct DeviceResult<T> {
    device: String,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
}

/// Execute a command via RPC and extract structured results.
async fn execute_via_rpc<T, F>(
    state: &HttpState,
    identity: &Identity,
    rate_key: &str,
    command: Command,
    extract: F,
) -> ApiResult<Vec<DeviceResult<T>>>
where
    T: Serialize,
    F: Fn(&CommandOutput) -> Option<T>,
{
    let mut rx = state
        .rpc
        .execute(command, identity.clone(), rate_key.to_string())
        .await
        .map_err(|e| api_err(StatusCode::BAD_GATEWAY, e.to_string()))?;

    let mut results = Vec::new();

    while let Some(event) = rx.recv().await {
        match event {
            ExecuteEvent::Result(r) => {
                let local_output = CommandOutput::from_rpc(r.output);
                results.push(DeviceResult {
                    device: r.device,
                    success: r.success,
                    data: extract(&local_output),
                });
            }
            ExecuteEvent::Error(e) => {
                let (status, msg) = match e.code.as_str() {
                    "policy_denied" => (StatusCode::FORBIDDEN, e.message),
                    "rate_limited" => (
                        StatusCode::TOO_MANY_REQUESTS,
                        format!("rate limited: {}", e.message),
                    ),
                    "bad_request" => (StatusCode::BAD_REQUEST, e.message),
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, e.message),
                };
                return Err(api_err(status, msg));
            }
            // Stream events are collected as text for REST (not applicable for most endpoints)
            _ => {}
        }
    }

    Ok(Json(results))
}

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AsnFilterQuery {
    asn: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct BgpSummaryQuery {
    #[serde(default = "default_ipv4")]
    af: String,
}

#[derive(Debug, Deserialize)]
struct MacTableQuery {
    vlan: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BgpRoutesQuery {
    source: Option<String>,
}

fn default_ipv4() -> String {
    "ipv4".to_string()
}

fn parse_af(af: &str) -> AddressFamily {
    match af {
        "ipv6" | "IPv6" => AddressFamily::IPv6,
        _ => AddressFamily::IPv4,
    }
}

// ---------------------------------------------------------------------------
// Helpers to extract identity/rate_key from request extensions
// ---------------------------------------------------------------------------

fn get_identity(request: &axum::extract::Request) -> Identity {
    request
        .extensions()
        .get::<RequestIdentity>()
        .map(|i| i.0.clone())
        .unwrap_or_else(Identity::anonymous)
}

fn get_rate_key(request: &axum::extract::Request) -> String {
    request
        .extensions()
        .get::<RateLimitKey>()
        .map(|k| k.0.clone())
        .unwrap_or_else(|| "anonymous".to_string())
}

fn make_cmd(resource: Resource, target: Option<String>) -> Command {
    Command {
        verb: Verb::Show,
        resource,
        target,
        device: None,
        address_family: AddressFamily::IPv4,
        filter_asn: None,
        filter_vlan: None,
        filter_source: None,
    }
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

use looking_glass::structured::{
    ArpEntry, BgpNeighborDetail, BgpRoute, BgpRouteList, BgpSourceStatus, BgpSummary,
    InterfaceDetail, InterfaceOptics, InterfaceStatus, LldpNeighbor, MacEntry, NdEntry,
    VxlanVtep,
};

async fn get_interfaces_status(
    State(state): State<HttpState>,
    Query(query): Query<AsnFilterQuery>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<InterfaceStatus>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let mut cmd = make_cmd(Resource::InterfacesStatus, None);
    cmd.filter_asn = query.asn;
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::InterfacesStatus(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_interface_detail(
    State(state): State<HttpState>,
    Path(name): Path<String>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<InterfaceDetail>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let cmd = make_cmd(Resource::InterfaceDetail, Some(name));
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::InterfaceDetail(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_optics(
    State(state): State<HttpState>,
    Query(query): Query<AsnFilterQuery>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<InterfaceOptics>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let mut cmd = make_cmd(Resource::Optics, None);
    cmd.filter_asn = query.asn;
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::Optics(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_optics_detail(
    State(state): State<HttpState>,
    Path(name): Path<String>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<InterfaceOptics>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let cmd = make_cmd(Resource::OpticsDetail, Some(name));
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::OpticsDetail(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_bgp_summary(
    State(state): State<HttpState>,
    Query(query): Query<BgpSummaryQuery>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<BgpSummary>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let mut cmd = make_cmd(Resource::BgpSummary, None);
    cmd.address_family = parse_af(&query.af);
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::BgpSummary(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_bgp_neighbor(
    State(state): State<HttpState>,
    Path(address): Path<String>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<BgpNeighborDetail>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let cmd = make_cmd(Resource::BgpNeighbor, Some(address));
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::BgpNeighborDetail(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_lldp_neighbors(
    State(state): State<HttpState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<LldpNeighbor>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let cmd = make_cmd(Resource::LldpNeighbors, None);
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::LldpNeighbors(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_mac_address_table(
    State(state): State<HttpState>,
    Query(query): Query<MacTableQuery>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<MacEntry>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let mut cmd = make_cmd(Resource::MacAddressTable, None);
    cmd.filter_vlan = query.vlan;
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::MacAddressTable(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_vxlan_vtep(
    State(state): State<HttpState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<VxlanVtep>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let cmd = make_cmd(Resource::VxlanVtep, None);
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::VxlanVtep(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_arp_table(
    State(state): State<HttpState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<ArpEntry>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let cmd = make_cmd(Resource::ArpTable, None);
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::ArpTable(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_nd_table(
    State(state): State<HttpState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<NdEntry>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let cmd = make_cmd(Resource::NdTable, None);
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::NdTable(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_participants(
    State(state): State<HttpState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let cmd = make_cmd(Resource::Participants, None);
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::Participants(s) = o { Some(s.clone()) } else { None }
    }).await
}

async fn get_bgp_sources(
    State(state): State<HttpState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<BgpSourceStatus>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let cmd = make_cmd(Resource::BgpSources, None);
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::BgpSources(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_bgp_routes(
    State(state): State<HttpState>,
    Path(neighbor): Path<String>,
    Query(query): Query<BgpRoutesQuery>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<BgpRouteList>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let mut cmd = make_cmd(Resource::BgpRoutes, Some(neighbor));
    cmd.filter_source = query.source;
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::BgpRoutes(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_bgp_route_lookup(
    State(state): State<HttpState>,
    Path(prefix): Path<String>,
    Query(query): Query<BgpRoutesQuery>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<BgpRoute>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let mut cmd = make_cmd(Resource::BgpRouteLookup, Some(prefix));
    cmd.filter_source = query.source;
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::BgpRouteLookup(v) = o { Some(v.clone()) } else { None }
    }).await
}

/// Proxy participants.json (IX-F export) from lg-server.
async fn get_ixf_member_export(
    State(state): State<HttpState>,
) -> impl IntoResponse {
    match state.rpc.get_json("/rpc/v1/participants.json").await {
        Ok(v) => Json(v).into_response(),
        Err(e) => api_err(StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

/// Proxy participant detail from lg-server.
async fn get_participant_detail(
    State(state): State<HttpState>,
    Path(asn): Path<u32>,
) -> impl IntoResponse {
    match state.rpc.get_json(&format!("/rpc/v1/participants/{asn}")).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => api_err(StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

/// Proxy netbox status from lg-server.
async fn get_netbox_status(
    State(state): State<HttpState>,
) -> impl IntoResponse {
    match state.rpc.get_json("/rpc/v1/netbox/status").await {
        Ok(v) => Json(v).into_response(),
        Err(e) => api_err(StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router(state: HttpState) -> Router {
    Router::new()
        .route("/api/v1/interfaces/status", get(get_interfaces_status))
        .route("/api/v1/interfaces/{name}", get(get_interface_detail))
        .route("/api/v1/optics", get(get_optics))
        .route("/api/v1/optics/{name}", get(get_optics_detail))
        .route("/api/v1/bgp/summary", get(get_bgp_summary))
        .route("/api/v1/lldp/neighbors", get(get_lldp_neighbors))
        .route("/api/v1/bgp/neighbor/{address}", get(get_bgp_neighbor))
        .route("/api/v1/mac-address-table", get(get_mac_address_table))
        .route("/api/v1/vxlan/vtep", get(get_vxlan_vtep))
        .route("/api/v1/arp", get(get_arp_table))
        .route("/api/v1/nd", get(get_nd_table))
        .route("/api/v1/participants", get(get_participants))
        .route("/api/v1/participants.json", get(get_ixf_member_export))
        .route("/api/v1/participants/{asn}", get(get_participant_detail))
        .route("/api/v1/netbox/status", get(get_netbox_status))
        .route("/api/v1/bgp/sources", get(get_bgp_sources))
        .route("/api/v1/bgp/routes/{neighbor}", get(get_bgp_routes))
        .route("/api/v1/bgp/route/{prefix}", get(get_bgp_route_lookup))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
}
