//! REST API frontend that proxies commands through the RPC backend.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use lg_client::client::{ExecuteEvent, RpcClient};
use looking_glass::command::{AddressFamily, Command, Resource, Verb};
use looking_glass::identity::Identity;
use looking_glass::oidc::OidcClient;
use looking_glass::structured::CommandOutput;

/// State shared across REST API handlers.
#[derive(Clone)]
pub struct HttpState {
    pub rpc: RpcClient,
    pub oidc_client: Option<OidcClient>,
    pub group_prefix: String,
    /// This server's public base URL (e.g. "https://lg-ng.sfmix.org").
    pub resource_url: Option<String>,
    /// OAuth2 authorization endpoint (Authentik's authorize URL).
    pub authorization_endpoint: Option<String>,
    /// Authentik's token endpoint, proxied in auth server metadata.
    pub token_endpoint: Option<String>,
    /// Authentik's JWKS URI, proxied in auth server metadata.
    pub jwks_uri: Option<String>,
    /// Public client_id to return from Dynamic Client Registration.
    pub mcp_client_id: Option<String>,
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
    #[serde(default)]
    unassigned: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct MacTableQuery {
    vlan: Option<String>,
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
    ArpEntry, InterfaceDetail, InterfaceOptics, InterfaceStatus, LldpNeighbor, MacEntry,
};
use lg_types::structured::OpticsInventoryEntry;

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

async fn get_optics_inventory(
    State(state): State<HttpState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<OpticsInventoryEntry>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let cmd = make_cmd(Resource::OpticsInventory, None);
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::OpticsInventory(v) = o { Some(v.clone()) } else { None }
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

async fn get_arp(
    State(state): State<HttpState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<ArpEntry>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let cmd = make_cmd(Resource::Arp, None);
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::Arp(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_ipv6_neighbors(
    State(state): State<HttpState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<ArpEntry>>>> {
    let identity = get_identity(&request);
    let rate_key = get_rate_key(&request);
    let cmd = make_cmd(Resource::IPv6Neighbors, None);
    execute_via_rpc(&state, &identity, &rate_key, cmd, |o| {
        if let CommandOutput::IPv6Neighbors(v) = o { Some(v.clone()) } else { None }
    }).await
}

async fn get_participants(
    State(state): State<HttpState>,
) -> impl IntoResponse {
    match state.rpc.get_json("/rpc/v1/participants").await {
        Ok(v) => Json(v).into_response(),
        Err(e) => api_err(StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
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

/// Proxy participant port map from lg-server.
async fn get_participant_ports(
    State(state): State<HttpState>,
) -> impl IntoResponse {
    match state.rpc.get_json("/rpc/v1/participant-ports").await {
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

/// Proxy device cache status from lg-server.
async fn get_device_cache_status(
    State(state): State<HttpState>,
) -> impl IntoResponse {
    match state.rpc.get_json("/rpc/v1/device-cache/status").await {
        Ok(v) => Json(v).into_response(),
        Err(e) => api_err(StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

/// Proxy the flat IX IP assignment list from lg-server. Public; `?asn=` filters.
async fn get_ix_ip_assignments(
    State(state): State<HttpState>,
    Query(query): Query<AsnFilterQuery>,
) -> impl IntoResponse {
    let path = match query.asn {
        Some(asn) => format!("/rpc/v1/ix-ip-assignments?asn={asn}"),
        None => "/rpc/v1/ix-ip-assignments".to_string(),
    };
    match state.rpc.get_json(&path).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => api_err(StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

/// Proxy discovered ARP/NDP neighbors from lg-server. Public; `?asn=` filters.
async fn get_discovered_neighbors(
    State(state): State<HttpState>,
    Query(query): Query<AsnFilterQuery>,
) -> impl IntoResponse {
    let path = if query.unassigned == Some(true) {
        "/rpc/v1/discovered-neighbors?unassigned=true".to_string()
    } else {
        match query.asn {
            Some(asn) => format!("/rpc/v1/discovered-neighbors?asn={asn}"),
            None => "/rpc/v1/discovered-neighbors".to_string(),
        }
    };
    match state.rpc.get_json(&path).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => api_err(StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

/// Proxy PeeringDB cache from lg-server.
async fn get_peeringdb_cache(
    State(state): State<HttpState>,
) -> impl IntoResponse {
    match state.rpc.get_json("/rpc/v1/peeringdb-cache").await {
        Ok(v) => Json(v).into_response(),
        Err(e) => api_err(StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// OAuth Protected Resource Metadata (RFC 9728)
// ---------------------------------------------------------------------------

/// OAuth 2.0 Protected Resource Metadata (RFC 9728).
/// Tells MCP clients where to obtain tokens.
#[derive(Serialize)]
struct ProtectedResourceMetadata {
    /// The protected resource identifier (this server's URL).
    resource: String,
    /// List of authorization servers that can issue tokens for this resource.
    authorization_servers: Vec<String>,
    /// Scopes supported by this resource.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scopes_supported: Vec<String>,
    /// Token types accepted.
    bearer_methods_supported: Vec<String>,
}

/// GET /.well-known/oauth-protected-resource
async fn get_oauth_protected_resource(
    State(state): State<HttpState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(resource_url) = &state.resource_url else {
        return (StatusCode::NOT_FOUND, "OAuth not configured").into_response();
    };

    // Extract host from headers
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    let resource = format!("https://{}", host);
    // Advertise ourselves as the authorization server (we proxy Authentik + handle DCR)
    let metadata = ProtectedResourceMetadata {
        resource,
        authorization_servers: vec![resource_url.clone()],
        scopes_supported: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
        bearer_methods_supported: vec!["header".to_string()],
    };

    Json(metadata).into_response()
}

// ---------------------------------------------------------------------------
// OAuth Authorization Server Metadata (RFC 8414)
// ---------------------------------------------------------------------------

/// RFC 8414 Authorization Server Metadata.
/// lg-http acts as an auth server proxy, advertising Authentik's real endpoints
/// but adding a registration_endpoint so MCP clients can do Dynamic Client Registration.
#[derive(Serialize)]
struct AuthServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    registration_endpoint: String,
    scopes_supported: Vec<String>,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
}

/// GET /.well-known/oauth-authorization-server
async fn get_oauth_authorization_server_metadata(
    State(state): State<HttpState>,
) -> Response {
    let (Some(resource_url), Some(authorization_endpoint), Some(token_endpoint), Some(jwks_uri)) = (
        &state.resource_url,
        &state.authorization_endpoint,
        &state.token_endpoint,
        &state.jwks_uri,
    ) else {
        return (StatusCode::NOT_FOUND, "OAuth not configured").into_response();
    };

    let metadata = AuthServerMetadata {
        issuer: resource_url.clone(),
        authorization_endpoint: authorization_endpoint.clone(),
        token_endpoint: token_endpoint.clone(),
        jwks_uri: jwks_uri.clone(),
        registration_endpoint: format!("{}/oauth/register", resource_url),
        scopes_supported: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
    };

    Json(metadata).into_response()
}

/// POST /oauth/register — Dynamic Client Registration (RFC 7591)
/// Since Authentik doesn't support DCR, we return our shared public client_id.
async fn post_oauth_register(
    State(state): State<HttpState>,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    let Some(client_id) = &state.mcp_client_id else {
        return (StatusCode::NOT_IMPLEMENTED, "DCR not configured").into_response();
    };

    // Echo back redirect_uris from the request if provided (RFC 7591 requires it in response).
    let redirect_uris = body
        .as_ref()
        .and_then(|b| b.get("redirect_uris"))
        .cloned()
        .unwrap_or(serde_json::json!([]));

    let response = serde_json::json!({
        "client_id": client_id,
        "client_name": "Looking Glass",
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "redirect_uris": redirect_uris,
    });

    (StatusCode::CREATED, Json(response)).into_response()
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router(state: HttpState) -> Router {
    // API routes with auth middleware
    let api_router = Router::new()
        .route("/api/v1/interfaces/status", get(get_interfaces_status))
        .route("/api/v1/interfaces/{name}", get(get_interface_detail))
        .route("/api/v1/optics", get(get_optics))
        .route("/api/v1/optics/inventory", get(get_optics_inventory))
        .route("/api/v1/optics/{name}", get(get_optics_detail))
        .route("/api/v1/lldp/neighbors", get(get_lldp_neighbors))
        .route("/api/v1/mac-address-table", get(get_mac_address_table))
        .route("/api/v1/arp", get(get_arp))
        .route("/api/v1/ipv6/neighbors", get(get_ipv6_neighbors))
        .route("/api/v1/participants", get(get_participants))
        .route("/api/v1/participants.json", get(get_ixf_member_export))
        .route("/api/v1/participants/{asn}", get(get_participant_detail))
        .route("/api/v1/participant-ports", get(get_participant_ports))
        .route("/api/v1/ix-ip-assignments", get(get_ix_ip_assignments))
        .route("/api/v1/discovered-neighbors", get(get_discovered_neighbors))
        .route("/api/v1/netbox/status", get(get_netbox_status))
        .route("/api/v1/device-cache/status", get(get_device_cache_status))
        .route("/api/v1/peeringdb-cache", get(get_peeringdb_cache))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    // Public routes (no auth required) merged after
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(get_oauth_protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(get_oauth_authorization_server_metadata),
        )
        .route("/oauth/register", post(post_oauth_register))
        .with_state(state)
        .merge(api_router)
}
