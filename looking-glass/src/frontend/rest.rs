//! REST API frontend with Bearer token authentication.
//!
//! Provides a JSON API for programmatic access to looking glass data.
//! Authentication is via OIDC Bearer tokens (id_token), verified cryptographically.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::command::{AddressFamily, Command, Resource, Verb};
use crate::frontend::common::SharedState;
use crate::identity::Identity;
use crate::oidc::OidcClient;
use crate::participants::Participant;
use crate::policy::PolicyDecision;
use crate::structured::{
    ArpEntry, BgpSummary, InterfaceDetail, InterfaceOptics, InterfaceStatus,
    LldpNeighbor, NdEntry,
};

/// State shared across REST API handlers.
#[derive(Clone)]
pub struct RestState {
    pub shared: Arc<SharedState>,
    pub oidc_client: Option<OidcClient>,
}

/// Per-request identity extracted from Bearer token.
#[derive(Clone)]
struct RequestIdentity(Identity);

/// Per-request rate limit key.
#[derive(Clone)]
struct RateLimitKey(String);

/// Extract Bearer token from Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Extract client IP from X-Forwarded-For or X-Real-IP for rate limiting.
fn extract_client_ip(headers: &HeaderMap) -> Option<std::net::IpAddr> {
    headers
        .get("X-Forwarded-For")
        .or_else(|| headers.get("X-Real-IP"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
}

/// Authentication middleware: verify Bearer token via OIDC.
async fn auth_middleware(
    State(state): State<RestState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    let token = extract_bearer_token(headers);
    let client_ip = extract_client_ip(headers);

    let (identity, rate_key) = match (&state.oidc_client, token) {
        (Some(oidc), Some(token)) => {
            match oidc.verify_id_token(&token).await {
                Ok(claims) => {
                    debug!(email = %claims.email, groups = ?claims.groups, "REST: authenticated via Bearer token");
                    let rate_key = claims.email.clone();
                    let identity = Identity::from_oidc_claims(
                        claims.email,
                        claims.groups,
                        &state.shared.group_prefix,
                    );
                    (identity, rate_key)
                }
                Err(e) => {
                    debug!(error = %e, "REST: Bearer token verification failed");
                    let rate_key = client_ip
                        .map(crate::ratelimit::ip_to_rate_key)
                        .unwrap_or_else(|| "anonymous".to_string());
                    (Identity::anonymous(), rate_key)
                }
            }
        }
        _ => {
            let rate_key = client_ip
                .map(crate::ratelimit::ip_to_rate_key)
                .unwrap_or_else(|| "anonymous".to_string());
            debug!(rate_key = %rate_key, "REST: anonymous request");
            (Identity::anonymous(), rate_key)
        }
    };

    request.extensions_mut().insert(RequestIdentity(identity));
    request.extensions_mut().insert(RateLimitKey(rate_key));
    next.run(request).await
}

/// API error response.
#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl ApiError {
    fn new(error: impl Into<String>) -> Self {
        Self { error: error.into(), detail: None }
    }

    fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
    }
}

/// Wrapper for API responses that can be errors.
type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ApiError>)>;

fn api_err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError::new(msg)))
}

/// Execute a command and collect results from all devices.
async fn execute_command<T, F>(
    state: &RestState,
    identity: &Identity,
    rate_key: &str,
    command: &Command,
    extract: F,
) -> ApiResult<Vec<DeviceResult<T>>>
where
    T: Serialize,
    F: Fn(&crate::structured::CommandOutput) -> Option<T>,
{
    // Policy check
    if let PolicyDecision::Deny { reason } = state
        .shared
        .policy
        .evaluate(command, identity, &state.shared.participants.load())
    {
        return Err(api_err(StatusCode::FORBIDDEN, reason));
    }

    // Rate limit
    state
        .shared
        .rate_limiter
        .acquire(rate_key)
        .await
        .map_err(|e| api_err(StatusCode::TOO_MANY_REQUESTS, format!("rate limited: {e}")))?;

    // Execute
    let mut rx = state
        .shared
        .device_pool
        .execute(
            command,
            identity,
            &state.shared.device_rate_limiter,
            state.shared.policy.admin_group(),
            &state.shared.port_map.load(),
            &state.shared.public_vlans,
        )
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, format!("device error: {e}")))?;

    let mut results = Vec::new();
    while let Some(r) = rx.recv().await {
        let data = extract(&r.output);
        results.push(DeviceResult {
            device: r.device,
            success: r.success,
            data,
        });
    }

    Ok(Json(results))
}

/// Result from a single device.
#[derive(Debug, Serialize)]
struct DeviceResult<T> {
    device: String,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
}

// --- Query parameters ---

#[derive(Debug, Deserialize)]
struct BgpSummaryQuery {
    #[serde(default = "default_ipv4")]
    af: String,
}

fn default_ipv4() -> String {
    "ipv4".to_string()
}

// --- Route handlers ---

async fn get_interfaces_status(
    State(state): State<RestState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<InterfaceStatus>>>> {
    let identity = request.extensions().get::<RequestIdentity>().map(|i| i.0.clone()).unwrap_or_else(Identity::anonymous);
    let rate_key = request.extensions().get::<RateLimitKey>().map(|k| k.0.clone()).unwrap_or_else(|| "anonymous".to_string());

    let cmd = Command {
        verb: Verb::Show,
        resource: Resource::InterfacesStatus,
        target: None,
        device: None,
        address_family: AddressFamily::IPv4,
        filter_asn: None,
        filter_vlan: None,
    };

    execute_command(&state, &identity, &rate_key, &cmd, |output| {
        if let crate::structured::CommandOutput::InterfacesStatus(v) = output {
            Some(v.clone())
        } else {
            None
        }
    })
    .await
}

async fn get_interface_detail(
    State(state): State<RestState>,
    Path(name): Path<String>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<InterfaceDetail>>> {
    let identity = request.extensions().get::<RequestIdentity>().map(|i| i.0.clone()).unwrap_or_else(Identity::anonymous);
    let rate_key = request.extensions().get::<RateLimitKey>().map(|k| k.0.clone()).unwrap_or_else(|| "anonymous".to_string());

    let cmd = Command {
        verb: Verb::Show,
        resource: Resource::InterfaceDetail,
        target: Some(name),
        device: None,
        address_family: AddressFamily::IPv4,
        filter_asn: None,
        filter_vlan: None,
    };

    execute_command(&state, &identity, &rate_key, &cmd, |output| {
        if let crate::structured::CommandOutput::InterfaceDetail(v) = output {
            Some(v.clone())
        } else {
            None
        }
    })
    .await
}

async fn get_optics(
    State(state): State<RestState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<InterfaceOptics>>>> {
    let identity = request.extensions().get::<RequestIdentity>().map(|i| i.0.clone()).unwrap_or_else(Identity::anonymous);
    let rate_key = request.extensions().get::<RateLimitKey>().map(|k| k.0.clone()).unwrap_or_else(|| "anonymous".to_string());

    let cmd = Command {
        verb: Verb::Show,
        resource: Resource::Optics,
        target: None,
        device: None,
        address_family: AddressFamily::IPv4,
        filter_asn: None,
        filter_vlan: None,
    };

    execute_command(&state, &identity, &rate_key, &cmd, |output| {
        if let crate::structured::CommandOutput::Optics(v) = output {
            Some(v.clone())
        } else {
            None
        }
    })
    .await
}

async fn get_optics_detail(
    State(state): State<RestState>,
    Path(name): Path<String>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<InterfaceOptics>>>> {
    let identity = request.extensions().get::<RequestIdentity>().map(|i| i.0.clone()).unwrap_or_else(Identity::anonymous);
    let rate_key = request.extensions().get::<RateLimitKey>().map(|k| k.0.clone()).unwrap_or_else(|| "anonymous".to_string());

    let cmd = Command {
        verb: Verb::Show,
        resource: Resource::OpticsDetail,
        target: Some(name),
        device: None,
        address_family: AddressFamily::IPv4,
        filter_asn: None,
        filter_vlan: None,
    };

    execute_command(&state, &identity, &rate_key, &cmd, |output| {
        if let crate::structured::CommandOutput::OpticsDetail(v) = output {
            Some(v.clone())
        } else {
            None
        }
    })
    .await
}

async fn get_bgp_summary(
    State(state): State<RestState>,
    Query(query): Query<BgpSummaryQuery>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<BgpSummary>>> {
    let identity = request.extensions().get::<RequestIdentity>().map(|i| i.0.clone()).unwrap_or_else(Identity::anonymous);
    let rate_key = request.extensions().get::<RateLimitKey>().map(|k| k.0.clone()).unwrap_or_else(|| "anonymous".to_string());

    let af = match query.af.as_str() {
        "ipv6" | "IPv6" => AddressFamily::IPv6,
        _ => AddressFamily::IPv4,
    };

    let cmd = Command {
        verb: Verb::Show,
        resource: Resource::BgpSummary,
        target: None,
        device: None,
        address_family: af,
        filter_asn: None,
        filter_vlan: None,
    };

    execute_command(&state, &identity, &rate_key, &cmd, |output| {
        if let crate::structured::CommandOutput::BgpSummary(v) = output {
            Some(v.clone())
        } else {
            None
        }
    })
    .await
}

async fn get_lldp_neighbors(
    State(state): State<RestState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<LldpNeighbor>>>> {
    let identity = request.extensions().get::<RequestIdentity>().map(|i| i.0.clone()).unwrap_or_else(Identity::anonymous);
    let rate_key = request.extensions().get::<RateLimitKey>().map(|k| k.0.clone()).unwrap_or_else(|| "anonymous".to_string());

    let cmd = Command {
        verb: Verb::Show,
        resource: Resource::LldpNeighbors,
        target: None,
        device: None,
        address_family: AddressFamily::IPv4,
        filter_asn: None,
        filter_vlan: None,
    };

    execute_command(&state, &identity, &rate_key, &cmd, |output| {
        if let crate::structured::CommandOutput::LldpNeighbors(v) = output {
            Some(v.clone())
        } else {
            None
        }
    })
    .await
}

async fn get_arp_table(
    State(state): State<RestState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<ArpEntry>>>> {
    let identity = request.extensions().get::<RequestIdentity>().map(|i| i.0.clone()).unwrap_or_else(Identity::anonymous);
    let rate_key = request.extensions().get::<RateLimitKey>().map(|k| k.0.clone()).unwrap_or_else(|| "anonymous".to_string());

    let cmd = Command {
        verb: Verb::Show,
        resource: Resource::ArpTable,
        target: None,
        device: None,
        address_family: AddressFamily::IPv4,
        filter_asn: None,
        filter_vlan: None,
    };

    execute_command(&state, &identity, &rate_key, &cmd, |output| {
        if let crate::structured::CommandOutput::ArpTable(v) = output {
            Some(v.clone())
        } else {
            None
        }
    })
    .await
}

async fn get_nd_table(
    State(state): State<RestState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<NdEntry>>>> {
    let identity = request.extensions().get::<RequestIdentity>().map(|i| i.0.clone()).unwrap_or_else(Identity::anonymous);
    let rate_key = request.extensions().get::<RateLimitKey>().map(|k| k.0.clone()).unwrap_or_else(|| "anonymous".to_string());

    let cmd = Command {
        verb: Verb::Show,
        resource: Resource::NdTable,
        target: None,
        device: None,
        address_family: AddressFamily::IPv6,
        filter_asn: None,
        filter_vlan: None,
    };

    execute_command(&state, &identity, &rate_key, &cmd, |output| {
        if let crate::structured::CommandOutput::NdTable(v) = output {
            Some(v.clone())
        } else {
            None
        }
    })
    .await
}

/// Participant info for REST API response.
#[derive(Debug, Serialize)]
struct ParticipantInfo {
    asn: u32,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    participant_type: Option<String>,
}

impl From<&Participant> for ParticipantInfo {
    fn from(p: &Participant) -> Self {
        Self {
            asn: p.asn,
            name: p.name.clone(),
            participant_type: p.participant_type.clone(),
        }
    }
}

async fn get_participants(
    State(state): State<RestState>,
) -> Json<Vec<ParticipantInfo>> {
    let participants = state.shared.participants.load();
    let mut entries: Vec<ParticipantInfo> = participants.all().map(ParticipantInfo::from).collect();
    entries.sort_by_key(|p| p.asn);
    Json(entries)
}

/// Build the REST API router.
pub fn router(state: RestState) -> Router {
    Router::new()
        .route("/api/v1/interfaces/status", get(get_interfaces_status))
        .route("/api/v1/interfaces/{name}", get(get_interface_detail))
        .route("/api/v1/optics", get(get_optics))
        .route("/api/v1/optics/{name}", get(get_optics_detail))
        .route("/api/v1/bgp/summary", get(get_bgp_summary))
        .route("/api/v1/lldp/neighbors", get(get_lldp_neighbors))
        .route("/api/v1/arp", get(get_arp_table))
        .route("/api/v1/nd", get(get_nd_table))
        .route("/api/v1/participants", get(get_participants))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
}

/// REST API frontend server.
pub struct RestFrontend {
    bind_addr: String,
    state: RestState,
}

impl RestFrontend {
    pub fn new(bind_addr: String, shared: Arc<SharedState>, oidc_client: Option<OidcClient>) -> Self {
        Self {
            bind_addr,
            state: RestState { shared, oidc_client },
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let app = router(self.state.clone());
        let listener = tokio::net::TcpListener::bind(&self.bind_addr).await?;
        info!("REST API server listening on {}", self.bind_addr);

        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                tokio::signal::ctrl_c().await.ok();
            })
            .await?;
        Ok(())
    }
}
