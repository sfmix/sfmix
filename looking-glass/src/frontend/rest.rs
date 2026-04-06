//! REST API frontend with Bearer token authentication.
//!
//! Provides a JSON API for programmatic access to looking glass data.
//! Authentication is via OIDC Bearer tokens (id_token), verified cryptographically.

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
use tracing::info;

use crate::command::{AddressFamily, Command, Resource, Verb};
use crate::identity::Identity;
use crate::oidc::OidcClient;
use crate::participants::Participant;
use crate::service::{self, LookingGlass};
use super::auth;
use crate::structured::{
    ArpEntry, BgpNeighborDetail, BgpSummary, InterfaceDetail, InterfaceOptics,
    InterfaceStatus, LldpNeighbor, MacEntry, NdEntry, VxlanVtep,
};

/// State shared across REST API handlers.
#[derive(Clone)]
pub struct RestState {
    pub lg: Arc<LookingGlass>,
    pub oidc_client: Option<OidcClient>,
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
    State(state): State<RestState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let (identity, rate_key) = auth::resolve_identity(
        request.headers(),
        &state.oidc_client,
        &state.lg.group_prefix,
        &state.lg.admin_group,
        &state.service_tokens,
        "REST",
    )
    .await;

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

/// Execute a command via the service layer and collect results.
async fn execute_command<T, F>(
    state: &RestState,
    identity: &Identity,
    rate_key: &str,
    command: Command,
    extract: F,
) -> ApiResult<Vec<DeviceResult<T>>>
where
    T: Serialize,
    F: Fn(&crate::structured::CommandOutput) -> Option<T>,
{
    let req = service::Request {
        command,
        identity: identity.clone(),
        rate_key: rate_key.to_string(),
    };

    let svc_results = state.lg.execute(req).await.map_err(|e| match e {
        service::Error::PolicyDenied(reason) => api_err(StatusCode::FORBIDDEN, reason),
        service::Error::RateLimited(reason) => api_err(StatusCode::TOO_MANY_REQUESTS, format!("rate limited: {reason}")),
        other => api_err(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;

    let results = svc_results
        .into_iter()
        .map(|r| DeviceResult {
            device: r.device,
            success: r.success,
            data: extract(&r.output),
        })
        .collect();

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
struct AsnFilterQuery {
    /// Filter to ports belonging to this ASN.
    asn: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct BgpSummaryQuery {
    #[serde(default = "default_ipv4")]
    af: String,
}

#[derive(Debug, Deserialize)]
struct BgpNeighborQuery {
    #[serde(default = "default_ipv4")]
    af: String,
}

#[derive(Debug, Deserialize)]
struct MacTableQuery {
    /// Filter by VLAN ID.
    vlan: Option<String>,
}

fn default_ipv4() -> String {
    "ipv4".to_string()
}

// --- Route handlers ---

async fn get_interfaces_status(
    State(state): State<RestState>,
    Query(query): Query<AsnFilterQuery>,
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
        filter_asn: query.asn,
        filter_vlan: None,
    };

    execute_command(&state, &identity, &rate_key, cmd, |output| {
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

    execute_command(&state, &identity, &rate_key, cmd, |output| {
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
    Query(query): Query<AsnFilterQuery>,
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
        filter_asn: query.asn,
        filter_vlan: None,
    };

    execute_command(&state, &identity, &rate_key, cmd, |output| {
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

    execute_command(&state, &identity, &rate_key, cmd, |output| {
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

    execute_command(&state, &identity, &rate_key, cmd, |output| {
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

    execute_command(&state, &identity, &rate_key, cmd, |output| {
        if let crate::structured::CommandOutput::LldpNeighbors(v) = output {
            Some(v.clone())
        } else {
            None
        }
    })
    .await
}

async fn get_bgp_neighbor(
    State(state): State<RestState>,
    Path(address): Path<String>,
    Query(query): Query<BgpNeighborQuery>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<BgpNeighborDetail>>> {
    let identity = request.extensions().get::<RequestIdentity>().map(|i| i.0.clone()).unwrap_or_else(Identity::anonymous);
    let rate_key = request.extensions().get::<RateLimitKey>().map(|k| k.0.clone()).unwrap_or_else(|| "anonymous".to_string());

    let af = match query.af.as_str() {
        "ipv6" | "IPv6" => AddressFamily::IPv6,
        _ => AddressFamily::IPv4,
    };

    let cmd = Command {
        verb: Verb::Show,
        resource: Resource::BgpNeighbor,
        target: Some(address),
        device: None,
        address_family: af,
        filter_asn: None,
        filter_vlan: None,
    };

    execute_command(&state, &identity, &rate_key, cmd, |output| {
        if let crate::structured::CommandOutput::BgpNeighborDetail(v) = output {
            Some(v.clone())
        } else {
            None
        }
    })
    .await
}

async fn get_mac_address_table(
    State(state): State<RestState>,
    Query(query): Query<MacTableQuery>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<MacEntry>>>> {
    let identity = request.extensions().get::<RequestIdentity>().map(|i| i.0.clone()).unwrap_or_else(Identity::anonymous);
    let rate_key = request.extensions().get::<RateLimitKey>().map(|k| k.0.clone()).unwrap_or_else(|| "anonymous".to_string());

    let cmd = Command {
        verb: Verb::Show,
        resource: Resource::MacAddressTable,
        target: None,
        device: None,
        address_family: AddressFamily::IPv4,
        filter_asn: None,
        filter_vlan: query.vlan,
    };

    execute_command(&state, &identity, &rate_key, cmd, |output| {
        if let crate::structured::CommandOutput::MacAddressTable(v) = output {
            Some(v.clone())
        } else {
            None
        }
    })
    .await
}

async fn get_vxlan_vtep(
    State(state): State<RestState>,
    request: axum::extract::Request,
) -> ApiResult<Vec<DeviceResult<Vec<VxlanVtep>>>> {
    let identity = request.extensions().get::<RequestIdentity>().map(|i| i.0.clone()).unwrap_or_else(Identity::anonymous);
    let rate_key = request.extensions().get::<RateLimitKey>().map(|k| k.0.clone()).unwrap_or_else(|| "anonymous".to_string());

    let cmd = Command {
        verb: Verb::Show,
        resource: Resource::VxlanVtep,
        target: None,
        device: None,
        address_family: AddressFamily::IPv4,
        filter_asn: None,
        filter_vlan: None,
    };

    execute_command(&state, &identity, &rate_key, cmd, |output| {
        if let crate::structured::CommandOutput::VxlanVtep(v) = output {
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

    execute_command(&state, &identity, &rate_key, cmd, |output| {
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

    execute_command(&state, &identity, &rate_key, cmd, |output| {
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
    let participants = state.lg.participants();
    let mut entries: Vec<ParticipantInfo> = participants.all().map(ParticipantInfo::from).collect();
    entries.sort_by_key(|p| p.asn);
    Json(entries)
}

// ── Participant detail endpoint ─────────────────────────────────────

async fn get_participant_detail(
    State(state): State<RestState>,
    Path(asn): Path<u32>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let nb_participants = state.lg.netbox_participants.load();
    let participant = nb_participants.iter().find(|p| p.asn == asn);
    match participant {
        Some(p) => Ok(Json(serde_json::to_value(p).unwrap_or_default())),
        None => Err(api_err(StatusCode::NOT_FOUND, format!("participant AS{asn} not found"))),
    }
}

// ── NetBox status endpoint ──────────────────────────────────────────

#[derive(Serialize)]
struct NetboxStatusResponse {
    configured: bool,
    participant_count: usize,
    peering_port_count: usize,
    core_port_count: usize,
    port_map_size: usize,
    age_secs: Option<u64>,
    last_error: Option<String>,
    refresh_interval_secs: u64,
    url: Option<String>,
}

async fn get_netbox_status(
    State(state): State<RestState>,
) -> Json<NetboxStatusResponse> {
    let status = state.lg.netbox_status.load();
    Json(NetboxStatusResponse {
        configured: status.configured,
        participant_count: status.participant_count,
        peering_port_count: status.peering_port_count,
        core_port_count: status.core_port_count,
        port_map_size: status.port_map_size,
        age_secs: status.age_secs(),
        last_error: status.last_error.clone(),
        refresh_interval_secs: status.refresh_interval_secs,
        url: status.url.clone(),
    })
}

// ── IX-F Member Export (participants.json) ───────────────────────────

async fn get_ixf_member_export(
    State(state): State<RestState>,
) -> Json<serde_json::Value> {
    let ixp_data = state.lg.ixp_data.load();
    let nb_participants = state.lg.netbox_participants.load();

    // Build switch list
    let switches: Vec<serde_json::Value> = ixp_data.switches.iter().map(|s| {
        serde_json::json!({
            "id": s.id,
            "name": s.name,
            "colo": s.colo,
            "pdb_facility_id": s.pdb_facility_id,
            "city": s.city,
            "country": s.country,
            "manufacturer": s.manufacturer,
            "model": s.model,
        })
    }).collect();

    // Build VLAN list
    let vlans: Vec<serde_json::Value> = ixp_data.vlans.iter().map(|v| {
        let mut vlan = serde_json::json!({
            "id": v.id,
            "name": v.name,
        });
        if let (Some(ref prefix), Some(mask)) = (&v.ipv4_prefix, v.ipv4_mask_length) {
            vlan["ipv4"] = serde_json::json!({ "prefix": prefix, "mask_length": mask });
        }
        if let (Some(ref prefix), Some(mask)) = (&v.ipv6_prefix, v.ipv6_mask_length) {
            vlan["ipv6"] = serde_json::json!({ "prefix": prefix, "mask_length": mask });
        }
        vlan
    }).collect();

    // Build member list
    let mut members: Vec<serde_json::Value> = Vec::new();
    for p in nb_participants.iter() {
        let member_type = match p.participant_type.as_deref() {
            Some("Infrastructure") => "ixp",
            _ => "peering",
        };

        let connections = build_connection_list(p, &ixp_data.vlans);
        members.push(serde_json::json!({
            "asnum": p.asn,
            "member_type": member_type,
            "name": p.name,
            "connection_list": connections,
        }));
    }
    members.sort_by_key(|m| m["asnum"].as_u64().unwrap_or(0));

    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%z").to_string();

    Json(serde_json::json!({
        "version": "1.0",
        "timestamp": timestamp,
        "ixp_list": [{
            "shortname": "SFMIX",
            "name": "San Francisco Metropolitan Internet Exchange",
            "ixp_id": 155,
            "ixf_id": 223,
            "peeringdb_id": 155,
            "country": "US",
            "url": "https://sfmix.org/",
            "support_email": "tech-c@sfmix.org",
            "support_phone": "+1 415 634-6712",
            "switch": switches,
            "vlan": vlans,
        }],
        "member_list": members,
    }))
}

/// Build the connection_list for a participant in IX-F format.
fn build_connection_list(
    p: &crate::netbox::NetboxParticipant,
    vlans: &[crate::netbox::IxpVlan],
) -> Vec<serde_json::Value> {
    // Special cases from the Jinja2 template
    if p.asn == 12276 {
        return vec![serde_json::json!({
            "ixp_id": 155,
            "state": "active",
            "if_list": [{ "switch_id": 59, "if_speed": 1000 }],
            "vlan_list": [
                { "vlan_id": 1, "ipv4": { "address": "206.197.187.1" }, "ipv6": { "address": "2001:504:30::ba01:2276:1" } },
                { "vlan_id": 1, "ipv4": { "address": "206.197.187.2" }, "ipv6": { "address": "2001:504:30::ba01:2276:2" } },
            ]
        })];
    }
    if p.asn == 63055 {
        return vec![serde_json::json!({
            "ixp_id": 155,
            "state": "active",
            "if_list": [
                { "switch_id": 59, "if_speed": 1000 },
                { "switch_id": 63, "if_speed": 1000 },
            ],
            "vlan_list": [
                { "vlan_id": 1, "ipv4": { "address": "206.197.187.253" }, "ipv6": { "address": "2001:504:30::ba06:3055:1" } },
                { "vlan_id": 1, "ipv4": { "address": "206.197.187.254" }, "ipv6": { "address": "2001:504:30::ba06:3055:2" } },
            ]
        })];
    }

    // Normal participants: one connection per peering port
    let mut connections = Vec::new();
    for port in &p.enriched_ports {
        // Compute if_speed: rate_limit_bps/1e6 or speed (already Mbps)
        let if_speed = if let Some(rl) = port.rate_limit_bps {
            Some(rl / 1_000_000)
        } else {
            port.speed
        };

        let mut if_entry = serde_json::json!({ "switch_id": port.device_id });
        if let Some(speed) = if_speed {
            if_entry["if_speed"] = serde_json::json!(speed);
        }

        // Match IPs to this port via participant_lag_id
        let port_ips: Vec<&crate::netbox::ParticipantIp> = p.ip_addresses.iter()
            .filter(|ip| ip.participant_lag_id == Some(port.interface_id))
            .collect();

        // Build vlan_list: group IPs by VLAN
        // For simplicity, assign IPs to the first VLAN if we can't determine the exact one.
        // The Jinja2 template does subnet matching, but we simplify by using the first peering VLAN.
        let vlan_list: Vec<serde_json::Value> = if !port_ips.is_empty() {
            let vlan_id = vlans.first().map(|v| v.id).unwrap_or(1);
            let mut ipv4_entries: Vec<serde_json::Value> = Vec::new();
            let mut ipv6_entries: Vec<serde_json::Value> = Vec::new();

            for ip in &port_ips {
                let mut ip_obj = serde_json::json!({ "address": ip.address });
                if let Some(ref mac) = ip.mac_address {
                    ip_obj["mac_addresses"] = serde_json::json!([mac]);
                }
                match ip.family.as_str() {
                    "IPv4" => ipv4_entries.push(ip_obj),
                    "IPv6" => ipv6_entries.push(ip_obj),
                    _ => {}
                }
            }

            // Group into vlan entries (one entry per unique vlan, with ipv4/ipv6 sub-objects)
            let mut vlan_entry = serde_json::json!({ "vlan_id": vlan_id });
            if let Some(v4) = ipv4_entries.first() {
                vlan_entry["ipv4"] = v4.clone();
            }
            if let Some(v6) = ipv6_entries.first() {
                vlan_entry["ipv6"] = v6.clone();
            }
            vec![vlan_entry]
        } else {
            Vec::new()
        };

        let mut conn = serde_json::json!({
            "ixp_id": 155,
            "state": "active",
            "if_list": [if_entry],
        });
        if !vlan_list.is_empty() {
            conn["vlan_list"] = serde_json::json!(vlan_list);
        }
        connections.push(conn);
    }

    connections
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
        .route("/api/v1/bgp/neighbor/{address}", get(get_bgp_neighbor))
        .route("/api/v1/mac-address-table", get(get_mac_address_table))
        .route("/api/v1/vxlan/vtep", get(get_vxlan_vtep))
        .route("/api/v1/arp", get(get_arp_table))
        .route("/api/v1/nd", get(get_nd_table))
        .route("/api/v1/participants", get(get_participants))
        .route("/api/v1/participants.json", get(get_ixf_member_export))
        .route("/api/v1/participants/{asn}", get(get_participant_detail))
        .route("/api/v1/netbox/status", get(get_netbox_status))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
}

/// REST API frontend server.
pub struct RestFrontend {
    bind_addr: String,
    state: RestState,
}

impl RestFrontend {
    pub fn new(bind_addr: String, lg: Arc<LookingGlass>, oidc_client: Option<OidcClient>, service_tokens: Vec<String>) -> Self {
        Self {
            bind_addr,
            state: RestState { lg, oidc_client, service_tokens },
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
