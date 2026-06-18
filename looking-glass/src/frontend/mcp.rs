use std::sync::Arc;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::local::LocalSessionManager,
    },
};
use serde_json::json;

use crate::oidc::OidcClient;

use crate::command::{AddressFamily, Command, Resource, Verb};
use crate::identity::Identity;
use crate::service::{self, LookingGlass};
use super::auth;

tokio::task_local! {
    /// Per-request identity extracted from Bearer token.
    static CURRENT_IDENTITY: Identity;
    /// Per-request rate-limit key (email for authenticated, IP prefix for anonymous).
    static CURRENT_RATE_KEY: String;
}

/// Authentication middleware: verify Bearer token via OIDC.
///
/// Identity is derived from cryptographically verified JWT claims only.
/// No header-based trust (X-Forwarded-Email, etc.) — all identity must come
/// from a valid Bearer token signed by the configured OIDC issuer.
pub async fn auth_middleware(
    request: Request,
    next: Next,
    group_prefix: String,
    oidc_client: Option<OidcClient>,
) -> Response {
    let (identity, rate_key) = auth::resolve_identity(
        request.headers(),
        &oidc_client,
        &group_prefix,
        "MCP",
    )
    .await;

    CURRENT_IDENTITY.scope(identity, async {
        CURRENT_RATE_KEY.scope(rate_key, next.run(request)).await
    }).await
}

/// Build the MCP axum router (mounted at `/mcp`).
///
/// The returned router includes its own auth middleware that sets
/// task-local identity for the rmcp handler.
pub fn router(
    lg: Arc<LookingGlass>,
    ct: tokio_util::sync::CancellationToken,
) -> axum::Router {
    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_cancellation_token(ct);

    let service = StreamableHttpService::new(
        move || {
            // Read identity and rate key from task-locals set by auth middleware
            let identity = CURRENT_IDENTITY
                .try_with(|id| id.clone())
                .unwrap_or_else(|_| Identity::anonymous());
            let rate_key = CURRENT_RATE_KEY
                .try_with(|k| k.clone())
                .unwrap_or_else(|_| "anonymous".to_string());
            Ok(LookingGlassMcp::new(lg.clone(), identity, rate_key))
        },
        LocalSessionManager::default().into(),
        config,
    );

    axum::Router::new().nest_service("/mcp", service)
}


// --- Tool parameter types ---

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct InterfaceParams {
    /// Device hostname (e.g. "switch01.sjc01.sfmix.org")
    device: String,
    /// Interface name (e.g. "Ethernet3/1")
    interface: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct DestinationParams {
    /// Target IP address or hostname
    destination: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ParticipantParams {
    /// ASN number (e.g. 12276)
    asn: u32,
}

// --- MCP Server Handler ---

#[derive(Clone)]
struct LookingGlassMcp {
    lg: Arc<LookingGlass>,
    identity: Identity,
    rate_key: String,
    // Required by the rmcp #[tool_router]/#[tool_handler] macro pair; the
    // generated handler consults it even though no code reads it directly.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl LookingGlassMcp {
    fn new(lg: Arc<LookingGlass>, identity: Identity, rate_key: String) -> Self {
        Self {
            lg,
            identity,
            rate_key,
            tool_router: Self::tool_router(),
        }
    }

    /// Execute a parsed command via the service layer.
    /// Returns JSON-serialized structured output for MCP/LLM consumption.
    async fn execute_command(&self, command: &Command) -> Result<String, McpError> {
        let req = service::Request {
            command: command.clone(),
            identity: self.identity.clone(),
            rate_key: self.rate_key.clone(),
        };

        let results = self.lg.execute(req).await.map_err(|e| match e {
            service::Error::PolicyDenied(reason) => McpError::invalid_request(reason, None),
            service::Error::RateLimited(reason) => McpError::invalid_request(format!("rate limited: {reason}"), None),
            other => McpError::internal_error(other.to_string(), None),
        })?;

        // Collect all device results, then serialize as JSON for LLM agents
        let mut json_results: Vec<serde_json::Value> = Vec::new();
        for r in results {
            let data = match r.output {
                crate::structured::CommandOutput::Stream(mut stream_rx) => {
                    let text = crate::format::drain_stream(&mut stream_rx).await;
                    serde_json::Value::String(text)
                }
                other => serde_json::json!(other),
            };
            json_results.push(serde_json::json!({
                "device": r.device,
                "success": r.success,
                "data": data,
            }));
        }

        serde_json::to_string_pretty(&json_results)
            .map_err(|e| McpError::internal_error(format!("serialization error: {e}"), None))
    }

    /// Shorthand: build a Show command, execute it, and wrap the output.
    async fn run_show(
        &self,
        resource: Resource,
        target: Option<String>,
        af: AddressFamily,
    ) -> Result<CallToolResult, McpError> {
        let command = Command {
            verb: Verb::Show,
            resource,
            target,
            device: None,
            address_family: af,
            filter_asn: None,
            filter_vlan: None,
            filter_source: None,
        };
        let output = self.execute_command(&command).await?;
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    /// Format the participant list as "AS<n> <name> [type]" lines.
    fn format_participants(&self) -> String {
        let participants = self.lg.participants();
        let mut entries: Vec<_> = participants.all().collect();
        entries.sort_by_key(|p| p.asn);
        if entries.is_empty() {
            return "No participants configured.\n".to_string();
        }
        entries
            .iter()
            .map(|p| {
                let ptype = p.participant_type.as_deref().unwrap_or("Member");
                format!(
                    "AS{} {} [{}] — {} port(s), {} BGP session(s)",
                    p.asn,
                    p.name,
                    ptype,
                    p.ports.len(),
                    p.sessions.len(),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    #[tool(description = "Show a summary of all interface statuses including name, link state, speed, and VLAN")]
    async fn show_interfaces_status(&self) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::InterfacesStatus, None, AddressFamily::IPv4).await
    }

    #[tool(description = "Show detailed counters and status for a specific interface on a specific device")]
    async fn show_interface_detail(
        &self,
        Parameters(params): Parameters<InterfaceParams>,
    ) -> Result<CallToolResult, McpError> {
        let command = Command {
            verb: Verb::Show,
            resource: Resource::InterfaceDetail,
            target: Some(params.interface),
            device: Some(params.device),
            address_family: AddressFamily::IPv4,
            filter_asn: None,
            filter_vlan: None,
            filter_source: None,
        };
        let output = self.execute_command(&command).await?;
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    #[tool(description = "Show transceiver DOM optical power levels for all ports")]
    async fn show_optics(&self) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::Optics, None, AddressFamily::IPv4).await
    }

    #[tool(description = "Show detailed transceiver DOM levels for a specific port on a specific device")]
    async fn show_optics_detail(
        &self,
        Parameters(params): Parameters<InterfaceParams>,
    ) -> Result<CallToolResult, McpError> {
        let command = Command {
            verb: Verb::Show,
            resource: Resource::OpticsDetail,
            target: Some(params.interface),
            device: Some(params.device),
            address_family: AddressFamily::IPv4,
            filter_asn: None,
            filter_vlan: None,
            filter_source: None,
        };
        let output = self.execute_command(&command).await?;
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    #[tool(description = "Show LLDP neighbor discovery table")]
    async fn show_lldp_neighbors(&self) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::LldpNeighbors, None, AddressFamily::IPv4).await
    }

    #[tool(description = "List IXP participants with their ASN and name")]
    async fn show_participants(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(self.format_participants())]))
    }

    #[tool(description = "Get metadata for a specific participant by ASN, including their \
        port names and BGP neighbor IPs. Use this before show_interface_detail to discover \
        which interfaces belong to this participant.")]
    async fn show_participant_detail(
        &self,
        Parameters(params): Parameters<ParticipantParams>,
    ) -> Result<CallToolResult, McpError> {
        let participants = self.lg.participants();
        match participants.get(params.asn) {
            Some(p) => {
                let netbox_participants = self.lg.netbox_participants.load();
                let enriched_ports = netbox_participants
                    .iter()
                    .find(|np| np.asn == params.asn)
                    .map(|np| np.enriched_ports.as_slice())
                    .unwrap_or(&[]);

                // Iterate enriched_ports (peering-tagged only), not p.ports which
                // now also contains physical LAG members added for port-map coverage.
                let ports_json: Vec<serde_json::Value> = enriched_ports.iter().map(|ep| {
                    let members: Vec<serde_json::Value> = ep.member_interfaces.iter()
                        .map(|(mdev, miface)| serde_json::json!({
                            "device": mdev,
                            "interface": miface,
                            "show_interface_args": { "device": mdev, "interface": miface },
                            "show_optics_args": { "device": mdev, "interface": miface },
                        })).collect();
                    serde_json::json!({
                        "device": ep.device,
                        "interface": ep.interface,
                        "speed_gbps": ep.speed.map(|s| s / 1000),
                        "enabled": ep.enabled,
                        "show_interface_args": { "device": ep.device, "interface": ep.interface },
                        "show_optics_args": { "device": ep.device, "interface": ep.interface },
                        "member_interfaces": members,
                    })
                }).collect();

                let result = serde_json::json!({
                    "asn": p.asn,
                    "name": p.name,
                    "type": p.participant_type,
                    "ports": ports_json,
                    "bgp_sessions": p.sessions.iter().map(|s| serde_json::json!({
                        "device": s.device,
                        "neighbor_v4": s.neighbor,
                        "neighbor_v6": s.neighbor_v6,
                    })).collect::<Vec<_>>(),
                });
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result).unwrap(),
                )]))
            }
            None => Err(McpError::invalid_request(
                format!("AS{} is not a participant", params.asn),
                None,
            )),
        }
    }

    #[tool(description = "Ping a destination from the looking glass vantage point")]
    async fn ping(
        &self,
        Parameters(params): Parameters<DestinationParams>,
    ) -> Result<CallToolResult, McpError> {
        let command = Command {
            verb: Verb::Ping,
            resource: Resource::NetworkReachability,
            target: Some(params.destination),
            device: None,
            address_family: AddressFamily::IPv4,
            filter_asn: None,
            filter_vlan: None,
            filter_source: None,
        };
        let output = self.execute_command(&command).await?;
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    #[tool(description = "Traceroute to a destination from the looking glass vantage point")]
    async fn traceroute(
        &self,
        Parameters(params): Parameters<DestinationParams>,
    ) -> Result<CallToolResult, McpError> {
        let command = Command {
            verb: Verb::Traceroute,
            resource: Resource::NetworkReachability,
            target: Some(params.destination),
            device: None,
            address_family: AddressFamily::IPv4,
            filter_asn: None,
            filter_vlan: None,
            filter_source: None,
        };
        let output = self.execute_command(&command).await?;
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }
}

#[tool_handler]
impl ServerHandler for LookingGlassMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(
            Implementation::new("sfmix-looking-glass", env!("CARGO_PKG_VERSION"))
                .with_description("SFMIX IXP Looking Glass"),
        )
        .with_instructions(
            "SFMIX Looking Glass — query IXP switch and router state.\n\
             \n\
             Typical workflow to investigate a participant:\n\
             1. show_participants — list all ASNs and names\n\
             2. show_participant_detail(asn) — get their port names and BGP neighbor IPs\n\
             3. show_interface_detail(interface) — per-port counters and link state\n\
             4. show_optics_detail(interface) — transceiver optical power levels\n\
             \n\
             For connectivity checks: ping / traceroute\n\
             Fabric-wide state: show_interfaces_status, show_lldp_neighbors",
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult {
            resources: vec![RawResource::new(
                "ixp://participants",
                "IXP Participants".to_string(),
            )
            .no_annotation()],
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        match request.uri.as_str() {
            "ixp://participants" => Ok(ReadResourceResult::new(vec![ResourceContents::text(
                self.format_participants(),
                request.uri,
            )])),
            _ => Err(McpError::resource_not_found(
                "resource_not_found",
                Some(json!({ "uri": request.uri })),
            )),
        }
    }
}
