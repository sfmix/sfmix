use std::sync::Arc;

use axum::extract::Request;
use axum::http::HeaderMap;
use axum::middleware::{self, Next};
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
use tracing::{info, debug};

use crate::oidc::OidcClient;

use crate::command::{AddressFamily, Command, Resource, Verb};
use crate::frontend::common::SharedState;
use crate::identity::Identity;
use crate::policy::PolicyDecision;

tokio::task_local! {
    /// Per-request identity extracted from Bearer token.
    static CURRENT_IDENTITY: Identity;
    /// Per-request rate-limit key (email for authenticated, IP prefix for anonymous).
    static CURRENT_RATE_KEY: String;
}

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
///
/// Identity is derived from cryptographically verified JWT claims only.
/// No header-based trust (X-Forwarded-Email, etc.) — all identity must come
/// from a valid Bearer token signed by the configured OIDC issuer.
async fn auth_middleware(
    request: Request,
    next: Next,
    group_prefix: String,
    oidc_client: Option<OidcClient>,
) -> Response {
    let headers = request.headers();
    let token = extract_bearer_token(headers);
    let client_ip = extract_client_ip(headers);

    let (identity, rate_key) = match (&oidc_client, token) {
        (Some(oidc), Some(token)) => {
            match oidc.verify_id_token(&token).await {
                Ok(claims) => {
                    debug!(email = %claims.email, groups = ?claims.groups, "MCP: authenticated via Bearer token");
                    let rate_key = claims.email.clone();
                    let identity = Identity::from_oidc_claims(
                        claims.email,
                        claims.groups,
                        &group_prefix,
                    );
                    (identity, rate_key)
                }
                Err(e) => {
                    debug!(error = %e, "MCP: Bearer token verification failed");
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
            debug!(rate_key = %rate_key, "MCP: anonymous request");
            (Identity::anonymous(), rate_key)
        }
    };

    CURRENT_IDENTITY.scope(identity, async {
        CURRENT_RATE_KEY.scope(rate_key, next.run(request)).await
    }).await
}

/// MCP (Model Context Protocol) frontend server.
///
/// Exposes the looking glass as an MCP server over streamable HTTP,
/// enabling LLM agents to query IXP state.
pub struct McpFrontend {
    bind_addr: String,
    state: Arc<SharedState>,
}

impl McpFrontend {
    pub fn new(bind_addr: String, state: Arc<SharedState>) -> Self {
        Self { bind_addr, state }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let state = self.state.clone();
        let ct = tokio_util::sync::CancellationToken::new();

        let config = StreamableHttpServerConfig::default()
            .with_stateful_mode(false)
            .with_cancellation_token(ct.child_token());

        let service = StreamableHttpService::new(
            move || {
                // Read identity and rate key from task-locals set by auth middleware
                let identity = CURRENT_IDENTITY
                    .try_with(|id| id.clone())
                    .unwrap_or_else(|_| Identity::anonymous());
                let rate_key = CURRENT_RATE_KEY
                    .try_with(|k| k.clone())
                    .unwrap_or_else(|_| "anonymous".to_string());
                Ok(LookingGlassMcp::new(state.clone(), identity, rate_key))
            },
            LocalSessionManager::default().into(),
            config,
        );

        let group_prefix = self.state.group_prefix.clone();
        let oidc_client = self.state.oidc_client.clone();
        let router = axum::Router::new()
            .nest_service("/mcp", service)
            .layer(middleware::from_fn(move |req, next| {
                auth_middleware(req, next, group_prefix.clone(), oidc_client.clone())
            }));
        let listener = tokio::net::TcpListener::bind(&self.bind_addr).await?;
        info!("MCP server listening on {}", self.bind_addr);

        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                tokio::signal::ctrl_c().await.ok();
                ct.cancel();
            })
            .await?;
        Ok(())
    }
}

// --- Tool parameter types ---

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct InterfaceParams {
    /// Interface name (e.g. "Ethernet3/1")
    interface: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct BgpSummaryParams {
    /// Address family: "ipv4" or "ipv6". Defaults to "ipv4".
    #[serde(default = "default_ipv4")]
    address_family: String,
}

fn default_ipv4() -> String {
    "ipv4".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct DestinationParams {
    /// Target IP address or hostname
    destination: String,
}

// --- MCP Server Handler ---

#[derive(Clone)]
struct LookingGlassMcp {
    state: Arc<SharedState>,
    identity: Identity,
    rate_key: String,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl LookingGlassMcp {
    fn new(state: Arc<SharedState>, identity: Identity, rate_key: String) -> Self {
        Self {
            state,
            identity,
            rate_key,
            tool_router: Self::tool_router(),
        }
    }

    /// Execute a parsed command through the policy engine, rate limiter, and device pool.
    /// Returns JSON-serialized structured output for MCP/LLM consumption.
    async fn execute_command(&self, command: &Command) -> Result<String, McpError> {
        if let PolicyDecision::Deny { reason } =
            self.state.policy.evaluate(command, &self.identity, &self.state.participants.load())
        {
            return Err(McpError::invalid_request(reason, None));
        }

        self.state
            .rate_limiter
            .acquire(&self.rate_key)
            .await
            .map_err(|e| McpError::invalid_request(format!("rate limited: {e}"), None))?;

        let mut rx = self.state
            .device_pool
            .execute(command, &self.identity, &self.state.device_rate_limiter, self.state.policy.admin_group(), &self.state.port_map.load(), &self.state.public_vlans)
            .await
            .map_err(|e| McpError::internal_error(format!("device error: {e}"), None))?;

        // Collect all device results, then serialize as JSON for LLM agents
        let mut json_results: Vec<serde_json::Value> = Vec::new();
        while let Some(r) = rx.recv().await {
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
        let cmd = Command {
            verb: Verb::Show,
            resource,
            target,
            device: None,
            address_family: af,
            filter_asn: None,
            filter_vlan: None,
        };
        let output = self.execute_command(&cmd).await?;
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    /// Format the participant list as "AS<n> <name> [type]" lines.
    fn format_participants(&self) -> String {
        let participants = self.state.participants.load();
        let mut entries: Vec<_> = participants.all().collect();
        entries.sort_by_key(|p| p.asn);
        if entries.is_empty() {
            return "No participants configured.\n".to_string();
        }
        entries
            .iter()
            .map(|p| {
                let ptype = p.participant_type.as_deref().unwrap_or("Member");
                format!("AS{} {} [{}]", p.asn, p.name, ptype)
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    #[tool(description = "Show a summary of all interface statuses including name, link state, speed, and VLAN")]
    async fn show_interfaces_status(&self) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::InterfacesStatus, None, AddressFamily::IPv4).await
    }

    #[tool(description = "Show detailed counters and status for a specific interface")]
    async fn show_interface_detail(
        &self,
        Parameters(params): Parameters<InterfaceParams>,
    ) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::InterfaceDetail, Some(params.interface), AddressFamily::IPv4).await
    }

    #[tool(description = "Show transceiver DOM optical power levels for all ports")]
    async fn show_optics(&self) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::Optics, None, AddressFamily::IPv4).await
    }

    #[tool(description = "Show detailed transceiver DOM levels for a specific port")]
    async fn show_optics_detail(
        &self,
        Parameters(params): Parameters<InterfaceParams>,
    ) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::OpticsDetail, Some(params.interface), AddressFamily::IPv4).await
    }

    #[tool(description = "Show BGP peer summary table. Set address_family to 'ipv4' or 'ipv6'.")]
    async fn show_bgp_summary(
        &self,
        Parameters(params): Parameters<BgpSummaryParams>,
    ) -> Result<CallToolResult, McpError> {
        let af = match params.address_family.as_str() {
            "ipv6" | "IPv6" => AddressFamily::IPv6,
            _ => AddressFamily::IPv4,
        };
        self.run_show(Resource::BgpSummary, None, af).await
    }

    #[tool(description = "Show LLDP neighbor discovery table")]
    async fn show_lldp_neighbors(&self) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::LldpNeighbors, None, AddressFamily::IPv4).await
    }

    #[tool(description = "Show ARP table (IPv4 address-to-MAC mappings)")]
    async fn show_arp_table(&self) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::ArpTable, None, AddressFamily::IPv4).await
    }

    #[tool(description = "Show IPv6 neighbor discovery table (IPv6 address-to-MAC mappings)")]
    async fn show_nd_table(&self) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::NdTable, None, AddressFamily::IPv6).await
    }

    #[tool(description = "List IXP participants with their ASN and name")]
    async fn show_participants(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(self.format_participants())]))
    }

    #[tool(description = "Ping a destination from the looking glass vantage point")]
    async fn ping(
        &self,
        Parameters(params): Parameters<DestinationParams>,
    ) -> Result<CallToolResult, McpError> {
        let cmd = Command {
            verb: Verb::Ping,
            resource: Resource::NetworkReachability,
            target: Some(params.destination),
            device: None,
            address_family: AddressFamily::IPv4,
            filter_asn: None,
            filter_vlan: None,
        };
        let output = self.execute_command(&cmd).await?;
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    #[tool(description = "Traceroute to a destination from the looking glass vantage point")]
    async fn traceroute(
        &self,
        Parameters(params): Parameters<DestinationParams>,
    ) -> Result<CallToolResult, McpError> {
        let cmd = Command {
            verb: Verb::Traceroute,
            resource: Resource::NetworkReachability,
            target: Some(params.destination),
            device: None,
            address_family: AddressFamily::IPv4,
            filter_asn: None,
            filter_vlan: None,
        };
        let output = self.execute_command(&cmd).await?;
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
            "SFMIX Looking Glass — query IXP switch and router state. \
             Available tools: show_interfaces_status, show_interface_detail, \
             show_optics, show_optics_detail, show_bgp_summary, \
             show_lldp_neighbors, show_arp_table, show_nd_table, \
             show_participants, ping, traceroute.",
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
