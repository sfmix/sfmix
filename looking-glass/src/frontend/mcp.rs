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
    lg: Arc<LookingGlass>,
    identity: Identity,
    rate_key: String,
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
        let cmd = Command {
            verb: Verb::Show,
            resource,
            target,
            device: None,
            address_family: af,
            filter_asn: None,
            filter_vlan: None,
            filter_source: None,
        };
        let output = self.execute_command(&cmd).await?;
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
            filter_source: None,
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
            filter_source: None,
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
