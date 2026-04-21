//! MCP frontend that routes commands through the RPC backend.

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

use lg_client::client::{ExecuteEvent, RpcClient};
use looking_glass::command::{AddressFamily, Command, Resource, Verb};
use looking_glass::identity::Identity;
use looking_glass::oidc::OidcClient;
use looking_glass::frontend::auth;

tokio::task_local! {
    static CURRENT_IDENTITY: Identity;
    static CURRENT_RATE_KEY: String;
}

/// Authentication middleware for MCP requests.
/// Returns 401 with WWW-Authenticate header if no valid Bearer token is present,
/// triggering OAuth discovery flow in MCP clients (RFC 9728).
pub async fn auth_middleware(
    request: Request,
    next: Next,
    group_prefix: String,
    oidc_client: Option<OidcClient>,
    resource_metadata_url: Option<String>,
) -> Response {
    let (identity, rate_key) = auth::resolve_identity(
        request.headers(),
        &oidc_client,
        &group_prefix,
        "MCP",
    )
    .await;

    if !identity.authenticated {
        let mut response = axum::http::Response::builder()
            .status(axum::http::StatusCode::UNAUTHORIZED);

        if let Some(ref url) = resource_metadata_url {
            let header_value = format!("Bearer resource_metadata=\"{}\"", url);
            response = response.header(axum::http::header::WWW_AUTHENTICATE, header_value);
        }

        return response.body(axum::body::Body::empty()).unwrap();
    }

    CURRENT_IDENTITY.scope(identity, async {
        CURRENT_RATE_KEY.scope(rate_key, next.run(request)).await
    }).await
}

/// Build the MCP axum router (mounted at `/mcp`).
pub fn router(
    rpc: RpcClient,
    ct: tokio_util::sync::CancellationToken,
) -> axum::Router {
    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_cancellation_token(ct);

    let service = StreamableHttpService::new(
        move || {
            let identity = CURRENT_IDENTITY
                .try_with(|id| id.clone())
                .unwrap_or_else(|_| Identity::anonymous());
            let rate_key = CURRENT_RATE_KEY
                .try_with(|k| k.clone())
                .unwrap_or_else(|_| "anonymous".to_string());
            Ok(McpHandler::new(rpc.clone(), identity, rate_key))
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
struct McpHandler {
    rpc: RpcClient,
    identity: Identity,
    rate_key: String,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl McpHandler {
    fn new(rpc: RpcClient, identity: Identity, rate_key: String) -> Self {
        Self {
            rpc,
            identity,
            rate_key,
            tool_router: Self::tool_router(),
        }
    }

    /// Execute a command via RPC and return JSON output for MCP/LLM consumption.
    async fn execute_command(&self, command: &Command) -> Result<String, McpError> {
        let mut rx = self
            .rpc
            .execute(command.clone(), self.identity.clone(), self.rate_key.clone())
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut json_results: Vec<serde_json::Value> = Vec::new();

        while let Some(event) = rx.recv().await {
            match event {
                ExecuteEvent::Result(r) => {
                    json_results.push(serde_json::json!({
                        "device": r.device,
                        "success": r.success,
                        "data": r.output,
                    }));
                }
                ExecuteEvent::StreamLine(sl) => {
                    // Collect stream lines into a text block per device
                    // Find or create a result entry for this device
                    if let Some(entry) = json_results.iter_mut().find(|e| {
                        e["device"].as_str() == Some(&sl.device) && e.get("_streaming").is_some()
                    }) {
                        if let Some(text) = entry["data"].as_str() {
                            entry["data"] =
                                serde_json::Value::String(format!("{text}{}\n", sl.line));
                        }
                    } else {
                        json_results.push(serde_json::json!({
                            "device": sl.device,
                            "success": true,
                            "data": format!("{}\n", sl.line),
                            "_streaming": true,
                        }));
                    }
                }
                ExecuteEvent::StreamEnd(se) => {
                    // Remove the _streaming marker
                    for entry in &mut json_results {
                        if entry["device"].as_str() == Some(&se.device) {
                            if let Some(obj) = entry.as_object_mut() {
                                obj.remove("_streaming");
                            }
                        }
                    }
                }
                ExecuteEvent::Error(e) => {
                    return match e.code.as_str() {
                        "policy_denied" => Err(McpError::invalid_request(e.message, None)),
                        "rate_limited" => Err(McpError::invalid_request(
                            format!("rate limited: {}", e.message),
                            None,
                        )),
                        _ => Err(McpError::internal_error(e.message, None)),
                    };
                }
            }
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

    /// Format participant list via RPC.
    async fn format_participants(&self) -> String {
        match self.rpc.get_json("/rpc/v1/participants.json").await {
            Ok(val) => {
                // Extract member_list and format as simple text
                if let Some(members) = val.get("member_list").and_then(|m| m.as_array()) {
                    let mut lines: Vec<String> = members
                        .iter()
                        .filter_map(|m| {
                            let asn = m.get("asnum")?.as_u64()?;
                            let name = m.get("name")?.as_str()?;
                            let mtype = m.get("member_type").and_then(|t| t.as_str()).unwrap_or("peering");
                            Some(format!("AS{asn} {name} [{mtype}]"))
                        })
                        .collect();
                    lines.sort();
                    if lines.is_empty() {
                        "No participants configured.\n".to_string()
                    } else {
                        lines.join("\n") + "\n"
                    }
                } else {
                    "No participants configured.\n".to_string()
                }
            }
            Err(e) => format!("Error fetching participants: {e}\n"),
        }
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
        Ok(CallToolResult::success(vec![Content::text(self.format_participants().await)]))
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
impl ServerHandler for McpHandler {
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
                self.format_participants().await,
                request.uri,
            )])),
            _ => Err(McpError::resource_not_found(
                "resource_not_found",
                Some(json!({ "uri": request.uri })),
            )),
        }
    }
}
