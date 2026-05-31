//! MCP frontend that routes commands through the RPC backend.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::borrow::Cow;

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::router::tool::ToolRouter,
    handler::server::tool::ToolCallContext,
    handler::server::wrapper::Parameters,
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_router,
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
    network_slug: String,
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
            Ok(McpHandler::new(rpc.clone(), identity, rate_key, network_slug.clone()))
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
struct McpHandler {
    rpc: RpcClient,
    identity: Identity,
    rate_key: String,
    network_slug: String,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl McpHandler {
    fn new(rpc: RpcClient, identity: Identity, rate_key: String, network_slug: String) -> Self {
        Self {
            rpc,
            identity,
            rate_key,
            network_slug,
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
                            let port_count = m.get("connection_list").and_then(|c| c.as_array()).map(|a| a.len()).unwrap_or(0);
                            Some(format!("AS{asn} {name} [{mtype}] — {port_count} port(s)"))
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

    #[tool(description = "Show detailed counters and status for a specific interface on a specific device")]
    async fn show_interface_detail(
        &self,
        Parameters(params): Parameters<InterfaceParams>,
    ) -> Result<CallToolResult, McpError> {
        let cmd = Command {
            verb: Verb::Show,
            resource: Resource::InterfaceDetail,
            target: Some(params.interface),
            device: Some(params.device),
            address_family: AddressFamily::IPv4,
            filter_asn: None,
            filter_vlan: None,
            filter_source: None,
        };
        let output = self.execute_command(&cmd).await?;
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
        let cmd = Command {
            verb: Verb::Show,
            resource: Resource::OpticsDetail,
            target: Some(params.interface),
            device: Some(params.device),
            address_family: AddressFamily::IPv4,
            filter_asn: None,
            filter_vlan: None,
            filter_source: None,
        };
        let output = self.execute_command(&cmd).await?;
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    #[tool(description = "Show LLDP neighbor discovery table")]
    async fn show_lldp_neighbors(&self) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::LldpNeighbors, None, AddressFamily::IPv4).await
    }

    #[tool(description = "List IXP participants with their ASN and name")]
    async fn show_participants(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(self.format_participants().await)]))
    }

    #[tool(description = "Get metadata for a specific participant by ASN, including their \
        port names and peering IPs. Use this before show_interface_detail to discover \
        which interfaces belong to this participant.")]
    async fn show_participant_detail(
        &self,
        Parameters(params): Parameters<ParticipantParams>,
    ) -> Result<CallToolResult, McpError> {
        match self.rpc.get_json(&format!("/rpc/v1/participants/{}", params.asn)).await {
            Ok(val) => {
                let asn = val.get("asn").and_then(|v| v.as_u64()).unwrap_or(params.asn as u64);
                let name = val.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
                let ptype = val.get("participant_type").and_then(|v| v.as_str()).unwrap_or("unknown");

                let prefix = format!("looking_glass__{}__", self.network_slug);
                let interface_tool = format!("{}show_interface_detail", prefix);
                let optics_tool = format!("{}show_optics_detail", prefix);

                let enriched_ports: Vec<_> = val
                    .get("enriched_ports")
                    .and_then(|p| p.as_array())
                    .cloned()
                    .unwrap_or_default();

                let peers: Vec<_> = val
                    .get("ip_addresses")
                    .and_then(|p| p.as_array())
                    .cloned()
                    .unwrap_or_default();

                let mut lines: Vec<String> = Vec::new();

                // Header record
                lines.push(serde_json::json!({
                    "type": "participant",
                    "asn": asn,
                    "name": name,
                    "participant_type": ptype,
                    "port_count": enriched_ports.len(),
                }).to_string());

                // One record per port — each is self-contained and immediately actionable
                for p in &enriched_ports {
                    let iface = p.get("interface").and_then(|v| v.as_str()).unwrap_or("");
                    let device = p.get("device").and_then(|v| v.as_str()).unwrap_or("");
                    let speed = p.get("speed").and_then(|v| v.as_u64()).unwrap_or(0);
                    let enabled = p.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                    let members: Vec<serde_json::Value> = p
                        .get("member_interfaces")
                        .and_then(|m| m.as_array())
                        .map(|arr| arr.iter().filter_map(|entry| {
                            let (mdev, miface) = entry.as_array()
                                .and_then(|a| Some((a.get(0)?.as_str()?, a.get(1)?.as_str()?)))?;
                            Some(serde_json::json!({
                                "device": mdev,
                                "interface": miface,
                                "args": { "device": mdev, "interface": miface },
                            }))
                        }).collect())
                        .unwrap_or_default();
                    lines.push(serde_json::json!({
                        "type": "port",
                        "interface": iface,
                        "device": device,
                        "speed_mbps": speed,
                        "enabled": enabled,
                        "call_for_status": interface_tool,
                        "call_for_optics": optics_tool,
                        "args": { "device": device, "interface": iface },
                        "member_interfaces": members,
                    }).to_string());
                }

                // BGP peer records
                for ip in &peers {
                    let addr = ip.get("address").and_then(|v| v.as_str()).unwrap_or("");
                    let family = ip.get("family").and_then(|v| v.as_str()).unwrap_or("");
                    lines.push(serde_json::json!({
                        "type": "bgp_peer",
                        "address": addr,
                        "family": family,
                    }).to_string());
                }

                Ok(CallToolResult::success(vec![Content::text(lines.join("\n"))]))
            }
            Err(e) if e.to_string().contains("404") || e.to_string().contains("not found") => {
                Err(McpError::invalid_request(
                    format!("AS{} is not a participant", params.asn),
                    None,
                ))
            }
            Err(e) => Err(McpError::internal_error(e.to_string(), None)),
        }
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

impl ServerHandler for McpHandler {
    fn get_info(&self) -> ServerInfo {
        let prefix = format!("looking_glass__{}", self.network_slug);
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(
            Implementation::new(
                format!("{}-looking-glass", self.network_slug),
                env!("CARGO_PKG_VERSION"),
            )
            .with_description(format!("{} Looking Glass", self.network_slug)),
        )
        .with_instructions(format!(
            "Looking Glass for {} — query IXP switch and router state.\n\
             \n\
             Typical workflow to investigate a participant:\n\
             1. {prefix}__show_participants — list all ASNs and names\n\
             2. {prefix}__show_participant_detail(asn) — get port names and BGP peer IPs\n\
             3. {prefix}__show_interface_detail(interface) — per-port counters and link state\n\
             4. {prefix}__show_optics_detail(interface) — transceiver optical power levels\n\
             \n\
             For connectivity checks: {prefix}__ping / {prefix}__traceroute\n\
             Fabric-wide state: {prefix}__show_interfaces_status, {prefix}__show_lldp_neighbors",
            self.network_slug,
            prefix = format!("looking_glass__{}", self.network_slug),
        ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let prefix = format!("looking_glass__{}", self.network_slug);
        let tools = self.tool_router.list_all()
            .into_iter()
            .map(|mut t| {
                t.name = Cow::Owned(format!("{}__{}", prefix, t.name));
                t
            })
            .collect();
        Ok(ListToolsResult { tools, meta: None, next_cursor: None })
    }

    async fn call_tool(
        &self,
        mut request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let prefix = format!("looking_glass__{}__", self.network_slug);
        if let Some(bare) = request.name.strip_prefix(prefix.as_str()) {
            request.name = Cow::Owned(bare.to_string());
        }
        let tcc = ToolCallContext::new(self, request, context);
        self.tool_router.call(tcc).await
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        let prefix = format!("looking_glass__{}__", self.network_slug);
        let bare = name.strip_prefix(prefix.as_str()).unwrap_or(name);
        self.tool_router.get(bare).cloned()
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
