use std::sync::Arc;

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
use tracing::info;

use crate::command::{AddressFamily, Command, Resource, Verb};
use crate::frontend::telnet::TelnetState;
use crate::identity::Identity;
use crate::policy::PolicyDecision;

/// MCP (Model Context Protocol) frontend server.
///
/// Exposes the looking glass as an MCP server over streamable HTTP,
/// enabling LLM agents to query IXP state.
pub struct McpFrontend {
    bind_addr: String,
    state: Arc<TelnetState>,
}

impl McpFrontend {
    pub fn new(bind_addr: String, state: Arc<TelnetState>) -> Self {
        Self { bind_addr, state }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let state = self.state.clone();
        let ct = tokio_util::sync::CancellationToken::new();

        let config = StreamableHttpServerConfig {
            cancellation_token: ct.child_token(),
            stateful_mode: false,
            ..Default::default()
        };

        let service = StreamableHttpService::new(
            move || Ok(LookingGlassMcp::new(state.clone())),
            LocalSessionManager::default().into(),
            config,
        );

        let router = axum::Router::new().nest_service("/mcp", service);
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
    state: Arc<TelnetState>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl LookingGlassMcp {
    fn new(state: Arc<TelnetState>) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    /// Execute a parsed command through the policy engine, rate limiter, and device pool.
    async fn execute_command(&self, command: &Command) -> Result<String, McpError> {
        let identity = Identity::anonymous();

        if let PolicyDecision::Deny { reason } =
            self.state.policy.evaluate(command, &identity, &self.state.participants)
        {
            return Err(McpError::invalid_request(reason, None));
        }

        self.state
            .rate_limiter
            .acquire("global", "mcp")
            .await
            .map_err(|e| McpError::invalid_request(format!("rate limited: {e}"), None))?;

        self.state
            .device_pool
            .execute(command)
            .await
            .map_err(|e| McpError::internal_error(format!("device error: {e}"), None))
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
        };
        let output = self.execute_command(&cmd).await?;
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    /// Format the participant list as "AS<n> <name>" lines.
    fn format_participants(&self) -> String {
        let mut entries: Vec<_> = self.state.participants.all().collect();
        entries.sort_by_key(|p| p.asn);
        if entries.is_empty() {
            return "No participants configured.\n".to_string();
        }
        entries
            .iter()
            .map(|p| format!("AS{} {}", p.asn, p.name))
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
        };
        let output = self.execute_command(&cmd).await?;
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }
}

#[tool_handler]
impl ServerHandler for LookingGlassMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::default(),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
            server_info: Implementation {
                name: "sfmix-looking-glass".to_string(),
                title: None,
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: Some("SFMIX IXP Looking Glass".to_string()),
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "SFMIX Looking Glass — query IXP switch and router state. \
                 Available tools: show_interfaces_status, show_interface_detail, \
                 show_optics, show_optics_detail, show_bgp_summary, \
                 show_lldp_neighbors, show_arp_table, show_nd_table, \
                 show_participants, ping, traceroute."
                    .to_string(),
            ),
        }
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
            "ixp://participants" => Ok(ReadResourceResult {
                contents: vec![ResourceContents::text(
                    self.format_participants(),
                    request.uri,
                )],
            }),
            _ => Err(McpError::resource_not_found(
                "resource_not_found",
                Some(json!({ "uri": request.uri })),
            )),
        }
    }
}
