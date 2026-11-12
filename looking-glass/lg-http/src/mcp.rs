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
use looking_glass::metrics::{parse_duration, parse_time, render::render as render_metrics, MAX_POINTS};
use lg_types::metrics::{Family, MetricsQuery, MetricsRequest, PeerDirection, Window};

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

/// How long clients may treat list/read results as fresh (SEP-2549).
const RESULT_TTL_MS: u64 = 60_000;

/// Build the MCP axum router (mounted at `/mcp`).
///
/// `allowed_hosts` feeds rmcp's DNS-rebinding guard, which only admits
/// localhost by default and answers 403 to every other Host header. nginx
/// passes the public name through, so the public hostname must be listed.
pub fn router(
    rpc: RpcClient,
    ct: tokio_util::sync::CancellationToken,
    network_slug: String,
    allowed_hosts: Vec<String>,
) -> axum::Router {
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_cancellation_token(ct)
        .with_allowed_hosts(allowed_hosts);

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

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
struct FleetParams {
    /// Limit to one device hostname (e.g. "switch01.sfo02.sfmix.org"). Strongly
    /// recommended: unfiltered output covers every port on every switch.
    #[serde(default)]
    device: Option<String>,
    /// Limit to the ports of one participant ASN (e.g. 13335).
    #[serde(default)]
    asn: Option<u32>,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
struct OpticsParams {
    /// Limit to one device hostname (e.g. "switch01.sfo02.sfmix.org"). Strongly
    /// recommended: unfiltered output covers every port on every switch.
    #[serde(default)]
    device: Option<String>,
    /// Limit to the ports of one participant ASN (e.g. 13335).
    #[serde(default)]
    asn: Option<u32>,
    /// Also list ports with no transceiver or no DOM data (default false).
    #[serde(default)]
    include_empty: Option<bool>,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
struct DeviceParams {
    /// Limit to one device hostname (e.g. "switch01.sfo02.sfmix.org").
    #[serde(default)]
    device: Option<String>,
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

// --- Metrics tool parameters ---
//
// Every metrics tool defaults to the *latest* reading. `range` switches to a
// per-series summary (last/min/avg/p95/max) over that window; `points` adds
// the raw downsampled series and should only be used when a shape over time
// is actually needed.

#[derive(Debug, Clone, Copy, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum MetricFamily {
    /// Throughput in/out (bps) and utilisation.
    Traffic,
    /// Interface error and discard counters.
    Errors,
    /// Transceiver DOM: per-lane Rx/Tx dBm, bias mA, SNR (coherent), module temperature.
    Optics,
}

impl From<MetricFamily> for Family {
    fn from(f: MetricFamily) -> Self {
        match f {
            MetricFamily::Traffic => Family::Traffic,
            MetricFamily::Errors => Family::Errors,
            MetricFamily::Optics => Family::Optics,
        }
    }
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
struct PortMetricsParams {
    /// Device hostname (e.g. "switch02.sfo02.sfmix.org"); use with `interface`.
    #[serde(default)]
    device: Option<String>,
    /// Interface name (e.g. "Ethernet18/1", "Port-Channel111", "Port-Channel114.998").
    #[serde(default)]
    interface: Option<String>,
    /// Instead of device+interface: every port of this participant ASN.
    #[serde(default)]
    asn: Option<u32>,
    /// Limit to these metric families (default: all).
    #[serde(default)]
    families: Option<Vec<MetricFamily>>,
    /// Look-back window, e.g. "1h", "24h", "7d" (max 30d). Omit for the latest reading only.
    #[serde(default)]
    range: Option<String>,
    /// Window end (RFC 3339 or unix seconds). Default now. Without `range`, the reading at that time.
    #[serde(default)]
    end: Option<String>,
    /// With `range`: also return this many points per series (max 500). Omit unless you need the shape over time.
    #[serde(default)]
    points: Option<u32>,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
struct LinkMetricsParams {
    /// Device hostname of the A side (e.g. "switch01.sfo02.sfmix.org").
    device: String,
    /// A-side interface; a LAG is followed member by member.
    interface: String,
    /// Limit to these metric families (default: all).
    #[serde(default)]
    families: Option<Vec<MetricFamily>>,
    /// Look-back window, e.g. "1h", "24h", "7d" (max 30d). Omit for the latest reading only.
    #[serde(default)]
    range: Option<String>,
    /// Window end (RFC 3339 or unix seconds). Default now.
    #[serde(default)]
    end: Option<String>,
    /// With `range`: also return this many points per series (max 500).
    #[serde(default)]
    points: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum PeerDir {
    /// Traffic the ASN sends to each peer.
    To,
    /// Traffic each peer sends to the ASN.
    From,
    #[default]
    Both,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
struct PeerTrafficParams {
    /// Participant ASN whose peer traffic to show.
    asn: u32,
    /// Only this peer ASN.
    #[serde(default)]
    peer_asn: Option<u32>,
    /// "to", "from" or "both" (default).
    #[serde(default)]
    direction: Option<PeerDir>,
    /// Peers listed per direction, largest first (default 10, max 100); the rest are summed as "other".
    #[serde(default)]
    top: Option<u32>,
    /// Look-back window, e.g. "1h", "24h", "7d" (max 30d). Omit for the latest reading (1-minute average).
    #[serde(default)]
    range: Option<String>,
    /// Window end (RFC 3339 or unix seconds). Default now.
    #[serde(default)]
    end: Option<String>,
    /// With `range`: also return this many points per listed peer (max 500).
    #[serde(default)]
    points: Option<u32>,
}

fn metrics_window(range: Option<&str>, end: Option<&str>, points: Option<u32>) -> Result<Window, McpError> {
    let range_secs = match range {
        None => None,
        Some(r) => Some(parse_duration(r).ok_or_else(|| {
            McpError::invalid_params(format!("range {r:?}: expected e.g. \"90m\", \"24h\", \"7d\""), None)
        })?),
    };
    let end = match end {
        None => None,
        Some(e) => Some(parse_time(e).ok_or_else(|| {
            McpError::invalid_params(format!("end {e:?}: expected RFC 3339 or unix seconds"), None)
        })?),
    };
    Ok(Window { range_secs, end, points: points.map(|p| p.min(MAX_POINTS)) })
}

fn families(f: Option<Vec<MetricFamily>>) -> Vec<Family> {
    f.unwrap_or_default().into_iter().map(Family::from).collect()
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

    /// Execute a command via RPC and render the result as compact plain text
    /// (the same tables lg-cli prints over telnet), one block per device.
    /// Text tables are several times smaller than pretty-printed JSON, which
    /// matters: MCP clients cap tool results at a few tens of kilobytes.
    async fn execute_command(&self, command: &Command, include_empty: bool) -> Result<String, McpError> {
        use looking_glass::format::{render, ColorMode};
        use looking_glass::structured::CommandOutput as LocalOutput;
        use lg_types::structured::CommandOutput as RpcOutput;

        let mut rx = self
            .rpc
            .execute(command.clone(), self.identity.clone(), self.rate_key.clone())
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // (device, text) in arrival order; streaming lines accumulate per device.
        let mut blocks: Vec<(String, String)> = Vec::new();
        fn block<'a>(blocks: &'a mut Vec<(String, String)>, device: &str) -> &'a mut String {
            if let Some(i) = blocks.iter().position(|(d, _)| d == device) {
                &mut blocks[i].1
            } else {
                blocks.push((device.to_string(), String::new()));
                &mut blocks.last_mut().unwrap().1
            }
        }

        while let Some(event) = rx.recv().await {
            match event {
                ExecuteEvent::Result(r) => {
                    let text = match r.output {
                        RpcOutput::StreamLines(lines) => lines.join("\n") + "\n",
                        RpcOutput::Optics(mut entries) if !include_empty => {
                            entries.retain(|e| e.dom_supported && !e.lanes.is_empty());
                            render(&LocalOutput::from_rpc(RpcOutput::Optics(entries)), ColorMode::Plain)
                        }
                        other => render(&LocalOutput::from_rpc(other), ColorMode::Plain),
                    };
                    block(&mut blocks, &r.device).push_str(&text);
                }
                ExecuteEvent::StreamLine(sl) => {
                    let b = block(&mut blocks, &sl.device);
                    b.push_str(&sl.line);
                    b.push('\n');
                }
                ExecuteEvent::StreamEnd(_) => {}
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

        if blocks.is_empty() {
            return Ok("No output.\n".to_string());
        }
        if blocks.len() == 1 {
            return Ok(blocks.pop().unwrap().1);
        }
        let mut out = String::new();
        for (device, text) in blocks {
            out.push_str("== ");
            out.push_str(&device);
            out.push_str(" ==\n");
            out.push_str(&text);
            if !text.ends_with('\n') {
                out.push('\n');
            }
        }
        Ok(out)
    }

    /// Shorthand: build a Show command, execute it, and wrap the output.
    async fn run_show(
        &self,
        resource: Resource,
        target: Option<String>,
        af: AddressFamily,
        device: Option<String>,
        filter_asn: Option<u32>,
        include_empty: bool,
    ) -> Result<CallToolResult, McpError> {
        let cmd = Command {
            verb: Verb::Show,
            resource,
            target,
            device,
            address_family: af,
            filter_asn,
            filter_vlan: None,
            filter_source: None,
        };
        let output = self.execute_command(&cmd, include_empty).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(output)]))
    }

    /// Run a metrics query through lg-server and render it as text.
    async fn run_metrics(&self, query: MetricsQuery) -> Result<CallToolResult, McpError> {
        let req = MetricsRequest {
            query,
            identity: self.identity.clone(),
            rate_key: self.rate_key.clone(),
        };
        match self.rpc.metrics(&req).await {
            Ok(Ok(report)) => Ok(CallToolResult::success(vec![ContentBlock::text(render_metrics(&report))])),
            Ok(Err((400 | 403 | 429, msg))) => Err(McpError::invalid_request(msg, None)),
            Ok(Err((503, _))) => Err(McpError::internal_error("metrics are not configured on this looking glass", None)),
            Ok(Err((_, msg))) => Err(McpError::internal_error(msg, None)),
            Err(e) => Err(McpError::internal_error(e.to_string(), None)),
        }
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

    #[tool(description = "Interface status table (name, description, link state, speed, VLAN). \
        Pass device and/or asn to keep the output small; unfiltered it lists every port on every switch.")]
    async fn show_interfaces_status(
        &self,
        Parameters(params): Parameters<FleetParams>,
    ) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::InterfacesStatus, None, AddressFamily::IPv4, params.device, params.asn, true).await
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
        let output = self.execute_command(&cmd, true).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(output)]))
    }

    #[tool(description = "Transceiver optical levels (temperature, voltage, Tx/Rx power, bias) as one row per port. \
        Ports without a transceiver or DOM data are omitted unless include_empty is true. \
        Pass device and/or asn to keep the output small; for one port use show_optics_detail.")]
    async fn show_optics(
        &self,
        Parameters(params): Parameters<OpticsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::Optics, None, AddressFamily::IPv4, params.device, params.asn, params.include_empty.unwrap_or(false)).await
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
        let output = self.execute_command(&cmd, true).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(output)]))
    }

    #[tool(description = "LLDP neighbour table (local port, neighbour device, neighbour port). Pass device to limit to one switch.")]
    async fn show_lldp_neighbors(
        &self,
        Parameters(params): Parameters<DeviceParams>,
    ) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::LldpNeighbors, None, AddressFamily::IPv4, params.device, None, true).await
    }

    #[tool(description = "List IXP participants with their ASN and name")]
    async fn show_participants(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text(self.format_participants().await)]))
    }

    #[tool(description = "List the IXP peering LANs: VLAN ID, name, and IPv4/IPv6 prefixes")]
    async fn show_peering_vlans(&self) -> Result<CallToolResult, McpError> {
        self.run_show(Resource::PeeringVlans, None, AddressFamily::IPv4, None, None, true).await
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
                                .and_then(|a| Some((a.first()?.as_str()?, a.get(1)?.as_str()?)))?;
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

                Ok(CallToolResult::success(vec![ContentBlock::text(lines.join("\n"))]))
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

    #[tool(description = "Port metrics from the fabric's time-series store: throughput (bps, utilisation), \
        error/discard counters, and optics (per-lane Rx/Tx dBm, bias mA, SNR for coherent optics, module temperature). \
        Give device+interface, or asn for all of a participant's ports (LAGs are broken out per member with a total). \
        Default is the LATEST reading only (traffic = 1-minute average, errors = count over the last 15 minutes). \
        Pass range (e.g. \"24h\") for a per-series summary (last/min/avg/p95/max; counters: total and max per step). \
        Only pass points when you need the shape over time. Use families to fetch less. \
        Participants may query their own ports; infrastructure ports require admin.")]
    async fn port_metrics(
        &self,
        Parameters(p): Parameters<PortMetricsParams>,
    ) -> Result<CallToolResult, McpError> {
        let window = metrics_window(p.range.as_deref(), p.end.as_deref(), p.points)?;
        self.run_metrics(MetricsQuery::Port {
            device: p.device,
            interface: p.interface,
            asn: p.asn,
            families: families(p.families),
            window,
        })
        .await
    }

    #[tool(description = "Both ends of a link side by side. Follows the A-side interface (each LAG member) to its \
        LLDP neighbour and, when that is another looking-glass device, returns traffic, errors and optics for both ends \
        plus derived values: per-lane optical loss (A tx - B rx and B tx - A rx, dB) and sent-minus-received throughput \
        in each direction. Use this to tell a dirty/attenuated span from a failing transmitter, or to spot one-sided errors. \
        Same latest/range/points semantics as port_metrics. Far ends that are participant routers are not measurable.")]
    async fn link_metrics(
        &self,
        Parameters(p): Parameters<LinkMetricsParams>,
    ) -> Result<CallToolResult, McpError> {
        let window = metrics_window(p.range.as_deref(), p.end.as_deref(), p.points)?;
        self.run_metrics(MetricsQuery::Link {
            device: p.device,
            interface: p.interface,
            families: families(p.families),
            window,
        })
        .await
    }

    #[tool(description = "Per-peer traffic for a participant ASN from the sFlow peering matrix (bps): who it sends to \
        and receives from across the exchange, top N peers per direction plus an 'other' row and a total. \
        Default is the latest 1-minute average; pass range for avg/p95/max/last per peer, and points only if you need \
        the series. Filter to one counterpart with peer_asn. Participants may query their own ASN; admins any.")]
    async fn peer_traffic(
        &self,
        Parameters(p): Parameters<PeerTrafficParams>,
    ) -> Result<CallToolResult, McpError> {
        let window = metrics_window(p.range.as_deref(), p.end.as_deref(), p.points)?;
        let direction = match p.direction.unwrap_or_default() {
            PeerDir::To => PeerDirection::To,
            PeerDir::From => PeerDirection::From,
            PeerDir::Both => PeerDirection::Both,
        };
        self.run_metrics(MetricsQuery::Peers {
            asn: p.asn,
            peer_asn: p.peer_asn,
            direction,
            top: p.top.map(|t| t as usize),
            window,
        })
        .await
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
        let output = self.execute_command(&cmd, true).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(output)]))
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
        let output = self.execute_command(&cmd, true).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(output)]))
    }
}

impl ServerHandler for McpHandler {
    fn get_info(&self) -> ServerConfig {
        let prefix = format!("looking_glass__{}", self.network_slug);
        ServerConfig::new(
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
             Fabric-wide state: {prefix}__show_interfaces_status, {prefix}__show_lldp_neighbors, \
             {prefix}__show_peering_vlans\n\
             \n\
             History and statistics (latest reading by default; add range=\"24h\" etc. for a summary):\n\
             - {prefix}__port_metrics(device+interface | asn) - traffic, errors, optics\n\
             - {prefix}__link_metrics(device, interface) - both ends of a link via LLDP, with optical loss\n\
             - {prefix}__peer_traffic(asn) - per-peer sFlow traffic",
            self.network_slug,
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
        // Protocol 2026-07-28 (SEP-2549) requires ttlMs and cacheScope on list
        // results; clients that validate strictly (Claude Code before 2.1.3xx)
        // reject the response without them. The list is static per build but
        // tool visibility follows the caller's identity, so keep it private.
        Ok(ListToolsResult::with_all_items(tools)
            .with_ttl_ms(RESULT_TTL_MS)
            .with_cache_scope(CacheScope::Private))
    }

    async fn call_tool(
        &self,
        mut request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
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
        Ok(ListResourcesResult::with_all_items(vec![
            rmcp::model::Resource::new("ixp://participants", "IXP Participants".to_string()),
        ])
        .with_ttl_ms(RESULT_TTL_MS)
        .with_cache_scope(CacheScope::Private))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        match request.uri.as_str() {
            "ixp://participants" => Ok(ReadResourceResult::new(vec![ResourceContents::text(
                self.format_participants().await,
                request.uri,
            )])
            .with_ttl_ms(RESULT_TTL_MS)
            .with_cache_scope(CacheScope::Private)
            .into()),
            _ => Err(McpError::resource_not_found(
                "resource_not_found",
                Some(json!({ "uri": request.uri })),
            )),
        }
    }
}
