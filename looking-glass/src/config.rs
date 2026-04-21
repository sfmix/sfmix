use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Config {
    pub service: ServiceConfig,
    pub site: SiteConfig,
    pub listen: ListenConfig,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub devices: Vec<DeviceConfig>,
    #[serde(default)]
    pub rate_limits: Option<RateLimitConfig>,
    #[serde(default)]
    pub participants: Option<ParticipantsSourceConfig>,
    #[serde(default)]
    pub policies: Option<PolicySourceConfig>,
    #[serde(default)]
    pub frontend_limits: Option<FrontendLimitsConfig>,
    #[serde(default)]
    pub vlans: VlanVisibilityConfig,
    #[serde(default)]
    pub bgp_sources: Vec<BgpSourceConfig>,
}

/// VLAN visibility configuration for MAC address table output.
///
/// Public VLANs are visible to all users. Everything else is private
/// and only visible to IX Administrators.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct VlanVisibilityConfig {
    /// VLAN IDs visible to all users (e.g. ["998", "999"]).
    #[serde(default)]
    pub public: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ServiceConfig {
    pub name: String,
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub operator_url: Option<String>,
    #[serde(default)]
    pub peeringdb_ix_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SiteConfig {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    #[serde(default)]
    pub telnet: Option<TelnetListenConfig>,
    #[serde(default)]
    pub ssh: Option<SshListenConfig>,
    /// Unified HTTP frontend serving REST API + MCP on a single port.
    #[serde(default)]
    pub http: Option<HttpListenConfig>,
    /// Deprecated: use `http` instead. Kept for backward compatibility.
    #[serde(default)]
    pub mcp: Option<McpListenConfig>,
    /// Deprecated: use `http` instead. Kept for backward compatibility.
    #[serde(default)]
    pub rest: Option<RestListenConfig>,
}

#[derive(Debug, Deserialize)]
pub struct TelnetListenConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_telnet_bind")]
    pub bind: String,
}

#[derive(Debug, Deserialize)]
pub struct SshListenConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_ssh_bind")]
    pub bind: String,
    pub host_key: String,
    /// Path to the SSH CA private key used for signing user certificates.
    /// If absent, certificate issuance is disabled (login command won't inject certs).
    #[serde(default)]
    pub ca_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct McpListenConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_mcp_bind")]
    pub bind: String,
    #[serde(default = "default_mcp_transport")]
    pub transport: String,
}

#[derive(Debug, Deserialize)]
pub struct HttpListenConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_http_bind")]
    pub bind: String,
}

#[derive(Debug, Deserialize)]
pub struct RestListenConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_rest_bind")]
    pub bind: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AuthConfig {
    pub oidc: OidcConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_group_prefix")]
    pub group_prefix: String,
    #[serde(default = "default_admin_group")]
    pub admin_group: String,
    /// Additional audiences to accept for cross-service token verification.
    /// Tokens with `aud` matching client_id OR any value in this list are accepted.
    /// e.g. ["portal"] to accept tokens issued for the portal app.
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
    /// Additional issuers to accept for cross-service token verification.
    /// Tokens with `iss` matching issuer OR any value in this list are accepted.
    /// e.g. ["https://login.sfmix.org/application/o/portal/"] for portal tokens.
    #[serde(default)]
    pub allowed_issuers: Vec<String>,
    /// Device authorization endpoint (RFC 8628).
    /// e.g. "https://login.sfmix.org/application/o/device/"
    #[serde(default)]
    pub device_auth_endpoint: Option<String>,
    /// Token endpoint for polling device auth grant.
    /// e.g. "https://login.sfmix.org/application/o/token/"
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// JWKS URI for verifying id_token signatures.
    /// If not set, derived from issuer's .well-known/openid-configuration.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Authorization server URL for OAuth Protected Resource Metadata (RFC 9728).
    /// e.g. "https://login.sfmix.org/application/o/looking-glass-api/"
    /// Used by MCP clients to discover where to obtain tokens.
    #[serde(default)]
    pub authorization_server: Option<String>,
    /// This server's public base URL, used to construct the resource metadata URL.
    /// e.g. "https://lg-ng.sfmix.org"
    /// Used in WWW-Authenticate headers to direct clients to /.well-known/oauth-protected-resource.
    #[serde(default)]
    pub resource_url: Option<String>,
    /// OAuth2 authorization endpoint (e.g. Authentik's authorize URL).
    /// e.g. "https://login.sfmix.org/application/o/authorize/"
    /// Advertised in /.well-known/oauth-authorization-server for MCP clients.
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    /// Public OAuth2 client_id to hand out via Dynamic Client Registration.
    /// e.g. "looking-glass"
    /// MCP clients that don't have a pre-registered client_id will receive this.
    #[serde(default)]
    pub mcp_client_id: Option<String>,
    /// Lifetime of issued SSH certificates in seconds (default: 43200 = 12h).
    #[serde(default = "default_cert_lifetime")]
    pub cert_lifetime_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceConfig {
    pub name: String,
    pub platform: Platform,
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub username: String,
    #[serde(default)]
    pub auth_method: DeviceAuthMethod,
    #[serde(default)]
    pub ssh_key: Option<String>,
    /// Expected SSH host key fingerprint (e.g. "SHA256:abc123...").
    /// If set, connections to this device will be rejected if the host key
    /// doesn't match. If unset, all host keys are accepted (TOFU model).
    #[serde(default)]
    pub host_key_fingerprint: Option<String>,
    /// Timeout in seconds for command execution (output collection).
    /// Defaults to 15s. Increase for devices with large output (e.g. Nokia SR-OS
    /// `show port` can produce megabytes of JSON).
    #[serde(default = "default_command_timeout")]
    pub command_timeout_secs: u64,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    AristaEos,
    NokiaSros,
}

#[derive(Debug, Default, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAuthMethod {
    #[default]
    SshKey,
    Password,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RateLimitConfig {
    pub global: RateLimitTier,
    pub per_device: RateLimitTier,
    pub per_user: PerUserRateLimit,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RateLimitTier {
    pub max_concurrent: u32,
    pub commands_per_minute: u32,
}

#[derive(Debug, Deserialize)]
pub struct PerUserRateLimit {
    pub commands_per_minute: u32,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum ParticipantsSourceConfig {
    /// Load participants from a static YAML file.
    File { file: String },
    /// Fetch participants + ports from NetBox GraphQL at startup and periodically.
    Netbox {
        url: String,
        token_env: String,
        #[serde(default = "default_refresh_interval")]
        refresh_interval_secs: u64,
        /// Domain suffix appended to short NetBox device names (e.g. "sfmix.org").
        /// If unset, device names are used as-is from NetBox.
        #[serde(default)]
        domain_suffix: Option<String>,
    },
}

fn default_refresh_interval() -> u64 {
    300
}

fn default_bgp_refresh_interval() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize)]
pub struct BgpSourceConfig {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub source_type: BgpSourceType,
    pub api: String,
    #[serde(default = "default_bgp_refresh_interval")]
    pub refresh_interval_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BgpSourceType {
    Birdwatcher,
    Bgplgd,
}

#[derive(Debug, Deserialize)]
pub struct PolicySourceConfig {
    pub file: String,
}

#[derive(Debug, Deserialize)]
pub struct FrontendLimitsConfig {
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_max_connections_per_source")]
    pub max_connections_per_source: u32,
}

fn default_idle_timeout_secs() -> u64 {
    300
}

fn default_max_connections() -> u32 {
    50
}

fn default_max_connections_per_source() -> u32 {
    5
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
}

fn default_true() -> bool {
    true
}

fn default_telnet_bind() -> String {
    "[::]:23".to_string()
}

fn default_ssh_bind() -> String {
    "[::]:2222".to_string()
}

fn default_mcp_bind() -> String {
    "[::]:8080".to_string()
}

fn default_mcp_transport() -> String {
    "sse".to_string()
}

fn default_http_bind() -> String {
    "[::]:8080".to_string()
}

fn default_rest_bind() -> String {
    "[::]:8081".to_string()
}

fn default_group_prefix() -> String {
    "as".to_string()
}

/// Default admin group name used when no OIDC config is present.
pub const DEFAULT_ADMIN_GROUP: &str = "IX Administrators";

fn default_admin_group() -> String {
    DEFAULT_ADMIN_GROUP.to_string()
}

fn default_cert_lifetime() -> u64 {
    43200 // 12 hours
}

fn default_command_timeout() -> u64 {
    15
}

fn default_ssh_port() -> u16 {
    22
}
