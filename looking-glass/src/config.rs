use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
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
}

#[derive(Debug, Deserialize)]
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
    #[serde(default)]
    pub mcp: Option<McpListenConfig>,
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
}

#[derive(Debug, Deserialize)]
pub struct McpListenConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_mcp_bind")]
    pub bind: String,
    #[serde(default = "default_mcp_transport")]
    pub transport: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    pub oidc: OidcConfig,
}

#[derive(Debug, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_group_prefix")]
    pub group_prefix: String,
    #[serde(default = "default_admin_group")]
    pub admin_group: String,
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
pub struct RateLimitConfig {
    pub global: RateLimitTier,
    pub per_device: RateLimitTier,
    pub per_user: PerUserRateLimit,
}

#[derive(Debug, Deserialize)]
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
pub enum ParticipantsSourceConfig {
    File { file: String },
    Netbox { url: String, token_env: String },
}

#[derive(Debug, Deserialize)]
pub struct PolicySourceConfig {
    pub file: String,
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

fn default_group_prefix() -> String {
    "as".to_string()
}

fn default_admin_group() -> String {
    "IX Administrators".to_string()
}

fn default_ssh_port() -> u16 {
    22
}
