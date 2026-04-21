use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

/// Configuration for the lg-server RPC backend.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub service: looking_glass::config::ServiceConfig,
    pub site: looking_glass::config::SiteConfig,
    pub rpc: RpcConfig,
    #[serde(default)]
    pub auth: Option<looking_glass::config::AuthConfig>,
    #[serde(default)]
    pub devices: Vec<looking_glass::config::DeviceConfig>,
    #[serde(default)]
    pub rate_limits: Option<looking_glass::config::RateLimitConfig>,
    #[serde(default)]
    pub participants: Option<looking_glass::config::ParticipantsSourceConfig>,
    #[serde(default)]
    pub policies: Option<looking_glass::config::PolicySourceConfig>,
    #[serde(default)]
    pub vlans: looking_glass::config::VlanVisibilityConfig,
    #[serde(default)]
    pub bgp_sources: Vec<looking_glass::config::BgpSourceConfig>,
}

#[derive(Debug, Deserialize)]
pub struct RpcConfig {
    #[serde(default = "default_rpc_bind")]
    pub bind: String,
    /// Name of the environment variable holding the shared secret.
    #[serde(default = "default_secret_env")]
    pub secret_env: String,
}

fn default_secret_env() -> String {
    "LG_RPC_SECRET".to_string()
}

fn default_rpc_bind() -> String {
    "127.0.0.1:9090".to_string()
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: ServerConfig = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
}
