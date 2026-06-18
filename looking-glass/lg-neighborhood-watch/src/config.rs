use serde::Deserialize;

/// Sensor configuration (YAML at /etc/lg-neighborhood-watch/config.yml).
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// HTTP listen address for the query/metrics interface.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// lg-server RPC base URL (e.g. "http://127.0.0.1:9090").
    pub lg_rpc_url: String,
    /// Env var holding the shared RPC secret.
    #[serde(default = "default_rpc_secret_env")]
    pub lg_rpc_secret_env: String,
    /// Interfaces to capture on (VLAN subinterfaces, e.g. ["vlan998"]).
    pub interfaces: Vec<String>,
    /// How often (seconds) to refresh the assigned-IP list from lg-server.
    #[serde(default = "default_lg_poll_interval")]
    pub lg_poll_interval_secs: u64,
    /// How often (seconds) to solicit (ping) every assigned IP.
    #[serde(default = "default_solicit_interval")]
    pub solicit_interval_secs: u64,
    /// Delay (milliseconds) between individual solicit sends, to pace the sweep.
    #[serde(default = "default_solicit_pace_ms")]
    pub solicit_pace_ms: u64,
}

fn default_bind() -> String {
    "127.0.0.1:29185".to_string()
}
fn default_rpc_secret_env() -> String {
    "LG_RPC_SECRET".to_string()
}
fn default_lg_poll_interval() -> u64 {
    300
}
fn default_solicit_interval() -> u64 {
    60
}
fn default_solicit_pace_ms() -> u64 {
    5
}
