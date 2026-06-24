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
    /// Time-to-live (seconds) for a heard (ip, mac) entry. Entries not re-heard
    /// within this window are dropped from `/neighbors`, so the sensor reports
    /// only *currently-live* MACs and its memory stays bounded. `None` (default)
    /// disables decay (report everything since process start). Must be set well
    /// above lg-server's poll interval (recommended 1800) so even a brief
    /// conflict is present in many polls before it ages out.
    #[serde(default)]
    pub sensor_ttl_secs: Option<u64>,
    /// Directory for the rolling pcap ring buffer and extracted evidence pcaps.
    /// When unset (default), evidence capture is disabled entirely (no ring buffer,
    /// and the `/evidence*` endpoints report unavailable).
    #[serde(default)]
    pub evidence_dir: Option<String>,
    /// How many seconds of ARP/NDP frames the ring buffer retains. Default 1800.
    #[serde(default = "default_ring_buffer_secs")]
    pub ring_buffer_secs: u64,
    /// Hard byte cap on the ring buffer on disk (oldest chunks pruned first).
    /// Default 100 MiB.
    #[serde(default = "default_ring_buffer_max_bytes")]
    pub ring_buffer_max_bytes: u64,
    /// Hard byte cap on saved evidence pcaps (oldest pruned first). Default 500 MiB.
    #[serde(default = "default_evidence_max_bytes")]
    pub evidence_max_bytes: u64,
}

fn default_ring_buffer_secs() -> u64 {
    1800
}
fn default_ring_buffer_max_bytes() -> u64 {
    100 * 1024 * 1024
}
fn default_evidence_max_bytes() -> u64 {
    500 * 1024 * 1024
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
