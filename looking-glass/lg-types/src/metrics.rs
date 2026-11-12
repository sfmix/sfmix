//! Time-series metrics RPC (`POST /rpc/v1/metrics`).
//!
//! lg-server resolves and authorizes the target, queries Prometheus, and
//! returns a [`MetricsReport`]; frontends only render it. Defaults keep the
//! output small: no `window.range_secs` means "latest reading only", and a
//! range returns per-series summary statistics unless `points` asks for the
//! raw (downsampled) series too.

use serde::{Deserialize, Serialize};

use crate::identity::Identity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsRequest {
    pub query: MetricsQuery,
    pub identity: Identity,
    pub rate_key: String,
}

/// What to measure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MetricsQuery {
    /// Traffic / errors / optics for one port, or every port of an ASN.
    Port {
        #[serde(default)]
        device: Option<String>,
        #[serde(default)]
        interface: Option<String>,
        #[serde(default)]
        asn: Option<u32>,
        /// Empty = all families.
        #[serde(default)]
        families: Vec<Family>,
        #[serde(default)]
        window: Window,
    },
    /// Both ends of a link (far end found via the cached LLDP table).
    Link {
        device: String,
        interface: String,
        #[serde(default)]
        families: Vec<Family>,
        #[serde(default)]
        window: Window,
    },
    /// Per-peer traffic from the sFlow peering matrix.
    Peers {
        asn: u32,
        #[serde(default)]
        peer_asn: Option<u32>,
        #[serde(default)]
        direction: PeerDirection,
        #[serde(default)]
        top: Option<usize>,
        #[serde(default)]
        window: Window,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Traffic,
    Errors,
    Optics,
}

impl Family {
    pub const ALL: [Family; 3] = [Family::Traffic, Family::Errors, Family::Optics];
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerDirection {
    /// Traffic the ASN sends to each peer.
    To,
    /// Traffic each peer sends to the ASN.
    From,
    #[default]
    Both,
}

/// Time window. All fields optional; the default is the latest reading.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Window {
    /// Look back this many seconds from `end`. `None` = latest reading only.
    #[serde(default)]
    pub range_secs: Option<u64>,
    /// End of the window (unix seconds). `None` = now.
    #[serde(default)]
    pub end: Option<i64>,
    /// Also return up to this many points per series (0/None = summary only).
    #[serde(default)]
    pub points: Option<u32>,
}

/// Summary of one series over the window. In latest mode only `last` is set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg: Option<f64>,
    /// 95th percentile of the per-step averages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    /// Counters only: total increase over the window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Series {
    /// Interface the series belongs to (a LAG's total uses the LAG name).
    pub interface: String,
    /// e.g. "traffic_in", "rx_dbm", "in_errors".
    pub metric: String,
    /// Optic lane ("1".."8") for per-lane optics; `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    /// "bps", "dBm", "mA", "C", "dB", "count".
    pub unit: String,
    pub stats: Stats,
    /// Per-step values aligned to `MetricsReport::start` + i * `step_secs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub points: Option<Vec<Option<f64>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortReport {
    pub device: String,
    pub interface: String,
    /// "participant port", "lag member", "core", "admin-only", "unclassified".
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_name: Option<String>,
    /// Interfaces measured for this port (LAG members, or the port itself).
    pub members: Vec<String>,
    /// Sum of member speeds in bps, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed_bps: Option<f64>,
    pub series: Vec<Series>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// One physical hop of a link: A side and (when resolvable) B side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkPair {
    pub a: PortReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub b: Option<PortReport>,
    /// Derived A↔B series: per-lane loss (A tx − B rx, B tx − A rx) and
    /// traffic deltas (A out − B in, B out − A in).
    pub derived: Vec<Series>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRow {
    pub peer_asn: u32,
    pub peer_name: String,
    /// "to" (ASN → peer) or "from" (peer → ASN).
    pub direction: String,
    pub stats: Stats,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub points: Option<Vec<Option<f64>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MetricsBody {
    Ports { ports: Vec<PortReport> },
    Link { pairs: Vec<LinkPair> },
    Peers {
        asn: u32,
        name: String,
        /// Top-N rows per direction, ranked by avg (range) or last (latest).
        rows: Vec<PeerRow>,
        /// Per direction: (direction, peers not shown, their combined stats).
        others: Vec<(String, usize, Stats)>,
        /// Per direction: (direction, all peers combined).
        totals: Vec<(String, Stats)>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsReport {
    /// Evaluation time (latest mode) or window end (unix seconds).
    pub end: i64,
    /// Window start; `None` in latest mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_secs: Option<u64>,
    pub body: MetricsBody,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}
