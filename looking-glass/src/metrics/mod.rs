//! Time-series metrics from Prometheus: port traffic/errors/optics, both ends
//! of a link, and per-peer sFlow traffic.
//!
//! lg-server owns resolution and authorization here; frontends send a
//! [`MetricsRequest`] and render the [`MetricsReport`] (see [`render`]).
//!
//! Sources (all on the fabric Prometheus):
//! * traffic — sFlow-RT `sflow_if{in,out}octets` gauges (bytes/s, physical
//!   ports and LAG members); subinterfaces use SNMP `ifHC{In,Out}Octets` rates
//!   because sFlow-RT exports no per-subif counters.
//! * errors — SNMP `if{In,Out}{Errors,Discards}` counters.
//! * optics — SNMP ENTITY-SENSOR `entPhySensorValue`, keyed by
//!   `entPhysicalName = "DOM <kind> Sensor for <port>"`. EOS units: power
//!   0.1 µW, bias 10 µA, temperature 0.1 °C, SNR 0.01 dB (its scale/precision
//!   columns disagree, so they are not used). -1e9 means "no reading". An `X/1`
//!   port owns lane sensors `X/2..X/9` unless those are interfaces themselves
//!   (breakouts); module temperature is named for the base port `X`.
//! * peers — sFlow-RT ixp-metrics `sflow_ixp_peering_bps{src_asn,dst_asn}`
//!   (bits/s, top 1000 pairs).

pub mod prom;
pub mod render;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use futures::future::try_join_all;
use lg_types::metrics::*;

use crate::config::MetricsConfig;
use crate::identity::Identity;
use crate::netbox::{EnrichedPort, NetboxParticipant};
use crate::participants::{ParticipantMap, PortClass, PortMap};
use crate::service::LookingGlass;
use crate::structured::LldpNeighbor;
use prom::{alternation, esc, re_esc, Labels, PromClient};

/// Smallest step for range queries: SNMP is scraped every 60–120 s.
const MIN_STEP: u64 = 120;
/// Steps used to summarise a range when no points were requested.
const SUMMARY_STEPS: u64 = 240;
/// Hard cap on points per series.
pub const MAX_POINTS: u32 = 500;
/// Counter window for "latest" error counts.
pub const LATEST_COUNTER_WINDOW: u64 = 900;
const DEFAULT_TOP_PEERS: usize = 10;
const MAX_TOP_PEERS: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    #[error("{0}")]
    Denied(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("metrics backend error: {0}")]
    Backend(String),
}

impl From<anyhow::Error> for MetricsError {
    fn from(e: anyhow::Error) -> Self {
        MetricsError::Backend(e.to_string())
    }
}

type Res<T> = Result<T, MetricsError>;

/// Snapshot of the LG state a metrics query resolves against.
pub struct Ctx<'a> {
    pub nb: &'a [NetboxParticipant],
    pub pmap: &'a PortMap,
    pub participants: &'a ParticipantMap,
    pub admin_group: &'a str,
    /// Cached LLDP neighbours per LG device.
    pub lldp: &'a HashMap<String, Vec<LldpNeighbor>>,
}

pub struct MetricsService {
    prom: PromClient,
    cfg: MetricsConfig,
}

// ── Window ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct Win {
    end: i64,
    /// (start, step) for a range; `None` = latest reading at `end`.
    range: Option<(i64, u64)>,
    points: bool,
}

impl Win {
    fn len(&self) -> usize {
        match self.range {
            None => 1,
            Some((start, step)) => ((self.end - start) / step as i64) as usize + 1,
        }
    }

    fn latest(&self) -> bool {
        self.range.is_none()
    }

    fn span(&self) -> u64 {
        self.range.map(|(s, _)| (self.end - s) as u64).unwrap_or(0)
    }

    #[cfg(test)]
    fn step(&self) -> u64 {
        self.range.map(|(_, s)| s).unwrap_or(0)
    }
}

fn resolve_window(w: &Window, max_range: u64, now: i64) -> Res<Win> {
    let end = w.end.unwrap_or(now).min(now);
    if end < now - max_range as i64 {
        return Err(MetricsError::BadRequest(format!(
            "end is older than the {}-day retention",
            max_range / 86400
        )));
    }
    let range = match w.range_secs {
        None | Some(0) => return Ok(Win { end, range: None, points: false }),
        Some(r) => r,
    };
    if range > max_range {
        return Err(MetricsError::BadRequest(format!(
            "range is limited to {} days",
            max_range / 86400
        )));
    }
    if range < 2 * MIN_STEP {
        return Err(MetricsError::BadRequest(format!(
            "range must be at least {}s (omit it for the latest reading)",
            2 * MIN_STEP
        )));
    }
    let want = match w.points {
        Some(p) if p > 0 => p.min(MAX_POINTS) as u64,
        _ => SUMMARY_STEPS,
    };
    let step = range.div_ceil(want).max(MIN_STEP).div_ceil(60) * 60;
    // Align to the step so repeated queries hit the same grid.
    let end = end - end.rem_euclid(step as i64);
    let start = end - ((range / step) * step) as i64;
    Ok(Win { end, range: Some((start, step)), points: w.points.unwrap_or(0) > 0 })
}

/// Parse "90s", "15m", "24h", "7d", "2w" or bare seconds.
pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = match s.char_indices().last()? {
        (i, 's') => (&s[..i], 1),
        (i, 'm') => (&s[..i], 60),
        (i, 'h') => (&s[..i], 3600),
        (i, 'd') => (&s[..i], 86400),
        (i, 'w') => (&s[..i], 7 * 86400),
        _ => (s, 1),
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// Parse an RFC 3339 timestamp or unix seconds.
pub fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|t| t.timestamp())
}

// ── Grids and stats ─────────────────────────────────────────────────────

type Col = Vec<Option<f64>>;

#[derive(Debug, Clone, Default)]
struct Grid {
    avg: Col,
    min: Option<Col>,
    max: Option<Col>,
}

impl Grid {
    fn map(&self, f: impl Fn(f64) -> Option<f64> + Copy) -> Grid {
        let m = |c: &Col| c.iter().map(|v| v.and_then(f)).collect::<Col>();
        Grid { avg: m(&self.avg), min: self.min.as_ref().map(m), max: self.max.as_ref().map(m) }
    }
}

fn zip_col(a: &Col, b: &Col, f: impl Fn(f64, f64) -> f64) -> Col {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| match (x, y) {
            (Some(x), Some(y)) => Some(f(*x, *y)),
            _ => None,
        })
        .collect()
}

/// Element-wise sum; a slot is `None` only when every input is `None`.
fn sum_cols<'a>(cols: impl IntoIterator<Item = &'a Col>, len: usize) -> Col {
    let mut out: Col = vec![None; len];
    for c in cols {
        for (o, v) in out.iter_mut().zip(c.iter()) {
            if let Some(v) = v {
                *o = Some(o.unwrap_or(0.0) + v);
            }
        }
    }
    out
}

fn percentile(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted.get(idx).copied()
}

fn gauge_stats(g: &Grid, win: &Win) -> Stats {
    let last = g.avg.iter().rev().find_map(|v| *v);
    if win.latest() {
        return Stats { last, ..Default::default() };
    }
    let mut vals: Vec<f64> = g.avg.iter().flatten().copied().collect();
    vals.sort_by(|a, b| a.total_cmp(b));
    let fold = |c: Option<&Col>, pick: fn(f64, f64) -> f64| {
        c.and_then(|c| c.iter().flatten().copied().reduce(pick))
    };
    Stats {
        last,
        avg: (!vals.is_empty()).then(|| vals.iter().sum::<f64>() / vals.len() as f64),
        p95: percentile(&vals, 0.95),
        min: fold(g.min.as_ref(), f64::min).or_else(|| vals.first().copied()),
        max: fold(g.max.as_ref(), f64::max).or_else(|| vals.last().copied()),
        total: None,
    }
}

fn counter_stats(g: &Grid, total: Option<f64>, win: &Win) -> Stats {
    if win.latest() {
        return Stats { total, ..Default::default() };
    }
    Stats {
        total,
        max: g.avg.iter().flatten().copied().reduce(f64::max),
        ..Default::default()
    }
}

/// One measured series before it is summarised.
#[derive(Debug, Clone)]
struct Data {
    interface: String,
    metric: &'static str,
    lane: Option<String>,
    unit: &'static str,
    grid: Grid,
    /// `Some` marks a counter (total increase over the window).
    total: Option<Option<f64>>,
}

impl Data {
    fn finish(&self, win: &Win) -> Series {
        let stats = match self.total {
            Some(total) => counter_stats(&self.grid, total, win),
            None => gauge_stats(&self.grid, win),
        };
        Series {
            interface: self.interface.clone(),
            metric: self.metric.to_string(),
            lane: self.lane.clone(),
            unit: self.unit.to_string(),
            stats,
            points: win.points.then(|| self.grid.avg.clone()),
        }
    }
}

// ── Target resolution + authorization ───────────────────────────────────
//
// Tenant isolation mirrors the portal's participant metrics exactly
// (portal/dashboard/views.py: `participant_metrics`, `_metric_port`,
// `_port_members`, `_if_counters_queries`), and reads the same data: the
// NetBox `enriched_ports` the portal fetches from this LG.
//
// * Who: authenticated, and IX Administrators or a member of `as<ASN>`.
// * What: a non-admin can only reach ports built *forward* from the
//   `enriched_ports` of an ASN in their identity (or one of those ports'
//   `member_interfaces`). Nothing is resolved backwards from an
//   interface name to an owner, and no PortMap heuristics are used.
// * How a port is measured:
//   - A subinterface's traffic comes from its own counters. Its physical
//     members are exactly NetBox's `member_interfaces`, which NetBox leaves
//     empty for encapsulated subinterfaces riding another network's port.
//     A parent port is never derived from the name.
//   - Any other port is its members, or the port itself.
// * Shared transceivers: lanes and module sensors of a transceiver that is
//   broken out to other interfaces are never attributed to a tenant.
// * Denials: a refusal never says whether an interface exists or who owns it.
// * Admins: IX Administrators may also name infrastructure ports.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Src {
    /// sFlow-RT gauge (physical ports, LAGs).
    Sflow,
    /// SNMP ifHC octet counter rate (subinterfaces).
    Snmp,
}

#[derive(Debug, Clone)]
struct Resolved {
    device: String,
    interface: String,
    role: String,
    owner_asn: Option<u32>,
    owner_name: Option<String>,
    /// Interfaces whose throughput is measured (device, ifname, source).
    traffic: Vec<(String, String, Src)>,
    /// Physical interfaces measured for errors and optics.
    phys: Vec<(String, String)>,
    /// `X/2..X/9` siblings of `phys` entries that NetBox knows as interfaces
    /// (breakouts, possibly another tenant's): never attributed as lanes.
    breakouts: HashSet<(String, String)>,
    notes: Vec<String>,
}

fn valid_name(s: &str, extra: &str) -> bool {
    !s.is_empty()
        && s.len() <= 96
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c) || extra.contains(c))
}

/// The same uniform refusal for another tenant's port, an infrastructure
/// port, and a name that does not exist.
fn not_yours(device: &str, interface: &str) -> MetricsError {
    MetricsError::Denied(format!("{device} {interface} is not one of your ports"))
}

/// Every (device, interface) NetBox knows, for breakout-lane exclusion.
fn known_interfaces(nb: &[NetboxParticipant], pmap: &PortMap) -> HashSet<(String, String)> {
    let mut known: HashSet<(String, String)> = pmap.iter().map(|(k, _)| k.clone()).collect();
    for p in nb {
        known.extend(p.ports.iter().cloned());
        for ep in &p.enriched_ports {
            known.insert((ep.device.clone(), ep.interface.clone()));
            known.extend(ep.member_interfaces.iter().cloned());
        }
    }
    known
}

fn with_breakouts(mut r: Resolved, known: &HashSet<(String, String)>) -> Resolved {
    for (d, i) in &r.phys {
        if let Some((_, sibs)) = siblings(i) {
            for s in sibs {
                if known.contains(&(d.clone(), s.clone())) {
                    r.breakouts.insert((d.clone(), s));
                }
            }
        }
    }
    r
}

/// A tenant's NetBox port, measured as the portal measures it.
fn tenant_port(p: &NetboxParticipant, ep: &EnrichedPort) -> Resolved {
    let members: Vec<(String, String)> = ep
        .member_interfaces
        .iter()
        .filter(|(d, i)| !d.is_empty() && !i.is_empty())
        .cloned()
        .collect();
    let mut notes = vec![];
    let (traffic, phys) = if ep.interface.contains('.') {
        if members.is_empty() {
            notes.push("subinterface with no physical members of its own (e.g. encapsulated on another network's port): only its own traffic is shown".into());
        }
        (vec![(ep.device.clone(), ep.interface.clone(), Src::Snmp)], members)
    } else if !members.is_empty() {
        (members.iter().map(|(d, i)| (d.clone(), i.clone(), Src::Sflow)).collect(), members)
    } else {
        (
            vec![(ep.device.clone(), ep.interface.clone(), Src::Sflow)],
            vec![(ep.device.clone(), ep.interface.clone())],
        )
    };
    Resolved {
        device: ep.device.clone(),
        interface: ep.interface.clone(),
        role: "participant port".into(),
        owner_asn: Some(p.asn),
        owner_name: Some(p.name.clone()),
        traffic,
        phys,
        breakouts: HashSet::new(),
        notes,
    }
}

/// Find `device interface` among the ports (or their physical members) of
/// participants accepted by `visible`, building forward from NetBox.
fn tenant_lookup(
    nb: &[NetboxParticipant],
    visible: impl Fn(u32) -> bool,
    device: &str,
    interface: &str,
) -> Option<Resolved> {
    let mine = || nb.iter().filter(|p| visible(p.asn));
    for p in mine() {
        if let Some(ep) = p.enriched_ports.iter().find(|ep| ep.device == device && ep.interface == interface) {
            return Some(tenant_port(p, ep));
        }
    }
    for p in mine() {
        for ep in &p.enriched_ports {
            if ep.member_interfaces.iter().any(|(d, i)| d == device && i == interface) {
                return Some(Resolved {
                    device: device.to_string(),
                    interface: interface.to_string(),
                    role: format!("member of {}", ep.interface),
                    owner_asn: Some(p.asn),
                    owner_name: Some(p.name.clone()),
                    traffic: vec![(device.to_string(), interface.to_string(), Src::Sflow)],
                    phys: vec![(device.to_string(), interface.to_string())],
                    breakouts: HashSet::new(),
                    notes: vec![],
                });
            }
        }
    }
    None
}

/// Resolve `device interface` for `identity`, or refuse.
fn resolve_for(ctx: &Ctx<'_>, known: &HashSet<(String, String)>, identity: &Identity, device: &str, interface: &str) -> Res<Resolved> {
    if !valid_name(device, "") || !valid_name(interface, "/:") {
        return Err(MetricsError::BadRequest("invalid device or interface name".into()));
    }
    if !identity.authenticated {
        return Err(not_yours(device, interface));
    }
    let admin = identity.is_admin(ctx.admin_group);
    if let Some(r) = tenant_lookup(ctx.nb, |asn| admin || identity.has_asn(asn), device, interface) {
        return Ok(with_breakouts(r, known));
    }
    if !admin {
        return Err(not_yours(device, interface));
    }
    // IX Administrators: infrastructure and anything else on the fabric.
    let role = match ctx.pmap.classify(device, interface) {
        Some(PortClass::Core) => "core".to_string(),
        Some(PortClass::AdminOnly) => "admin-only".to_string(),
        Some(PortClass::Participant { asn }) => format!("participant AS{asn} (not a NetBox peering port)"),
        None => "unclassified".to_string(),
    };
    let mut notes = vec![];
    let (traffic, phys) = if interface.contains('.') {
        (vec![(device.to_string(), interface.to_string(), Src::Snmp)], vec![])
    } else if interface.starts_with("Port-Channel") {
        notes.push("LAG members unknown; query a member for errors/optics".into());
        (vec![(device.to_string(), interface.to_string(), Src::Sflow)], vec![])
    } else {
        (
            vec![(device.to_string(), interface.to_string(), Src::Sflow)],
            vec![(device.to_string(), interface.to_string())],
        )
    };
    let r = Resolved {
        device: device.to_string(),
        interface: interface.to_string(),
        role,
        owner_asn: None,
        owner_name: None,
        traffic,
        phys,
        breakouts: HashSet::new(),
        notes,
    };
    Ok(with_breakouts(r, known))
}

fn authorize_asn(identity: &Identity, admin_group: &str, asn: u32) -> Res<()> {
    if identity.authenticated && (identity.is_admin(admin_group) || identity.has_asn(asn)) {
        Ok(())
    } else {
        Err(MetricsError::Denied(format!("you do not administer AS{asn}")))
    }
}

/// Match an LLDP system name to an LG device name ("switch01.fmt01" ↔
/// "switch01.fmt01.sfmix.org").
fn match_device<'a>(devices: impl IntoIterator<Item = &'a String>, neighbor: &str) -> Option<String> {
    let n = neighbor.trim().trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() {
        return None;
    }
    devices
        .into_iter()
        .find(|d| {
            let d = d.to_ascii_lowercase();
            d == n || d.starts_with(&format!("{n}.")) || n.starts_with(&format!("{d}."))
        })
        .cloned()
}

// ── Optics sensor naming ────────────────────────────────────────────────

/// The transceiver a port's module-level sensors are named for:
/// "Ethernet18/1" → "Ethernet18"; "Ethernet1" → "Ethernet1".
fn module_of(ifname: &str) -> &str {
    match ifname.rsplit_once('/') {
        Some((base, last)) if last.chars().all(|c| c.is_ascii_digit()) && base.starts_with("Ethernet") => base,
        _ => ifname,
    }
}

/// Lane label: last `/N` component, or "1" for an unsplit port.
fn lane_of(name: &str) -> String {
    match name.rsplit_once('/') {
        Some((_, last)) if last.chars().all(|c| c.is_ascii_digit()) => last.to_string(),
        _ => "1".to_string(),
    }
}

/// Sibling lane names `X/2..X/9` an `X/1` port may own.
fn siblings(ifname: &str) -> Option<(String, Vec<String>)> {
    let base = ifname.strip_suffix("/1")?;
    if !base.starts_with("Ethernet") {
        return None;
    }
    Some((base.to_string(), (2..=9).map(|n| format!("{base}/{n}")).collect()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SensorKind {
    Rx,
    Tx,
    Bias,
    Temp,
    Snr,
}

impl SensorKind {
    fn parse(name: &str) -> Option<(SensorKind, &str)> {
        let rest = name.strip_prefix("DOM ")?;
        let (kind, target) = rest.split_once(" Sensor for ")?;
        let k = match kind {
            "RX Power" => SensorKind::Rx,
            "TX Power" => SensorKind::Tx,
            "TX Bias" => SensorKind::Bias,
            "Temperature" => SensorKind::Temp,
            "SNR" => SensorKind::Snr,
            _ => return None,
        };
        Some((k, target))
    }

    fn metric(self) -> (&'static str, &'static str) {
        match self {
            SensorKind::Rx => ("rx_dbm", "dBm"),
            SensorKind::Tx => ("tx_dbm", "dBm"),
            SensorKind::Bias => ("bias_ma", "mA"),
            SensorKind::Temp => ("temp_c", "C"),
            SensorKind::Snr => ("snr_db", "dB"),
        }
    }

    fn convert(self, v: f64) -> Option<f64> {
        match self {
            SensorKind::Rx | SensorKind::Tx => (v > 0.0).then(|| 10.0 * (v / 10_000.0).log10()),
            SensorKind::Bias => Some(v / 100.0),
            SensorKind::Temp => Some(v / 10.0),
            SensorKind::Snr => Some(v / 100.0),
        }
    }
}

/// Whether port `p` owns its whole transceiver (so module-level sensors are
/// its alone): an unsplit port, or an `X/1` port none of whose `X/2..X/9`
/// siblings is an interface. A breakout lane never does — the module is
/// shared with other interfaces, possibly another tenant's.
fn owns_module(p: &str, excluded: &HashSet<String>) -> bool {
    match siblings(p) {
        Some((_, sibs)) => !sibs.iter().any(|s| excluded.contains(s)),
        None => module_of(p) == p,
    }
}

/// Map a sensor's target name onto one of `ports` → (port, lane). Module
/// temperature has no lane. `excluded` holds sibling names that are
/// interfaces in their own right.
fn sensor_owner(
    kind: SensorKind,
    target: &str,
    ports: &[String],
    excluded: &HashSet<String>,
) -> Option<(String, Option<String>)> {
    for p in ports {
        let module = module_of(p);
        if kind == SensorKind::Temp {
            if target == module && owns_module(p, excluded) {
                return Some((p.clone(), None));
            }
            continue;
        }
        if target == p {
            return Some((p.clone(), Some(lane_of(p))));
        }
        if let Some((_, sibs)) = siblings(p) {
            if sibs.iter().any(|s| s == target) && !excluded.contains(target) {
                return Some((p.clone(), Some(lane_of(target))));
            }
        }
    }
    None
}

// ── Query execution ─────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Agg {
    Avg,
    Min,
    Max,
}

impl Agg {
    fn func(self) -> &'static str {
        match self {
            Agg::Avg => "avg_over_time",
            Agg::Min => "min_over_time",
            Agg::Max => "max_over_time",
        }
    }
}

fn group_by_host(items: &[(String, String)]) -> BTreeMap<String, Vec<String>> {
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (d, i) in items {
        let v = m.entry(d.clone()).or_default();
        if !v.contains(i) {
            v.push(i.clone());
        }
    }
    m
}

fn to_col(samples: &[(i64, f64)], win: &Win) -> Col {
    let mut out = vec![None; win.len()];
    if let Some((start, step)) = win.range {
        for (t, v) in samples {
            let idx = ((t - start) as f64 / step as f64).round();
            if idx >= 0.0 && (idx as usize) < out.len() {
                out[idx as usize] = Some(*v);
            }
        }
    }
    out
}

impl MetricsService {
    pub fn new(cfg: MetricsConfig) -> Self {
        let prom = PromClient::new(&cfg.prometheus_url, Duration::from_secs(cfg.timeout_secs));
        Self { prom, cfg }
    }

    /// Gauge: `build(agg, window_secs)` → PromQL. Latest mode runs
    /// `build(Avg, latest_window)` instantly; range mode runs one range query
    /// per aggregation. Results are merged by `key(labels)`.
    async fn gauge(
        &self,
        win: &Win,
        aggs: &[Agg],
        latest_window: u64,
        build: impl Fn(Agg, u64) -> String,
        key: impl Fn(&Labels) -> Option<String>,
    ) -> Res<HashMap<String, (Labels, Grid)>> {
        let mut out: HashMap<String, (Labels, Grid)> = HashMap::new();
        match win.range {
            None => {
                for (labels, v) in self.prom.instant(&build(Agg::Avg, latest_window), win.end).await? {
                    if let Some(k) = key(&labels) {
                        out.insert(k, (labels, Grid { avg: vec![Some(v)], ..Default::default() }));
                    }
                }
            }
            Some((start, step)) => {
                let futs = aggs.iter().map(|a| {
                    let q = build(*a, step);
                    async move { self.prom.range(&q, start, win.end, step).await.map(|r| (*a, r)) }
                });
                for (agg, rows) in try_join_all(futs).await? {
                    for s in rows {
                        let Some(k) = key(&s.labels) else { continue };
                        let col = to_col(&s.samples, win);
                        let e = out.entry(k).or_insert_with(|| {
                            (s.labels.clone(), Grid { avg: vec![None; win.len()], ..Default::default() })
                        });
                        match agg {
                            Agg::Avg => e.1.avg = col,
                            Agg::Min => e.1.min = Some(col),
                            Agg::Max => e.1.max = Some(col),
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Counter `selector`: total increase over the window plus (range mode)
    /// per-step increases. Keyed by `key(labels)` → (grid, total).
    async fn counter(
        &self,
        win: &Win,
        selector: &str,
        key: impl Fn(&Labels) -> Option<String>,
    ) -> Res<HashMap<String, (Grid, Option<f64>)>> {
        let total_window = if win.latest() { LATEST_COUNTER_WINDOW } else { win.span() };
        let totals_q = format!("increase({selector}[{total_window}s])");
        let mut out: HashMap<String, (Grid, Option<f64>)> = HashMap::new();
        let (totals, steps) = futures::try_join!(
            self.prom.instant(&totals_q, win.end),
            async {
                match win.range {
                    None => Ok(vec![]),
                    Some((start, step)) => {
                        self.prom.range(&format!("increase({selector}[{step}s])"), start, win.end, step).await
                    }
                }
            }
        )?;
        for (labels, v) in totals {
            if let Some(k) = key(&labels) {
                let avg = if win.latest() { vec![Some(v)] } else { vec![None; win.len()] };
                out.insert(k, (Grid { avg, ..Default::default() }, Some(v)));
            }
        }
        for s in steps {
            if let Some(k) = key(&s.labels) {
                let e = out.entry(k).or_insert_with(|| (Grid::default(), None));
                e.0.avg = to_col(&s.samples, win);
            }
        }
        Ok(out)
    }

    async fn traffic(&self, r: &Resolved, win: &Win) -> Res<(Vec<Data>, Option<f64>)> {
        let mut data = vec![];
        let sflow: Vec<(String, String)> =
            r.traffic.iter().filter(|t| t.2 == Src::Sflow).map(|t| (t.0.clone(), t.1.clone())).collect();
        let snmp: Vec<(String, String)> =
            r.traffic.iter().filter(|t| t.2 == Src::Snmp).map(|t| (t.0.clone(), t.1.clone())).collect();
        let ifkey = |l: &Labels| l.get("ifname").cloned();

        let mut jobs = vec![];
        for (dir, sf_metric, snmp_metric) in [("in", "sflow_ifinoctets", "ifHCInOctets"), ("out", "sflow_ifoutoctets", "ifHCOutOctets")] {
            for (host, names) in group_by_host(&sflow) {
                let sel = format!(
                    r#"{sf_metric}{{job="sflow-rt-ifcounters",host="{}",ifname=~"{}"}}"#,
                    esc(&host),
                    esc(&alternation(names.iter().map(|s| s.as_str())))
                );
                jobs.push((dir, host, true, sel));
            }
            for (host, names) in group_by_host(&snmp) {
                let sel = format!(
                    r#"{snmp_metric}{{job="snmp-eos",host="{}",ifname=~"{}"}}"#,
                    esc(&host),
                    esc(&alternation(names.iter().map(|s| s.as_str())))
                );
                jobs.push((dir, host, false, sel));
            }
        }
        let results = try_join_all(jobs.iter().map(|(dir, host, is_sflow, sel)| {
            let sel = sel.clone();
            let is_sflow = *is_sflow;
            async move {
                let rows = if is_sflow {
                    self.gauge(win, &[Agg::Avg, Agg::Max], 60, |a, w| format!("{}({sel}[{w}s]) * 8", a.func()), ifkey).await?
                } else {
                    // rate() needs ≥2 SNMP samples (60 s scrape).
                    self.gauge(win, &[Agg::Avg], 300, |_, w| format!("rate({sel}[{}s]) * 8", w.max(240)), ifkey).await?
                };
                Res::Ok((*dir, host.clone(), rows))
            }
        }))
        .await?;

        let mut per_dir: HashMap<&str, Vec<Col>> = HashMap::new();
        for (dir, host, rows) in results {
            for (dev, ifname, _) in r.traffic.iter().filter(|t| t.0 == host) {
                let Some((_, grid)) = rows.get(ifname) else { continue };
                per_dir.entry(dir).or_default().push(grid.avg.clone());
                data.push(Data {
                    interface: if r.traffic.iter().any(|t| t.0 != *dev) { format!("{dev}:{ifname}") } else { ifname.clone() },
                    metric: if dir == "in" { "traffic_in" } else { "traffic_out" },
                    lane: None,
                    unit: "bps",
                    grid: grid.clone(),
                    total: None,
                });
            }
        }
        if r.traffic.len() > 1 {
            for dir in ["in", "out"] {
                if let Some(cols) = per_dir.get(dir) {
                    data.push(Data {
                        interface: format!("{} (total)", r.interface),
                        metric: if dir == "in" { "traffic_in" } else { "traffic_out" },
                        lane: None,
                        unit: "bps",
                        grid: Grid { avg: sum_cols(cols, win.len()), ..Default::default() },
                        total: None,
                    });
                }
            }
        }

        // Port speed (sum of measured interfaces) for utilisation.
        let speed_window = if win.latest() { 900 } else { win.span().max(900) };
        let mut speed = 0.0;
        let all: Vec<(String, String)> = r.traffic.iter().map(|t| (t.0.clone(), t.1.clone())).collect();
        for (host, names) in group_by_host(&all) {
            let q = format!(
                r#"max by (ifname) (last_over_time(ifHighSpeed{{job="snmp-eos",host="{}",ifname=~"{}"}}[{speed_window}s]))"#,
                esc(&host),
                esc(&alternation(names.iter().map(|s| s.as_str())))
            );
            for (_, v) in self.prom.instant(&q, win.end).await? {
                speed += v * 1e6;
            }
        }
        data.sort_by(|a, b| (&a.interface, a.metric).cmp(&(&b.interface, b.metric)));
        Ok((data, (speed > 0.0).then_some(speed)))
    }

    async fn errors(&self, r: &Resolved, win: &Win) -> Res<Vec<Data>> {
        let multi_host = group_by_host(&r.phys).len() > 1;
        let mut jobs = vec![];
        for (host, names) in group_by_host(&r.phys) {
            for (metric, oid) in [
                ("in_errors", "ifInErrors"),
                ("out_errors", "ifOutErrors"),
                ("in_discards", "ifInDiscards"),
                ("out_discards", "ifOutDiscards"),
            ] {
                let sel = format!(
                    r#"{oid}{{job="snmp-eos",host="{}",ifname=~"{}"}}"#,
                    esc(&host),
                    esc(&alternation(names.iter().map(|s| s.as_str())))
                );
                jobs.push((host.clone(), metric, sel));
            }
        }
        let results = try_join_all(jobs.iter().map(|(host, metric, sel)| async move {
            let rows = self.counter(win, sel, |l| l.get("ifname").cloned()).await?;
            Res::Ok((host.clone(), *metric, rows))
        }))
        .await?;
        let mut data = vec![];
        for (host, metric, rows) in results {
            for (ifname, (grid, total)) in rows {
                data.push(Data {
                    interface: if multi_host { format!("{host}:{ifname}") } else { ifname },
                    metric,
                    lane: None,
                    unit: "count",
                    grid,
                    total: Some(total),
                });
            }
        }
        data.sort_by(|a, b| (&a.interface, a.metric).cmp(&(&b.interface, b.metric)));
        Ok(data)
    }

    async fn optics(&self, r: &Resolved, win: &Win) -> Res<Vec<Data>> {
        let multi_host = group_by_host(&r.phys).len() > 1;
        let mut data = vec![];
        for (host, ports) in group_by_host(&r.phys) {
            let h = esc(&host);
            let mut alts: Vec<String> = vec![];
            let mut sib_res: Vec<String> = vec![];
            for p in &ports {
                alts.push(re_esc(p));
                let m = module_of(p);
                if m != p {
                    alts.push(re_esc(m));
                }
                if let Some((base, _)) = siblings(p) {
                    sib_res.push(format!("{}/[2-9]", re_esc(&base)));
                }
            }
            alts.extend(sib_res.iter().cloned());
            let name_re = format!(
                "DOM (RX Power|TX Power|TX Bias|Temperature|SNR) Sensor for ({})",
                alts.join("|")
            );
            let sel = format!(r#"entPhySensorValue{{job="snmp-eos-health",host="{h}",entPhysicalName=~"{}"}}"#, esc(&name_re));

            // Siblings that are interfaces in their own right are not lanes:
            // those NetBox knows, plus any SNMP reported during the window
            // (the portal uses only the latter).
            let mut excluded: HashSet<String> =
                r.breakouts.iter().filter(|(d, _)| *d == host).map(|(_, i)| i.clone()).collect();
            excluded.extend(if sib_res.is_empty() {
                HashSet::new()
            } else {
                let w = if win.latest() { 900 } else { win.span() };
                let q = format!(
                    r#"group by (ifname) (last_over_time(ifOperStatus{{job="snmp-eos",host="{h}",ifname=~"{}"}}[{w}s]))"#,
                    esc(&sib_res.join("|"))
                );
                self.prom.instant(&q, win.end).await?.into_iter().filter_map(|(l, _)| l.get("ifname").cloned()).collect()
            });

            let rows = self
                .gauge(
                    win,
                    &[Agg::Avg, Agg::Min, Agg::Max],
                    600,
                    |a, w| {
                        let f = if win.latest() { "last_over_time" } else { a.func() };
                        format!("{f}({sel}[{w}s]) > -1000000")
                    },
                    |l| l.get("entPhysicalName").cloned(),
                )
                .await?;
            for (name, (_, grid)) in rows {
                let Some((kind, target)) = SensorKind::parse(&name) else { continue };
                let Some((port, lane)) = sensor_owner(kind, target, &ports, &excluded) else { continue };
                let (metric, unit) = kind.metric();
                data.push(Data {
                    interface: if multi_host { format!("{host}:{port}") } else { port },
                    metric,
                    lane,
                    unit,
                    grid: grid.map(|v| kind.convert(v)),
                    total: None,
                });
            }
        }
        data.sort_by(|a, b| {
            (&a.interface, a.lane.as_deref().unwrap_or(""), a.metric).cmp(&(&b.interface, b.lane.as_deref().unwrap_or(""), b.metric))
        });
        Ok(data)
    }

    async fn collect(&self, r: &Resolved, families: &[Family], win: &Win) -> Res<(Vec<Data>, Option<f64>, Vec<String>)> {
        let want = |f| families.is_empty() || families.contains(&f);
        let (traffic, errors, optics) = futures::try_join!(
            async { if want(Family::Traffic) { self.traffic(r, win).await.map(Some) } else { Ok(None) } },
            async { if want(Family::Errors) && !r.phys.is_empty() { self.errors(r, win).await } else { Ok(vec![]) } },
            async { if want(Family::Optics) && !r.phys.is_empty() { self.optics(r, win).await } else { Ok(vec![]) } },
        )?;
        let mut notes = r.notes.clone();
        let mut data = vec![];
        let mut speed = None;
        if let Some((t, s)) = traffic {
            if t.is_empty() {
                notes.push("no traffic series in Prometheus for this port".into());
            }
            data.extend(t);
            speed = s;
        }
        if want(Family::Optics) && !r.phys.is_empty() && optics.is_empty() {
            notes.push("no optic DOM sensors in Prometheus (no transceiver, no DOM, or non-EOS device)".into());
        }
        data.extend(errors);
        data.extend(optics);
        Ok((data, speed, notes))
    }

    fn report(r: &Resolved, data: &[Data], speed: Option<f64>, notes: Vec<String>, win: &Win) -> PortReport {
        PortReport {
            device: r.device.clone(),
            interface: r.interface.clone(),
            role: r.role.clone(),
            owner_asn: r.owner_asn,
            owner_name: r.owner_name.clone(),
            members: r.phys.iter().map(|(_, i)| i.clone()).collect(),
            speed_bps: speed,
            series: data.iter().map(|d| d.finish(win)).collect(),
            notes,
        }
    }

    // ── Entry point ─────────────────────────────────────────────────────

    pub async fn run(&self, lg: &LookingGlass, req: MetricsRequest) -> Res<MetricsReport> {
        let nb = lg.netbox_participants.load();
        let pmap = lg.port_map.load();
        let participants = lg.participants();
        let lldp: HashMap<String, Vec<LldpNeighbor>> = lg
            .device_state_cache
            .load()
            .iter()
            .map(|(d, c)| (d.clone(), c.lldp_neighbors.clone()))
            .collect();
        let ctx = Ctx { nb: &nb, pmap: &pmap, participants: &participants, admin_group: lg.admin_group(), lldp: &lldp };
        self.run_ctx(&ctx, req, chrono::Utc::now().timestamp()).await
    }

    /// [`Self::run`] against an explicit snapshot of LG state.
    pub async fn run_ctx(&self, ctx: &Ctx<'_>, req: MetricsRequest, now: i64) -> Res<MetricsReport> {
        let admin_group = ctx.admin_group.to_string();
        let identity = &req.identity;
        if !identity.authenticated {
            return Err(MetricsError::Denied("metrics require authentication".into()));
        }
        let nb = ctx.nb;
        let participants = ctx.participants;
        let is_admin = identity.is_admin(&admin_group);
        let known = known_interfaces(nb, ctx.pmap);
        let resolve = |d: &str, i: &str| resolve_for(ctx, &known, identity, d, i);

        let (win, body, mut notes) = match req.query {
            MetricsQuery::Port { device, interface, asn, families, window } => {
                let win = resolve_window(&window, self.cfg.max_range_secs, now)?;
                let mut notes = vec![];
                let targets: Vec<Resolved> = match (device, interface, asn) {
                    (Some(d), Some(i), None) => vec![resolve(&d, &i)?],
                    (None, None, Some(asn)) => {
                        // As the portal: the ASN's own NetBox ports, built forward.
                        authorize_asn(identity, &admin_group, asn)?;
                        let p = nb
                            .iter()
                            .find(|p| p.asn == asn)
                            .ok_or_else(|| MetricsError::BadRequest(format!("AS{asn} has no peering ports")))?;
                        let mut v: Vec<Resolved> =
                            p.enriched_ports.iter().map(|ep| with_breakouts(tenant_port(p, ep), &known)).collect();
                        if v.len() > self.cfg.max_ports {
                            notes.push(format!("showing {} of {} ports; query the rest by device+interface", self.cfg.max_ports, v.len()));
                            v.truncate(self.cfg.max_ports);
                        }
                        v
                    }
                    _ => {
                        return Err(MetricsError::BadRequest(
                            "give either device + interface, or asn".into(),
                        ))
                    }
                };
                let reports = try_join_all(targets.iter().map(|r| async {
                    let (data, speed, notes) = self.collect(r, &families, &win).await?;
                    Res::Ok(Self::report(r, &data, speed, notes, &win))
                }))
                .await?;
                (win, MetricsBody::Ports { ports: reports }, notes)
            }
            MetricsQuery::Link { device, interface, families, window } => {
                let win = resolve_window(&window, self.cfg.max_range_secs, now)?;
                let a = resolve(&device, &interface)?;
                if a.phys.is_empty() {
                    return Err(MetricsError::BadRequest(format!(
                        "{device} {interface} has no physical members to follow over LLDP"
                    )));
                }
                let mut legs: Vec<(Resolved, Option<Resolved>, Vec<String>)> = vec![];
                for (d, i) in &a.phys {
                    let mut leg_notes = vec![];
                    // Each member is checked on its own (it is in the same
                    // NetBox port's member_interfaces, so an owner passes).
                    let am = resolve(d, i)?;
                    let nbr = ctx.lldp.get(d).and_then(|v| v.iter().find(|n| &n.local_interface == i));
                    let b = match nbr {
                        None => {
                            leg_notes.push(format!("no LLDP neighbour cached for {d} {i}"));
                            None
                        }
                        Some(n) => match match_device(ctx.lldp.keys(), &n.neighbor_device) {
                            None => {
                                leg_notes.push(if is_admin {
                                    format!(
                                        "LLDP neighbour {} port {} is not a looking-glass device; far end not measurable",
                                        n.neighbor_device, n.neighbor_port
                                    )
                                } else {
                                    "far end is not a looking-glass device; not measurable".into()
                                });
                                None
                            }
                            // The far end passes the same tenant check as A.
                            Some(bd) => match resolve(&bd, &n.neighbor_port) {
                                Ok(b) => Some(b),
                                Err(_) => {
                                    leg_notes.push("far end not visible to you".into());
                                    None
                                }
                            },
                        },
                    };
                    legs.push((am, b, leg_notes));
                }
                let pairs = try_join_all(legs.iter().map(|(am, b, leg_notes)| {
                    let families = families.clone();
                    async move {
                        let (ad, aspeed, anotes) = self.collect(am, &families, &win).await?;
                        let mut derived = vec![];
                        let b_report = match b {
                            None => None,
                            Some(b) => {
                                let (bd, bspeed, bnotes) = self.collect(b, &families, &win).await?;
                                derived = derive_link(&ad, &bd, &am.interface, &b.interface);
                                Some(Self::report(b, &bd, bspeed, bnotes, &win))
                            }
                        };
                        Res::Ok(LinkPair {
                            a: Self::report(am, &ad, aspeed, anotes, &win),
                            b: b_report,
                            derived: derived.iter().map(|d| d.finish(&win)).collect(),
                            notes: leg_notes.clone(),
                        })
                    }
                }))
                .await?;
                (win, MetricsBody::Link { pairs }, vec![])
            }
            MetricsQuery::Peers { asn, peer_asn, direction, top, window } => {
                let win = resolve_window(&window, self.cfg.max_range_secs, now)?;
                authorize_asn(identity, &admin_group, asn)?;
                let top = top.unwrap_or(DEFAULT_TOP_PEERS).clamp(1, MAX_TOP_PEERS);
                let body = self.peers(participants, asn, peer_asn, direction, top, &win).await?;
                (win, body, vec!["peer matrix is sFlow-sampled and limited to the fabric's top 1000 ASN pairs".into()])
            }
        };
        if win.points && win.latest() {
            notes.push("points ignored without a range".into());
        }
        Ok(MetricsReport {
            end: win.end,
            start: win.range.map(|(s, _)| s),
            step_secs: win.range.map(|(_, s)| s),
            body,
            notes,
        })
    }

    async fn peers(
        &self,
        participants: &ParticipantMap,
        asn: u32,
        peer_asn: Option<u32>,
        direction: PeerDirection,
        top: usize,
        win: &Win,
    ) -> Res<MetricsBody> {
        let dirs: &[&str] = match direction {
            PeerDirection::To => &["to"],
            PeerDirection::From => &["from"],
            PeerDirection::Both => &["to", "from"],
        };
        let mut rows = vec![];
        let mut others = vec![];
        let mut totals = vec![];
        let results = try_join_all(dirs.iter().map(|dir| async move {
            let (me, peer_lbl, peer_name) = if *dir == "to" {
                ("src_asn", "dst_asn", "dst_name")
            } else {
                ("dst_asn", "src_asn", "src_name")
            };
            let mut sel = format!(r#"{me}="{asn}""#);
            if let Some(p) = peer_asn {
                sel.push_str(&format!(r#",{peer_lbl}="{p}""#));
            }
            let sel = format!("sflow_ixp_peering_bps{{{sel}}}");
            let got = self
                .gauge(win, &[Agg::Avg, Agg::Max], 60, |a, w| format!("{}({sel}[{w}s])", a.func()), |l| {
                    l.get(peer_lbl).cloned()
                })
                .await?;
            Res::Ok((*dir, peer_name, got))
        }))
        .await?;
        for (dir, peer_name, got) in results {
            let mut dir_rows: Vec<(PeerRow, Col)> = got
                .into_iter()
                .filter_map(|(peer, (labels, grid))| {
                    let stats = gauge_stats(&grid, win);
                    Some((
                        PeerRow {
                            peer_asn: peer.parse().ok()?,
                            peer_name: peer_display_name(participants, &peer, labels.get(peer_name)),
                            direction: dir.to_string(),
                            stats,
                            points: win.points.then(|| grid.avg.clone()),
                        },
                        grid.avg,
                    ))
                })
                .collect();
            let rank = |r: &PeerRow| if win.latest() { r.stats.last } else { r.stats.avg }.unwrap_or(0.0);
            dir_rows.sort_by(|a, b| rank(&b.0).total_cmp(&rank(&a.0)));
            let total = sum_cols(dir_rows.iter().map(|r| &r.1), win.len());
            totals.push((dir.to_string(), aggregate_stats(total, win)));
            if dir_rows.len() > top {
                let rest = dir_rows.split_off(top);
                let sum = sum_cols(rest.iter().map(|r| &r.1), win.len());
                others.push((dir.to_string(), rest.len(), aggregate_stats(sum, win)));
            }
            rows.extend(dir_rows.into_iter().map(|r| r.0));
        }
        let name = participants.get(asn).map(|p| p.name.clone()).unwrap_or_default();
        Ok(MetricsBody::Peers { asn, name, rows, others, totals })
    }
}

/// Prefer the participant's NetBox name; sFlow-RT's labels replace spaces and
/// punctuation with `_` ("OpenColo_(aka_...)" → "OpenColo  aka ...").
fn peer_display_name(participants: &ParticipantMap, asn: &str, sflow_name: Option<&String>) -> String {
    if let Some(p) = asn.parse().ok().and_then(|a| participants.get(a)) {
        return p.name.clone();
    }
    sflow_name.map(|n| n.replace('_', " ").split_whitespace().collect::<Vec<_>>().join(" ")).unwrap_or_default()
}

/// Stats for a summed ("other" / total) series. Its max would be the max of
/// summed step averages — not comparable with a single peer's true max — so
/// it is left out.
fn aggregate_stats(avg: Col, win: &Win) -> Stats {
    Stats { max: None, ..gauge_stats(&Grid { avg, ..Default::default() }, win) }
}

/// Derived A↔B series for one physical link: per-lane optical loss and
/// throughput mismatch (A out vs B in, and the reverse).
fn derive_link(a: &[Data], b: &[Data], a_if: &str, b_if: &str) -> Vec<Data> {
    let find = |d: &[Data], metric: &str, lane: Option<&str>| {
        d.iter().find(|x| x.metric == metric && x.lane.as_deref() == lane).map(|x| x.grid.avg.clone())
    };
    let mut out = vec![];
    let lanes: Vec<String> = a.iter().filter(|x| x.metric == "tx_dbm").filter_map(|x| x.lane.clone()).collect();
    for lane in &lanes {
        for (tx_side, rx_side, label) in [(a, b, format!("{a_if}→{b_if}")), (b, a, format!("{b_if}→{a_if}"))] {
            if let (Some(tx), Some(rx)) = (find(tx_side, "tx_dbm", Some(lane)), find(rx_side, "rx_dbm", Some(lane))) {
                out.push(Data {
                    interface: label,
                    metric: "loss_db",
                    lane: Some(lane.clone()),
                    unit: "dB",
                    grid: Grid { avg: zip_col(&tx, &rx, |t, r| t - r), ..Default::default() },
                    total: None,
                });
            }
        }
    }
    for (out_side, in_side, label) in [(a, b, format!("{a_if}→{b_if}")), (b, a, format!("{b_if}→{a_if}"))] {
        if let (Some(o), Some(i)) = (find(out_side, "traffic_out", None), find(in_side, "traffic_in", None)) {
            out.push(Data {
                interface: label,
                metric: "sent_minus_received",
                lane: None,
                unit: "bps",
                grid: Grid { avg: zip_col(&o, &i, |o, i| o - i), ..Default::default() },
                total: None,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_and_times() {
        assert_eq!(parse_duration("24h"), Some(86400));
        assert_eq!(parse_duration("7d"), Some(604800));
        assert_eq!(parse_duration("90m"), Some(5400));
        assert_eq!(parse_duration("300"), Some(300));
        assert_eq!(parse_duration("x"), None);
        assert_eq!(parse_time("1700000000"), Some(1_700_000_000));
        assert_eq!(parse_time("2026-11-11T00:00:00Z"), Some(1_794_355_200));
    }

    #[test]
    fn window_defaults_to_latest() {
        let w = resolve_window(&Window::default(), 30 * 86400, 1_000_000).unwrap();
        assert!(w.latest());
        assert_eq!(w.end, 1_000_000);
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn window_range_steps() {
        let now = 1_800_000_000;
        let w = resolve_window(&Window { range_secs: Some(86400), ..Default::default() }, 30 * 86400, now).unwrap();
        let (start, step) = w.range.unwrap();
        assert_eq!(step, 360); // 86400/240
        assert_eq!(w.end % step as i64, 0);
        assert_eq!(w.end - start, 86400);
        assert!(!w.points);
        let w = resolve_window(&Window { range_secs: Some(3600), points: Some(1000), ..Default::default() }, 30 * 86400, now).unwrap();
        assert_eq!(w.step(), MIN_STEP); // clamped
        assert!(w.points);
        assert!(resolve_window(&Window { range_secs: Some(40 * 86400), ..Default::default() }, 30 * 86400, now).is_err());
        assert!(resolve_window(&Window { range_secs: Some(60), ..Default::default() }, 30 * 86400, now).is_err());
    }

    #[test]
    fn optic_lane_ownership() {
        let ports = vec!["Ethernet18/1".to_string()];
        let none = HashSet::new();
        assert_eq!(sensor_owner(SensorKind::Rx, "Ethernet18/1", &ports, &none), Some(("Ethernet18/1".into(), Some("1".into()))));
        assert_eq!(sensor_owner(SensorKind::Rx, "Ethernet18/3", &ports, &none), Some(("Ethernet18/1".into(), Some("3".into()))));
        assert_eq!(sensor_owner(SensorKind::Temp, "Ethernet18", &ports, &none), Some(("Ethernet18/1".into(), None)));
        let breakout: HashSet<String> = ["Ethernet18/3".to_string()].into();
        assert_eq!(sensor_owner(SensorKind::Rx, "Ethernet18/3", &ports, &breakout), None);
        // Unsplit SFP port: lane sensors and module sensors share the name.
        let sfp = vec!["Ethernet7".to_string()];
        assert_eq!(sensor_owner(SensorKind::Tx, "Ethernet7", &sfp, &none), Some(("Ethernet7".into(), Some("1".into()))));
        assert_eq!(sensor_owner(SensorKind::Temp, "Ethernet7", &sfp, &none), Some(("Ethernet7".into(), None)));
    }

    #[test]
    fn sensor_units() {
        let (k, t) = SensorKind::parse("DOM TX Power Sensor for Ethernet18/1").unwrap();
        assert_eq!((k, t), (SensorKind::Tx, "Ethernet18/1"));
        // Values verified against `show interfaces transceiver` on EOS.
        assert!((k.convert(5507.0).unwrap() - -2.59).abs() < 0.01);
        assert!((SensorKind::Bias.convert(2975.0).unwrap() - 29.75).abs() < 1e-9);
        assert!((SensorKind::Temp.convert(365.0).unwrap() - 36.5).abs() < 1e-9);
        assert_eq!(SensorKind::Rx.convert(0.0), None);
    }

    /// NetBox fixture: tenant A (64500) has LAG Po10 (Et1/1, Et2/1) on sw1 and
    /// unsplit-looking Et5/1 on sw2; tenant B (64501) has an encapsulated
    /// subif riding A's Po10 (NetBox gives it no members), a breakout lane
    /// Et5/3 on the same sw2 transceiver as A's Et5/1, and a member-less
    /// physical subif Et7/1.998 on sw3. sw1 Et49/1 is a core port.
    fn fixture() -> (Vec<NetboxParticipant>, PortMap, ParticipantMap) {
        let ep = |d: &str, i: &str, members: &[(&str, &str)]| EnrichedPort {
            device: d.into(),
            interface: i.into(),
            device_id: 0,
            interface_id: 0,
            speed: None,
            rate_limit_bps: None,
            enabled: true,
            member_interfaces: members.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
        };
        let participant = |asn: u32, name: &str, ports: Vec<EnrichedPort>| {
            let mut flat: Vec<(String, String)> = vec![];
            for p in &ports {
                flat.push((p.device.clone(), p.interface.clone()));
                flat.extend(p.member_interfaces.iter().cloned());
            }
            NetboxParticipant { asn, name: name.into(), participant_type: None, ports: flat, enriched_ports: ports, ip_addresses: vec![] }
        };
        let nb = vec![
            participant(64500, "Tenant A", vec![
                ep("sw1", "Port-Channel10", &[("sw1", "Ethernet1/1"), ("sw1", "Ethernet2/1")]),
                ep("sw2", "Ethernet5/1", &[]),
            ]),
            participant(64501, "Tenant B", vec![
                ep("sw1", "Port-Channel10.1426", &[]),
                ep("sw2", "Ethernet5/3", &[]),
                ep("sw3", "Ethernet7/1.998", &[]),
            ]),
        ];
        let pmap = PortMap::build(&nb, &[("sw1".to_string(), "Ethernet49/1".to_string())], &[])
            .with_encapsulated(&[("sw1".to_string(), "Port-Channel10.1426".to_string())]);
        let participants = ParticipantMap::build_from_netbox(&nb);
        (nb, pmap, participants)
    }

    fn who(asns: &[u32], admin: bool) -> Identity {
        let mut id = Identity::anonymous();
        id.authenticated = true;
        id.asns.extend(asns.iter().copied());
        if admin {
            id.groups.insert("admins".into());
        }
        id
    }

    #[test]
    fn tenant_isolation_allowlist() {
        let (nb, pmap, participants) = fixture();
        let lldp = HashMap::new();
        let ctx = Ctx { nb: &nb, pmap: &pmap, participants: &participants, admin_group: "admins", lldp: &lldp };
        let known = known_interfaces(&nb, &pmap);
        let b = who(&[64501], false);

        // B cannot reach A's LAG, A's physical members, A's port on the shared
        // transceiver, infrastructure, or a name that does not exist — and the
        // refusal is identical in shape for all of them (no existence/owner oracle).
        for (d, i) in [
            ("sw1", "Port-Channel10"),
            ("sw1", "Ethernet1/1"),
            ("sw2", "Ethernet5/1"),
            ("sw1", "Ethernet49/1"),
            ("sw9", "Ethernet1/1"),
            ("sw3", "Ethernet7/1"), // parent of B's own subif: never derived
        ] {
            match resolve_for(&ctx, &known, &b, d, i) {
                Err(MetricsError::Denied(m)) => assert_eq!(m, format!("{d} {i} is not one of your ports")),
                other => panic!("{d} {i}: expected denial, got {:?}", other.map(|r| r.role)),
            }
        }
        // Unauthenticated: same refusal even for an owned name.
        let mut anon = b.clone();
        anon.authenticated = false;
        assert!(matches!(resolve_for(&ctx, &known, &anon, "sw2", "Ethernet5/3"), Err(MetricsError::Denied(_))));

        // B's encapsulated subif: its own SNMP counters only; no physical
        // members, so no errors/optics from A's Po10 members.
        let r = resolve_for(&ctx, &known, &b, "sw1", "Port-Channel10.1426").unwrap();
        assert_eq!(r.traffic, vec![("sw1".into(), "Port-Channel10.1426".into(), Src::Snmp)]);
        assert!(r.phys.is_empty());
        // B's member-less physical subif: no parent derived.
        let r = resolve_for(&ctx, &known, &b, "sw3", "Ethernet7/1.998").unwrap();
        assert!(r.phys.is_empty());

        // A reaches its LAG (members summed via sFlow) and each member.
        let a = who(&[64500], false);
        let r = resolve_for(&ctx, &known, &a, "sw1", "Port-Channel10").unwrap();
        assert_eq!(r.phys.len(), 2);
        assert!(r.traffic.iter().all(|t| t.2 == Src::Sflow));
        assert_eq!(resolve_for(&ctx, &known, &a, "sw1", "Ethernet2/1").unwrap().owner_asn, Some(64500));
        // ...but not B's encapsulated subif on its own LAG.
        assert!(resolve_for(&ctx, &known, &a, "sw1", "Port-Channel10.1426").is_err());

        // A's Et5/1 shares a transceiver with B's Et5/3: that lane is excluded
        // from A even if SNMP has a scrape gap.
        let r = resolve_for(&ctx, &known, &a, "sw2", "Ethernet5/1").unwrap();
        assert!(r.breakouts.contains(&("sw2".to_string(), "Ethernet5/3".to_string())));

        // Admins reach infrastructure.
        let admin = who(&[], true);
        assert_eq!(resolve_for(&ctx, &known, &admin, "sw1", "Ethernet49/1").unwrap().role, "core");

        // ASN-wide queries: own ASN or admin only.
        assert!(authorize_asn(&b, "admins", 64500).is_err());
        assert!(authorize_asn(&b, "admins", 64501).is_ok());
        assert!(authorize_asn(&admin, "admins", 64500).is_ok());
        assert!(authorize_asn(&anon, "admins", 64501).is_err());
    }

    #[test]
    fn shared_transceiver_sensors_not_attributed() {
        let breakout: HashSet<String> = ["Ethernet5/3".to_string()].into();
        let a = vec!["Ethernet5/1".to_string()];
        // A gets its own lane, not B's breakout lane, and no module temperature.
        assert_eq!(sensor_owner(SensorKind::Rx, "Ethernet5/1", &a, &breakout), Some(("Ethernet5/1".into(), Some("1".into()))));
        assert_eq!(sensor_owner(SensorKind::Rx, "Ethernet5/3", &a, &breakout), None);
        assert_eq!(sensor_owner(SensorKind::Temp, "Ethernet5", &a, &breakout), None);
        // B's breakout lane: its own lane sensors, no module temperature.
        let b = vec!["Ethernet5/3".to_string()];
        assert_eq!(sensor_owner(SensorKind::Tx, "Ethernet5/3", &b, &HashSet::new()), Some(("Ethernet5/3".into(), Some("3".into()))));
        assert_eq!(sensor_owner(SensorKind::Temp, "Ethernet5", &b, &HashSet::new()), None);
    }

    #[test]
    fn lldp_device_matching() {
        let devs = vec!["switch01.fmt01.sfmix.org".to_string(), "switch01.sfo02.sfmix.org".to_string()];
        assert_eq!(match_device(&devs, "switch01.fmt01").as_deref(), Some("switch01.fmt01.sfmix.org"));
        assert_eq!(match_device(&devs, "SWITCH01.SFO02.sfmix.org.").as_deref(), Some("switch01.sfo02.sfmix.org"));
        assert_eq!(match_device(&devs, "router1.example.net"), None);
    }

    /// Live smoke test against a real Prometheus:
    /// `LG_LIVE_PROMETHEUS=http://metrics.sfo02.sfmix.org:9090 cargo test -p looking-glass --lib live_ -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn live_prometheus_smoke() {
        use crate::netbox::EnrichedPort;
        let Ok(url) = std::env::var("LG_LIVE_PROMETHEUS") else { return };
        let svc = MetricsService::new(MetricsConfig {
            prometheus_url: url,
            max_range_secs: 30 * 86400,
            timeout_secs: 30,
            max_ports: 16,
        });
        let ep = |d: &str, i: &str, members: &[(&str, &str)]| EnrichedPort {
            device: d.into(),
            interface: i.into(),
            device_id: 0,
            interface_id: 0,
            speed: None,
            rate_limit_bps: None,
            enabled: true,
            member_interfaces: members.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
        };
        let participant = |asn: u32, name: &str, ports: Vec<EnrichedPort>| NetboxParticipant {
            asn,
            name: name.into(),
            participant_type: None,
            ports: ports.iter().map(|p| (p.device.clone(), p.interface.clone())).collect(),
            enriched_ports: ports,
            ip_addresses: vec![],
        };
        let nb = vec![
            participant(30640, "Etheric Networks", vec![ep("switch02.sfo02.sfmix.org", "Port-Channel102", &[("switch02.sfo02.sfmix.org", "Ethernet18/1")])]),
            participant(13335, "Cloudflare", vec![ep("switch04.sjc01.sfmix.org", "Port-Channel109", &[("switch04.sjc01.sfmix.org", "Ethernet5/1")])]),
        ];
        let core = vec![
            ("switch01.scl02.sfmix.org".to_string(), "Ethernet22/1".to_string()),
            ("switch01.scl05.sfmix.org".to_string(), "Ethernet54/1".to_string()),
        ];
        let pmap = PortMap::build(&nb, &core, &[]);
        let participants = ParticipantMap::build_from_netbox(&nb);
        let mut lldp: HashMap<String, Vec<LldpNeighbor>> = HashMap::new();
        lldp.insert(
            "switch01.scl02.sfmix.org".into(),
            vec![LldpNeighbor {
                local_interface: "Ethernet22/1".into(),
                neighbor_device: "switch01.scl05.sfmix.org".into(),
                neighbor_port: "Ethernet54/1".into(),
                ttl: "120".into(),
            }],
        );
        lldp.insert("switch01.scl05.sfmix.org".into(), vec![]);
        let ctx = Ctx { nb: &nb, pmap: &pmap, participants: &participants, admin_group: "admins", lldp: &lldp };

        let mut owner = Identity::anonymous();
        owner.authenticated = true;
        owner.asns.insert(30640);
        let mut admin = owner.clone();
        admin.groups.insert("admins".into());
        let now = chrono::Utc::now().timestamp();
        let req = |query: MetricsQuery, identity: &Identity| MetricsRequest { query, identity: identity.clone(), rate_key: "t".into() };
        let w = |range: Option<u64>, points: Option<u32>| Window { range_secs: range, end: None, points };
        let port = |asn: u32, window: Window| MetricsQuery::Port { device: None, interface: None, asn: Some(asn), families: vec![], window };

        for (title, q, id) in [
            ("PORT latest (owner)", port(30640, w(None, None)), &owner),
            ("PORT 24h summary (owner)", port(30640, w(Some(86400), None)), &owner),
            ("PORT 6h traffic points=12", MetricsQuery::Port {
                device: Some("switch02.sfo02.sfmix.org".into()),
                interface: Some("Ethernet18/1".into()),
                asn: None,
                families: vec![Family::Traffic],
                window: w(Some(6 * 3600), Some(12)),
            }, &owner),
            ("LINK latest (admin)", MetricsQuery::Link { device: "switch01.scl02.sfmix.org".into(), interface: "Ethernet22/1".into(), families: vec![], window: w(None, None) }, &admin),
            ("LINK 7d optics (admin)", MetricsQuery::Link { device: "switch01.scl02.sfmix.org".into(), interface: "Ethernet22/1".into(), families: vec![Family::Optics], window: w(Some(7 * 86400), None) }, &admin),
            ("PEERS latest top 5 (admin)", MetricsQuery::Peers { asn: 13335, peer_asn: None, direction: PeerDirection::Both, top: Some(5), window: w(None, None) }, &admin),
            ("PEERS 24h to, top 3, points 6 (owner of 30640)", MetricsQuery::Peers { asn: 30640, peer_asn: None, direction: PeerDirection::To, top: Some(3), window: w(Some(86400), Some(6)) }, &owner),
        ] {
            let t = std::time::Instant::now();
            let r = svc.run_ctx(&ctx, req(q, id), now).await.unwrap_or_else(|e| panic!("{title}: {e}"));
            let text = render::render(&r);
            println!("\n######## {title} ({} ms, {} bytes)\n{text}", t.elapsed().as_millis(), text.len());
        }

        // Authorization: owner of 30640 may not see 13335's port, peers, or core links.
        for q in [
            port(13335, w(None, None)),
            MetricsQuery::Peers { asn: 13335, peer_asn: None, direction: PeerDirection::Both, top: None, window: w(None, None) },
            MetricsQuery::Link { device: "switch01.scl02.sfmix.org".into(), interface: "Ethernet22/1".into(), families: vec![], window: w(None, None) },
            MetricsQuery::Port { device: Some("switch04.sjc01.sfmix.org".into()), interface: Some("Ethernet5/1".into()), asn: None, families: vec![], window: w(None, None) },
        ] {
            match svc.run_ctx(&ctx, req(q, &owner), now).await {
                Err(MetricsError::Denied(m)) => println!("denied as expected: {m}"),
                other => panic!("expected denial, got {:?}", other.map(|_| ())),
            }
        }
    }
}
