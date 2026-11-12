//! Compact plain-text rendering of a [`MetricsReport`] (for MCP / CLI).
//!
//! Latest mode pivots each family into one small table; range mode prints
//! one summary row per series; points (only when asked for) follow as one
//! space-separated line per series.

use std::collections::BTreeMap;
use std::fmt::Write;

use lg_types::metrics::*;

fn ts(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| t.to_string())
}

fn si(v: f64) -> String {
    let a = v.abs();
    let (d, s) = if a >= 1e12 {
        (1e12, "T")
    } else if a >= 1e9 {
        (1e9, "G")
    } else if a >= 1e6 {
        (1e6, "M")
    } else if a >= 1e3 {
        (1e3, "k")
    } else {
        (1.0, "")
    };
    let x = v / d;
    if s.is_empty() {
        format!("{x:.0}")
    } else if x.abs() >= 100.0 {
        format!("{x:.0}{s}")
    } else if x.abs() >= 10.0 {
        format!("{x:.1}{s}")
    } else {
        format!("{x:.2}{s}")
    }
}

pub fn fmt_val(v: Option<f64>, unit: &str) -> String {
    match v {
        None => "-".into(),
        Some(v) => match unit {
            "bps" => si(v),
            "count" => format!("{v:.0}"),
            "C" => format!("{v:.1}"),
            _ => format!("{v:.2}"),
        },
    }
}

fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut w: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if i < w.len() {
                w[i] = w[i].max(c.chars().count());
            }
        }
    }
    let line = |cells: Vec<&str>| {
        let mut s = String::from("  ");
        for (i, c) in cells.iter().enumerate() {
            let pad = w[i].saturating_sub(c.chars().count());
            s.push_str(c);
            if i + 1 < cells.len() {
                s.push_str(&" ".repeat(pad + 2));
            }
        }
        s.push('\n');
        s
    };
    let mut out = line(headers.to_vec());
    for r in rows {
        out.push_str(&line(r.iter().map(|s| s.as_str()).collect()));
    }
    out
}

fn points_line(out: &mut String, label: &str, unit: &str, pts: &[Option<f64>]) {
    let vals: Vec<String> = pts.iter().map(|v| fmt_val(*v, unit)).collect();
    let _ = writeln!(out, "  {label} ({unit}): {}", vals.join(" "));
}

fn series_label(s: &Series) -> String {
    match &s.lane {
        Some(l) => format!("{} {} lane{}", s.interface, s.metric, l),
        None => format!("{} {}", s.interface, s.metric),
    }
}

fn port_header(out: &mut String, p: &PortReport) {
    let mut h = format!("== {} {} · {}", p.device, p.interface, p.role);
    if let Some(asn) = p.owner_asn {
        let _ = write!(h, " · AS{asn}");
        if let Some(n) = p.owner_name.as_ref().filter(|n| !n.is_empty()) {
            let _ = write!(h, " {n}");
        }
    }
    if let Some(s) = p.speed_bps {
        let _ = write!(h, " · {}", si(s));
    }
    let _ = writeln!(out, "{h} ==");
    if p.members.len() > 1 {
        let _ = writeln!(out, "  members: {}", p.members.join(", "));
    }
    for n in &p.notes {
        let _ = writeln!(out, "  note: {n}");
    }
}

fn latest_port(out: &mut String, p: &PortReport) {
    // traffic
    let mut traffic: BTreeMap<&str, [Option<f64>; 2]> = BTreeMap::new();
    for s in p.series.iter().filter(|s| s.unit == "bps") {
        let e = traffic.entry(&s.interface).or_default();
        let i = if s.metric == "traffic_in" { 0 } else { 1 };
        e[i] = s.stats.last;
    }
    if !traffic.is_empty() {
        let single = traffic.len() == 1;
        let rows: Vec<Vec<String>> = traffic
            .iter()
            .map(|(iface, [i, o])| {
                let pct = |v: &Option<f64>| match (v, p.speed_bps) {
                    (Some(v), Some(sp)) if single || iface.ends_with("(total)") => format!("{:.1}%", v / sp * 100.0),
                    _ => "-".into(),
                };
                vec![iface.to_string(), fmt_val(*i, "bps"), fmt_val(*o, "bps"), pct(i), pct(o)]
            })
            .collect();
        out.push_str("traffic (1m avg, bps)\n");
        out.push_str(&table(&["interface", "in", "out", "in%", "out%"], &rows));
    }
    // errors
    let cols = ["in_errors", "out_errors", "in_discards", "out_discards"];
    let mut errs: BTreeMap<&str, [Option<f64>; 4]> = BTreeMap::new();
    for s in p.series.iter().filter(|s| s.unit == "count") {
        if let Some(i) = cols.iter().position(|c| *c == s.metric) {
            errs.entry(&s.interface).or_default()[i] = s.stats.total;
        }
    }
    if !errs.is_empty() {
        let rows: Vec<Vec<String>> = errs
            .iter()
            .map(|(iface, v)| {
                let mut r = vec![iface.to_string()];
                r.extend(v.iter().map(|x| fmt_val(*x, "count")));
                r
            })
            .collect();
        out.push_str("errors (count, last 15m)\n");
        out.push_str(&table(&["interface", "in_err", "out_err", "in_disc", "out_disc"], &rows));
    }
    // optics
    let ocols = ["rx_dbm", "tx_dbm", "bias_ma", "snr_db"];
    let mut lanes: BTreeMap<(&str, u32, &str), [Option<f64>; 4]> = BTreeMap::new();
    let mut temps: BTreeMap<&str, Option<f64>> = BTreeMap::new();
    for s in &p.series {
        if s.metric == "temp_c" {
            temps.insert(&s.interface, s.stats.last);
        } else if let (Some(i), Some(l)) = (ocols.iter().position(|c| *c == s.metric), s.lane.as_deref()) {
            lanes.entry((&s.interface, l.parse().unwrap_or(0), l)).or_default()[i] = s.stats.last;
        }
    }
    if !lanes.is_empty() || !temps.is_empty() {
        let has_snr = lanes.values().any(|v| v[3].is_some());
        let mut seen = std::collections::HashSet::new();
        let mut rows = vec![];
        for ((iface, _, lane), v) in &lanes {
            let mut r = vec![iface.to_string(), lane.to_string()];
            r.push(fmt_val(v[0], "dBm"));
            r.push(fmt_val(v[1], "dBm"));
            r.push(fmt_val(v[2], "mA"));
            if has_snr {
                r.push(fmt_val(v[3], "dB"));
            }
            r.push(if seen.insert(*iface) { fmt_val(temps.get(iface).copied().flatten(), "C") } else { String::new() });
            rows.push(r);
        }
        for (iface, t) in &temps {
            if !seen.contains(iface) {
                let mut r = vec![iface.to_string(), "-".into(), "-".into(), "-".into(), "-".into()];
                if has_snr {
                    r.push("-".into());
                }
                r.push(fmt_val(*t, "C"));
                rows.push(r);
            }
        }
        let mut h = vec!["interface", "lane", "rx_dBm", "tx_dBm", "bias_mA"];
        if has_snr {
            h.push("snr_dB");
        }
        h.push("temp_C");
        out.push_str("optics\n");
        out.push_str(&table(&h, &rows));
    }
}

fn stats_tables(out: &mut String, series: &[Series]) {
    let gauges: Vec<Vec<String>> = series
        .iter()
        .filter(|s| s.stats.total.is_none() && s.unit != "count")
        .map(|s| {
            vec![
                s.interface.clone(),
                s.metric.clone(),
                s.lane.clone().unwrap_or_default(),
                s.unit.clone(),
                fmt_val(s.stats.last, &s.unit),
                fmt_val(s.stats.min, &s.unit),
                fmt_val(s.stats.avg, &s.unit),
                fmt_val(s.stats.p95, &s.unit),
                fmt_val(s.stats.max, &s.unit),
            ]
        })
        .collect();
    if !gauges.is_empty() {
        out.push_str(&table(&["interface", "metric", "lane", "unit", "last", "min", "avg", "p95", "max"], &gauges));
    }
    let counters: Vec<Vec<String>> = series
        .iter()
        .filter(|s| s.unit == "count")
        .map(|s| vec![s.interface.clone(), s.metric.clone(), fmt_val(s.stats.total, "count"), fmt_val(s.stats.max, "count")])
        .collect();
    if !counters.is_empty() {
        out.push_str(&table(&["interface", "counter", "total", "max/step"], &counters));
    }
}

fn series_points(out: &mut String, series: &[Series]) {
    for s in series {
        if let Some(p) = &s.points {
            points_line(out, &series_label(s), &s.unit, p);
        }
    }
}

fn port(out: &mut String, p: &PortReport, latest: bool) {
    port_header(out, p);
    if p.series.is_empty() {
        out.push_str("  (no data)\n");
        return;
    }
    if latest {
        latest_port(out, p);
    } else {
        stats_tables(out, &p.series);
    }
}

pub fn render(r: &MetricsReport) -> String {
    let mut out = String::new();
    let latest = r.start.is_none();
    match (r.start, r.step_secs) {
        (Some(s), Some(step)) => {
            let counters = match &r.body {
                MetricsBody::Peers { .. } => "",
                _ => "; counters: total and max per step",
            };
            let _ = writeln!(
                out,
                "window {} → {} · step {step}s · last/avg/p95 are over step averages; min/max are true extremes{counters}",
                ts(s),
                ts(r.end)
            );
        }
        _ => {
            let _ = writeln!(out, "latest reading at {}", ts(r.end));
        }
    }
    for n in &r.notes {
        let _ = writeln!(out, "note: {n}");
    }
    let points_header = |out: &mut String| {
        if let (Some(s), Some(step)) = (r.start, r.points_step_secs.or(r.step_secs)) {
            let _ = writeln!(out, "points (from {} every {step}s; '-' = no data)", ts(s));
        }
    };
    let mut points: Vec<&Series> = vec![];
    match &r.body {
        MetricsBody::Ports { ports } => {
            for p in ports {
                port(&mut out, p, latest);
                points.extend(p.series.iter().filter(|s| s.points.is_some()));
            }
        }
        MetricsBody::Link { pairs } => {
            for pair in pairs {
                match &pair.b {
                    Some(b) => {
                        let _ = writeln!(
                            out,
                            "### link {} {} ⇄ {} {}",
                            pair.a.device, pair.a.interface, b.device, b.interface
                        );
                    }
                    None => {
                        let _ = writeln!(out, "### link {} {} ⇄ (far end unknown)", pair.a.device, pair.a.interface);
                    }
                }
                for n in &pair.notes {
                    let _ = writeln!(out, "note: {n}");
                }
                port(&mut out, &pair.a, latest);
                points.extend(pair.a.series.iter().filter(|s| s.points.is_some()));
                if let Some(b) = &pair.b {
                    port(&mut out, b, latest);
                    points.extend(b.series.iter().filter(|s| s.points.is_some()));
                }
                if !pair.derived.is_empty() {
                    out.push_str("derived (loss_db = tx − far rx; sent_minus_received = out − far in)\n");
                    if latest {
                        let rows: Vec<Vec<String>> = pair
                            .derived
                            .iter()
                            .map(|s| {
                                vec![s.interface.clone(), s.metric.clone(), s.lane.clone().unwrap_or_default(), fmt_val(s.stats.last, &s.unit), s.unit.clone()]
                            })
                            .collect();
                        out.push_str(&table(&["direction", "metric", "lane", "value", "unit"], &rows));
                    } else {
                        stats_tables(&mut out, &pair.derived);
                    }
                    points.extend(pair.derived.iter().filter(|s| s.points.is_some()));
                }
            }
        }
        MetricsBody::Peers { asn, name, rows, others, totals } => {
            // An empty matrix is explained by a note; blank tables add nothing.
            for (dir, total) in totals.iter().filter(|_| !rows.is_empty()) {
                let arrow = if dir == "to" { format!("AS{asn} → peer") } else { format!("peer → AS{asn}") };
                let _ = writeln!(out, "== AS{asn} {name} · {dir} peers ({arrow}), bps ==");
                let dir_rows: Vec<&PeerRow> = rows.iter().filter(|r| &r.direction == dir).collect();
                let mut t: Vec<Vec<String>> = vec![];
                let tot = if latest { total.last } else { total.avg };
                let share = |v: Option<f64>| match (v, tot) {
                    (Some(v), Some(t)) if t > 0.0 => format!("{:.1}%", v / t * 100.0),
                    _ => "-".into(),
                };
                let row = |asn: String, n: String, s: &Stats| {
                    if latest {
                        vec![asn, n, fmt_val(s.last, "bps"), share(s.last)]
                    } else {
                        vec![asn, n, fmt_val(s.avg, "bps"), share(s.avg), fmt_val(s.p95, "bps"), fmt_val(s.max, "bps"), fmt_val(s.last, "bps")]
                    }
                };
                for r in &dir_rows {
                    t.push(row(r.peer_asn.to_string(), r.peer_name.clone(), &r.stats));
                }
                if let Some((_, n, s)) = others.iter().find(|o| &o.0 == dir) {
                    t.push(row("-".into(), format!("({n} other peers)"), s));
                }
                t.push(row("-".into(), "TOTAL".into(), total));
                if latest {
                    out.push_str(&table(&["peer_asn", "name", "bps", "share"], &t));
                } else {
                    out.push_str(&table(&["peer_asn", "name", "avg", "share", "p95", "max", "last"], &t));
                }
                let with_points: Vec<_> = dir_rows.iter().filter_map(|r| r.points.as_ref().map(|p| (r, p))).collect();
                if !with_points.is_empty() {
                    points_header(&mut out);
                }
                for (r, p) in with_points {
                    points_line(&mut out, &format!("{dir} AS{} {}", r.peer_asn, r.peer_name), "bps", p);
                }
            }
        }
    }
    if !points.is_empty() {
        points_header(&mut out);
        series_points(&mut out, &points.into_iter().cloned().collect::<Vec<_>>());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn si_formatting() {
        assert_eq!(si(0.0), "0");
        assert_eq!(si(1_234.0), "1.23k");
        assert_eq!(si(326_600_000.0), "327M");
        assert_eq!(si(12_300_000_000.0), "12.3G");
        assert_eq!(fmt_val(Some(-2.587), "dBm"), "-2.59");
        assert_eq!(fmt_val(None, "bps"), "-");
    }

    #[test]
    fn renders_latest_port() {
        let s = |metric: &str, lane: Option<&str>, unit: &str, last: f64, total: bool| Series {
            interface: "Ethernet18/1".into(),
            metric: metric.into(),
            lane: lane.map(String::from),
            unit: unit.into(),
            stats: if total { Stats { total: Some(last), ..Default::default() } } else { Stats { last: Some(last), ..Default::default() } },
            points: None,
        };
        let r = MetricsReport {
            end: 1_794_355_200,
            start: None,
            step_secs: None,
            points_step_secs: None,
            body: MetricsBody::Ports {
                ports: vec![PortReport {
                    device: "switch02.sfo02.sfmix.org".into(),
                    interface: "Ethernet18/1".into(),
                    role: "participant port".into(),
                    owner_asn: Some(64500),
                    owner_name: Some("Example".into()),
                    members: vec!["Ethernet18/1".into()],
                    speed_bps: Some(10e9),
                    series: vec![
                        s("traffic_in", None, "bps", 1e9, false),
                        s("traffic_out", None, "bps", 2e9, false),
                        s("in_errors", None, "count", 3.0, true),
                        s("rx_dbm", Some("1"), "dBm", -2.13, false),
                        s("tx_dbm", Some("1"), "dBm", -2.59, false),
                        s("temp_c", None, "C", 36.5, false),
                    ],
                    notes: vec![],
                }],
            },
            notes: vec![],
        };
        let out = render(&r);
        assert!(out.contains("latest reading at 2026-11-11T00:00:00Z"), "{out}");
        assert!(out.contains("10.0%"), "{out}");
        assert!(out.contains("-2.13"), "{out}");
        assert!(out.contains("36.5"), "{out}");
        assert!(out.contains("AS64500 Example"), "{out}");
    }
}
