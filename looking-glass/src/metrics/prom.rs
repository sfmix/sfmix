//! Minimal read-only Prometheus HTTP API client and PromQL escaping.
//!
//! Every query string is built in this crate from resolved, validated
//! (device, interface) pairs; callers never supply PromQL.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::Deserialize;

pub type Labels = HashMap<String, String>;

#[derive(Clone)]
pub struct PromClient {
    base_url: String,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct ApiResponse {
    status: String,
    #[serde(default)]
    data: Option<ApiData>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct ApiData {
    #[serde(default)]
    result: Vec<ApiSeries>,
}

#[derive(Deserialize)]
struct ApiSeries {
    metric: Labels,
    #[serde(default)]
    value: Option<(f64, String)>,
    #[serde(default)]
    values: Vec<(f64, String)>,
}

/// One series from a range query: labels plus (unix ts, value) samples.
pub struct RangeSeries {
    pub labels: Labels,
    pub samples: Vec<(i64, f64)>,
}

impl PromClient {
    pub fn new(base_url: &str, timeout: Duration) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout)
            .build()
            .expect("building reqwest Prometheus client");
        Self { base_url: base_url.trim_end_matches('/').to_string(), http }
    }

    async fn get(&self, path: &str, params: &[(&str, String)]) -> Result<Vec<ApiSeries>> {
        let resp = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .query(params)
            .send()
            .await?;
        let status = resp.status();
        let body: ApiResponse = resp
            .json()
            .await
            .map_err(|e| anyhow!("prometheus {status}: undecodable response: {e}"))?;
        if body.status != "success" {
            return Err(anyhow!(
                "prometheus query failed: {}",
                body.error.unwrap_or_else(|| status.to_string())
            ));
        }
        Ok(body.data.map(|d| d.result).unwrap_or_default())
    }

    /// Instant query evaluated at `time`. Returns (labels, value) per series.
    pub async fn instant(&self, query: &str, time: i64) -> Result<Vec<(Labels, f64)>> {
        let rows = self
            .get("/api/v1/query", &[("query", query.to_string()), ("time", time.to_string())])
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|s| {
                let v = s.value.as_ref().and_then(|(_, v)| parse_val(v))?;
                Some((s.metric, v))
            })
            .collect())
    }

    /// Range query over [start, end] at `step` seconds.
    pub async fn range(&self, query: &str, start: i64, end: i64, step: u64) -> Result<Vec<RangeSeries>> {
        let rows = self
            .get(
                "/api/v1/query_range",
                &[
                    ("query", query.to_string()),
                    ("start", start.to_string()),
                    ("end", end.to_string()),
                    ("step", step.to_string()),
                ],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|s| RangeSeries {
                samples: s
                    .values
                    .iter()
                    .filter_map(|(t, v)| Some((t.round() as i64, parse_val(v)?)))
                    .collect(),
                labels: s.metric,
            })
            .collect())
    }
}

fn parse_val(v: &str) -> Option<f64> {
    let f: f64 = v.parse().ok()?;
    f.is_finite().then_some(f)
}

/// Escape a value for a PromQL double-quoted string literal.
pub fn esc(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Escape RE2 metacharacters so `value` matches literally inside `=~`.
pub fn re_esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// An `=~` alternation matching exactly the given names (already literal).
pub fn alternation<'a>(names: impl IntoIterator<Item = &'a str>) -> String {
    let parts: Vec<String> = names.into_iter().map(re_esc).collect();
    parts.join("|")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_regex_and_string() {
        assert_eq!(re_esc("Ethernet3/1.998"), "Ethernet3/1\\.998");
        assert_eq!(esc(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(alternation(["Ethernet1/1", "Port-Channel5"]), "Ethernet1/1|Port-Channel5");
    }
}
