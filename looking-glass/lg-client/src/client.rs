use anyhow::{anyhow, Result};
use lg_types::command::Command;
use lg_types::identity::Identity;
use lg_types::rpc::{DeviceInfo, DeviceResultEvent, ErrorEvent, ExecuteRequest, ServiceInfo, StreamLineEvent, StreamEndEvent};
use tokio::sync::mpsc;
use tracing::warn;

use crate::sse::SseLineParser;

/// Event emitted by the RPC client during command execution.
#[derive(Debug)]
pub enum ExecuteEvent {
    /// A complete device result (non-streaming command output).
    Result(DeviceResultEvent),
    /// A single streaming line (ping/traceroute).
    StreamLine(StreamLineEvent),
    /// A device finished streaming.
    StreamEnd(StreamEndEvent),
    /// An error from the server.
    Error(ErrorEvent),
}

/// RPC client for communicating with lg-server.
#[derive(Clone)]
pub struct RpcClient {
    base_url: String,
    secret: String,
    http: reqwest::Client,
}

impl RpcClient {
    pub fn new(base_url: &str, secret: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            secret: secret.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Execute a command, returning a channel of SSE events.
    ///
    /// The caller receives events as they arrive from the server.
    /// The channel closes when the server sends a `done` event or the
    /// connection drops.
    pub async fn execute(
        &self,
        command: Command,
        identity: Identity,
        rate_key: String,
    ) -> Result<mpsc::Receiver<ExecuteEvent>> {
        let req = ExecuteRequest {
            command,
            identity,
            rate_key,
        };

        let resp = self
            .http
            .post(format!("{}/rpc/v1/execute", self.base_url))
            .header("X-RPC-Secret", &self.secret)
            .header("Content-Type", "application/json")
            .json(&req)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("RPC execute failed: {} {}", status, body));
        }

        let (tx, rx) = mpsc::channel(64);

        // Spawn a task to read the SSE stream and forward events
        let resp_bytes = resp;
        tokio::spawn(async move {
            if let Err(e) = read_sse_stream(resp_bytes, tx).await {
                warn!("SSE stream error: {e}");
            }
        });

        Ok(rx)
    }

    /// List available devices.
    pub async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let resp = self
            .http
            .get(format!("{}/rpc/v1/devices", self.base_url))
            .header("X-RPC-Secret", &self.secret)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("RPC list_devices failed: {} {}", status, body));
        }

        Ok(resp.json().await?)
    }

    /// Get service info.
    pub async fn service_info(&self) -> Result<ServiceInfo> {
        let resp = self
            .http
            .get(format!("{}/rpc/v1/service-info", self.base_url))
            .header("X-RPC-Secret", &self.secret)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("RPC service_info failed: {} {}", status, body));
        }

        Ok(resp.json().await?)
    }

    /// Generic GET that returns raw JSON (for proxying participants, netbox, etc.).
    pub async fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let resp = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .header("X-RPC-Secret", &self.secret)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("RPC GET {} failed: {} {}", path, status, body));
        }

        Ok(resp.json().await?)
    }
}

/// Read an SSE response stream, parsing events and forwarding them.
async fn read_sse_stream(
    response: reqwest::Response,
    tx: mpsc::Sender<ExecuteEvent>,
) -> Result<()> {
    let body = response.text().await?;
    let mut parser = SseLineParser::new();

    for line in body.lines() {
        if let Some(event) = parser.feed_line(line) {
            match dispatch_sse_event(&event.event, &event.data) {
                Some(ev) => {
                    if tx.send(ev).await.is_err() {
                        break; // receiver dropped
                    }
                }
                None => {
                    if event.event == "done" {
                        break;
                    }
                }
            }
        }
    }

    // Flush any trailing event
    if let Some(event) = parser.flush() {
        if let Some(ev) = dispatch_sse_event(&event.event, &event.data) {
            let _ = tx.send(ev).await;
        }
    }

    Ok(())
}

fn dispatch_sse_event(event_type: &str, data: &str) -> Option<ExecuteEvent> {
    match event_type {
        "result" => {
            match serde_json::from_str::<DeviceResultEvent>(data) {
                Ok(r) => Some(ExecuteEvent::Result(r)),
                Err(e) => {
                    warn!("Failed to parse result event: {e}");
                    None
                }
            }
        }
        "stream_line" => {
            match serde_json::from_str::<StreamLineEvent>(data) {
                Ok(r) => Some(ExecuteEvent::StreamLine(r)),
                Err(e) => {
                    warn!("Failed to parse stream_line event: {e}");
                    None
                }
            }
        }
        "stream_end" => {
            match serde_json::from_str::<StreamEndEvent>(data) {
                Ok(r) => Some(ExecuteEvent::StreamEnd(r)),
                Err(e) => {
                    warn!("Failed to parse stream_end event: {e}");
                    None
                }
            }
        }
        "error" => {
            match serde_json::from_str::<ErrorEvent>(data) {
                Ok(r) => Some(ExecuteEvent::Error(r)),
                Err(e) => {
                    warn!("Failed to parse error event: {e}");
                    None
                }
            }
        }
        "done" => None,
        _ => {
            warn!("Unknown SSE event type: {event_type}");
            None
        }
    }
}
