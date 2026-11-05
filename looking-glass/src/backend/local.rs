//! Commands that run on the looking-glass host itself rather than on a device.
//!
//! Traceroute runs once from here instead of fanning out to every switch and
//! router: the path out of the exchange is the same from any of them, and one
//! trace is far cheaper than N device SSH sessions.

use std::net::Ipv6Addr;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, Semaphore, SemaphorePermit};
use tokio::time::{timeout_at, Instant};
use tracing::{debug, warn};

/// Result label for output produced on the looking-glass host.
pub const LOCAL_DEVICE_NAME: &str = "looking-glass";

/// Concurrent local traceroutes, across all users.
static TRACEROUTE_SLOTS: Semaphore = Semaphore::const_new(4);

/// Per-line idle timeout and overall timeout, matching device streams.
const LINE_TIMEOUT: Duration = Duration::from_secs(10);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Reserve a local traceroute slot, or `None` if all are in use.
pub fn try_acquire_traceroute_slot() -> Option<SemaphorePermit<'static>> {
    TRACEROUTE_SLOTS.try_acquire().ok()
}

/// Run `traceroute` on this host and stream its output line by line.
///
/// `target` must already be validated (`is_valid_destination`): it is passed
/// as a single argv element (no shell) and cannot start with `-`. The child is
/// killed if the reader goes away, the trace goes quiet, or it runs too long.
pub fn traceroute_stream(
    target: &str,
    permit: SemaphorePermit<'static>,
) -> Result<mpsc::Receiver<String>> {
    let mut cmd = Command::new("traceroute");
    if target.parse::<Ipv6Addr>().is_ok() {
        cmd.arg("-6");
    }
    cmd.args(["-w", "2", "-q", "3", "-m", "30"])
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    debug!(target, "local traceroute");
    let mut child = cmd.spawn().context("failed to start traceroute")?;

    let (line_tx, mut line_rx) = mpsc::channel::<String>(64);
    if let Some(out) = child.stdout.take() {
        tokio::spawn(forward_lines(out, line_tx.clone()));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(forward_lines(err, line_tx));
    }

    let (tx, rx) = mpsc::channel::<String>(64);
    tokio::spawn(async move {
        let _permit = permit;
        let deadline = Instant::now() + TOTAL_TIMEOUT;
        loop {
            let wait_until = deadline.min(Instant::now() + LINE_TIMEOUT);
            match timeout_at(wait_until, line_rx.recv()).await {
                Ok(Some(line)) => {
                    if tx.send(line).await.is_err() {
                        break; // client went away
                    }
                }
                Ok(None) => break, // stdout and stderr closed
                Err(_) => {
                    let msg = if Instant::now() >= deadline {
                        format!("[timed out after {}s]", TOTAL_TIMEOUT.as_secs())
                    } else {
                        "[timed out waiting for output]".to_string()
                    };
                    let _ = tx.send(msg).await;
                    break;
                }
            }
        }
        let _ = child.start_kill();
        if let Err(e) = child.wait().await {
            warn!(error = %e, "reaping local traceroute failed");
        }
    });

    Ok(rx)
}

async fn forward_lines<R: AsyncRead + Unpin>(reader: R, tx: mpsc::Sender<String>) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if tx.send(line).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn traceroute_loopback_streams_and_releases_slot() {
        if std::process::Command::new("traceroute").arg("--version").output().is_err() {
            eprintln!("traceroute not installed; skipping");
            return;
        }
        let permit = try_acquire_traceroute_slot().expect("slot");
        let mut rx = traceroute_stream("127.0.0.1", permit).expect("spawn");
        let mut lines = Vec::new();
        while let Some(l) = rx.recv().await {
            lines.push(l);
        }
        assert!(lines.iter().any(|l| l.contains("127.0.0.1")), "{lines:?}");
        // The stream task drops its permit just after closing the channel.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(TRACEROUTE_SLOTS.available_permits(), 4);
    }
}
