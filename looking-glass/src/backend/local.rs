//! Commands that run on the looking-glass host itself rather than on a device.
//!
//! Ping and traceroute run once from here instead of fanning out to every
//! switch and router: one probe from inside the exchange answers the question,
//! and it is far cheaper than N device SSH sessions.

use std::net::Ipv6Addr;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, Semaphore, SemaphorePermit};
use tokio::time::{timeout_at, Instant};
use tracing::{debug, warn};

use crate::command::Verb;

/// Result label for output produced on the looking-glass host.
pub const LOCAL_DEVICE_NAME: &str = "looking-glass";

/// Concurrent local ping/traceroute runs, across all users.
static SLOTS: Semaphore = Semaphore::const_new(4);

/// Per-line idle timeout and overall timeout, matching device streams.
const LINE_TIMEOUT: Duration = Duration::from_secs(10);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Reserve a local run slot, or `None` if all are in use.
pub fn try_acquire_slot() -> Option<SemaphorePermit<'static>> {
    SLOTS.try_acquire().ok()
}

/// argv for `verb` to `target`.
fn argv(verb: Verb, target: &str) -> Result<(&'static str, Vec<String>)> {
    let mut args = Vec::new();
    if target.parse::<Ipv6Addr>().is_ok() {
        args.push("-6".to_string());
    }
    let prog = match verb {
        // 5 echoes, 1s apart, 2s per-reply wait, hard 10s deadline.
        Verb::Ping => {
            args.extend(["-c", "5", "-i", "1", "-W", "2", "-w", "10"].map(String::from));
            "ping"
        }
        Verb::Traceroute => {
            args.extend(["-w", "2", "-q", "3", "-m", "30"].map(String::from));
            "traceroute"
        }
        Verb::Show => bail!("show does not run locally"),
    };
    args.push(target.to_string());
    Ok((prog, args))
}

/// Run ping/traceroute on this host and stream its output line by line.
///
/// `target` must already be validated (`is_valid_destination`): it is passed
/// as a single argv element (no shell) and cannot start with `-`. The child is
/// killed if the reader goes away, output goes quiet, or it runs too long.
pub fn stream(
    verb: Verb,
    target: &str,
    permit: SemaphorePermit<'static>,
) -> Result<mpsc::Receiver<String>> {
    let (prog, args) = argv(verb, target)?;
    debug!(prog, target, "local network probe");
    let mut child = Command::new(prog)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to start {prog}"))?;

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
            warn!(error = %e, "reaping local {prog} failed");
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

    #[test]
    fn argv_adds_family_flag_only_for_v6_literals() {
        let (p, a) = argv(Verb::Ping, "2001:db8::1").unwrap();
        assert_eq!(p, "ping");
        assert_eq!(a.first().unwrap(), "-6");
        assert_eq!(a.last().unwrap(), "2001:db8::1");
        let (p, a) = argv(Verb::Traceroute, "example.com").unwrap();
        assert_eq!(p, "traceroute");
        assert!(!a.contains(&"-6".to_string()));
        assert!(argv(Verb::Show, "x").is_err());
    }

    async fn run_loopback(verb: Verb, prog: &str) {
        if std::process::Command::new(prog).arg("-V").output().is_err() {
            eprintln!("{prog} not installed; skipping");
            return;
        }
        let permit = try_acquire_slot().expect("slot");
        let mut rx = stream(verb, "127.0.0.1", permit).expect("spawn");
        let mut lines = Vec::new();
        while let Some(l) = rx.recv().await {
            lines.push(l);
        }
        assert!(lines.iter().any(|l| l.contains("127.0.0.1")), "{lines:?}");
    }

    #[tokio::test]
    async fn loopback_probes_stream_and_release_slots() {
        run_loopback(Verb::Traceroute, "traceroute").await;
        run_loopback(Verb::Ping, "ping").await;
        // The stream task drops its permit just after closing the channel.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(SLOTS.available_permits(), 4);
    }
}
