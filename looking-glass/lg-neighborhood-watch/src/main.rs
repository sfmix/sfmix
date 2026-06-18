//! lg-neighborhood-watch — a thin passive ARP/NDP sensor for the IX fabric.
//!
//! Runs on the route server, attached to the peering VLAN(s). It:
//!   - asks lg-server which IX IPs are assigned, and solicits them via the
//!     kernel (ICMP echo → kernel ARP/NDP), never transmitting L2 itself;
//!   - passively captures ARP and IPv6 NDP to learn every MAC heard per IP;
//!   - serves the current observations over an internal HTTP/JSON interface.
//!
//! It is stateless by design: durability, tenant-change invalidation, and
//! conflict history live in lg-server, which polls this sensor's `/neighbors`.

use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use clap::Parser;
use lg_client::client::RpcClient;
use tracing::info;

mod capture;
mod config;
mod http;
mod lgpoll;
mod solicit;
mod store;

#[derive(Parser)]
#[command(name = "lg-neighborhood-watch", about = "Passive ARP/NDP neighbor sensor")]
struct Cli {
    #[arg(short, long, default_value = "/etc/lg-neighborhood-watch/config.yml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    info!("Loading configuration from {}", cli.config.display());
    let contents = std::fs::read_to_string(&cli.config)?;
    let cfg: config::Config = serde_yaml::from_str(&contents)?;

    let rpc_secret = std::env::var(&cfg.lg_rpc_secret_env).unwrap_or_else(|_| {
        tracing::warn!("RPC secret env var '{}' not set", cfg.lg_rpc_secret_env);
        String::new()
    });
    let rpc = RpcClient::new(&cfg.lg_rpc_url, &rpc_secret);

    // Shared state.
    let table = Arc::new(ArcSwap::from_pointee(store::Snapshot::default()));
    let targets = Arc::new(ArcSwap::from_pointee(Vec::<String>::new()));
    let last_lg_sync = Arc::new(ArcSwap::from_pointee(None::<String>));
    let dropped = Arc::new(AtomicU64::new(0));

    // Writer task: drain observations into the published snapshot.
    let (tx, rx) = tokio::sync::mpsc::channel::<store::Observation>(4096);
    {
        let table = table.clone();
        tokio::spawn(async move { store::run_writer(rx, table).await });
    }

    // Capture threads, one per interface.
    for iface in &cfg.interfaces {
        capture::spawn_capture(iface.clone(), tx.clone(), dropped.clone());
    }
    drop(tx); // capture threads hold their own clones

    // Solicitation: warn early if raw sockets are unavailable, then sweep.
    solicit::preflight();
    {
        let targets = targets.clone();
        let (interval, pace) = (cfg.solicit_interval_secs, cfg.solicit_pace_ms);
        tokio::spawn(async move { solicit::run(targets, interval, pace).await });
    }

    // lg-server poll: refresh the assigned-IP (solicit target) set.
    {
        let rpc = rpc.clone();
        let targets = targets.clone();
        let last_sync = last_lg_sync.clone();
        let interval = cfg.lg_poll_interval_secs;
        tokio::spawn(async move { lgpoll::run(rpc, targets, last_sync, interval).await });
    }

    let state = http::AppState {
        table,
        targets,
        last_lg_sync,
        dropped,
        ifaces: cfg.interfaces.clone(),
    };
    let app = http::router(state);

    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    info!("lg-neighborhood-watch listening on {}", cfg.bind);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            info!("shutting down");
        })
        .await?;

    Ok(())
}
