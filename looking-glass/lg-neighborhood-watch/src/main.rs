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

mod afpacket;
mod bum;
mod capture;
mod config;
mod evidence;
mod http;
mod lgpoll;
mod ringbuf;
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
        let ttl = cfg.sensor_ttl_secs;
        tokio::spawn(async move { store::run_writer(rx, table, ttl).await });
    }

    // Evidence capture (optional): rolling pcap ring buffer + extraction store.
    // Capture threads tee raw ARP/NDP frames to the ring writer.
    let (evidence_store, ring_tx) = if let Some(ref dir) = cfg.evidence_dir {
        let dir = PathBuf::from(dir);
        let ring_dir = dir.join("ring");
        let ring_cfg = ringbuf::RingConfig::new(ring_dir.clone(), cfg.ring_buffer_secs, cfg.ring_buffer_max_bytes);
        // Bounded handoff; capture drops on backpressure rather than blocking.
        let (rtx, rrx) = std::sync::mpsc::sync_channel::<ringbuf::CapturedFrame>(8192);
        std::thread::Builder::new()
            .name("ring-writer".into())
            .spawn(move || ringbuf::run_ring_writer(rrx, ring_cfg))
            .expect("spawn ring writer thread");
        match evidence::EvidenceStore::new(dir.join("snapshots"), ring_dir, cfg.evidence_max_bytes) {
            Ok(store) => {
                info!(
                    "Evidence capture enabled (dir: {}, ring {}s/{}MiB, evidence cap {}MiB)",
                    dir.display(),
                    cfg.ring_buffer_secs,
                    cfg.ring_buffer_max_bytes / (1024 * 1024),
                    cfg.evidence_max_bytes / (1024 * 1024),
                );
                (Some(Arc::new(store)), Some(rtx))
            }
            Err(e) => {
                tracing::warn!("evidence store init failed ({e}); evidence capture disabled");
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    // LAN-hygiene classifier: detections + per-second rate samples from the
    // capture threads fold into one bounded table (bum.rs).
    let bum_table = Arc::new(ArcSwap::from_pointee(bum::BumSnapshot::default()));
    let bum_frames: bum::FrameStore = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let bum_dropped = Arc::new(AtomicU64::new(0));
    let kernel_frames = Arc::new(AtomicU64::new(0));
    let kernel_drops = Arc::new(AtomicU64::new(0));
    let (bum_tx, bum_rx) = tokio::sync::mpsc::channel::<bum::BumMsg>(4096);
    {
        let (table, frames) = (bum_table.clone(), bum_frames.clone());
        let (ttl, pps) = (cfg.bum_ttl_secs, cfg.bum_flood_pps);
        tokio::spawn(async move { bum::run_writer(bum_rx, table, frames, ttl, pps).await });
    }
    let ignore_src_macs: std::collections::HashSet<[u8; 6]> = cfg
        .ignore_src_macs
        .iter()
        .filter_map(|m| {
            let parsed = afpacket::parse_mac(m);
            if parsed.is_none() {
                tracing::warn!("ignore_src_macs: unparseable MAC {m:?} skipped");
            }
            parsed
        })
        .collect();
    let classify_ctx = Arc::new(ArcSwap::from_pointee(bum::ClassifyCtx {
        ignore_src_macs: ignore_src_macs.clone(),
        ..Default::default()
    }));
    info!(
        "LAN-hygiene classifier enabled ({} mode, ttl {}s, flood {} pps, {} ignored MACs)",
        cfg.capture_mode.as_str(),
        cfg.bum_ttl_secs,
        cfg.bum_flood_pps,
        ignore_src_macs.len()
    );

    // Capture threads, one per interface.
    let sinks = capture::CaptureSinks {
        obs_tx: tx,
        ring_tx,
        bum_tx,
        ctx: classify_ctx.clone(),
        mode: cfg.capture_mode,
        dropped: dropped.clone(),
        bum_dropped: bum_dropped.clone(),
        kernel_frames: kernel_frames.clone(),
        kernel_drops: kernel_drops.clone(),
    };
    for iface in &cfg.interfaces {
        capture::spawn_capture(iface.clone(), sinks.clone());
    }
    drop(sinks); // capture threads hold their own clones

    // Solicitation: warn early if raw sockets are unavailable, then sweep.
    solicit::preflight();
    {
        let targets = targets.clone();
        let (interval, pace) = (cfg.solicit_interval_secs, cfg.solicit_pace_ms);
        tokio::spawn(async move { solicit::run(targets, interval, pace).await });
    }

    // lg-server poll: refresh the assigned-IP (solicit target) set + IX prefixes.
    {
        let rpc = rpc.clone();
        let targets = targets.clone();
        let last_sync = last_lg_sync.clone();
        let interval = cfg.lg_poll_interval_secs;
        let ctx = classify_ctx.clone();
        tokio::spawn(async move { lgpoll::run(rpc, targets, last_sync, interval, ctx, ignore_src_macs).await });
    }

    let state = http::AppState {
        table,
        targets,
        last_lg_sync,
        dropped,
        ifaces: cfg.interfaces.clone(),
        evidence: evidence_store,
        bum: bum_table,
        bum_frames,
        bum_dropped,
        kernel_frames,
        kernel_drops,
        capture_mode: cfg.capture_mode.as_str(),
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
