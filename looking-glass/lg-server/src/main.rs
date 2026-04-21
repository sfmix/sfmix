use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use clap::Parser;
use tracing::info;

use looking_glass::backend::pool::DevicePool;
use looking_glass::bgp;
use looking_glass::config::{self, ParticipantsSourceConfig};
use looking_glass::netbox::{self, NetboxIxpData, NetboxStatus};
use looking_glass::oidc;
use looking_glass::participants::{ParticipantMap, PortMap};
use looking_glass::policy::PolicyEngine;
use looking_glass::ratelimit::{ConnectionTracker, DeviceRateLimiter, RateLimiter};
use looking_glass::service::LookingGlass;

#[path = "config.rs"]
mod server_config;
mod rpc_server;

#[derive(Parser)]
#[command(name = "lg-server", about = "Looking glass RPC backend")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/looking-glass/lg-server.yml")]
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
    let server_cfg = server_config::ServerConfig::load(&cli.config)?;

    info!("Starting {} looking glass RPC server", server_cfg.service.name);

    // Load participant mapping (and port map if file-based)
    let (participants, file_port_map) = match &server_cfg.participants {
        Some(ParticipantsSourceConfig::File { file }) => {
            info!("Loading participants from {}", file);
            match ParticipantMap::load_with_port_map(Path::new(file)) {
                Ok((pmap, port_map)) => (pmap, Some(port_map)),
                Err(e) => {
                    tracing::warn!("Failed to load participants: {e}, using empty map");
                    (ParticipantMap::empty(), None)
                }
            }
        }
        Some(ParticipantsSourceConfig::Netbox { .. }) => {
            (ParticipantMap::empty(), None)
        }
        None => {
            info!("No participant source configured, using empty map");
            (ParticipantMap::empty(), None)
        }
    };

    // Extract admin group name
    let admin_group = server_cfg
        .auth
        .as_ref()
        .map(|a| a.oidc.admin_group.clone())
        .unwrap_or_else(|| config::DEFAULT_ADMIN_GROUP.to_string());

    // Initialize policy engine
    let policy = match &server_cfg.policies {
        Some(ref ps) => {
            info!("Loading policies from {}", ps.file);
            PolicyEngine::load(Path::new(&ps.file)).unwrap_or_else(|e| {
                tracing::warn!("Failed to load policies: {e}, using default public policy");
                PolicyEngine::default_public()
            })
        }
        None => {
            info!("No policy file configured, using default public policy");
            PolicyEngine::default_public()
        }
    }
    .with_admin_group(&admin_group);

    // Initialize rate limiter
    let rl_config = server_cfg.rate_limits.as_ref();
    let rate_limiter = RateLimiter::new(
        rl_config.map(|r| r.global.max_concurrent).unwrap_or(10),
        rl_config.map(|r| r.global.commands_per_minute).unwrap_or(60),
        rl_config.map(|r| r.per_user.commands_per_minute).unwrap_or(10),
    );

    // Initialize device backend pool
    let device_pool = DevicePool::new(server_cfg.devices);
    info!("Configured devices: {:?}", device_pool.device_names());

    // Initialize per-device rate limiter
    let per_device_concurrent = rl_config.map(|r| r.per_device.max_concurrent).unwrap_or(2);
    let per_device_cpm = rl_config.map(|r| r.per_device.commands_per_minute).unwrap_or(20);
    let device_rate_limiter = DeviceRateLimiter::new(
        &device_pool.device_names(),
        per_device_concurrent,
        per_device_cpm,
    );

    // Initialize connection tracker
    let connection_tracker = ConnectionTracker::new(50, 5, 300);

    // Build OIDC client if configured
    let oidc_client = server_cfg.auth.as_ref().and_then(|auth| {
        match oidc::OidcClient::new(&auth.oidc) {
            Ok(c) => {
                info!("OIDC client configured for {}", auth.oidc.issuer);
                Some(c)
            }
            Err(e) => {
                tracing::warn!("Failed to create OIDC client: {e}");
                None
            }
        }
    });

    let group_prefix = server_cfg
        .auth
        .as_ref()
        .map(|a| a.oidc.group_prefix.clone())
        .unwrap_or_else(|| "as".to_string());
    let public_vlans = server_cfg.vlans.public.clone();

    // Initialize BGP source pool
    let bgp_source_pool = if server_cfg.bgp_sources.is_empty() {
        None
    } else {
        info!("Configuring {} BGP sources", server_cfg.bgp_sources.len());
        let pool = Arc::new(bgp::pool::BgpSourcePool::new(server_cfg.bgp_sources));
        pool.start_background_refresh();
        Some(pool)
    };

    let lg = Arc::new(LookingGlass {
        service_name: server_cfg.service.name.clone(),
        policy,
        rate_limiter,
        device_rate_limiter,
        connection_tracker,
        participants: ArcSwap::from_pointee(participants),
        port_map: ArcSwap::from_pointee(file_port_map.unwrap_or_else(PortMap::empty)),
        device_pool,
        group_prefix,
        admin_group: admin_group.clone(),
        oidc_client,
        public_vlans,
        netbox_status: ArcSwap::from_pointee(NetboxStatus::unconfigured()),
        ixp_data: ArcSwap::from_pointee(NetboxIxpData { switches: Vec::new(), vlans: Vec::new() }),
        netbox_participants: ArcSwap::from_pointee(Vec::new()),
        bgp_source_pool,
    });

    // NetBox participant source: initial fetch + background refresh
    if let Some(ParticipantsSourceConfig::Netbox { ref url, ref token_env, refresh_interval_secs, ref domain_suffix }) = server_cfg.participants {
        lg.netbox_status.store(Arc::new(NetboxStatus {
            configured: true,
            participant_count: 0,
            peering_port_count: 0,
            core_port_count: 0,
            port_map_size: 0,
            last_success: None,
            last_error: None,
            refresh_interval_secs,
            url: Some(url.clone()),
        }));

        let token = std::env::var(token_env).unwrap_or_else(|_| {
            tracing::warn!("NetBox token env var '{token_env}' not set");
            String::new()
        });
        if !token.is_empty() {
            info!("Fetching port map from NetBox: {url}");
            match netbox::fetch_port_map(url, &token, domain_suffix.as_deref()).await {
                Ok(result) => {
                    let pmap = ParticipantMap::build_from_netbox(&result.participants);
                    let port_map = PortMap::build(&result.participants, &result.core_ports, &result.admin_ports);
                    let pc = pmap.all().count();
                    let pmc = port_map.len();
                    let pp_count = result.participants.iter().map(|p| p.ports.len()).sum();
                    let core_count = result.core_ports.len();
                    info!("NetBox: {} participants, {} classified ports", pc, pmc);
                    lg.participants.store(Arc::new(pmap));
                    lg.port_map.store(Arc::new(port_map));
                    lg.ixp_data.store(Arc::new(result.ixp_data));
                    lg.netbox_participants.store(Arc::new(result.participants));
                    lg.netbox_status.store(Arc::new(NetboxStatus {
                        configured: true,
                        participant_count: pc,
                        peering_port_count: pp_count,
                        core_port_count: core_count,
                        port_map_size: pmc,
                        last_success: Some(std::time::Instant::now()),
                        last_error: None,
                        refresh_interval_secs,
                        url: Some(url.clone()),
                    }));
                }
                Err(e) => {
                    tracing::warn!("NetBox initial fetch failed: {e}");
                    let mut status = (*lg.netbox_status.load_full()).clone();
                    status.last_error = Some(e.to_string());
                    lg.netbox_status.store(Arc::new(status));
                }
            }

            if refresh_interval_secs > 0 {
                let state = lg.clone();
                let url = url.clone();
                let token = token.clone();
                let suffix = domain_suffix.clone();
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(refresh_interval_secs));
                    tick.tick().await;
                    loop {
                        tick.tick().await;
                        match netbox::fetch_port_map(&url, &token, suffix.as_deref()).await {
                            Ok(result) => {
                                let pmap = ParticipantMap::build_from_netbox(&result.participants);
                                let port_map = PortMap::build(&result.participants, &result.core_ports, &result.admin_ports);
                                let pc = pmap.all().count();
                                let pmc = port_map.len();
                                let pp_count = result.participants.iter().map(|p| p.ports.len()).sum();
                                let core_count = result.core_ports.len();
                                info!("NetBox refresh: {} participants, {} classified ports", pc, pmc);
                                state.participants.store(Arc::new(pmap));
                                state.port_map.store(Arc::new(port_map));
                                state.ixp_data.store(Arc::new(result.ixp_data));
                                state.netbox_participants.store(Arc::new(result.participants));
                                state.netbox_status.store(Arc::new(NetboxStatus {
                                    configured: true,
                                    participant_count: pc,
                                    peering_port_count: pp_count,
                                    core_port_count: core_count,
                                    port_map_size: pmc,
                                    last_success: Some(std::time::Instant::now()),
                                    last_error: None,
                                    refresh_interval_secs,
                                    url: Some(url.clone()),
                                }));
                            }
                            Err(e) => {
                                tracing::warn!("NetBox refresh failed: {e}");
                                let mut status = (*state.netbox_status.load_full()).clone();
                                status.last_error = Some(e.to_string());
                                state.netbox_status.store(Arc::new(status));
                            }
                        }
                    }
                });
            }
        }
    }

    // Resolve RPC shared secret from environment
    let rpc_secret = std::env::var(&server_cfg.rpc.secret_env).unwrap_or_else(|_| {
        tracing::warn!("RPC secret env var '{}' not set", server_cfg.rpc.secret_env);
        String::new()
    });

    // Start RPC server
    let rpc_state = Arc::new(rpc_server::RpcState {
        lg,
        rpc_secret,
    });

    let app = rpc_server::router(rpc_state);
    let listener = tokio::net::TcpListener::bind(&server_cfg.rpc.bind).await?;
    info!("RPC server listening on {}", server_cfg.rpc.bind);

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            info!("Shutting down RPC server");
        })
        .await?;

    Ok(())
}
