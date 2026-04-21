use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use clap::Parser;
use tracing::info;

use looking_glass::backend::pool::DevicePool;
use looking_glass::config::{self, ParticipantsSourceConfig};
use looking_glass::frontend::http::HttpFrontend;
use looking_glass::frontend::ssh::SshFrontend;
use looking_glass::frontend::telnet::TelnetServer;
use looking_glass::netbox::{self, NetboxIxpData, NetboxStatus};
use looking_glass::oidc;
use looking_glass::participants::{ParticipantMap, PortMap};
use looking_glass::policy::PolicyEngine;
use looking_glass::ratelimit::{ConnectionTracker, DeviceRateLimiter, RateLimiter};
use looking_glass::service::LookingGlass;
use looking_glass::bgp;
use looking_glass::frontend;

#[derive(Parser)]
#[command(name = "looking-glass", about = "Multi-purpose IXP looking glass")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/looking-glass/config.yml")]
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
    let config = config::Config::load(&cli.config)?;

    info!("Starting {} looking glass", config.service.name);

    // Load participant mapping (and port map if file-based)
    let (participants, file_port_map) = match &config.participants {
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
            // Initial fetch happens after shared state is built (below)
            (ParticipantMap::empty(), None)
        }
        None => {
            info!("No participant source configured, using empty map");
            (ParticipantMap::empty(), None)
        }
    };

    // Extract admin group name from config (default: "IX Administrators")
    let admin_group = config
        .auth
        .as_ref()
        .map(|a| a.oidc.admin_group.clone())
        .unwrap_or_else(|| config::DEFAULT_ADMIN_GROUP.to_string());

    // Initialize policy engine
    let policy = match &config.policies {
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
    let rl_config = config.rate_limits.as_ref();
    let rate_limiter = RateLimiter::new(
        rl_config.map(|r| r.global.max_concurrent).unwrap_or(10),
        rl_config.map(|r| r.global.commands_per_minute).unwrap_or(60),
        rl_config.map(|r| r.per_user.commands_per_minute).unwrap_or(10),
    );

    // Initialize device backend pool
    let device_pool = DevicePool::new(config.devices);
    info!("Configured devices: {:?}", device_pool.device_names());

    // Initialize per-device rate limiter
    let per_device_concurrent = rl_config.map(|r| r.per_device.max_concurrent).unwrap_or(2);
    let per_device_cpm = rl_config.map(|r| r.per_device.commands_per_minute).unwrap_or(20);
    let device_rate_limiter = DeviceRateLimiter::new(
        &device_pool.device_names(),
        per_device_concurrent,
        per_device_cpm,
    );

    // Initialize connection tracker (frontend limits)
    let fl_config = config.frontend_limits.as_ref();
    let connection_tracker = ConnectionTracker::new(
        fl_config.map(|f| f.max_connections).unwrap_or(50),
        fl_config.map(|f| f.max_connections_per_source).unwrap_or(5),
        fl_config.map(|f| f.idle_timeout_secs).unwrap_or(300),
    );

    // Build OIDC client if configured (shared between frontends)
    let oidc_client = config.auth.as_ref().and_then(|auth| {
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

    // Build the central LookingGlass service
    let group_prefix = config
        .auth
        .as_ref()
        .map(|a| a.oidc.group_prefix.clone())
        .unwrap_or_else(|| "as".to_string());
    let public_vlans = config.vlans.public.clone();

    // Initialize BGP source pool if configured
    let bgp_source_pool = if config.bgp_sources.is_empty() {
        None
    } else {
        info!("Configuring {} BGP sources", config.bgp_sources.len());
        let pool = Arc::new(bgp::pool::BgpSourcePool::new(config.bgp_sources));
        pool.start_background_refresh();
        Some(pool)
    };

    let lg = Arc::new(LookingGlass {
        service_name: config.service.name.clone(),
        policy,
        rate_limiter,
        device_rate_limiter,
        connection_tracker,
        participants: ArcSwap::from_pointee(participants),
        port_map: ArcSwap::from_pointee(file_port_map.unwrap_or_else(PortMap::empty)),
        device_pool,
        group_prefix,
        admin_group: config.auth.as_ref().map(|a| a.oidc.admin_group.clone()).unwrap_or_else(|| "IX Administrators".to_string()),
        oidc_client: oidc_client.clone(),
        public_vlans,
        netbox_status: ArcSwap::from_pointee(NetboxStatus::unconfigured()),
        ixp_data: ArcSwap::from_pointee(NetboxIxpData { switches: Vec::new(), vlans: Vec::new() }),
        netbox_participants: ArcSwap::from_pointee(Vec::new()),
        bgp_source_pool,
    });

    // Start telnet server
    if let Some(ref telnet_config) = config.listen.telnet {
        if telnet_config.enabled {
            let server = TelnetServer::new(telnet_config.bind.clone(), lg.clone());
            tokio::spawn(async move {
                if let Err(e) = server.run().await {
                    tracing::error!("Telnet server error: {e}");
                }
            });
        }
    } else {
        // Default: start telnet on [::]:23
        let server = TelnetServer::new("[::]:23".to_string(), lg.clone());
        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                tracing::error!("Telnet server error: {e}");
            }
        });
    }

    // Start SSH server
    if let Some(ref ssh_config) = config.listen.ssh {
        if ssh_config.enabled {
            let cert_lifetime = config
                .auth
                .as_ref()
                .map(|a| a.oidc.cert_lifetime_secs)
                .unwrap_or(43200);

            match SshFrontend::new(
                ssh_config.bind.clone(),
                &ssh_config.host_key,
                ssh_config.ca_key.as_deref(),
                oidc_client,
                cert_lifetime,
                lg.clone(),
            ) {
                Ok(mut ssh_server) => {
                    tokio::spawn(async move {
                        if let Err(e) = ssh_server.run().await {
                            tracing::error!("SSH server error: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to initialize SSH server: {e}");
                }
            }
        }
    }

    // Start unified HTTP server (REST + MCP)
    //
    // Precedence: listen.http > legacy listen.rest / listen.mcp
    // If the old keys are present but listen.http is absent, fall back to
    // starting separate legacy servers (REST-only or MCP-only).
    if let Some(ref http_config) = config.listen.http {
        if http_config.enabled {
            let http_server = HttpFrontend::new(
                http_config.bind.clone(),
                lg.clone(),
            );
            tokio::spawn(async move {
                if let Err(e) = http_server.run().await {
                    tracing::error!("HTTP server error: {e}");
                }
            });
        }
    } else {
        // Legacy: start separate REST and MCP servers if configured
        if let Some(ref rest_config) = config.listen.rest {
            if rest_config.enabled {
                let rest_server = frontend::rest::RestFrontend::new(
                    rest_config.bind.clone(),
                    lg.clone(),
                    config.auth.as_ref().and_then(|auth| oidc::OidcClient::new(&auth.oidc).ok()),
                );
                tokio::spawn(async move {
                    if let Err(e) = rest_server.run().await {
                        tracing::error!("REST API server error: {e}");
                    }
                });
            }
        }
        if let Some(ref _mcp_config) = config.listen.mcp {
            tracing::warn!("listen.mcp is deprecated — migrate to listen.http");
        }
    }

    // NetBox participant source: initial fetch + background refresh
    if let Some(ParticipantsSourceConfig::Netbox { ref url, ref token_env, refresh_interval_secs, ref domain_suffix }) = config.participants {
        // Seed initial status as "configured but not yet fetched"
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

            // Background refresh
            if refresh_interval_secs > 0 {
                let state = lg.clone();
                let url = url.clone();
                let token = token.clone();
                let suffix = domain_suffix.clone();
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(refresh_interval_secs));
                    tick.tick().await; // skip immediate first tick
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

    info!("Looking glass ready");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down");

    Ok(())
}
