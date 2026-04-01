use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::info;

mod command;
mod completion;
mod config;
mod identity;
mod participants;
mod policy;
mod ratelimit;

mod backend;
mod frontend;

use backend::pool::DevicePool;
use config::ParticipantsSourceConfig;
use frontend::mcp::McpFrontend;
use frontend::ssh::SshFrontend;
use frontend::telnet::{TelnetServer, TelnetState};
use participants::ParticipantMap;
use policy::PolicyEngine;
use ratelimit::RateLimiter;

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

    // Load participant mapping
    let participants = match &config.participants {
        Some(ParticipantsSourceConfig::File { file }) => {
            info!("Loading participants from {}", file);
            ParticipantMap::load_from_file(Path::new(file)).unwrap_or_else(|e| {
                tracing::warn!("Failed to load participants: {e}, using empty map");
                ParticipantMap::empty()
            })
        }
        _ => {
            info!("No participant source configured, using empty map");
            ParticipantMap::empty()
        }
    };

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
    };

    // Initialize rate limiter
    let rl_config = config.rate_limits.as_ref();
    let per_device_concurrent = rl_config.map(|r| r.per_device.max_concurrent).unwrap_or(2);
    let rate_limiter = RateLimiter::new(
        rl_config.map(|r| r.global.max_concurrent).unwrap_or(10),
        rl_config.map(|r| r.per_user.commands_per_minute).unwrap_or(10),
    );

    // Initialize device backend pool
    let device_pool = DevicePool::new(config.devices, per_device_concurrent);
    info!("Configured devices: {:?}", device_pool.device_names());

    // Build shared state
    let group_prefix = config
        .auth
        .as_ref()
        .map(|a| a.oidc.group_prefix.clone())
        .unwrap_or_else(|| "as".to_string());
    let telnet_state = Arc::new(TelnetState {
        service_name: config.service.name.clone(),
        policy,
        rate_limiter,
        participants,
        device_pool,
        group_prefix,
    });

    // Start telnet server
    if let Some(ref telnet_config) = config.listen.telnet {
        if telnet_config.enabled {
            let server = TelnetServer::new(telnet_config.bind.clone(), telnet_state.clone());
            tokio::spawn(async move {
                if let Err(e) = server.run().await {
                    tracing::error!("Telnet server error: {e}");
                }
            });
        }
    } else {
        // Default: start telnet on [::]:23
        let server = TelnetServer::new("[::]:23".to_string(), telnet_state.clone());
        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                tracing::error!("Telnet server error: {e}");
            }
        });
    }

    // Start SSH server
    if let Some(ref ssh_config) = config.listen.ssh {
        if ssh_config.enabled {
            match SshFrontend::new(
                ssh_config.bind.clone(),
                &ssh_config.host_key,
                telnet_state.clone(),
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

    // Start MCP server
    if let Some(ref mcp_config) = config.listen.mcp {
        if mcp_config.enabled {
            let mcp_server = McpFrontend::new(
                mcp_config.bind.clone(),
                telnet_state.clone(),
            );
            tokio::spawn(async move {
                if let Err(e) = mcp_server.run().await {
                    tracing::error!("MCP server error: {e}");
                }
            });
        }
    }

    info!("Looking glass ready");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down");

    Ok(())
}
