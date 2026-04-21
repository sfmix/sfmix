use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::info;

use lg_client::client::RpcClient;
use looking_glass::oidc::OidcClient;

mod mcp;
mod rest;

#[derive(Parser)]
#[command(name = "lg-http", about = "Looking glass HTTP frontend (REST API + MCP)")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/looking-glass/lg-http.yml")]
    config: PathBuf,
}

#[derive(Debug, serde::Deserialize)]
struct HttpConfig {
    /// RPC backend URL (e.g. "http://127.0.0.1:9090")
    rpc_url: String,
    /// Env var name holding the shared secret for RPC authentication
    #[serde(default = "default_rpc_secret_env")]
    rpc_secret_env: String,
    /// HTTP listen address
    #[serde(default = "default_bind")]
    bind: String,
    /// OIDC config for Bearer token verification
    #[serde(default)]
    auth: Option<looking_glass::config::AuthConfig>,
}

fn default_bind() -> String {
    "[::]:8080".to_string()
}
fn default_rpc_secret_env() -> String {
    "LG_RPC_SECRET".to_string()
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
    let config: HttpConfig = serde_yaml::from_str(&contents)?;

    // Connect to lg-server RPC backend
    info!("Connecting to RPC backend at {}", config.rpc_url);
    let rpc_secret = std::env::var(&config.rpc_secret_env).unwrap_or_else(|_| {
        tracing::warn!("RPC secret env var '{}' not set", config.rpc_secret_env);
        String::new()
    });
    let rpc = RpcClient::new(&config.rpc_url, &rpc_secret);
    let svc_info = rpc.service_info().await?;
    info!(
        "Connected to {} ({} devices)",
        svc_info.name, svc_info.device_count
    );

    // Build OIDC client if configured
    let oidc_client = config.auth.as_ref().and_then(|auth| {
        match OidcClient::new(&auth.oidc) {
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

    let group_prefix = config
        .auth
        .as_ref()
        .map(|a| a.oidc.group_prefix.clone())
        .unwrap_or_else(|| "as".to_string());

    let authorization_server = config
        .auth
        .as_ref()
        .and_then(|a| a.oidc.authorization_server.clone());

    let state = rest::HttpState {
        rpc,
        oidc_client,
        group_prefix,
        authorization_server,
    };

    // MCP router with its own auth middleware
    let ct = tokio_util::sync::CancellationToken::new();
    let mcp_rpc = state.rpc.clone();
    let mcp_oidc = state.oidc_client.clone();
    let mcp_group_prefix = state.group_prefix.clone();

    let mcp_router = mcp::router(mcp_rpc, ct.clone()).layer(
        axum::middleware::from_fn(move |req, next| {
            let gp = mcp_group_prefix.clone();
            let oc = mcp_oidc.clone();
            mcp::auth_middleware(req, next, gp, oc)
        }),
    );

    let app = rest::router(state).merge(mcp_router);

    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    info!("HTTP server listening on {}", config.bind);

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            info!("Shutting down HTTP server");
        })
        .await?;

    Ok(())
}
