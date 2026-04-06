use std::sync::Arc;

use axum::middleware;
use tracing::info;

use crate::oidc::OidcClient;
use crate::service::LookingGlass;

use super::mcp;
use super::rest::{self, RestState};

/// Unified HTTP frontend serving REST API (`/api/v1/*`) and MCP (`/mcp`)
/// on a single listener.
pub struct HttpFrontend {
    bind_addr: String,
    lg: Arc<LookingGlass>,
    service_tokens: Vec<String>,
}

impl HttpFrontend {
    pub fn new(bind_addr: String, lg: Arc<LookingGlass>, service_tokens: Vec<String>) -> Self {
        Self { bind_addr, lg, service_tokens }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let ct = tokio_util::sync::CancellationToken::new();

        // REST router — /api/v1/* with its own auth middleware
        let oidc_client: Option<OidcClient> = self.lg.oidc_client.clone();
        let rest_state = RestState {
            lg: self.lg.clone(),
            oidc_client: oidc_client.clone(),
            service_tokens: self.service_tokens.clone(),
        };
        let rest_router = rest::router(rest_state);

        // MCP router — /mcp with task-local auth middleware
        let mcp_router = mcp::router(self.lg.clone(), ct.child_token());
        let group_prefix = self.lg.group_prefix.clone();
        let admin_group = self.lg.admin_group.clone();
        let mcp_service_tokens = self.service_tokens.clone();
        let mcp_oidc = oidc_client;
        let mcp_router = mcp_router.layer(middleware::from_fn(move |req, next| {
            let gp = group_prefix.clone();
            let ag = admin_group.clone();
            let st = mcp_service_tokens.clone();
            let oc = mcp_oidc.clone();
            mcp::auth_middleware(req, next, gp, ag, st, oc)
        }));

        // Merge into one router
        let app = rest_router.merge(mcp_router);

        let listener = tokio::net::TcpListener::bind(&self.bind_addr).await?;
        info!("HTTP server listening on {} (REST + MCP)", self.bind_addr);

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                tokio::signal::ctrl_c().await.ok();
                ct.cancel();
            })
            .await?;
        Ok(())
    }
}
