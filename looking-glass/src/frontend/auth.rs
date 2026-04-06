//! Shared HTTP authentication helpers for REST and MCP frontends.
//!
//! Both frontends verify Bearer tokens the same way; this module
//! eliminates the duplication.

use axum::http::HeaderMap;
use tracing::{debug, info};

use crate::identity::Identity;
use crate::oidc::OidcClient;

/// Extract Bearer token from Authorization header.
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Extract service API key from X-API-Key header.
pub fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Extract client IP from X-Forwarded-For or X-Real-IP for rate limiting.
pub fn extract_client_ip(headers: &HeaderMap) -> Option<std::net::IpAddr> {
    headers
        .get("X-Forwarded-For")
        .or_else(|| headers.get("X-Real-IP"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
}

/// Resolve identity and rate-limit key from HTTP headers.
///
/// Priority: X-API-Key service token > Bearer OIDC token > anonymous.
pub async fn resolve_identity(
    headers: &HeaderMap,
    oidc_client: &Option<OidcClient>,
    group_prefix: &str,
    admin_group: &str,
    service_tokens: &[String],
    frontend: &str,
) -> (Identity, String) {
    let client_ip = extract_client_ip(headers);

    // Check X-API-Key for service token auth first
    if let Some(api_key) = extract_api_key(headers) {
        if service_tokens.iter().any(|t| t == &api_key) {
            info!("{frontend}: authenticated via service API key");
            let identity = Identity::service(admin_group);
            let rate_key = "service".to_string();
            return (identity, rate_key);
        } else {
            debug!("{frontend}: invalid service API key");
        }
    }

    let token = extract_bearer_token(headers);

    match (oidc_client, token) {
        (Some(oidc), Some(token)) => {
            match oidc.verify_id_token(&token).await {
                Ok(claims) => {
                    debug!(email = %claims.email, groups = ?claims.groups, "{frontend}: authenticated via Bearer token");
                    let rate_key = claims.email.clone();
                    let identity = Identity::from_oidc_claims(
                        claims.email,
                        claims.groups,
                        group_prefix,
                    );
                    (identity, rate_key)
                }
                Err(e) => {
                    debug!(error = %e, "{frontend}: Bearer token verification failed");
                    anonymous_with_ip(client_ip)
                }
            }
        }
        _ => {
            let (identity, rate_key) = anonymous_with_ip(client_ip);
            debug!(rate_key = %rate_key, "{frontend}: anonymous request");
            (identity, rate_key)
        }
    }
}

fn anonymous_with_ip(client_ip: Option<std::net::IpAddr>) -> (Identity, String) {
    let rate_key = client_ip
        .map(crate::ratelimit::ip_to_rate_key)
        .unwrap_or_else(|| "anonymous".to_string());
    (Identity::anonymous(), rate_key)
}
