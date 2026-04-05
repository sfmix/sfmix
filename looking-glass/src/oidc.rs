use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::config::OidcConfig;

/// OIDC client for device authorization flow + JWT verification.
#[derive(Clone)]
pub struct OidcClient {
    http: Client,
    config: Arc<OidcConfig>,
    jwks_cache: Arc<RwLock<JwksCache>>,
}

struct JwksCache {
    keys: Vec<JwkKey>,
    fetched_at: Option<SystemTime>,
}

/// Result of a successful OIDC device authorization flow.
#[derive(Debug, Clone)]
pub struct OidcClaims {
    pub email: String,
    pub groups: Vec<String>,
}

// --- Wire types for OIDC / JWKS responses ---

#[derive(Deserialize)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: Option<String>,
    verification_uri_complete: Option<String>,
    #[serde(default = "default_interval")]
    interval: u64,
    expires_in: u64,
}

fn default_interval() -> u64 {
    5
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct OpenIdConfiguration {
    #[serde(default)]
    jwks_uri: Option<String>,
    #[serde(default)]
    device_authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
}

#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct JwkKey {
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    // RSA fields
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    // EC fields
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    preferred_username: Option<String>,
}

impl OidcClient {
    pub fn new(config: &OidcConfig) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to create HTTP client")?;

        Ok(Self {
            http,
            config: Arc::new(config.clone()),
            jwks_cache: Arc::new(RwLock::new(JwksCache {
                keys: Vec::new(),
                fetched_at: None,
            })),
        })
    }

    /// Discover OIDC endpoints from the issuer's .well-known/openid-configuration.
    async fn discover(&self) -> Result<OpenIdConfiguration> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        debug!(url, "fetching OIDC discovery document");
        let resp = self.http.get(&url).send().await?.error_for_status()?;
        Ok(resp.json().await?)
    }

    /// Get the device authorization endpoint, from config or discovery.
    async fn device_auth_endpoint(&self) -> Result<String> {
        if let Some(ref ep) = self.config.device_auth_endpoint {
            return Ok(ep.clone());
        }
        let disc = self.discover().await?;
        disc.device_authorization_endpoint
            .ok_or_else(|| anyhow!("OIDC issuer does not advertise device_authorization_endpoint"))
    }

    /// Get the token endpoint, from config or discovery.
    async fn token_endpoint(&self) -> Result<String> {
        if let Some(ref ep) = self.config.token_endpoint {
            return Ok(ep.clone());
        }
        let disc = self.discover().await?;
        disc.token_endpoint
            .ok_or_else(|| anyhow!("OIDC issuer does not advertise token_endpoint"))
    }

    /// Get the JWKS URI, from config or discovery.
    async fn jwks_uri(&self) -> Result<String> {
        if let Some(ref uri) = self.config.jwks_uri {
            return Ok(uri.clone());
        }
        let disc = self.discover().await?;
        disc.jwks_uri
            .ok_or_else(|| anyhow!("OIDC issuer does not advertise jwks_uri"))
    }

    /// Fetch or return cached JWKS keys (cache for 1 hour).
    async fn get_jwks(&self) -> Result<Vec<JwkKey>> {
        {
            let cache = self.jwks_cache.read().await;
            if let Some(fetched) = cache.fetched_at {
                if fetched.elapsed().unwrap_or_default() < Duration::from_secs(3600) {
                    return Ok(cache.keys.clone());
                }
            }
        }
        // Fetch fresh
        let uri = self.jwks_uri().await?;
        debug!(uri, "fetching JWKS");
        let resp = self.http.get(&uri).send().await?.error_for_status()?;
        let jwks: JwksResponse = resp.json().await?;
        let keys = jwks.keys;
        {
            let mut cache = self.jwks_cache.write().await;
            cache.keys = keys.clone();
            cache.fetched_at = Some(SystemTime::now());
        }
        Ok(keys)
    }

    /// Start the device authorization flow.
    /// Returns (user_code, verification_uri, DeviceAuthState) for polling.
    pub async fn start_device_auth(&self) -> Result<DeviceAuthState> {
        let endpoint = self.device_auth_endpoint().await?;
        let scopes = if self.config.scopes.is_empty() {
            "openid profile email groups".to_string()
        } else {
            self.config.scopes.join(" ")
        };

        let resp = self
            .http
            .post(&endpoint)
            .form(&[
                ("client_id", self.config.client_id.as_str()),
                ("scope", &scopes),
            ])
            .send()
            .await?
            .error_for_status()
            .context("device authorization request failed")?;

        let da: DeviceAuthResponse = resp.json().await?;

        let verification_uri = da
            .verification_uri_complete
            .or(da.verification_uri)
            .context("OIDC provider did not return a verification URI")?;

        info!(user_code = da.user_code, "OIDC device auth started");

        Ok(DeviceAuthState {
            device_code: da.device_code,
            user_code: da.user_code,
            verification_uri,
            interval: Duration::from_secs(da.interval.max(5)),
            expires_at: SystemTime::now() + Duration::from_secs(da.expires_in),
        })
    }

    /// Poll the token endpoint until the user completes authentication.
    /// Returns the verified claims on success.
    pub async fn poll_for_token(&self, state: &DeviceAuthState) -> Result<OidcClaims> {
        let token_endpoint = self.token_endpoint().await?;

        loop {
            if SystemTime::now() > state.expires_at {
                return Err(anyhow!("device authorization timed out"));
            }

            tokio::time::sleep(state.interval).await;

            let resp = self
                .http
                .post(&token_endpoint)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", &state.device_code),
                    ("client_id", &self.config.client_id),
                ])
                .send()
                .await?;

            // Handle non-200 responses that contain error JSON
            let token_resp: TokenResponse = resp.json().await?;

            if let Some(ref error) = token_resp.error {
                match error.as_str() {
                    "authorization_pending" => {
                        debug!("device auth: authorization pending, polling again");
                        continue;
                    }
                    "slow_down" => {
                        debug!("device auth: slow_down, increasing interval");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                    "expired_token" => {
                        return Err(anyhow!("device authorization expired"));
                    }
                    "access_denied" => {
                        return Err(anyhow!("access denied by user"));
                    }
                    other => {
                        let desc = token_resp
                            .error_description
                            .unwrap_or_else(|| other.to_string());
                        return Err(anyhow!("OIDC error: {desc}"));
                    }
                }
            }

            // Success — we have a token response
            let id_token = token_resp
                .id_token
                .ok_or_else(|| anyhow!("token response missing id_token"))?;

            let claims = self.verify_id_token(&id_token).await?;
            return Ok(claims);
        }
    }

    /// Verify an id_token JWT and extract claims.
    /// Accepts tokens with `aud` matching client_id OR any value in allowed_audiences.
    pub async fn verify_id_token(&self, token: &str) -> Result<OidcClaims> {
        let header = decode_header(token).context("invalid JWT header")?;
        let kid = header.kid.as_deref();
        let alg = header.alg;

        let keys = self.get_jwks().await?;

        // Find matching key by kid (or use first key if no kid in header)
        let jwk = if let Some(kid) = kid {
            keys.iter()
                .find(|k| k.kid.as_deref() == Some(kid))
                .ok_or_else(|| anyhow!("no JWKS key matching kid={kid}"))?
        } else {
            keys.first()
                .ok_or_else(|| anyhow!("JWKS has no keys"))?
        };

        let decoding_key = make_decoding_key(jwk, alg)?;

        let mut validation = Validation::new(alg);
        // Accept client_id OR any allowed_audience
        let mut audiences: Vec<&str> = vec![&self.config.client_id];
        for aud in &self.config.allowed_audiences {
            audiences.push(aud);
        }
        validation.set_audience(&audiences);
        validation.set_issuer(&[&self.config.issuer]);

        let token_data = decode::<IdTokenClaims>(token, &decoding_key, &validation)
            .context("JWT verification failed")?;

        let claims = token_data.claims;
        let email = claims
            .email
            .or(claims.preferred_username)
            .ok_or_else(|| anyhow!("id_token has no email or preferred_username claim"))?;
        let mut groups = claims.groups.unwrap_or_default();
        groups.sort();
        groups.dedup();

        info!(email, groups = ?groups, "OIDC authentication successful");

        Ok(OidcClaims { email, groups })
    }
}

/// State for an in-progress device authorization flow.
pub struct DeviceAuthState {
    device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    interval: Duration,
    expires_at: SystemTime,
}

/// Construct a `DecodingKey` from a JWK.
fn make_decoding_key(jwk: &JwkKey, _alg: Algorithm) -> Result<DecodingKey> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk.n.as_deref().ok_or_else(|| anyhow!("RSA JWK missing n"))?;
            let e = jwk.e.as_deref().ok_or_else(|| anyhow!("RSA JWK missing e"))?;
            Ok(DecodingKey::from_rsa_components(n, e)?)
        }
        "EC" => {
            let x = jwk.x.as_deref().ok_or_else(|| anyhow!("EC JWK missing x"))?;
            let y = jwk.y.as_deref().ok_or_else(|| anyhow!("EC JWK missing y"))?;
            Ok(DecodingKey::from_ec_components(x, y)?)
        }
        other => Err(anyhow!("unsupported JWK key type: {other}")),
    }
}
