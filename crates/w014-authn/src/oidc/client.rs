//! OIDC Protocol Client coordinating Authorization Code + PKCE flow.
//!
//! Generates cryptographically secure authorization URLs, exchanges authorization codes
//! for tokens at the token endpoint, and validates ID tokens.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use rand::rngs::OsRng;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::AuthnError;
use crate::oidc::jwks::JwksCache;
use crate::oidc::pkce::PkceCodeVerifier;
use crate::oidc::token::{IdTokenClaims, IdTokenValidator};

/// Strongly-typed configuration for an OIDC Identity Provider integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub issuer_allowlist: Vec<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state_ttl_secs: i64,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer: "https://accounts.google.com".to_string(),
            issuer_allowlist: vec!["https://accounts.google.com".to_string()],
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
            jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
            client_id: "w014-client-id".to_string(),
            client_secret: None,
            redirect_uri: "http://localhost:8080/api/v1/auth/callback".to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            state_ttl_secs: 600, // 10 minutes
        }
    }
}

/// Token endpoint JSON response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTokenResponse {
    pub access_token: Option<String>,
    pub token_type: Option<String>,
    pub id_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
}

/// Error payload returned by standard OAuth2/OIDC token endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

/// Generated authorization flow parameters for a login attempt.
#[derive(Debug, Clone)]
pub struct AuthorizationParameters {
    pub authorization_url: Url,
    pub state_token: String,
    pub nonce: String,
    pub pkce_verifier: PkceCodeVerifier,
    pub redirect_uri: String,
    pub expires_at: DateTime<Utc>,
}

/// High-level authoritative OIDC client.
#[derive(Clone)]
pub struct OidcClient {
    config: OidcConfig,
    jwks_cache: JwksCache,
    validator: IdTokenValidator,
    http_client: HttpClient,
}

impl OidcClient {
    /// Creates a new OidcClient with the given configuration.
    pub fn new(config: OidcConfig) -> Self {
        let jwks_cache = JwksCache::new(&config.jwks_uri);
        let validator = IdTokenValidator::new(
            &config.issuer,
            config.issuer_allowlist.clone(),
            &config.client_id,
        );
        let http_client = HttpClient::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        Self {
            config,
            jwks_cache,
            validator,
            http_client,
        }
    }

    /// Creates an OidcClient with a pre-seeded JWKS cache (for tests or static setups).
    pub fn with_jwks_cache(config: OidcConfig, jwks_cache: JwksCache) -> Self {
        let validator = IdTokenValidator::new(
            &config.issuer,
            config.issuer_allowlist.clone(),
            &config.client_id,
        );
        let http_client = HttpClient::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        Self {
            config,
            jwks_cache,
            validator,
            http_client,
        }
    }

    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    pub fn jwks_cache(&self) -> &JwksCache {
        &self.jwks_cache
    }

    pub fn validator(&self) -> &IdTokenValidator {
        &self.validator
    }

    /// Generates high-entropy state and nonce, derives S256 PKCE challenge, and builds the IdP auth URL.
    pub fn create_authorization_request(&self) -> Result<AuthorizationParameters, AuthnError> {
        let mut state_bytes = [0u8; 32];
        let mut nonce_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut state_bytes);
        OsRng.fill_bytes(&mut nonce_bytes);

        let state_token = URL_SAFE_NO_PAD.encode(state_bytes);
        let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
        let pkce_verifier = PkceCodeVerifier::generate();
        let pkce_challenge = pkce_verifier.challenge();

        let scope_str = self.config.scopes.join(" ");

        let mut url = Url::parse(&self.config.authorization_endpoint).map_err(|e| {
            AuthnError::InvalidIssuer(format!("Invalid authorization endpoint: {e}"))
        })?;

        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", &scope_str)
            .append_pair("state", &state_token)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", pkce_challenge.as_str())
            .append_pair("code_challenge_method", pkce_challenge.method().as_str());

        let expires_at = Utc::now() + Duration::seconds(self.config.state_ttl_secs);

        Ok(AuthorizationParameters {
            authorization_url: url,
            state_token,
            nonce,
            pkce_verifier,
            redirect_uri: self.config.redirect_uri.clone(),
            expires_at,
        })
    }

    /// Exchanges an authorization code and PKCE code_verifier with the IdP token endpoint.
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<OidcTokenResponse, AuthnError> {
        let params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", &self.config.client_id),
            ("code_verifier", code_verifier),
        ];

        let mut req = self
            .http_client
            .post(&self.config.token_endpoint)
            .form(&params);

        if let Some(ref secret) = self.config.client_secret {
            req = req.basic_auth(&self.config.client_id, Some(secret));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| AuthnError::IdpCommunicationError(e.to_string()))?;

        let status = resp.status();
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| AuthnError::IdpCommunicationError(e.to_string()))?;

        if !status.is_success() {
            if let Ok(err_resp) = serde_json::from_slice::<OidcErrorResponse>(&body_bytes) {
                return Err(AuthnError::IdpTokenExchangeError {
                    error: err_resp.error,
                    description: err_resp
                        .error_description
                        .unwrap_or_else(|| "no description".to_string()),
                });
            }

            let text = String::from_utf8_lossy(&body_bytes);
            return Err(AuthnError::IdpTokenExchangeError {
                error: format!("HTTP {status}"),
                description: text.to_string(),
            });
        }

        let token_resp: OidcTokenResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
            AuthnError::InvalidToken(format!("Failed to parse token response: {e}"))
        })?;

        Ok(token_resp)
    }

    /// Validates an ID token from the IdP against JWKS and transaction nonce.
    pub async fn validate_id_token(
        &self,
        id_token: &str,
        expected_nonce: &str,
    ) -> Result<IdTokenClaims, AuthnError> {
        self.validator
            .validate_token(id_token, expected_nonce, &self.jwks_cache)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_request_generation() {
        let config = OidcConfig::default();
        let client = OidcClient::new(config);

        let params = client.create_authorization_request().unwrap();
        let url_str = params.authorization_url.as_str();

        assert!(url_str.contains("response_type=code"));
        assert!(url_str.contains("client_id=w014-client-id"));
        assert!(url_str.contains("code_challenge_method=S256"));
        assert!(url_str.contains(&format!("state={}", params.state_token)));
        assert!(url_str.contains(&format!("nonce={}", params.nonce)));
        assert!(params.expires_at > Utc::now());
    }
}
