//! JSON Web Key Set (JWKS) handling, parsing, and caching.
//!
//! Provides asymmetric key verification (RSA, ECDSA, Ed25519) and JWKS caching with TTL
//! and rate-limited refreshing on unknown `kid`. Prohibits symmetric algorithms and `alg=none`.

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::error::AuthnError;

/// List of approved asymmetric algorithms for OIDC ID token validation.
pub const ALLOWED_ASYMMETRIC_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Validates that an algorithm string or token header algorithm is permitted.
pub fn validate_algorithm(alg: Algorithm) -> Result<(), AuthnError> {
    match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::ES256
        | Algorithm::ES384
        | Algorithm::EdDSA => Ok(()),
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Err(AuthnError::SymmetricAlgorithmRejected(format!("{alg:?}")))
        }
        other => Err(AuthnError::AlgorithmNotAllowed(format!("{other:?}"))),
    }
}

/// JSON Web Key (JWK).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub use_: Option<String>,
    #[serde(default)]
    pub key_ops: Option<Vec<String>>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,

    // RSA parameters
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,

    // EC parameters
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

impl Jwk {
    /// Converts this JWK into a `jsonwebtoken::DecodingKey` and validates asymmetric constraints.
    pub fn to_decoding_key(&self) -> Result<DecodingKey, AuthnError> {
        match self.kty.as_str() {
            "RSA" => {
                let n = self.n.as_ref().ok_or_else(|| {
                    AuthnError::InvalidToken("Missing RSA modulus 'n' in JWK".to_string())
                })?;
                let e = self.e.as_ref().ok_or_else(|| {
                    AuthnError::InvalidToken("Missing RSA exponent 'e' in JWK".to_string())
                })?;

                DecodingKey::from_rsa_components(n, e).map_err(|err| {
                    AuthnError::InvalidToken(format!("Failed to build RSA decoding key: {err}"))
                })
            }
            "EC" => {
                let x = self.x.as_ref().ok_or_else(|| {
                    AuthnError::InvalidToken("Missing EC coordinate 'x' in JWK".to_string())
                })?;
                let y = self.y.as_ref().ok_or_else(|| {
                    AuthnError::InvalidToken("Missing EC coordinate 'y' in JWK".to_string())
                })?;

                DecodingKey::from_ec_components(x, y).map_err(|err| {
                    AuthnError::InvalidToken(format!("Failed to build EC decoding key: {err}"))
                })
            }
            "OKP" => {
                let x = self.x.as_ref().ok_or_else(|| {
                    AuthnError::InvalidToken("Missing OKP public key 'x' in JWK".to_string())
                })?;

                DecodingKey::from_ed_components(x).map_err(|err| {
                    AuthnError::InvalidToken(format!("Failed to build EdDSA decoding key: {err}"))
                })
            }
            "oct" => Err(AuthnError::SymmetricAlgorithmRejected(
                "Symmetric JWK (kty=oct) prohibited for OIDC ID tokens".to_string(),
            )),
            other => Err(AuthnError::AlgorithmNotAllowed(format!(
                "Unsupported key type '{other}'"
            ))),
        }
    }
}

/// JSON Web Key Set (JWKS) container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Finds a JWK by key ID (`kid`). If kid is None and there is exactly one key, returns that key.
    pub fn find_key(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(target_kid) => self
                .keys
                .iter()
                .find(|k| k.kid.as_deref() == Some(target_kid)),
            None => {
                if self.keys.len() == 1 {
                    self.keys.first()
                } else {
                    None
                }
            }
        }
    }
}

type CachedJwksEntry = (Jwks, DateTime<Utc>);
type CachedJwks = Arc<RwLock<Option<CachedJwksEntry>>>;

/// JWKS Cache with TTL and rate-limited refreshing for controlled JWKS refresh behavior.
#[derive(Clone)]
pub struct JwksCache {
    jwks_uri: String,
    ttl: Duration,
    cached_jwks: CachedJwks,
    last_refresh_attempt: Arc<RwLock<DateTime<Utc>>>,
    http_client: reqwest::Client,
    min_refresh_interval: Duration,
}

impl JwksCache {
    /// Creates a new JWKS cache for the given URI.
    pub fn new(jwks_uri: impl Into<String>) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            ttl: Duration::hours(1),
            cached_jwks: Arc::new(RwLock::new(None)),
            last_refresh_attempt: Arc::new(RwLock::new(DateTime::<Utc>::MIN_UTC)),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            min_refresh_interval: Duration::seconds(10), // Rate limit background refreshes
        }
    }

    /// Seeds the cache with predefined static JWKS (useful for testing or air-gapped environments).
    pub fn seeded(jwks_uri: impl Into<String>, jwks: Jwks) -> Self {
        let cache = Self::new(jwks_uri);
        *cache.cached_jwks.write().unwrap() = Some((jwks, Utc::now() + Duration::days(365)));
        cache
    }

    /// Retrieves the decoding key for a given `kid`, fetching or refreshing the JWKS if needed.
    pub async fn get_decoding_key(&self, kid: Option<&str>) -> Result<DecodingKey, AuthnError> {
        let now = Utc::now();

        // 1. Check if cached JWKS is valid and has the key
        let cached = {
            let guard = self.cached_jwks.read().unwrap();
            guard.clone()
        };

        if let Some(jwk) = cached
            .filter(|(_, expires_at)| now < *expires_at)
            .and_then(|(jwks, _)| jwks.find_key(kid).cloned())
        {
            return jwk.to_decoding_key();
        }

        // 2. If key is missing or expired, attempt controlled refresh (subject to rate limiting)
        let should_refresh = {
            let last_attempt = *self.last_refresh_attempt.read().unwrap();
            now - last_attempt >= self.min_refresh_interval
        };

        if !should_refresh {
            // Rate-limited; use existing cache if available or error
            let guard = self.cached_jwks.read().unwrap();
            if let Some(jwk) = guard.as_ref().and_then(|(jwks, _)| jwks.find_key(kid)) {
                return jwk.to_decoding_key();
            }
            return Err(AuthnError::KeyNotFound(
                kid.unwrap_or("default").to_string(),
            ));
        }

        // 3. Fetch fresh JWKS
        self.refresh().await?;

        // 4. Retry lookup in refreshed JWKS
        let guard = self.cached_jwks.read().unwrap();
        if let Some(jwk) = guard.as_ref().and_then(|(jwks, _)| jwks.find_key(kid)) {
            return jwk.to_decoding_key();
        }

        Err(AuthnError::KeyNotFound(
            kid.unwrap_or("default").to_string(),
        ))
    }

    /// Refreshes the cached JWKS from the remote URI.
    pub async fn refresh(&self) -> Result<(), AuthnError> {
        let now = Utc::now();
        *self.last_refresh_attempt.write().unwrap() = now;

        let response = self
            .http_client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| AuthnError::JwksFetchError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AuthnError::JwksFetchError(format!(
                "JWKS endpoint returned HTTP {}",
                response.status()
            )));
        }

        let jwks: Jwks = response
            .json()
            .await
            .map_err(|e| AuthnError::JwksFetchError(e.to_string()))?;

        let expires_at = now + self.ttl;
        *self.cached_jwks.write().unwrap() = Some((jwks, expires_at));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_allowlist() {
        assert!(validate_algorithm(Algorithm::RS256).is_ok());
        assert!(validate_algorithm(Algorithm::ES256).is_ok());
        assert!(validate_algorithm(Algorithm::EdDSA).is_ok());

        // Symmetric must be rejected
        assert_eq!(
            validate_algorithm(Algorithm::HS256),
            Err(AuthnError::SymmetricAlgorithmRejected("HS256".into()))
        );
        assert_eq!(
            validate_algorithm(Algorithm::HS512),
            Err(AuthnError::SymmetricAlgorithmRejected("HS512".into()))
        );
    }

    #[test]
    fn test_jwk_key_lookup() {
        let jwk1 = Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            key_ops: None,
            alg: Some("RS256".to_string()),
            kid: Some("key-1".to_string()),
            n: Some("n_val".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        };

        let jwks = Jwks {
            keys: vec![jwk1.clone()],
        };

        assert_eq!(jwks.find_key(Some("key-1")), Some(&jwk1));
        assert_eq!(jwks.find_key(Some("key-unknown")), None);
        assert_eq!(jwks.find_key(None), Some(&jwk1));
    }
}
