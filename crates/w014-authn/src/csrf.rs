//! CSRF Defense enforcing exact Origin policy and X-W014-CSRF token verification for cookie-authenticated requests.
//!
//! Frozen Requirements:
//! - Safe methods (GET, HEAD, OPTIONS) bypass Origin and CSRF header verification.
//! - Unsafe methods (POST, PUT, DELETE, PATCH, etc.) authenticated via session cookies must have
//!   an `Origin` header present that exactly matches an approved scheme+host+port.
//! - Missing, opaque ("null"), malformed, or non-allowlisted Origin fails closed with 403 CSRF_FAILED.
//! - STRICTLY NO REFERER FALLBACK: Referer MUST NOT rescue a request whose Origin is missing or invalid.
//! - `X-W014-CSRF` header is required on unsafe cookie-authenticated requests and verified using constant-time comparison.
//! - HMAC secret key material remains runtime secret material and is never logged.

use hmac::{Hmac, Mac};
use http::header::ORIGIN;
use http::{HeaderMap, Method};
use sha2::Sha256;
use std::collections::HashSet;

use crate::error::AuthnError;

type HmacSha256 = Hmac<Sha256>;

/// Standard application CSRF header name.
pub const CSRF_HEADER_NAME: &str = "X-W014-CSRF";

/// Configuration for CSRF Exact Origin and token validation.
#[derive(Clone)]
pub struct CsrfConfig {
    pub allowed_origins: HashSet<String>,
    pub hmac_secret: Vec<u8>,
}

impl std::fmt::Debug for CsrfConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsrfConfig")
            .field("allowed_origins", &self.allowed_origins)
            .field("hmac_secret", &"[REDACTED_CSRF_SECRET]")
            .finish()
    }
}

impl Default for CsrfConfig {
    fn default() -> Self {
        let mut origins = HashSet::new();
        origins.insert("http://localhost:8080".to_string());
        origins.insert("http://127.0.0.1:8080".to_string());
        origins.insert("http://localhost:3000".to_string());
        origins.insert("http://127.0.0.1:3000".to_string());
        Self {
            allowed_origins: origins,
            hmac_secret: b"w014-default-dev-csrf-secret-key-32b!".to_vec(),
        }
    }
}

impl CsrfConfig {
    pub fn new(allowed_origins: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed_origins: allowed_origins.into_iter().collect(),
            hmac_secret: b"w014-default-dev-csrf-secret-key-32b!".to_vec(),
        }
    }

    pub fn with_hmac_secret(mut self, secret: Vec<u8>) -> Self {
        self.hmac_secret = secret;
        self
    }

    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.allowed_origins.insert(origin.into());
        self
    }
}

/// Computes a session-bound CSRF token via keyed HMAC-SHA256.
pub fn derive_csrf_token(session_token: &str, secret_key: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret_key).expect("HMAC-SHA256 can accept any key length");
    mac.update(b"w014-csrf-token:");
    mac.update(session_token.trim().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time string equality check to prevent timing attacks.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Authoritative CSRF Origin & Token protector.
#[derive(Clone, Debug)]
pub struct CsrfProtector {
    config: CsrfConfig,
}

impl CsrfProtector {
    pub fn new(config: CsrfConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &CsrfConfig {
        &self.config
    }

    /// Derives the expected session-bound CSRF token for a given session handle.
    pub fn derive_token(&self, session_token: &str) -> String {
        derive_csrf_token(session_token, &self.config.hmac_secret)
    }

    /// Determines if an HTTP method is safe (read-only / idempotent from CSRF perspective).
    pub fn is_safe_method(method: &Method) -> bool {
        matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
    }

    /// Validates request Origin and X-W014-CSRF header for unsafe cookie-authenticated requests.
    pub fn validate_request(
        &self,
        method: &Method,
        headers: &HeaderMap,
        is_cookie_authenticated: bool,
        expected_token: Option<&str>,
    ) -> Result<(), AuthnError> {
        // 1. Safe methods bypass CSRF checks
        if Self::is_safe_method(method) {
            return Ok(());
        }

        // 2. Non-cookie-authenticated requests (e.g. Bearer tokens) do not use ambient cookie auth
        if !is_cookie_authenticated {
            return Ok(());
        }

        // 3. Exact Origin header validation (mandatory on all unsafe cookie-authenticated requests)
        let origin_hdr = headers
            .get(ORIGIN)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthnError::CsrfMissingOrigin)?;

        let trimmed_origin = origin_hdr.trim();
        if trimmed_origin.is_empty() || trimmed_origin == "null" {
            return Err(AuthnError::CsrfOriginMismatch(origin_hdr.to_string()));
        }

        // Validate origin structure (must have valid scheme and host)
        let parsed = url::Url::parse(trimmed_origin)
            .map_err(|_| AuthnError::CsrfOriginMismatch(origin_hdr.to_string()))?;
        if parsed.cannot_be_a_base() || parsed.host_str().is_none() {
            return Err(AuthnError::CsrfOriginMismatch(origin_hdr.to_string()));
        }

        let normalized = trimmed_origin.trim_end_matches('/');
        let is_allowed = self
            .config
            .allowed_origins
            .iter()
            .any(|allowed| allowed.trim_end_matches('/') == normalized);

        if !is_allowed {
            return Err(AuthnError::CsrfOriginMismatch(origin_hdr.to_string()));
        }

        // STRICTLY NO REFERER FALLBACK: Referer is NEVER checked to rescue missing or mismatched Origin.

        // 4. X-W014-CSRF Header validation
        let csrf_hdr = headers
            .get(CSRF_HEADER_NAME)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim())
            .ok_or(AuthnError::CsrfMissingHeader)?;

        if csrf_hdr.is_empty() {
            return Err(AuthnError::CsrfMissingHeader);
        }

        if expected_token.is_some_and(|expected| !constant_time_eq(csrf_hdr, expected.trim())) {
            return Err(AuthnError::CsrfTokenMismatch);
        }

        Ok(())
    }
}
