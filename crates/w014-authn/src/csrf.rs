//! CSRF Defense enforcing exact Origin policy and X-W014-CSRF token verification for cookie-authenticated requests.
//!
//! Frozen Requirements:
//! - Safe methods (GET, HEAD, OPTIONS) bypass Origin and CSRF header verification.
//! - Unsafe methods (POST, PUT, DELETE, PATCH, etc.) authenticated via session cookies must have
//!   an `Origin` header present that exactly matches an approved scheme+host+port.
//! - Missing, opaque ("null"), malformed, or non-allowlisted Origin fails closed with 403 CSRF_FAILED.
//! - STRICTLY NO REFERER FALLBACK: Referer MUST NOT rescue a request whose Origin is missing or invalid.
//! - `X-W014-CSRF` header is required on unsafe cookie-authenticated requests and verified using constant-time comparison.
//! - CSRF token derivation is cryptographically bound to:
//!   1. Server-side session CSRF secret key
//!   2. Current session rotation identity (e.g. session token hash / rotation counter)
//!   3. Canonical exact request origin
//! - CSRF tokens are invalid after session rotation and cannot be reused across origins.
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

/// Normalizes an origin string into canonical `scheme://host[:port]` format without trailing slash.
pub fn canonicalize_origin(origin: &str) -> Result<String, AuthnError> {
    let trimmed = origin.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Err(AuthnError::CsrfOriginMismatch(origin.to_string()));
    }

    let parsed =
        url::Url::parse(trimmed).map_err(|_| AuthnError::CsrfOriginMismatch(origin.to_string()))?;

    if parsed.cannot_be_a_base() || parsed.host_str().is_none() {
        return Err(AuthnError::CsrfOriginMismatch(origin.to_string()));
    }

    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap();
    let canonical = match parsed.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };

    Ok(canonical)
}

/// Computes a session- and origin-bound CSRF token via keyed HMAC-SHA256.
///
/// Formula:
/// HMAC-SHA256(csrf_secret, "w014-csrf-v1:" || rotation_identity || ":" || canonical_origin)
pub fn derive_csrf_token(
    secret_key: &[u8],
    rotation_identity: &str,
    canonical_origin: &str,
) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret_key).expect("HMAC-SHA256 can accept any key length");
    mac.update(b"w014-csrf-v1:");
    mac.update(rotation_identity.trim().as_bytes());
    mac.update(b":");
    mac.update(canonical_origin.trim().trim_end_matches('/').as_bytes());
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

    /// Derives the expected CSRF token bound to the given session rotation identity and request origin.
    pub fn derive_token(&self, rotation_identity: &str, request_origin: &str) -> String {
        let canonical = canonicalize_origin(request_origin)
            .unwrap_or_else(|_| request_origin.trim().trim_end_matches('/').to_string());
        derive_csrf_token(&self.config.hmac_secret, rotation_identity, &canonical)
    }

    /// Determines if an HTTP method is safe (read-only / idempotent from CSRF perspective).
    pub fn is_safe_method(method: &Method) -> bool {
        matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
    }

    /// Validates request Origin and X-W014-CSRF header for unsafe cookie-authenticated requests.
    ///
    /// When `rotation_identity` is provided, the `X-W014-CSRF` header is checked against the
    /// token derived specifically for that session rotation and the canonical request origin.
    pub fn validate_request(
        &self,
        method: &Method,
        headers: &HeaderMap,
        is_cookie_authenticated: bool,
        rotation_identity: Option<&str>,
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

        let canonical_origin = canonicalize_origin(origin_hdr)?;

        let is_allowed = self
            .config
            .allowed_origins
            .iter()
            .any(|allowed| canonicalize_origin(allowed).is_ok_and(|c| c == canonical_origin));

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

        if let Some(rot_id) = rotation_identity {
            let expected_token =
                derive_csrf_token(&self.config.hmac_secret, rot_id, &canonical_origin);
            if !constant_time_eq(csrf_hdr, expected_token.trim()) {
                return Err(AuthnError::CsrfTokenMismatch);
            }
        }

        Ok(())
    }
}
