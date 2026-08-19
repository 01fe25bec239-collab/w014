//! CSRF Defense enforcing exact Origin policy for cookie-authenticated unsafe requests.
//!
//! Enforces:
//! - Safe methods (GET, HEAD, OPTIONS) bypass Origin verification.
//! - Unsafe methods (POST, PUT, DELETE, PATCH) authenticated via session cookies must have
//!   an `Origin` or `Referer` matching an approved origin.
//! - Fails closed if headers are missing or mismatched.

use http::header::{ORIGIN, REFERER};
use http::{HeaderMap, Method};
use std::collections::HashSet;

use crate::error::AuthnError;

/// Configuration for CSRF Exact Origin validation.
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    pub allowed_origins: HashSet<String>,
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
        }
    }
}

impl CsrfConfig {
    pub fn new(allowed_origins: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed_origins: allowed_origins.into_iter().collect(),
        }
    }

    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.allowed_origins.insert(origin.into());
        self
    }
}

/// Authoritative CSRF Origin protector.
#[derive(Clone)]
pub struct CsrfProtector {
    config: CsrfConfig,
}

impl CsrfProtector {
    pub fn new(config: CsrfConfig) -> Self {
        Self { config }
    }

    /// Determines if an HTTP method is considered safe from CSRF state mutations.
    pub fn is_safe_method(method: &Method) -> bool {
        matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
    }

    /// Validates request origin against allowed origins for unsafe cookie-authenticated requests.
    pub fn validate_request(
        &self,
        method: &Method,
        headers: &HeaderMap,
        is_cookie_authenticated: bool,
    ) -> Result<(), AuthnError> {
        // 1. Safe methods bypass CSRF Origin check
        if Self::is_safe_method(method) {
            return Ok(());
        }

        // 2. Non-cookie-authenticated requests (e.g. anonymous or Bearer) do not use ambient cookie auth
        if !is_cookie_authenticated {
            return Ok(());
        }

        // 3. Check Origin header first
        if let Some(origin_hdr) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) {
            let normalized = origin_hdr.trim_end_matches('/');
            if self
                .config
                .allowed_origins
                .iter()
                .any(|allowed| allowed.trim_end_matches('/') == normalized)
            {
                return Ok(());
            }
            return Err(AuthnError::CsrfOriginMismatch(origin_hdr.to_string()));
        }

        // 4. Fallback to Referer header if Origin is absent
        if let Some(referer_hdr) = headers.get(REFERER).and_then(|v| v.to_str().ok()) {
            if self.config.allowed_origins.iter().any(|allowed| {
                let trimmed_allowed = allowed.trim_end_matches('/');
                referer_hdr.starts_with(trimmed_allowed)
            }) {
                return Ok(());
            }
            return Err(AuthnError::CsrfOriginMismatch(referer_hdr.to_string()));
        }

        // 5. Fail closed if neither Origin nor Referer is present on unsafe cookie-authenticated request
        Err(AuthnError::CsrfMissingOrigin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn test_csrf_safe_methods_bypass() {
        let protector = CsrfProtector::new(CsrfConfig::default());
        let headers = HeaderMap::new();

        assert!(
            protector
                .validate_request(&Method::GET, &headers, true)
                .is_ok()
        );
        assert!(
            protector
                .validate_request(&Method::HEAD, &headers, true)
                .is_ok()
        );
        assert!(
            protector
                .validate_request(&Method::OPTIONS, &headers, true)
                .is_ok()
        );
    }

    #[test]
    fn test_csrf_non_cookie_bypasses() {
        let protector = CsrfProtector::new(CsrfConfig::default());
        let headers = HeaderMap::new();

        // Unsafe method but not cookie authenticated -> OK
        assert!(
            protector
                .validate_request(&Method::POST, &headers, false)
                .is_ok()
        );
    }

    #[test]
    fn test_csrf_origin_matching() {
        let config = CsrfConfig::new(vec!["https://app.example.com".to_string()]);
        let protector = CsrfProtector::new(config);

        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://app.example.com"));
        assert!(
            protector
                .validate_request(&Method::POST, &headers, true)
                .is_ok()
        );

        // Mismatched origin
        let mut bad_headers = HeaderMap::new();
        bad_headers.insert(ORIGIN, HeaderValue::from_static("https://attacker.com"));
        assert!(matches!(
            protector.validate_request(&Method::POST, &bad_headers, true),
            Err(AuthnError::CsrfOriginMismatch(_))
        ));

        // Missing origin & referer
        let empty_headers = HeaderMap::new();
        assert!(matches!(
            protector.validate_request(&Method::POST, &empty_headers, true),
            Err(AuthnError::CsrfMissingOrigin)
        ));
    }

    #[test]
    fn test_csrf_referer_fallback() {
        let config = CsrfConfig::new(vec!["https://app.example.com".to_string()]);
        let protector = CsrfProtector::new(config);

        let mut headers = HeaderMap::new();
        headers.insert(
            REFERER,
            HeaderValue::from_static("https://app.example.com/some/path"),
        );
        assert!(
            protector
                .validate_request(&Method::POST, &headers, true)
                .is_ok()
        );

        let mut bad_headers = HeaderMap::new();
        bad_headers.insert(
            REFERER,
            HeaderValue::from_static("https://evil.com/app.example.com"),
        );
        assert!(matches!(
            protector.validate_request(&Method::POST, &bad_headers, true),
            Err(AuthnError::CsrfOriginMismatch(_))
        ));
    }
}
