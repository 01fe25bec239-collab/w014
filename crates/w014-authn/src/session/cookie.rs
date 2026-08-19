//! Authoritative HTTP session cookie construction and extraction.
//!
//! Enforces:
//! - HttpOnly
//! - SameSite=Lax
//! - Path=/
//! - Secure (where configured)
//! - No Domain attribute for strict __Host- cookie semantics

use cookie::{Cookie, SameSite};
use http::HeaderMap;
use http::header::COOKIE;

use crate::session::manager::SessionConfig;

/// Builds Set-Cookie headers for session creation and deletion.
pub struct SessionCookieBuilder;

impl SessionCookieBuilder {
    /// Builds the `Set-Cookie` header value for an active session.
    pub fn build_set_cookie(config: &SessionConfig, raw_token: &str) -> String {
        let mut builder = Cookie::build((config.cookie_name.clone(), raw_token.to_string()))
            .http_only(true)
            .same_site(SameSite::Lax)
            .path(&config.cookie_path)
            .max_age(cookie::time::Duration::seconds(config.absolute_ttl_secs));

        if config.cookie_secure {
            builder = builder.secure(true);
        }

        // Explicitly NO Domain attribute for __Host- prefix compatibility
        builder.build().to_string()
    }

    /// Builds the `Set-Cookie` header value to immediately invalidate and clear the session cookie.
    pub fn build_clear_cookie(config: &SessionConfig) -> String {
        let mut builder = Cookie::build((config.cookie_name.clone(), ""))
            .http_only(true)
            .same_site(SameSite::Lax)
            .path(&config.cookie_path)
            .max_age(cookie::time::Duration::seconds(0));

        if config.cookie_secure {
            builder = builder.secure(true);
        }

        builder.build().to_string()
    }

    /// Extracts the raw session token from a raw `Cookie` header string.
    pub fn extract_token_from_str(cookie_header: &str, cookie_name: &str) -> Option<String> {
        cookie_header.split(';').find_map(|cookie_str| {
            let c = Cookie::parse(cookie_str.trim()).ok()?;
            if c.name() == cookie_name {
                let val = c.value().trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
            None
        })
    }

    /// Extracts the raw session token from standard HTTP request headers.
    pub fn extract_token(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
        headers
            .get(COOKIE)
            .and_then(|val| val.to_str().ok())
            .and_then(|cookie_str| Self::extract_token_from_str(cookie_str, cookie_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_construction_and_extraction() {
        let config = SessionConfig {
            absolute_ttl_secs: 3600,
            idle_ttl_secs: 1800,
            cookie_name: "__Host-session".to_string(),
            cookie_secure: true,
            cookie_path: "/".to_string(),
        };

        let raw_token = "raw_opaque_token_12345";
        let cookie_str = SessionCookieBuilder::build_set_cookie(&config, raw_token);

        assert!(cookie_str.contains("__Host-session=raw_opaque_token_12345"));
        assert!(cookie_str.contains("HttpOnly"));
        assert!(cookie_str.contains("SameSite=Lax"));
        assert!(cookie_str.contains("Path=/"));
        assert!(cookie_str.contains("Secure"));
        assert!(!cookie_str.contains("Domain="));

        // Extraction
        let extracted =
            SessionCookieBuilder::extract_token_from_str(&cookie_str, "__Host-session").unwrap();
        assert_eq!(extracted, raw_token);
    }

    #[test]
    fn test_clear_cookie() {
        let config = SessionConfig::default();
        let clear_str = SessionCookieBuilder::build_clear_cookie(&config);
        assert!(clear_str.contains("Max-Age=0"));
    }
}
