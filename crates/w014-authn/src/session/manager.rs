//! Server-side opaque session token utilities and lifecycle validation.
//!
//! Generates cryptographically secure opaque tokens, hashes them using keyed HMAC-SHA256,
//! and evaluates absolute and idle expiration policies.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;

use crate::error::AuthnError;
use crate::session::{Session, SessionStatus};

type HmacSha256 = Hmac<Sha256>;

/// Generates a 256-bit cryptographically secure opaque session token.
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Computes the keyed HMAC-SHA256 hex digest of a raw opaque session token.
pub fn hash_session_token(token: &str, secret_key: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret_key).expect("HMAC-SHA256 can accept any key length");
    mac.update(token.trim().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Session configuration governing TTL, idle timeouts, cookie parameters, and HMAC secret.
#[derive(Clone)]
pub struct SessionConfig {
    pub absolute_ttl_secs: i64,
    pub idle_ttl_secs: i64,
    pub cookie_name: String,
    pub cookie_secure: bool,
    pub cookie_path: String,
    pub hmac_secret: Vec<u8>,
}

impl std::fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionConfig")
            .field("absolute_ttl_secs", &self.absolute_ttl_secs)
            .field("idle_ttl_secs", &self.idle_ttl_secs)
            .field("cookie_name", &self.cookie_name)
            .field("cookie_secure", &self.cookie_secure)
            .field("cookie_path", &self.cookie_path)
            .field("hmac_secret", &"[REDACTED_SESSION_HMAC_SECRET]")
            .finish()
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            absolute_ttl_secs: 7 * 24 * 3600, // 7 days
            idle_ttl_secs: 24 * 3600,         // 24 hours
            cookie_name: "w014_session".to_string(),
            cookie_secure: true,
            cookie_path: "/".to_string(),
            hmac_secret: b"w014-default-dev-session-secret-key-32b!".to_vec(),
        }
    }
}

impl SessionConfig {
    pub fn for_testing() -> Self {
        Self {
            absolute_ttl_secs: 3600,
            idle_ttl_secs: 1800,
            cookie_name: "w014_session_test".to_string(),
            cookie_secure: false, // Permit HTTP in local mock tests
            cookie_path: "/".to_string(),
            hmac_secret: b"w014-test-session-hmac-secret-32b!!".to_vec(),
        }
    }

    pub fn with_hmac_secret(mut self, secret: Vec<u8>) -> Self {
        self.hmac_secret = secret;
        self
    }

    /// Computes the authoritative HMAC-SHA256 hash of a session token under this configuration's secret.
    pub fn hash_token(&self, token: &str) -> String {
        hash_session_token(token, &self.hmac_secret)
    }
}

/// Manager evaluating session validity against absolute and idle expiration policies.
pub struct SessionEvaluator;

impl SessionEvaluator {
    /// Validates whether an active session is currently usable at `now` under the idle timeout rule.
    pub fn evaluate_active(
        session: &Session,
        idle_timeout: Duration,
        now: DateTime<Utc>,
    ) -> Result<(), AuthnError> {
        if session.status == SessionStatus::Revoked {
            return Err(AuthnError::SessionRevoked(session.id.to_string()));
        }

        if session.status == SessionStatus::Expired || now >= session.expires_at {
            return Err(AuthnError::SessionExpired(session.id.to_string()));
        }

        if now - session.last_seen_at > idle_timeout {
            return Err(AuthnError::SessionExpired(format!(
                "Session '{}' expired due to idle timeout",
                session.id
            )));
        }

        Ok(())
    }
}
