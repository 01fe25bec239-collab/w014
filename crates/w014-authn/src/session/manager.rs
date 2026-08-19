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

/// Result of an authoritative session authentication attempt.
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub session: Session,
    /// If the session was rotated during authentication (e.g. valid under previous HMAC key
    /// or periodic 4h rotation), this holds the newly generated raw handle for Set-Cookie.
    pub rotated_token: Option<String>,
}

/// Generates a 256-bit cryptographically secure opaque session token using OS CSPRNG.
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

/// Session configuration governing TTL, idle timeouts, cookie parameters, and HMAC key lifecycle.
#[derive(Clone)]
pub struct SessionConfig {
    pub absolute_ttl_secs: i64,
    pub idle_ttl_secs: i64,
    pub cookie_name: String,
    pub cookie_secure: bool,
    pub cookie_path: String,
    pub active_hmac_secret: Vec<u8>,
    pub previous_hmac_secret: Option<Vec<u8>>,
    pub periodic_rotation_interval_secs: i64,
    pub activity_touch_interval_secs: i64,
    pub max_concurrent_sessions: usize,
}

impl std::fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionConfig")
            .field("absolute_ttl_secs", &self.absolute_ttl_secs)
            .field("idle_ttl_secs", &self.idle_ttl_secs)
            .field("cookie_name", &self.cookie_name)
            .field("cookie_secure", &self.cookie_secure)
            .field("cookie_path", &self.cookie_path)
            .field("active_hmac_secret", &"[REDACTED_SESSION_HMAC_SECRET]")
            .field(
                "previous_hmac_secret_present",
                &self.previous_hmac_secret.is_some(),
            )
            .field(
                "periodic_rotation_interval_secs",
                &self.periodic_rotation_interval_secs,
            )
            .field(
                "activity_touch_interval_secs",
                &self.activity_touch_interval_secs,
            )
            .field("max_concurrent_sessions", &self.max_concurrent_sessions)
            .finish()
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            absolute_ttl_secs: 7 * 24 * 3600, // 7 days
            idle_ttl_secs: 12 * 3600,         // 12 hours (frozen spec)
            cookie_name: "w014_session".to_string(),
            cookie_secure: true,
            cookie_path: "/".to_string(),
            active_hmac_secret: b"w014-default-dev-session-secret-key-32b!".to_vec(),
            previous_hmac_secret: None,
            periodic_rotation_interval_secs: 4 * 3600, // 4 hours periodic rotation
            activity_touch_interval_secs: 5 * 60,      // 5 minutes activity touch throttling
            max_concurrent_sessions: 5,                // Max 5 concurrent sessions per principal
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
            active_hmac_secret: b"w014-test-session-hmac-secret-32b!!".to_vec(),
            previous_hmac_secret: None,
            periodic_rotation_interval_secs: 4 * 3600,
            activity_touch_interval_secs: 300,
            max_concurrent_sessions: 5,
        }
    }

    pub fn with_hmac_secret(mut self, secret: Vec<u8>) -> Self {
        self.active_hmac_secret = secret;
        self
    }

    pub fn with_previous_hmac_secret(mut self, secret: Vec<u8>) -> Self {
        self.previous_hmac_secret = Some(secret);
        self
    }

    /// Computes the authoritative HMAC-SHA256 hash of a session token under the active key.
    pub fn hash_token(&self, token: &str) -> String {
        hash_session_token(token, &self.active_hmac_secret)
    }

    /// Computes the HMAC-SHA256 hash under the previous key, if configured.
    pub fn hash_token_previous(&self, token: &str) -> Option<String> {
        self.previous_hmac_secret
            .as_ref()
            .map(|secret| hash_session_token(token, secret))
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
