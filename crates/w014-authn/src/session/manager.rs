//! Server-side opaque session token utilities and lifecycle validation.
//!
//! Generates cryptographically secure opaque tokens, hashes them using SHA-256,
//! and evaluates absolute and idle expiration policies.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AuthnError;
use crate::session::{Session, SessionStatus};

/// Generates a 256-bit cryptographically secure opaque session token.
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Computes the SHA-256 hex digest of a raw opaque session token.
pub fn hash_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.trim().as_bytes());
    hex::encode(hasher.finalize())
}

/// Session configuration governing TTL, idle timeouts, and cookie parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub absolute_ttl_secs: i64,
    pub idle_ttl_secs: i64,
    pub cookie_name: String,
    pub cookie_secure: bool,
    pub cookie_path: String,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            absolute_ttl_secs: 7 * 24 * 3600, // 7 days
            idle_ttl_secs: 24 * 3600,         // 24 hours
            cookie_name: "w014_session".to_string(),
            cookie_secure: true,
            cookie_path: "/".to_string(),
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
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use w014_domain::ids::PrincipalId;

    #[test]
    fn test_token_generation_and_hashing() {
        let token1 = generate_session_token();
        let token2 = generate_session_token();
        assert_ne!(token1, token2);
        assert!(token1.len() >= 40);

        let hash1 = hash_session_token(&token1);
        let hash2 = hash_session_token(&token2);
        assert_eq!(hash1.len(), 64);
        assert_ne!(hash1, hash2);

        // Deterministic hashing
        assert_eq!(hash_session_token(&token1), hash1);
    }

    #[test]
    fn test_idle_timeout_evaluation() {
        let p_id = PrincipalId::new();
        let now = Utc::now();
        let expires = now + Duration::days(7);
        let session =
            Session::new(p_id, None, "hash123", expires, None::<&str>, None::<&str>).unwrap();

        let idle_ttl = Duration::hours(1);

        // Active within idle window
        assert!(
            SessionEvaluator::evaluate_active(&session, idle_ttl, now + Duration::minutes(30))
                .is_ok()
        );

        // Expired after idle window
        assert!(
            SessionEvaluator::evaluate_active(&session, idle_ttl, now + Duration::hours(2))
                .is_err()
        );
    }
}
