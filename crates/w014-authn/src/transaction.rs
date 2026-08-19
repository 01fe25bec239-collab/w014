//! OIDC Transaction persistence-facing domain semantics.
//!
//! Captures transient state/nonce/PKCE verification tokens for OIDC flows.
//! Note: Full WI-0102 protocol execution flows are deferred to WI-0102.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::AuthnError;

/// Authoritative identifier for an OIDC transaction record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OidcTransactionId(pub Uuid);

impl OidcTransactionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for OidcTransactionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for OidcTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for OidcTransactionId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<OidcTransactionId> for Uuid {
    fn from(id: OidcTransactionId) -> Self {
        id.0
    }
}

impl FromStr for OidcTransactionId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::from_str(s).map(Self)
    }
}

/// Persistence-facing record for an in-flight OIDC authorization transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcTransaction {
    pub id: OidcTransactionId,
    pub state_token: String,
    pub nonce: String,
    pub pkce_verifier: Option<String>,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl OidcTransaction {
    /// Creates a new OidcTransaction domain entity enforcing token invariants.
    pub fn new(
        state_token: impl AsRef<str>,
        nonce: impl AsRef<str>,
        pkce_verifier: Option<impl AsRef<str>>,
        redirect_uri: impl AsRef<str>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, AuthnError> {
        let trimmed_state = state_token.as_ref().trim();
        if trimmed_state.is_empty() {
            return Err(AuthnError::EmptyField("state_token"));
        }

        let trimmed_nonce = nonce.as_ref().trim();
        if trimmed_nonce.is_empty() {
            return Err(AuthnError::EmptyField("nonce"));
        }

        let trimmed_redirect = redirect_uri.as_ref().trim();
        if trimmed_redirect.is_empty() {
            return Err(AuthnError::EmptyField("redirect_uri"));
        }

        let now = Utc::now();
        if expires_at <= now {
            return Err(AuthnError::InvalidExpiry(
                "expires_at must be strictly in the future".to_string(),
            ));
        }

        Ok(Self {
            id: OidcTransactionId::new(),
            state_token: trimmed_state.to_string(),
            nonce: trimmed_nonce.to_string(),
            pkce_verifier: pkce_verifier.map(|v| v.as_ref().trim().to_string()),
            redirect_uri: trimmed_redirect.to_string(),
            created_at: now,
            expires_at,
        })
    }

    /// Reconstructs an existing OidcTransaction from persistent storage.
    pub fn reconstruct(
        id: OidcTransactionId,
        state_token: String,
        nonce: String,
        pkce_verifier: Option<String>,
        redirect_uri: String,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, AuthnError> {
        let trimmed_state = state_token.trim();
        if trimmed_state.is_empty() {
            return Err(AuthnError::EmptyField("state_token"));
        }

        let trimmed_nonce = nonce.trim();
        if trimmed_nonce.is_empty() {
            return Err(AuthnError::EmptyField("nonce"));
        }

        let trimmed_redirect = redirect_uri.trim();
        if trimmed_redirect.is_empty() {
            return Err(AuthnError::EmptyField("redirect_uri"));
        }

        Ok(Self {
            id,
            state_token: trimmed_state.to_string(),
            nonce: trimmed_nonce.to_string(),
            pkce_verifier,
            redirect_uri: trimmed_redirect.to_string(),
            created_at,
            expires_at,
        })
    }

    /// Evaluates if the transaction is currently valid (non-expired) at `now`.
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_transaction_validity() {
        let expires = Utc::now() + Duration::minutes(10);
        let tx = OidcTransaction::new(
            "state_abc",
            "nonce_123",
            Some("verifier_xyz"),
            "https://app.example.com/auth/callback",
            expires,
        )
        .unwrap();

        let now = Utc::now();
        assert!(tx.is_valid_at(now));
        assert!(!tx.is_valid_at(expires + Duration::seconds(1)));
    }
}
