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
    pub state_hash: Vec<u8>,
    pub nonce_hash: Vec<u8>,
    pub pkce_verifier_ciphertext: Option<Vec<u8>>,
    pub return_path: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

impl OidcTransaction {
    /// Creates a new OidcTransaction domain entity enforcing token invariants.
    pub fn new(
        state_hash: Vec<u8>,
        nonce_hash: Vec<u8>,
        pkce_verifier_ciphertext: Option<Vec<u8>>,
        return_path: impl AsRef<str>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, AuthnError> {
        if state_hash.is_empty() {
            return Err(AuthnError::EmptyField("state_hash"));
        }
        if nonce_hash.is_empty() {
            return Err(AuthnError::EmptyField("nonce_hash"));
        }

        let trimmed_path = return_path.as_ref().trim();
        let path = if trimmed_path.is_empty() {
            "/".to_string()
        } else {
            trimmed_path.to_string()
        };

        let now = Utc::now();
        if expires_at <= now {
            return Err(AuthnError::InvalidExpiry(
                "expires_at must be strictly in the future".to_string(),
            ));
        }

        Ok(Self {
            id: OidcTransactionId::new(),
            state_hash,
            nonce_hash,
            pkce_verifier_ciphertext,
            return_path: path,
            created_at: now,
            expires_at,
            consumed_at: None,
        })
    }

    /// Reconstructs an existing OidcTransaction from persistent storage.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: OidcTransactionId,
        state_hash: Vec<u8>,
        nonce_hash: Vec<u8>,
        pkce_verifier_ciphertext: Option<Vec<u8>>,
        return_path: String,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        consumed_at: Option<DateTime<Utc>>,
    ) -> Result<Self, AuthnError> {
        if state_hash.is_empty() {
            return Err(AuthnError::EmptyField("state_hash"));
        }
        if nonce_hash.is_empty() {
            return Err(AuthnError::EmptyField("nonce_hash"));
        }

        Ok(Self {
            id,
            state_hash,
            nonce_hash,
            pkce_verifier_ciphertext,
            return_path,
            created_at,
            expires_at,
            consumed_at,
        })
    }

    /// Evaluates if the transaction is currently valid (non-consumed, non-expired) at `now`.
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.consumed_at.is_none() && now < self.expires_at
    }

    /// Consumes the transaction (single-use semantics).
    pub fn consume(&mut self, now: DateTime<Utc>) {
        self.consumed_at = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_transaction_validity() {
        let expires = Utc::now() + Duration::minutes(10);
        let mut tx = OidcTransaction::new(
            b"state_hash_bytes".to_vec(),
            b"nonce_hash_bytes".to_vec(),
            Some(b"pkce_cipher_bytes".to_vec()),
            "/auth/callback",
            expires,
        )
        .unwrap();

        let now = Utc::now();
        assert!(tx.is_valid_at(now));
        assert!(!tx.is_valid_at(expires + Duration::seconds(1)));

        tx.consume(now);
        assert!(!tx.is_valid_at(now));
    }
}
