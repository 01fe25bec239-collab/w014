//! Session rotation persistence-facing domain semantics.
//!
//! Captures append-style session token rotations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::AuthnError;
use crate::session::SessionId;

/// Authoritative identifier for an immutable Session Rotation audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionRotationId(pub Uuid);

impl SessionRotationId {
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

impl Default for SessionRotationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionRotationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for SessionRotationId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<SessionRotationId> for Uuid {
    fn from(id: SessionRotationId) -> Self {
        id.0
    }
}

impl FromStr for SessionRotationId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::from_str(s).map(Self)
    }
}

/// Persistence-facing record for an append-style session rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRotation {
    pub id: SessionRotationId,
    pub session_id: SessionId,
    pub old_handle_hash: Vec<u8>,
    pub new_handle_hash: Vec<u8>,
    pub rotated_at: DateTime<Utc>,
    pub ip_address: Option<String>,
}

impl SessionRotation {
    /// Creates a new SessionRotation record validating hash distinctness.
    pub fn new(
        session_id: SessionId,
        old_handle_hash: impl Into<Vec<u8>>,
        new_handle_hash: impl Into<Vec<u8>>,
        ip_address: Option<impl AsRef<str>>,
    ) -> Result<Self, AuthnError> {
        let old_bytes = old_handle_hash.into();
        if old_bytes.is_empty() {
            return Err(AuthnError::EmptyField("old_handle_hash"));
        }

        let new_bytes = new_handle_hash.into();
        if new_bytes.is_empty() {
            return Err(AuthnError::EmptyField("new_handle_hash"));
        }

        if old_bytes == new_bytes {
            return Err(AuthnError::IdenticalRotationHashes);
        }

        Ok(Self {
            id: SessionRotationId::new(),
            session_id,
            old_handle_hash: old_bytes,
            new_handle_hash: new_bytes,
            rotated_at: Utc::now(),
            ip_address: ip_address.map(|s| s.as_ref().trim().to_string()),
        })
    }

    /// Reconstructs an existing SessionRotation from persistent storage.
    pub fn reconstruct(
        id: SessionRotationId,
        session_id: SessionId,
        old_handle_hash: Vec<u8>,
        new_handle_hash: Vec<u8>,
        rotated_at: DateTime<Utc>,
        ip_address: Option<String>,
    ) -> Result<Self, AuthnError> {
        if old_handle_hash.is_empty() {
            return Err(AuthnError::EmptyField("old_handle_hash"));
        }

        if new_handle_hash.is_empty() {
            return Err(AuthnError::EmptyField("new_handle_hash"));
        }

        if old_handle_hash == new_handle_hash {
            return Err(AuthnError::IdenticalRotationHashes);
        }

        Ok(Self {
            id,
            session_id,
            old_handle_hash,
            new_handle_hash,
            rotated_at,
            ip_address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_creation() {
        let s_id = SessionId::new();
        let rot = SessionRotation::new(
            s_id,
            b"old_hash".to_vec(),
            b"new_hash".to_vec(),
            Some("127.0.0.1"),
        )
        .unwrap();
        assert_eq!(rot.session_id, s_id);
        assert_eq!(rot.old_handle_hash, b"old_hash".to_vec());
        assert_eq!(rot.new_handle_hash, b"new_hash".to_vec());

        let err = SessionRotation::new(
            s_id,
            b"same_hash".to_vec(),
            b"same_hash".to_vec(),
            None::<&str>,
        )
        .unwrap_err();
        assert_eq!(err, AuthnError::IdenticalRotationHashes);
    }
}
