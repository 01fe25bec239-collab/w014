//! Server-side Session persistence-facing domain semantics.
//!
//! Captures opaque server-side session identity and status lifecycle.
//! Note: Full WI-0102 session execution flows are deferred to WI-0102.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;
use w014_domain::ids::{PrincipalId, WorkspaceId};

use crate::error::AuthnError;

/// Authoritative identifier for a server-side Session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub Uuid);

impl SessionId {
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

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for SessionId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<SessionId> for Uuid {
    fn from(id: SessionId) -> Self {
        id.0
    }
}

impl FromStr for SessionId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::from_str(s).map(Self)
    }
}

/// Status lifecycle of a server-side session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Active,
    Revoked,
    Expired,
}

impl SessionStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for SessionStatus {
    type Err = AuthnError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            other => Err(AuthnError::InvalidSessionStatus(other.to_string())),
        }
    }
}

/// Persistence-facing representation of a server-side Session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub principal_id: PrincipalId,
    pub workspace_id: Option<WorkspaceId>,
    pub session_token_hash: String,
    pub status: SessionStatus,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

impl Session {
    /// Creates a new active session domain entity.
    pub fn new(
        principal_id: PrincipalId,
        workspace_id: Option<WorkspaceId>,
        session_token_hash: impl AsRef<str>,
        expires_at: DateTime<Utc>,
        ip_address: Option<impl AsRef<str>>,
        user_agent: Option<impl AsRef<str>>,
    ) -> Result<Self, AuthnError> {
        let trimmed_hash = session_token_hash.as_ref().trim();
        if trimmed_hash.is_empty() {
            return Err(AuthnError::EmptyField("session_token_hash"));
        }

        let now = Utc::now();
        if expires_at <= now {
            return Err(AuthnError::InvalidExpiry(
                "expires_at must be strictly in the future".to_string(),
            ));
        }

        Ok(Self {
            id: SessionId::new(),
            principal_id,
            workspace_id,
            session_token_hash: trimmed_hash.to_string(),
            status: SessionStatus::Active,
            ip_address: ip_address.map(|s| s.as_ref().trim().to_string()),
            user_agent: user_agent.map(|s| s.as_ref().trim().to_string()),
            created_at: now,
            expires_at,
            last_seen_at: now,
        })
    }

    /// Reconstructs an existing Session from persistent storage.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: SessionId,
        principal_id: PrincipalId,
        workspace_id: Option<WorkspaceId>,
        session_token_hash: String,
        status: SessionStatus,
        ip_address: Option<String>,
        user_agent: Option<String>,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        last_seen_at: DateTime<Utc>,
    ) -> Result<Self, AuthnError> {
        let trimmed_hash = session_token_hash.trim();
        if trimmed_hash.is_empty() {
            return Err(AuthnError::EmptyField("session_token_hash"));
        }

        Ok(Self {
            id,
            principal_id,
            workspace_id,
            session_token_hash: trimmed_hash.to_string(),
            status,
            ip_address,
            user_agent,
            created_at,
            expires_at,
            last_seen_at,
        })
    }

    /// Evaluates if the session is currently active at `now`.
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.status == SessionStatus::Active && now < self.expires_at
    }

    /// Evaluates if the session has expired at `now`.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at || self.status == SessionStatus::Expired
    }

    /// Revokes the session (one-way status transition).
    pub fn revoke(&mut self) {
        self.status = SessionStatus::Revoked;
    }

    /// Updates `last_seen_at` if the session is active.
    pub fn touch(&mut self, now: DateTime<Utc>) -> Result<(), AuthnError> {
        if self.status == SessionStatus::Revoked {
            return Err(AuthnError::SessionRevoked(self.id.to_string()));
        }
        if self.is_expired_at(now) {
            self.status = SessionStatus::Expired;
            return Err(AuthnError::SessionExpired(self.id.to_string()));
        }

        self.last_seen_at = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_session_lifecycle() {
        let p_id = PrincipalId::new();
        let expires = Utc::now() + Duration::hours(12);
        let mut session = Session::new(
            p_id,
            None,
            "hash_1234567890abcdef",
            expires,
            Some("127.0.0.1"),
            Some("Mozilla/5.0"),
        )
        .unwrap();

        assert_eq!(session.status, SessionStatus::Active);
        let now = Utc::now();
        assert!(session.is_active_at(now));

        session.touch(now + Duration::minutes(5)).unwrap();

        session.revoke();
        assert_eq!(session.status, SessionStatus::Revoked);
        assert!(!session.is_active_at(now));
        assert!(session.touch(now + Duration::minutes(10)).is_err());
    }
}
