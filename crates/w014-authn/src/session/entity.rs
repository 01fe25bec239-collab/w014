//! Server-side Session persistence-facing domain semantics.
//!
//! Captures opaque server-side session identity and status lifecycle.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;
use w014_domain::ids::PrincipalId;

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

/// Status lifecycle of a server-side session (derived at runtime from timestamps and revocation state).
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

/// Persistence-facing representation of a server-side Session conforming to Prompt-12.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub session_id: SessionId,
    pub principal_id: PrincipalId,
    pub handle_hash: Vec<u8>,
    pub csrf_secret_hash: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub rotation_counter: i32,
}

impl Session {
    /// Creates a new active session domain entity.
    pub fn new(
        principal_id: PrincipalId,
        handle_hash: impl Into<Vec<u8>>,
        csrf_secret_hash: impl Into<Vec<u8>>,
        idle_expires_at: DateTime<Utc>,
        absolute_expires_at: DateTime<Utc>,
    ) -> Result<Self, AuthnError> {
        let handle_bytes = handle_hash.into();
        if handle_bytes.is_empty() {
            return Err(AuthnError::EmptyField("handle_hash"));
        }

        let csrf_bytes = csrf_secret_hash.into();
        if csrf_bytes.is_empty() {
            return Err(AuthnError::EmptyField("csrf_secret_hash"));
        }

        let now = Utc::now();
        if idle_expires_at <= now {
            return Err(AuthnError::InvalidExpiry(
                "idle_expires_at must be strictly in the future".to_string(),
            ));
        }

        if absolute_expires_at <= now {
            return Err(AuthnError::InvalidExpiry(
                "absolute_expires_at must be strictly in the future".to_string(),
            ));
        }

        Ok(Self {
            session_id: SessionId::new(),
            principal_id,
            handle_hash: handle_bytes,
            csrf_secret_hash: csrf_bytes,
            created_at: now,
            last_seen_at: now,
            idle_expires_at,
            absolute_expires_at,
            revoked_at: None,
            rotation_counter: 0,
        })
    }

    /// Reconstructs an existing Session from persistent storage.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        session_id: SessionId,
        principal_id: PrincipalId,
        handle_hash: Vec<u8>,
        csrf_secret_hash: Vec<u8>,
        created_at: DateTime<Utc>,
        last_seen_at: DateTime<Utc>,
        idle_expires_at: DateTime<Utc>,
        absolute_expires_at: DateTime<Utc>,
        revoked_at: Option<DateTime<Utc>>,
        rotation_counter: i32,
    ) -> Result<Self, AuthnError> {
        if handle_hash.is_empty() {
            return Err(AuthnError::EmptyField("handle_hash"));
        }
        if csrf_secret_hash.is_empty() {
            return Err(AuthnError::EmptyField("csrf_secret_hash"));
        }

        Ok(Self {
            session_id,
            principal_id,
            handle_hash,
            csrf_secret_hash,
            created_at,
            last_seen_at,
            idle_expires_at,
            absolute_expires_at,
            revoked_at,
            rotation_counter,
        })
    }

    /// Evaluates if the session is currently active at `now`.
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && now < self.idle_expires_at && now < self.absolute_expires_at
    }

    /// Evaluates if the session has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Evaluates if the session has expired at `now`.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.idle_expires_at || now >= self.absolute_expires_at
    }

    /// Derives the current lifecycle status of the session at `now`.
    pub fn status_at(&self, now: DateTime<Utc>) -> SessionStatus {
        if self.revoked_at.is_some() {
            SessionStatus::Revoked
        } else if self.is_expired_at(now) {
            SessionStatus::Expired
        } else {
            SessionStatus::Active
        }
    }

    /// Revokes the session by setting `revoked_at`.
    pub fn revoke(&mut self, now: DateTime<Utc>) {
        self.revoked_at = Some(now);
    }

    /// Updates `last_seen_at` and extends `idle_expires_at` if the session is active.
    pub fn touch(&mut self, now: DateTime<Utc>, idle_ttl: Duration) -> Result<(), AuthnError> {
        if self.revoked_at.is_some() {
            return Err(AuthnError::SessionRevoked(self.session_id.to_string()));
        }
        if self.is_expired_at(now) {
            return Err(AuthnError::SessionExpired(self.session_id.to_string()));
        }

        self.last_seen_at = now;
        self.idle_expires_at = now + idle_ttl;
        Ok(())
    }

    /// Returns a hex-encoded representation of handle_hash for rotation identity binding (e.g. CSRF tokens).
    pub fn rotation_identity(&self) -> String {
        hex::encode(&self.handle_hash)
    }
}
