//! Authentication and session request contextual structures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use w014_domain::ids::PrincipalId;

use crate::session::{Session, SessionId};

/// Authoritative request context representing an authenticated session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedSession {
    pub session_id: SessionId,
    pub principal_id: PrincipalId,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub rotation_counter: i32,
}

impl AuthenticatedSession {
    pub fn from_session(session: &Session) -> Self {
        Self {
            session_id: session.session_id,
            principal_id: session.principal_id,
            created_at: session.created_at,
            last_seen_at: session.last_seen_at,
            idle_expires_at: session.idle_expires_at,
            absolute_expires_at: session.absolute_expires_at,
            rotation_counter: session.rotation_counter,
        }
    }
}
