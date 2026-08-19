//! Authentication and session request contextual structures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use w014_domain::ids::{PrincipalId, WorkspaceId};

use crate::session::{Session, SessionId, SessionStatus};

/// Authoritative request context representing an authenticated session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedSession {
    pub session_id: SessionId,
    pub principal_id: PrincipalId,
    pub workspace_id: Option<WorkspaceId>,
    pub status: SessionStatus,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

impl AuthenticatedSession {
    pub fn from_session(session: &Session) -> Self {
        Self {
            session_id: session.id,
            principal_id: session.principal_id,
            workspace_id: session.workspace_id,
            status: session.status,
            ip_address: session.ip_address.clone(),
            user_agent: session.user_agent.clone(),
            created_at: session.created_at,
            expires_at: session.expires_at,
            last_seen_at: session.last_seen_at,
        }
    }
}
