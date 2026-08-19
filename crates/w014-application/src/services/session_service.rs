//! Session persistence application service.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use w014_authn::rotation::SessionRotation;
use w014_authn::session::{Session, SessionId};
use w014_domain::ids::{PrincipalId, WorkspaceId};

use crate::error::ApplicationError;
use crate::persistence::{SessionRepository, SessionRotationRepository};

/// Service managing session persistence, concurrent session bounding, and append-style rotations.
pub struct SessionService;

impl SessionService {
    /// Enforces the maximum concurrent active sessions limit for a principal by revoking the oldest active sessions.
    pub async fn enforce_concurrent_session_limit(
        tx: &mut PgConnection,
        principal_id: PrincipalId,
        max_concurrent: usize,
    ) -> Result<(), ApplicationError> {
        let active_sessions = SessionRepository::list_active_by_principal(tx, principal_id).await?;
        if active_sessions.len() >= max_concurrent {
            let to_revoke_count = active_sessions.len() + 1 - max_concurrent;
            for old_sess in active_sessions.into_iter().take(to_revoke_count) {
                Self::revoke_session(tx, old_sess.id).await?;
            }
        }
        Ok(())
    }

    /// Creates a new server-side session, enforcing the maximum active session limit.
    pub async fn create_session(
        tx: &mut PgConnection,
        principal_id: PrincipalId,
        workspace_id: Option<WorkspaceId>,
        session_token_hash: impl AsRef<str>,
        expires_at: DateTime<Utc>,
        ip_address: Option<impl AsRef<str>>,
        user_agent: Option<impl AsRef<str>>,
    ) -> Result<Session, ApplicationError> {
        // Enforce maximum 5 active sessions per principal (6th revokes oldest)
        Self::enforce_concurrent_session_limit(tx, principal_id, 5).await?;

        let session = Session::new(
            principal_id,
            workspace_id,
            session_token_hash,
            expires_at,
            ip_address,
            user_agent,
        )?;

        SessionRepository::insert(tx, &session).await?;
        Ok(session)
    }

    /// Performs an append-style session rotation, updating session token hash and recording rotation history.
    pub async fn rotate_session(
        tx: &mut PgConnection,
        session_id: SessionId,
        new_token_hash: impl AsRef<str>,
        new_expires_at: DateTime<Utc>,
        ip_address: Option<impl AsRef<str>>,
    ) -> Result<SessionRotation, ApplicationError> {
        let mut session = SessionRepository::get_by_id(tx, session_id)
            .await?
            .ok_or_else(|| ApplicationError::NotFound(format!("Session {}", session_id)))?;

        let old_token_hash = session.session_token_hash.clone();
        let rotation = SessionRotation::new(
            session_id,
            &old_token_hash,
            new_token_hash.as_ref(),
            ip_address.as_ref().map(|s| s.as_ref()),
        )?;

        // 1. Insert immutable rotation record
        SessionRotationRepository::insert(tx, &rotation).await?;

        // 2. Update session with new token hash, expiry, and touch timestamp
        session.session_token_hash = new_token_hash.as_ref().to_string();
        session.expires_at = new_expires_at;
        session.last_seen_at = Utc::now();
        SessionRepository::update(tx, &session).await?;

        Ok(rotation)
    }

    /// Revokes a server-side session.
    pub async fn revoke_session(
        tx: &mut PgConnection,
        session_id: SessionId,
    ) -> Result<(), ApplicationError> {
        let mut session = SessionRepository::get_by_id(tx, session_id)
            .await?
            .ok_or_else(|| ApplicationError::NotFound(format!("Session {}", session_id)))?;

        session.revoke();
        SessionRepository::update(tx, &session).await?;
        Ok(())
    }

    /// Revokes all active sessions for a principal (e.g. on privilege or membership change).
    pub async fn revoke_all_for_principal(
        tx: &mut PgConnection,
        principal_id: PrincipalId,
    ) -> Result<u64, ApplicationError> {
        SessionRepository::revoke_all_by_principal(tx, principal_id)
            .await
            .map_err(ApplicationError::from)
    }

    /// Retrieves an active session by token hash, validating expiry.
    pub async fn get_session_by_token_hash(
        tx: &mut PgConnection,
        token_hash: &str,
    ) -> Result<Option<Session>, ApplicationError> {
        SessionRepository::get_by_token_hash(tx, token_hash)
            .await
            .map_err(ApplicationError::from)
    }
}
