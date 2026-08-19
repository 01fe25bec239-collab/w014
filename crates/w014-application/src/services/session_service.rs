//! Session persistence application service.
//!
//! Note: Full WI-0102 session execution flow is deferred to WI-0102.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use w014_authn::rotation::SessionRotation;
use w014_authn::session::{Session, SessionId};
use w014_domain::ids::{PrincipalId, WorkspaceId};

use crate::error::ApplicationError;
use crate::persistence::{SessionRepository, SessionRotationRepository};

/// Service managing session persistence and append-style session rotations.
pub struct SessionService;

impl SessionService {
    /// Creates a new server-side session.
    pub async fn create_session(
        tx: &mut PgConnection,
        principal_id: PrincipalId,
        workspace_id: Option<WorkspaceId>,
        session_token_hash: impl AsRef<str>,
        expires_at: DateTime<Utc>,
        ip_address: Option<impl AsRef<str>>,
        user_agent: Option<impl AsRef<str>>,
    ) -> Result<Session, ApplicationError> {
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
