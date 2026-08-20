//! Session persistence application service.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use w014_authn::rotation::SessionRotation;
use w014_authn::session::{Session, SessionId};
use w014_domain::ids::PrincipalId;

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
                Self::revoke_session(tx, old_sess.session_id).await?;
            }
        }
        Ok(())
    }

    /// Creates a new server-side session, enforcing the maximum active session limit.
    pub async fn create_session(
        tx: &mut PgConnection,
        principal_id: PrincipalId,
        handle_hash: impl Into<Vec<u8>>,
        csrf_secret_hash: impl Into<Vec<u8>>,
        idle_expires_at: DateTime<Utc>,
        absolute_expires_at: DateTime<Utc>,
    ) -> Result<Session, ApplicationError> {
        // Enforce maximum 5 active sessions per principal (6th revokes oldest)
        Self::enforce_concurrent_session_limit(tx, principal_id, 5).await?;

        let session = Session::new(
            principal_id,
            handle_hash,
            csrf_secret_hash,
            idle_expires_at,
            absolute_expires_at,
        )?;

        SessionRepository::insert(tx, &session).await?;
        Ok(session)
    }

    /// Performs an append-style session rotation, updating session handle hash and recording rotation history.
    pub async fn rotate_session(
        tx: &mut PgConnection,
        session_id: SessionId,
        new_handle_hash: impl Into<Vec<u8>>,
        new_idle_expires_at: DateTime<Utc>,
        new_absolute_expires_at: DateTime<Utc>,
        reason: Option<impl AsRef<str>>,
    ) -> Result<SessionRotation, ApplicationError> {
        let mut session = SessionRepository::get_by_id(tx, session_id)
            .await?
            .ok_or_else(|| ApplicationError::NotFound(format!("Session {}", session_id)))?;

        let old_handle_hash = session.handle_hash.clone();
        let new_hash_bytes = new_handle_hash.into();
        session.rotation_counter += 1;
        let rotation_number = session.rotation_counter;

        let rotation = SessionRotation::new(
            session_id,
            rotation_number,
            old_handle_hash,
            new_hash_bytes.clone(),
            reason.as_ref().map(|s| s.as_ref()).unwrap_or("periodic"),
        )?;

        // 1. Insert immutable rotation record
        SessionRotationRepository::insert(tx, &rotation).await?;

        // 2. Update session with new handle hash, expiry, touch timestamp, and increment rotation counter
        let now = Utc::now();
        session.handle_hash = new_hash_bytes;
        session.last_seen_at = now;
        session.idle_expires_at = new_idle_expires_at;
        session.absolute_expires_at = new_absolute_expires_at;
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

        session.revoke(Utc::now());
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

    /// Retrieves an active session by handle hash.
    pub async fn get_session_by_handle_hash(
        tx: &mut PgConnection,
        handle_hash: &[u8],
    ) -> Result<Option<Session>, ApplicationError> {
        SessionRepository::get_by_handle_hash(tx, handle_hash)
            .await
            .map_err(ApplicationError::from)
    }
}
