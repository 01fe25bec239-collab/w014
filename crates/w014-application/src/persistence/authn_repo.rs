//! PostgreSQL repository operations for OIDC Identities, Sessions, Session Rotations, and OIDC Transactions.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, Row};
use w014_authn::identity::{OidcIdentity, OidcIdentityId};
use w014_authn::rotation::SessionRotation;
use w014_authn::session::{Session, SessionId};
use w014_authn::transaction::{OidcTransaction, OidcTransactionId};
use w014_domain::ids::PrincipalId;
use w014_persistence::error::PersistenceError;

/// Repository operations for OIDC Identities.
pub struct OidcIdentityRepository;

impl OidcIdentityRepository {
    pub async fn insert(
        tx: &mut PgConnection,
        identity: &OidcIdentity,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO oidc_identities (oidc_identity_id, principal_id, issuer, subject, email_at_link, linked_at, last_login_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(identity.id.as_uuid())
        .bind(identity.principal_id.as_uuid())
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .bind(identity.email_at_link.as_deref())
        .bind(identity.linked_at)
        .bind(identity.last_login_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn get_by_issuer_subject(
        tx: &mut PgConnection,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<OidcIdentity>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT oidc_identity_id, principal_id, issuer, subject, email_at_link, linked_at, last_login_at
             FROM oidc_identities
             WHERE issuer = $1 AND subject = $2",
        )
        .bind(issuer)
        .bind(subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let id = OidcIdentity::reconstruct(
                    OidcIdentityId::from_uuid(row.get("oidc_identity_id")),
                    PrincipalId::from_uuid(row.get("principal_id")),
                    row.get("issuer"),
                    row.get("subject"),
                    row.get("email_at_link"),
                    row.get("linked_at"),
                    row.get("last_login_at"),
                )
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;

                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    pub async fn update_last_login(
        tx: &mut PgConnection,
        id: OidcIdentityId,
        last_login_at: DateTime<Utc>,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "UPDATE oidc_identities
             SET last_login_at = $2
             WHERE oidc_identity_id = $1",
        )
        .bind(id.as_uuid())
        .bind(last_login_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }
}

/// Repository operations for Sessions.
pub struct SessionRepository;

impl SessionRepository {
    pub async fn insert(tx: &mut PgConnection, session: &Session) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO sessions (session_id, principal_id, handle_hash, csrf_secret_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, rotation_counter)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(session.session_id.as_uuid())
        .bind(session.principal_id.as_uuid())
        .bind(&session.handle_hash[..])
        .bind(&session.csrf_secret_hash[..])
        .bind(session.created_at)
        .bind(session.last_seen_at)
        .bind(session.idle_expires_at)
        .bind(session.absolute_expires_at)
        .bind(session.revoked_at)
        .bind(session.rotation_counter)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn get_by_id(
        tx: &mut PgConnection,
        session_id: SessionId,
    ) -> Result<Option<Session>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT session_id, principal_id, handle_hash, csrf_secret_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, rotation_counter
             FROM sessions
             WHERE session_id = $1",
        )
        .bind(session_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Self::map_row_opt(row_opt)
    }

    pub async fn get_by_handle_hash(
        tx: &mut PgConnection,
        handle_hash: &[u8],
    ) -> Result<Option<Session>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT session_id, principal_id, handle_hash, csrf_secret_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, rotation_counter
             FROM sessions
             WHERE handle_hash = $1",
        )
        .bind(handle_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Self::map_row_opt(row_opt)
    }

    pub async fn update(tx: &mut PgConnection, session: &Session) -> Result<(), PersistenceError> {
        sqlx::query(
            "UPDATE sessions
             SET handle_hash = $2, csrf_secret_hash = $3, last_seen_at = $4, idle_expires_at = $5, absolute_expires_at = $6, revoked_at = $7, rotation_counter = $8
             WHERE session_id = $1",
        )
        .bind(session.session_id.as_uuid())
        .bind(&session.handle_hash[..])
        .bind(&session.csrf_secret_hash[..])
        .bind(session.last_seen_at)
        .bind(session.idle_expires_at)
        .bind(session.absolute_expires_at)
        .bind(session.revoked_at)
        .bind(session.rotation_counter)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    /// Lists all currently active sessions for a principal, ordered by creation time ASC (oldest first).
    pub async fn list_active_by_principal(
        tx: &mut PgConnection,
        principal_id: PrincipalId,
    ) -> Result<Vec<Session>, PersistenceError> {
        let rows = sqlx::query(
            "SELECT session_id, principal_id, handle_hash, csrf_secret_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, rotation_counter
             FROM sessions
             WHERE principal_id = $1
               AND revoked_at IS NULL
               AND idle_expires_at > CURRENT_TIMESTAMP
               AND absolute_expires_at > CURRENT_TIMESTAMP
             ORDER BY created_at ASC",
        )
        .bind(principal_id.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let mut sessions = Vec::with_capacity(rows.len());
        for row in rows {
            if let Some(session) = Self::map_row_opt(Some(row))? {
                sessions.push(session);
            }
        }

        Ok(sessions)
    }

    /// Revokes all active sessions for a given principal.
    pub async fn revoke_all_by_principal(
        tx: &mut PgConnection,
        principal_id: PrincipalId,
    ) -> Result<u64, PersistenceError> {
        let result = sqlx::query(
            "UPDATE sessions
             SET revoked_at = CURRENT_TIMESTAMP
             WHERE principal_id = $1
               AND revoked_at IS NULL",
        )
        .bind(principal_id.as_uuid())
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(result.rows_affected())
    }

    fn map_row_opt(
        row_opt: Option<sqlx::postgres::PgRow>,
    ) -> Result<Option<Session>, PersistenceError> {
        match row_opt {
            Some(row) => {
                let s = Session::reconstruct(
                    SessionId::from_uuid(row.get("session_id")),
                    PrincipalId::from_uuid(row.get("principal_id")),
                    row.get("handle_hash"),
                    row.get("csrf_secret_hash"),
                    row.get("created_at"),
                    row.get("last_seen_at"),
                    row.get("idle_expires_at"),
                    row.get("absolute_expires_at"),
                    row.get("revoked_at"),
                    row.get("rotation_counter"),
                )
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;

                Ok(Some(s))
            }
            None => Ok(None),
        }
    }
}

/// Repository operations for Session Rotations.
pub struct SessionRotationRepository;

impl SessionRotationRepository {
    pub async fn insert(
        tx: &mut PgConnection,
        rotation: &SessionRotation,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO session_rotations (session_rotation_id, session_id, rotation_number, old_handle_hash, new_handle_hash, reason, rotated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(rotation.id.as_uuid())
        .bind(rotation.session_id.as_uuid())
        .bind(rotation.rotation_number)
        .bind(&rotation.old_handle_hash[..])
        .bind(&rotation.new_handle_hash[..])
        .bind(&rotation.reason)
        .bind(rotation.rotated_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }
}

/// Repository operations for OIDC Transactions.
pub struct OidcTransactionRepository;

impl OidcTransactionRepository {
    pub async fn insert(
        tx: &mut PgConnection,
        transaction: &OidcTransaction,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO oidc_transactions (oidc_transaction_id, state_hash, nonce_hash, pkce_verifier_ciphertext, return_path, created_at, expires_at, consumed_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(transaction.id.as_uuid())
        .bind(&transaction.state_hash[..])
        .bind(&transaction.nonce_hash[..])
        .bind(transaction.pkce_verifier_ciphertext.as_deref())
        .bind(&transaction.return_path)
        .bind(transaction.created_at)
        .bind(transaction.expires_at)
        .bind(transaction.consumed_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn get_by_state_hash(
        tx: &mut PgConnection,
        state_hash: &[u8],
    ) -> Result<Option<OidcTransaction>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT oidc_transaction_id, state_hash, nonce_hash, pkce_verifier_ciphertext, return_path, created_at, expires_at, consumed_at
             FROM oidc_transactions
             WHERE state_hash = $1",
        )
        .bind(state_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let tx_rec = OidcTransaction::reconstruct(
                    OidcTransactionId::from_uuid(row.get("oidc_transaction_id")),
                    row.get("state_hash"),
                    row.get("nonce_hash"),
                    row.get("pkce_verifier_ciphertext"),
                    row.get("return_path"),
                    row.get("created_at"),
                    row.get("expires_at"),
                    row.get("consumed_at"),
                )
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;

                Ok(Some(tx_rec))
            }
            None => Ok(None),
        }
    }

    pub async fn consume(
        tx: &mut PgConnection,
        id: OidcTransactionId,
        consumed_at: DateTime<Utc>,
    ) -> Result<bool, PersistenceError> {
        let result = sqlx::query(
            "UPDATE oidc_transactions
             SET consumed_at = $2
             WHERE oidc_transaction_id = $1 AND consumed_at IS NULL",
        )
        .bind(id.as_uuid())
        .bind(consumed_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_by_id(
        tx: &mut PgConnection,
        id: OidcTransactionId,
    ) -> Result<(), PersistenceError> {
        sqlx::query("DELETE FROM oidc_transactions WHERE oidc_transaction_id = $1")
            .bind(id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(())
    }
}
