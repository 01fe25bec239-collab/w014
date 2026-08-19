//! PostgreSQL repository operations for OIDC Identities, Sessions, Session Rotations, and OIDC Transactions.

use sqlx::{PgConnection, Row};
use uuid::Uuid;
use w014_authn::identity::{OidcIdentity, OidcIdentityId};
use w014_authn::rotation::SessionRotation;
use w014_authn::session::{Session, SessionId, SessionStatus};
use w014_authn::transaction::{OidcTransaction, OidcTransactionId};
use w014_domain::ids::{PrincipalId, WorkspaceId};
use w014_persistence::error::PersistenceError;

/// Repository operations for OIDC Identities.
pub struct OidcIdentityRepository;

impl OidcIdentityRepository {
    pub async fn insert(
        tx: &mut PgConnection,
        identity: &OidcIdentity,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO oidc_identities (id, principal_id, issuer, subject, email, claims, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(identity.id.as_uuid())
        .bind(identity.principal_id.as_uuid())
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .bind(&identity.email)
        .bind(&identity.claims)
        .bind(identity.created_at)
        .bind(identity.updated_at)
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
            "SELECT id, principal_id, issuer, subject, email, claims, created_at, updated_at
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
                    OidcIdentityId::from_uuid(row.get("id")),
                    PrincipalId::from_uuid(row.get("principal_id")),
                    row.get("issuer"),
                    row.get("subject"),
                    row.get("email"),
                    row.get("claims"),
                    row.get("created_at"),
                    row.get("updated_at"),
                )
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;

                Ok(Some(id))
            }
            None => Ok(None),
        }
    }
}

/// Repository operations for Sessions.
pub struct SessionRepository;

impl SessionRepository {
    pub async fn insert(tx: &mut PgConnection, session: &Session) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO sessions (id, principal_id, workspace_id, session_token_hash, status, ip_address, user_agent, created_at, expires_at, last_seen_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(session.id.as_uuid())
        .bind(session.principal_id.as_uuid())
        .bind(session.workspace_id.map(|w| w.as_uuid()))
        .bind(&session.session_token_hash)
        .bind(session.status.as_str())
        .bind(&session.ip_address)
        .bind(&session.user_agent)
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(session.last_seen_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn get_by_id(
        tx: &mut PgConnection,
        id: SessionId,
    ) -> Result<Option<Session>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, principal_id, workspace_id, session_token_hash, status, ip_address, user_agent, created_at, expires_at, last_seen_at
             FROM sessions
             WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Self::map_row_opt(row_opt)
    }

    pub async fn get_by_token_hash(
        tx: &mut PgConnection,
        token_hash: &str,
    ) -> Result<Option<Session>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, principal_id, workspace_id, session_token_hash, status, ip_address, user_agent, created_at, expires_at, last_seen_at
             FROM sessions
             WHERE session_token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Self::map_row_opt(row_opt)
    }

    pub async fn update(tx: &mut PgConnection, session: &Session) -> Result<(), PersistenceError> {
        sqlx::query(
            "UPDATE sessions
             SET status = $2, session_token_hash = $3, last_seen_at = $4, expires_at = $5
             WHERE id = $1",
        )
        .bind(session.id.as_uuid())
        .bind(session.status.as_str())
        .bind(&session.session_token_hash)
        .bind(session.last_seen_at)
        .bind(session.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    fn map_row_opt(
        row_opt: Option<sqlx::postgres::PgRow>,
    ) -> Result<Option<Session>, PersistenceError> {
        match row_opt {
            Some(row) => {
                let status_str: String = row.get("status");
                let status: SessionStatus =
                    status_str
                        .parse()
                        .map_err(|e: w014_authn::error::AuthnError| {
                            PersistenceError::Operation(e.to_string())
                        })?;

                let ws_uuid: Option<Uuid> = row.get("workspace_id");

                let s = Session::reconstruct(
                    SessionId::from_uuid(row.get("id")),
                    PrincipalId::from_uuid(row.get("principal_id")),
                    ws_uuid.map(WorkspaceId::from_uuid),
                    row.get("session_token_hash"),
                    status,
                    row.get("ip_address"),
                    row.get("user_agent"),
                    row.get("created_at"),
                    row.get("expires_at"),
                    row.get("last_seen_at"),
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
            "INSERT INTO session_rotations (id, session_id, old_token_hash, new_token_hash, rotated_at, ip_address)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(rotation.id.as_uuid())
        .bind(rotation.session_id.as_uuid())
        .bind(&rotation.old_token_hash)
        .bind(&rotation.new_token_hash)
        .bind(rotation.rotated_at)
        .bind(&rotation.ip_address)
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
            "INSERT INTO oidc_transactions (id, state_token, nonce, pkce_verifier, redirect_uri, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(transaction.id.as_uuid())
        .bind(&transaction.state_token)
        .bind(&transaction.nonce)
        .bind(&transaction.pkce_verifier)
        .bind(&transaction.redirect_uri)
        .bind(transaction.created_at)
        .bind(transaction.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn get_by_state_token(
        tx: &mut PgConnection,
        state_token: &str,
    ) -> Result<Option<OidcTransaction>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, state_token, nonce, pkce_verifier, redirect_uri, created_at, expires_at
             FROM oidc_transactions
             WHERE state_token = $1",
        )
        .bind(state_token)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let tx_rec = OidcTransaction::reconstruct(
                    OidcTransactionId::from_uuid(row.get("id")),
                    row.get("state_token"),
                    row.get("nonce"),
                    row.get("pkce_verifier"),
                    row.get("redirect_uri"),
                    row.get("created_at"),
                    row.get("expires_at"),
                )
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;

                Ok(Some(tx_rec))
            }
            None => Ok(None),
        }
    }

    pub async fn delete_by_id(
        tx: &mut PgConnection,
        id: OidcTransactionId,
    ) -> Result<(), PersistenceError> {
        sqlx::query("DELETE FROM oidc_transactions WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(())
    }
}
