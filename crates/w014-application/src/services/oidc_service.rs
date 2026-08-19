//! OIDC Identity and Transaction persistence application service.
//!
//! Note: Full protocol validation and exchange paths (WI-0102) are deferred.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use w014_authn::identity::OidcIdentity;
use w014_authn::transaction::OidcTransaction;
use w014_domain::ids::PrincipalId;

use crate::error::ApplicationError;
use crate::persistence::{OidcIdentityRepository, OidcTransactionRepository};

/// Service managing OIDC identity linkages and transient authorization transaction tokens.
pub struct OidcPersistenceService;

impl OidcPersistenceService {
    /// Links an external OIDC identity to an authoritative principal.
    pub async fn link_identity(
        tx: &mut PgConnection,
        principal_id: PrincipalId,
        issuer: impl AsRef<str>,
        subject: impl AsRef<str>,
        email: Option<impl AsRef<str>>,
        claims: serde_json::Value,
    ) -> Result<OidcIdentity, ApplicationError> {
        let identity = OidcIdentity::new(principal_id, issuer, subject, email, claims)?;
        OidcIdentityRepository::insert(tx, &identity).await?;
        Ok(identity)
    }

    /// Looks up an OIDC identity by the unique (issuer, subject) composite key.
    pub async fn find_by_issuer_subject(
        tx: &mut PgConnection,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<OidcIdentity>, ApplicationError> {
        OidcIdentityRepository::get_by_issuer_subject(tx, issuer, subject)
            .await
            .map_err(ApplicationError::from)
    }

    /// Stores a transient OIDC transaction state token.
    pub async fn store_transaction(
        tx: &mut PgConnection,
        state_token: impl AsRef<str>,
        nonce: impl AsRef<str>,
        pkce_verifier: Option<impl AsRef<str>>,
        redirect_uri: impl AsRef<str>,
        expires_at: DateTime<Utc>,
    ) -> Result<OidcTransaction, ApplicationError> {
        let transaction =
            OidcTransaction::new(state_token, nonce, pkce_verifier, redirect_uri, expires_at)?;
        OidcTransactionRepository::insert(tx, &transaction).await?;
        Ok(transaction)
    }

    /// Consumes and deletes a transient OIDC transaction by state token (single-use semantics).
    pub async fn consume_transaction(
        tx: &mut PgConnection,
        state_token: &str,
    ) -> Result<Option<OidcTransaction>, ApplicationError> {
        let tx_opt = OidcTransactionRepository::get_by_state_token(tx, state_token).await?;
        if let Some(ref transaction) = tx_opt {
            OidcTransactionRepository::delete_by_id(tx, transaction.id).await?;
        }
        Ok(tx_opt)
    }
}
