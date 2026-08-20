//! OIDC Identity and Transaction persistence application service.

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
        email_at_link: Option<impl AsRef<str>>,
    ) -> Result<OidcIdentity, ApplicationError> {
        let identity = OidcIdentity::new(principal_id, issuer, subject, email_at_link)?;
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
        state_hash: Vec<u8>,
        nonce_hash: Vec<u8>,
        pkce_verifier_ciphertext: Option<Vec<u8>>,
        return_path: impl AsRef<str>,
        expires_at: DateTime<Utc>,
    ) -> Result<OidcTransaction, ApplicationError> {
        let transaction = OidcTransaction::new(
            state_hash,
            nonce_hash,
            pkce_verifier_ciphertext,
            return_path,
            expires_at,
        )?;
        OidcTransactionRepository::insert(tx, &transaction).await?;
        Ok(transaction)
    }

    /// Consumes a transient OIDC transaction by state hash (single-use semantics).
    pub async fn consume_transaction(
        tx: &mut PgConnection,
        state_hash: &[u8],
    ) -> Result<Option<OidcTransaction>, ApplicationError> {
        let tx_opt = OidcTransactionRepository::get_by_state_hash(tx, state_hash).await?;
        if let Some(ref transaction) = tx_opt {
            let now = Utc::now();
            let consumed = OidcTransactionRepository::consume(tx, transaction.id, now).await?;
            if !consumed {
                return Ok(None);
            }
        }
        Ok(tx_opt)
    }
}
