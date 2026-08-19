//! Application layer error definitions.

use thiserror::Error;
use w014_authn::error::AuthnError;
use w014_authz::error::AuthzError;
use w014_domain::error::DomainError;
use w014_persistence::error::PersistenceError;

/// Application layer unified error type.
#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("Domain error: {0}")]
    Domain(#[from] DomainError),

    #[error("Authentication/Session error: {0}")]
    Authn(#[from] AuthnError),

    #[error("Authorization error: {0}")]
    Authz(#[from] AuthzError),

    #[error("Persistence error: {0}")]
    Persistence(#[from] PersistenceError),

    #[error("Entity not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Idempotency mismatch: stored hash '{expected}', requested hash '{actual}'")]
    IdempotencyMismatch { expected: String, actual: String },

    #[error("Idempotency key currently in progress by another request")]
    IdempotencyInProgress,

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    #[error("RLS workspace context verification failed: expected {expected}, actual {actual:?}")]
    RlsContextVerificationFailed {
        expected: uuid::Uuid,
        actual: Option<uuid::Uuid>,
    },

    #[error("Internal application error: {0}")]
    Internal(String),
}

impl From<sqlx::Error> for ApplicationError {
    fn from(err: sqlx::Error) -> Self {
        Self::Persistence(PersistenceError::Connection(err))
    }
}
