//! Authentication and session error definitions.

use thiserror::Error;

/// Error type for authentication, session, and OIDC transaction semantics.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum AuthnError {
    /// A required field was empty or whitespace.
    #[error("Required field '{0}' cannot be empty or whitespace")]
    EmptyField(&'static str),

    /// Invalid issuer format.
    #[error("Invalid OIDC issuer: '{0}'")]
    InvalidIssuer(String),

    /// Invalid subject format.
    #[error("Invalid OIDC subject: '{0}'")]
    InvalidSubject(String),

    /// Invalid session status string.
    #[error("Invalid session status '{0}': expected 'active', 'revoked', or 'expired'")]
    InvalidSessionStatus(String),

    /// Session is revoked.
    #[error("Session '{0}' is revoked")]
    SessionRevoked(String),

    /// Session is expired.
    #[error("Session '{0}' is expired")]
    SessionExpired(String),

    /// Old and new token hashes in a session rotation must not be identical.
    #[error("Session rotation old and new token hashes cannot be identical")]
    IdenticalRotationHashes,

    /// Invalid expiration timestamp (e.g., expiry in the past or before creation).
    #[error("Invalid expiration timestamp: {0}")]
    InvalidExpiry(String),
}
