//! Authorization error definitions for capability grants.

use thiserror::Error;

/// Error type for capability grants and authorization semantics.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum AuthzError {
    /// Capability cannot be empty or blank.
    #[error("Capability name cannot be empty or whitespace")]
    EmptyCapability,

    /// An invalid capability string was encountered.
    #[error("Invalid capability format: '{0}'")]
    InvalidCapability(String),

    /// Attempted to revoke a grant that is already expired or revoked.
    #[error("Capability grant '{0}' is already revoked or expired")]
    AlreadyRevoked(String),

    /// Grant expiry time cannot be in the past when creating a new grant.
    #[error("Grant expiry time cannot be before grant time")]
    InvalidExpiryTime,
}
