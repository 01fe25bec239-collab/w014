//! Error definitions for the W-014 domain model.

use thiserror::Error;

/// Domain error representing invariant violations, invalid formats, or illegal state transitions.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum DomainError {
    /// A required field was empty or contained only whitespace.
    #[error("Required field '{0}' cannot be empty or whitespace")]
    EmptyField(&'static str),

    /// A slug contained invalid characters or violated formatting constraints.
    #[error(
        "Invalid slug '{0}': slugs must contain only lowercase alphanumeric characters, dashes, and underscores"
    )]
    InvalidSlug(String),

    /// An invalid principal type was specified.
    #[error("Invalid principal type '{0}': expected 'user', 'service', or 'system'")]
    InvalidPrincipalType(String),

    /// An invalid membership role was specified.
    #[error("Invalid membership role '{0}': expected 'admin', 'operator', 'reviewer', or 'reader'")]
    InvalidMembershipRole(String),

    /// General entity invariant validation failure.
    #[error("Domain validation error for {field}: {reason}")]
    ValidationError { field: &'static str, reason: String },

    /// Attempted illegal state transition.
    #[error("Illegal state transition from '{from}' to '{to}': {reason}")]
    IllegalStateTransition {
        from: String,
        to: String,
        reason: String,
    },

    /// The principal is deactivated and cannot perform the operation.
    #[error("Principal '{0}' is inactive")]
    InactivePrincipal(String),
}
