//! Authorization error definitions for capability grants and workspace authorization.

use thiserror::Error;
use w014_domain::ids::{OrganizationId, PrincipalId, ProgramId, WorkspaceId};

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

    /// Access denied due to missing required capability.
    #[error("Access denied: missing required capability '{0}'")]
    PermissionDenied(String),

    /// Access denied due to missing required special authority.
    #[error("Access denied: missing required special authority '{0}'")]
    SpecialAuthorityDenied(String),

    /// Access denied: principal requires all of the specified capabilities.
    #[error("Access denied: requires all of {0:?}")]
    MissingAllCapabilities(Vec<String>),

    /// Access denied: principal requires at least one of the specified capabilities.
    #[error("Access denied: requires at least one of {0:?}")]
    MissingAnyCapability(Vec<String>),

    /// Principal is inactive in the system.
    #[error("Principal '{0}' is inactive")]
    InactivePrincipal(PrincipalId),

    /// Principal has no membership in the workspace.
    #[error("Principal '{principal_id}' has no membership in workspace '{workspace_id}'")]
    NoMembership {
        principal_id: PrincipalId,
        workspace_id: WorkspaceId,
    },

    /// Tenant boundary violation or mismatch between entity scopes.
    #[error("Tenant boundary mismatch: {0}")]
    TenantBoundaryMismatch(String),

    /// Workspace organization mismatch.
    #[error("Organization mismatch: expected '{expected}', got '{actual}'")]
    OrganizationMismatch {
        expected: OrganizationId,
        actual: OrganizationId,
    },

    /// Workspace program mismatch.
    #[error("Program mismatch: expected '{expected}', got '{actual}'")]
    ProgramMismatch {
        expected: ProgramId,
        actual: ProgramId,
    },

    /// Workspace identity mismatch.
    #[error("Workspace mismatch: expected '{expected}', got '{actual}'")]
    WorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
}
