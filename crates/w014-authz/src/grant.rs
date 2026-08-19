//! Capability grant domain representation and lifecycle semantics.
//!
//! Note: The WI-0103 capability predicate engine and AuthorizedWorkspaceContext
//! are explicitly deferred to WI-0103.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use w014_domain::ids::{PrincipalId, WorkspaceId};

use crate::capability::{Capability, CapabilityGrantId};
use crate::error::AuthzError;

/// Authoritative domain representation of a capability grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub id: CapabilityGrantId,
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub capability: Capability,
    pub granted_by: Option<PrincipalId>,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl CapabilityGrant {
    /// Creates a new capability grant for a principal within a workspace.
    pub fn new(
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        capability: Capability,
        granted_by: Option<PrincipalId>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Self, AuthzError> {
        let now = Utc::now();
        if expires_at.is_some_and(|exp| exp <= now) {
            return Err(AuthzError::InvalidExpiryTime);
        }

        Ok(Self {
            id: CapabilityGrantId::new(),
            workspace_id,
            principal_id,
            capability,
            granted_by,
            granted_at: now,
            expires_at,
        })
    }

    /// Reconstructs an existing capability grant from persistent storage.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: CapabilityGrantId,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        capability: Capability,
        granted_by: Option<PrincipalId>,
        granted_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            id,
            workspace_id,
            principal_id,
            capability,
            granted_by,
            granted_at,
            expires_at,
        }
    }

    /// Evaluates if the grant is active at the given timestamp.
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            Some(exp) => now < exp,
            None => true,
        }
    }

    /// Evaluates if the grant is expired at the given timestamp.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            Some(exp) => now >= exp,
            None => false,
        }
    }

    /// Revokes the grant at the specified timestamp (one-way revocation).
    ///
    /// Once revoked, `expires_at` is set to `revoked_at`. If the grant was already expired
    /// before `revoked_at`, an `AlreadyRevoked` error is returned.
    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), AuthzError> {
        if self.is_expired_at(revoked_at) {
            return Err(AuthzError::AlreadyRevoked(self.id.to_string()));
        }

        self.expires_at = Some(revoked_at);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_grant_active_and_expiry_lifecycle() {
        let ws_id = WorkspaceId::new();
        let p_id = PrincipalId::new();
        let grantor = PrincipalId::new();

        let future_expiry = Utc::now() + Duration::hours(2);
        let mut grant = CapabilityGrant::new(
            ws_id,
            p_id,
            Capability::OverrideBlock,
            Some(grantor),
            Some(future_expiry),
        )
        .unwrap();

        let now = Utc::now();
        assert!(grant.is_active_at(now));
        assert!(!grant.is_expired_at(now));

        // Revoke the grant
        grant.revoke(now).unwrap();
        assert!(!grant.is_active_at(now + Duration::seconds(1)));
        assert!(grant.is_expired_at(now + Duration::seconds(1)));

        // Revoking already revoked grant fails
        assert!(grant.revoke(now + Duration::seconds(5)).is_err());
    }
}
