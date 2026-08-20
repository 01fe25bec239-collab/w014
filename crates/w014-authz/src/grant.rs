//! Capability grant domain representation and lifecycle semantics.
//!
//! Note: The WI-0103 capability predicate engine and AuthorizedWorkspaceContext
//! are explicitly deferred to WI-0103.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use w014_domain::ids::{PrincipalId, ProgramId, WorkspaceId};

use crate::capability::{Capability, CapabilityGrantId};
use crate::error::AuthzError;

/// Authoritative domain representation of a capability grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub id: CapabilityGrantId,
    pub workspace_id: Option<WorkspaceId>,
    pub program_id: Option<ProgramId>,
    pub principal_id: PrincipalId,
    pub capability: Capability,
    pub granted_by: Option<PrincipalId>,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<PrincipalId>,
    pub grant_reason: Option<String>,
}

impl CapabilityGrant {
    /// Creates a new workspace-scoped capability grant for a principal.
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
            workspace_id: Some(workspace_id),
            program_id: None,
            principal_id,
            capability,
            granted_by,
            granted_at: now,
            expires_at,
            revoked_at: None,
            revoked_by: None,
            grant_reason: None,
        })
    }

    /// Creates a new program-scoped capability grant for a principal.
    pub fn new_program_grant(
        program_id: ProgramId,
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
            workspace_id: None,
            program_id: Some(program_id),
            principal_id,
            capability,
            granted_by,
            granted_at: now,
            expires_at,
            revoked_at: None,
            revoked_by: None,
            grant_reason: None,
        })
    }

    /// Reconstructs an existing capability grant from persistent storage.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: CapabilityGrantId,
        workspace_id: Option<WorkspaceId>,
        program_id: Option<ProgramId>,
        principal_id: PrincipalId,
        capability: Capability,
        granted_by: Option<PrincipalId>,
        granted_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        revoked_at: Option<DateTime<Utc>>,
        revoked_by: Option<PrincipalId>,
        grant_reason: Option<String>,
    ) -> Self {
        Self {
            id,
            workspace_id,
            program_id,
            principal_id,
            capability,
            granted_by,
            granted_at,
            expires_at,
            revoked_at,
            revoked_by,
            grant_reason,
        }
    }

    /// Evaluates if the grant is active at the given timestamp.
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        if let Some(revoked_at) = self.revoked_at
            && now >= revoked_at
        {
            return false;
        }
        match self.expires_at {
            Some(exp) => now < exp,
            None => true,
        }
    }

    /// Evaluates if the grant is expired or revoked at the given timestamp.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        !self.is_active_at(now)
    }

    /// Evaluates if the grant is explicitly revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Revokes the grant at the specified timestamp (one-way revocation).
    pub fn revoke(
        &mut self,
        revoked_at: DateTime<Utc>,
        revoked_by: Option<PrincipalId>,
        reason: Option<String>,
    ) -> Result<(), AuthzError> {
        if self.revoked_at.is_some() {
            return Err(AuthzError::AlreadyRevoked(self.id.to_string()));
        }

        self.revoked_at = Some(revoked_at);
        self.revoked_by = revoked_by;
        if reason.is_some() {
            self.grant_reason = reason;
        }
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
        grant
            .revoke(now, Some(grantor), Some("Revoked".to_string()))
            .unwrap();
        assert!(!grant.is_active_at(now + Duration::seconds(1)));
        assert!(grant.is_expired_at(now + Duration::seconds(1)));
        assert!(grant.is_revoked());

        // Revoking already revoked grant fails
        assert!(
            grant
                .revoke(now + Duration::seconds(5), None, None)
                .is_err()
        );
    }
}
