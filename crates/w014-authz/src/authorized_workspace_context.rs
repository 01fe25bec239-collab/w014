//! AuthorizedWorkspaceContext domain boundary.
//!
//! Provides the typed, fail-closed workspace authorization context required
//! by tenant-scoped commands and services.
//!
//! Preserves:
//! - Principal identity
//! - Organization / Program / Workspace hierarchy relationship
//! - Membership state and role
//! - Resolved capability set and predicates
//! - Tenant / workspace identity binding
//! - Special-authority separation

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use w014_domain::ids::{OrganizationId, PrincipalId, ProgramId, WorkspaceId};
use w014_domain::membership::MembershipRole;

use crate::authority::SpecialAuthority;
use crate::capability::Capability;
use crate::capability_set::CapabilitySet;
use crate::error::AuthzError;
use crate::grant::CapabilityGrant;
use crate::policy::{Decision, PolicyEngine, PolicyRule};
use crate::role_profile::RoleProfile;

/// Authoritative, typed, fail-closed workspace authorization context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedWorkspaceContext {
    principal_id: PrincipalId,
    organization_id: OrganizationId,
    program_id: ProgramId,
    workspace_id: WorkspaceId,
    membership_role: MembershipRole,
    capabilities: CapabilitySet,
    active_grants: Vec<CapabilityGrant>,
    evaluated_at: DateTime<Utc>,
}

impl AuthorizedWorkspaceContext {
    /// Constructs and resolves an `AuthorizedWorkspaceContext` from membership and active capability grants.
    ///
    /// Fail-closed semantics:
    /// - Base capabilities are initialized from `RoleProfile::base_capabilities(membership_role)`.
    /// - All provided capability grants are filtered to ensure:
    ///   1. `grant.workspace_id == Some(workspace_id)` OR `grant.program_id == Some(program_id)`
    ///   2. `grant.principal_id == principal_id`
    ///   3. `grant.is_active_at(evaluated_at)`
    /// - Active grants are merged into the resolved `CapabilitySet`.
    pub fn resolve(
        principal_id: PrincipalId,
        organization_id: OrganizationId,
        program_id: ProgramId,
        workspace_id: WorkspaceId,
        membership_role: MembershipRole,
        grants: Vec<CapabilityGrant>,
        evaluated_at: DateTime<Utc>,
    ) -> Self {
        let mut capabilities = RoleProfile::base_capabilities(membership_role);
        let mut valid_active_grants = Vec::new();

        for grant in grants {
            let matches_scope =
                grant.workspace_id == Some(workspace_id) || grant.program_id == Some(program_id);

            if matches_scope
                && grant.principal_id == principal_id
                && grant.is_active_at(evaluated_at)
            {
                capabilities.insert(grant.capability.clone());
                valid_active_grants.push(grant);
            }
        }

        Self {
            principal_id,
            organization_id,
            program_id,
            workspace_id,
            membership_role,
            capabilities,
            active_grants: valid_active_grants,
            evaluated_at,
        }
    }

    /// Reconstructs an already resolved `AuthorizedWorkspaceContext` (e.g. from cache or snapshot).
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        principal_id: PrincipalId,
        organization_id: OrganizationId,
        program_id: ProgramId,
        workspace_id: WorkspaceId,
        membership_role: MembershipRole,
        capabilities: CapabilitySet,
        active_grants: Vec<CapabilityGrant>,
        evaluated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            principal_id,
            organization_id,
            program_id,
            workspace_id,
            membership_role,
            capabilities,
            active_grants,
            evaluated_at,
        }
    }

    // Accessors

    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    pub const fn program_id(&self) -> ProgramId {
        self.program_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn membership_role(&self) -> MembershipRole {
        self.membership_role
    }

    pub const fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    pub fn active_grants(&self) -> &[CapabilityGrant] {
        &self.active_grants
    }

    pub const fn evaluated_at(&self) -> DateTime<Utc> {
        self.evaluated_at
    }

    // Predicates & Evaluation

    /// Checks if this context has the specified capability.
    pub fn can(&self, capability: &Capability) -> bool {
        self.capabilities.contains(capability)
    }

    /// Checks if this context has all of the specified capabilities.
    pub fn can_all(&self, capabilities: &[Capability]) -> bool {
        self.capabilities.contains_all(capabilities)
    }

    /// Checks if this context has at least one of the specified capabilities.
    pub fn can_any(&self, capabilities: &[Capability]) -> bool {
        self.capabilities.contains_any(capabilities)
    }

    /// Checks if this context has the specified special authority.
    pub fn has_special_authority(&self, authority: SpecialAuthority) -> bool {
        self.capabilities.has_special_authority(authority)
    }

    /// Requires a specific capability, returning `Ok(())` or `Err(AuthzError)`.
    pub fn require(&self, capability: &Capability) -> Result<(), AuthzError> {
        PolicyEngine::evaluate_capability(&self.capabilities, capability).into_result()
    }

    /// Requires all of the specified capabilities, returning `Ok(())` or `Err(AuthzError)`.
    pub fn require_all(&self, capabilities: &[Capability]) -> Result<(), AuthzError> {
        PolicyEngine::evaluate_all(&self.capabilities, capabilities).into_result()
    }

    /// Requires at least one of the specified capabilities, returning `Ok(())` or `Err(AuthzError)`.
    pub fn require_any(&self, capabilities: &[Capability]) -> Result<(), AuthzError> {
        PolicyEngine::evaluate_any(&self.capabilities, capabilities).into_result()
    }

    /// Requires a specific special authority, returning `Ok(())` or `Err(AuthzError)`.
    pub fn require_special_authority(&self, authority: SpecialAuthority) -> Result<(), AuthzError> {
        PolicyEngine::evaluate_special(&self.capabilities, authority).into_result()
    }

    /// Evaluates a `PolicyRule` against this context.
    pub fn evaluate(&self, rule: &PolicyRule) -> Decision {
        PolicyEngine::evaluate_rule(&self.capabilities, rule)
    }

    // Standard convenience predicates

    pub fn can_read_workspace(&self) -> bool {
        self.capabilities.can_read_workspace()
    }

    pub fn can_write_workspace(&self) -> bool {
        self.capabilities.can_write_workspace()
    }

    pub fn can_admin_workspace(&self) -> bool {
        self.capabilities.can_admin_workspace()
    }

    pub fn can_read_audit(&self) -> bool {
        self.capabilities.can_read_audit()
    }

    // Special authority predicates

    pub fn can_override_block(&self) -> bool {
        self.capabilities.can_override_block()
    }

    pub fn can_review_rights(&self) -> bool {
        self.capabilities.can_review_rights()
    }

    pub fn can_activate_rule(&self) -> bool {
        self.capabilities.can_activate_rule()
    }

    pub fn can_grant_authority(&self) -> bool {
        self.capabilities.can_grant_authority()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_authorized_workspace_context_resolution_and_predicates() {
        let p_id = PrincipalId::new();
        let org_id = OrganizationId::new();
        let prog_id = ProgramId::new();
        let ws_id = WorkspaceId::new();
        let now = Utc::now();

        // 1. Reader role with no extra grants
        let ctx = AuthorizedWorkspaceContext::resolve(
            p_id,
            org_id,
            prog_id,
            ws_id,
            MembershipRole::Reader,
            vec![],
            now,
        );

        assert_eq!(ctx.principal_id(), p_id);
        assert_eq!(ctx.organization_id(), org_id);
        assert_eq!(ctx.program_id(), prog_id);
        assert_eq!(ctx.workspace_id(), ws_id);
        assert_eq!(ctx.membership_role(), MembershipRole::Reader);

        assert!(ctx.can_read_workspace());
        assert!(!ctx.can_write_workspace());
        assert!(!ctx.can_admin_workspace());
        assert!(!ctx.can_read_audit());
        assert!(!ctx.can_override_block());

        assert!(ctx.require(&Capability::WorkspaceRead).is_ok());
        assert!(ctx.require(&Capability::WorkspaceWrite).is_err());
    }

    #[test]
    fn test_authorized_workspace_context_with_grants() {
        let p_id = PrincipalId::new();
        let org_id = OrganizationId::new();
        let prog_id = ProgramId::new();
        let ws_id = WorkspaceId::new();
        let now = Utc::now();

        // Active grant for OVERRIDE_BLOCK (workspace-scoped)
        let active_grant = CapabilityGrant::new(
            ws_id,
            p_id,
            Capability::OverrideBlock,
            None,
            Some(now + Duration::hours(1)),
        )
        .unwrap();

        // Expired grant for RIGHTS_REVIEW
        let expired_grant = CapabilityGrant::reconstruct(
            crate::capability::CapabilityGrantId::new(),
            Some(ws_id),
            None,
            p_id,
            Capability::RightsReview,
            None,
            now - Duration::hours(2),
            Some(now - Duration::hours(1)),
            None,
            None,
            None,
        );

        // Grant for a different workspace
        let other_ws_grant = CapabilityGrant::new(
            WorkspaceId::new(),
            p_id,
            Capability::RuleActivation,
            None,
            Some(now + Duration::hours(1)),
        )
        .unwrap();

        // Program-scoped grant for RULE_ACTIVATION
        let prog_grant = CapabilityGrant::new_program_grant(
            prog_id,
            p_id,
            Capability::RuleActivation,
            None,
            Some(now + Duration::hours(1)),
        )
        .unwrap();

        let ctx = AuthorizedWorkspaceContext::resolve(
            p_id,
            org_id,
            prog_id,
            ws_id,
            MembershipRole::Operator,
            vec![active_grant, expired_grant, other_ws_grant, prog_grant],
            now,
        );

        assert!(ctx.can_read_workspace());
        assert!(ctx.can_write_workspace());
        assert!(ctx.can_override_block());
        assert!(ctx.can_activate_rule(), "Program grant must resolve");
        assert!(!ctx.can_review_rights(), "Expired grant must not resolve");
        assert_eq!(ctx.active_grants().len(), 2);
    }
}
