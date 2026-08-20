//! Comprehensive capability matrix tests for roles, grants, and predicates.
//!
//! Validates:
//! 1. Base capability matrix for all 5 membership roles against all standard capabilities and special authorities.
//! 2. Dynamic capability grant additions extending base role profiles.
//! 3. Expired and revoked grants never granting permissions.
//! 4. Cross-principal and cross-workspace grant isolation.
//! 5. Policy engine evaluation across all combination predicates.

use chrono::{Duration, Utc};
use w014_authz::authority::SpecialAuthority;
use w014_authz::authorized_workspace_context::AuthorizedWorkspaceContext;
use w014_authz::capability::Capability;
use w014_authz::grant::CapabilityGrant;
use w014_authz::policy::{Decision, PolicyRule};
use w014_authz::role_profile::RoleProfile;
use w014_domain::ids::{OrganizationId, PrincipalId, ProgramId, WorkspaceId};
use w014_domain::membership::MembershipRole;

#[test]
fn test_base_role_capability_matrix() {
    let roles = [
        MembershipRole::Admin,
        MembershipRole::Operator,
        MembershipRole::Reviewer,
        MembershipRole::Reader,
    ];

    // Standard capabilities
    let ws_admin = Capability::WorkspaceAdmin;
    let ws_read = Capability::WorkspaceRead;
    let ws_write = Capability::WorkspaceWrite;
    let audit_read = Capability::AuditRead;

    // Special authorities
    let override_block = Capability::OverrideBlock;
    let rights_review = Capability::RightsReview;
    let rule_activation = Capability::RuleActivation;
    let grant_authority = Capability::GrantAuthority;

    // Custom named
    let custom = Capability::Named("CUSTOM:OP".to_string());

    for role in roles {
        let caps = RoleProfile::base_capabilities(role);

        // Special authorities MUST BE DENIED for ALL roles by default
        assert!(
            !caps.contains(&override_block),
            "Role {:?} had OVERRIDE_BLOCK",
            role
        );
        assert!(
            !caps.contains(&rights_review),
            "Role {:?} had RIGHTS_REVIEW",
            role
        );
        assert!(
            !caps.contains(&rule_activation),
            "Role {:?} had RULE_ACTIVATION",
            role
        );
        assert!(
            !caps.contains(&grant_authority),
            "Role {:?} had GRANT_AUTHORITY",
            role
        );
        assert!(
            !caps.contains(&custom),
            "Role {:?} had custom capability",
            role
        );

        match role {
            MembershipRole::Admin => {
                assert!(caps.contains(&ws_admin));
                assert!(caps.contains(&ws_read));
                assert!(caps.contains(&ws_write));
                assert!(caps.contains(&audit_read));
            }
            MembershipRole::Operator => {
                assert!(!caps.contains(&ws_admin));
                assert!(caps.contains(&ws_read));
                assert!(caps.contains(&ws_write));
                assert!(!caps.contains(&audit_read));
            }
            MembershipRole::Reviewer => {
                assert!(!caps.contains(&ws_admin));
                assert!(caps.contains(&ws_read));
                assert!(!caps.contains(&ws_write));
                assert!(caps.contains(&audit_read));
            }
            MembershipRole::Reader => {
                assert!(!caps.contains(&ws_admin));
                assert!(caps.contains(&ws_read));
                assert!(!caps.contains(&ws_write));
                assert!(!caps.contains(&audit_read));
            }
        }
    }
}

#[test]
fn test_matrix_with_dynamic_grants() {
    let p_id = PrincipalId::new();
    let org_id = OrganizationId::new();
    let prog_id = ProgramId::new();
    let ws_id = WorkspaceId::new();
    let now = Utc::now();

    // 1. Reader with explicit WorkspaceWrite grant
    let grant_write = CapabilityGrant::new(
        ws_id,
        p_id,
        Capability::WorkspaceWrite,
        None,
        Some(now + Duration::hours(1)),
    )
    .unwrap();

    let ctx = AuthorizedWorkspaceContext::resolve(
        p_id,
        org_id,
        prog_id,
        ws_id,
        MembershipRole::Reader,
        vec![grant_write],
        now,
    );

    assert!(ctx.can_read_workspace());
    assert!(ctx.can_write_workspace()); // granted
    assert!(!ctx.can_admin_workspace()); // not granted
    assert!(!ctx.can_read_audit()); // not granted

    // 2. Operator with explicit AuditRead grant
    let grant_audit = CapabilityGrant::new(
        ws_id,
        p_id,
        Capability::AuditRead,
        None,
        Some(now + Duration::hours(1)),
    )
    .unwrap();

    let ctx2 = AuthorizedWorkspaceContext::resolve(
        p_id,
        org_id,
        prog_id,
        ws_id,
        MembershipRole::Operator,
        vec![grant_audit],
        now,
    );

    assert!(ctx2.can_read_workspace());
    assert!(ctx2.can_write_workspace());
    assert!(ctx2.can_read_audit()); // granted
    assert!(!ctx2.can_admin_workspace());

    // 3. Reviewer with custom named capability grant
    let custom_cap = Capability::Named("REPORTS:EXPORT".to_string());
    let grant_custom = CapabilityGrant::new(
        ws_id,
        p_id,
        custom_cap.clone(),
        None,
        Some(now + Duration::hours(1)),
    )
    .unwrap();

    let ctx3 = AuthorizedWorkspaceContext::resolve(
        p_id,
        org_id,
        prog_id,
        ws_id,
        MembershipRole::Reviewer,
        vec![grant_custom],
        now,
    );

    assert!(ctx3.can_read_workspace());
    assert!(ctx3.can_read_audit());
    assert!(!ctx3.can_write_workspace());
    assert!(ctx3.can(&custom_cap));
}

#[test]
fn test_matrix_expired_and_revoked_grants_deny() {
    let p_id = PrincipalId::new();
    let org_id = OrganizationId::new();
    let prog_id = ProgramId::new();
    let ws_id = WorkspaceId::new();
    let now = Utc::now();

    // Expired grant
    let expired_grant = CapabilityGrant::reconstruct(
        w014_authz::CapabilityGrantId::new(),
        Some(ws_id),
        None,
        p_id,
        Capability::WorkspaceWrite,
        None,
        now - Duration::hours(3),
        Some(now - Duration::hours(1)),
        None,
        None,
        None,
    );

    let ctx = AuthorizedWorkspaceContext::resolve(
        p_id,
        org_id,
        prog_id,
        ws_id,
        MembershipRole::Reader,
        vec![expired_grant],
        now,
    );

    assert!(ctx.can_read_workspace());
    assert!(
        !ctx.can_write_workspace(),
        "Expired grant must not grant capability"
    );

    // Revoked grant (expiry set to past upon revocation)
    let mut revoked_grant = CapabilityGrant::new(
        ws_id,
        p_id,
        Capability::AuditRead,
        None,
        Some(now + Duration::hours(2)),
    )
    .unwrap();
    revoked_grant
        .revoke(now - Duration::minutes(5), None, None)
        .unwrap();

    let ctx2 = AuthorizedWorkspaceContext::resolve(
        p_id,
        org_id,
        prog_id,
        ws_id,
        MembershipRole::Operator,
        vec![revoked_grant],
        now,
    );

    assert!(
        !ctx2.can_read_audit(),
        "Revoked grant must not grant capability"
    );
}

#[test]
fn test_matrix_cross_workspace_and_principal_isolation() {
    let p1 = PrincipalId::new();
    let p2 = PrincipalId::new();
    let org_id = OrganizationId::new();
    let prog_id = ProgramId::new();
    let ws1 = WorkspaceId::new();
    let ws2 = WorkspaceId::new();
    let now = Utc::now();

    // Grant belonging to ws2, p1
    let grant_ws2 = CapabilityGrant::new(
        ws2,
        p1,
        Capability::WorkspaceWrite,
        None,
        Some(now + Duration::hours(1)),
    )
    .unwrap();

    // Grant belonging to ws1, p2
    let grant_p2 = CapabilityGrant::new(
        ws1,
        p2,
        Capability::WorkspaceAdmin,
        None,
        Some(now + Duration::hours(1)),
    )
    .unwrap();

    // Resolving for ws1, p1 with both foreign grants
    let ctx = AuthorizedWorkspaceContext::resolve(
        p1,
        org_id,
        prog_id,
        ws1,
        MembershipRole::Reader,
        vec![grant_ws2, grant_p2],
        now,
    );

    assert!(ctx.can_read_workspace());
    assert!(
        !ctx.can_write_workspace(),
        "Foreign workspace grant must be rejected"
    );
    assert!(
        !ctx.can_admin_workspace(),
        "Foreign principal grant must be rejected"
    );
    assert_eq!(ctx.active_grants().len(), 0);
}

#[test]
fn test_matrix_policy_rule_combinations() {
    let p_id = PrincipalId::new();
    let org_id = OrganizationId::new();
    let prog_id = ProgramId::new();
    let ws_id = WorkspaceId::new();
    let now = Utc::now();

    let ctx = AuthorizedWorkspaceContext::resolve(
        p_id,
        org_id,
        prog_id,
        ws_id,
        MembershipRole::Operator, // has Read, Write
        vec![],
        now,
    );

    // Require all
    let rule_read_write =
        PolicyRule::require_all(vec![Capability::WorkspaceRead, Capability::WorkspaceWrite]);
    assert_eq!(ctx.evaluate(&rule_read_write), Decision::Allow);

    let rule_read_admin =
        PolicyRule::require_all(vec![Capability::WorkspaceRead, Capability::WorkspaceAdmin]);
    assert!(ctx.evaluate(&rule_read_admin).is_denied());

    // Require any
    let rule_any_admin_or_read =
        PolicyRule::require_any(vec![Capability::WorkspaceAdmin, Capability::WorkspaceRead]);
    assert_eq!(ctx.evaluate(&rule_any_admin_or_read), Decision::Allow);

    let rule_any_admin_or_audit =
        PolicyRule::require_any(vec![Capability::WorkspaceAdmin, Capability::AuditRead]);
    assert!(ctx.evaluate(&rule_any_admin_or_audit).is_denied());

    // Require special authority
    let rule_special = PolicyRule::require_special(SpecialAuthority::OverrideBlock);
    assert!(ctx.evaluate(&rule_special).is_denied());
}
