//! Comprehensive integration and invariant tests for AuthorizedWorkspaceContext.

use chrono::{Duration, Utc};
use w014_authz::authority::SpecialAuthority;
use w014_authz::authorized_workspace_context::AuthorizedWorkspaceContext;
use w014_authz::capability::Capability;
use w014_authz::error::AuthzError;
use w014_authz::grant::CapabilityGrant;
use w014_authz::policy::{Decision, PolicyRule};
use w014_domain::ids::{OrganizationId, PrincipalId, ProgramId, WorkspaceId};
use w014_domain::membership::MembershipRole;

#[test]
fn test_context_construction_and_accessors() {
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
        MembershipRole::Admin,
        vec![],
        now,
    );

    assert_eq!(ctx.principal_id(), p_id);
    assert_eq!(ctx.organization_id(), org_id);
    assert_eq!(ctx.program_id(), prog_id);
    assert_eq!(ctx.workspace_id(), ws_id);
    assert_eq!(ctx.membership_role(), MembershipRole::Admin);
    assert_eq!(ctx.evaluated_at(), now);
    assert_eq!(ctx.active_grants().len(), 0);

    assert!(ctx.can_admin_workspace());
    assert!(ctx.can_read_workspace());
    assert!(ctx.can_write_workspace());
    assert!(ctx.can_read_audit());
}

#[test]
fn test_context_fail_closed_checks() {
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
        MembershipRole::Viewer,
        vec![],
        now,
    );

    // can checks
    assert!(ctx.can(&Capability::WorkspaceRead));
    assert!(!ctx.can(&Capability::WorkspaceWrite));
    assert!(!ctx.can(&Capability::WorkspaceAdmin));
    assert!(!ctx.can(&Capability::AuditRead));

    // can_all
    assert!(ctx.can_all(&[Capability::WorkspaceRead]));
    assert!(!ctx.can_all(&[Capability::WorkspaceRead, Capability::WorkspaceWrite]));

    // can_any
    assert!(ctx.can_any(&[Capability::WorkspaceRead, Capability::WorkspaceWrite]));
    assert!(!ctx.can_any(&[Capability::WorkspaceWrite, Capability::WorkspaceAdmin]));

    // require checks with typed error matching
    assert!(ctx.require(&Capability::WorkspaceRead).is_ok());

    let write_err = ctx.require(&Capability::WorkspaceWrite).unwrap_err();
    assert_eq!(
        write_err,
        AuthzError::PermissionDenied("WORKSPACE_WRITE".to_string())
    );

    let all_err = ctx
        .require_all(&[Capability::WorkspaceRead, Capability::WorkspaceWrite])
        .unwrap_err();
    assert_eq!(
        all_err,
        AuthzError::MissingAllCapabilities(vec!["WORKSPACE_WRITE".to_string()])
    );

    let any_err = ctx
        .require_any(&[Capability::WorkspaceAdmin, Capability::AuditRead])
        .unwrap_err();
    assert_eq!(
        any_err,
        AuthzError::MissingAnyCapability(vec![
            "WORKSPACE_ADMIN".to_string(),
            "AUDIT_READ".to_string()
        ])
    );
}

#[test]
fn test_context_grant_filtering_invariants() {
    let p1 = PrincipalId::new();
    let p2 = PrincipalId::new();
    let org_id = OrganizationId::new();
    let prog_id = ProgramId::new();
    let ws1 = WorkspaceId::new();
    let ws2 = WorkspaceId::new();
    let now = Utc::now();

    // 1. Valid grant for (ws1, p1)
    let grant_valid = CapabilityGrant::new(
        ws1,
        p1,
        Capability::AuditRead,
        None,
        Some(now + Duration::hours(1)),
    )
    .unwrap();

    // 2. Grant for wrong workspace (ws2, p1)
    let grant_wrong_ws = CapabilityGrant::new(
        ws2,
        p1,
        Capability::WorkspaceAdmin,
        None,
        Some(now + Duration::hours(1)),
    )
    .unwrap();

    // 3. Grant for wrong principal (ws1, p2)
    let grant_wrong_p = CapabilityGrant::new(
        ws1,
        p2,
        Capability::OverrideBlock,
        None,
        Some(now + Duration::hours(1)),
    )
    .unwrap();

    // 4. Expired grant for (ws1, p1)
    let grant_expired = CapabilityGrant::reconstruct(
        w014_authz::CapabilityGrantId::new(),
        ws1,
        p1,
        Capability::RightsReview,
        None,
        now - Duration::hours(2),
        Some(now - Duration::minutes(10)),
    );

    let ctx = AuthorizedWorkspaceContext::resolve(
        p1,
        org_id,
        prog_id,
        ws1,
        MembershipRole::Viewer,
        vec![grant_valid, grant_wrong_ws, grant_wrong_p, grant_expired],
        now,
    );

    // Only grant_valid should be included
    assert_eq!(ctx.active_grants().len(), 1);
    assert_eq!(ctx.active_grants()[0].capability, Capability::AuditRead);

    assert!(ctx.can_read_workspace()); // Viewer base
    assert!(ctx.can_read_audit()); // from grant_valid
    assert!(!ctx.can_admin_workspace()); // grant_wrong_ws ignored
    assert!(!ctx.can_override_block()); // grant_wrong_p ignored
    assert!(!ctx.can_review_rights()); // grant_expired ignored
}

#[test]
fn test_context_serde_roundtrip() {
    let p_id = PrincipalId::new();
    let org_id = OrganizationId::new();
    let prog_id = ProgramId::new();
    let ws_id = WorkspaceId::new();
    let now = Utc::now();

    let grant = CapabilityGrant::new(
        ws_id,
        p_id,
        Capability::OverrideBlock,
        None,
        Some(now + Duration::hours(2)),
    )
    .unwrap();

    let ctx = AuthorizedWorkspaceContext::resolve(
        p_id,
        org_id,
        prog_id,
        ws_id,
        MembershipRole::Member,
        vec![grant],
        now,
    );

    let json = serde_json::to_string(&ctx).unwrap();
    let deserialized: AuthorizedWorkspaceContext = serde_json::from_str(&json).unwrap();

    assert_eq!(ctx, deserialized);
    assert!(deserialized.can_read_workspace());
    assert!(deserialized.can_write_workspace());
    assert!(deserialized.can_override_block());
}

#[test]
fn test_context_policy_rule_evaluation() {
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
        MembershipRole::Member,
        vec![],
        now,
    );

    let rule_require_special = PolicyRule::require_special(SpecialAuthority::RuleActivation);
    assert_eq!(
        ctx.evaluate(&rule_require_special),
        Decision::Deny(w014_authz::policy::DenyReason::MissingSpecialAuthority(
            SpecialAuthority::RuleActivation
        ))
    );
}
