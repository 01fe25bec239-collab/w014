//! Invariant tests proving frozen special authority separation.
//!
//! Frozen Authorities:
//! - OVERRIDE_BLOCK
//! - RIGHTS_REVIEW
//! - RULE_ACTIVATION
//! - GRANT_AUTHORITY
//!
//! Core Invariants:
//! 1. Roles (including Owner and Admin) NEVER automatically grant any special authority.
//! 2. Each special authority is completely orthogonal and independent of the other three.
//! 3. Special authorities require explicit, active CapabilityGrants.
//! 4. Expired or revoked special authority grants immediately fail closed.

use chrono::{Duration, Utc};
use w014_authz::authority::SpecialAuthority;
use w014_authz::authorized_workspace_context::AuthorizedWorkspaceContext;
use w014_authz::capability::Capability;
use w014_authz::error::AuthzError;
use w014_authz::grant::CapabilityGrant;
use w014_domain::ids::{OrganizationId, PrincipalId, ProgramId, WorkspaceId};
use w014_domain::membership::MembershipRole;

#[test]
fn test_admin_and_owner_do_not_have_special_authorities_by_default() {
    let p_id = PrincipalId::new();
    let org_id = OrganizationId::new();
    let prog_id = ProgramId::new();
    let ws_id = WorkspaceId::new();
    let now = Utc::now();

    for &role in &[MembershipRole::Owner, MembershipRole::Admin] {
        let ctx =
            AuthorizedWorkspaceContext::resolve(p_id, org_id, prog_id, ws_id, role, vec![], now);

        // Standard capabilities should be present
        assert!(ctx.can_admin_workspace());
        assert!(ctx.can_read_workspace());
        assert!(ctx.can_write_workspace());
        assert!(ctx.can_read_audit());

        // ALL four special authorities must be absent
        assert!(
            !ctx.can_override_block(),
            "{:?} had OVERRIDE_BLOCK by default",
            role
        );
        assert!(
            !ctx.can_review_rights(),
            "{:?} had RIGHTS_REVIEW by default",
            role
        );
        assert!(
            !ctx.can_activate_rule(),
            "{:?} had RULE_ACTIVATION by default",
            role
        );
        assert!(
            !ctx.can_grant_authority(),
            "{:?} had GRANT_AUTHORITY by default",
            role
        );

        // Require checks must fail closed
        assert!(matches!(
            ctx.require_special_authority(SpecialAuthority::OverrideBlock),
            Err(AuthzError::SpecialAuthorityDenied(_))
        ));
        assert!(matches!(
            ctx.require_special_authority(SpecialAuthority::RightsReview),
            Err(AuthzError::SpecialAuthorityDenied(_))
        ));
        assert!(matches!(
            ctx.require_special_authority(SpecialAuthority::RuleActivation),
            Err(AuthzError::SpecialAuthorityDenied(_))
        ));
        assert!(matches!(
            ctx.require_special_authority(SpecialAuthority::GrantAuthority),
            Err(AuthzError::SpecialAuthorityDenied(_))
        ));
    }
}

#[test]
fn test_special_authorities_are_mutually_orthogonal() {
    let p_id = PrincipalId::new();
    let org_id = OrganizationId::new();
    let prog_id = ProgramId::new();
    let ws_id = WorkspaceId::new();
    let now = Utc::now();

    let special_auths = [
        (SpecialAuthority::OverrideBlock, Capability::OverrideBlock),
        (SpecialAuthority::RightsReview, Capability::RightsReview),
        (SpecialAuthority::RuleActivation, Capability::RuleActivation),
        (SpecialAuthority::GrantAuthority, Capability::GrantAuthority),
    ];

    for (target_auth, target_cap) in &special_auths {
        let grant = CapabilityGrant::new(
            ws_id,
            p_id,
            target_cap.clone(),
            None,
            Some(now + Duration::hours(1)),
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

        // Target special authority must be granted
        assert!(ctx.has_special_authority(*target_auth));
        assert!(ctx.require_special_authority(*target_auth).is_ok());

        // ALL other special authorities must remain denied
        for (other_auth, _) in &special_auths {
            if other_auth != target_auth {
                assert!(
                    !ctx.has_special_authority(*other_auth),
                    "Granting {:?} accidentally granted {:?}",
                    target_auth,
                    other_auth
                );
                assert!(
                    ctx.require_special_authority(*other_auth).is_err(),
                    "Require check for {:?} did not fail when only {:?} was granted",
                    other_auth,
                    target_auth
                );
            }
        }
    }
}

#[test]
fn test_special_authority_expiry_and_revocation_lifecycle() {
    let p_id = PrincipalId::new();
    let org_id = OrganizationId::new();
    let prog_id = ProgramId::new();
    let ws_id = WorkspaceId::new();
    let now = Utc::now();

    let mut grant = CapabilityGrant::new(
        ws_id,
        p_id,
        Capability::OverrideBlock,
        None,
        Some(now + Duration::hours(2)),
    )
    .unwrap();

    // 1. Active at `now`
    let ctx_active = AuthorizedWorkspaceContext::resolve(
        p_id,
        org_id,
        prog_id,
        ws_id,
        MembershipRole::Admin,
        vec![grant.clone()],
        now,
    );
    assert!(ctx_active.can_override_block());
    assert!(
        ctx_active
            .require_special_authority(SpecialAuthority::OverrideBlock)
            .is_ok()
    );

    // 2. Evaluated after expiry
    let ctx_expired = AuthorizedWorkspaceContext::resolve(
        p_id,
        org_id,
        prog_id,
        ws_id,
        MembershipRole::Admin,
        vec![grant.clone()],
        now + Duration::hours(3),
    );
    assert!(!ctx_expired.can_override_block());
    assert!(
        ctx_expired
            .require_special_authority(SpecialAuthority::OverrideBlock)
            .is_err()
    );

    // 3. Revoked grant evaluated after revocation time
    grant.revoke(now + Duration::minutes(30)).unwrap();
    let ctx_revoked = AuthorizedWorkspaceContext::resolve(
        p_id,
        org_id,
        prog_id,
        ws_id,
        MembershipRole::Admin,
        vec![grant],
        now + Duration::hours(1),
    );
    assert!(!ctx_revoked.can_override_block());
    assert!(
        ctx_revoked
            .require_special_authority(SpecialAuthority::OverrideBlock)
            .is_err()
    );
}
