//! Unit tests for capability grant representations and invariants in w014-authz.

use chrono::{Duration, Utc};
use w014_authz::capability::Capability;
use w014_authz::error::AuthzError;
use w014_authz::grant::CapabilityGrant;
use w014_domain::ids::{PrincipalId, WorkspaceId};

#[test]
fn test_special_authorities_are_distinct_and_independent() {
    let override_block = Capability::OverrideBlock;
    let rights_review = Capability::RightsReview;
    let rule_activation = Capability::RuleActivation;
    let grant_authority = Capability::GrantAuthority;

    assert_eq!(override_block.as_str(), "OVERRIDE_BLOCK");
    assert_eq!(rights_review.as_str(), "RIGHTS_REVIEW");
    assert_eq!(rule_activation.as_str(), "RULE_ACTIVATION");
    assert_eq!(grant_authority.as_str(), "GRANT_AUTHORITY");

    assert!(override_block.is_special_authority());
    assert!(rights_review.is_special_authority());
    assert!(rule_activation.is_special_authority());
    assert!(grant_authority.is_special_authority());

    assert_ne!(override_block, rights_review);
    assert_ne!(override_block, rule_activation);
    assert_ne!(override_block, grant_authority);
    assert_ne!(rights_review, rule_activation);
    assert_ne!(rights_review, grant_authority);
    assert_ne!(rule_activation, grant_authority);
}

#[test]
fn test_standard_workspace_capabilities() {
    assert_eq!(Capability::WorkspaceAdmin.as_str(), "WORKSPACE_ADMIN");
    assert_eq!(Capability::WorkspaceRead.as_str(), "WORKSPACE_READ");
    assert_eq!(Capability::WorkspaceWrite.as_str(), "WORKSPACE_WRITE");
    assert_eq!(Capability::AuditRead.as_str(), "AUDIT_READ");

    assert!(!Capability::WorkspaceAdmin.is_special_authority());
    assert!(!Capability::WorkspaceRead.is_special_authority());
    assert!(!Capability::WorkspaceWrite.is_special_authority());
    assert!(!Capability::AuditRead.is_special_authority());
}

#[test]
fn test_capability_grant_lifecycle_and_one_way_revocation() {
    let ws_id = WorkspaceId::new();
    let p_id = PrincipalId::new();
    let grantor = PrincipalId::new();
    let now = Utc::now();
    let future_exp = now + Duration::hours(4);

    let mut grant = CapabilityGrant::new(
        ws_id,
        p_id,
        Capability::RightsReview,
        Some(grantor),
        Some(future_exp),
    )
    .unwrap();

    assert_eq!(grant.workspace_id, Some(ws_id));
    assert_eq!(grant.program_id, None);
    assert_eq!(grant.principal_id, p_id);
    assert_eq!(grant.capability, Capability::RightsReview);
    assert_eq!(grant.granted_by, Some(grantor));
    assert!(grant.is_active_at(now));
    assert!(!grant.is_expired_at(now));

    // One-way revocation
    let revoke_time = now + Duration::minutes(30);
    grant.revoke(revoke_time, None, None).unwrap();
    assert!(grant.is_active_at(now + Duration::minutes(10)));
    assert!(!grant.is_active_at(revoke_time + Duration::seconds(1)));
    assert!(grant.is_expired_at(revoke_time + Duration::seconds(1)));

    // Second revocation attempt fails
    let err = grant
        .revoke(revoke_time + Duration::minutes(10), None, None)
        .unwrap_err();
    assert_eq!(err, AuthzError::AlreadyRevoked(grant.id.to_string()));
}
