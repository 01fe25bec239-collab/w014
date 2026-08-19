//! Unit tests for domain models, typed IDs, and business invariants in w014-domain.

use w014_domain::error::DomainError;
use w014_domain::ids::{MembershipId, OrganizationId, PrincipalId, ProgramId, WorkspaceId};
use w014_domain::membership::{Membership, MembershipRole};
use w014_domain::organization::Organization;
use w014_domain::principal::{Principal, PrincipalType};
use w014_domain::program::Program;
use w014_domain::workspace::Workspace;

#[test]
fn test_typed_identifiers_invariants() {
    let org_id = OrganizationId::new();
    let principal_id = PrincipalId::new();
    let program_id = ProgramId::new();
    let workspace_id = WorkspaceId::new();
    let membership_id = MembershipId::new();

    assert_eq!(org_id, OrganizationId::from_uuid(org_id.as_uuid()));
    assert_eq!(
        principal_id,
        PrincipalId::from_uuid(principal_id.into_uuid())
    );
    assert_eq!(program_id, ProgramId::from_uuid(*program_id));
    assert_eq!(workspace_id, WorkspaceId::from_uuid(workspace_id.as_uuid()));
    assert_eq!(
        membership_id,
        MembershipId::from_uuid(membership_id.as_uuid())
    );

    assert_eq!(OrganizationId::nil().as_uuid(), uuid::Uuid::nil());
}

#[test]
fn test_organization_invariants() {
    // Valid organization creation
    let org = Organization::new("Acme Corporation", "acme-corp").unwrap();
    assert_eq!(org.name, "Acme Corporation");
    assert_eq!(org.slug, "acme-corp");

    // Whitespace trimming
    let org_trimmed = Organization::new("  Trimmed Org  ", "trimmed-org").unwrap();
    assert_eq!(org_trimmed.name, "Trimmed Org");

    // Empty name rejected
    let empty_name_err = Organization::new("   ", "valid-slug").unwrap_err();
    assert_eq!(empty_name_err, DomainError::EmptyField("name"));

    // Empty slug rejected
    let empty_slug_err = Organization::new("Valid Name", "   ").unwrap_err();
    assert_eq!(empty_slug_err, DomainError::EmptyField("slug"));

    // Invalid slug character set rejected
    let invalid_slug_err = Organization::new("Valid Name", "Invalid Slug!").unwrap_err();
    assert_eq!(
        invalid_slug_err,
        DomainError::InvalidSlug("Invalid Slug!".to_string())
    );
}

#[test]
fn test_principal_invariants() {
    let org_id = OrganizationId::new();

    // Valid principal creation
    let principal = Principal::new(
        org_id,
        PrincipalType::User,
        Some("user@acme.com"),
        "Jane Doe",
    )
    .unwrap();

    assert_eq!(principal.organization_id, org_id);
    assert_eq!(principal.principal_type, PrincipalType::User);
    assert_eq!(principal.email.as_deref(), Some("user@acme.com"));
    assert_eq!(principal.display_name, "Jane Doe");
    assert!(principal.is_active);

    // Empty display name rejected
    let empty_name_err =
        Principal::new(org_id, PrincipalType::User, None::<&str>, "   ").unwrap_err();
    assert_eq!(empty_name_err, DomainError::EmptyField("display_name"));

    // Principal type string parsing
    assert_eq!(
        "user".parse::<PrincipalType>().unwrap(),
        PrincipalType::User
    );
    assert_eq!(
        "service".parse::<PrincipalType>().unwrap(),
        PrincipalType::Service
    );
    assert_eq!(
        "system".parse::<PrincipalType>().unwrap(),
        PrincipalType::System
    );
    assert!("invalid".parse::<PrincipalType>().is_err());

    // Lifecycle transitions
    let mut p = principal;
    p.deactivate();
    assert!(!p.is_active);
    p.activate();
    assert!(p.is_active);
}

#[test]
fn test_program_and_workspace_invariants() {
    let org_id = OrganizationId::new();

    // Program creation
    let program = Program::new(
        org_id,
        "Compliance Program",
        "compliance-prog",
        Some("Audit compliance"),
    )
    .unwrap();
    assert_eq!(program.organization_id, org_id);
    assert_eq!(program.name, "Compliance Program");
    assert_eq!(program.slug, "compliance-prog");

    // Workspace creation with staged FK
    let workspace = Workspace::new(program.id, org_id, "Compliance Q1", "compliance-q1").unwrap();
    assert_eq!(workspace.program_id, program.id);
    assert_eq!(workspace.organization_id, org_id);
    assert_eq!(workspace.name, "Compliance Q1");
    assert_eq!(workspace.slug, "compliance-q1");
    // STAGED FK: current_source_state_id must be None in W1
    assert_eq!(workspace.current_source_state_id, None);
}

#[test]
fn test_membership_invariants() {
    let ws_id = WorkspaceId::new();
    let p_id = PrincipalId::new();

    let mut m = Membership::new(ws_id, p_id, MembershipRole::Viewer);
    assert_eq!(m.workspace_id, ws_id);
    assert_eq!(m.principal_id, p_id);
    assert_eq!(m.role, MembershipRole::Viewer);

    // Role transitions
    m.change_role(MembershipRole::Admin);
    assert_eq!(m.role, MembershipRole::Admin);

    // Role enum parsing
    assert_eq!(
        "owner".parse::<MembershipRole>().unwrap(),
        MembershipRole::Owner
    );
    assert_eq!(
        "admin".parse::<MembershipRole>().unwrap(),
        MembershipRole::Admin
    );
    assert_eq!(
        "member".parse::<MembershipRole>().unwrap(),
        MembershipRole::Member
    );
    assert_eq!(
        "viewer".parse::<MembershipRole>().unwrap(),
        MembershipRole::Viewer
    );
    assert_eq!(
        "auditor".parse::<MembershipRole>().unwrap(),
        MembershipRole::Auditor
    );
    assert!("superuser".parse::<MembershipRole>().is_err());
}
