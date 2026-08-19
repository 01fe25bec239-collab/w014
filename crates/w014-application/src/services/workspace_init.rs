//! Workspace Initialization Service.
//!
//! Orchestrates the creation of organizations, programs, workspaces, and memberships
//! atomically with authoritative audit chain head initialization and genesis audit events.

use sqlx::PgConnection;
use w014_domain::ids::{OrganizationId, PrincipalId, ProgramId, WorkspaceId};
use w014_domain::membership::{Membership, MembershipRole};
use w014_domain::organization::Organization;
use w014_domain::principal::{Principal, PrincipalType};
use w014_domain::program::Program;
use w014_domain::workspace::Workspace;
use w014_persistence::audit::{AppendAuditParams, AuditAppendContract};

use crate::error::ApplicationError;
use crate::persistence::{
    MembershipRepository, OrganizationRepository, PrincipalRepository, ProgramRepository,
    WorkspaceRepository,
};

/// Service orchestrating tenant, workspace, and audit chain initialization.
pub struct WorkspaceInitializationService;

impl WorkspaceInitializationService {
    /// Creates an organization entity.
    pub async fn create_organization(
        tx: &mut PgConnection,
        name: impl AsRef<str>,
        slug: impl AsRef<str>,
    ) -> Result<Organization, ApplicationError> {
        let org = Organization::new(name, slug)?;
        OrganizationRepository::insert(tx, &org).await?;
        Ok(org)
    }

    /// Creates a principal within an organization.
    pub async fn create_principal(
        tx: &mut PgConnection,
        organization_id: OrganizationId,
        principal_type: PrincipalType,
        email: Option<impl AsRef<str>>,
        display_name: impl AsRef<str>,
    ) -> Result<Principal, ApplicationError> {
        let principal = Principal::new(organization_id, principal_type, email, display_name)?;
        PrincipalRepository::insert(tx, &principal).await?;
        Ok(principal)
    }

    /// Creates a program within an organization.
    pub async fn create_program(
        tx: &mut PgConnection,
        organization_id: OrganizationId,
        name: impl AsRef<str>,
        slug: impl AsRef<str>,
        description: Option<impl AsRef<str>>,
    ) -> Result<Program, ApplicationError> {
        let program = Program::new(organization_id, name, slug, description)?;
        ProgramRepository::insert(tx, &program).await?;
        Ok(program)
    }

    /// Atomically creates a workspace and initializes its authoritative audit chain head.
    ///
    /// Preserves:
    /// - Tenant/Program/Workspace relationships.
    /// - Explicit chain head initialization via `AuditAppendContract::initialize_chain_head`.
    /// - Authoritative audit event append for `workspace.created`.
    /// - Strict single-transaction atomicity (audit failure rolls back entire workspace creation).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_workspace_with_audit_head(
        tx: &mut PgConnection,
        audit_store: &impl AuditAppendContract,
        program_id: ProgramId,
        organization_id: OrganizationId,
        name: impl AsRef<str>,
        slug: impl AsRef<str>,
        actor_principal_id: Option<PrincipalId>,
        correlation_id: Option<String>,
    ) -> Result<Workspace, ApplicationError> {
        let ws = Workspace::new(program_id, organization_id, name, slug)?;

        // 1. Insert workspace record
        WorkspaceRepository::insert(tx, &ws).await?;

        // 2. Initialize audit chain head
        audit_store
            .initialize_chain_head(tx, ws.id.as_uuid())
            .await?;

        // 3. Append workspace creation audit event atomically
        let audit_payload = serde_json::json!({
            "workspace_id": ws.id.to_string(),
            "program_id": ws.program_id.to_string(),
            "organization_id": ws.organization_id.to_string(),
            "name": ws.name,
            "slug": ws.slug,
        });

        let audit_params = AppendAuditParams {
            workspace_id: ws.id.into_uuid(),
            event_type: "workspace.created".to_string(),
            actor_principal_id: actor_principal_id.map(|p| p.into_uuid()),
            action: "create".to_string(),
            resource_type: "workspace".to_string(),
            resource_id: ws.id.to_string(),
            payload: audit_payload,
            correlation_id,
        };

        audit_store.append_audit_event(tx, audit_params).await?;

        Ok(ws)
    }

    /// Atomically assigns a principal as a workspace owner and logs the audit event.
    pub async fn assign_workspace_owner_with_audit(
        tx: &mut PgConnection,
        audit_store: &impl AuditAppendContract,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        actor_principal_id: Option<PrincipalId>,
        correlation_id: Option<String>,
    ) -> Result<Membership, ApplicationError> {
        let membership = Membership::new(workspace_id, principal_id, MembershipRole::Owner);
        MembershipRepository::insert(tx, &membership).await?;

        let audit_payload = serde_json::json!({
            "membership_id": membership.id.to_string(),
            "workspace_id": workspace_id.to_string(),
            "principal_id": principal_id.to_string(),
            "role": "owner",
        });

        let audit_params = AppendAuditParams {
            workspace_id: workspace_id.into_uuid(),
            event_type: "membership.created".to_string(),
            actor_principal_id: actor_principal_id.map(|p| p.into_uuid()),
            action: "create".to_string(),
            resource_type: "membership".to_string(),
            resource_id: membership.id.to_string(),
            payload: audit_payload,
            correlation_id,
        };

        audit_store.append_audit_event(tx, audit_params).await?;

        Ok(membership)
    }
}
