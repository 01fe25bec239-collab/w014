//! Workspace Initialization Service.
//!
//! Orchestrates the creation of organizations, programs, workspaces, and memberships
//! atomically with authoritative audit chain head initialization and genesis audit events.

use sqlx::PgConnection;
use w014_domain::ids::{OrganizationId, PrincipalId, ProgramId, WorkspaceId};
use w014_domain::membership::{Membership, MembershipRole};
use w014_domain::organization::Organization;
use w014_domain::principal::Principal;
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
        display_name: impl AsRef<str>,
        slug: impl AsRef<str>,
    ) -> Result<Organization, ApplicationError> {
        let org = Organization::new(display_name, slug)?;
        OrganizationRepository::insert(tx, &org).await?;
        Ok(org)
    }

    /// Creates a principal.
    pub async fn create_principal(
        tx: &mut PgConnection,
        display_name: impl AsRef<str>,
        email: Option<impl AsRef<str>>,
    ) -> Result<Principal, ApplicationError> {
        let principal = Principal::new(display_name, email)?;
        PrincipalRepository::insert(tx, &principal).await?;
        Ok(principal)
    }

    /// Creates a program within an organization.
    pub async fn create_program(
        tx: &mut PgConnection,
        organization_id: OrganizationId,
        name: impl AsRef<str>,
        program_code: impl AsRef<str>,
    ) -> Result<Program, ApplicationError> {
        let program = Program::new(organization_id, name, program_code)?;
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
        workspace_code: impl AsRef<str>,
        actor_principal_id: Option<PrincipalId>,
        correlation_id: Option<String>,
    ) -> Result<Workspace, ApplicationError> {
        let ws = Workspace::new(program_id, organization_id, name, workspace_code)?;

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
            "workspace_code": ws.workspace_code,
            "name": ws.name,
        });

        let audit_params = AppendAuditParams {
            workspace_id: ws.id.into_uuid(),
            actor_type: if actor_principal_id.is_some() {
                "principal".to_string()
            } else {
                "system".to_string()
            },
            actor_id: actor_principal_id.map(|p| p.into_uuid()),
            authority_snapshot: serde_json::json!({}),
            action_code: "WORKSPACE_CREATE".to_string(),
            entity_type: "workspace".to_string(),
            entity_id: ws.id.to_string(),
            entity_version: Some(ws.row_version),
            request_id: None,
            correlation_id,
            job_id: None,
            source_state_hash: None,
            before_ref: None,
            after_ref: Some(audit_payload),
            metadata: serde_json::json!({}),
        };

        audit_store.append_audit_event(tx, audit_params).await?;

        Ok(ws)
    }

    /// Atomically assigns a principal as a workspace admin and logs the audit event.
    pub async fn assign_workspace_admin_with_audit(
        tx: &mut PgConnection,
        audit_store: &impl AuditAppendContract,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        actor_principal_id: Option<PrincipalId>,
        correlation_id: Option<String>,
    ) -> Result<Membership, ApplicationError> {
        let membership = Membership::new(workspace_id, principal_id, MembershipRole::Admin);
        MembershipRepository::insert(tx, &membership).await?;

        let audit_payload = serde_json::json!({
            "membership_id": membership.id.to_string(),
            "workspace_id": workspace_id.to_string(),
            "principal_id": principal_id.to_string(),
            "role": "admin",
        });

        let audit_params = AppendAuditParams {
            workspace_id: workspace_id.into_uuid(),
            actor_type: if actor_principal_id.is_some() {
                "principal".to_string()
            } else {
                "system".to_string()
            },
            actor_id: actor_principal_id.map(|p| p.into_uuid()),
            authority_snapshot: serde_json::json!({}),
            action_code: "MEMBERSHIP_CREATE".to_string(),
            entity_type: "membership".to_string(),
            entity_id: membership.id.to_string(),
            entity_version: Some(membership.row_version),
            request_id: None,
            correlation_id,
            job_id: None,
            source_state_hash: None,
            before_ref: None,
            after_ref: Some(audit_payload),
            metadata: serde_json::json!({}),
        };

        audit_store.append_audit_event(tx, audit_params).await?;

        Ok(membership)
    }

    /// Alias for backwards compatibility with test calls expecting assign_workspace_owner_with_audit
    pub async fn assign_workspace_owner_with_audit(
        tx: &mut PgConnection,
        audit_store: &impl AuditAppendContract,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        actor_principal_id: Option<PrincipalId>,
        correlation_id: Option<String>,
    ) -> Result<Membership, ApplicationError> {
        Self::assign_workspace_admin_with_audit(
            tx,
            audit_store,
            workspace_id,
            principal_id,
            actor_principal_id,
            correlation_id,
        )
        .await
    }
}
