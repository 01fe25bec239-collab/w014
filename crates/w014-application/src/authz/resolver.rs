//! Application service for resolving AuthorizedWorkspaceContext from persistent storage.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use w014_authz::authorized_workspace_context::AuthorizedWorkspaceContext;
use w014_authz::error::AuthzError;
use w014_domain::ids::{PrincipalId, WorkspaceId};

use crate::error::ApplicationError;
use crate::persistence::{
    CapabilityGrantRepository, MembershipRepository, OrganizationRepository, PrincipalRepository,
    ProgramRepository, WorkspaceRepository,
};

/// Service resolving strongly-typed, fail-closed `AuthorizedWorkspaceContext`.
pub struct WorkspaceAuthzResolver;

impl WorkspaceAuthzResolver {
    /// Resolves an `AuthorizedWorkspaceContext` for a principal within a workspace.
    ///
    /// Validates tenant hierarchy, principal active status, membership, and merges active capability grants.
    /// Fails closed if any invariant is violated.
    pub async fn resolve(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        evaluated_at: DateTime<Utc>,
    ) -> Result<AuthorizedWorkspaceContext, ApplicationError> {
        // Set transaction-local RLS context for workspace resolution
        w014_persistence::set_session_workspace_id(tx, workspace_id.into_uuid()).await?;

        // Verify RLS context before executing queries
        let current_ctx = super::coordinator::get_current_workspace_id(tx).await?;
        if current_ctx != Some(workspace_id.into_uuid()) {
            return Err(ApplicationError::RlsContextVerificationFailed {
                expected: workspace_id.into_uuid(),
                actual: current_ctx,
            });
        }

        // 1. Fetch workspace
        let workspace = WorkspaceRepository::get_by_id(tx, workspace_id)
            .await?
            .ok_or_else(|| ApplicationError::NotFound(format!("Workspace {}", workspace_id)))?;

        // 2. Fetch program and verify program-workspace org binding
        let program = ProgramRepository::get_by_id(tx, workspace.program_id)
            .await?
            .ok_or_else(|| {
                ApplicationError::NotFound(format!("Program {}", workspace.program_id))
            })?;

        if program.organization_id != workspace.organization_id {
            return Err(ApplicationError::Authz(AuthzError::OrganizationMismatch {
                expected: workspace.organization_id,
                actual: program.organization_id,
            }));
        }

        // 3. Fetch organization
        let organization = OrganizationRepository::get_by_id(tx, workspace.organization_id)
            .await?
            .ok_or_else(|| {
                ApplicationError::NotFound(format!("Organization {}", workspace.organization_id))
            })?;

        // 4. Fetch principal and verify active status and tenant binding
        let principal = PrincipalRepository::get_by_id(tx, principal_id)
            .await?
            .ok_or_else(|| ApplicationError::NotFound(format!("Principal {}", principal_id)))?;

        if !principal.is_active {
            return Err(ApplicationError::Authz(AuthzError::InactivePrincipal(
                principal_id,
            )));
        }

        if principal.organization_id != workspace.organization_id {
            return Err(ApplicationError::Authz(AuthzError::TenantBoundaryMismatch(
                format!(
                    "Principal org '{}' does not match workspace org '{}'",
                    principal.organization_id, workspace.organization_id
                ),
            )));
        }

        // 5. Fetch membership
        let membership =
            MembershipRepository::get_by_workspace_and_principal(tx, workspace_id, principal_id)
                .await?
                .ok_or_else(|| {
                    ApplicationError::Authz(AuthzError::NoMembership {
                        principal_id,
                        workspace_id,
                    })
                })?;

        // 6. Fetch capability grants for principal in this workspace
        let grants = CapabilityGrantRepository::get_by_workspace_and_principal(
            tx,
            workspace_id,
            principal_id,
        )
        .await?;

        // 7. Resolve fail-closed AuthorizedWorkspaceContext
        let context = AuthorizedWorkspaceContext::resolve(
            principal.id,
            organization.id,
            program.id,
            workspace.id,
            membership.role,
            grants,
            evaluated_at,
        );

        Ok(context)
    }
}
