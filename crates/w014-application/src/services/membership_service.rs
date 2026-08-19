//! Membership application service with atomic audit logging.

use sqlx::PgConnection;
use w014_domain::ids::{PrincipalId, WorkspaceId};
use w014_domain::membership::{Membership, MembershipRole};
use w014_persistence::audit::{AppendAuditParams, AuditAppendContract};

use crate::error::ApplicationError;
use crate::persistence::MembershipRepository;

/// Service managing workspace memberships with audit atomicity.
pub struct MembershipService;

impl MembershipService {
    /// Adds a principal to a workspace with a specified role and appends an audit event.
    pub async fn add_member_with_audit(
        tx: &mut PgConnection,
        audit_store: &impl AuditAppendContract,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        role: MembershipRole,
        actor_principal_id: Option<PrincipalId>,
        correlation_id: Option<String>,
    ) -> Result<Membership, ApplicationError> {
        let membership = Membership::new(workspace_id, principal_id, role);
        MembershipRepository::insert(tx, &membership).await?;

        let audit_payload = serde_json::json!({
            "membership_id": membership.id.to_string(),
            "workspace_id": workspace_id.to_string(),
            "principal_id": principal_id.to_string(),
            "role": role.as_str(),
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

    /// Updates a principal's role in a workspace and appends an audit event.
    pub async fn update_member_role_with_audit(
        tx: &mut PgConnection,
        audit_store: &impl AuditAppendContract,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        new_role: MembershipRole,
        actor_principal_id: Option<PrincipalId>,
        correlation_id: Option<String>,
    ) -> Result<Membership, ApplicationError> {
        let mut membership =
            MembershipRepository::get_by_workspace_and_principal(tx, workspace_id, principal_id)
                .await?
                .ok_or_else(|| {
                    ApplicationError::NotFound(format!(
                        "Membership for principal {} in workspace {}",
                        principal_id, workspace_id
                    ))
                })?;

        let old_role = membership.role;
        membership.change_role(new_role);
        MembershipRepository::update_role(tx, &membership).await?;

        let audit_payload = serde_json::json!({
            "membership_id": membership.id.to_string(),
            "workspace_id": workspace_id.to_string(),
            "principal_id": principal_id.to_string(),
            "old_role": old_role.as_str(),
            "new_role": new_role.as_str(),
        });

        let audit_params = AppendAuditParams {
            workspace_id: workspace_id.into_uuid(),
            event_type: "membership.role_updated".to_string(),
            actor_principal_id: actor_principal_id.map(|p| p.into_uuid()),
            action: "update".to_string(),
            resource_type: "membership".to_string(),
            resource_id: membership.id.to_string(),
            payload: audit_payload,
            correlation_id,
        };

        audit_store.append_audit_event(tx, audit_params).await?;

        Ok(membership)
    }
}
