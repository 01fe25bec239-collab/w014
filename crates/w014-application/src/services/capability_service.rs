//! Capability Grant application service with atomic audit logging.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use w014_authz::capability::{Capability, CapabilityGrantId};
use w014_authz::grant::CapabilityGrant;
use w014_domain::ids::{PrincipalId, WorkspaceId};
use w014_persistence::audit::{AppendAuditParams, AuditAppendContract};

use crate::error::ApplicationError;
use crate::persistence::CapabilityGrantRepository;

/// Service managing capability grants with audit atomicity.
pub struct CapabilityGrantService;

impl CapabilityGrantService {
    /// Grants a capability to a principal within a workspace and appends an audit event.
    #[allow(clippy::too_many_arguments)]
    pub async fn grant_capability_with_audit(
        tx: &mut PgConnection,
        audit_store: &impl AuditAppendContract,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        capability: Capability,
        granted_by: Option<PrincipalId>,
        expires_at: Option<DateTime<Utc>>,
        actor_principal_id: Option<PrincipalId>,
        correlation_id: Option<String>,
    ) -> Result<CapabilityGrant, ApplicationError> {
        let grant = CapabilityGrant::new(
            workspace_id,
            principal_id,
            capability.clone(),
            granted_by,
            expires_at,
        )?;

        CapabilityGrantRepository::insert(tx, &grant).await?;

        let audit_payload = serde_json::json!({
            "grant_id": grant.id.to_string(),
            "workspace_id": workspace_id.to_string(),
            "principal_id": principal_id.to_string(),
            "capability": capability.as_str(),
            "granted_by": granted_by.map(|g| g.to_string()),
            "expires_at": expires_at.map(|e| e.to_rfc3339()),
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
            action_code: "CAPABILITY_GRANT".to_string(),
            entity_type: "capability_grant".to_string(),
            entity_id: grant.id.to_string(),
            entity_version: Some(1),
            request_id: None,
            correlation_id,
            job_id: None,
            source_state_hash: None,
            before_ref: None,
            after_ref: Some(audit_payload),
            metadata: serde_json::json!({}),
        };

        audit_store.append_audit_event(tx, audit_params).await?;

        Ok(grant)
    }

    /// Revokes a capability grant and appends an audit event (one-way revocation).
    pub async fn revoke_capability_with_audit(
        tx: &mut PgConnection,
        audit_store: &impl AuditAppendContract,
        grant_id: CapabilityGrantId,
        actor_principal_id: Option<PrincipalId>,
        correlation_id: Option<String>,
    ) -> Result<(), ApplicationError> {
        let mut grant = CapabilityGrantRepository::get_by_id(tx, grant_id)
            .await?
            .ok_or_else(|| ApplicationError::NotFound(format!("Capability grant {}", grant_id)))?;

        let now = Utc::now();
        grant.revoke(now, actor_principal_id, Some("Revoked via API".to_string()))?;
        CapabilityGrantRepository::revoke(
            tx,
            grant.id,
            now,
            actor_principal_id,
            Some("Revoked via API"),
        )
        .await?;

        let audit_payload = serde_json::json!({
            "grant_id": grant.id.to_string(),
            "workspace_id": grant.workspace_id.map(|id| id.to_string()),
            "principal_id": grant.principal_id.to_string(),
            "capability": grant.capability.as_str(),
            "revoked_at": now.to_rfc3339(),
        });

        if let Some(ws_id) = grant.workspace_id {
            let audit_params = AppendAuditParams {
                workspace_id: ws_id.into_uuid(),
                actor_type: if actor_principal_id.is_some() {
                    "principal".to_string()
                } else {
                    "system".to_string()
                },
                actor_id: actor_principal_id.map(|p| p.into_uuid()),
                authority_snapshot: serde_json::json!({}),
                action_code: "CAPABILITY_REVOKE".to_string(),
                entity_type: "capability_grant".to_string(),
                entity_id: grant.id.to_string(),
                entity_version: Some(2),
                request_id: None,
                correlation_id,
                job_id: None,
                source_state_hash: None,
                before_ref: None,
                after_ref: Some(audit_payload),
                metadata: serde_json::json!({}),
            };

            audit_store.append_audit_event(tx, audit_params).await?;
        }

        Ok(())
    }
}
