//! Capability Grant application service with atomic audit logging.
//!
//! Note: The WI-0103 capability engine is deferred to WI-0103.

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
            event_type: "capability.granted".to_string(),
            actor_principal_id: actor_principal_id.map(|p| p.into_uuid()),
            action: "grant".to_string(),
            resource_type: "capability_grant".to_string(),
            resource_id: grant.id.to_string(),
            payload: audit_payload,
            correlation_id,
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
        grant.revoke(now)?;
        CapabilityGrantRepository::update_expiry(tx, grant.id, grant.expires_at).await?;

        let audit_payload = serde_json::json!({
            "grant_id": grant.id.to_string(),
            "workspace_id": grant.workspace_id.to_string(),
            "principal_id": grant.principal_id.to_string(),
            "capability": grant.capability.as_str(),
            "revoked_at": now.to_rfc3339(),
        });

        let audit_params = AppendAuditParams {
            workspace_id: grant.workspace_id.into_uuid(),
            event_type: "capability.revoked".to_string(),
            actor_principal_id: actor_principal_id.map(|p| p.into_uuid()),
            action: "revoke".to_string(),
            resource_type: "capability_grant".to_string(),
            resource_id: grant.id.to_string(),
            payload: audit_payload,
            correlation_id,
        };

        audit_store.append_audit_event(tx, audit_params).await?;

        Ok(())
    }
}
