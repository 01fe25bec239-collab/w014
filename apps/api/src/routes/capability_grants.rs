//! Capability Grants API endpoints (E14: Create Capability Grant, E15: Revoke Capability Grant).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use w014_application::authn::SessionAuthnService;
use w014_application::authz::{
    DatabaseRole, WorkspaceAuthzResolver, WorkspaceTransaction, WorkspaceTxOptions,
};
use w014_application::persistence::{
    CapabilityGrantRepository, MembershipRepository, PrincipalRepository,
};
use w014_application::services::IdempotencyCoordinator;
use w014_authn::error::AuthnError;
use w014_authn::session::SessionCookieBuilder;
use w014_authz::authority::SpecialAuthority;
use w014_authz::capability::{Capability, CapabilityGrantId};
use w014_authz::grant::CapabilityGrant;
use w014_domain::ids::{PrincipalId, WorkspaceId};
use w014_domain::principal::Principal;
use w014_persistence::audit::{AppendAuditParams, AuditAppendContract, PostgresAuditStore};
use w014_persistence::idempotency::{IdempotencyCheckResult, PostgresIdempotencyStore};

use crate::AppState;
use crate::error::ProblemDetails;

/// Request/Response payload representing a capability grant (E14, E15).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CapabilityGrantDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub workspace_id: String,
    pub principal_id: String,
    pub capability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<&CapabilityGrant> for CapabilityGrantDto {
    fn from(g: &CapabilityGrant) -> Self {
        Self {
            id: Some(g.id.to_string()),
            workspace_id: g.workspace_id.map(|w| w.to_string()).unwrap_or_default(),
            principal_id: g.principal_id.to_string(),
            capability: g.capability.to_string(),
            granted_by: g.granted_by.map(|p| p.to_string()),
            granted_at: Some(g.granted_at),
            expires_at: g.expires_at,
        }
    }
}

/// Request payload for revoking a capability grant (E15).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Default)]
pub struct RevokeGrantDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Authenticates the request caller from session cookies, verifying active principal status.
async fn authenticate_caller(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
) -> Result<(w014_authn::session::Session, Principal), ProblemDetails> {
    let raw_token = SessionCookieBuilder::extract_token(headers, &state.config.session.cookie_name)
        .ok_or(AuthnError::Unauthenticated)?;

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| ProblemDetails::internal_server_error(Some(path.into())))?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(path.into())))?;

    let auth_res =
        SessionAuthnService::authenticate(&mut tx, &raw_token, &state.config.session, None)
            .await
            .map_err(ProblemDetails::from)?;

    let principal = PrincipalRepository::get_by_id(&mut tx, auth_res.session.principal_id)
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(path.into())))?
        .ok_or_else(|| ProblemDetails::unauthorized("Principal not found", Some(path.into())))?;

    if !principal.is_active() {
        return Err(ProblemDetails::forbidden(
            "Principal account is deactivated",
            Some(path.into()),
        ));
    }

    tx.commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(path.into())))?;

    Ok((auth_res.session, principal))
}

/// E14: POST /api/v1/workspaces/{workspace_id}/capability-grants
/// Creates a capability grant for a principal within a workspace. Requires GRANT_AUTHORITY special authority.
#[utoipa::path(
    post,
    path = "/api/v1/workspaces/{workspace_id}/capability-grants",
    params(
        ("workspace_id" = String, Path, description = "Workspace unique identifier")
    ),
    request_body = CapabilityGrantDto,
    responses(
        (status = 201, description = "Capability grant created successfully", body = CapabilityGrantDto),
        (status = 400, description = "Bad Request", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden: missing GRANT_AUTHORITY special authority or CSRF failed", body = ProblemDetails),
        (status = 404, description = "Not found", body = ProblemDetails),
        (status = 409, description = "Conflict: capability grant already exists", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "CapabilityGrants"
)]
pub async fn create_capability_grant_handler(
    State(state): State<AppState>,
    Path(workspace_id_str): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<CapabilityGrantDto>,
) -> Result<Response, ProblemDetails> {
    let req_path = format!("/api/v1/workspaces/{workspace_id_str}/capability-grants");

    // 1. Authenticate caller
    let (session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

    // 2. CSRF exact Origin and token validation
    state
        .csrf_protector
        .validate_request(
            &Method::POST,
            &headers,
            true,
            Some(&session.rotation_identity()),
        )
        .map_err(ProblemDetails::from)?;

    let ws_uuid = Uuid::parse_str(&workspace_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Workspace '{}' was not found", workspace_id_str),
            Some(req_path.clone()),
        )
    })?;

    // Selector validation: body workspace_id must match URL path if provided
    if !payload.workspace_id.trim().is_empty()
        && payload.workspace_id.trim() != workspace_id_str.trim()
    {
        return Err(ProblemDetails::bad_request(
            "Payload workspace_id must match URL path",
            Some(req_path),
        ));
    }

    let target_principal_uuid = Uuid::parse_str(&payload.principal_id).map_err(|_| {
        ProblemDetails::bad_request(
            format!("Invalid principal_id format: '{}'", payload.principal_id),
            Some(req_path.clone()),
        )
    })?;

    let capability: Capability = payload.capability.parse().map_err(|_| {
        ProblemDetails::bad_request(
            format!("Invalid capability format: '{}'", payload.capability),
            Some(req_path.clone()),
        )
    })?;

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    let now = Utc::now();
    let mut setup_tx = pool
        .begin()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    // 3. Resolve AuthorizedWorkspaceContext for caller
    let awc = match WorkspaceAuthzResolver::resolve(
        &mut setup_tx,
        WorkspaceId::from_uuid(ws_uuid),
        principal.id,
        now,
    )
    .await
    {
        Ok(context) => context,
        Err(w014_application::error::ApplicationError::NotFound(_))
        | Err(w014_application::error::ApplicationError::Authz(
            w014_authz::error::AuthzError::NoMembership { .. },
        ))
        | Err(w014_application::error::ApplicationError::Authz(
            w014_authz::error::AuthzError::TenantBoundaryMismatch(_),
        )) => {
            return Err(ProblemDetails::not_found(
                format!("Workspace '{}' was not found", workspace_id_str),
                Some(req_path),
            ));
        }
        Err(e) => return Err(ProblemDetails::from(e)),
    };

    // 4. Primary Rust authorization check: STRICTLY REQUIRES GRANT_AUTHORITY special authority!
    // (Never implied by Admin role profile)
    if !awc.can_grant_authority() {
        return Err(ProblemDetails::forbidden(
            "GRANT_AUTHORITY special authority required to grant capabilities",
            Some(req_path),
        ));
    }

    // 5. Verify target principal has active membership in this workspace
    let target_membership = MembershipRepository::get_by_workspace_and_principal(
        &mut setup_tx,
        awc.workspace_id(),
        PrincipalId::from_uuid(target_principal_uuid),
    )
    .await
    .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?
    .ok_or_else(|| {
        ProblemDetails::bad_request(
            format!(
                "Target principal '{}' is not a member of workspace '{}'",
                payload.principal_id, workspace_id_str
            ),
            Some(req_path.clone()),
        )
    })?;

    let _ = target_membership;

    setup_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    // 6. Begin workspace transaction with RLS app.workspace_id
    let options = WorkspaceTxOptions::new()
        .with_client_workspace(WorkspaceId::from_uuid(ws_uuid))
        .with_special_authority(SpecialAuthority::GrantAuthority)
        .with_role(DatabaseRole::App);

    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc, options)
        .await
        .map_err(ProblemDetails::from)?;

    // 7. Idempotency arbitration
    let idemp_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let payload_val = serde_json::to_value(&payload)
        .map_err(|e| ProblemDetails::bad_request(e.to_string(), Some(req_path.clone())))?;
    let req_hash = IdempotencyCoordinator::compute_payload_hash(&payload_val);
    let idemp_store = PostgresIdempotencyStore::new();

    let record_id_opt = if let Some(ref key) = idemp_key {
        let key_hash =
            IdempotencyCoordinator::compute_key_hash(&state.config.session.active_hmac_secret, key);
        match IdempotencyCoordinator::evaluate_key(
            ws_tx.conn(),
            &idemp_store,
            Some(awc.workspace_id()),
            principal.id,
            "CAPABILITY_GRANT",
            &key_hash,
            &req_hash,
            86400,
        )
        .await
        .map_err(ProblemDetails::from)?
        {
            IdempotencyCheckResult::Replay {
                status_code, body, ..
            } => {
                ws_tx.commit().await.map_err(ProblemDetails::from)?;
                let sc = StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK);
                return Ok((sc, Json(body.unwrap_or(payload_val))).into_response());
            }
            IdempotencyCheckResult::Mismatch {
                expected_hash,
                actual_hash,
            } => {
                return Err(ProblemDetails::bad_request(
                    format!(
                        "Idempotency key reused with different request payload (expected: {expected_hash}, actual: {actual_hash})"
                    ),
                    Some(req_path),
                ));
            }
            IdempotencyCheckResult::InProgress => {
                return Err(ProblemDetails::bad_request(
                    "Request with this idempotency key is currently in progress",
                    Some(req_path),
                ));
            }
            IdempotencyCheckResult::Acquired { record_id } => Some(record_id),
        }
    } else {
        None
    };

    // 8. Check for existing grant with same capability
    if let Some(existing_grant) = CapabilityGrantRepository::get_by_workspace_principal_capability(
        ws_tx.conn(),
        awc.workspace_id(),
        PrincipalId::from_uuid(target_principal_uuid),
        &capability,
    )
    .await
    .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?
        && existing_grant.is_active_at(now)
    {
        return Err(ProblemDetails::conflict(
            format!(
                "Active capability grant for '{}' already exists for principal '{}'",
                payload.capability, payload.principal_id
            ),
            Some(req_path),
        ));
    }

    // 9. Create grant entity and append audit event in same transaction
    let grant = CapabilityGrant::new(
        awc.workspace_id(),
        PrincipalId::from_uuid(target_principal_uuid),
        capability.clone(),
        Some(principal.id),
        payload.expires_at,
    )
    .map_err(|e| ProblemDetails::bad_request(e.to_string(), Some(req_path.clone())))?;

    CapabilityGrantRepository::insert(ws_tx.conn(), &grant)
        .await
        .map_err(|e| match e {
            w014_persistence::error::PersistenceError::Connection(ref sqlx_err)
                if sqlx_err.to_string().contains("duplicate key")
                    || sqlx_err
                        .to_string()
                        .contains("uq_capability_grants_workspace_principal_cap") =>
            {
                ProblemDetails::conflict("Capability grant already exists", Some(req_path.clone()))
            }
            _ => ProblemDetails::internal_server_error(Some(req_path.clone())),
        })?;

    let audit_store = PostgresAuditStore::new();
    let grant_audit_payload = serde_json::json!({
        "grant_id": grant.id.to_string(),
        "workspace_id": awc.workspace_id().to_string(),
        "principal_id": grant.principal_id.to_string(),
        "capability": capability.as_str(),
        "granted_by": principal.id.to_string(),
        "expires_at": grant.expires_at.map(|e| e.to_rfc3339()),
    });

    let grant_audit_params = AppendAuditParams {
        workspace_id: awc.workspace_id().into_uuid(),
        actor_type: "principal".to_string(),
        actor_id: Some(principal.id.into_uuid()),
        authority_snapshot: serde_json::json!({}),
        action_code: "CAPABILITY_GRANT".to_string(),
        entity_type: "capability_grant".to_string(),
        entity_id: grant.id.to_string(),
        entity_version: Some(1),
        request_id: None,
        correlation_id: None,
        job_id: None,
        source_state_hash: None,
        before_ref: None,
        after_ref: None,
        metadata: grant_audit_payload,
    };

    audit_store
        .append_audit_event(ws_tx.conn(), grant_audit_params)
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    let dto = CapabilityGrantDto::from(&grant);
    let resp_body = serde_json::to_value(&dto).ok();

    if let Some(record_id) = record_id_opt {
        IdempotencyCoordinator::complete_record(
            ws_tx.conn(),
            &idemp_store,
            record_id,
            StatusCode::CREATED.as_u16(),
            resp_body,
        )
        .await
        .map_err(ProblemDetails::from)?;
    }

    ws_tx.commit().await.map_err(ProblemDetails::from)?;

    Ok((StatusCode::CREATED, Json(dto)).into_response())
}

/// E15: POST /api/v1/workspaces/{workspace_id}/capability-grants/{grant_id}/revoke
/// Revokes a capability grant (one-way revocation). Requires GRANT_AUTHORITY special authority.
#[utoipa::path(
    post,
    path = "/api/v1/workspaces/{workspace_id}/capability-grants/{grant_id}/revoke",
    params(
        ("workspace_id" = String, Path, description = "Workspace unique identifier"),
        ("grant_id" = String, Path, description = "Capability grant unique identifier")
    ),
    request_body = RevokeGrantDto,
    responses(
        (status = 200, description = "Capability grant revoked successfully", body = CapabilityGrantDto),
        (status = 400, description = "Bad Request", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden: missing GRANT_AUTHORITY special authority or CSRF failed", body = ProblemDetails),
        (status = 404, description = "Not found", body = ProblemDetails),
        (status = 409, description = "Conflict: capability grant is already expired or revoked", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "CapabilityGrants"
)]
pub async fn revoke_capability_grant_handler(
    State(state): State<AppState>,
    Path((workspace_id_str, grant_id_str)): Path<(String, String)>,
    headers: HeaderMap,
    Json(payload): Json<RevokeGrantDto>,
) -> Result<Response, ProblemDetails> {
    let req_path =
        format!("/api/v1/workspaces/{workspace_id_str}/capability-grants/{grant_id_str}/revoke");

    // 1. Authenticate caller
    let (session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

    // 2. CSRF exact Origin and token validation
    state
        .csrf_protector
        .validate_request(
            &Method::POST,
            &headers,
            true,
            Some(&session.rotation_identity()),
        )
        .map_err(ProblemDetails::from)?;

    let ws_uuid = Uuid::parse_str(&workspace_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Workspace '{}' was not found", workspace_id_str),
            Some(req_path.clone()),
        )
    })?;

    let grant_uuid = Uuid::parse_str(&grant_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Capability grant '{}' was not found", grant_id_str),
            Some(req_path.clone()),
        )
    })?;

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    let now = Utc::now();
    let mut setup_tx = pool
        .begin()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    // 3. Resolve AuthorizedWorkspaceContext for caller
    let awc = match WorkspaceAuthzResolver::resolve(
        &mut setup_tx,
        WorkspaceId::from_uuid(ws_uuid),
        principal.id,
        now,
    )
    .await
    {
        Ok(context) => context,
        Err(w014_application::error::ApplicationError::NotFound(_))
        | Err(w014_application::error::ApplicationError::Authz(
            w014_authz::error::AuthzError::NoMembership { .. },
        ))
        | Err(w014_application::error::ApplicationError::Authz(
            w014_authz::error::AuthzError::TenantBoundaryMismatch(_),
        )) => {
            return Err(ProblemDetails::not_found(
                format!("Workspace '{}' was not found", workspace_id_str),
                Some(req_path),
            ));
        }
        Err(e) => return Err(ProblemDetails::from(e)),
    };

    // 4. Primary Rust authorization check: STRICTLY REQUIRES GRANT_AUTHORITY special authority!
    if !awc.can_grant_authority() {
        return Err(ProblemDetails::forbidden(
            "GRANT_AUTHORITY special authority required to revoke capabilities",
            Some(req_path),
        ));
    }

    setup_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    // 5. Begin workspace transaction with RLS app.workspace_id
    let options = WorkspaceTxOptions::new()
        .with_client_workspace(WorkspaceId::from_uuid(ws_uuid))
        .with_special_authority(SpecialAuthority::GrantAuthority)
        .with_role(DatabaseRole::App);

    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc, options)
        .await
        .map_err(ProblemDetails::from)?;

    // 6. Idempotency arbitration
    let idemp_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let payload_val = serde_json::to_value(&payload)
        .map_err(|e| ProblemDetails::bad_request(e.to_string(), Some(req_path.clone())))?;
    let req_hash = IdempotencyCoordinator::compute_payload_hash(&payload_val);
    let idemp_store = PostgresIdempotencyStore::new();

    let record_id_opt = if let Some(ref key) = idemp_key {
        let key_hash =
            IdempotencyCoordinator::compute_key_hash(&state.config.session.active_hmac_secret, key);
        match IdempotencyCoordinator::evaluate_key(
            ws_tx.conn(),
            &idemp_store,
            Some(awc.workspace_id()),
            principal.id,
            "CAPABILITY_REVOKE",
            &key_hash,
            &req_hash,
            86400,
        )
        .await
        .map_err(ProblemDetails::from)?
        {
            IdempotencyCheckResult::Replay {
                status_code, body, ..
            } => {
                ws_tx.commit().await.map_err(ProblemDetails::from)?;
                let sc = StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK);
                return Ok((sc, Json(body.unwrap_or(payload_val))).into_response());
            }
            IdempotencyCheckResult::Mismatch {
                expected_hash,
                actual_hash,
            } => {
                return Err(ProblemDetails::bad_request(
                    format!(
                        "Idempotency key reused with different request payload (expected: {expected_hash}, actual: {actual_hash})"
                    ),
                    Some(req_path),
                ));
            }
            IdempotencyCheckResult::InProgress => {
                return Err(ProblemDetails::bad_request(
                    "Request with this idempotency key is currently in progress",
                    Some(req_path),
                ));
            }
            IdempotencyCheckResult::Acquired { record_id } => Some(record_id),
        }
    } else {
        None
    };

    // 7. Fetch grant and verify ownership
    let mut grant = CapabilityGrantRepository::get_by_id(
        ws_tx.conn(),
        CapabilityGrantId::from_uuid(grant_uuid),
    )
    .await
    .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?
    .ok_or_else(|| {
        ProblemDetails::not_found(
            format!("Capability grant '{}' was not found", grant_id_str),
            Some(req_path.clone()),
        )
    })?;

    if grant.workspace_id != Some(awc.workspace_id()) {
        return Err(ProblemDetails::not_found(
            format!("Capability grant '{}' was not found", grant_id_str),
            Some(req_path),
        ));
    }

    if !grant.is_active_at(now) {
        return Err(ProblemDetails::conflict(
            format!(
                "Capability grant '{}' is already revoked or expired",
                grant_id_str
            ),
            Some(req_path),
        ));
    }

    // 8. Revoke grant (one-way revocation)
    grant
        .revoke(now, Some(principal.id), payload.reason.clone())
        .map_err(|e| ProblemDetails::conflict(e.to_string(), Some(req_path.clone())))?;

    CapabilityGrantRepository::revoke(
        ws_tx.conn(),
        grant.id,
        now,
        Some(principal.id),
        payload.reason.as_deref(),
    )
    .await
    .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    // 9. Append capability.revoked audit event
    let audit_store = PostgresAuditStore::new();
    let revoke_audit_payload = serde_json::json!({
        "grant_id": grant.id.to_string(),
        "workspace_id": awc.workspace_id().to_string(),
        "principal_id": grant.principal_id.to_string(),
        "capability": grant.capability.as_str(),
        "revoked_at": now.to_rfc3339(),
        "reason": payload.reason,
    });

    let revoke_audit_params = AppendAuditParams {
        workspace_id: awc.workspace_id().into_uuid(),
        actor_type: "principal".to_string(),
        actor_id: Some(principal.id.into_uuid()),
        authority_snapshot: serde_json::json!({}),
        action_code: "CAPABILITY_REVOKE".to_string(),
        entity_type: "capability_grant".to_string(),
        entity_id: grant.id.to_string(),
        entity_version: Some(1),
        request_id: None,
        correlation_id: None,
        job_id: None,
        source_state_hash: None,
        before_ref: None,
        after_ref: None,
        metadata: revoke_audit_payload,
    };

    audit_store
        .append_audit_event(ws_tx.conn(), revoke_audit_params)
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    let dto = CapabilityGrantDto::from(&grant);
    let resp_body = serde_json::to_value(&dto).ok();

    if let Some(record_id) = record_id_opt {
        IdempotencyCoordinator::complete_record(
            ws_tx.conn(),
            &idemp_store,
            record_id,
            StatusCode::OK.as_u16(),
            resp_body,
        )
        .await
        .map_err(ProblemDetails::from)?;
    }

    ws_tx.commit().await.map_err(ProblemDetails::from)?;

    Ok((StatusCode::OK, Json(dto)).into_response())
}
