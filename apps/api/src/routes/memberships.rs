//! Workspace membership API endpoints (E12: List Memberships, E13: Create Membership).

use axum::Json;
use axum::extract::{Path, Query, State};
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
use w014_application::persistence::{MembershipRepository, PrincipalRepository};
use w014_application::services::IdempotencyCoordinator;
use w014_authn::error::AuthnError;
use w014_authn::session::SessionCookieBuilder;
use w014_authz::capability::Capability;
use w014_domain::ids::{PrincipalId, WorkspaceId};
use w014_domain::membership::{Membership, MembershipRole};
use w014_domain::principal::Principal;
use w014_persistence::audit::{AppendAuditParams, AuditAppendContract, PostgresAuditStore};
use w014_persistence::idempotency::{IdempotencyCheckResult, PostgresIdempotencyStore};

use crate::AppState;
use crate::error::ProblemDetails;
use crate::routes::programs::PaginationQuery;

/// Request payload for adding a member to a workspace (E13).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateMembershipDto {
    pub principal_id: String,
    pub role: String,
}

/// Response payload representing a membership domain entity (E12, E13).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MembershipDto {
    pub id: String,
    pub workspace_id: String,
    pub principal_id: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&Membership> for MembershipDto {
    fn from(m: &Membership) -> Self {
        Self {
            id: m.id.to_string(),
            workspace_id: m.workspace_id.to_string(),
            principal_id: m.principal_id.to_string(),
            role: m.role.as_str().to_string(),
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

/// Paginated page of memberships (E12).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MembershipPage {
    pub items: Vec<MembershipDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
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

    if !principal.is_active {
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

/// E12: GET /api/v1/workspaces/{workspace_id}/memberships
/// Lists memberships within a workspace under RLS isolation.
#[utoipa::path(
    get,
    path = "/api/v1/workspaces/{workspace_id}/memberships",
    params(
        ("workspace_id" = String, Path, description = "Workspace unique identifier"),
        PaginationQuery
    ),
    responses(
        (status = 200, description = "Paginated list of memberships", body = MembershipPage),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 404, description = "Not found", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "Memberships"
)]
pub async fn list_memberships_handler(
    State(state): State<AppState>,
    Path(workspace_id_str): Path<String>,
    Query(pagination): Query<PaginationQuery>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let req_path = format!("/api/v1/workspaces/{workspace_id_str}/memberships");
    let (_session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

    let ws_uuid = Uuid::parse_str(&workspace_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Workspace '{}' was not found", workspace_id_str),
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

    // Resolve fail-closed AuthorizedWorkspaceContext
    let awc = match WorkspaceAuthzResolver::resolve(
        &mut setup_tx,
        WorkspaceId::from_uuid(ws_uuid),
        principal.id,
        now,
    )
    .await
    {
        Ok(context) => {
            setup_tx
                .commit()
                .await
                .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;
            context
        }
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

    // Execute under isolated WorkspaceTransaction with RLS context app.workspace_id
    let options = WorkspaceTxOptions::new()
        .with_client_workspace(WorkspaceId::from_uuid(ws_uuid))
        .with_capability(Capability::WorkspaceRead)
        .with_role(DatabaseRole::App);

    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc, options)
        .await
        .map_err(ProblemDetails::from)?;

    let cursor_uuid = pagination
        .cursor
        .as_deref()
        .and_then(|c| Uuid::parse_str(c).ok());
    let limit = pagination.limit.unwrap_or(50).clamp(1, 100) as i64;

    let (memberships, next_cursor, has_more) = MembershipRepository::list_by_workspace(
        ws_tx.conn(),
        awc.workspace_id(),
        cursor_uuid,
        limit,
    )
    .await
    .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    ws_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path)))?;

    let items = memberships.iter().map(MembershipDto::from).collect();
    let page = MembershipPage {
        items,
        next_cursor,
        has_more,
    };

    Ok((StatusCode::OK, Json(page)).into_response())
}

/// E13: POST /api/v1/workspaces/{workspace_id}/memberships
/// Adds a principal to a workspace with an assigned role.
#[utoipa::path(
    post,
    path = "/api/v1/workspaces/{workspace_id}/memberships",
    params(
        ("workspace_id" = String, Path, description = "Workspace unique identifier")
    ),
    request_body = CreateMembershipDto,
    responses(
        (status = 201, description = "Membership created successfully", body = MembershipDto),
        (status = 400, description = "Bad Request", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden: CSRF check failed or missing MEMBERSHIP_MANAGE", body = ProblemDetails),
        (status = 404, description = "Not found", body = ProblemDetails),
        (status = 409, description = "Conflict: membership already exists", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "Memberships"
)]
pub async fn create_membership_handler(
    State(state): State<AppState>,
    Path(workspace_id_str): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<CreateMembershipDto>,
) -> Result<Response, ProblemDetails> {
    let req_path = format!("/api/v1/workspaces/{workspace_id_str}/memberships");

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

    let target_principal_uuid = Uuid::parse_str(&payload.principal_id).map_err(|_| {
        ProblemDetails::bad_request(
            format!("Invalid principal_id format: '{}'", payload.principal_id),
            Some(req_path.clone()),
        )
    })?;

    let role: MembershipRole = payload.role.parse().map_err(|_| {
        ProblemDetails::bad_request(
            format!(
                "Invalid role '{}'. Valid roles: owner, admin, member, viewer, auditor",
                payload.role
            ),
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

    // 3. Resolve AuthorizedWorkspaceContext for caller in this workspace
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

    // 4. Primary Rust authorization check: Caller must have MEMBERSHIP_MANAGE or WorkspaceAdmin
    if !awc.can_admin_workspace()
        && !awc.can(&Capability::named("MEMBERSHIP_MANAGE").unwrap_or(Capability::WorkspaceAdmin))
    {
        return Err(ProblemDetails::forbidden(
            "MEMBERSHIP_MANAGE capability required to create memberships",
            Some(req_path),
        ));
    }

    // 5. Verify target principal exists, is active, and belongs to the SAME organization
    let target_principal = PrincipalRepository::get_by_id(
        &mut setup_tx,
        PrincipalId::from_uuid(target_principal_uuid),
    )
    .await
    .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?
    .ok_or_else(|| {
        ProblemDetails::not_found(
            format!("Principal '{}' was not found", payload.principal_id),
            Some(req_path.clone()),
        )
    })?;

    if !target_principal.is_active {
        return Err(ProblemDetails::bad_request(
            "Target principal is deactivated",
            Some(req_path.clone()),
        ));
    }

    if target_principal.organization_id != awc.organization_id() {
        return Err(ProblemDetails::forbidden(
            "Cross-tenant membership creation is prohibited",
            Some(req_path),
        ));
    }

    setup_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    // 6. Begin workspace-scoped transaction with RLS app.workspace_id
    let options = WorkspaceTxOptions::new()
        .with_client_workspace(WorkspaceId::from_uuid(ws_uuid))
        .with_capability(Capability::WorkspaceAdmin)
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
        match IdempotencyCoordinator::evaluate_key(
            ws_tx.conn(),
            &idemp_store,
            Some(awc.workspace_id()),
            key,
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

    // 8. Check for existing membership
    if let Some(_existing) = MembershipRepository::get_by_workspace_and_principal(
        ws_tx.conn(),
        awc.workspace_id(),
        target_principal.id,
    )
    .await
    .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?
    {
        return Err(ProblemDetails::conflict(
            format!(
                "Membership for principal '{}' already exists in this workspace",
                payload.principal_id
            ),
            Some(req_path),
        ));
    }

    // 9. Create membership entity and append audit event in same transaction
    let membership = Membership::new(awc.workspace_id(), target_principal.id, role);
    MembershipRepository::insert(ws_tx.conn(), &membership)
        .await
        .map_err(|e| match e {
            w014_persistence::error::PersistenceError::Connection(ref sqlx_err)
                if sqlx_err.to_string().contains("duplicate key")
                    || sqlx_err
                        .to_string()
                        .contains("uq_memberships_workspace_principal") =>
            {
                ProblemDetails::conflict("Membership already exists", Some(req_path.clone()))
            }
            _ => ProblemDetails::internal_server_error(Some(req_path.clone())),
        })?;

    let audit_store = PostgresAuditStore::new();
    let mem_audit_payload = serde_json::json!({
        "membership_id": membership.id.to_string(),
        "workspace_id": awc.workspace_id().to_string(),
        "principal_id": target_principal.id.to_string(),
        "role": role.as_str(),
    });

    let mem_audit_params = AppendAuditParams {
        workspace_id: awc.workspace_id().into_uuid(),
        event_type: "membership.created".to_string(),
        actor_principal_id: Some(principal.id.into_uuid()),
        action: "create".to_string(),
        resource_type: "membership".to_string(),
        resource_id: membership.id.to_string(),
        payload: mem_audit_payload,
        correlation_id: None,
    };

    audit_store
        .append_audit_event(ws_tx.conn(), mem_audit_params)
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    let dto = MembershipDto::from(&membership);
    let resp_body = serde_json::to_value(&dto).ok();

    if let Some(record_id) = record_id_opt {
        IdempotencyCoordinator::complete_record(
            ws_tx.conn(),
            &idemp_store,
            record_id,
            StatusCode::CREATED.as_u16(),
            None,
            resp_body,
        )
        .await
        .map_err(ProblemDetails::from)?;
    }

    ws_tx.commit().await.map_err(ProblemDetails::from)?;

    Ok((StatusCode::CREATED, Json(dto)).into_response())
}
