//! Workspace management API endpoints (E08: List Workspaces, E09: Create Workspace, E10: Get Workspace).

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
use w014_application::persistence::{
    MembershipRepository, PrincipalRepository, ProgramRepository, WorkspaceRepository,
};
use w014_application::services::IdempotencyCoordinator;
use w014_authn::error::AuthnError;
use w014_authn::session::SessionCookieBuilder;
use w014_authz::capability::Capability;
use w014_domain::ids::{ProgramId, WorkspaceId};
use w014_domain::membership::{Membership, MembershipRole};
use w014_domain::principal::Principal;
use w014_domain::workspace::Workspace;
use w014_persistence::audit::{AppendAuditParams, AuditAppendContract, PostgresAuditStore};
use w014_persistence::idempotency::{IdempotencyCheckResult, PostgresIdempotencyStore};

use crate::AppState;
use crate::error::ProblemDetails;
use crate::routes::programs::PaginationQuery;

/// Request payload for creating a workspace (E09).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateWorkspaceDto {
    pub name: String,
    pub slug: String,
}

/// Response payload representing a workspace domain entity (E08, E09, E10).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkspaceDto {
    pub id: String,
    pub program_id: String,
    pub organization_id: String,
    pub name: String,
    pub slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_source_state_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&Workspace> for WorkspaceDto {
    fn from(ws: &Workspace) -> Self {
        Self {
            id: ws.id.to_string(),
            program_id: ws.program_id.to_string(),
            organization_id: ws.organization_id.to_string(),
            name: ws.name.clone(),
            slug: ws.slug().to_string(),
            current_source_state_id: ws.current_source_state_id.map(|u| u.to_string()),
            created_at: ws.created_at,
            updated_at: ws.created_at,
        }
    }
}

/// Paginated page of workspaces (E08).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkspacePage {
    pub items: Vec<WorkspaceDto>,
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

/// E08: GET /api/v1/programs/{program_id}/workspaces
/// Lists workspaces belonging to a specific program.
#[utoipa::path(
    get,
    path = "/api/v1/programs/{program_id}/workspaces",
    params(
        ("program_id" = String, Path, description = "Program unique identifier"),
        PaginationQuery
    ),
    responses(
        (status = 200, description = "Paginated list of workspaces", body = WorkspacePage),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 404, description = "Not found", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "Workspaces"
)]
pub async fn list_workspaces_handler(
    State(state): State<AppState>,
    Path(program_id_str): Path<String>,
    Query(pagination): Query<PaginationQuery>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let req_path = format!("/api/v1/programs/{program_id_str}/workspaces");
    let (_session, _principal) = authenticate_caller(&state, &headers, &req_path).await?;

    let prog_uuid = Uuid::parse_str(&program_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Program '{}' was not found", program_id_str),
            Some(req_path.clone()),
        )
    })?;

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    let _program = ProgramRepository::get_by_id(&mut tx, ProgramId::from_uuid(prog_uuid))
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?
        .ok_or_else(|| {
            ProblemDetails::not_found(
                format!("Program '{}' was not found", program_id_str),
                Some(req_path.clone()),
            )
        })?;

    // Privacy-safe tenant boundary isolation: if program has workspaces, caller must be a member or grantee
    let has_workspaces: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM workspaces WHERE program_id = $1)")
            .bind(prog_uuid)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(false);

    if has_workspaces {
        let has_member: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM workspaces w
                 JOIN memberships m ON w.workspace_id = m.workspace_id
                 WHERE w.program_id = $1 AND m.principal_id = $2
             ) OR EXISTS (
                 SELECT 1 FROM capability_grants cg
                 WHERE (cg.program_id = $1 OR cg.workspace_id IN (SELECT workspace_id FROM workspaces WHERE program_id = $1))
                   AND cg.principal_id = $2
             )",
        )
        .bind(prog_uuid)
        .bind(_principal.id.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(false);

        if !has_member {
            return Err(ProblemDetails::not_found(
                format!("Program '{}' was not found", program_id_str),
                Some(req_path),
            ));
        }
    }

    let cursor_uuid = pagination
        .cursor
        .as_deref()
        .and_then(|c| Uuid::parse_str(c).ok());
    let limit = pagination.limit.unwrap_or(50).clamp(1, 100) as i64;

    let (workspaces, next_cursor, has_more) = WorkspaceRepository::list_by_program(
        &mut tx,
        ProgramId::from_uuid(prog_uuid),
        cursor_uuid,
        limit,
    )
    .await
    .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    tx.commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path)))?;

    let items = workspaces.iter().map(WorkspaceDto::from).collect();
    let page = WorkspacePage {
        items,
        next_cursor,
        has_more,
    };

    Ok((StatusCode::OK, Json(page)).into_response())
}

/// E09: POST /api/v1/programs/{program_id}/workspaces
/// Creates a new workspace within a program, initializing its audit chain head atomically.
#[utoipa::path(
    post,
    path = "/api/v1/programs/{program_id}/workspaces",
    params(
        ("program_id" = String, Path, description = "Program unique identifier")
    ),
    request_body = CreateWorkspaceDto,
    responses(
        (status = 201, description = "Workspace created successfully", body = WorkspaceDto),
        (status = 400, description = "Bad Request", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 404, description = "Not found", body = ProblemDetails),
        (status = 409, description = "Conflict: workspace slug already exists in program", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "Workspaces"
)]
pub async fn create_workspace_handler(
    State(state): State<AppState>,
    Path(program_id_str): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<CreateWorkspaceDto>,
) -> Result<Response, ProblemDetails> {
    let req_path = format!("/api/v1/programs/{program_id_str}/workspaces");

    // 1. Authenticate caller
    let (session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

    // 2. CSRF exact Origin and token validation (fail closed before mutation or idempotency consumption)
    state
        .csrf_protector
        .validate_request(
            &Method::POST,
            &headers,
            true,
            Some(&session.rotation_identity()),
        )
        .map_err(ProblemDetails::from)?;

    let prog_uuid = Uuid::parse_str(&program_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Program '{}' was not found", program_id_str),
            Some(req_path.clone()),
        )
    })?;

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    // 3. Verify program exists
    let program = ProgramRepository::get_by_id(&mut tx, ProgramId::from_uuid(prog_uuid))
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?
        .ok_or_else(|| {
            ProblemDetails::not_found(
                format!("Program '{}' was not found", program_id_str),
                Some(req_path.clone()),
            )
        })?;

    // 4. Idempotency arbitration
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
            &mut tx,
            &idemp_store,
            None,
            principal.id,
            "WORKSPACE_CREATE",
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
                tx.commit()
                    .await
                    .map_err(|_| ProblemDetails::internal_server_error(None))?;
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

    // 5. Conflict check on slug
    if let Some(_existing) =
        WorkspaceRepository::get_by_program_and_slug(&mut tx, program.id, &payload.slug)
            .await
            .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?
    {
        return Err(ProblemDetails::conflict(
            format!(
                "Workspace with slug '{}' already exists in this program",
                payload.slug
            ),
            Some(req_path),
        ));
    }

    // 6. Domain creation & Atomic audit append in same transaction
    let ws = Workspace::new(
        program.id,
        program.organization_id,
        payload.name,
        payload.slug,
    )
    .map_err(|e| ProblemDetails::bad_request(e.to_string(), Some(req_path.clone())))?;

    WorkspaceRepository::insert(&mut tx, &ws)
        .await
        .map_err(|e| match e {
            w014_persistence::error::PersistenceError::Connection(ref sqlx_err)
                if sqlx_err.to_string().contains("duplicate key")
                    || sqlx_err
                        .to_string()
                        .contains("uq_workspaces_program_workspace_code") =>
            {
                ProblemDetails::conflict("Workspace slug already exists", Some(req_path.clone()))
            }
            _ => ProblemDetails::internal_server_error(Some(req_path.clone())),
        })?;

    // Initialize audit chain head
    let audit_store = PostgresAuditStore::new();
    audit_store
        .initialize_chain_head(&mut tx, ws.id.as_uuid())
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    // Append workspace.created audit event
    let ws_audit_payload = serde_json::json!({
        "workspace_id": ws.id.to_string(),
        "program_id": ws.program_id.to_string(),
        "organization_id": ws.organization_id.to_string(),
        "name": ws.name,
        "workspace_code": ws.workspace_code,
    });

    let ws_audit_params = AppendAuditParams {
        workspace_id: ws.id.into_uuid(),
        actor_type: "principal".to_string(),
        actor_id: Some(principal.id.into_uuid()),
        authority_snapshot: serde_json::json!({}),
        action_code: "WORKSPACE_CREATE".to_string(),
        entity_type: "workspace".to_string(),
        entity_id: ws.id.to_string(),
        entity_version: Some(1),
        request_id: None,
        correlation_id: None,
        job_id: None,
        source_state_hash: None,
        before_ref: None,
        after_ref: None,
        metadata: ws_audit_payload,
    };

    audit_store
        .append_audit_event(&mut tx, ws_audit_params)
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    // Assign creator as workspace Admin
    let membership = Membership::new(ws.id, principal.id, MembershipRole::Admin);
    MembershipRepository::insert(&mut tx, &membership)
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    let mem_audit_payload = serde_json::json!({
        "membership_id": membership.id.to_string(),
        "workspace_id": ws.id.to_string(),
        "principal_id": principal.id.to_string(),
        "role_code": "admin",
    });

    let mem_audit_params = AppendAuditParams {
        workspace_id: ws.id.into_uuid(),
        actor_type: "principal".to_string(),
        actor_id: Some(principal.id.into_uuid()),
        authority_snapshot: serde_json::json!({}),
        action_code: "MEMBERSHIP_CREATE".to_string(),
        entity_type: "membership".to_string(),
        entity_id: membership.id.to_string(),
        entity_version: Some(1),
        request_id: None,
        correlation_id: None,
        job_id: None,
        source_state_hash: None,
        before_ref: None,
        after_ref: None,
        metadata: mem_audit_payload,
    };

    audit_store
        .append_audit_event(&mut tx, mem_audit_params)
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    let dto = WorkspaceDto::from(&ws);
    let resp_body = serde_json::to_value(&dto).ok();

    if let Some(record_id) = record_id_opt {
        IdempotencyCoordinator::complete_record(
            &mut tx,
            &idemp_store,
            record_id,
            StatusCode::CREATED.as_u16(),
            resp_body,
        )
        .await
        .map_err(ProblemDetails::from)?;
    }

    tx.commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path)))?;

    Ok((StatusCode::CREATED, Json(dto)).into_response())
}

/// E10: GET /api/v1/workspaces/{workspace_id}
/// Retrieves details of a specific workspace under RLS isolation and capability authorization.
#[utoipa::path(
    get,
    path = "/api/v1/workspaces/{workspace_id}",
    params(
        ("workspace_id" = String, Path, description = "Workspace unique identifier")
    ),
    responses(
        (status = 200, description = "Workspace details", body = WorkspaceDto),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden: insufficient capabilities", body = ProblemDetails),
        (status = 404, description = "Not found", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "Workspaces"
)]
pub async fn get_workspace_handler(
    State(state): State<AppState>,
    Path(workspace_id_str): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let req_path = format!("/api/v1/workspaces/{workspace_id_str}");
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
            // Privacy-safe: Foreign or unmembered workspaces return 404 Not Found
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

    let ws = WorkspaceRepository::get_by_id(ws_tx.conn(), awc.workspace_id())
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?
        .ok_or_else(|| {
            ProblemDetails::not_found(
                format!("Workspace '{}' was not found", workspace_id_str),
                Some(req_path.clone()),
            )
        })?;

    ws_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path)))?;

    Ok((StatusCode::OK, Json(WorkspaceDto::from(&ws))).into_response())
}
