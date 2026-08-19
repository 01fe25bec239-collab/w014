//! Program management API endpoints (E05: List Programs, E06: Create Program, E07: Get Program).

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use w014_application::authn::SessionAuthnService;
use w014_application::persistence::{PrincipalRepository, ProgramRepository};
use w014_application::services::IdempotencyCoordinator;
use w014_authn::error::AuthnError;
use w014_authn::session::SessionCookieBuilder;
use w014_domain::ids::ProgramId;
use w014_domain::principal::Principal;
use w014_domain::program::Program;
use w014_persistence::idempotency::{IdempotencyCheckResult, PostgresIdempotencyStore};

use crate::AppState;
use crate::error::ProblemDetails;

/// Query parameters for cursor-based pagination.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct PaginationQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

/// Request payload for creating a program (E06).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateProgramDto {
    pub name: String,
    pub slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Response payload representing a program domain entity (E05, E06, E07).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProgramDto {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&Program> for ProgramDto {
    fn from(p: &Program) -> Self {
        Self {
            id: p.id.to_string(),
            organization_id: p.organization_id.to_string(),
            name: p.name.clone(),
            slug: p.slug.clone(),
            description: p.description.clone(),
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

/// Paginated page of programs (E05).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProgramPage {
    pub items: Vec<ProgramDto>,
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

/// E05: GET /api/v1/programs
/// Lists programs within the caller's organization.
#[utoipa::path(
    get,
    path = "/api/v1/programs",
    params(PaginationQuery),
    responses(
        (status = 200, description = "Paginated list of programs", body = ProgramPage),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "Programs"
)]
pub async fn list_programs_handler(
    State(state): State<AppState>,
    Query(pagination): Query<PaginationQuery>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let (_session, principal) = authenticate_caller(&state, &headers, "/api/v1/programs").await?;

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| ProblemDetails::internal_server_error(Some("/api/v1/programs".into())))?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some("/api/v1/programs".into())))?;

    let cursor_uuid = pagination
        .cursor
        .as_deref()
        .and_then(|c| Uuid::parse_str(c).ok());
    let limit = pagination.limit.unwrap_or(50).clamp(1, 100) as i64;

    let (programs, next_cursor, has_more) = ProgramRepository::list_by_organization(
        &mut tx,
        principal.organization_id,
        cursor_uuid,
        limit,
    )
    .await
    .map_err(|_| ProblemDetails::internal_server_error(Some("/api/v1/programs".into())))?;

    tx.commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some("/api/v1/programs".into())))?;

    let items = programs.iter().map(ProgramDto::from).collect();
    let page = ProgramPage {
        items,
        next_cursor,
        has_more,
    };

    Ok((StatusCode::OK, Json(page)).into_response())
}

/// E06: POST /api/v1/programs
/// Creates a new program within the caller's organization.
#[utoipa::path(
    post,
    path = "/api/v1/programs",
    request_body = CreateProgramDto,
    responses(
        (status = 201, description = "Program created successfully", body = ProgramDto),
        (status = 400, description = "Bad Request", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden: CSRF check failed or missing capability", body = ProblemDetails),
        (status = 409, description = "Conflict: program slug already exists in organization", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "Programs"
)]
pub async fn create_program_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateProgramDto>,
) -> Result<Response, ProblemDetails> {
    // 1. Authenticate caller first
    let (session, principal) = authenticate_caller(&state, &headers, "/api/v1/programs").await?;

    // 2. CSRF exact Origin and token validation (fail closed before any DB mutation or idempotency consumption)
    state
        .csrf_protector
        .validate_request(
            &Method::POST,
            &headers,
            true,
            Some(&session.rotation_identity()),
        )
        .map_err(ProblemDetails::from)?;

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| ProblemDetails::internal_server_error(Some("/api/v1/programs".into())))?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some("/api/v1/programs".into())))?;

    let idemp_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let payload_val = serde_json::to_value(&payload)
        .map_err(|e| ProblemDetails::bad_request(e.to_string(), None))?;
    let req_hash = IdempotencyCoordinator::compute_payload_hash(&payload_val);
    let idemp_store = PostgresIdempotencyStore::new();

    let record_id_opt = if let Some(ref key) = idemp_key {
        match IdempotencyCoordinator::evaluate_key(
            &mut tx,
            &idemp_store,
            None,
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
                    Some("/api/v1/programs".into()),
                ));
            }
            IdempotencyCheckResult::InProgress => {
                return Err(ProblemDetails::bad_request(
                    "Request with this idempotency key is currently in progress",
                    Some("/api/v1/programs".into()),
                ));
            }
            IdempotencyCheckResult::Acquired { record_id } => Some(record_id),
        }
    } else {
        None
    };

    // 3. Domain validation & Conflict check
    if let Some(_existing) = ProgramRepository::get_by_organization_and_slug(
        &mut tx,
        principal.organization_id,
        &payload.slug,
    )
    .await
    .map_err(|_| ProblemDetails::internal_server_error(Some("/api/v1/programs".into())))?
    {
        return Err(ProblemDetails::conflict(
            format!(
                "Program with slug '{}' already exists in this organization",
                payload.slug
            ),
            Some("/api/v1/programs".into()),
        ));
    }

    let program = Program::new(
        principal.organization_id,
        payload.name,
        payload.slug,
        payload.description,
    )
    .map_err(|e| ProblemDetails::bad_request(e.to_string(), Some("/api/v1/programs".into())))?;

    ProgramRepository::insert(&mut tx, &program)
        .await
        .map_err(|e| match e {
            w014_persistence::error::PersistenceError::Connection(ref sqlx_err)
                if sqlx_err.to_string().contains("duplicate key")
                    || sqlx_err.to_string().contains("uq_programs_org_slug") =>
            {
                ProblemDetails::conflict(
                    "Program slug already exists",
                    Some("/api/v1/programs".into()),
                )
            }
            _ => ProblemDetails::internal_server_error(Some("/api/v1/programs".into())),
        })?;

    let dto = ProgramDto::from(&program);
    let resp_body = serde_json::to_value(&dto).ok();

    if let Some(record_id) = record_id_opt {
        IdempotencyCoordinator::complete_record(
            &mut tx,
            &idemp_store,
            record_id,
            StatusCode::CREATED.as_u16(),
            None,
            resp_body,
        )
        .await
        .map_err(ProblemDetails::from)?;
    }

    tx.commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some("/api/v1/programs".into())))?;

    Ok((StatusCode::CREATED, Json(dto)).into_response())
}

/// E07: GET /api/v1/programs/{program_id}
/// Retrieves details of a specific program within the caller's organization.
#[utoipa::path(
    get,
    path = "/api/v1/programs/{program_id}",
    params(
        ("program_id" = String, Path, description = "Program unique identifier")
    ),
    responses(
        (status = 200, description = "Program details", body = ProgramDto),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 404, description = "Not found", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "Programs"
)]
pub async fn get_program_handler(
    State(state): State<AppState>,
    Path(program_id_str): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let (_session, principal) = authenticate_caller(
        &state,
        &headers,
        &format!("/api/v1/programs/{program_id_str}"),
    )
    .await?;

    let program_uuid = Uuid::parse_str(&program_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Program '{}' was not found", program_id_str),
            Some(format!("/api/v1/programs/{program_id_str}")),
        )
    })?;

    let pool = state.pool.as_ref().ok_or_else(|| {
        ProblemDetails::internal_server_error(Some(format!("/api/v1/programs/{program_id_str}")))
    })?;

    let mut tx = pool.begin().await.map_err(|_| {
        ProblemDetails::internal_server_error(Some(format!("/api/v1/programs/{program_id_str}")))
    })?;

    let program = ProgramRepository::get_by_id(&mut tx, ProgramId::from_uuid(program_uuid))
        .await
        .map_err(|_| {
            ProblemDetails::internal_server_error(Some(format!(
                "/api/v1/programs/{program_id_str}"
            )))
        })?
        .ok_or_else(|| {
            ProblemDetails::not_found(
                format!("Program '{}' was not found", program_id_str),
                Some(format!("/api/v1/programs/{program_id_str}")),
            )
        })?;

    // Privacy-safe tenant boundary isolation: foreign program returns 404 Not Found
    if program.organization_id != principal.organization_id {
        return Err(ProblemDetails::not_found(
            format!("Program '{}' was not found", program_id_str),
            Some(format!("/api/v1/programs/{program_id_str}")),
        ));
    }

    tx.commit().await.map_err(|_| {
        ProblemDetails::internal_server_error(Some(format!("/api/v1/programs/{program_id_str}")))
    })?;

    Ok((StatusCode::OK, Json(ProgramDto::from(&program))).into_response())
}
