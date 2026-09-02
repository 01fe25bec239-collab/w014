//! Document Registry and Presign API routes (E16-E24).
//!
//! Implements:
//! - E16: GET  /api/v1/workspaces/{workspace_id}/documents
//! - E17: POST /api/v1/workspaces/{workspace_id}/documents
//! - E18: GET  /api/v1/workspaces/{workspace_id}/documents/{document_id}
//! - E19: GET  /api/v1/workspaces/{workspace_id}/documents/{document_id}/versions
//! - E20: POST /api/v1/workspaces/{workspace_id}/documents/{document_id}/upload-intents
//! - E21: POST /api/v1/workspaces/{workspace_id}/upload-intents/{intent_id}/finalize (deferred to WI-0203)
//! - E22: GET  /api/v1/workspaces/{workspace_id}/document-versions/{version_id}
//! - E23: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/accept
//! - E24: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download

#![allow(clippy::result_large_err)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::header::{HeaderMap, HeaderValue, IF_MATCH};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use w014_application::authn::SessionAuthnService;
use w014_application::authz::{
    DatabaseRole, WorkspaceAuthzResolver, WorkspaceTransaction, WorkspaceTxOptions,
};
use w014_application::error::ApplicationError;
use w014_application::persistence::{
    DocumentRepository, DocumentVersionRepository, ObjectArtifactRepository, PrincipalRepository,
    UploadIntentRepository,
};
use w014_application::services::document_service::FinalizeUploadError;
use w014_application::services::{
    DocumentService, IdempotencyCoordinator, can_manage_documents, can_read_documents,
    can_upload_documents,
};
use w014_authn::error::AuthnError;
use w014_authn::session::SessionCookieBuilder;
use w014_domain::ids::{DocumentId, DocumentVersionId, WorkspaceId};
use w014_domain::limits::MAX_UPLOAD_BYTES;
use w014_domain::principal::Principal;
use w014_domain::{Document, DocumentClass, DocumentVersion, MediaType, Sha256, UploadIntent};
use w014_persistence::audit::{AppendAuditParams, AuditAppendContract, PostgresAuditStore};
use w014_persistence::idempotency::{IdempotencyCheckResult, PostgresIdempotencyStore};

use crate::AppState;
use crate::error::ProblemDetails;
use crate::routes::programs::PaginationQuery;

// ============================================================================
// DTOs & Schemas
// ============================================================================

/// Request body for creating a logical document.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateDocumentDto {
    pub title: String,
    pub document_class: String,
}

/// Logical document representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DocumentDto {
    pub id: String,
    pub workspace_id: String,
    pub title: String,
    pub document_class: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_version_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i32,
}

impl From<&Document> for DocumentDto {
    fn from(doc: &Document) -> Self {
        Self {
            id: doc.id.to_string(),
            workspace_id: doc.workspace_id.to_string(),
            title: doc.title.clone(),
            document_class: doc.document_class.as_str().to_string(),
            status: doc.status.as_str().to_string(),
            current_version_id: doc.current_version_id.map(|v| v.to_string()),
            created_by: doc.created_by.map(|p| p.to_string()),
            created_at: doc.created_at,
            updated_at: doc.updated_at,
            row_version: doc.row_version,
        }
    }
}

/// Paginated page of logical documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DocumentPage {
    pub items: Vec<DocumentDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// Immutable document version representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DocumentVersionDto {
    pub id: String,
    pub document_id: String,
    pub workspace_id: String,
    pub version_number: u32,
    pub object_artifact_id: String,
    pub byte_size: i64,
    pub sha256_hash: String,
    pub content_type: String,
    pub original_filename: String,
    pub trust_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitted_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<&DocumentVersion> for DocumentVersionDto {
    fn from(v: &DocumentVersion) -> Self {
        Self {
            id: v.id.to_string(),
            document_id: v.document_id.to_string(),
            workspace_id: v.workspace_id.to_string(),
            version_number: v.version_ordinal.get(),
            object_artifact_id: v.object_artifact_id.to_string(),
            byte_size: v.byte_size,
            sha256_hash: v.sha256_hash.to_hex(),
            content_type: v.content_type.as_str().to_string(),
            original_filename: v.original_filename.clone(),
            trust_state: v.trust_state.as_str().to_string(),
            submitted_by: v.submitted_by.map(|p| p.to_string()),
            created_at: v.created_at,
        }
    }
}

/// Paginated page of document versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DocumentVersionPage {
    pub items: Vec<DocumentVersionDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// Request body for creating an upload intent.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateUploadIntentDto {
    pub filename: String,
    pub media_type: String,
    pub byte_length: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_b64: Option<String>,
}

/// Presigned PUT contract returned in upload intent response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PresignedPutDto {
    pub upload_url: String,
    pub method: String,
    pub expires_at: DateTime<Utc>,
    pub headers: HashMap<String, String>,
}

/// Upload intent representation with presigned upload contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UploadIntentDto {
    pub id: String,
    pub workspace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    pub filename: String,
    pub expected_media_type: String,
    pub expected_length: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_sha256_b64: Option<String>,
    pub opaque_object_key: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub presigned_put: PresignedPutDto,
}

/// Download signing response (E24).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DownloadDto {
    pub download_url: String,
    pub expires_at: DateTime<Utc>,
    pub content_type: String,
    pub byte_size: i64,
    pub sha256_hash: String,
    pub original_filename: String,
}

/// Upload finalization response (E21).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UploadFinalizeDto {
    pub upload_intent_id: String,
    pub document_id: String,
    pub document_version_id: String,
    pub version_number: u32,
    pub object_artifact_id: String,
    pub quarantine_record_id: String,
    pub scan_job_id: String,
    pub status: String,
    pub trust_state: String,
}

// ============================================================================
// Problem Details Helper Constructors & Authentication
// ============================================================================

fn payload_too_large(detail: impl Into<String>, instance: Option<String>) -> ProblemDetails {
    ProblemDetails {
        type_uri: "urn:w014:error:payload-too-large".to_string(),
        title: "Payload Too Large".to_string(),
        status: StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
        detail: Some(detail.into()),
        instance,
        code: Some("PAYLOAD_TOO_LARGE".to_string()),
        correlation_id: None,
    }
}

fn unsupported_media_type(detail: impl Into<String>, instance: Option<String>) -> ProblemDetails {
    ProblemDetails {
        type_uri: "urn:w014:error:unsupported-media-type".to_string(),
        title: "Unsupported Media Type".to_string(),
        status: StatusCode::UNSUPPORTED_MEDIA_TYPE.as_u16(),
        detail: Some(detail.into()),
        instance,
        code: Some("UNSUPPORTED_MEDIA_TYPE".to_string()),
        correlation_id: None,
    }
}

fn precondition_failed(detail: impl Into<String>, instance: Option<String>) -> ProblemDetails {
    ProblemDetails {
        type_uri: "urn:w014:error:precondition-failed".to_string(),
        title: "Precondition Failed".to_string(),
        status: StatusCode::PRECONDITION_FAILED.as_u16(),
        detail: Some(detail.into()),
        instance,
        code: Some("PRECONDITION_FAILED".to_string()),
        correlation_id: None,
    }
}

fn unprocessable_entity(detail: impl Into<String>, instance: Option<String>) -> ProblemDetails {
    ProblemDetails {
        type_uri: "urn:w014:error:unprocessable-entity".to_string(),
        title: "Unprocessable Entity".to_string(),
        status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
        detail: Some(detail.into()),
        instance,
        code: Some("UNPROCESSABLE_ENTITY".to_string()),
        correlation_id: None,
    }
}

fn parse_if_match_header(header_val: &HeaderValue) -> Result<i32, ProblemDetails> {
    let raw = header_val
        .to_str()
        .map_err(|_| ProblemDetails::bad_request("Invalid If-Match header value", None))?;
    let trimmed = raw.trim().trim_start_matches("W/").trim_matches('"');
    trimmed.parse::<i32>().map_err(|_| {
        ProblemDetails::bad_request(
            format!("If-Match header must be an integer row_version, got '{raw}'"),
            None,
        )
    })
}

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

// ============================================================================
// Route Handlers
// ============================================================================

/// E16: GET /api/v1/workspaces/{workspace_id}/documents
#[utoipa::path(
    get,
    path = "/api/v1/workspaces/{workspace_id}/documents",
    params(
        ("workspace_id" = String, Path, description = "Workspace identifier (UUID)"),
        PaginationQuery
    ),
    responses(
        (status = 200, description = "Paginated list of documents", body = DocumentPage),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 404, description = "Workspace not found", body = ProblemDetails)
    ),
    tag = "Documents"
)]
pub async fn list_documents_handler(
    State(state): State<AppState>,
    Path(workspace_id_str): Path<String>,
    Query(pagination): Query<PaginationQuery>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let req_path = format!("/api/v1/workspaces/{workspace_id_str}/documents");
    let (_session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

    let ws_uuid = Uuid::parse_str(&workspace_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Workspace '{workspace_id_str}' was not found"),
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

    let awc = WorkspaceAuthzResolver::resolve(
        &mut setup_tx,
        WorkspaceId::from_uuid(ws_uuid),
        principal.id,
        now,
    )
    .await
    .map_err(|_| {
        ProblemDetails::not_found(
            "Workspace not found or access denied",
            Some(req_path.clone()),
        )
    })?;

    setup_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    if !can_read_documents(&awc) {
        return Err(ProblemDetails::forbidden(
            "DOCUMENT_READ capability required",
            Some(req_path),
        ));
    }

    let limit = i64::from(pagination.limit.unwrap_or(50).clamp(1, 100));
    let cursor_uuid = pagination
        .cursor
        .as_deref()
        .and_then(|c| Uuid::parse_str(c).ok());

    let tx_opts = WorkspaceTxOptions::new()
        .with_client_workspace(awc.workspace_id())
        .with_role(DatabaseRole::App);
    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc, tx_opts).await?;

    let (docs, next_cursor, has_more) =
        DocumentRepository::list_by_workspace(ws_tx.conn(), awc.workspace_id(), cursor_uuid, limit)
            .await
            .map_err(|e| ProblemDetails::internal_server_error(Some(e.to_string())))?;

    let items: Vec<DocumentDto> = docs.iter().map(DocumentDto::from).collect();
    Ok((
        StatusCode::OK,
        Json(DocumentPage {
            items,
            next_cursor,
            has_more,
        }),
    )
        .into_response())
}

/// E17: POST /api/v1/workspaces/{workspace_id}/documents
#[utoipa::path(
    post,
    path = "/api/v1/workspaces/{workspace_id}/documents",
    params(
        ("workspace_id" = String, Path, description = "Workspace identifier (UUID)")
    ),
    request_body = CreateDocumentDto,
    responses(
        (status = 201, description = "Logical document created", body = DocumentDto),
        (status = 400, description = "Bad Request", body = ProblemDetails),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 409, description = "Conflict", body = ProblemDetails)
    ),
    tag = "Documents"
)]
pub async fn create_document_handler(
    State(state): State<AppState>,
    Path(workspace_id_str): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<CreateDocumentDto>,
) -> Result<Response, ProblemDetails> {
    let req_path = format!("/api/v1/workspaces/{workspace_id_str}/documents");
    let (session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

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
            format!("Workspace '{workspace_id_str}' was not found"),
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

    let awc = WorkspaceAuthzResolver::resolve(
        &mut setup_tx,
        WorkspaceId::from_uuid(ws_uuid),
        principal.id,
        now,
    )
    .await
    .map_err(|_| {
        ProblemDetails::not_found(
            "Workspace not found or access denied",
            Some(req_path.clone()),
        )
    })?;

    setup_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    if !can_upload_documents(&awc) {
        return Err(ProblemDetails::forbidden(
            "DOCUMENT_UPLOAD capability required",
            Some(req_path),
        ));
    }

    let doc_class = DocumentClass::parse(&payload.document_class)
        .map_err(|e| ProblemDetails::bad_request(e.to_string(), Some(req_path.clone())))?;

    let title_trimmed = payload.title.trim();
    if title_trimmed.is_empty() || title_trimmed.len() > 512 {
        return Err(ProblemDetails::bad_request(
            "Title must be between 1 and 512 bytes",
            Some(req_path.clone()),
        ));
    }

    let idemp_header = headers.get("idempotency-key").ok_or_else(|| {
        ProblemDetails::bad_request("Idempotency-Key header is required", Some(req_path.clone()))
    })?;
    let idemp_key_raw = idemp_header.to_str().map_err(|_| {
        ProblemDetails::bad_request("Invalid Idempotency-Key header", Some(req_path.clone()))
    })?;

    let tx_opts = WorkspaceTxOptions::new()
        .with_client_workspace(awc.workspace_id())
        .with_role(DatabaseRole::App);
    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc, tx_opts).await?;

    let payload_val = serde_json::json!({
        "workspace_id": workspace_id_str,
        "title": title_trimmed,
        "document_class": doc_class.as_str(),
    });

    let req_hash = IdempotencyCoordinator::compute_payload_hash(&payload_val);
    let idemp_store = PostgresIdempotencyStore::new();
    let key_hash = IdempotencyCoordinator::compute_key_hash(
        &state.config.session.active_hmac_secret,
        idemp_key_raw,
    );

    let eval_res = IdempotencyCoordinator::evaluate_key(
        ws_tx.conn(),
        &idemp_store,
        Some(awc.workspace_id()),
        principal.id,
        "DOCUMENT_CREATE",
        &key_hash,
        &req_hash,
        86400,
    )
    .await
    .map_err(ProblemDetails::from)?;

    let idemp_record_id = match eval_res {
        IdempotencyCheckResult::Replay {
            status_code, body, ..
        } => {
            ws_tx.commit().await?;
            let sc = StatusCode::from_u16(status_code).unwrap_or(StatusCode::CREATED);
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
        IdempotencyCheckResult::Acquired { record_id } => record_id,
    };

    let doc = Document::new(
        awc.workspace_id(),
        title_trimmed,
        doc_class,
        Some(principal.id),
    )
    .map_err(|e| ProblemDetails::bad_request(e.to_string(), Some(req_path.clone())))?;

    DocumentRepository::insert(ws_tx.conn(), &doc)
        .await
        .map_err(|e| ProblemDetails::internal_server_error(Some(e.to_string())))?;

    let audit_store = PostgresAuditStore::new();
    let audit_params = AppendAuditParams {
        workspace_id: awc.workspace_id().into_uuid(),
        actor_type: "principal".to_string(),
        actor_id: Some(principal.id.into_uuid()),
        authority_snapshot: serde_json::json!({}),
        action_code: "DOCUMENT_CREATE".to_string(),
        entity_type: "document".to_string(),
        entity_id: doc.id.to_string(),
        entity_version: Some(1),
        request_id: None,
        correlation_id: None,
        job_id: None,
        source_state_hash: None,
        before_ref: None,
        after_ref: Some(serde_json::json!(doc.id.to_string())),
        metadata: serde_json::json!({
            "document_id": doc.id.to_string(),
            "workspace_id": doc.workspace_id.to_string(),
            "title": doc.title,
            "document_class": doc.document_class.as_str(),
        }),
    };

    audit_store
        .append_audit_event(ws_tx.conn(), audit_params)
        .await
        .map_err(|e| ProblemDetails::internal_server_error(Some(e.to_string())))?;

    let dto = DocumentDto::from(&doc);
    let resp_body = serde_json::to_value(&dto).ok();
    IdempotencyCoordinator::complete_record(
        ws_tx.conn(),
        &idemp_store,
        idemp_record_id,
        StatusCode::CREATED.as_u16(),
        resp_body,
    )
    .await?;

    ws_tx.commit().await?;
    Ok((StatusCode::CREATED, Json(dto)).into_response())
}

/// E18: GET /api/v1/workspaces/{workspace_id}/documents/{document_id}
#[utoipa::path(
    get,
    path = "/api/v1/workspaces/{workspace_id}/documents/{document_id}",
    params(
        ("workspace_id" = String, Path, description = "Workspace identifier (UUID)"),
        ("document_id" = String, Path, description = "Document identifier (UUID)")
    ),
    responses(
        (status = 200, description = "Logical document details", body = DocumentDto),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 404, description = "Document or workspace not found", body = ProblemDetails)
    ),
    tag = "Documents"
)]
pub async fn get_document_handler(
    State(state): State<AppState>,
    Path((workspace_id_str, document_id_str)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let req_path = format!("/api/v1/workspaces/{workspace_id_str}/documents/{document_id_str}");
    let (_session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

    let ws_uuid = Uuid::parse_str(&workspace_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Workspace '{workspace_id_str}' was not found"),
            Some(req_path.clone()),
        )
    })?;

    let doc_uuid = Uuid::parse_str(&document_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Document '{document_id_str}' was not found"),
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

    let awc = WorkspaceAuthzResolver::resolve(
        &mut setup_tx,
        WorkspaceId::from_uuid(ws_uuid),
        principal.id,
        now,
    )
    .await
    .map_err(|_| {
        ProblemDetails::not_found(
            "Workspace not found or access denied",
            Some(req_path.clone()),
        )
    })?;

    setup_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    if !can_read_documents(&awc) {
        return Err(ProblemDetails::forbidden(
            "DOCUMENT_READ capability required",
            Some(req_path),
        ));
    }

    let tx_opts = WorkspaceTxOptions::new()
        .with_client_workspace(awc.workspace_id())
        .with_role(DatabaseRole::App);
    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc, tx_opts).await?;

    let doc = DocumentRepository::get_by_id(
        ws_tx.conn(),
        awc.workspace_id(),
        DocumentId::from_uuid(doc_uuid),
    )
    .await
    .map_err(|e| ProblemDetails::internal_server_error(Some(e.to_string())))?
    .ok_or_else(|| {
        ProblemDetails::not_found(
            format!("Document '{document_id_str}' not found"),
            Some(req_path),
        )
    })?;

    Ok((StatusCode::OK, Json(DocumentDto::from(&doc))).into_response())
}

/// E19: GET /api/v1/workspaces/{workspace_id}/documents/{document_id}/versions
#[utoipa::path(
    get,
    path = "/api/v1/workspaces/{workspace_id}/documents/{document_id}/versions",
    params(
        ("workspace_id" = String, Path, description = "Workspace identifier (UUID)"),
        ("document_id" = String, Path, description = "Document identifier (UUID)"),
        PaginationQuery
    ),
    responses(
        (status = 200, description = "Paginated list of document versions", body = DocumentVersionPage),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 404, description = "Document or workspace not found", body = ProblemDetails)
    ),
    tag = "Documents"
)]
pub async fn list_document_versions_handler(
    State(state): State<AppState>,
    Path((workspace_id_str, document_id_str)): Path<(String, String)>,
    Query(pagination): Query<PaginationQuery>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let req_path =
        format!("/api/v1/workspaces/{workspace_id_str}/documents/{document_id_str}/versions");
    let (_session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

    let ws_uuid = Uuid::parse_str(&workspace_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Workspace '{workspace_id_str}' was not found"),
            Some(req_path.clone()),
        )
    })?;

    let doc_uuid = Uuid::parse_str(&document_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Document '{document_id_str}' was not found"),
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

    let awc = WorkspaceAuthzResolver::resolve(
        &mut setup_tx,
        WorkspaceId::from_uuid(ws_uuid),
        principal.id,
        now,
    )
    .await
    .map_err(|_| {
        ProblemDetails::not_found(
            "Workspace not found or access denied",
            Some(req_path.clone()),
        )
    })?;

    setup_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    if !can_read_documents(&awc) {
        return Err(ProblemDetails::forbidden(
            "DOCUMENT_READ capability required",
            Some(req_path),
        ));
    }

    let limit = i64::from(pagination.limit.unwrap_or(50).clamp(1, 100));
    let cursor_uuid = pagination
        .cursor
        .as_deref()
        .and_then(|c| Uuid::parse_str(c).ok());

    let tx_opts = WorkspaceTxOptions::new()
        .with_client_workspace(awc.workspace_id())
        .with_role(DatabaseRole::App);
    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc, tx_opts).await?;

    // Verify document exists in workspace
    DocumentRepository::get_by_id(
        ws_tx.conn(),
        awc.workspace_id(),
        DocumentId::from_uuid(doc_uuid),
    )
    .await
    .map_err(|e| ProblemDetails::internal_server_error(Some(e.to_string())))?
    .ok_or_else(|| {
        ProblemDetails::not_found(
            format!("Document '{document_id_str}' not found"),
            Some(req_path.clone()),
        )
    })?;

    let (versions, next_cursor, has_more) = DocumentVersionRepository::list_by_document(
        ws_tx.conn(),
        awc.workspace_id(),
        DocumentId::from_uuid(doc_uuid),
        cursor_uuid,
        limit,
    )
    .await
    .map_err(|e| ProblemDetails::internal_server_error(Some(e.to_string())))?;

    let items: Vec<DocumentVersionDto> = versions.iter().map(DocumentVersionDto::from).collect();
    Ok((
        StatusCode::OK,
        Json(DocumentVersionPage {
            items,
            next_cursor,
            has_more,
        }),
    )
        .into_response())
}

/// E20: POST /api/v1/workspaces/{workspace_id}/documents/{document_id}/upload-intents
#[utoipa::path(
    post,
    path = "/api/v1/workspaces/{workspace_id}/documents/{document_id}/upload-intents",
    params(
        ("workspace_id" = String, Path, description = "Workspace identifier (UUID)"),
        ("document_id" = String, Path, description = "Document identifier (UUID)")
    ),
    request_body = CreateUploadIntentDto,
    responses(
        (status = 201, description = "Upload intent created with presigned contract", body = UploadIntentDto),
        (status = 400, description = "Bad Request", body = ProblemDetails),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 404, description = "Document not found", body = ProblemDetails),
        (status = 413, description = "Payload Too Large (>100MiB)", body = ProblemDetails),
        (status = 415, description = "Unsupported Media Type", body = ProblemDetails)
    ),
    tag = "Documents"
)]
pub async fn create_upload_intent_handler(
    State(state): State<AppState>,
    Path((workspace_id_str, document_id_str)): Path<(String, String)>,
    headers: HeaderMap,
    Json(payload): Json<CreateUploadIntentDto>,
) -> Result<Response, ProblemDetails> {
    let req_path =
        format!("/api/v1/workspaces/{workspace_id_str}/documents/{document_id_str}/upload-intents");
    let (session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

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
            format!("Workspace '{workspace_id_str}' was not found"),
            Some(req_path.clone()),
        )
    })?;

    let doc_uuid = Uuid::parse_str(&document_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Document '{document_id_str}' was not found"),
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

    let awc = WorkspaceAuthzResolver::resolve(
        &mut setup_tx,
        WorkspaceId::from_uuid(ws_uuid),
        principal.id,
        now,
    )
    .await
    .map_err(|_| {
        ProblemDetails::not_found(
            "Workspace not found or access denied",
            Some(req_path.clone()),
        )
    })?;

    setup_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    if !can_upload_documents(&awc) {
        return Err(ProblemDetails::forbidden(
            "DOCUMENT_UPLOAD capability required",
            Some(req_path),
        ));
    }

    // Validate media type against frozen P0 allowlist (PDF, DOCX)
    let media_type = MediaType::parse(&payload.media_type).map_err(|_| {
        unsupported_media_type(
            format!(
                "Media type '{}' is not supported. Allowed: PDF, DOCX",
                payload.media_type
            ),
            Some(req_path.clone()),
        )
    })?;

    // Validate byte length
    if payload.byte_length < 1 {
        return Err(ProblemDetails::bad_request(
            "byte_length must be at least 1 byte",
            Some(req_path.clone()),
        ));
    }
    if payload.byte_length > MAX_UPLOAD_BYTES {
        return Err(payload_too_large(
            format!(
                "Declared upload size {} exceeds 100 MiB limit",
                payload.byte_length
            ),
            Some(req_path.clone()),
        ));
    }

    // Validate filename
    let filename_trimmed = payload.filename.trim();
    if filename_trimmed.is_empty() || filename_trimmed.len() > 255 {
        return Err(ProblemDetails::bad_request(
            "filename must be between 1 and 255 bytes",
            Some(req_path.clone()),
        ));
    }

    // Mandatory SHA-256 validation (CREATE_UPLOAD_SHA256_REQUIRED: YES, SHA256_EMPTY_DIGEST_FALLBACK: ABSENT)
    let sha256_raw = payload
        .sha256_b64
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            ProblemDetails::bad_request(
                "sha256_b64 is required: upload-intent checksum integrity is mandatory",
                Some(req_path.clone()),
            )
        })?;

    let sha256 = Sha256::from_base64("sha256_b64", sha256_raw)
        .map_err(|e| ProblemDetails::bad_request(e.to_string(), Some(req_path.clone())))?;

    if sha256 == Sha256::digest(b"") {
        return Err(ProblemDetails::bad_request(
            "sha256_b64 cannot be the empty digest fallback",
            Some(req_path.clone()),
        ));
    }

    let tx_opts = WorkspaceTxOptions::new()
        .with_client_workspace(awc.workspace_id())
        .with_role(DatabaseRole::App);
    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc, tx_opts).await?;

    // Verify document exists in workspace
    let doc = DocumentRepository::get_by_id(
        ws_tx.conn(),
        awc.workspace_id(),
        DocumentId::from_uuid(doc_uuid),
    )
    .await
    .map_err(|e| ProblemDetails::internal_server_error(Some(e.to_string())))?
    .ok_or_else(|| {
        ProblemDetails::not_found(
            format!("Document '{document_id_str}' not found"),
            Some(req_path.clone()),
        )
    })?;

    let idemp_header = headers.get("idempotency-key");
    let idemp_store = PostgresIdempotencyStore::new();
    let idemp_record_id = if let Some(hdr) = idemp_header {
        let key_raw = hdr.to_str().map_err(|_| {
            ProblemDetails::bad_request("Invalid Idempotency-Key", Some(req_path.clone()))
        })?;
        let payload_val = serde_json::json!({
            "workspace_id": workspace_id_str,
            "document_id": document_id_str,
            "filename": filename_trimmed,
            "media_type": media_type.as_str(),
            "byte_length": payload.byte_length,
            "sha256_b64": payload.sha256_b64,
        });

        let req_hash = IdempotencyCoordinator::compute_payload_hash(&payload_val);
        let key_hash = IdempotencyCoordinator::compute_key_hash(
            &state.config.session.active_hmac_secret,
            key_raw,
        );

        let eval = IdempotencyCoordinator::evaluate_key(
            ws_tx.conn(),
            &idemp_store,
            Some(awc.workspace_id()),
            principal.id,
            "UPLOAD_INTENT_CREATE",
            &key_hash,
            &req_hash,
            86400,
        )
        .await
        .map_err(ProblemDetails::from)?;

        match eval {
            IdempotencyCheckResult::Replay {
                status_code, body, ..
            } => {
                ws_tx.commit().await?;
                let sc = StatusCode::from_u16(status_code).unwrap_or(StatusCode::CREATED);
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

    let expires_at = now + Duration::minutes(10);
    let intent = UploadIntent::new(
        awc.workspace_id(),
        principal.id,
        Some(doc.id),
        filename_trimmed,
        media_type,
        payload.byte_length,
        Some(sha256),
        expires_at,
    )
    .map_err(|e| ProblemDetails::bad_request(e.to_string(), Some(req_path.clone())))?;

    UploadIntentRepository::insert(ws_tx.conn(), &intent)
        .await
        .map_err(|e| ProblemDetails::internal_server_error(Some(e.to_string())))?;

    let audit_store = PostgresAuditStore::new();
    let audit_params = AppendAuditParams {
        workspace_id: awc.workspace_id().into_uuid(),
        actor_type: "principal".to_string(),
        actor_id: Some(principal.id.into_uuid()),
        authority_snapshot: serde_json::json!({}),
        action_code: "UPLOAD_INTENT_CREATE".to_string(),
        entity_type: "upload_intent".to_string(),
        entity_id: intent.id.to_string(),
        entity_version: Some(1),
        request_id: None,
        correlation_id: None,
        job_id: None,
        source_state_hash: None,
        before_ref: None,
        after_ref: Some(serde_json::json!(intent.id.to_string())),
        metadata: serde_json::json!({
            "upload_intent_id": intent.id.to_string(),
            "workspace_id": intent.workspace_id.to_string(),
            "document_id": doc.id.to_string(),
            "filename": intent.filename,
            "expected_media_type": intent.expected_media_type.as_str(),
            "expected_length": intent.expected_length,
        }),
    };

    audit_store
        .append_audit_event(ws_tx.conn(), audit_params)
        .await
        .map_err(|e| ProblemDetails::internal_server_error(Some(e.to_string())))?;

    let presigned_contract = DocumentService::generate_presigned_put(
        "w014-documents",
        intent.opaque_object_key.as_str(),
        media_type,
        payload.byte_length,
        sha256_raw,
        expires_at,
    )
    .map_err(|e| match e {
        FinalizeUploadError::PreconditionFailed(msg) => {
            precondition_failed(msg, Some(req_path.clone()))
        }
        FinalizeUploadError::PayloadTooLarge(msg) => payload_too_large(msg, Some(req_path.clone())),
        other => ProblemDetails::internal_server_error(Some(other.to_string())),
    })?;

    let dto = UploadIntentDto {
        id: intent.id.to_string(),
        workspace_id: intent.workspace_id.to_string(),
        document_id: intent.document_id.map(|d| d.to_string()),
        filename: intent.filename.clone(),
        expected_media_type: intent.expected_media_type.as_str().to_string(),
        expected_length: intent.expected_length,
        expected_sha256_b64: intent.expected_sha256_b64.as_ref().map(|s| s.to_base64()),
        opaque_object_key: intent.opaque_object_key.as_str().to_string(),
        status: intent.status.as_str().to_string(),
        expires_at: intent.expires_at,
        created_at: intent.created_at,
        presigned_put: PresignedPutDto {
            upload_url: presigned_contract.upload_url,
            method: presigned_contract.method,
            expires_at: presigned_contract.expires_at,
            headers: presigned_contract.headers,
        },
    };

    if let Some(record_id) = idemp_record_id {
        let resp_body = serde_json::to_value(&dto).ok();
        IdempotencyCoordinator::complete_record(
            ws_tx.conn(),
            &idemp_store,
            record_id,
            StatusCode::CREATED.as_u16(),
            resp_body,
        )
        .await?;
    }

    ws_tx.commit().await?;
    Ok((StatusCode::CREATED, Json(dto)).into_response())
}

/// E21: POST /api/v1/workspaces/{workspace_id}/upload-intents/{intent_id}/finalize
#[utoipa::path(
    post,
    path = "/api/v1/workspaces/{workspace_id}/upload-intents/{intent_id}/finalize",
    params(
        ("workspace_id" = String, Path, description = "Workspace identifier (UUID)"),
        ("intent_id" = String, Path, description = "Upload intent identifier (UUID)")
    ),
    responses(
        (status = 202, description = "Upload finalized and scan job enqueued", body = UploadFinalizeDto),
        (status = 400, description = "Bad Request (Missing Idempotency-Key)", body = ProblemDetails),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 404, description = "Upload intent or workspace not found", body = ProblemDetails),
        (status = 409, description = "Conflict", body = ProblemDetails),
        (status = 412, description = "Precondition Failed", body = ProblemDetails),
        (status = 413, description = "Payload Too Large", body = ProblemDetails),
        (status = 415, description = "Unsupported Media Type", body = ProblemDetails),
        (status = 422, description = "Unprocessable Entity", body = ProblemDetails),
        (status = 501, description = "Not Implemented (Deferred)", body = ProblemDetails)
    ),
    tag = "Documents"
)]
pub async fn finalize_upload_intent_handler(
    State(state): State<AppState>,
    Path((workspace_id_str, intent_id_str)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let req_path =
        format!("/api/v1/workspaces/{workspace_id_str}/upload-intents/{intent_id_str}/finalize");
    let (session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

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
            format!("Workspace '{workspace_id_str}' was not found"),
            Some(req_path.clone()),
        )
    })?;

    let intent_uuid = Uuid::parse_str(&intent_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("UploadIntent '{intent_id_str}' was not found"),
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

    let awc = WorkspaceAuthzResolver::resolve(
        &mut setup_tx,
        WorkspaceId::from_uuid(ws_uuid),
        principal.id,
        now,
    )
    .await
    .map_err(|_| {
        ProblemDetails::not_found(
            "Workspace not found or access denied",
            Some(req_path.clone()),
        )
    })?;

    setup_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    if !can_upload_documents(&awc) {
        return Err(ProblemDetails::forbidden(
            "DOCUMENT_UPLOAD capability required",
            Some(req_path),
        ));
    }

    let idemp_header = headers.get("idempotency-key").ok_or_else(|| {
        ProblemDetails::bad_request("Idempotency-Key header is required", Some(req_path.clone()))
    })?;
    let idemp_key_raw = idemp_header.to_str().map_err(|_| {
        ProblemDetails::bad_request("Invalid Idempotency-Key header", Some(req_path.clone()))
    })?;

    let tx_opts = WorkspaceTxOptions::new()
        .with_client_workspace(awc.workspace_id())
        .with_role(DatabaseRole::App);
    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc, tx_opts).await?;

    let payload_val = serde_json::json!({
        "workspace_id": workspace_id_str,
        "intent_id": intent_id_str,
    });

    let req_hash = IdempotencyCoordinator::compute_payload_hash(&payload_val);
    let idemp_store = PostgresIdempotencyStore::new();
    let key_hash = IdempotencyCoordinator::compute_key_hash(
        &state.config.session.active_hmac_secret,
        idemp_key_raw,
    );

    let eval = IdempotencyCoordinator::evaluate_key(
        ws_tx.conn(),
        &idemp_store,
        Some(awc.workspace_id()),
        principal.id,
        "UPLOAD_FINALIZE",
        &key_hash,
        &req_hash,
        86400,
    )
    .await
    .map_err(ProblemDetails::from)?;

    let idemp_record_id = match eval {
        IdempotencyCheckResult::Replay {
            status_code, body, ..
        } => {
            ws_tx.commit().await?;
            let sc = StatusCode::from_u16(status_code).unwrap_or(StatusCode::ACCEPTED);
            return Ok((sc, Json(body.unwrap_or(payload_val))).into_response());
        }
        IdempotencyCheckResult::Mismatch {
            expected_hash,
            actual_hash,
        } => {
            return Err(ProblemDetails::conflict(
                format!(
                    "Idempotency key reused with different request payload (expected: {expected_hash}, actual: {actual_hash})"
                ),
                Some(req_path),
            ));
        }
        IdempotencyCheckResult::InProgress => {
            return Err(ProblemDetails::conflict(
                "Request with this idempotency key is currently in progress",
                Some(req_path),
            ));
        }
        IdempotencyCheckResult::Acquired { record_id } => record_id,
    };

    let result = DocumentService::execute_finalize_upload_tx(
        ws_tx.conn(),
        &awc,
        principal.id,
        w014_domain::ids::UploadIntentId::from_uuid(intent_uuid),
        now,
        Some(idemp_record_id),
        &idemp_store,
    )
    .await
    .map_err(|e| match e {
        w014_application::services::FinalizeUploadError::Conflict(msg) => {
            ProblemDetails::conflict(msg, Some(req_path.clone()))
        }
        w014_application::services::FinalizeUploadError::PreconditionFailed(msg) => {
            precondition_failed(msg, Some(req_path.clone()))
        }
        w014_application::services::FinalizeUploadError::UnprocessableEntity(msg) => {
            unprocessable_entity(msg, Some(req_path.clone()))
        }
        w014_application::services::FinalizeUploadError::UnsupportedMediaType(msg) => {
            unsupported_media_type(msg, Some(req_path.clone()))
        }
        w014_application::services::FinalizeUploadError::PayloadTooLarge(msg) => {
            payload_too_large(msg, Some(req_path.clone()))
        }
        w014_application::services::FinalizeUploadError::NotFound(msg) => {
            ProblemDetails::not_found(msg, Some(req_path.clone()))
        }
        w014_application::services::FinalizeUploadError::Domain(dom_err) => {
            ProblemDetails::bad_request(dom_err.to_string(), Some(req_path.clone()))
        }
        w014_application::services::FinalizeUploadError::Application(app_err) => {
            ProblemDetails::from(app_err)
        }
        w014_application::services::FinalizeUploadError::Persistence(_)
        | w014_application::services::FinalizeUploadError::Internal(_) => {
            ProblemDetails::internal_server_error(Some(req_path.clone()))
        }
    })?;

    ws_tx.commit().await?;

    let dto = UploadFinalizeDto {
        upload_intent_id: result.intent.id.to_string(),
        document_id: result.document.id.to_string(),
        document_version_id: result.version.id.to_string(),
        version_number: result.version.version_ordinal.get(),
        object_artifact_id: result.artifact.id.to_string(),
        quarantine_record_id: result.quarantine.id.to_string(),
        scan_job_id: result.job_id.to_string(),
        status: "quarantined_processing".to_string(),
        trust_state: result.version.trust_state.as_str().to_string(),
    };

    Ok((StatusCode::ACCEPTED, Json(dto)).into_response())
}

/// E22: GET /api/v1/workspaces/{workspace_id}/document-versions/{version_id}
#[utoipa::path(
    get,
    path = "/api/v1/workspaces/{workspace_id}/document-versions/{version_id}",
    params(
        ("workspace_id" = String, Path, description = "Workspace identifier (UUID)"),
        ("version_id" = String, Path, description = "Document version identifier (UUID)")
    ),
    responses(
        (status = 200, description = "Document version details", body = DocumentVersionDto),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 404, description = "Document version or workspace not found", body = ProblemDetails)
    ),
    tag = "Documents"
)]
pub async fn get_document_version_handler(
    State(state): State<AppState>,
    Path((workspace_id_str, version_id_str)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let req_path =
        format!("/api/v1/workspaces/{workspace_id_str}/document-versions/{version_id_str}");
    let (_session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

    let ws_uuid = Uuid::parse_str(&workspace_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("Workspace '{workspace_id_str}' was not found"),
            Some(req_path.clone()),
        )
    })?;

    let ver_uuid = Uuid::parse_str(&version_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("DocumentVersion '{version_id_str}' was not found"),
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

    let awc = WorkspaceAuthzResolver::resolve(
        &mut setup_tx,
        WorkspaceId::from_uuid(ws_uuid),
        principal.id,
        now,
    )
    .await
    .map_err(|_| {
        ProblemDetails::not_found(
            "Workspace not found or access denied",
            Some(req_path.clone()),
        )
    })?;

    setup_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    if !can_read_documents(&awc) {
        return Err(ProblemDetails::forbidden(
            "DOCUMENT_READ capability required",
            Some(req_path),
        ));
    }

    let tx_opts = WorkspaceTxOptions::new()
        .with_client_workspace(awc.workspace_id())
        .with_role(DatabaseRole::App);
    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc, tx_opts).await?;

    let version = DocumentVersionRepository::get_by_id(
        ws_tx.conn(),
        awc.workspace_id(),
        DocumentVersionId::from_uuid(ver_uuid),
    )
    .await
    .map_err(|e| ProblemDetails::internal_server_error(Some(e.to_string())))?
    .ok_or_else(|| {
        ProblemDetails::not_found(
            format!("DocumentVersion '{version_id_str}' not found"),
            Some(req_path),
        )
    })?;

    Ok((StatusCode::OK, Json(DocumentVersionDto::from(&version))).into_response())
}

/// E23: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/accept
#[utoipa::path(
    post,
    path = "/api/v1/workspaces/{workspace_id}/document-versions/{version_id}/accept",
    params(
        ("workspace_id" = String, Path, description = "Workspace identifier (UUID)"),
        ("version_id" = String, Path, description = "Document version identifier (UUID)")
    ),
    responses(
        (status = 200, description = "Version accepted as current document pointer", body = DocumentDto),
        (status = 400, description = "Bad Request (Missing If-Match or Idempotency-Key)", body = ProblemDetails),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 404, description = "Version or document not found", body = ProblemDetails),
        (status = 409, description = "Conflict (Version document mismatch)", body = ProblemDetails),
        (status = 412, description = "Precondition Failed (Stale If-Match row_version)", body = ProblemDetails)
    ),
    tag = "Documents"
)]
pub async fn accept_version_handler(
    State(state): State<AppState>,
    Path((workspace_id_str, version_id_str)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let req_path =
        format!("/api/v1/workspaces/{workspace_id_str}/document-versions/{version_id_str}/accept");
    let (session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

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
            format!("Workspace '{workspace_id_str}' was not found"),
            Some(req_path.clone()),
        )
    })?;

    let ver_uuid = Uuid::parse_str(&version_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("DocumentVersion '{version_id_str}' was not found"),
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

    let awc = WorkspaceAuthzResolver::resolve(
        &mut setup_tx,
        WorkspaceId::from_uuid(ws_uuid),
        principal.id,
        now,
    )
    .await
    .map_err(|_| {
        ProblemDetails::not_found(
            "Workspace not found or access denied",
            Some(req_path.clone()),
        )
    })?;

    setup_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    if !can_manage_documents(&awc) {
        return Err(ProblemDetails::forbidden(
            "DOCUMENT_MANAGE capability required",
            Some(req_path),
        ));
    }

    let if_match_hdr = headers.get(IF_MATCH).ok_or_else(|| {
        ProblemDetails::bad_request(
            "If-Match header is required for AcceptVersion",
            Some(req_path.clone()),
        )
    })?;
    let expected_row_version = parse_if_match_header(if_match_hdr)?;

    let idemp_hdr = headers.get("idempotency-key").ok_or_else(|| {
        ProblemDetails::bad_request("Idempotency-Key header is required", Some(req_path.clone()))
    })?;
    let idemp_key_raw = idemp_hdr.to_str().map_err(|_| {
        ProblemDetails::bad_request("Invalid Idempotency-Key header", Some(req_path.clone()))
    })?;

    let tx_opts = WorkspaceTxOptions::new()
        .with_client_workspace(awc.workspace_id())
        .with_role(DatabaseRole::App);
    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc, tx_opts).await?;

    let payload_val = serde_json::json!({
        "workspace_id": workspace_id_str,
        "version_id": version_id_str,
        "if_match": expected_row_version,
    });

    let req_hash = IdempotencyCoordinator::compute_payload_hash(&payload_val);
    let idemp_store = PostgresIdempotencyStore::new();
    let key_hash = IdempotencyCoordinator::compute_key_hash(
        &state.config.session.active_hmac_secret,
        idemp_key_raw,
    );

    let eval = IdempotencyCoordinator::evaluate_key(
        ws_tx.conn(),
        &idemp_store,
        Some(awc.workspace_id()),
        principal.id,
        "ACCEPT_VERSION",
        &key_hash,
        &req_hash,
        86400,
    )
    .await
    .map_err(ProblemDetails::from)?;

    let idemp_record_id = match eval {
        IdempotencyCheckResult::Replay {
            status_code, body, ..
        } => {
            ws_tx.commit().await?;
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
        IdempotencyCheckResult::Acquired { record_id } => record_id,
    };

    let updated_doc = DocumentService::execute_accept_version_tx(
        ws_tx.conn(),
        &awc,
        principal.id,
        DocumentVersionId::from_uuid(ver_uuid),
        expected_row_version,
        now,
        Some(idemp_record_id),
        &idemp_store,
    )
    .await
    .map_err(|e| match e {
        ApplicationError::Conflict(msg) => precondition_failed(msg, Some(req_path.clone())),
        ApplicationError::NotFound(msg) => ProblemDetails::not_found(msg, Some(req_path.clone())),
        other => ProblemDetails::from(other),
    })?;

    ws_tx.commit().await?;
    let dto = DocumentDto::from(&updated_doc);
    Ok((StatusCode::OK, Json(dto)).into_response())
}

/// E24: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download
#[utoipa::path(
    post,
    path = "/api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download",
    params(
        ("workspace_id" = String, Path, description = "Workspace identifier (UUID)"),
        ("version_id" = String, Path, description = "Document version identifier (UUID)")
    ),
    responses(
        (status = 200, description = "Presigned download contract generated", body = DownloadDto),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 404, description = "Document version or artifact not found", body = ProblemDetails)
    ),
    tag = "Documents"
)]
pub async fn download_version_handler(
    State(state): State<AppState>,
    Path((workspace_id_str, version_id_str)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let req_path = format!(
        "/api/v1/workspaces/{workspace_id_str}/document-versions/{version_id_str}/download"
    );
    let (session, principal) = authenticate_caller(&state, &headers, &req_path).await?;

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
            format!("Workspace '{workspace_id_str}' was not found"),
            Some(req_path.clone()),
        )
    })?;

    let ver_uuid = Uuid::parse_str(&version_id_str).map_err(|_| {
        ProblemDetails::not_found(
            format!("DocumentVersion '{version_id_str}' was not found"),
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

    let awc = WorkspaceAuthzResolver::resolve(
        &mut setup_tx,
        WorkspaceId::from_uuid(ws_uuid),
        principal.id,
        now,
    )
    .await
    .map_err(|_| {
        ProblemDetails::not_found(
            "Workspace not found or access denied",
            Some(req_path.clone()),
        )
    })?;

    setup_tx
        .commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some(req_path.clone())))?;

    if !can_read_documents(&awc) {
        return Err(ProblemDetails::forbidden(
            "DOCUMENT_READ capability required",
            Some(req_path),
        ));
    }

    let tx_opts = WorkspaceTxOptions::new()
        .with_client_workspace(awc.workspace_id())
        .with_role(DatabaseRole::App);
    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc, tx_opts).await?;

    let version = DocumentVersionRepository::get_by_id(
        ws_tx.conn(),
        awc.workspace_id(),
        DocumentVersionId::from_uuid(ver_uuid),
    )
    .await
    .map_err(|e| ProblemDetails::internal_server_error(Some(e.to_string())))?
    .ok_or_else(|| {
        ProblemDetails::not_found(
            format!("DocumentVersion '{version_id_str}' not found"),
            Some(req_path.clone()),
        )
    })?;

    let artifact = ObjectArtifactRepository::get_by_id(
        ws_tx.conn(),
        awc.workspace_id(),
        version.object_artifact_id,
    )
    .await
    .map_err(|e| ProblemDetails::internal_server_error(Some(e.to_string())))?
    .ok_or_else(|| {
        ProblemDetails::not_found(
            format!("ObjectArtifact '{}' not found", version.object_artifact_id),
            Some(req_path.clone()),
        )
    })?;

    let expires_at = now + Duration::minutes(5);
    let presigned_get =
        DocumentService::generate_presigned_get(&artifact, &version.original_filename, expires_at)
            .map_err(|e| match e {
                FinalizeUploadError::PreconditionFailed(msg) => {
                    precondition_failed(msg, Some(req_path))
                }
                other => ProblemDetails::internal_server_error(Some(other.to_string())),
            })?;

    let dto = DownloadDto {
        download_url: presigned_get.download_url,
        expires_at: presigned_get.expires_at,
        content_type: presigned_get.content_type,
        byte_size: presigned_get.byte_size,
        sha256_hash: presigned_get.sha256_hash,
        original_filename: presigned_get.original_filename,
    };

    Ok((StatusCode::OK, Json(dto)).into_response())
}

// ============================================================================
// Router Assembly
// ============================================================================

/// Constructs the Document Pipeline OpenApiRouter integrating routes E16-E24.
pub fn document_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_documents_handler, create_document_handler))
        .routes(routes!(get_document_handler))
        .routes(routes!(list_document_versions_handler))
        .routes(routes!(create_upload_intent_handler))
        .routes(routes!(finalize_upload_intent_handler))
        .routes(routes!(get_document_version_handler))
        .routes(routes!(accept_version_handler))
        .routes(routes!(download_version_handler))
}
