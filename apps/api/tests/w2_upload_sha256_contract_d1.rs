//! W2 D1: Upload SHA-256 transport-contract closure.
//!
//! Proves the authoritative Rust/utoipa contract requires SHA-256:
//! 1. OpenAPI request schema marks sha256_b64 required.
//! 2. Missing sha256_b64 cannot be a valid authoritative create-upload request.
//! 3. Malformed SHA-256 fails closed.
//! 4. Empty SHA-256 fails closed.
//! 5. Valid SHA-256 succeeds through the explicit test-storage path.
//! 6. Presign still cryptographically binds checksum.
//! 7. Finalize still validates authoritative HEAD checksum.

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE, ORIGIN};
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::{PgPool, Row};
use tower::ServiceExt;
use uuid::Uuid;

use chrono::{Duration, Utc};
use w014_api::build_openapi_router;
use w014_api::config::ApiConfig;
use w014_api::create_app_with_pool;
use w014_api::routes::documents::UploadIntentDto;
use w014_application::persistence::{
    DocumentRepository, MembershipRepository, OrganizationRepository, PrincipalRepository,
    ProgramRepository, SessionRepository, WorkspaceRepository,
};
use w014_application::services::DocumentService;
use w014_authn::csrf::{CSRF_HEADER_NAME, CsrfConfig, derive_csrf_token};
use w014_authn::session::{Session, generate_session_token};
use w014_domain::ids::{OrganizationId, PrincipalId, WorkspaceId};
use w014_domain::membership::{Membership, MembershipRole};
use w014_domain::organization::Organization;
use w014_domain::principal::Principal;
use w014_domain::program::Program;
use w014_domain::workspace::Workspace;
use w014_domain::{Document, DocumentClass, Sha256};
use w014_persistence::harness::TestDatabase;
use w014_persistence::runner::{MIGRATOR, MigrationRunner};

async fn provision_migrated_db() -> TestDatabase {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision test database");
    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply migrations");
    test_db
}

fn create_test_config() -> ApiConfig {
    let mut config = ApiConfig::for_testing();
    config.csrf = CsrfConfig::new(vec!["http://127.0.0.1:3000".to_string()]);
    config.session.cookie_name = "test_session".to_string();
    config
}

fn create_test_app(config: &ApiConfig, pool: PgPool) -> axum::Router {
    create_app_with_pool(config, pool)
}

async fn create_org(db: &TestDatabase, name: &str, slug: &str) -> Organization {
    let mut tx = db.pool().begin().await.unwrap();
    let org = Organization::new(name, slug).unwrap();
    OrganizationRepository::insert(&mut tx, &org).await.unwrap();
    tx.commit().await.unwrap();
    org
}

async fn create_principal(
    db: &TestDatabase,
    _org_id: OrganizationId,
    email: &str,
    display_name: &str,
) -> Principal {
    let mut tx = db.pool().begin().await.unwrap();
    let principal = Principal::new(display_name, Some(email)).unwrap();
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    principal
}

async fn create_program(
    db: &TestDatabase,
    org_id: OrganizationId,
    name: &str,
    slug: &str,
) -> Program {
    let mut tx = db.pool().begin().await.unwrap();
    let prog = Program::new(org_id, name, slug).unwrap();
    ProgramRepository::insert(&mut tx, &prog).await.unwrap();
    tx.commit().await.unwrap();
    prog
}

async fn create_workspace(db: &TestDatabase, prog: &Program, name: &str, slug: &str) -> Workspace {
    let mut tx = db.pool().begin().await.unwrap();
    let ws = Workspace::new(prog.id, prog.organization_id, name, slug).unwrap();
    WorkspaceRepository::insert(&mut tx, &ws).await.unwrap();
    tx.commit().await.unwrap();
    ws
}

async fn add_membership(
    db: &TestDatabase,
    ws_id: WorkspaceId,
    principal_id: PrincipalId,
    role: MembershipRole,
) -> Membership {
    let mut tx = db.pool().begin().await.unwrap();
    let membership = Membership::new(ws_id, principal_id, role);
    MembershipRepository::insert(&mut tx, &membership)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    membership
}

async fn create_session_and_csrf(
    db: &TestDatabase,
    principal_id: PrincipalId,
    config: &ApiConfig,
) -> (String, String) {
    let mut tx = db.pool().begin().await.unwrap();
    let raw_token = generate_session_token();
    let handle_hash = config.session.hash_handle(&raw_token);
    let csrf_hash = config.session.hash_handle("csrf_test");
    let session = Session::new(
        principal_id,
        handle_hash.to_vec(),
        csrf_hash.to_vec(),
        Utc::now() + Duration::hours(12),
        Utc::now() + Duration::hours(12),
    )
    .unwrap();
    SessionRepository::insert(&mut tx, &session).await.unwrap();
    tx.commit().await.unwrap();

    let rot_id = session.rotation_identity();
    let csrf_token = derive_csrf_token(&config.csrf.hmac_secret, &rot_id, "http://127.0.0.1:3000");

    (format!("test_session={raw_token}"), csrf_token)
}

async fn setup_workspace_with_doc(
    db: &TestDatabase,
    org_slug: &str,
    ws_slug: &str,
    user_email: &str,
) -> (ApiConfig, axum::Router, Workspace, Document, String, String) {
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());
    let org = create_org(db, &format!("Org {org_slug}"), org_slug).await;
    let prog = create_program(
        db,
        org.id,
        &format!("Prog {org_slug}"),
        &format!("prog-{org_slug}"),
    )
    .await;
    let ws = create_workspace(db, &prog, &format!("WS {ws_slug}"), ws_slug).await;
    let user = create_principal(db, org.id, user_email, &format!("User {org_slug}")).await;
    add_membership(db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(db, user.id, &config).await;
    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let d = Document::new(ws.id, "D1 Doc", DocumentClass::Pdf, Some(user.id)).unwrap();
        DocumentRepository::insert(&mut tx, &d).await.unwrap();
        tx.commit().await.unwrap();
        d
    };
    (config, app, ws, doc, cookie, csrf)
}

fn upload_intent_uri(ws: &Workspace, doc: &Document) -> String {
    format!(
        "/api/v1/workspaces/{}/documents/{}/upload-intents",
        ws.id, doc.id
    )
}

// 1. OpenAPI request schema marks sha256_b64 required.
#[test]
fn test_d1_openapi_request_schema_marks_sha256_required() {
    let (_router, spec) = build_openapi_router();
    let value = serde_json::to_value(&spec).expect("spec must serialize");
    let schemas = value
        .pointer("/components/schemas")
        .expect("components.schemas must exist");
    let create = schemas
        .get("CreateUploadIntentDto")
        .expect("CreateUploadIntentDto must exist");
    let required = create
        .get("required")
        .and_then(|v| v.as_array())
        .expect("CreateUploadIntentDto must have required");
    let req: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
    for field in ["filename", "media_type", "byte_length", "sha256_b64"] {
        assert!(
            req.contains(&field),
            "CreateUploadIntentDto.required must contain {field}, got {req:?}"
        );
    }
    let intent = schemas
        .get("UploadIntentDto")
        .expect("UploadIntentDto must exist");
    let required = intent
        .get("required")
        .and_then(|v| v.as_array())
        .expect("UploadIntentDto must have required");
    let req: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        req.contains(&"expected_sha256_b64"),
        "UploadIntentDto.required must contain expected_sha256_b64, got {req:?}"
    );
}

// 2. Missing sha256_b64 cannot be a valid authoritative create-upload request.
#[tokio::test]
async fn test_d1_missing_sha256_not_valid() {
    let _storage = DocumentService::scoped_test_storage().await;
    let db = provision_migrated_db().await;
    let (_config, app, ws, doc, cookie, csrf) =
        setup_workspace_with_doc(&db, "d1-missing", "ws-d1-missing", "d1_missing@test.com").await;

    let req = Request::builder()
        .uri(upload_intent_uri(&ws, &doc))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "d1-missing-1")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "filename": "missing.pdf",
                "media_type": "application/pdf",
                "byte_length": 1024,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status() == StatusCode::UNPROCESSABLE_ENTITY
            || resp.status() == StatusCode::BAD_REQUEST,
        "missing sha256_b64 must fail closed with 400/422, got {}",
        resp.status()
    );
    assert_ne!(resp.status(), StatusCode::CREATED);
}

// 3. Malformed SHA-256 fails closed.
#[tokio::test]
async fn test_d1_malformed_sha256_fails_closed() {
    let _storage = DocumentService::scoped_test_storage().await;
    let db = provision_migrated_db().await;
    let (_config, app, ws, doc, cookie, csrf) = setup_workspace_with_doc(
        &db,
        "d1-malformed",
        "ws-d1-malformed",
        "d1_malformed@test.com",
    )
    .await;

    let req = Request::builder()
        .uri(upload_intent_uri(&ws, &doc))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "d1-malformed-1")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "filename": "malformed.pdf",
                "media_type": "application/pdf",
                "byte_length": 1024,
                "sha256_b64": "not-valid-base64!",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// 4. Empty SHA-256 fails closed (whitespace + empty-digest fallback).
#[tokio::test]
async fn test_d1_empty_sha256_fails_closed() {
    let _storage = DocumentService::scoped_test_storage().await;
    let db = provision_migrated_db().await;
    let (_config, app, ws, doc, cookie, csrf) =
        setup_workspace_with_doc(&db, "d1-empty", "ws-d1-empty", "d1_empty@test.com").await;

    // Whitespace-only.
    let req = Request::builder()
        .uri(upload_intent_uri(&ws, &doc))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "d1-empty-ws")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "filename": "empty.pdf",
                "media_type": "application/pdf",
                "byte_length": 1024,
                "sha256_b64": "   ",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Empty-digest fallback.
    let empty_digest_b64 = Sha256::digest(b"").to_base64();
    let req = Request::builder()
        .uri(upload_intent_uri(&ws, &doc))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "d1-empty-digest")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "filename": "empty_digest.pdf",
                "media_type": "application/pdf",
                "byte_length": 1024,
                "sha256_b64": empty_digest_b64,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// 5 + 6. Valid SHA-256 succeeds via explicit test-storage path and presign binds checksum.
#[tokio::test]
async fn test_d1_valid_sha256_succeeds_and_presign_binds_checksum() {
    let _storage = DocumentService::scoped_test_storage().await;
    let db = provision_migrated_db().await;
    let (_config, app, ws, doc, cookie, csrf) =
        setup_workspace_with_doc(&db, "d1-valid", "ws-d1-valid", "d1_valid@test.com").await;

    let sample_bytes = b"%PDF-1.7 d1 valid content";
    let sha_b64 = Sha256::digest(sample_bytes).to_base64();

    let req = Request::builder()
        .uri(upload_intent_uri(&ws, &doc))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "d1-valid-1")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "filename": "valid.pdf",
                "media_type": "application/pdf",
                "byte_length": sample_bytes.len() as i64,
                "sha256_b64": sha_b64,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let dto: UploadIntentDto = serde_json::from_slice(&body).unwrap();

    // Success truth carries the expected digest (runtime required, non-optional).
    assert!(!dto.expected_sha256_b64.is_empty());
    assert_eq!(dto.expected_sha256_b64, sha_b64);

    // Physical row preserves a NOT NULL expected digest.
    let intent_id = Uuid::parse_str(&dto.id).unwrap();
    let row = sqlx::query(
        "SELECT expected_sha256_b64 FROM upload_intents WHERE workspace_id = $1 AND upload_intent_id = $2",
    )
    .bind(ws.id.as_uuid())
    .bind(intent_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let stored: Option<String> = row.get("expected_sha256_b64");
    assert_eq!(stored.as_deref(), Some(sha_b64.as_str()));

    // Presign cryptographically binds checksum + content bindings.
    assert_eq!(dto.presigned_put.method, "PUT");
    assert_eq!(
        dto.presigned_put
            .headers
            .get("x-amz-checksum-sha256")
            .map(String::as_str),
        Some(sha_b64.as_str())
    );
    assert_eq!(
        dto.presigned_put
            .headers
            .get("content-type")
            .map(String::as_str),
        Some("application/pdf")
    );
    assert_eq!(
        dto.presigned_put
            .headers
            .get("content-length")
            .map(String::as_str),
        Some((sample_bytes.len().to_string()).as_str())
    );
    // PUT TTL <= 600s: expires_at is bounded (creation is ~now, expiry <= 10m out).
    let ttl = dto
        .presigned_put
        .expires_at
        .signed_duration_since(dto.created_at);
    assert!(ttl.num_seconds() <= 600);
}

// 7. Finalize still validates authoritative HEAD checksum.
#[tokio::test]
async fn test_d1_finalize_validates_head_checksum() {
    let _storage = DocumentService::scoped_test_storage().await;
    let db = provision_migrated_db().await;
    let (_config, app, ws, doc, cookie, csrf) =
        setup_workspace_with_doc(&db, "d1-finalize", "ws-d1-finalize", "d1_finalize@test.com")
            .await;

    // Happy path: declared digest matches staged bytes -> 202.
    let good_bytes = b"%PDF-1.7 d1 finalize good";
    let good_sha = Sha256::digest(good_bytes).to_base64();
    let req = Request::builder()
        .uri(upload_intent_uri(&ws, &doc))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "d1-fin-good-intent")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "filename": "good.pdf",
                "media_type": "application/pdf",
                "byte_length": good_bytes.len() as i64,
                "sha256_b64": good_sha,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let good_intent: UploadIntentDto = serde_json::from_slice(&body).unwrap();
    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &good_intent.opaque_object_key,
        good_bytes,
        "application/pdf",
    );
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, good_intent.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "d1-fin-good")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Mismatch path: declared digest does NOT match staged bytes -> 422.
    let declared_bytes = b"%PDF-1.7 d1 declared";
    let other_bytes = b"%PDF-1.7 d1 other bytes!!";
    assert_ne!(declared_bytes.len(), other_bytes.len());
    let declared_sha = Sha256::digest(declared_bytes).to_base64();
    let req = Request::builder()
        .uri(upload_intent_uri(&ws, &doc))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "d1-fin-bad-intent")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "filename": "bad.pdf",
                "media_type": "application/pdf",
                // Declare the length of the STAGED bytes so the failure is
                // specifically the SHA-256 mismatch (not a length mismatch).
                "byte_length": other_bytes.len() as i64,
                "sha256_b64": declared_sha,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let bad_intent: UploadIntentDto = serde_json::from_slice(&body).unwrap();
    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &bad_intent.opaque_object_key,
        other_bytes,
        "application/pdf",
    );
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, bad_intent.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "d1-fin-bad")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
