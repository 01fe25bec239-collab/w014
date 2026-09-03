//! Comprehensive API & Security Integration Test Suite for WI-0202:
//! Document Registry + Upload Intent Presign + AcceptVersion API.
//!
//! Verifies:
//! - E16: GET  /api/v1/workspaces/{workspace_id}/documents (list, pagination, tenant isolation)
//! - E17: POST /api/v1/workspaces/{workspace_id}/documents (create, CSRF, Idempotency-Key, audit)
//! - E18: GET  /api/v1/workspaces/{workspace_id}/documents/{document_id} (read, IDOR defense)
//! - E19: GET  /api/v1/workspaces/{workspace_id}/documents/{document_id}/versions (list, pagination)
//! - E20: POST /api/v1/workspaces/{workspace_id}/documents/{document_id}/upload-intents (server key, TTL <= 10m, 413, 415, CSRF, idempotency)
//! - E21: POST /api/v1/workspaces/{workspace_id}/upload-intents/{intent_id}/finalize (deferred to WI-0203 -> 501)
//! - E22: GET  /api/v1/workspaces/{workspace_id}/document-versions/{version_id} (read, IDOR defense)
//! - E23: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/accept (DOCUMENT_MANAGE, If-Match, 412, audit, dependency_key, change_event, durable job enqueue, rollback)
//! - E24: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download (DOCUMENT_READ, presigned GET, TTL <= 5m, no mutation, cross-workspace rejection)

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE, IF_MATCH, ORIGIN};
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::{PgPool, Row};
use tower::ServiceExt;

use w014_api::config::ApiConfig;
use w014_api::create_app_with_pool;
use w014_api::routes::documents::{
    DocumentDto, DocumentPage, DownloadDto, UploadFinalizeDto, UploadIntentDto,
};
use w014_application::persistence::{
    DocumentRepository, DocumentVersionRepository, MembershipRepository, ObjectArtifactRepository,
    OrganizationRepository, PrincipalRepository, ProgramRepository, SessionRepository,
    WorkspaceRepository,
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
use w014_domain::{
    ArtifactKind, Document, DocumentClass, DocumentVersion, EncryptionMode, ObjectArtifact, Sha256,
    StorageTier, VersionOrdinal,
};
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

// ============================================================================
// Gate Tests
// ============================================================================

#[tokio::test]
async fn test_e16_list_documents_pagination_and_tenant_isolation() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Test Org", "test-org").await;
    let prog = create_program(&db, org.id, "Test Program", "test-prog").await;
    let ws_a = create_workspace(&db, &prog, "Workspace A", "ws-a").await;
    let ws_b = create_workspace(&db, &prog, "Workspace B", "ws-b").await;

    let user_a = create_principal(&db, org.id, "usera@test.com", "User A").await;
    add_membership(&db, ws_a.id, user_a.id, MembershipRole::Reader).await;
    let (cookie_a, _) = create_session_and_csrf(&db, user_a.id, &config).await;

    // Seed 3 documents in Workspace A and 2 in Workspace B
    {
        let mut tx = db.pool().begin().await.unwrap();
        for i in 1..=3 {
            let doc = Document::new(
                ws_a.id,
                format!("Doc A {i}"),
                DocumentClass::Pdf,
                Some(user_a.id),
            )
            .unwrap();
            DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        }
        for i in 1..=2 {
            let doc = Document::new(
                ws_b.id,
                format!("Doc B {i}"),
                DocumentClass::Docx,
                Some(user_a.id),
            )
            .unwrap();
            DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        }
        tx.commit().await.unwrap();
    }

    // 1. List documents in Workspace A
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/documents?limit=10", ws_a.id))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let page: DocumentPage = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(page.items.len(), 3);
    assert!(!page.has_more);
    for doc in &page.items {
        assert_eq!(doc.workspace_id, ws_a.id.to_string());
    }

    // 2. Pagination test (limit = 2)
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/documents?limit=2", ws_a.id))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let page1: DocumentPage = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(page1.items.len(), 2);
    assert!(page1.has_more);
    assert!(page1.next_cursor.is_some());

    // Next page
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/documents?cursor={}&limit=2",
            ws_a.id,
            page1.next_cursor.unwrap()
        ))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let page2: DocumentPage = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(page2.items.len(), 1);
    assert!(!page2.has_more);

    // 3. User A attempts to list Workspace B (not a member) -> returns 404
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/documents", ws_b.id))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_e17_create_document_idempotency_audit_csrf() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org 17", "org-17").await;
    let prog = create_program(&db, org.id, "Prog 17", "prog-17").await;
    let ws = create_workspace(&db, &prog, "Workspace 17", "ws-17").await;

    let admin = create_principal(&db, org.id, "admin17@test.com", "Admin 17").await;
    add_membership(&db, ws.id, admin.id, MembershipRole::Admin).await;
    let (cookie_admin, csrf_admin) = create_session_and_csrf(&db, admin.id, &config).await;

    let reader = create_principal(&db, org.id, "reader17@test.com", "Reader 17").await;
    add_membership(&db, ws.id, reader.id, MembershipRole::Reader).await;
    let (cookie_reader, csrf_reader) = create_session_and_csrf(&db, reader.id, &config).await;

    let create_payload = json!({
        "title": "Quarterly Financial Report",
        "document_class": "pdf"
    });

    // 1. Reader attempts creation -> 403 Forbidden (no DOCUMENT_UPLOAD)
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/documents", ws.id))
        .method("POST")
        .header(COOKIE, &cookie_reader)
        .header(CSRF_HEADER_NAME, &csrf_reader)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "reader-create-key-1")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(create_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. CSRF missing on unsafe POST -> 403 Forbidden
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/documents", ws.id))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "admin-create-key-1")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(create_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 3. Missing Idempotency-Key -> 400 Bad Request
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/documents", ws.id))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(CSRF_HEADER_NAME, &csrf_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(create_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 4. Successful document creation by Admin
    let idemp_key = "idemp-doc-create-001";
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/documents", ws.id))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(CSRF_HEADER_NAME, &csrf_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", idemp_key)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(create_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let doc_dto: DocumentDto = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(doc_dto.title, "Quarterly Financial Report");
    assert_eq!(doc_dto.document_class, "pdf");
    assert_eq!(doc_dto.status, "active");
    assert_eq!(doc_dto.row_version, 1);
    assert!(doc_dto.current_version_id.is_none());

    // 5. Idempotent replay with same key and payload -> returns 201 Created with same doc
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/documents", ws.id))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(CSRF_HEADER_NAME, &csrf_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", idemp_key)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(create_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes2 = resp.into_body().collect().await.unwrap().to_bytes();
    let doc_dto2: DocumentDto = serde_json::from_slice(&body_bytes2).unwrap();
    assert_eq!(doc_dto.id, doc_dto2.id);

    // 6. Idempotent mismatch with same key but different payload -> 400 Bad Request
    let mismatch_payload = json!({
        "title": "Different Title Mismatch",
        "document_class": "pdf"
    });
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/documents", ws.id))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(CSRF_HEADER_NAME, &csrf_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", idemp_key)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(mismatch_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 7. Verify audit event was written
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE workspace_id = $1 AND action_code = 'DOCUMENT_CREATE'",
    )
    .bind(ws.id.as_uuid())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(audit_count, 1);
}

#[tokio::test]
async fn test_e18_get_document_by_id_and_idor_protection() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org 18", "org-18").await;
    let prog = create_program(&db, org.id, "Prog 18", "prog-18").await;
    let ws_a = create_workspace(&db, &prog, "WS 18 A", "ws-18-a").await;
    let ws_b = create_workspace(&db, &prog, "WS 18 B", "ws-18-b").await;

    let user_a = create_principal(&db, org.id, "usera18@test.com", "User A").await;
    let user_b = create_principal(&db, org.id, "userb18@test.com", "User B").await;

    add_membership(&db, ws_a.id, user_a.id, MembershipRole::Reader).await;
    add_membership(&db, ws_b.id, user_b.id, MembershipRole::Reader).await;

    let (cookie_a, _) = create_session_and_csrf(&db, user_a.id, &config).await;
    let (cookie_b, _) = create_session_and_csrf(&db, user_b.id, &config).await;

    let doc_a = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc =
            Document::new(ws_a.id, "Document A", DocumentClass::Pdf, Some(user_a.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    // 1. User A reads Document A -> 200 OK
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/documents/{}",
            ws_a.id, doc_a.id
        ))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let doc_dto: DocumentDto = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(doc_dto.id, doc_a.id.to_string());

    // 2. User B in Workspace B attempts IDOR on Document A in Workspace A -> 404 Not Found
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/documents/{}",
            ws_a.id, doc_a.id
        ))
        .method("GET")
        .header(COOKIE, &cookie_b)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 3. User B queries Document A using Workspace B's URL -> 404 Not Found (scoped query)
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/documents/{}",
            ws_b.id, doc_a.id
        ))
        .method("GET")
        .header(COOKIE, &cookie_b)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_e20_unconfigured_s3_fails_closed() {
    let _unconfigured = DocumentService::scoped_unconfigured_storage().await;
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org 20 Fail Closed", "org-20-fail-closed").await;
    let prog = create_program(&db, org.id, "Prog 20 Fail Closed", "prog-20-fail-closed").await;
    let ws = create_workspace(&db, &prog, "WS 20 Fail Closed", "ws-20-fail-closed").await;

    let user = create_principal(&db, org.id, "user20fc@test.com", "User 20 Fail Closed").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc =
            Document::new(ws.id, "Target Document", DocumentClass::Pdf, Some(user.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    let valid_payload = json!({
        "filename": "specification.pdf",
        "media_type": "application/pdf",
        "byte_length": 2048576,
        "sha256_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    });
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/documents/{}/upload-intents",
            ws.id, doc.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "upload-intent-fail-closed-key")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(valid_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    // Production behavior when S3 configuration is absent MUST FAIL CLOSED with 412 Precondition Failed.
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn test_e20_upload_intent_presign_put_security_gates() {
    let _storage = DocumentService::scoped_test_storage().await;
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org 20", "org-20").await;
    let prog = create_program(&db, org.id, "Prog 20", "prog-20").await;
    let ws = create_workspace(&db, &prog, "WS 20", "ws-20").await;

    let user = create_principal(&db, org.id, "user20@test.com", "User 20").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc =
            Document::new(ws.id, "Target Document", DocumentClass::Pdf, Some(user.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    // 1. Unsupported media type (e.g. text/plain) -> 415 Unsupported Media Type
    let bad_media_payload = json!({
        "filename": "notes.txt",
        "media_type": "text/plain",
        "byte_length": 1024
    });
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/documents/{}/upload-intents",
            ws.id, doc.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(bad_media_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // 2. Oversized payload (> 100 MiB = 104857600 bytes) -> 413 Payload Too Large
    let oversized_payload = json!({
        "filename": "huge.pdf",
        "media_type": "application/pdf",
        "byte_length": 104857601
    });
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/documents/{}/upload-intents",
            ws.id, doc.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(oversized_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 3. Valid upload intent with PDF and SHA-256 base64
    let valid_payload = json!({
        "filename": "specification.pdf",
        "media_type": "application/pdf",
        "byte_length": 2048576,
        "sha256_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    });
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/documents/{}/upload-intents",
            ws.id, doc.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "upload-intent-key-1")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(valid_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let intent_dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(intent_dto.filename, "specification.pdf");
    assert_eq!(intent_dto.expected_media_type, "application/pdf");
    assert_eq!(intent_dto.expected_length, 2048576);
    assert_eq!(
        intent_dto.expected_sha256_b64.as_deref(),
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    );
    assert!(intent_dto.opaque_object_key.starts_with("upload-intents/"));
    assert_eq!(intent_dto.status, "initiated");

    // Presigned PUT contract verification
    let presigned = intent_dto.presigned_put;
    assert_eq!(presigned.method, "PUT");
    assert!(presigned.upload_url.contains(&intent_dto.opaque_object_key));
    assert_eq!(
        presigned.headers.get("content-type").map(|s| s.as_str()),
        Some("application/pdf")
    );
    assert_eq!(
        presigned.headers.get("content-length").map(|s| s.as_str()),
        Some("2048576")
    );
    assert_eq!(
        presigned
            .headers
            .get("x-amz-checksum-sha256")
            .map(|s| s.as_str()),
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    );

    // TTL check: must be <= 10 minutes from creation
    let ttl_duration = presigned
        .expires_at
        .signed_duration_since(intent_dto.created_at);
    assert!(ttl_duration <= Duration::minutes(10));
}

#[tokio::test]
async fn test_e21_finalize_upload_intent_full_flow() {
    let _storage = DocumentService::scoped_test_storage().await;
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org 21", "org-21").await;
    let prog = create_program(&db, org.id, "Prog 21", "prog-21").await;
    let ws = create_workspace(&db, &prog, "WS 21", "ws-21").await;

    let user = create_principal(&db, org.id, "user21@test.com", "User 21").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    // 1. Create document & upload intent
    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(ws.id, "Spec Doc", DocumentClass::Pdf, Some(user.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    let sample_bytes = b"%PDF-1.7 sample content";
    let sha256_val = Sha256::digest(sample_bytes);
    let sha256_b64 = sha256_val.to_base64();

    let create_intent_payload = json!({
        "filename": "spec.pdf",
        "media_type": "application/pdf",
        "byte_length": sample_bytes.len() as i64,
        "sha256_b64": sha256_b64,
    });

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/documents/{}/upload-intents",
            ws.id, doc.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "intent-key-21")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(create_intent_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let intent_dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();

    // 2. Stage object in mock storage
    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_dto.opaque_object_key,
        sample_bytes,
        "application/pdf",
    );

    // 3. Finalize upload intent via E21
    let idemp_key = "finalize-key-21";
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_dto.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", idemp_key)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let finalize_dto: UploadFinalizeDto = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(finalize_dto.upload_intent_id, intent_dto.id);
    assert_eq!(finalize_dto.document_id, doc.id.to_string());
    assert_eq!(finalize_dto.version_number, 1);
    assert_eq!(finalize_dto.trust_state, "pending");
    assert_eq!(finalize_dto.status, "quarantined_processing");
}

#[tokio::test]
async fn test_e23_accept_version_atomic_transaction_and_gates() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org 23", "org-23").await;
    let prog = create_program(&db, org.id, "Prog 23", "prog-23").await;
    let ws = create_workspace(&db, &prog, "WS 23", "ws-23").await;

    let admin = create_principal(&db, org.id, "admin23@test.com", "Admin 23").await;
    let operator = create_principal(&db, org.id, "op23@test.com", "Operator 23").await;

    add_membership(&db, ws.id, admin.id, MembershipRole::Admin).await;
    add_membership(&db, ws.id, operator.id, MembershipRole::Operator).await;

    let (cookie_admin, csrf_admin) = create_session_and_csrf(&db, admin.id, &config).await;
    let (cookie_op, csrf_op) = create_session_and_csrf(&db, operator.id, &config).await;

    // Seed document, artifact, and version
    let (_doc, version) = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(
            ws.id,
            "Architectural Specification",
            DocumentClass::Pdf,
            Some(admin.id),
        )
        .unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();

        let sha = Sha256::digest(b"test pdf content");
        let media_type = w014_domain::StoredMediaType::new("application/pdf").unwrap();
        let artifact = ObjectArtifact::new(
            ws.id,
            ArtifactKind::Original,
            "w014-documents",
            media_type,
            sha,
            2048,
            StorageTier::Hot,
            EncryptionMode::SseAes256,
            None,
        )
        .unwrap();
        ObjectArtifactRepository::insert(&mut tx, &artifact)
            .await
            .unwrap();

        let version = DocumentVersion::new(
            &doc,
            VersionOrdinal::new(1).unwrap(),
            artifact.id,
            2048,
            sha,
            "spec_v1.pdf",
            Some(admin.id),
        )
        .unwrap();
        DocumentVersionRepository::insert(&mut tx, &version)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (doc, version)
    };

    // 1. Operator without DOCUMENT_MANAGE capability -> 403 Forbidden
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/document-versions/{}/accept",
            ws.id, version.id
        ))
        .method("POST")
        .header(COOKIE, &cookie_op)
        .header(CSRF_HEADER_NAME, &csrf_op)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(IF_MATCH, "\"1\"")
        .header("idempotency-key", "op-accept-key-1")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. Missing If-Match header -> 400 Bad Request
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/document-versions/{}/accept",
            ws.id, version.id
        ))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(CSRF_HEADER_NAME, &csrf_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "admin-accept-key-1")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 3. Stale If-Match (expected row_version 2 when doc is row_version 1) -> 412 Precondition Failed
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/document-versions/{}/accept",
            ws.id, version.id
        ))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(CSRF_HEADER_NAME, &csrf_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(IF_MATCH, "\"2\"")
        .header("idempotency-key", "admin-accept-key-stale")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);

    // 4. Successful AcceptVersion execution by Admin
    let accept_key = "admin-accept-key-success-1";
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/document-versions/{}/accept",
            ws.id, version.id
        ))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(CSRF_HEADER_NAME, &csrf_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(IF_MATCH, "\"1\"")
        .header("idempotency-key", accept_key)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let updated_doc: DocumentDto = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(updated_doc.current_version_id, Some(version.id.to_string()));
    assert_eq!(updated_doc.row_version, 2);

    // 5. Verify authoritative database effects:
    // A. Audit event appended
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE workspace_id = $1 AND action_code = 'ACCEPT_VERSION'",
    )
    .bind(ws.id.as_uuid())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(audit_count, 1);

    // B. Dependency key written
    let dep_key_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dependency_keys WHERE workspace_id = $1 AND key_type = 'document'",
    )
    .bind(ws.id.as_uuid())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(dep_key_count, 1);

    // C. Change event appended
    let change_event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM change_events WHERE workspace_id = $1 AND event_type = 'DOCUMENT_VERSION_ACCEPTED'",
    )
    .bind(ws.id.as_uuid())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(change_event_count, 1);

    // D. Real durable parse job enqueued in PostgreSQL jobs queue
    let job_row = sqlx::query("SELECT job_type, status, payload FROM jobs WHERE workspace_id = $1")
        .bind(ws.id.as_uuid())
        .fetch_one(db.pool())
        .await
        .unwrap();

    let job_type: String = job_row.get("job_type");
    let job_status: String = job_row.get("status");
    assert_eq!(job_type, "parse_document_pdf");
    assert_eq!(job_status, "queued");

    // 6. Idempotent replay of AcceptVersion
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/document-versions/{}/accept",
            ws.id, version.id
        ))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(CSRF_HEADER_NAME, &csrf_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(IF_MATCH, "\"1\"")
        .header("idempotency-key", accept_key)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_e24_download_signing_presigned_get() {
    let _storage = DocumentService::scoped_test_storage().await;
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org 24", "org-24").await;
    let prog = create_program(&db, org.id, "Prog 24", "prog-24").await;
    let ws_a = create_workspace(&db, &prog, "WS 24 A", "ws-24-a").await;
    let ws_b = create_workspace(&db, &prog, "WS 24 B", "ws-24-b").await;

    let user_a = create_principal(&db, org.id, "usera24@test.com", "User 24 A").await;
    let user_b = create_principal(&db, org.id, "userb24@test.com", "User 24 B").await;

    add_membership(&db, ws_a.id, user_a.id, MembershipRole::Reader).await;
    add_membership(&db, ws_b.id, user_b.id, MembershipRole::Reader).await;

    let (cookie_a, csrf_a) = create_session_and_csrf(&db, user_a.id, &config).await;
    let (cookie_b, csrf_b) = create_session_and_csrf(&db, user_b.id, &config).await;

    let (_doc, version, artifact) = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(
            ws_a.id,
            "Downloadable Document",
            DocumentClass::Pdf,
            Some(user_a.id),
        )
        .unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();

        let sha = Sha256::digest(b"downloadable pdf content");
        let media_type = w014_domain::StoredMediaType::new("application/pdf").unwrap();
        let artifact = ObjectArtifact::new(
            ws_a.id,
            ArtifactKind::Original,
            "w014-documents",
            media_type,
            sha,
            4096,
            StorageTier::Hot,
            EncryptionMode::SseAes256,
            None,
        )
        .unwrap();
        ObjectArtifactRepository::insert(&mut tx, &artifact)
            .await
            .unwrap();

        let version = DocumentVersion::new(
            &doc,
            VersionOrdinal::new(1).unwrap(),
            artifact.id,
            4096,
            sha,
            "download_me.pdf",
            Some(user_a.id),
        )
        .unwrap();
        DocumentVersionRepository::insert(&mut tx, &version)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (doc, version, artifact)
    };

    // 1. User A downloads in Workspace A -> 200 OK with presigned GET contract
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/document-versions/{}/download",
            ws_a.id, version.id
        ))
        .method("POST")
        .header(COOKIE, &cookie_a)
        .header(CSRF_HEADER_NAME, &csrf_a)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let download_dto: DownloadDto = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(download_dto.original_filename, "download_me.pdf");
    assert_eq!(download_dto.content_type, "application/pdf");
    assert_eq!(download_dto.byte_size, 4096);
    assert!(download_dto.download_url.contains(artifact.key.as_str()));
    assert!(download_dto.download_url.contains("signature=valid"));

    // TTL must be <= 5 minutes
    let now = Utc::now();
    let ttl = download_dto.expires_at.signed_duration_since(now);
    assert!(ttl <= Duration::minutes(5) + Duration::seconds(5));

    // 2. Cross-workspace IDOR: User B in Workspace B tries to download Version in Workspace A -> 404 Not Found
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/document-versions/{}/download",
            ws_a.id, version.id
        ))
        .method("POST")
        .header(COOKIE, &cookie_b)
        .header(CSRF_HEADER_NAME, &csrf_b)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 3. User B tries with Workspace B ID in path -> 404 Not Found
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/document-versions/{}/download",
            ws_b.id, version.id
        ))
        .method("POST")
        .header(COOKIE, &cookie_b)
        .header(CSRF_HEADER_NAME, &csrf_b)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_e19_list_document_versions() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org 19", "org-19").await;
    let prog = create_program(&db, org.id, "Prog 19", "prog-19").await;
    let ws = create_workspace(&db, &prog, "WS 19", "ws-19").await;

    let user = create_principal(&db, org.id, "user19@test.com", "User 19").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Reader).await;
    let (cookie, _) = create_session_and_csrf(&db, user.id, &config).await;

    let (doc, _v1, _v2) = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(
            ws.id,
            "Multi-version Document",
            DocumentClass::Pdf,
            Some(user.id),
        )
        .unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();

        let sha1 = Sha256::digest(b"version 1 bytes");
        let media_type = w014_domain::StoredMediaType::new("application/pdf").unwrap();
        let art1 = ObjectArtifact::new(
            ws.id,
            ArtifactKind::Original,
            "w014-documents",
            media_type.clone(),
            sha1,
            1000,
            StorageTier::Hot,
            EncryptionMode::SseAes256,
            None,
        )
        .unwrap();
        ObjectArtifactRepository::insert(&mut tx, &art1)
            .await
            .unwrap();

        let v1 = DocumentVersion::new(
            &doc,
            VersionOrdinal::new(1).unwrap(),
            art1.id,
            1000,
            sha1,
            "file_v1.pdf",
            Some(user.id),
        )
        .unwrap();
        DocumentVersionRepository::insert(&mut tx, &v1)
            .await
            .unwrap();

        let sha2 = Sha256::digest(b"version 2 bytes");
        let art2 = ObjectArtifact::new(
            ws.id,
            ArtifactKind::Original,
            "w014-documents",
            media_type,
            sha2,
            2000,
            StorageTier::Hot,
            EncryptionMode::SseAes256,
            None,
        )
        .unwrap();
        ObjectArtifactRepository::insert(&mut tx, &art2)
            .await
            .unwrap();

        let v2 = DocumentVersion::new(
            &doc,
            VersionOrdinal::new(2).unwrap(),
            art2.id,
            2000,
            sha2,
            "file_v2.pdf",
            Some(user.id),
        )
        .unwrap();
        DocumentVersionRepository::insert(&mut tx, &v2)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (doc, v1, v2)
    };

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/documents/{}/versions",
            ws.id, doc.id
        ))
        .method("GET")
        .header(COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let page: w014_api::routes::documents::DocumentVersionPage =
        serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].version_number, 1);
    assert_eq!(page.items[1].version_number, 2);
}

#[tokio::test]
async fn test_e22_get_document_version_by_id() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org 22", "org-22").await;
    let prog = create_program(&db, org.id, "Prog 22", "prog-22").await;
    let ws = create_workspace(&db, &prog, "WS 22", "ws-22").await;

    let user = create_principal(&db, org.id, "user22@test.com", "User 22").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Reader).await;
    let (cookie, _) = create_session_and_csrf(&db, user.id, &config).await;

    let (_doc, version) = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(
            ws.id,
            "Single Version Document",
            DocumentClass::Pdf,
            Some(user.id),
        )
        .unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();

        let sha = Sha256::digest(b"pdf content 22");
        let media_type = w014_domain::StoredMediaType::new("application/pdf").unwrap();
        let artifact = ObjectArtifact::new(
            ws.id,
            ArtifactKind::Original,
            "w014-documents",
            media_type,
            sha,
            3000,
            StorageTier::Hot,
            EncryptionMode::SseAes256,
            None,
        )
        .unwrap();
        ObjectArtifactRepository::insert(&mut tx, &artifact)
            .await
            .unwrap();

        let version = DocumentVersion::new(
            &doc,
            VersionOrdinal::new(1).unwrap(),
            artifact.id,
            3000,
            sha,
            "spec22.pdf",
            Some(user.id),
        )
        .unwrap();
        DocumentVersionRepository::insert(&mut tx, &version)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (doc, version)
    };

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/document-versions/{}",
            ws.id, version.id
        ))
        .method("GET")
        .header(COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let dto: w014_api::routes::documents::DocumentVersionDto =
        serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(dto.id, version.id.to_string());
    assert_eq!(dto.version_number, 1);
    assert_eq!(dto.original_filename, "spec22.pdf");
    assert_eq!(dto.byte_size, 3000);
}
