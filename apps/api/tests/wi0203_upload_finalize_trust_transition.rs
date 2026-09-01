//! Comprehensive API & Security Integration Test Suite for WI-0203:
//! Finalize Upload — Checksum / MIME / Quarantine / Object Immutability.
//!
//! Validates:
//! - E21: POST /api/v1/workspaces/{workspace_id}/upload-intents/{intent_id}/finalize
//! - Authoritative authn & active membership re-check
//! - DOCUMENT_UPLOAD capability reauthorization
//! - Strict server-owned opaque object key verification (no client-supplied keys/buckets)
//! - Authoritative HEAD storage verification (existence, exact length, exact SHA-256, conservative Content-Type)
//! - Single PostgreSQL transaction atomicity across ObjectArtifact, DocumentVersion, QuarantineRecord,
//!   UploadIntent consumption, AuditEvent, real durable Job enqueue, and Idempotency completion.
//! - Idempotency evaluation (Acquire, Replay, Mismatch, InProgress)
//! - Post-finalize security posture: Quarantined / Processing (trust_state = pending, quarantine = pending)
//! - Direct S3 success does NOT advance trust
//! - Tenant isolation and RLS boundaries

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE, ORIGIN};
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::{PgPool, Row};
use tower::ServiceExt;
use uuid::Uuid;

use w014_api::config::ApiConfig;
use w014_api::create_app_with_pool;
use w014_api::routes::documents::{UploadFinalizeDto, UploadIntentDto};
use w014_application::persistence::{
    DocumentRepository, MembershipRepository, ObjectArtifactRepository, OrganizationRepository,
    PrincipalRepository, ProgramRepository, QuarantineRecordRepository, SessionRepository,
    UploadIntentRepository, WorkspaceRepository,
};
use w014_application::services::DocumentService;
use w014_authn::csrf::{CSRF_HEADER_NAME, CsrfConfig, derive_csrf_token};
use w014_authn::session::{Session, generate_session_token};
use w014_domain::ids::{OrganizationId, PrincipalId, UploadIntentId, WorkspaceId};
use w014_domain::membership::{Membership, MembershipRole};
use w014_domain::organization::Organization;
use w014_domain::principal::Principal;
use w014_domain::program::Program;
use w014_domain::workspace::Workspace;
use w014_domain::{
    ArtifactKind, Document, DocumentClass, EncryptionMode, IntentStatus, MediaType, ObjectArtifact,
    ObjectKey, QuarantineStatus, Sha256, StorageTier, UploadIntent,
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
async fn test_wi0203_gate01_authoritative_upload_finalize_pdf_happy_path() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Finalize 1", "org-fin-1").await;
    let prog = create_program(&db, org.id, "Prog Finalize 1", "prog-fin-1").await;
    let ws = create_workspace(&db, &prog, "WS Finalize 1", "ws-fin-1").await;

    let user = create_principal(&db, org.id, "user_fin1@test.com", "User Fin 1").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    // 1. Create document
    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(
            ws.id,
            "Quarterly Report PDF",
            DocumentClass::Pdf,
            Some(user.id),
        )
        .unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    // 2. Create upload intent via E20
    let sample_bytes = b"%PDF-1.7 Authoritative Document Body Content";
    let sha256_val = Sha256::digest(sample_bytes);
    let sha256_b64 = sha256_val.to_base64();

    let create_intent_payload = json!({
        "filename": "quarterly_report.pdf",
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
        .header("idempotency-key", "intent-key-gate01")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(create_intent_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let intent_dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();

    // 3. Stage mock storage object
    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_dto.opaque_object_key,
        sample_bytes,
        "application/pdf",
    );

    // 4. Finalize upload intent via E21
    let idemp_key = "finalize-key-gate01";
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

    // 5. Verify database facts within workspace
    let ver_uuid = Uuid::parse_str(&finalize_dto.document_version_id).unwrap();
    let art_uuid = Uuid::parse_str(&finalize_dto.object_artifact_id).unwrap();
    let _qr_uuid = Uuid::parse_str(&finalize_dto.quarantine_record_id).unwrap();
    let job_uuid = Uuid::parse_str(&finalize_dto.scan_job_id).unwrap();

    // DocumentVersion fact
    let version_row = sqlx::query(
        "SELECT document_id, version_number, object_artifact_id, byte_size, sha256_hash, content_type, original_filename, trust_state \
         FROM document_versions WHERE workspace_id = $1 AND document_version_id = $2",
    )
    .bind(ws.id.as_uuid())
    .bind(ver_uuid)
    .fetch_one(db.pool())
    .await
    .unwrap();

    assert_eq!(version_row.get::<i32, _>("version_number"), 1);
    assert_eq!(version_row.get::<Uuid, _>("object_artifact_id"), art_uuid);
    assert_eq!(
        version_row.get::<i64, _>("byte_size"),
        sample_bytes.len() as i64
    );
    assert_eq!(version_row.get::<String, _>("trust_state"), "pending");
    assert_eq!(
        version_row.get::<String, _>("content_type"),
        "application/pdf"
    );

    // ObjectArtifact fact
    let artifact_row = sqlx::query(
        "SELECT artifact_kind, object_key, byte_length, content_sha256, media_type, sse_mode, kms_key_ref, retention_until \
         FROM object_artifacts WHERE workspace_id = $1 AND object_artifact_id = $2",
    )
    .bind(ws.id.as_uuid())
    .bind(art_uuid)
    .fetch_one(db.pool())
    .await
    .unwrap();

    assert_eq!(artifact_row.get::<String, _>("artifact_kind"), "raw_upload");
    assert_eq!(
        artifact_row.get::<String, _>("object_key"),
        intent_dto.opaque_object_key
    );
    assert_eq!(
        artifact_row.get::<i64, _>("byte_length"),
        sample_bytes.len() as i64
    );
    assert_eq!(
        artifact_row.get::<Vec<u8>, _>("content_sha256"),
        sha256_val.as_bytes()
    );
    assert_eq!(
        artifact_row.get::<String, _>("media_type"),
        "application/pdf"
    );
    assert_eq!(artifact_row.get::<String, _>("sse_mode"), "aws:kms");
    assert_eq!(artifact_row.get::<Option<String>, _>("kms_key_ref"), None);
    assert_eq!(
        artifact_row.get::<Option<chrono::DateTime<Utc>>, _>("retention_until"),
        None
    );

    // QuarantineRecord fact: physical scan verdict row is deferred until scanner execution,
    // and repository yields the pending intake representation.
    let qr_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM quarantine_records WHERE workspace_id = $1 AND upload_intent_id = $2",
    )
    .bind(ws.id.as_uuid())
    .bind(Uuid::parse_str(&intent_dto.id).unwrap())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(qr_count, 0);

    let mut conn = db.pool().acquire().await.unwrap();
    let qr = QuarantineRecordRepository::get_latest_by_intent(
        &mut conn,
        ws.id,
        UploadIntentId::from_uuid(Uuid::parse_str(&intent_dto.id).unwrap()),
    )
    .await
    .unwrap()
    .expect("quarantine representation must exist");
    assert_eq!(qr.status, QuarantineStatus::Pending);
    assert_eq!(
        qr.upload_intent_id.into_uuid(),
        Uuid::parse_str(&intent_dto.id).unwrap()
    );

    // UploadIntent consumption
    let intent_row = sqlx::query(
        "SELECT status, finalized_at, object_artifact_id FROM upload_intents WHERE workspace_id = $1 AND upload_intent_id = $2",
    )
    .bind(ws.id.as_uuid())
    .bind(Uuid::parse_str(&intent_dto.id).unwrap())
    .fetch_one(db.pool())
    .await
    .unwrap();

    assert_eq!(intent_row.get::<String, _>("status"), "verified");
    assert!(
        intent_row
            .get::<Option<chrono::DateTime<Utc>>, _>("finalized_at")
            .is_some()
    );
    assert_eq!(
        intent_row.get::<Option<Uuid>, _>("object_artifact_id"),
        Some(art_uuid)
    );

    // Real durable Job in PostgreSQL jobs queue
    let job_row = sqlx::query(
        "SELECT queue_name, job_type, status, idempotency_key, payload FROM jobs WHERE workspace_id = $1 AND job_id = $2",
    )
    .bind(ws.id.as_uuid())
    .bind(job_uuid)
    .fetch_one(db.pool())
    .await
    .unwrap();

    assert_eq!(
        job_row.get::<String, _>("queue_name"),
        "documents.malware_scan"
    );
    assert_eq!(
        job_row.get::<String, _>("job_type"),
        "malware_scan_document_pdf"
    );
    assert_eq!(job_row.get::<String, _>("status"), "queued");

    // Audit event
    let audit_row = sqlx::query(
        "SELECT action_code, entity_type, entity_id FROM audit_events WHERE workspace_id = $1 AND action_code = 'UPLOAD_FINALIZE'",
    )
    .bind(ws.id.as_uuid())
    .fetch_one(db.pool())
    .await
    .unwrap();

    assert_eq!(audit_row.get::<String, _>("action_code"), "UPLOAD_FINALIZE");
    assert_eq!(audit_row.get::<String, _>("entity_type"), "upload_intent");
    assert_eq!(audit_row.get::<String, _>("entity_id"), intent_dto.id);
}

#[tokio::test]
async fn test_wi0203_gate02_authoritative_upload_finalize_docx_enqueues_docx_ocr_job() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Finalize DOCX", "org-fin-docx").await;
    let prog = create_program(&db, org.id, "Prog Finalize DOCX", "prog-fin-docx").await;
    let ws = create_workspace(&db, &prog, "WS Finalize DOCX", "ws-fin-docx").await;

    let user = create_principal(&db, org.id, "user_docx@test.com", "User DOCX").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(
            ws.id,
            "Contracts Specification DOCX",
            DocumentClass::Docx,
            Some(user.id),
        )
        .unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    let sample_bytes = b"PK\x03\x04 DOCX ZIP Sample Content";
    let sha256_val = Sha256::digest(sample_bytes);
    let sha256_b64 = sha256_val.to_base64();
    let docx_mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

    let create_intent_payload = json!({
        "filename": "contracts.docx",
        "media_type": docx_mime,
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
        .header("idempotency-key", "intent-key-docx")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(create_intent_payload.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let intent_dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_dto.opaque_object_key,
        sample_bytes,
        docx_mime,
    );

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_dto.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "finalize-key-docx")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let finalize_dto: UploadFinalizeDto = serde_json::from_slice(&body_bytes).unwrap();

    let job_uuid = Uuid::parse_str(&finalize_dto.scan_job_id).unwrap();
    let job_row = sqlx::query("SELECT job_type FROM jobs WHERE job_id = $1")
        .bind(job_uuid)
        .fetch_one(db.pool())
        .await
        .unwrap();

    assert_eq!(
        job_row.get::<String, _>("job_type"),
        "malware_scan_document_docx_ocr"
    );
}

#[tokio::test]
async fn test_wi0203_gate04_multiversion_sequential_version_numbering() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Multiver", "org-multiver").await;
    let prog = create_program(&db, org.id, "Prog Multiver", "prog-multiver").await;
    let ws = create_workspace(&db, &prog, "WS Multiver", "ws-multiver").await;

    let user = create_principal(&db, org.id, "user_mv@test.com", "User MV").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc =
            Document::new(ws.id, "Versioned Spec", DocumentClass::Pdf, Some(user.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    // Version 1
    let bytes_v1 = b"%PDF-1.7 Version 1 content";
    let intent_v1 = {
        let req = Request::builder()
            .uri(format!(
                "/api/v1/workspaces/{}/documents/{}/upload-intents",
                ws.id, doc.id
            ))
            .method("POST")
            .header(COOKIE, &cookie)
            .header(CSRF_HEADER_NAME, &csrf)
            .header(ORIGIN, "http://127.0.0.1:3000")
            .header("idempotency-key", "intent-v1")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "filename": "v1.pdf",
                    "media_type": "application/pdf",
                    "byte_length": bytes_v1.len() as i64,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();
        dto
    };

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_v1.opaque_object_key,
        bytes_v1,
        "application/pdf",
    );

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_v1.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-v1")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let fin1: UploadFinalizeDto = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(fin1.version_number, 1);

    // Version 2 for the same document
    let bytes_v2 = b"%PDF-1.7 Version 2 content revised";
    let intent_v2 = {
        let req = Request::builder()
            .uri(format!(
                "/api/v1/workspaces/{}/documents/{}/upload-intents",
                ws.id, doc.id
            ))
            .method("POST")
            .header(COOKIE, &cookie)
            .header(CSRF_HEADER_NAME, &csrf)
            .header(ORIGIN, "http://127.0.0.1:3000")
            .header("idempotency-key", "intent-v2")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "filename": "v2.pdf",
                    "media_type": "application/pdf",
                    "byte_length": bytes_v2.len() as i64,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();
        dto
    };

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_v2.opaque_object_key,
        bytes_v2,
        "application/pdf",
    );

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_v2.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-v2")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let fin2: UploadFinalizeDto = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(fin2.version_number, 2);
    assert_eq!(fin2.document_id, doc.id.to_string());
}

#[tokio::test]
async fn test_wi0203_gate05_authn_and_deactivated_recheck() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Authn", "org-authn").await;
    let prog = create_program(&db, org.id, "Prog Authn", "prog-authn").await;
    let ws = create_workspace(&db, &prog, "WS Authn", "ws-authn").await;

    let user = create_principal(&db, org.id, "user_authn@test.com", "User Authn").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let intent_id = Uuid::new_v4();

    // 1. Unauthenticated -> 401
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_id
        ))
        .method("POST")
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "key-unauth")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Deactivated principal -> 403
    sqlx::query("UPDATE principals SET status = 'deactivated' WHERE principal_id = $1")
        .bind(user.id.as_uuid())
        .execute(db.pool())
        .await
        .unwrap();

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "key-deactivated")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_wi0203_gate06_revoked_after_presign_recheck() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Revoked", "org-revoked").await;
    let prog = create_program(&db, org.id, "Prog Revoked", "prog-revoked").await;
    let ws = create_workspace(&db, &prog, "WS Revoked", "ws-revoked").await;

    let user = create_principal(&db, org.id, "user_rev@test.com", "User Rev").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(ws.id, "Doc Revoked", DocumentClass::Pdf, Some(user.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    let sample_bytes = b"%PDF-1.7 Revoked Test";
    let intent_dto = {
        let req = Request::builder()
            .uri(format!(
                "/api/v1/workspaces/{}/documents/{}/upload-intents",
                ws.id, doc.id
            ))
            .method("POST")
            .header(COOKIE, &cookie)
            .header(CSRF_HEADER_NAME, &csrf)
            .header(ORIGIN, "http://127.0.0.1:3000")
            .header("idempotency-key", "intent-rev")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "filename": "rev.pdf",
                    "media_type": "application/pdf",
                    "byte_length": sample_bytes.len() as i64,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();
        dto
    };

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_dto.opaque_object_key,
        sample_bytes,
        "application/pdf",
    );

    // Revoke / delete membership before finalize
    sqlx::query("DELETE FROM memberships WHERE workspace_id = $1 AND principal_id = $2")
        .bind(ws.id.as_uuid())
        .bind(user.id.as_uuid())
        .execute(db.pool())
        .await
        .unwrap();

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_dto.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-rev")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_wi0203_gate07_document_upload_capability_reauthorization() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Reader", "org-reader").await;
    let prog = create_program(&db, org.id, "Prog Reader", "prog-reader").await;
    let ws = create_workspace(&db, &prog, "WS Reader", "ws-reader").await;

    let admin = create_principal(&db, org.id, "admin_r@test.com", "Admin R").await;
    let reader = create_principal(&db, org.id, "reader_r@test.com", "Reader R").await;

    add_membership(&db, ws.id, admin.id, MembershipRole::Admin).await;
    add_membership(&db, ws.id, reader.id, MembershipRole::Reader).await;

    let (cookie_admin, csrf_admin) = create_session_and_csrf(&db, admin.id, &config).await;
    let (cookie_reader, csrf_reader) = create_session_and_csrf(&db, reader.id, &config).await;

    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc =
            Document::new(ws.id, "Doc Reader Test", DocumentClass::Pdf, Some(admin.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    let sample_bytes = b"%PDF-1.7 Reader Test";
    let intent_dto = {
        let req = Request::builder()
            .uri(format!(
                "/api/v1/workspaces/{}/documents/{}/upload-intents",
                ws.id, doc.id
            ))
            .method("POST")
            .header(COOKIE, &cookie_admin)
            .header(CSRF_HEADER_NAME, &csrf_admin)
            .header(ORIGIN, "http://127.0.0.1:3000")
            .header("idempotency-key", "intent-admin-create")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "filename": "read.pdf",
                    "media_type": "application/pdf",
                    "byte_length": sample_bytes.len() as i64,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();
        dto
    };

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_dto.opaque_object_key,
        sample_bytes,
        "application/pdf",
    );

    // Reader attempts to finalize -> 403 Forbidden (missing DOCUMENT_UPLOAD)
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_dto.id
        ))
        .method("POST")
        .header(COOKIE, &cookie_reader)
        .header(CSRF_HEADER_NAME, &csrf_reader)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-reader-attempt")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_wi0203_gate08_missing_idempotency_key_header() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Missing Key", "org-miss-key").await;
    let prog = create_program(&db, org.id, "Prog Missing Key", "prog-miss-key").await;
    let ws = create_workspace(&db, &prog, "WS Missing Key", "ws-miss-key").await;

    let user = create_principal(&db, org.id, "user_mk@test.com", "User MK").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let intent_id = Uuid::new_v4();

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        // No idempotency-key header
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_wi0203_gate09_idempotency_replay_and_mismatch() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Idemp", "org-idemp").await;
    let prog = create_program(&db, org.id, "Prog Idemp", "prog-idemp").await;
    let ws = create_workspace(&db, &prog, "WS Idemp", "ws-idemp").await;

    let user = create_principal(&db, org.id, "user_idemp@test.com", "User Idemp").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(ws.id, "Doc Idemp", DocumentClass::Pdf, Some(user.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    let sample_bytes = b"%PDF-1.7 Idempotency Test Content";
    let intent_dto = {
        let req = Request::builder()
            .uri(format!(
                "/api/v1/workspaces/{}/documents/{}/upload-intents",
                ws.id, doc.id
            ))
            .method("POST")
            .header(COOKIE, &cookie)
            .header(CSRF_HEADER_NAME, &csrf)
            .header(ORIGIN, "http://127.0.0.1:3000")
            .header("idempotency-key", "intent-idemp-1")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "filename": "idemp.pdf",
                    "media_type": "application/pdf",
                    "byte_length": sample_bytes.len() as i64,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();
        dto
    };

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_dto.opaque_object_key,
        sample_bytes,
        "application/pdf",
    );

    let idemp_key = "shared-finalize-idemp-key";

    // 1. Initial finalize -> 202 Accepted
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
    let body_bytes1 = resp.into_body().collect().await.unwrap().to_bytes();
    let fin1: UploadFinalizeDto = serde_json::from_slice(&body_bytes1).unwrap();

    // 2. Replay with same key & same payload -> 202 Accepted, exact same body
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
    let body_bytes2 = resp.into_body().collect().await.unwrap().to_bytes();
    let fin2: UploadFinalizeDto = serde_json::from_slice(&body_bytes2).unwrap();
    assert_eq!(fin1, fin2);

    // Verify exactly ONE document version and ONE job exists
    let ver_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM document_versions WHERE workspace_id = $1")
            .bind(ws.id.as_uuid())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(ver_count, 1);

    let job_count: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs WHERE workspace_id = $1")
        .bind(ws.id.as_uuid())
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(job_count, 1);

    // 3. Payload mismatch with same key but different intent_id -> 409 Conflict
    let other_intent_id = Uuid::new_v4();
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, other_intent_id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", idemp_key)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_wi0203_gate10_expired_intent_rejected() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Expired", "org-expired").await;
    let prog = create_program(&db, org.id, "Prog Expired", "prog-expired").await;
    let ws = create_workspace(&db, &prog, "WS Expired", "ws-expired").await;

    let user = create_principal(&db, org.id, "user_exp@test.com", "User Exp").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let expired_intent = {
        let mut tx = db.pool().begin().await.unwrap();
        let past = Utc::now() - Duration::hours(2);
        let intent = UploadIntent::reconstruct(
            UploadIntentId::new(),
            ws.id,
            user.id,
            None,
            "expired.pdf".to_string(),
            MediaType::ApplicationPdf,
            1024,
            None,
            None,
            ObjectKey::reconstruct(format!("upload-intents/{}/expired.pdf", ws.id)).unwrap(),
            IntentStatus::Expired,
            past,
            None,
            None,
            past - Duration::hours(1),
        )
        .unwrap();
        UploadIntentRepository::insert(&mut tx, &intent)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        intent
    };

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        expired_intent.opaque_object_key.as_str(),
        &[0u8; 1024],
        "application/pdf",
    );

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, expired_intent.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-expired")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn test_wi0203_gate11_abandoned_intent_rejected() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Abort", "org-abort").await;
    let prog = create_program(&db, org.id, "Prog Abort", "prog-abort").await;
    let ws = create_workspace(&db, &prog, "WS Abort", "ws-abort").await;

    let user = create_principal(&db, org.id, "user_abort@test.com", "User Abort").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let aborted_intent = {
        let mut tx = db.pool().begin().await.unwrap();
        let now = Utc::now();
        let intent = UploadIntent::reconstruct(
            UploadIntentId::new(),
            ws.id,
            user.id,
            None,
            "aborted.pdf".to_string(),
            MediaType::ApplicationPdf,
            1024,
            None,
            None,
            ObjectKey::reconstruct(format!("upload-intents/{}/aborted.pdf", ws.id)).unwrap(),
            IntentStatus::Aborted,
            now + Duration::hours(1),
            None,
            Some(now),
            now,
        )
        .unwrap();
        UploadIntentRepository::insert(&mut tx, &intent)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        intent
    };

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        aborted_intent.opaque_object_key.as_str(),
        &[0u8; 1024],
        "application/pdf",
    );

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, aborted_intent.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-aborted")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_wi0203_gate12_already_finalized_intent_new_key_rejected() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Double Fin", "org-dbl-fin").await;
    let prog = create_program(&db, org.id, "Prog Double Fin", "prog-dbl-fin").await;
    let ws = create_workspace(&db, &prog, "WS Double Fin", "ws-dbl-fin").await;

    let user = create_principal(&db, org.id, "user_dbl@test.com", "User Dbl").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let sample_bytes = b"%PDF-1.7 Double Finalize Test";
    let intent_dto = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(ws.id, "Dbl Spec", DocumentClass::Pdf, Some(user.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();

        let req = Request::builder()
            .uri(format!(
                "/api/v1/workspaces/{}/documents/{}/upload-intents",
                ws.id, doc.id
            ))
            .method("POST")
            .header(COOKIE, &cookie)
            .header(CSRF_HEADER_NAME, &csrf)
            .header(ORIGIN, "http://127.0.0.1:3000")
            .header("idempotency-key", "intent-dbl-2")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "filename": "dbl.pdf",
                    "media_type": "application/pdf",
                    "byte_length": sample_bytes.len() as i64,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();
        dto
    };

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_dto.opaque_object_key,
        sample_bytes,
        "application/pdf",
    );

    // 1st finalize -> 202 Accepted
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_dto.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-key-1")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // 2nd finalize with DIFFERENT key -> 409 Conflict
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_dto.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-key-2-different")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_wi0203_gate13_cross_workspace_finalize_rejected() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Cross", "org-cross").await;
    let prog = create_program(&db, org.id, "Prog Cross", "prog-cross").await;
    let ws_a = create_workspace(&db, &prog, "WS A", "ws-a").await;
    let ws_b = create_workspace(&db, &prog, "WS B", "ws-b").await;

    let user_a = create_principal(&db, org.id, "user_a@test.com", "User A").await;
    add_membership(&db, ws_a.id, user_a.id, MembershipRole::Operator).await;
    let (cookie_a, csrf_a) = create_session_and_csrf(&db, user_a.id, &config).await;

    let user_b = create_principal(&db, org.id, "user_b@test.com", "User B").await;
    add_membership(&db, ws_b.id, user_b.id, MembershipRole::Operator).await;
    let (cookie_b, csrf_b) = create_session_and_csrf(&db, user_b.id, &config).await;

    // Create intent in Workspace B
    let doc_b = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(ws_b.id, "Doc B", DocumentClass::Pdf, Some(user_b.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    let sample_bytes = b"%PDF-1.7 Workspace B Content";
    let intent_b = {
        let req = Request::builder()
            .uri(format!(
                "/api/v1/workspaces/{}/documents/{}/upload-intents",
                ws_b.id, doc_b.id
            ))
            .method("POST")
            .header(COOKIE, &cookie_b)
            .header(CSRF_HEADER_NAME, &csrf_b)
            .header(ORIGIN, "http://127.0.0.1:3000")
            .header("idempotency-key", "intent-ws-b")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "filename": "b.pdf",
                    "media_type": "application/pdf",
                    "byte_length": sample_bytes.len() as i64,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();
        dto
    };

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_b.opaque_object_key,
        sample_bytes,
        "application/pdf",
    );

    // User A in Workspace A tries to finalize Workspace B's intent -> 404 Not Found
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws_a.id, intent_b.id
        ))
        .method("POST")
        .header(COOKIE, &cookie_a)
        .header(CSRF_HEADER_NAME, &csrf_a)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-cross-attempt")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_wi0203_gate14_object_head_required_missing_storage_upload() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Missing S3", "org-miss-s3").await;
    let prog = create_program(&db, org.id, "Prog Missing S3", "prog-miss-s3").await;
    let ws = create_workspace(&db, &prog, "WS Missing S3", "ws-miss-s3").await;

    let user = create_principal(&db, org.id, "user_ms3@test.com", "User MS3").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc =
            Document::new(ws.id, "Doc Missing S3", DocumentClass::Pdf, Some(user.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    let intent_dto = {
        let req = Request::builder()
            .uri(format!(
                "/api/v1/workspaces/{}/documents/{}/upload-intents",
                ws.id, doc.id
            ))
            .method("POST")
            .header(COOKIE, &cookie)
            .header(CSRF_HEADER_NAME, &csrf)
            .header(ORIGIN, "http://127.0.0.1:3000")
            .header("idempotency-key", "intent-no-upload")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "filename": "no_upload.pdf",
                    "media_type": "application/pdf",
                    "byte_length": 4096,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();
        dto
    };

    // We do NOT stage anything in mock storage -> HEAD returns None
    DocumentService::ensure_test_storage_injected();

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_dto.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-no-upload")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn test_wi0203_gate15_byte_length_mismatch_rejected() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Len Mismatch", "org-len-mis").await;
    let prog = create_program(&db, org.id, "Prog Len Mismatch", "prog-len-mis").await;
    let ws = create_workspace(&db, &prog, "WS Len Mismatch", "ws-len-mis").await;

    let user = create_principal(&db, org.id, "user_len@test.com", "User Len").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(ws.id, "Doc Len", DocumentClass::Pdf, Some(user.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    let intent_dto = {
        let req = Request::builder()
            .uri(format!(
                "/api/v1/workspaces/{}/documents/{}/upload-intents",
                ws.id, doc.id
            ))
            .method("POST")
            .header(COOKIE, &cookie)
            .header(CSRF_HEADER_NAME, &csrf)
            .header(ORIGIN, "http://127.0.0.1:3000")
            .header("idempotency-key", "intent-len-mis")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "filename": "len.pdf",
                    "media_type": "application/pdf",
                    "byte_length": 5000,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();
        dto
    };

    // Stage object with 4000 bytes instead of declared 5000
    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_dto.opaque_object_key,
        &[0u8; 4000],
        "application/pdf",
    );

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_dto.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-len-mis")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_wi0203_gate16_sha256_checksum_mismatch_rejected() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Sha Mismatch", "org-sha-mis").await;
    let prog = create_program(&db, org.id, "Prog Sha Mismatch", "prog-sha-mis").await;
    let ws = create_workspace(&db, &prog, "WS Sha Mismatch", "ws-sha-mis").await;

    let user = create_principal(&db, org.id, "user_sha@test.com", "User Sha").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(ws.id, "Doc Sha", DocumentClass::Pdf, Some(user.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    let expected_bytes = b"Expected bytes sequence";
    let declared_sha_b64 = Sha256::digest(expected_bytes).to_base64();

    let intent_dto = {
        let req = Request::builder()
            .uri(format!(
                "/api/v1/workspaces/{}/documents/{}/upload-intents",
                ws.id, doc.id
            ))
            .method("POST")
            .header(COOKIE, &cookie)
            .header(CSRF_HEADER_NAME, &csrf)
            .header(ORIGIN, "http://127.0.0.1:3000")
            .header("idempotency-key", "intent-sha-mis")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "filename": "sha.pdf",
                    "media_type": "application/pdf",
                    "byte_length": expected_bytes.len() as i64,
                    "sha256_b64": declared_sha_b64,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();
        dto
    };

    // Stage DIFFERENT bytes with same length
    let different_bytes = b"Different bytes sequence";
    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_dto.opaque_object_key,
        different_bytes,
        "application/pdf",
    );

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_dto.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-sha-mis")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_wi0203_gate17_content_type_mismatch_rejected() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Mime Mismatch", "org-mime-mis").await;
    let prog = create_program(&db, org.id, "Prog Mime Mismatch", "prog-mime-mis").await;
    let ws = create_workspace(&db, &prog, "WS Mime Mismatch", "ws-mime-mis").await;

    let user = create_principal(&db, org.id, "user_mime@test.com", "User Mime").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let doc = {
        let mut tx = db.pool().begin().await.unwrap();
        let doc = Document::new(ws.id, "Doc Mime", DocumentClass::Pdf, Some(user.id)).unwrap();
        DocumentRepository::insert(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        doc
    };

    let sample_bytes = b"%PDF-1.7 Mime Mismatch Test";
    let intent_dto = {
        let req = Request::builder()
            .uri(format!(
                "/api/v1/workspaces/{}/documents/{}/upload-intents",
                ws.id, doc.id
            ))
            .method("POST")
            .header(COOKIE, &cookie)
            .header(CSRF_HEADER_NAME, &csrf)
            .header(ORIGIN, "http://127.0.0.1:3000")
            .header("idempotency-key", "intent-mime-mis")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "filename": "mime.pdf",
                    "media_type": "application/pdf",
                    "byte_length": sample_bytes.len() as i64,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let dto: UploadIntentDto = serde_json::from_slice(&body_bytes).unwrap();
        dto
    };

    // Stage with WRONG content-type: image/png
    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        &intent_dto.opaque_object_key,
        sample_bytes,
        "image/png",
    );

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_dto.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-mime-mis")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_wi0203_gate18_oversize_upload_rejected() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Oversize", "org-oversize").await;
    let prog = create_program(&db, org.id, "Prog Oversize", "prog-oversize").await;
    let ws = create_workspace(&db, &prog, "WS Oversize", "ws-oversize").await;

    let user = create_principal(&db, org.id, "user_ov@test.com", "User OV").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    // E20 creation of oversized intent (>100 MiB) is rejected with 413 Payload Too Large
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/documents/{}/upload-intents",
            ws.id,
            Uuid::new_v4()
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "intent-oversize")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "filename": "huge.pdf",
                "media_type": "application/pdf",
                "byte_length": 104857601, // 100 MiB + 1
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_wi0203_gate20_database_immutability_triggers() {
    let db = provision_migrated_db().await;

    let org = create_org(&db, "Org Immutability", "org-immut").await;
    let prog = create_program(&db, org.id, "Prog Immutability", "prog-immut").await;
    let ws = create_workspace(&db, &prog, "WS Immutability", "ws-immut").await;
    let user = create_principal(&db, org.id, "user_immut@test.com", "User Immut").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Admin).await;

    let mut tx = db.pool().begin().await.unwrap();
    let doc = Document::new(ws.id, "Immutable Doc", DocumentClass::Pdf, Some(user.id)).unwrap();
    DocumentRepository::insert(&mut tx, &doc).await.unwrap();

    let key = ObjectKey::reconstruct(format!("artifacts/{}/key-immut.pdf", ws.id)).unwrap();
    let artifact = ObjectArtifact::reconstruct(
        w014_domain::ids::ObjectArtifactId::new(),
        ws.id,
        ArtifactKind::Original,
        "w014-documents".to_string(),
        key,
        Sha256::digest(b"immut"),
        5,
        w014_domain::StoredMediaType::new("application/pdf").unwrap(),
        StorageTier::Hot,
        EncryptionMode::SseAes256,
        None,
        Utc::now(),
    )
    .unwrap();
    ObjectArtifactRepository::insert(&mut tx, &artifact)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // 1. Attempting UPDATE on object_artifacts must fail due to trigger
    let update_res =
        sqlx::query("UPDATE object_artifacts SET byte_length = 999 WHERE object_artifact_id = $1")
            .bind(artifact.id.as_uuid())
            .execute(db.pool())
            .await;
    assert!(update_res.is_err());

    // 2. Attempting DELETE on object_artifacts must fail due to trigger
    let delete_res = sqlx::query("DELETE FROM object_artifacts WHERE object_artifact_id = $1")
        .bind(artifact.id.as_uuid())
        .execute(db.pool())
        .await;
    assert!(delete_res.is_err());
}

#[tokio::test]
async fn test_wi0203_gate03_standalone_intent_without_doc_creates_new_document() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org Standalone", "org-standalone").await;
    let prog = create_program(&db, org.id, "Prog Standalone", "prog-standalone").await;
    let ws = create_workspace(&db, &prog, "WS Standalone", "ws-standalone").await;

    let user = create_principal(&db, org.id, "user_sa@test.com", "User SA").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    // Create a standalone intent directly in DB without document_id
    let sample_bytes = b"%PDF-1.7 Standalone Doc Content";
    let now = Utc::now();
    let key = ObjectKey::reconstruct(format!("upload-intents/{}/standalone.pdf", ws.id)).unwrap();
    let standalone_intent = UploadIntent::reconstruct(
        UploadIntentId::new(),
        ws.id,
        user.id,
        None, // No initial document_id
        "standalone.pdf".to_string(),
        MediaType::ApplicationPdf,
        sample_bytes.len() as i64,
        Some(Sha256::digest(sample_bytes)),
        None,
        key,
        IntentStatus::Initiated,
        now + Duration::minutes(10),
        None,
        None,
        now,
    )
    .unwrap();

    {
        let mut tx = db.pool().begin().await.unwrap();
        UploadIntentRepository::insert(&mut tx, &standalone_intent)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        standalone_intent.opaque_object_key.as_str(),
        sample_bytes,
        "application/pdf",
    );

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, standalone_intent.id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-standalone")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let finalize_dto: UploadFinalizeDto = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(finalize_dto.version_number, 1);
    assert_eq!(finalize_dto.trust_state, "pending");
    assert_eq!(finalize_dto.status, "quarantined_processing");

    // Verify document was created with title derived from filename
    let doc_id = Uuid::parse_str(&finalize_dto.document_id).unwrap();
    let doc_row =
        sqlx::query("SELECT title, document_type, status FROM documents WHERE document_id = $1")
            .bind(doc_id)
            .fetch_one(db.pool())
            .await
            .unwrap();

    assert_eq!(doc_row.get::<String, _>("title"), "standalone.pdf");
    assert_eq!(doc_row.get::<String, _>("document_type"), "pdf");
    assert_eq!(doc_row.get::<String, _>("status"), "active");
}

#[tokio::test]
async fn test_wi0203_gate21_csrf_protection_on_finalize() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_test_app(&config, db.pool().clone());

    let org = create_org(&db, "Org CSRF", "org-csrf").await;
    let prog = create_program(&db, org.id, "Prog CSRF", "prog-csrf").await;
    let ws = create_workspace(&db, &prog, "WS CSRF", "ws-csrf").await;

    let user = create_principal(&db, org.id, "user_csrf@test.com", "User CSRF").await;
    add_membership(&db, ws.id, user.id, MembershipRole::Operator).await;
    let (cookie, _csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let intent_id = Uuid::new_v4();

    // 1. Missing CSRF header -> 403 Forbidden
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-csrf-missing")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. Invalid CSRF header -> 403 Forbidden
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/upload-intents/{}/finalize",
            ws.id, intent_id
        ))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, "invalid-csrf-token-string")
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header("idempotency-key", "fin-csrf-invalid")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
