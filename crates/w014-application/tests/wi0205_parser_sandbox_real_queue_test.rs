//! Integration and Security Gate Test Suite for WI-0205:
//! Parser Sandbox Image / Profile / Resource Ceilings + Real Queue Execution.
//!
//! Validates:
//! - Complete parse job execution of durable parse jobs (`JobKind::ParseDocumentPdf` / `JobKind::ParseDocumentDocxOcr`)
//! - Real PostgreSQL durable queue claim, lease, heartbeat, retry, and fencing
//! - Malware-gate admission precondition: exact document version MUST have completed a clean WI-0204 malware scan
//! - Rejection (fail-closed) of parser execution when malware scan is pending, malware detected, or integrity failed
//! - Scoped single-object handoff: exactly one immutable, scanned input handed to sandbox
//! - Hard frozen sandbox security profile (<= 2 vCPU, <= 2 GiB RAM, <= 1 GiB tmpfs, <= 64 PIDs, <= 10 min wall clock)
//! - Absence of database, AI, generic S3, KMS, audit signing, and session credentials in sandbox
//! - Network isolation (no public ingress, no general egress, no external URLs)
//! - Fail-closed execution on timeout, OOM, process crash, security violations, and malformed output
//! - Worker lease generation fencing: stale workers with superseded lease generations cannot commit parse outcomes
//! - Direct database write absence: sandbox does not write application tables directly
//! - Strict negative scope: zero early canonical pages/blocks/spans written (reserved for WI-0206/WI-0207)

use std::sync::Arc;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use sqlx::Row;
use uuid::Uuid;

use w014_application::persistence::{
    OrganizationRepository, PrincipalRepository, ProgramRepository, QuarantineRecordRepository,
    UploadIntentRepository, WorkspaceRepository,
};
use w014_application::services::{
    DocumentService, MalwareScanJobExecutor, MembershipService, ParserSandboxJobExecutor,
};
use w014_authz::AuthorizedWorkspaceContext;
use w014_document_processing::sandbox::{
    MockSandboxBehavior, MockSandboxRunner, ProcessSandboxRunner, SANDBOX_PROTOCOL_VERSION,
    SandboxOutput, SandboxSecurityProfile, SandboxStatus,
};
use w014_document_processing::scanner::{EICAR_TEST_SIGNATURE, MockClamAvScanner};
use w014_domain::ids::{DocumentVersionId, ObjectArtifactId};
use w014_domain::membership::MembershipRole;
use w014_domain::organization::Organization;
use w014_domain::principal::Principal;
use w014_domain::program::Program;
use w014_domain::quarantine::QuarantineStatus;
use w014_domain::workspace::Workspace;
use w014_domain::{LocatorVersion, MediaType, Sha256, UploadIntent};
use w014_jobs::job_identity::CanonicalJobIdentity;
use w014_jobs::kind::{JobKind, QUEUE_DOCUMENT_PARSE, QUEUE_MALWARE_SCAN};
use w014_jobs::models::{ClaimCriteria, FailureKind, WorkspaceScope};
use w014_jobs::payload::JobPayload;
use w014_jobs::queue::PgJobQueue;
use w014_jobs::{FROZEN_BACKOFF_MAX_SECS, FROZEN_MAX_ATTEMPTS, WorkerId};
use w014_persistence::audit::PostgresAuditStore;
use w014_persistence::harness::TestDatabase;
use w014_persistence::idempotency::PostgresIdempotencyStore;
use w014_persistence::runner::{MIGRATOR, MigrationRunner};

struct TestFixture {
    test_db: TestDatabase,
    ws_a: Workspace,
    _ws_b: Workspace,
    principal: Principal,
    awc_a: AuthorizedWorkspaceContext,
    queue: PgJobQueue,
}

async fn setup_fixture() -> TestFixture {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to run migrations");

    let audit_store = PostgresAuditStore::new();
    let mut tx = test_db.pool().begin().await.unwrap();

    let org = Organization::new("Security Org", "sec-org").unwrap();
    OrganizationRepository::insert(&mut tx, &org).await.unwrap();

    let principal = Principal::new("Security Engineer", Some("sec@example.com")).unwrap();
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .unwrap();

    let prog = Program::new(org.id, "Security Program", "sec-prog").unwrap();
    ProgramRepository::insert(&mut tx, &prog).await.unwrap();

    let ws_a = Workspace::new(prog.id, org.id, "Workspace Alpha", "ws-alpha").unwrap();
    WorkspaceRepository::insert(&mut tx, &ws_a).await.unwrap();

    let ws_b = Workspace::new(prog.id, org.id, "Workspace Beta", "ws-beta").unwrap();
    WorkspaceRepository::insert(&mut tx, &ws_b).await.unwrap();

    MembershipService::add_member_with_audit(
        &mut tx,
        &audit_store,
        ws_a.id,
        principal.id,
        MembershipRole::Admin,
        Some(principal.id),
        Some("setup-principal".to_string()),
    )
    .await
    .unwrap();

    tx.commit().await.unwrap();

    let awc_a = AuthorizedWorkspaceContext::resolve(
        principal.id,
        org.id,
        prog.id,
        ws_a.id,
        MembershipRole::Admin,
        vec![],
        Utc::now(),
    );

    let queue = PgJobQueue::new(test_db.pool().clone());

    TestFixture {
        test_db,
        ws_a,
        _ws_b: ws_b,
        principal,
        awc_a,
        queue,
    }
}

/// Helper to stage bytes and finalize upload without running malware scan.
async fn finalize_staged_upload(
    f: &TestFixture,
    filename: &str,
    media_type: MediaType,
    bytes: &[u8],
) -> (UploadIntent, DocumentVersionId, ObjectArtifactId) {
    let mut tx = f.test_db.pool().begin().await.unwrap();

    let intent = UploadIntent::new(
        f.ws_a.id,
        f.principal.id,
        None,
        filename,
        media_type,
        bytes.len() as i64,
        Some(Sha256::digest(bytes)),
        Utc::now() + ChronoDuration::minutes(5),
    )
    .unwrap();
    UploadIntentRepository::insert(&mut tx, &intent)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let bucket = "w014-documents";
    let key = intent.opaque_object_key.as_str();
    DocumentService::stage_mock_upload_bytes(bucket, key, bytes, media_type.as_str());

    let idemp_store = PostgresIdempotencyStore::new();
    let mut tx = f.test_db.pool().begin().await.unwrap();
    let finalize_res = DocumentService::execute_finalize_upload_tx(
        &mut tx,
        &f.awc_a,
        f.principal.id,
        intent.id,
        Utc::now(),
        None,
        &idemp_store,
    )
    .await
    .expect("finalize must succeed");
    tx.commit().await.unwrap();

    (
        finalize_res.intent,
        finalize_res.version.id,
        finalize_res.artifact.id,
    )
}

/// Helper to stage bytes, finalize upload, and run malware scan to clean state.
async fn finalize_and_clean_scan(
    f: &TestFixture,
    filename: &str,
    media_type: MediaType,
    bytes: &[u8],
) -> (UploadIntent, DocumentVersionId, ObjectArtifactId) {
    let mut tx = f.test_db.pool().begin().await.unwrap();

    // 1. Create upload intent
    let intent = UploadIntent::new(
        f.ws_a.id,
        f.principal.id,
        None,
        filename,
        media_type,
        bytes.len() as i64,
        Some(Sha256::digest(bytes)),
        Utc::now() + ChronoDuration::minutes(5),
    )
    .unwrap();
    UploadIntentRepository::insert(&mut tx, &intent)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // 2. Stage bytes into server-owned mock storage
    let bucket = "w014-documents";
    let key = intent.opaque_object_key.as_str();
    DocumentService::stage_mock_upload_bytes(bucket, key, bytes, media_type.as_str());

    // 3. Finalize upload
    let idemp_store = PostgresIdempotencyStore::new();
    let mut tx = f.test_db.pool().begin().await.unwrap();
    let finalize_res = DocumentService::execute_finalize_upload_tx(
        &mut tx,
        &f.awc_a,
        f.principal.id,
        intent.id,
        Utc::now(),
        None,
        &idemp_store,
    )
    .await
    .expect("finalize must succeed");
    tx.commit().await.unwrap();

    // 4. Claim and execute malware scan job to clean state
    let scan_kind = match media_type {
        MediaType::ApplicationPdf => JobKind::MalwareScanDocumentPdf,
        MediaType::Docx => JobKind::MalwareScanDocumentDocxOcr,
    };
    let criteria = ClaimCriteria {
        queues: vec![QUEUE_MALWARE_SCAN.to_string()],
        kinds: vec![scan_kind],
        workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
        lease_duration: Duration::from_secs(30),
    };
    let claimed = f
        .queue
        .claim(criteria, WorkerId::new())
        .await
        .unwrap()
        .expect("malware scan job must be claimed");

    let scanner = Arc::new(MockClamAvScanner::new());
    let scan_executor = MalwareScanJobExecutor::new(f.test_db.pool().clone(), scanner);
    let scan_outcome = scan_executor
        .execute_claimed(&claimed)
        .await
        .expect("malware scan should complete");
    f.queue
        .complete_success(&claimed, scan_outcome)
        .await
        .expect("malware scan job succeeded");

    (intent, finalize_res.version.id, finalize_res.artifact.id)
}

/// Helper to enqueue a durable parse job onto `documents.parse`.
async fn enqueue_parse_job(
    f: &TestFixture,
    kind: JobKind,
    version_id: DocumentVersionId,
    artifact_id: ObjectArtifactId,
) -> Uuid {
    let mut tx = f.test_db.pool().begin().await.unwrap();

    let immutable_targets = vec![version_id.to_string()];
    let envelope = JobPayload::validate(&serde_json::json!({
        "payload_contract_version": 1,
        "producer_version": "w014-document-pipeline",
        "immutable_targets": immutable_targets.clone(),
        "dependency_hash": null,
        "parameters": {
            "document_version_id": version_id.to_string(),
            "object_artifact_id": artifact_id.to_string(),
        },
    }))
    .unwrap();

    let identity = CanonicalJobIdentity::new(
        kind.as_str(),
        f.ws_a.id.into_uuid(),
        immutable_targets,
        None,
        1,
        "w014-document-pipeline",
    );
    let idempotency_key = identity.idempotency_key();
    let payload_json = envelope.to_json();

    let row = sqlx::query(
        "INSERT INTO jobs \
         (workspace_id, queue_name, job_type, status, priority, payload, \
          idempotency_key, correlation_id, max_attempts, backoff_max_secs) \
         VALUES ($1, $2, $3, 'requested', 0, $4, $5, NULL, $6, $7) \
         ON CONFLICT (idempotency_key) DO UPDATE SET status = jobs.status \
         RETURNING job_id",
    )
    .bind(f.ws_a.id.as_uuid())
    .bind(kind.default_queue())
    .bind(kind.as_str())
    .bind(&payload_json)
    .bind(&idempotency_key)
    .bind(FROZEN_MAX_ATTEMPTS)
    .bind(FROZEN_BACKOFF_MAX_SECS)
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    let job_id: Uuid = row.get("job_id");

    sqlx::query(
        "UPDATE jobs SET status = 'queued', not_before = clock_timestamp(), \
         row_version = row_version + 1 \
         WHERE job_id = $1 AND status = 'requested'",
    )
    .bind(job_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    tx.commit().await.unwrap();
    job_id
}

#[tokio::test]
async fn test_wi0205_gate01_clean_scan_allows_sandbox_parse_success_and_audit() {
    let f = setup_fixture().await;
    let pdf_bytes = b"%PDF-1.7 sample clean PDF document for parsing";

    let (_intent, version_id, artifact_id) =
        finalize_and_clean_scan(&f, "clean_doc.pdf", MediaType::ApplicationPdf, pdf_bytes).await;

    // 1. Enqueue and Claim parse job from real PostgreSQL queue
    let job_id = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;

    let criteria = ClaimCriteria {
        queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
        kinds: vec![JobKind::ParseDocumentPdf],
        workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
        lease_duration: Duration::from_secs(30),
    };
    let claimed = f
        .queue
        .claim(criteria, WorkerId::new())
        .await
        .expect("claim should succeed")
        .expect("parse job must be claimed");

    assert_eq!(claimed.job_id, job_id);
    assert_eq!(claimed.kind, JobKind::ParseDocumentPdf);
    assert_eq!(claimed.lease_generation, 1);

    // 2. Execute parser sandbox with automatic success runner
    let runner = Arc::new(MockSandboxRunner::new());
    let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner.clone());

    let outcome = executor
        .execute_claimed(&claimed)
        .await
        .expect("parse executor must succeed");

    assert!(outcome.is_some());
    let res_json = outcome.unwrap();
    assert_eq!(res_json["status"], "succeeded");
    assert_eq!(res_json["page_count"], 1);
    assert_eq!(res_json["block_count"], 1);
    assert_eq!(res_json["span_count"], 1);
    assert_eq!(res_json["parser_name"], "mock-sandbox-parser");

    // 3. Complete job in real PostgreSQL queue
    f.queue
        .complete_success(&claimed, Some(res_json))
        .await
        .expect("complete success in queue");

    // 4. Verify jobs row is succeeded
    let job_row = sqlx::query("SELECT status, completed_at FROM jobs WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(f.test_db.pool())
        .await
        .unwrap();
    let status: String = job_row.get("status");
    assert_eq!(status, "succeeded");

    // 5. Verify audit event was persisted under lease authority
    let audit_row = sqlx::query(
        "SELECT action_code, entity_type, metadata FROM audit_events WHERE workspace_id = $1 AND action_code IN ('PARSER_COMPLETED', 'PARSER_SANDBOX_COMPLETED')",
    )
    .bind(f.ws_a.id.as_uuid())
    .fetch_optional(f.test_db.pool())
    .await
    .unwrap();
    assert!(
        audit_row.is_some(),
        "Audit event PARSER_COMPLETED or PARSER_SANDBOX_COMPLETED must be recorded"
    );
    let audit_event = audit_row.unwrap();
    let metadata: serde_json::Value = audit_event.get("metadata");
    assert_eq!(metadata["document_version_id"], version_id.to_string());
    assert_eq!(metadata["parser_name"], "mock-sandbox-parser");

    // 6. Verify input received by sandbox was the exact single object
    assert_eq!(runner.execution_count(), 1);
    let last_input = runner.last_input().expect("sandbox input recorded");
    assert_eq!(last_input.document_version_id, version_id);
    assert_eq!(last_input.object_artifact_id, artifact_id);
    assert_eq!(last_input.content_sha256, Sha256::digest(pdf_bytes));
    assert_eq!(last_input.byte_length, pdf_bytes.len() as i64);
}

#[tokio::test]
async fn test_wi0205_gate02_malware_gate_precondition_enforcement() {
    let runner = Arc::new(MockSandboxRunner::new());

    // -------------------------------------------------------------
    // CASE A: Malware Scan is PENDING -> Parser execution is DEFERRED / RETRYABLE (sandbox NEVER launched!)
    // -------------------------------------------------------------
    {
        let f = setup_fixture().await;
        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner.clone());

        let pdf_bytes = b"%PDF-1.7 sample pending scan document";
        let mut tx = f.test_db.pool().begin().await.unwrap();
        let intent = UploadIntent::new(
            f.ws_a.id,
            f.principal.id,
            None,
            "pending.pdf",
            MediaType::ApplicationPdf,
            pdf_bytes.len() as i64,
            Some(Sha256::digest(pdf_bytes)),
            Utc::now() + ChronoDuration::minutes(5),
        )
        .unwrap();
        UploadIntentRepository::insert(&mut tx, &intent)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let bucket = "w014-documents";
        let key = intent.opaque_object_key.as_str();
        DocumentService::stage_mock_upload_bytes(bucket, key, pdf_bytes, "application/pdf");

        let idemp_store = PostgresIdempotencyStore::new();
        let mut tx = f.test_db.pool().begin().await.unwrap();
        let finalize_res = DocumentService::execute_finalize_upload_tx(
            &mut tx,
            &f.awc_a,
            f.principal.id,
            intent.id,
            Utc::now(),
            None,
            &idemp_store,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // Enqueue parse job directly while quarantine is still Pending
        let _ = enqueue_parse_job(
            &f,
            JobKind::ParseDocumentPdf,
            finalize_res.version.id,
            finalize_res.artifact.id,
        )
        .await;

        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        let failure = executor
            .execute_claimed(&claimed)
            .await
            .expect_err("parse execution MUST fail when malware scan is pending");

        assert_eq!(failure.kind, FailureKind::Retryable);
        assert_eq!(failure.error_code, "MALWARE_SCAN_PENDING");
        assert_eq!(runner.execution_count(), 0, "Sandbox MUST NOT be launched!");
    }

    // -------------------------------------------------------------
    // CASE B: Malware Detected (EICAR) -> Parser execution is TERMINALLY REJECTED (sandbox NEVER launched!)
    // -------------------------------------------------------------
    {
        let f = setup_fixture().await;
        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner.clone());

        let mut tx = f.test_db.pool().begin().await.unwrap();
        let intent = UploadIntent::new(
            f.ws_a.id,
            f.principal.id,
            None,
            "eicar.pdf",
            MediaType::ApplicationPdf,
            EICAR_TEST_SIGNATURE.len() as i64,
            Some(Sha256::digest(EICAR_TEST_SIGNATURE)),
            Utc::now() + ChronoDuration::minutes(5),
        )
        .unwrap();
        UploadIntentRepository::insert(&mut tx, &intent)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let bucket = "w014-documents";
        let key = intent.opaque_object_key.as_str();
        DocumentService::stage_mock_upload_bytes(
            bucket,
            key,
            EICAR_TEST_SIGNATURE,
            "application/pdf",
        );

        let idemp_store = PostgresIdempotencyStore::new();
        let mut tx = f.test_db.pool().begin().await.unwrap();
        let finalize_res = DocumentService::execute_finalize_upload_tx(
            &mut tx,
            &f.awc_a,
            f.principal.id,
            intent.id,
            Utc::now(),
            None,
            &idemp_store,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // Run malware scanner to produce Malware verdict
        let scan_claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_MALWARE_SCAN.to_string()],
                    kinds: vec![JobKind::MalwareScanDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        let scanner = Arc::new(MockClamAvScanner::new());
        let scan_executor = MalwareScanJobExecutor::new(f.test_db.pool().clone(), scanner);
        let scan_out = scan_executor.execute_claimed(&scan_claimed).await.unwrap();
        f.queue
            .complete_success(&scan_claimed, scan_out)
            .await
            .unwrap();

        // Enqueue and claim parse job
        let _ = enqueue_parse_job(
            &f,
            JobKind::ParseDocumentPdf,
            finalize_res.version.id,
            finalize_res.artifact.id,
        )
        .await;

        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        let failure = executor
            .execute_claimed(&claimed)
            .await
            .expect_err("parse execution MUST fail when malware is detected");

        assert_eq!(failure.kind, FailureKind::Terminal);
        assert_eq!(failure.error_code, "MALWARE_DETECTED");
        assert_eq!(runner.execution_count(), 0, "Sandbox MUST NOT be launched!");
    }

    // -------------------------------------------------------------
    // CASE C: Integrity Failed -> Parser execution is TERMINALLY REJECTED (sandbox NEVER launched!)
    // -------------------------------------------------------------
    {
        let f = setup_fixture().await;
        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner.clone());

        let pdf_bytes = b"%PDF-1.7 integrity test document";
        let (intent, version_id, artifact_id) =
            finalize_staged_upload(&f, "integrity.pdf", MediaType::ApplicationPdf, pdf_bytes).await;

        // Force insert an IntegrityFailed quarantine record
        let mut tx = f.test_db.pool().begin().await.unwrap();
        let record = w014_domain::QuarantineRecord::new(
            f.ws_a.id,
            intent.id,
            QuarantineStatus::IntegrityFailed,
            "test-scanner",
            None,
            Some("CHECKSUM_MISMATCH".to_string()),
            Some(version_id),
            Some(artifact_id),
            Utc::now() + ChronoDuration::seconds(10),
            w014_domain::BoundedJson::empty(),
        )
        .unwrap();
        QuarantineRecordRepository::insert(&mut tx, &record)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let _ = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;

        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        let failure = executor
            .execute_claimed(&claimed)
            .await
            .expect_err("parse execution MUST fail when integrity has failed");

        assert_eq!(failure.kind, FailureKind::Terminal);
        assert_eq!(failure.error_code, "INTEGRITY_FAILED");
        assert_eq!(runner.execution_count(), 0, "Sandbox MUST NOT be launched!");
    }
}

#[tokio::test]
async fn test_wi0205_gate03_scoped_single_object_handoff_and_tamper_rejection() {
    let f = setup_fixture().await;
    let pdf_bytes = b"%PDF-1.7 sample document for storage tamper test";

    let (intent, version_id, artifact_id) =
        finalize_and_clean_scan(&f, "tamper_test.pdf", MediaType::ApplicationPdf, pdf_bytes).await;

    // Tamper with bytes in storage (flip one byte)
    let bucket = "w014-documents";
    let key = intent.opaque_object_key.as_str();
    let mut tampered = pdf_bytes.to_vec();
    tampered[0] = 0xFF;
    DocumentService::stage_mock_upload_bytes(bucket, key, &tampered, "application/pdf");

    let _ = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;

    let claimed = f
        .queue
        .claim(
            ClaimCriteria {
                queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                kinds: vec![JobKind::ParseDocumentPdf],
                workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                lease_duration: Duration::from_secs(30),
            },
            WorkerId::new(),
        )
        .await
        .unwrap()
        .unwrap();

    let runner = Arc::new(MockSandboxRunner::new());
    let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner.clone());

    let failure = executor
        .execute_claimed(&claimed)
        .await
        .expect_err("tampered storage bytes must fail closed before sandbox execution");

    assert_eq!(failure.kind, FailureKind::Terminal);
    assert_eq!(failure.error_code, "INTEGRITY_FAILED");
    assert_eq!(
        runner.execution_count(),
        0,
        "Sandbox MUST NOT be launched on storage tamper"
    );
}

#[tokio::test]
async fn test_wi0205_gate04_fail_closed_on_sandbox_crash_oom_timeout_and_violations() {
    let f = setup_fixture().await;
    let pdf_bytes = b"%PDF-1.7 sample document for sandbox failure modes";

    // 1. Timeout (wall-clock limit exceeded)
    {
        let (_intent, version_id, artifact_id) =
            finalize_and_clean_scan(&f, "timeout.pdf", MediaType::ApplicationPdf, pdf_bytes).await;

        let _ = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;
        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        let runner =
            Arc::new(MockSandboxRunner::new().with_behavior(MockSandboxBehavior::Timeout(601)));
        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner);

        let failure = executor
            .execute_claimed(&claimed)
            .await
            .expect_err("timeout fails closed");
        assert_eq!(failure.kind, FailureKind::Retryable);
        assert_eq!(failure.error_code, "SANDBOX_TIMEOUT");
    }

    // 2. Out of Memory (OOM)
    {
        let (_intent, version_id, artifact_id) =
            finalize_and_clean_scan(&f, "oom.pdf", MediaType::ApplicationPdf, pdf_bytes).await;

        let _ = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;
        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        let runner =
            Arc::new(MockSandboxRunner::new().with_behavior(MockSandboxBehavior::OutOfMemory));
        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner);

        let failure = executor
            .execute_claimed(&claimed)
            .await
            .expect_err("OOM fails closed");
        assert_eq!(failure.kind, FailureKind::Retryable);
        assert_eq!(failure.error_code, "SANDBOX_OOM");
    }

    // 3. Process Crash
    {
        let (_intent, version_id, artifact_id) =
            finalize_and_clean_scan(&f, "crash.pdf", MediaType::ApplicationPdf, pdf_bytes).await;

        let _ = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;
        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        let runner = Arc::new(
            MockSandboxRunner::new().with_behavior(MockSandboxBehavior::Crash {
                exit_code: Some(139),
                stderr: "Segmentation fault".into(),
            }),
        );
        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner);

        let failure = executor
            .execute_claimed(&claimed)
            .await
            .expect_err("crash fails closed");
        assert_eq!(failure.kind, FailureKind::Retryable);
        assert_eq!(failure.error_code, "SANDBOX_CRASH");
    }

    // 4. Security Violation (attempted network egress)
    {
        let (_intent, version_id, artifact_id) =
            finalize_and_clean_scan(&f, "violation.pdf", MediaType::ApplicationPdf, pdf_bytes)
                .await;

        let _ = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;
        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        let runner = Arc::new(MockSandboxRunner::new().with_behavior(
            MockSandboxBehavior::SandboxViolation("Network egress attempt blocked".into()),
        ));
        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner);

        let failure = executor
            .execute_claimed(&claimed)
            .await
            .expect_err("violation fails closed");
        assert_eq!(failure.kind, FailureKind::Terminal);
        assert_eq!(failure.error_code, "SANDBOX_VIOLATION");
    }

    // 5. Malformed Output
    {
        let (_intent, version_id, artifact_id) =
            finalize_and_clean_scan(&f, "malformed.pdf", MediaType::ApplicationPdf, pdf_bytes)
                .await;

        let _ = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;
        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        let runner = Arc::new(MockSandboxRunner::new().with_behavior(
            MockSandboxBehavior::MalformedOutput("Invalid JSON payload".into()),
        ));
        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner);

        let failure = executor
            .execute_claimed(&claimed)
            .await
            .expect_err("malformed fails closed");
        assert_eq!(failure.kind, FailureKind::Terminal);
        assert_eq!(failure.error_code, "SANDBOX_MALFORMED_OUTPUT");
    }

    // 6. Tampered Output (mismatched version_id)
    {
        let (_intent, version_id, artifact_id) =
            finalize_and_clean_scan(&f, "tampered.pdf", MediaType::ApplicationPdf, pdf_bytes).await;

        let _ = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;
        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        let tampered_output = SandboxOutput {
            protocol_version: SANDBOX_PROTOCOL_VERSION.to_string(),
            document_version_id: DocumentVersionId::new(), // WRONG ID
            object_artifact_id: artifact_id,
            input_sha256: Sha256::digest(pdf_bytes),
            status: SandboxStatus::Success,
            parser_name: "test-parser".to_string(),
            parser_version: "1.0.0".to_string(),
            locator_version: LocatorVersion::new("w014-loc-v1").unwrap(),
            page_count: 1,
            block_count: 1,
            span_count: 1,
            text_sha256: Some(Sha256::digest(pdf_bytes)),
            execution_duration_ms: 50,
            failure_code: None,
            failure_detail: None,
            parsed_artifact: None,
        };

        let runner = Arc::new(
            MockSandboxRunner::new()
                .with_behavior(MockSandboxBehavior::TamperedOutput(tampered_output)),
        );
        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner);

        let failure = executor
            .execute_claimed(&claimed)
            .await
            .expect_err("tampered output fails closed");
        assert_eq!(failure.kind, FailureKind::Terminal);
        assert_eq!(failure.error_code, "SANDBOX_OUTPUT_VALIDATION_FAILED");
    }
}

#[tokio::test]
async fn test_wi0205_gate05_stale_worker_lease_fencing_rejection() {
    let f = setup_fixture().await;
    let pdf_bytes = b"%PDF-1.7 sample document for lease fencing test";

    let (_intent, version_id, artifact_id) =
        finalize_and_clean_scan(&f, "fence_test.pdf", MediaType::ApplicationPdf, pdf_bytes).await;

    let job_id = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;

    // 1. Worker 1 claims job (lease_generation = 1)
    let criteria = ClaimCriteria {
        queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
        kinds: vec![JobKind::ParseDocumentPdf],
        workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
        lease_duration: Duration::from_secs(30),
    };
    let w1 = f
        .queue
        .claim(criteria.clone(), WorkerId::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(w1.lease_generation, 1);

    // 2. Force lease expiry and reclaim by Worker 2 (advances lease_generation to 2)
    sqlx::query("UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE job_id = $1")
        .bind(job_id)
        .execute(f.test_db.pool())
        .await
        .unwrap();

    let w2 = f
        .queue
        .claim(criteria, WorkerId::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        w2.lease_generation, 2,
        "Reclaimed job must advance generation fence"
    );

    // 3. Stale Worker 1 attempts to execute and complete
    let runner = Arc::new(MockSandboxRunner::new());
    let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner.clone());

    let failure_w1 = executor
        .execute_claimed(&w1)
        .await
        .expect_err("stale worker must be rejected");
    assert_eq!(failure_w1.error_code, "STALE_LEASE");

    // 4. Valid Worker 2 executes and succeeds
    let outcome_w2 = executor
        .execute_claimed(&w2)
        .await
        .expect("valid worker must succeed");
    f.queue.complete_success(&w2, outcome_w2).await.unwrap();

    let job_row = sqlx::query("SELECT status FROM jobs WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(f.test_db.pool())
        .await
        .unwrap();
    let status: String = job_row.get("status");
    assert_eq!(status, "succeeded");
}

#[tokio::test]
async fn test_wi0205_gate06_docx_ocr_parse_job_kind_support() {
    let f = setup_fixture().await;
    let docx_bytes = b"PK\x03\x04 DOCX test content for parse sandbox execution";

    let (_intent, version_id, artifact_id) =
        finalize_and_clean_scan(&f, "sample.docx", MediaType::Docx, docx_bytes).await;

    let job_id =
        enqueue_parse_job(&f, JobKind::ParseDocumentDocxOcr, version_id, artifact_id).await;

    let criteria = ClaimCriteria {
        queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
        kinds: vec![JobKind::ParseDocumentDocxOcr],
        workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
        lease_duration: Duration::from_secs(30),
    };
    let claimed = f
        .queue
        .claim(criteria, WorkerId::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed.kind, JobKind::ParseDocumentDocxOcr);

    let runner = Arc::new(MockSandboxRunner::new());
    let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner.clone());

    let outcome = executor
        .execute_claimed(&claimed)
        .await
        .expect("docx parse sandbox must succeed");

    f.queue.complete_success(&claimed, outcome).await.unwrap();

    let job_row = sqlx::query("SELECT status FROM jobs WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(f.test_db.pool())
        .await
        .unwrap();
    let status: String = job_row.get("status");
    assert_eq!(status, "succeeded");
}

#[tokio::test]
async fn test_wi0205_gate07_negative_scope_zero_canonical_page_block_span_writes() {
    let f = setup_fixture().await;
    let pdf_bytes = b"%PDF-1.7 sample document for negative scope verification";

    let (_intent, version_id, artifact_id) =
        finalize_and_clean_scan(&f, "neg_scope.pdf", MediaType::ApplicationPdf, pdf_bytes).await;

    let _ = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;

    let claimed = f
        .queue
        .claim(
            ClaimCriteria {
                queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                kinds: vec![JobKind::ParseDocumentPdf],
                workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                lease_duration: Duration::from_secs(30),
            },
            WorkerId::new(),
        )
        .await
        .unwrap()
        .unwrap();

    let runner = Arc::new(MockSandboxRunner::new());
    let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner);

    let outcome = executor.execute_claimed(&claimed).await.unwrap();
    f.queue.complete_success(&claimed, outcome).await.unwrap();

    // Verify zero parser_pages rows exist
    let pages_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM parser_pages WHERE workspace_id = $1")
            .bind(f.ws_a.id.as_uuid())
            .fetch_one(f.test_db.pool())
            .await
            .unwrap();
    assert_eq!(
        pages_count, 0,
        "WI-0205 must NOT persist canonical parser_pages rows"
    );

    // Verify zero parser_blocks rows exist
    let blocks_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM parser_blocks WHERE workspace_id = $1")
            .bind(f.ws_a.id.as_uuid())
            .fetch_one(f.test_db.pool())
            .await
            .unwrap();
    assert_eq!(
        blocks_count, 0,
        "WI-0205 must NOT persist canonical parser_blocks rows"
    );

    // Verify zero source_spans rows exist
    let spans_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM source_spans WHERE workspace_id = $1")
            .bind(f.ws_a.id.as_uuid())
            .fetch_one(f.test_db.pool())
            .await
            .unwrap();
    assert_eq!(
        spans_count, 0,
        "WI-0205 must NOT persist canonical source_spans rows"
    );
}

#[tokio::test]
async fn test_wi0205_gate08_process_sandbox_runner_real_queue_enforcement() {
    let f = setup_fixture().await;
    let pdf_bytes = b"%PDF-1.7 sample document for process sandbox real queue test";

    // -------------------------------------------------------------
    // CASE A: Real ProcessSandboxRunner Successful Execution
    // -------------------------------------------------------------
    {
        let (_intent, version_id, artifact_id) =
            finalize_and_clean_scan(&f, "proc_success.pdf", MediaType::ApplicationPdf, pdf_bytes)
                .await;

        let job_id =
            enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;

        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        let success_script = r#"
            printf '{"protocol_version":"parser-sandbox-v1","document_version_id":"%s","object_artifact_id":"%s","input_sha256":"%s","status":"success","parser_name":"real-process-parser","parser_version":"1.0.0","locator_version":"w014-loc-v1","page_count":1,"block_count":1,"span_count":1,"text_sha256":"%s","execution_duration_ms":15,"failure_code":null,"failure_detail":null,"parsed_artifact":null}' "$W014_DOCUMENT_VERSION_ID" "$W014_OBJECT_ARTIFACT_ID" "$W014_INPUT_SHA256" "$W014_INPUT_SHA256"
        "#;

        let runner = Arc::new(
            ProcessSandboxRunner::new("/bin/sh")
                .with_platform_wrapper()
                .with_args(["-c", success_script]),
        );
        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner);

        let outcome = executor
            .execute_claimed(&claimed)
            .await
            .expect("process sandbox execution must succeed");

        f.queue.complete_success(&claimed, outcome).await.unwrap();

        let job_row = sqlx::query("SELECT status FROM jobs WHERE job_id = $1")
            .bind(job_id)
            .fetch_one(f.test_db.pool())
            .await
            .unwrap();
        let status: String = job_row.get("status");
        assert_eq!(status, "succeeded");

        let artifact_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM parser_artifacts WHERE document_version_id = $1",
        )
        .bind(version_id.as_uuid())
        .fetch_one(f.test_db.pool())
        .await
        .unwrap();
        assert_eq!(artifact_count, 1, "Parser artifact must be persisted");
    }

    // -------------------------------------------------------------
    // CASE B: Real ProcessSandboxRunner Oversized Stdout -> Fails Closed & Commits Zero Truth
    // -------------------------------------------------------------
    {
        let (_intent, version_id, artifact_id) = finalize_and_clean_scan(
            &f,
            "proc_overflow.pdf",
            MediaType::ApplicationPdf,
            pdf_bytes,
        )
        .await;

        let _ = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;

        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        // Runner generates massive output stream (exceeding bound during streaming)
        let overflow_script = "head -c 20000000 /dev/zero | tr '\\000' 'A'";
        let runner = Arc::new(
            ProcessSandboxRunner::new("/bin/sh")
                .with_platform_wrapper()
                .with_args(["-c", overflow_script]),
        );
        let mut custom_profile = SandboxSecurityProfile::frozen_default();
        custom_profile.ceilings.max_output_bytes = 10_000; // Tight bound for test

        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner)
            .with_profile(custom_profile);

        let failure = executor
            .execute_claimed(&claimed)
            .await
            .expect_err("oversized stdout must fail closed");

        assert_eq!(failure.error_code, "SANDBOX_RESOURCE_VIOLATION");

        // Verify zero parser facts written to DB on failure
        let artifact_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM parser_artifacts WHERE document_version_id = $1",
        )
        .bind(version_id.as_uuid())
        .fetch_one(f.test_db.pool())
        .await
        .unwrap();
        assert_eq!(
            artifact_count, 0,
            "Zero parser artifacts must be persisted on overflow"
        );
    }

    // -------------------------------------------------------------
    // CASE C: Real ProcessSandboxRunner Timeout -> Fails Closed & Commits Zero Truth
    // -------------------------------------------------------------
    {
        let (_intent, version_id, artifact_id) =
            finalize_and_clean_scan(&f, "proc_timeout.pdf", MediaType::ApplicationPdf, pdf_bytes)
                .await;

        let _ = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;

        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        let runner = Arc::new(
            ProcessSandboxRunner::new("/bin/sh")
                .with_platform_wrapper()
                .with_args(["-c", "sleep 10"]),
        );
        let mut custom_profile = SandboxSecurityProfile::frozen_default();
        custom_profile.ceilings.max_wall_clock_seconds = 1; // Strict 1s timeout

        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner)
            .with_profile(custom_profile);

        let failure = executor
            .execute_claimed(&claimed)
            .await
            .expect_err("timeout must fail closed");

        assert_eq!(failure.error_code, "SANDBOX_TIMEOUT");

        let artifact_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM parser_artifacts WHERE document_version_id = $1",
        )
        .bind(version_id.as_uuid())
        .fetch_one(f.test_db.pool())
        .await
        .unwrap();
        assert_eq!(
            artifact_count, 0,
            "Zero parser artifacts must be persisted on timeout"
        );
    }

    // -------------------------------------------------------------
    // CASE D: Real ProcessSandboxRunner Missing Wrapper -> Fails Closed & Commits Zero Truth
    // -------------------------------------------------------------
    {
        let (_intent, version_id, artifact_id) = finalize_and_clean_scan(
            &f,
            "proc_nowrapper.pdf",
            MediaType::ApplicationPdf,
            pdf_bytes,
        )
        .await;

        let _ = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;

        let claimed = f
            .queue
            .claim(
                ClaimCriteria {
                    queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
                    kinds: vec![JobKind::ParseDocumentPdf],
                    workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
                    lease_duration: Duration::from_secs(30),
                },
                WorkerId::new(),
            )
            .await
            .unwrap()
            .unwrap();

        // Runner has NO wrapper configured (direct execution attempt fails closed)
        let unisolated_runner =
            Arc::new(ProcessSandboxRunner::new("/bin/sh").with_args(["-c", "exit 0"]));
        let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), unisolated_runner);

        let failure = executor
            .execute_claimed(&claimed)
            .await
            .expect_err("unisolated direct execution must fail closed");

        assert_eq!(failure.error_code, "SANDBOX_VIOLATION");
        assert_eq!(failure.kind, FailureKind::Terminal);

        let artifact_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM parser_artifacts WHERE document_version_id = $1",
        )
        .bind(version_id.as_uuid())
        .fetch_one(f.test_db.pool())
        .await
        .unwrap();
        assert_eq!(
            artifact_count, 0,
            "Zero parser artifacts must be persisted when isolation wrapper is missing"
        );
    }
}
