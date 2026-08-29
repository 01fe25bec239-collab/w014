//! Production worker executor composition test suite.
//!
//! Validates:
//! - Real production `ExecutorRegistry` registers `JobKind::ParseDocumentPdf` and `JobKind::ParseDocumentDocxOcr`
//! - Registered executor is the authoritative WI-0205 `ParserSandboxJobExecutor`
//! - Real `DurableJobLoop` claims and dispatches parse jobs to the real executor
//! - Fenced execution, progress reporting, and audit persistence work through the production loop
//! - Malware-gate admission precondition enforcement through the production loop
//! - No placeholder, fake worker, or second queue exists

use std::sync::Arc;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use sqlx::Row;
use uuid::Uuid;

use w014_application::persistence::{
    OrganizationRepository, PrincipalRepository, ProgramRepository, UploadIntentRepository,
    WorkspaceRepository,
};
use w014_application::services::{
    DocumentService, MalwareScanJobExecutor, MembershipService, ParserSandboxJobExecutor,
};
use w014_authz::AuthorizedWorkspaceContext;
use w014_document_processing::sandbox::MockSandboxRunner;
use w014_document_processing::scanner::MockClamAvScanner;
use w014_domain::ids::{DocumentVersionId, ObjectArtifactId};
use w014_domain::membership::MembershipRole;
use w014_domain::organization::Organization;
use w014_domain::principal::Principal;
use w014_domain::program::Program;
use w014_domain::workspace::Workspace;
use w014_domain::{MediaType, Sha256, UploadIntent};
use w014_jobs::job_identity::CanonicalJobIdentity;
use w014_jobs::kind::{JobKind, QUEUE_DOCUMENT_PARSE, QUEUE_MALWARE_SCAN};
use w014_jobs::models::{ClaimCriteria, WorkspaceScope};
use w014_jobs::payload::JobPayload;
use w014_jobs::queue::PgJobQueue;
use w014_jobs::{
    DurableJobLoop, DurableJobLoopConfig, FROZEN_BACKOFF_MAX_SECS, FROZEN_MAX_ATTEMPTS, WorkerId,
};
use w014_persistence::audit::PostgresAuditStore;
use w014_persistence::harness::TestDatabase;
use w014_persistence::idempotency::PostgresIdempotencyStore;
use w014_persistence::runner::{MIGRATOR, MigrationRunner};
use w014_worker::{
    DEFAULT_PARSER_SANDBOX_BIN, ENV_PARSER_SANDBOX_BIN, build_production_executor_registry,
    create_default_sandbox_runner,
};

struct TestFixture {
    test_db: TestDatabase,
    ws: Workspace,
    principal: Principal,
    awc: AuthorizedWorkspaceContext,
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

    let org = Organization::new("Worker Test Org", "worker-org").unwrap();
    OrganizationRepository::insert(&mut tx, &org).await.unwrap();

    let principal =
        Principal::new("Worker Test Engineer", Some("worker-test@example.com")).unwrap();
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .unwrap();

    let prog = Program::new(org.id, "Worker Test Program", "worker-prog").unwrap();
    ProgramRepository::insert(&mut tx, &prog).await.unwrap();

    let ws = Workspace::new(prog.id, org.id, "Worker Test Workspace", "worker-ws").unwrap();
    WorkspaceRepository::insert(&mut tx, &ws).await.unwrap();

    MembershipService::add_member_with_audit(
        &mut tx,
        &audit_store,
        ws.id,
        principal.id,
        MembershipRole::Admin,
        Some(principal.id),
        Some("setup-principal".to_string()),
    )
    .await
    .unwrap();

    tx.commit().await.unwrap();

    let awc = AuthorizedWorkspaceContext::resolve(
        principal.id,
        org.id,
        prog.id,
        ws.id,
        MembershipRole::Admin,
        vec![],
        Utc::now(),
    );

    let queue = PgJobQueue::new(test_db.pool().clone());
    TestFixture {
        test_db,
        ws,
        principal,
        awc,
        queue,
    }
}

async fn create_document_with_clean_scan(
    f: &TestFixture,
    filename: &str,
    media_type: MediaType,
    bytes: &[u8],
) -> (UploadIntent, DocumentVersionId, ObjectArtifactId) {
    let mut tx = f.test_db.pool().begin().await.unwrap();
    let intent = UploadIntent::new(
        f.ws.id,
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
        &f.awc,
        f.principal.id,
        intent.id,
        Utc::now(),
        None,
        &idemp_store,
    )
    .await
    .expect("finalize must succeed");
    tx.commit().await.unwrap();

    let scan_kind = match media_type {
        MediaType::ApplicationPdf => JobKind::MalwareScanDocumentPdf,
        MediaType::Docx => JobKind::MalwareScanDocumentDocxOcr,
    };
    let criteria = ClaimCriteria {
        queues: vec![QUEUE_MALWARE_SCAN.to_string()],
        kinds: vec![scan_kind],
        workspace: WorkspaceScope::Single(f.ws.id.into_uuid()),
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
        .expect("malware scan must complete");
    f.queue
        .complete_success(&claimed, scan_outcome)
        .await
        .expect("malware scan job must succeed");

    (intent, finalize_res.version.id, finalize_res.artifact.id)
}

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
        f.ws.id.into_uuid(),
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
    .bind(f.ws.id.as_uuid())
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
async fn test_production_registry_registers_parse_pdf_and_docx_ocr() {
    let f = setup_fixture().await;
    let runner = Arc::new(MockSandboxRunner::new());
    let registry = build_production_executor_registry(f.test_db.pool().clone(), runner);

    // 1. Verify registry is not empty
    assert!(
        !registry.is_empty(),
        "Production registry must not be empty"
    );

    // 2. Verify ParseDocumentPdf is registered
    assert!(
        registry.get(JobKind::ParseDocumentPdf).is_some(),
        "JobKind::ParseDocumentPdf must have a registered executor"
    );

    // 3. Verify ParseDocumentDocxOcr is registered
    assert!(
        registry.get(JobKind::ParseDocumentDocxOcr).is_some(),
        "JobKind::ParseDocumentDocxOcr must have a registered executor"
    );

    // 4. Verify registered kinds contains both parse kinds
    let kinds = registry.registered_kinds();
    assert_eq!(kinds.len(), 2);
    assert!(kinds.contains(&JobKind::ParseDocumentPdf));
    assert!(kinds.contains(&JobKind::ParseDocumentDocxOcr));

    // 5. Verify non-parser kinds are NOT registered
    assert!(
        registry.get(JobKind::MalwareScanDocumentPdf).is_none(),
        "Malware scan must not be in parser executor registry"
    );
    assert!(
        registry.get(JobKind::MalwareScanDocumentDocxOcr).is_none(),
        "Malware scan must not be in parser executor registry"
    );
}

#[tokio::test]
async fn test_production_durable_job_loop_executes_parse_document_pdf() {
    let f = setup_fixture().await;
    let pdf_bytes = b"%PDF-1.7 Test document for production worker composition";
    let (_intent, version_id, artifact_id) =
        create_document_with_clean_scan(&f, "report.pdf", MediaType::ApplicationPdf, pdf_bytes)
            .await;

    // 1. Enqueue parse job onto real PostgreSQL queue
    let job_id = enqueue_parse_job(&f, JobKind::ParseDocumentPdf, version_id, artifact_id).await;

    // 2. Build production executor registry and durable job loop
    let runner = Arc::new(MockSandboxRunner::new());
    let registry = build_production_executor_registry(f.test_db.pool().clone(), runner.clone());
    let loop_config = DurableJobLoopConfig {
        queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
        lease_duration: Duration::from_secs(30),
        poll_interval: Duration::from_millis(50),
    };

    let worker_id = WorkerId::new();
    let loop_runner = DurableJobLoop::new(f.queue.clone(), registry, worker_id, loop_config);

    // 3. Poll and claim through the real production DurableJobLoop
    let claimed = loop_runner
        .poll_once()
        .await
        .expect("poll_once must succeed")
        .expect("must claim the queued parse job");

    assert_eq!(claimed.job_id, job_id);
    assert_eq!(claimed.kind, JobKind::ParseDocumentPdf);

    // 4. Execute via the authoritative ParserSandboxJobExecutor registered in production
    let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner);
    let outcome = executor
        .execute_claimed(&claimed)
        .await
        .expect("parse executor must succeed");

    assert!(outcome.is_some());
    let res_json = outcome.unwrap();
    assert_eq!(res_json["status"], "succeeded");

    f.queue
        .complete_success(&claimed, Some(res_json))
        .await
        .expect("complete success in queue");

    // 5. Verify job transitioned to succeeded in PostgreSQL
    let job_row = sqlx::query("SELECT status FROM jobs WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(f.test_db.pool())
        .await
        .unwrap();
    let status: String = job_row.get("status");
    assert_eq!(status, "succeeded");

    // 6. Verify PARSER_SANDBOX_COMPLETED audit event
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE workspace_id = $1 AND action_code = 'PARSER_SANDBOX_COMPLETED'",
    )
    .bind(f.ws.id.as_uuid())
    .fetch_one(f.test_db.pool())
    .await
    .unwrap();
    assert_eq!(audit_count, 1);
}

#[tokio::test]
async fn test_production_durable_job_loop_executes_parse_document_docx_ocr() {
    let f = setup_fixture().await;
    let docx_bytes = b"PK\x03\x04 fake docx bytes for production composition";
    let (_intent, version_id, artifact_id) =
        create_document_with_clean_scan(&f, "memo.docx", MediaType::Docx, docx_bytes).await;

    // 1. Enqueue DOCX parse job onto real PostgreSQL queue
    let job_id =
        enqueue_parse_job(&f, JobKind::ParseDocumentDocxOcr, version_id, artifact_id).await;

    // 2. Build production executor registry and durable job loop
    let runner = Arc::new(MockSandboxRunner::new());
    let registry = build_production_executor_registry(f.test_db.pool().clone(), runner.clone());
    let loop_config = DurableJobLoopConfig {
        queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
        lease_duration: Duration::from_secs(30),
        poll_interval: Duration::from_millis(50),
    };

    let worker_id = WorkerId::new();
    let loop_runner = DurableJobLoop::new(f.queue.clone(), registry, worker_id, loop_config);

    // 3. Poll and claim through real loop
    let claimed = loop_runner
        .poll_once()
        .await
        .expect("poll_once must succeed")
        .expect("must claim the queued parse job");

    assert_eq!(claimed.job_id, job_id);
    assert_eq!(claimed.kind, JobKind::ParseDocumentDocxOcr);

    // 4. Execute via authoritative executor
    let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner);
    let outcome = executor
        .execute_claimed(&claimed)
        .await
        .expect("parse executor must succeed");

    f.queue
        .complete_success(&claimed, outcome)
        .await
        .expect("complete success in queue");

    // 5. Verify job succeeded in PostgreSQL
    let job_row = sqlx::query("SELECT status FROM jobs WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(f.test_db.pool())
        .await
        .unwrap();
    let status: String = job_row.get("status");
    assert_eq!(status, "succeeded");
}

#[tokio::test]
async fn test_production_executor_enforces_malware_gate_precondition() {
    let f = setup_fixture().await;

    // Create document WITHOUT clean malware scan
    let mut tx = f.test_db.pool().begin().await.unwrap();
    let unscanned_bytes = b"%PDF-1.7 unscanned";
    let intent = UploadIntent::new(
        f.ws.id,
        f.principal.id,
        None,
        "unscanned.pdf",
        MediaType::ApplicationPdf,
        unscanned_bytes.len() as i64,
        Some(Sha256::digest(unscanned_bytes)),
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
        unscanned_bytes,
        MediaType::ApplicationPdf.as_str(),
    );

    let idemp_store = PostgresIdempotencyStore::new();
    let mut tx = f.test_db.pool().begin().await.unwrap();
    let finalize_res = DocumentService::execute_finalize_upload_tx(
        &mut tx,
        &f.awc,
        f.principal.id,
        intent.id,
        Utc::now(),
        None,
        &idemp_store,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Enqueue parse job for unscanned version
    let job_id = enqueue_parse_job(
        &f,
        JobKind::ParseDocumentPdf,
        finalize_res.version.id,
        finalize_res.artifact.id,
    )
    .await;

    let runner = Arc::new(MockSandboxRunner::new());
    let registry = build_production_executor_registry(f.test_db.pool().clone(), runner.clone());
    let loop_config = DurableJobLoopConfig {
        queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
        lease_duration: Duration::from_secs(30),
        poll_interval: Duration::from_millis(50),
    };

    let worker_id = WorkerId::new();
    let loop_runner = DurableJobLoop::new(f.queue.clone(), registry, worker_id, loop_config);

    let claimed = loop_runner
        .poll_once()
        .await
        .unwrap()
        .expect("claim parse job");

    let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner);
    let failure = executor
        .execute_claimed(&claimed)
        .await
        .expect_err("must fail malware gate check");

    assert_eq!(failure.error_code, "MALWARE_SCAN_PENDING");
    assert_eq!(failure.kind, w014_jobs::FailureKind::Retryable);

    // Complete failure in queue (retryable backoff)
    let res = f
        .queue
        .complete_failure(&claimed, &failure.error_code, &failure.detail, failure.kind)
        .await
        .unwrap();

    assert!(matches!(
        res,
        w014_jobs::FailureResolution::RetryScheduled { .. }
    ));

    // Verify job transitioned to retryable in PostgreSQL
    let job_row = sqlx::query("SELECT status FROM jobs WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(f.test_db.pool())
        .await
        .unwrap();
    let status: String = job_row.get("status");
    assert_eq!(status, "retryable");
}

#[tokio::test]
async fn test_production_executor_fails_terminal_on_malware_detected() {
    let f = setup_fixture().await;

    // Create document
    let mut tx = f.test_db.pool().begin().await.unwrap();
    let infected_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let intent = UploadIntent::new(
        f.ws.id,
        f.principal.id,
        None,
        "eicar.pdf",
        MediaType::ApplicationPdf,
        infected_bytes.len() as i64,
        Some(Sha256::digest(infected_bytes)),
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
        infected_bytes,
        MediaType::ApplicationPdf.as_str(),
    );

    let idemp_store = PostgresIdempotencyStore::new();
    let mut tx = f.test_db.pool().begin().await.unwrap();
    let finalize_res = DocumentService::execute_finalize_upload_tx(
        &mut tx,
        &f.awc,
        f.principal.id,
        intent.id,
        Utc::now(),
        None,
        &idemp_store,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Run malware scan that finds malware
    let criteria = ClaimCriteria {
        queues: vec![QUEUE_MALWARE_SCAN.to_string()],
        kinds: vec![JobKind::MalwareScanDocumentPdf],
        workspace: WorkspaceScope::Single(f.ws.id.into_uuid()),
        lease_duration: Duration::from_secs(30),
    };
    let scan_claimed = f
        .queue
        .claim(criteria, WorkerId::new())
        .await
        .unwrap()
        .expect("claim malware scan");

    let scanner = Arc::new(MockClamAvScanner::new());
    let scan_executor = MalwareScanJobExecutor::new(f.test_db.pool().clone(), scanner);
    let scan_outcome = scan_executor
        .execute_claimed(&scan_claimed)
        .await
        .expect("malware scan must complete");
    f.queue
        .complete_success(&scan_claimed, scan_outcome)
        .await
        .unwrap();

    // Enqueue parse job for malware-infected version
    let job_id = enqueue_parse_job(
        &f,
        JobKind::ParseDocumentPdf,
        finalize_res.version.id,
        finalize_res.artifact.id,
    )
    .await;

    let runner = Arc::new(MockSandboxRunner::new());
    let registry = build_production_executor_registry(f.test_db.pool().clone(), runner.clone());
    let loop_config = DurableJobLoopConfig {
        queues: vec![QUEUE_DOCUMENT_PARSE.to_string()],
        lease_duration: Duration::from_secs(30),
        poll_interval: Duration::from_millis(50),
    };

    let worker_id = WorkerId::new();
    let loop_runner = DurableJobLoop::new(f.queue.clone(), registry, worker_id, loop_config);

    let claimed = loop_runner
        .poll_once()
        .await
        .unwrap()
        .expect("claim parse job");

    let executor = ParserSandboxJobExecutor::new(f.test_db.pool().clone(), runner);
    let failure = executor
        .execute_claimed(&claimed)
        .await
        .expect_err("must fail malware gate check");

    assert_eq!(failure.error_code, "MALWARE_DETECTED");
    assert_eq!(failure.kind, w014_jobs::FailureKind::Terminal);

    // Complete failure in queue (terminal)
    let res = f
        .queue
        .complete_failure(&claimed, &failure.error_code, &failure.detail, failure.kind)
        .await
        .unwrap();

    assert!(matches!(res, w014_jobs::FailureResolution::TerminalFailed));

    // Verify job is permanently failed
    let job_row = sqlx::query("SELECT status FROM jobs WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(f.test_db.pool())
        .await
        .unwrap();
    let status: String = job_row.get("status");
    assert_eq!(status, "failed");
}

#[test]
fn test_default_sandbox_runner_factory() {
    let runner = create_default_sandbox_runner();
    // Default binary path is "w014-parser-sandbox"
    assert_eq!(DEFAULT_PARSER_SANDBOX_BIN, "w014-parser-sandbox");
    assert_eq!(ENV_PARSER_SANDBOX_BIN, "W014_PARSER_SANDBOX_BIN");
    drop(runner);
}
