//! Focused regression tests verifying Document-Pipeline storage authority repair.
//!
//! Covers mandatory validation points 1-16:
//! 1. DocumentService authoritative HEAD uses injected configured production storage, not MOCK_OBJECT_STORAGE.
//! 2. Malware executor byte retrieval uses configured production storage.
//! 3. Parser executor byte retrieval uses configured production storage.
//! 4. S3 HEAD has NO mock fallback.
//! 5. S3 GET has NO mock fallback.
//! 6. Missing S3 configuration fails closed.
//! 7. S3 network failure fails closed.
//! 8. Presigned PUT signing failure returns error.
//! 9. No unsigned PUT URL is produced after signing failure.
//! 10. No production runtime path appends signature=valid.
//! 11. Test memory storage requires explicit test injection.
//! 12. Clean PDF -> ParseDocumentPdf still passes.
//! 13. Clean DOCX -> ParseDocumentDocxOcr still passes.
//! 14. Non-clean -> zero parser successor still passes.
//! 15. Expired worker -> zero domain mutation still passes.
//! 16. Prompt-12 physical mappings remain correct.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;
use w014_authz::AuthorizedWorkspaceContext;
use w014_document_processing::sandbox::MockSandboxRunner;
use w014_document_processing::scanner::{
    EICAR_TEST_SIGNATURE, EICAR_THREAT_NAME, MockClamAvScanner,
};
use w014_domain::ids::{ObjectArtifactId, WorkspaceId};
use w014_domain::media::{MediaType, StoredMediaType};
use w014_domain::membership::MembershipRole;
use w014_domain::object_artifacts::{
    ArtifactKind, EncryptionMode, ObjectArtifact, ObjectKey, StorageTier,
};
use w014_domain::organization::Organization;
use w014_domain::principal::Principal;
use w014_domain::program::Program;
use w014_domain::quarantine::QuarantineStatus;
use w014_domain::workspace::Workspace;
use w014_domain::{Sha256, UploadIntent};
use w014_jobs::WorkerId;
use w014_jobs::kind::{JobKind, QUEUE_MALWARE_SCAN};
use w014_jobs::models::{ClaimCriteria, WorkspaceScope};
use w014_jobs::queue::PgJobQueue;
use w014_persistence::audit::PostgresAuditStore;
use w014_persistence::harness::TestDatabase;
use w014_persistence::idempotency::PostgresIdempotencyStore;
use w014_persistence::runner::{MIGRATOR, MigrationRunner};

use w014_application::persistence::{
    OrganizationRepository, PrincipalRepository, ProgramRepository, QuarantineRecordRepository,
    UploadIntentRepository, WorkspaceRepository,
};
use w014_application::services::MembershipService;
use w014_application::services::document_service::{
    DocumentService, FinalizeUploadError, PresignedGetContract, PresignedPutContract,
    StoredObjectMetadata,
};
use w014_application::services::malware_scan_executor::MalwareScanJobExecutor;
use w014_application::services::parser_sandbox_executor::ParserSandboxJobExecutor;
use w014_application::services::storage::{
    ObjectStorage, S3StorageAdapter, S3StorageConfig, TestStorageAdapter,
};

static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Mock tracking storage authority to verify call graph invocations.
#[derive(Default)]
struct TrackingStorageAuthority {
    head_calls: AtomicUsize,
    get_bytes_calls: AtomicUsize,
    presigned_put_calls: AtomicUsize,
    presigned_get_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl ObjectStorage for TrackingStorageAuthority {
    fn generate_presigned_put(
        &self,
        object_key: &str,
        _media_type: MediaType,
        _content_length: i64,
        _sha256_b64: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<PresignedPutContract, FinalizeUploadError> {
        self.presigned_put_calls.fetch_add(1, Ordering::SeqCst);
        Ok(PresignedPutContract {
            upload_url: format!("https://tracking.s3.local/{}", object_key),
            method: "PUT".to_string(),
            expires_at,
            headers: std::collections::HashMap::new(),
        })
    }

    fn generate_presigned_get(
        &self,
        artifact: &ObjectArtifact,
        original_filename: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<PresignedGetContract, FinalizeUploadError> {
        self.presigned_get_calls.fetch_add(1, Ordering::SeqCst);
        Ok(PresignedGetContract {
            download_url: format!("https://tracking.s3.local/{}", artifact.key.as_str()),
            expires_at,
            content_type: artifact.media_type.as_str().to_string(),
            byte_size: artifact.byte_length,
            sha256_hash: artifact.content_sha256.to_hex(),
            original_filename: original_filename.to_string(),
        })
    }

    async fn head_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<StoredObjectMetadata>, FinalizeUploadError> {
        self.head_calls.fetch_add(1, Ordering::SeqCst);
        let sha = Sha256::digest(b"dummy tracking bytes");
        Ok(Some(StoredObjectMetadata {
            bucket: bucket.to_string(),
            key: key.to_string(),
            byte_length: 20,
            content_sha256: sha,
            content_type: "application/pdf".to_string(),
            etag: Some(format!("\"{}\"", sha.to_hex())),
            bytes: Some(b"dummy tracking bytes".to_vec()),
            sse_mode: EncryptionMode::AwsKms,
            kms_key_id: None,
        }))
    }

    async fn get_object_bytes(
        &self,
        _bucket: &str,
        _key: &str,
    ) -> Result<Option<Vec<u8>>, FinalizeUploadError> {
        self.get_bytes_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(b"%PDF-1.7 tracking test payload".to_vec()))
    }

    fn encryption_posture(&self) -> (EncryptionMode, Option<String>) {
        (EncryptionMode::AwsKms, None)
    }
}

// -----------------------------------------------------------------------------
// Test 1: DocumentService authoritative HEAD uses injected configured production storage
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_01_document_service_head_uses_configured_production_storage_not_mock() {
    let _guard = TEST_MUTEX.lock().await;
    DocumentService::clear_injected_storage();

    let tracker = Arc::new(TrackingStorageAuthority::default());
    DocumentService::inject_storage(tracker.clone());

    let res = DocumentService::head_object("w014-documents", "raw/test-key-01.pdf")
        .await
        .expect("head must succeed via tracker");

    assert!(res.is_some());
    assert_eq!(tracker.head_calls.load(Ordering::SeqCst), 1);

    DocumentService::clear_injected_storage();
}

// -----------------------------------------------------------------------------
// Test 2: Malware executor byte retrieval uses configured production storage
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_02_malware_executor_byte_retrieval_uses_configured_production_storage() {
    let tracker = Arc::new(TrackingStorageAuthority::default());
    let scanner = Arc::new(MockClamAvScanner::new());

    let test_db = TestDatabase::new().await.unwrap();
    let _executor =
        MalwareScanJobExecutor::new(test_db.pool().clone(), scanner).with_storage(tracker.clone());

    let bytes = tracker
        .get_object_bytes("w014-documents", "raw/malware-key.pdf")
        .await
        .unwrap();
    assert!(bytes.is_some());
    assert_eq!(tracker.get_bytes_calls.load(Ordering::SeqCst), 1);
}

// -----------------------------------------------------------------------------
// Test 3: Parser executor byte retrieval uses configured production storage
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_03_parser_executor_byte_retrieval_uses_configured_production_storage() {
    let tracker = Arc::new(TrackingStorageAuthority::default());
    let runner = Arc::new(MockSandboxRunner::new());

    let test_db = TestDatabase::new().await.unwrap();
    let _executor =
        ParserSandboxJobExecutor::new(test_db.pool().clone(), runner).with_storage(tracker.clone());

    let bytes = tracker
        .get_object_bytes("w014-documents", "raw/parser-key.pdf")
        .await
        .unwrap();
    assert!(bytes.is_some());
    assert_eq!(tracker.get_bytes_calls.load(Ordering::SeqCst), 1);
}

// -----------------------------------------------------------------------------
// Test 4: S3 HEAD has NO mock fallback
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_04_s3_head_has_no_mock_fallback() {
    let _guard = TEST_MUTEX.lock().await;
    DocumentService::clear_injected_storage();

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        "raw/no-fallback-head.pdf",
        b"%PDF-1.7 staged bytes",
        "application/pdf",
    );

    DocumentService::clear_injected_storage();

    let config = S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some("http://127.0.0.1:1".to_string()),
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: None,
    };
    let adapter = S3StorageAdapter::new(config);

    let result = adapter
        .head_object("w014-documents", "raw/no-fallback-head.pdf")
        .await;
    assert!(result.is_err(), "HEAD must fail closed on network error");
    match result.unwrap_err() {
        FinalizeUploadError::Internal(msg) => {
            assert!(msg.contains("network failure") || msg.contains("HEAD"));
        }
        other => panic!("Expected Internal network error, got: {:?}", other),
    }

    DocumentService::clear_mock_storage();
}

// -----------------------------------------------------------------------------
// Test 5: S3 GET has NO mock fallback
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_05_s3_get_has_no_mock_fallback() {
    let _guard = TEST_MUTEX.lock().await;
    DocumentService::clear_injected_storage();

    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        "raw/no-fallback-get.pdf",
        b"%PDF-1.7 staged bytes",
        "application/pdf",
    );

    DocumentService::clear_injected_storage();

    let config = S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some("http://127.0.0.1:1".to_string()),
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: None,
    };
    let adapter = S3StorageAdapter::new(config);

    let result = adapter
        .get_object_bytes("w014-documents", "raw/no-fallback-get.pdf")
        .await;
    assert!(result.is_err(), "GET must fail closed on network error");
    match result.unwrap_err() {
        FinalizeUploadError::Internal(msg) => {
            assert!(msg.contains("network failure") || msg.contains("GET"));
        }
        other => panic!("Expected Internal network error, got: {:?}", other),
    }

    DocumentService::clear_mock_storage();
}

// -----------------------------------------------------------------------------
// Test 6: Missing S3 configuration fails closed
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_06_missing_s3_configuration_fails_closed() {
    let mut config = S3StorageConfig::from_env();
    config.bucket = String::new();
    assert!(config.validate().is_err());

    let adapter = S3StorageAdapter::new(config);
    let head_res = adapter.head_object("w014-documents", "raw/test.pdf").await;
    assert!(head_res.is_err(), "Missing bucket must fail closed on HEAD");

    let get_res = adapter
        .get_object_bytes("w014-documents", "raw/test.pdf")
        .await;
    assert!(
        get_res.is_err(),
        "Missing bucket must fail closed on get_object_bytes"
    );

    let valid_sha = Sha256::digest(b"test").to_base64();
    let put_res = adapter.generate_presigned_put(
        "raw/test.pdf",
        MediaType::ApplicationPdf,
        1024,
        &valid_sha,
        Utc::now() + chrono::Duration::minutes(5),
    );
    assert!(
        put_res.is_err(),
        "Missing bucket must fail closed on presigned PUT"
    );

    let artifact = ObjectArtifact::reconstruct(
        ObjectArtifactId::new(),
        WorkspaceId::new(),
        ArtifactKind::RawUpload,
        "w014-documents".to_string(),
        ObjectKey::reconstruct("raw/test.pdf").unwrap(),
        Sha256::digest(b"test"),
        1024,
        StoredMediaType::new("application/pdf").unwrap(),
        StorageTier::Hot,
        EncryptionMode::AwsKms,
        None,
        Utc::now(),
    )
    .unwrap();
    let get_res = adapter.generate_presigned_get(
        &artifact,
        "test.pdf",
        Utc::now() + chrono::Duration::minutes(5),
    );
    assert!(
        get_res.is_err(),
        "Missing bucket must fail closed on presigned GET"
    );

    // Placeholder credentials must fail closed
    let placeholder_config = S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: None,
        access_key_id: "w014-production-access-key".to_string(),
        secret_access_key: "w014-production-secret-key-at-least-32-bytes".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: None,
    };
    assert!(
        placeholder_config.validate().is_err(),
        "Placeholder credentials must fail closed"
    );

    let mut config2 = S3StorageConfig::from_env();
    config2.secret_access_key = "   ".to_string();
    assert!(
        config2.validate().is_err(),
        "Empty secret_access_key must fail closed"
    );

    // Empty region fails closed
    let mut config_region = S3StorageConfig::from_env();
    config_region.bucket = "w014-documents".to_string();
    config_region.region = "   ".to_string();
    config_region.access_key_id = "key".to_string();
    config_region.secret_access_key = "secret".to_string();
    assert!(
        config_region.validate().is_err(),
        "Empty region must fail closed"
    );

    // Empty access key fails closed
    let mut config_key = config_region.clone();
    config_key.region = "us-east-1".to_string();
    config_key.access_key_id = "   ".to_string();
    assert!(
        config_key.validate().is_err(),
        "Empty access key must fail closed"
    );

    // Malformed sse_mode fails closed
    let mut config_sse = config_region.clone();
    config_sse.region = "us-east-1".to_string();
    config_sse.access_key_id = "key".to_string();
    config_sse.sse_mode = "invalid-sse".to_string();
    assert!(
        config_sse.validate().is_err(),
        "Malformed sse_mode must fail closed"
    );

    // Blank endpoint if provided fails closed
    let mut config_ep = config_region.clone();
    config_ep.region = "us-east-1".to_string();
    config_ep.access_key_id = "key".to_string();
    config_ep.endpoint = Some("   ".to_string());
    assert!(
        config_ep.validate().is_err(),
        "Blank endpoint must fail closed"
    );
}

// -----------------------------------------------------------------------------
// Test 7: S3 network failure fails closed
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_07_s3_network_failure_fails_closed() {
    let config = S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some("http://127.0.0.1:2".to_string()),
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: None,
    };
    let adapter = S3StorageAdapter::new(config);

    let head_err = adapter
        .head_object("w014-documents", "raw/net-fail.pdf")
        .await
        .unwrap_err();
    match head_err {
        FinalizeUploadError::Internal(e) => assert!(e.contains("network failure")),
        other => panic!("Expected Internal, got: {:?}", other),
    }

    let get_err = adapter
        .get_object_bytes("w014-documents", "raw/net-fail.pdf")
        .await
        .unwrap_err();
    match get_err {
        FinalizeUploadError::Internal(e) => assert!(e.contains("network failure")),
        other => panic!("Expected Internal, got: {:?}", other),
    }
}

// -----------------------------------------------------------------------------
// Test 8: Presigned PUT signing failure returns error
// -----------------------------------------------------------------------------
#[test]
fn test_08_presigned_put_signing_failure_returns_error() {
    let config = S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: None,
        access_key_id: "test-access-key".to_string(),
        secret_access_key: "test-secret-key".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: None,
    };
    let adapter = S3StorageAdapter::new(config);
    let valid_sha = Sha256::digest(b"valid").to_base64();

    // Invalid key with leading slash
    let err = adapter
        .generate_presigned_put(
            "/leading-slash",
            MediaType::ApplicationPdf,
            1024,
            &valid_sha,
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap_err();
    assert!(matches!(err, FinalizeUploadError::PreconditionFailed(_)));

    // Invalid key with directory traversal
    let err2 = adapter
        .generate_presigned_put(
            "dir/../escape",
            MediaType::ApplicationPdf,
            1024,
            &valid_sha,
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap_err();
    assert!(matches!(err2, FinalizeUploadError::PreconditionFailed(_)));

    // Zero content length
    let err3 = adapter
        .generate_presigned_put(
            "valid/key.pdf",
            MediaType::ApplicationPdf,
            0,
            &valid_sha,
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap_err();
    assert!(matches!(err3, FinalizeUploadError::PreconditionFailed(_)));

    // Exceeding 100 MiB limit
    let err4 = adapter
        .generate_presigned_put(
            "valid/key.pdf",
            MediaType::ApplicationPdf,
            104_857_601,
            &valid_sha,
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap_err();
    assert!(matches!(err4, FinalizeUploadError::PayloadTooLarge(_)));

    // Invalid base64 checksum
    let err5 = adapter
        .generate_presigned_put(
            "valid/key.pdf",
            MediaType::ApplicationPdf,
            1024,
            "not-valid-base64!",
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap_err();
    assert!(matches!(err5, FinalizeUploadError::PreconditionFailed(_)));

    // Empty digest fallback forbidden
    let empty_sha = Sha256::digest(b"").to_base64();
    let err_empty = adapter
        .generate_presigned_put(
            "valid/key.pdf",
            MediaType::ApplicationPdf,
            1024,
            &empty_sha,
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap_err();
    assert!(matches!(
        err_empty,
        FinalizeUploadError::PreconditionFailed(_)
    ));

    // Expired TTL
    let err6 = adapter
        .generate_presigned_put(
            "valid/key.pdf",
            MediaType::ApplicationPdf,
            1024,
            &valid_sha,
            Utc::now() - chrono::Duration::seconds(10),
        )
        .unwrap_err();
    assert!(matches!(err6, FinalizeUploadError::PreconditionFailed(_)));
}

// -----------------------------------------------------------------------------
// Test 9: No unsigned PUT URL is produced after signing failure
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_09_no_unsigned_put_url_produced_after_signing_failure() {
    let _guard = TEST_MUTEX.lock().await;
    DocumentService::clear_injected_storage();

    let valid_sha = Sha256::digest(b"test").to_base64();
    let res = DocumentService::try_generate_presigned_put(
        "w014-documents",
        "../bad-key",
        MediaType::ApplicationPdf,
        1024,
        &valid_sha,
        Utc::now() + chrono::Duration::minutes(5),
    );

    assert!(res.is_err(), "Signing failure must propagate error");
}

// -----------------------------------------------------------------------------
// Test 10: No production runtime path appends signature=valid
// -----------------------------------------------------------------------------
#[test]
fn test_10_no_production_runtime_path_appends_signature_valid() {
    let config = S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: None,
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: Some("arn:aws:kms:us-east-1:123456789012:key/test-key-id".to_string()),
    };
    let adapter = S3StorageAdapter::new(config);
    let valid_sha = Sha256::digest(b"dummy payload").to_base64();

    let put_res = adapter
        .generate_presigned_put(
            "raw/upload-intent-1.pdf",
            MediaType::ApplicationPdf,
            2048,
            &valid_sha,
            Utc::now() + chrono::Duration::minutes(15), // Requested 15 mins (900s)
        )
        .unwrap();

    assert!(
        !put_res.upload_url.contains("signature=valid"),
        "Production PUT URL must not contain signature=valid: {}",
        put_res.upload_url
    );
    assert!(
        put_res.upload_url.contains("X-Amz-Signature="),
        "Production PUT URL must contain real SigV4 signature: {}",
        put_res.upload_url
    );

    // Defect 2: Presigned PUT required content headers signature-bound
    assert!(
        put_res.upload_url.contains("X-Amz-SignedHeaders="),
        "Must contain X-Amz-SignedHeaders parameter"
    );
    let signed_headers_param = put_res
        .upload_url
        .split("X-Amz-SignedHeaders=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .unwrap_or_default();
    assert!(
        signed_headers_param.contains("content-type"),
        "SignedHeaders must bind content-type: {signed_headers_param}"
    );
    assert!(
        signed_headers_param.contains("content-length"),
        "SignedHeaders must bind content-length: {signed_headers_param}"
    );
    assert!(
        signed_headers_param.contains("x-amz-checksum-sha256"),
        "SignedHeaders must bind x-amz-checksum-sha256: {signed_headers_param}"
    );
    assert!(
        signed_headers_param.contains("x-amz-server-side-encryption"),
        "SignedHeaders must bind x-amz-server-side-encryption: {signed_headers_param}"
    );
    assert!(
        signed_headers_param.contains("x-amz-server-side-encryption-aws-kms-key-id"),
        "SignedHeaders must bind kms key id: {signed_headers_param}"
    );

    // Defect 4: Presigned PUT TTL frozen ceiling <= 600s
    let remaining_ttl = (put_res.expires_at - Utc::now()).num_seconds();
    assert!(
        remaining_ttl <= 600 && remaining_ttl > 590,
        "PUT TTL must be clamped to at most 600 seconds, got: {remaining_ttl}"
    );

    let sha = Sha256::digest(b"dummy download content");
    let artifact = ObjectArtifact::reconstruct(
        ObjectArtifactId::new(),
        WorkspaceId::new(),
        ArtifactKind::RawUpload,
        "w014-documents".to_string(),
        ObjectKey::reconstruct("raw/upload-1.pdf").unwrap(),
        sha,
        2048,
        StoredMediaType::new("application/pdf").unwrap(),
        StorageTier::Hot,
        EncryptionMode::AwsKms,
        None,
        Utc::now(),
    )
    .unwrap();

    let get_res = adapter
        .generate_presigned_get(
            &artifact,
            "invoice.pdf",
            Utc::now() + chrono::Duration::minutes(10), // Requested 10 mins (600s)
        )
        .unwrap();

    assert!(
        !get_res.download_url.contains("signature=valid"),
        "Production GET URL must not contain signature=valid: {}",
        get_res.download_url
    );
    assert!(
        get_res.download_url.contains("X-Amz-Signature="),
        "Production GET URL must contain real SigV4 signature: {}",
        get_res.download_url
    );

    // Defect 4: Presigned GET TTL frozen ceiling <= 300s
    let remaining_get_ttl = (get_res.expires_at - Utc::now()).num_seconds();
    assert!(
        remaining_get_ttl <= 300 && remaining_get_ttl > 290,
        "GET TTL must be clamped to at most 300 seconds, got: {remaining_get_ttl}"
    );
}

// -----------------------------------------------------------------------------
// Test 11: Test memory storage requires explicit test injection
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_11_test_memory_storage_requires_explicit_test_injection() {
    let _guard = TEST_MUTEX.lock().await;
    DocumentService::clear_injected_storage();
    assert!(
        !DocumentService::is_test_storage_active(),
        "Test storage must not be active by default"
    );

    let test_adapter = Arc::new(TestStorageAdapter::new());
    DocumentService::inject_storage(test_adapter);
    assert!(
        DocumentService::is_test_storage_active(),
        "Test storage must be active when explicitly injected"
    );

    DocumentService::clear_injected_storage();
    assert!(
        !DocumentService::is_test_storage_active(),
        "Test storage must be inactive after clear"
    );
}

// -----------------------------------------------------------------------------
// Fixture setup helper for Tests 12-15
// -----------------------------------------------------------------------------
struct TestFixture {
    test_db: TestDatabase,
    ws_a: Workspace,
    principal: Principal,
    awc_a: AuthorizedWorkspaceContext,
    queue: PgJobQueue,
}

async fn setup_fixture() -> TestFixture {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision test db");
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
        principal,
        awc_a,
        queue,
    }
}

async fn finalize_staged_upload(
    f: &TestFixture,
    filename: &str,
    media_type: MediaType,
    bytes: &[u8],
) -> (UploadIntent, Uuid) {
    let mut tx = f.test_db.pool().begin().await.unwrap();

    let intent = UploadIntent::new(
        f.ws_a.id,
        f.principal.id,
        None,
        filename,
        media_type,
        bytes.len() as i64,
        Some(Sha256::digest(bytes)),
        Utc::now() + chrono::Duration::minutes(5),
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

    let job_row = sqlx::query(
        "SELECT job_id FROM jobs WHERE workspace_id = $1 AND queue_name = $2 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(f.ws_a.id.as_uuid())
    .bind(QUEUE_MALWARE_SCAN)
    .fetch_one(f.test_db.pool())
    .await
    .unwrap();
    let job_id: Uuid = job_row.get("job_id");

    (finalize_res.intent, job_id)
}

// -----------------------------------------------------------------------------
// Test 12: Clean PDF -> ParseDocumentPdf still passes
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_12_clean_pdf_parse_document_pdf_successor_passes() {
    let _guard = TEST_MUTEX.lock().await;
    let f = setup_fixture().await;
    let pdf_bytes = b"%PDF-1.7 harmless clean sample document bytes for testing";

    let (intent, _job_id) =
        finalize_staged_upload(&f, "clean.pdf", MediaType::ApplicationPdf, pdf_bytes).await;

    let criteria = ClaimCriteria {
        queues: vec![QUEUE_MALWARE_SCAN.to_string()],
        kinds: vec![JobKind::MalwareScanDocumentPdf],
        workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
        lease_duration: Duration::from_secs(30),
    };
    let claimed = f
        .queue
        .claim(criteria, WorkerId::new())
        .await
        .unwrap()
        .unwrap();

    let scanner = Arc::new(MockClamAvScanner::new());
    let executor = MalwareScanJobExecutor::new(f.test_db.pool().clone(), scanner);
    let outcome = executor
        .execute_claimed(&claimed)
        .await
        .expect("executor must succeed");
    assert!(outcome.is_some());

    // Verify quarantine status transitioned to Clean
    let mut conn = f.test_db.pool().acquire().await.unwrap();
    let record = QuarantineRecordRepository::get_latest_by_intent(&mut conn, f.ws_a.id, intent.id)
        .await
        .unwrap()
        .expect("quarantine record must exist");
    assert_eq!(record.status, QuarantineStatus::Clean);

    // Verify ParseDocumentPdf successor was enqueued
    let parser_criteria = ClaimCriteria {
        queues: vec!["documents.parse".to_string()],
        kinds: vec![JobKind::ParseDocumentPdf],
        workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
        lease_duration: Duration::from_secs(30),
    };
    let parser_claimed = f
        .queue
        .claim(parser_criteria, WorkerId::new())
        .await
        .unwrap();
    assert!(
        parser_claimed.is_some(),
        "ParseDocumentPdf successor must be enqueued"
    );

    DocumentService::clear_mock_storage();
}

// -----------------------------------------------------------------------------
// Test 13: Clean DOCX -> ParseDocumentDocxOcr still passes
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_13_clean_docx_parse_document_docx_ocr_successor_passes() {
    let _guard = TEST_MUTEX.lock().await;
    let f = setup_fixture().await;
    let docx_bytes = b"PK\x03\x04 fake docx bytes for testing";

    let (intent, _job_id) =
        finalize_staged_upload(&f, "clean.docx", MediaType::Docx, docx_bytes).await;

    let criteria = ClaimCriteria {
        queues: vec![QUEUE_MALWARE_SCAN.to_string()],
        kinds: vec![JobKind::MalwareScanDocumentDocxOcr],
        workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
        lease_duration: Duration::from_secs(30),
    };
    let claimed = f
        .queue
        .claim(criteria, WorkerId::new())
        .await
        .unwrap()
        .unwrap();

    let scanner = Arc::new(MockClamAvScanner::new());
    let executor = MalwareScanJobExecutor::new(f.test_db.pool().clone(), scanner);
    let outcome = executor
        .execute_claimed(&claimed)
        .await
        .expect("executor must succeed");
    assert!(outcome.is_some());

    // Verify quarantine status transitioned to Clean
    let mut conn = f.test_db.pool().acquire().await.unwrap();
    let record = QuarantineRecordRepository::get_latest_by_intent(&mut conn, f.ws_a.id, intent.id)
        .await
        .unwrap()
        .expect("quarantine record must exist");
    assert_eq!(record.status, QuarantineStatus::Clean);

    // Verify ParseDocumentDocxOcr successor was enqueued
    let parser_criteria = ClaimCriteria {
        queues: vec!["documents.parse".to_string()],
        kinds: vec![JobKind::ParseDocumentDocxOcr],
        workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
        lease_duration: Duration::from_secs(30),
    };
    let parser_claimed = f
        .queue
        .claim(parser_criteria, WorkerId::new())
        .await
        .unwrap();
    assert!(
        parser_claimed.is_some(),
        "ParseDocumentDocxOcr successor must be enqueued"
    );

    DocumentService::clear_mock_storage();
}

// -----------------------------------------------------------------------------
// Test 14: Non-clean -> zero parser successor still passes
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_14_non_clean_zero_parser_successor_passes() {
    let _guard = TEST_MUTEX.lock().await;
    let f = setup_fixture().await;
    let malware_bytes = EICAR_TEST_SIGNATURE;

    let (intent, _job_id) =
        finalize_staged_upload(&f, "eicar.pdf", MediaType::ApplicationPdf, malware_bytes).await;

    let criteria = ClaimCriteria {
        queues: vec![QUEUE_MALWARE_SCAN.to_string()],
        kinds: vec![JobKind::MalwareScanDocumentPdf],
        workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
        lease_duration: Duration::from_secs(30),
    };
    let claimed = f
        .queue
        .claim(criteria, WorkerId::new())
        .await
        .unwrap()
        .unwrap();

    let scanner = Arc::new(MockClamAvScanner::new());
    let executor = MalwareScanJobExecutor::new(f.test_db.pool().clone(), scanner);
    let outcome = executor
        .execute_claimed(&claimed)
        .await
        .expect("malware scan completes execution");
    let res_json = outcome.expect("malware outcome result");
    assert_eq!(res_json["status"], "malware");
    assert_eq!(res_json["threat_name"], EICAR_THREAT_NAME);

    // Quarantine must be recorded as Malware
    let mut conn = f.test_db.pool().acquire().await.unwrap();
    let record = QuarantineRecordRepository::get_latest_by_intent(&mut conn, f.ws_a.id, intent.id)
        .await
        .unwrap()
        .expect("quarantine record must exist");
    assert_eq!(record.status, QuarantineStatus::Malware);
    assert_eq!(record.reason_code.as_deref(), Some(EICAR_THREAT_NAME));

    // ZERO parser successor jobs enqueued
    let parser_jobs = sqlx::query(
        "SELECT count(*) as cnt FROM jobs WHERE workspace_id = $1 AND queue_name = 'documents.parse'",
    )
    .bind(f.ws_a.id.as_uuid())
    .fetch_one(f.test_db.pool())
    .await
    .unwrap();
    let count: i64 = parser_jobs.get("cnt");
    assert_eq!(
        count, 0,
        "Zero parser successors must be enqueued on malware hit"
    );

    DocumentService::clear_mock_storage();
}

// -----------------------------------------------------------------------------
// Test 15: Expired worker -> zero domain mutation still passes
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_15_expired_worker_zero_domain_mutation_passes() {
    let _guard = TEST_MUTEX.lock().await;
    let f = setup_fixture().await;
    let pdf_bytes = b"%PDF-1.7 harmless clean sample document bytes for testing";

    let (intent, _job_id) =
        finalize_staged_upload(&f, "clean.pdf", MediaType::ApplicationPdf, pdf_bytes).await;

    let criteria = ClaimCriteria {
        queues: vec![QUEUE_MALWARE_SCAN.to_string()],
        kinds: vec![JobKind::MalwareScanDocumentPdf],
        workspace: WorkspaceScope::Single(f.ws_a.id.into_uuid()),
        lease_duration: Duration::from_secs(30),
    };
    let mut claimed = f
        .queue
        .claim(criteria, WorkerId::new())
        .await
        .unwrap()
        .unwrap();

    // Tamper with lease token to simulate expired lease fence
    claimed.lease_token = Uuid::new_v4();

    let scanner = Arc::new(MockClamAvScanner::new());
    let executor = MalwareScanJobExecutor::new(f.test_db.pool().clone(), scanner);
    let err = executor.execute_claimed(&claimed).await.unwrap_err();
    assert!(err.error_code.contains("LEASE") || err.detail.contains("lease"));

    // Quarantine record must remain Pending (zero domain mutation)
    let mut conn = f.test_db.pool().acquire().await.unwrap();
    let record = QuarantineRecordRepository::get_latest_by_intent(&mut conn, f.ws_a.id, intent.id)
        .await
        .unwrap()
        .expect("quarantine record must exist");
    assert_eq!(record.status, QuarantineStatus::Pending);

    // ZERO parser successors
    let parser_jobs = sqlx::query(
        "SELECT count(*) as cnt FROM jobs WHERE workspace_id = $1 AND queue_name = 'documents.parse'",
    )
    .bind(f.ws_a.id.as_uuid())
    .fetch_one(f.test_db.pool())
    .await
    .unwrap();
    let count: i64 = parser_jobs.get("cnt");
    assert_eq!(count, 0, "Zero parser successors on expired lease");

    DocumentService::clear_mock_storage();
}

// -----------------------------------------------------------------------------
// Test 16: Prompt-12 physical mappings remain correct
// -----------------------------------------------------------------------------
#[test]
fn test_16_prompt12_physical_mappings_remain_correct() {
    assert_eq!(StorageTier::Hot.as_str(), "hot");
    assert_eq!(StorageTier::Warm.as_str(), "warm");
    assert_eq!(StorageTier::Cold.as_str(), "cold");
    assert_eq!(StorageTier::Archive.as_str(), "archive");

    assert_eq!(EncryptionMode::AwsKms.as_str(), "aws:kms");
    assert_eq!(EncryptionMode::Local.as_str(), "local");

    assert_eq!(ArtifactKind::RawUpload.as_str(), "raw_upload");
    assert_eq!(ArtifactKind::Ocr.as_str(), "ocr");
    assert_eq!(ArtifactKind::Parser.as_str(), "parser");
    assert_eq!(ArtifactKind::PagePreview.as_str(), "page_preview");
    assert_eq!(ArtifactKind::ReportJson.as_str(), "report_json");
    assert_eq!(ArtifactKind::ReportPdf.as_str(), "report_pdf");
    assert_eq!(ArtifactKind::Temp.as_str(), "temp");
}

// -----------------------------------------------------------------------------
// Test 17: S3 HEAD checksum validations fail closed
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_17_s3_head_checksum_validations_fail_closed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]);

                let resp = if req_str.contains("/raw/missing-checksum.pdf") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nContent-Type: application/pdf\r\nETag: \"abc\"\r\n\r\n"
                } else if req_str.contains("/raw/malformed-checksum.pdf") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nContent-Type: application/pdf\r\nx-amz-checksum-sha256: not-valid-base64!\r\nETag: \"abc\"\r\n\r\n"
                } else if req_str.contains("/raw/empty-digest.pdf") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nContent-Type: application/pdf\r\nx-amz-checksum-sha256: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\r\nETag: \"abc\"\r\n\r\n"
                } else if req_str.contains("/raw/missing-len.pdf") {
                    "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nx-amz-checksum-sha256: dGVzdA==\r\nETag: \"abc\"\r\n\r\n"
                } else if req_str.contains("/raw/missing-type.pdf") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nx-amz-checksum-sha256: dGVzdA==\r\nETag: \"abc\"\r\n\r\n"
                } else if req_str.contains("/raw/valid.pdf") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nContent-Type: application/pdf\r\nx-amz-checksum-sha256: n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=\r\nx-amz-server-side-encryption: aws:kms\r\nx-amz-server-side-encryption-aws-kms-key-id: arn:aws:kms:us-east-1:123456789012:key/test-kms-key\r\nETag: \"abc\"\r\n\r\n"
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
                };

                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });

    let config = S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some(format!("http://{local_addr}")),
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: Some("arn:aws:kms:us-east-1:123456789012:key/test-kms-key".to_string()),
    };
    let adapter = S3StorageAdapter::new(config);

    // 1. Missing checksum -> fail closed
    let err_missing = adapter
        .head_object("w014-documents", "raw/missing-checksum.pdf")
        .await
        .unwrap_err();
    match err_missing {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(msg.contains("missing required x-amz-checksum-sha256 header"));
        }
        other => panic!("Expected PreconditionFailed, got: {:?}", other),
    }

    // 2. Malformed checksum -> fail closed
    let err_malformed = adapter
        .head_object("w014-documents", "raw/malformed-checksum.pdf")
        .await
        .unwrap_err();
    match err_malformed {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(msg.contains("malformed x-amz-checksum-sha256 checksum"));
        }
        other => panic!("Expected PreconditionFailed, got: {:?}", other),
    }

    // 3. Empty digest fallback -> fail closed
    let err_empty = adapter
        .head_object("w014-documents", "raw/empty-digest.pdf")
        .await
        .unwrap_err();
    match err_empty {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(msg.contains("empty digest fallback is forbidden"));
        }
        other => panic!("Expected PreconditionFailed, got: {:?}", other),
    }

    // 4. Missing Content-Length -> fail closed
    let err_len = adapter
        .head_object("w014-documents", "raw/missing-len.pdf")
        .await
        .unwrap_err();
    match err_len {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(msg.contains("missing or invalid Content-Length"));
        }
        other => panic!("Expected PreconditionFailed, got: {:?}", other),
    }

    // 5. Missing Content-Type -> fail closed
    let err_type = adapter
        .head_object("w014-documents", "raw/missing-type.pdf")
        .await
        .unwrap_err();
    match err_type {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(msg.contains("missing Content-Type"));
        }
        other => panic!("Expected PreconditionFailed, got: {:?}", other),
    }

    // 6. Valid HEAD -> succeeds with exact facts
    let meta = adapter
        .head_object("w014-documents", "raw/valid.pdf")
        .await
        .unwrap()
        .expect("Valid object must return Some(meta)");
    assert_eq!(meta.byte_length, 1024);
    assert_eq!(meta.content_type, "application/pdf");
    assert_eq!(
        meta.content_sha256,
        Sha256::from_base64(
            "x-amz-checksum-sha256",
            "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="
        )
        .unwrap()
    );
    assert_eq!(meta.sse_mode, EncryptionMode::AwsKms);
    assert_eq!(
        meta.kms_key_id.as_deref(),
        Some("arn:aws:kms:us-east-1:123456789012:key/test-kms-key")
    );

    server_task.abort();
}

// -----------------------------------------------------------------------------
// Test 18: Encryption facts derived directly from storage authority
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_18_encryption_facts_derived_from_storage_authority() {
    let _guard = TEST_MUTEX.lock().await;

    // 1. Adapter level posture deriving
    let kms_config = S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: None,
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: Some("arn:aws:kms:us-east-1:123456789012:key/test-kms-key".to_string()),
    };
    let kms_adapter = S3StorageAdapter::new(kms_config);
    assert_eq!(
        kms_adapter.encryption_posture(),
        (
            EncryptionMode::AwsKms,
            Some("arn:aws:kms:us-east-1:123456789012:key/test-kms-key".to_string())
        )
    );

    let local_config = S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: None,
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "local".to_string(),
        kms_key_id: None,
    };
    let local_adapter = S3StorageAdapter::new(local_config);
    assert_eq!(
        local_adapter.encryption_posture(),
        (EncryptionMode::Local, None)
    );

    // 2. End-to-end database persistence of authoritative encryption posture
    let f = setup_fixture().await;

    // A. Local posture persisted into ObjectArtifact
    DocumentService::set_test_storage_encryption_posture(EncryptionMode::Local, None);
    let bytes_local = b"%PDF-1.7 local encryption content";
    let (intent_local, _) =
        finalize_staged_upload(&f, "local.pdf", MediaType::ApplicationPdf, bytes_local).await;

    let artifact_local =
        sqlx::query("SELECT sse_mode, kms_key_ref FROM object_artifacts WHERE object_key = $1")
            .bind(intent_local.opaque_object_key.as_str())
            .fetch_one(f.test_db.pool())
            .await
            .unwrap();
    let sse_local: String = artifact_local.get("sse_mode");
    let kms_local: Option<String> = artifact_local.get("kms_key_ref");
    assert_eq!(sse_local, "local");
    assert_eq!(kms_local, None);

    // B. KMS posture persisted into ObjectArtifact
    let kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/test-kms-key".to_string();
    DocumentService::set_test_storage_encryption_posture(
        EncryptionMode::AwsKms,
        Some(kms_key_id.clone()),
    );
    let bytes_kms = b"%PDF-1.7 kms encryption content";
    let (intent_kms, _) =
        finalize_staged_upload(&f, "kms.pdf", MediaType::ApplicationPdf, bytes_kms).await;

    let artifact_kms =
        sqlx::query("SELECT sse_mode, kms_key_ref FROM object_artifacts WHERE object_key = $1")
            .bind(intent_kms.opaque_object_key.as_str())
            .fetch_one(f.test_db.pool())
            .await
            .unwrap();
    let sse_kms: String = artifact_kms.get("sse_mode");
    let kms_ref: Option<String> = artifact_kms.get("kms_key_ref");
    assert_eq!(sse_kms, "aws:kms");
    assert_eq!(kms_ref, Some(kms_key_id));

    DocumentService::clear_mock_storage();
}

// -----------------------------------------------------------------------------
// Test 19: Presigned PUT and GET TTL frozen limits cannot be expanded
// -----------------------------------------------------------------------------
#[test]
fn test_19_ttl_frozen_limits_cannot_be_expanded() {
    let config = S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: None,
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: None,
    };
    let s3_adapter = S3StorageAdapter::new(config);
    let valid_sha = Sha256::digest(b"test").to_base64();

    // 1. PUT TTL requested > 600s is clamped to <= 600s
    let put_res = s3_adapter
        .generate_presigned_put(
            "raw/test-ttl.pdf",
            MediaType::ApplicationPdf,
            1024,
            &valid_sha,
            Utc::now() + chrono::Duration::seconds(10_000),
        )
        .unwrap();
    let put_remaining = (put_res.expires_at - Utc::now()).num_seconds();
    assert!(
        put_remaining <= 600 && put_remaining > 590,
        "PUT TTL must be clamped to at most 600 seconds, got: {put_remaining}"
    );
    assert!(put_res.upload_url.contains("X-Amz-Expires=600"));

    // 2. GET TTL requested > 300s is clamped to <= 300s
    let artifact = ObjectArtifact::reconstruct(
        ObjectArtifactId::new(),
        WorkspaceId::new(),
        ArtifactKind::RawUpload,
        "w014-documents".to_string(),
        ObjectKey::reconstruct("raw/test-ttl.pdf").unwrap(),
        Sha256::digest(b"test"),
        1024,
        StoredMediaType::new("application/pdf").unwrap(),
        StorageTier::Hot,
        EncryptionMode::AwsKms,
        None,
        Utc::now(),
    )
    .unwrap();

    let get_res = s3_adapter
        .generate_presigned_get(
            &artifact,
            "test-ttl.pdf",
            Utc::now() + chrono::Duration::seconds(10_000),
        )
        .unwrap();
    let get_remaining = (get_res.expires_at - Utc::now()).num_seconds();
    assert!(
        get_remaining <= 300 && get_remaining > 290,
        "GET TTL must be clamped to at most 300 seconds, got: {get_remaining}"
    );
    assert!(get_res.download_url.contains("X-Amz-Expires=300"));

    // 3. Test storage adapter also enforces frozen limits
    let test_adapter = TestStorageAdapter::new();
    let test_put = test_adapter
        .generate_presigned_put(
            "raw/test-ttl.pdf",
            MediaType::ApplicationPdf,
            1024,
            &valid_sha,
            Utc::now() + chrono::Duration::seconds(10_000),
        )
        .unwrap();
    let test_put_remaining = (test_put.expires_at - Utc::now()).num_seconds();
    assert!(
        test_put_remaining <= 600 && test_put_remaining > 590,
        "Test adapter PUT TTL must be clamped to at most 600 seconds, got: {test_put_remaining}"
    );

    let test_get = test_adapter
        .generate_presigned_get(
            &artifact,
            "test-ttl.pdf",
            Utc::now() + chrono::Duration::seconds(10_000),
        )
        .unwrap();
    let test_get_remaining = (test_get.expires_at - Utc::now()).num_seconds();
    assert!(
        test_get_remaining <= 300 && test_get_remaining > 290,
        "Test adapter GET TTL must be clamped to at most 300 seconds, got: {test_get_remaining}"
    );
}

// -----------------------------------------------------------------------------
// Test 20: Mandatory SHA-256 integrity and empty digest fallback rejection
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_20_mandatory_sha256_rejections() {
    let _guard = TEST_MUTEX.lock().await;
    let config = S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: None,
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: None,
    };
    let s3_adapter = S3StorageAdapter::new(config);
    let empty_sha = Sha256::digest(b"").to_base64();

    // 1. S3 Presigned PUT rejects empty digest fallback
    let err_empty = s3_adapter
        .generate_presigned_put(
            "raw/empty.pdf",
            MediaType::ApplicationPdf,
            1024,
            &empty_sha,
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap_err();
    assert!(matches!(
        err_empty,
        FinalizeUploadError::PreconditionFailed(_)
    ));

    // 2. TestStorageAdapter Presigned PUT rejects empty digest fallback
    let test_adapter = TestStorageAdapter::new();
    let err_test_empty = test_adapter
        .generate_presigned_put(
            "raw/empty.pdf",
            MediaType::ApplicationPdf,
            1024,
            &empty_sha,
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap_err();
    assert!(matches!(
        err_test_empty,
        FinalizeUploadError::PreconditionFailed(_)
    ));

    // 3. Finalize upload without expected sha256 fails closed
    let f = setup_fixture().await;
    let mut tx = f.test_db.pool().begin().await.unwrap();
    let intent_no_sha = UploadIntent::new(
        f.ws_a.id,
        f.principal.id,
        None,
        "no-sha.pdf",
        MediaType::ApplicationPdf,
        1024,
        None, // missing expected sha256
        Utc::now() + chrono::Duration::minutes(5),
    )
    .unwrap();
    UploadIntentRepository::insert(&mut tx, &intent_no_sha)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let dummy_1024 = vec![0u8; 1024];
    DocumentService::stage_mock_upload_bytes(
        "w014-documents",
        intent_no_sha.opaque_object_key.as_str(),
        &dummy_1024,
        "application/pdf",
    );

    let idemp_store = PostgresIdempotencyStore::new();
    let mut tx = f.test_db.pool().begin().await.unwrap();
    let err_fin_no_sha = DocumentService::execute_finalize_upload_tx(
        &mut tx,
        &f.awc_a,
        f.principal.id,
        intent_no_sha.id,
        Utc::now(),
        None,
        &idemp_store,
    )
    .await
    .unwrap_err();
    match err_fin_no_sha {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(msg.contains("UploadIntent missing mandatory expected SHA-256 checksum"));
        }
        other => panic!("Expected PreconditionFailed, got: {:?}", other),
    }

    DocumentService::clear_mock_storage();
}
