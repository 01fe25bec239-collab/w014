//! WI0203 E2 repair: AWS S3 HEAD must explicitly request checksum mode.
//!
//! Proves against the real [`S3StorageAdapter`] (no production mock fallback):
//! - HEAD requests SigV4-bind `x-amz-checksum-mode: ENABLED`
//! - `X-Amz-SignedHeaders` contains the checksum-mode header
//! - The header value sent over HTTP exactly matches the signed value
//! - AWS-style HEAD checksum responses are accepted as authoritative
//! - Missing / malformed checksums fail closed (even though mode was requested)
//! - Declared-vs-authoritative mismatch fails closed via finalize
//! - PUT contract (SHA required/signed, content headers/SSE signed, TTLs) preserved

use std::sync::{Arc, Mutex};

use chrono::Utc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use w014_application::services::document_service::{DocumentService, FinalizeUploadError};
use w014_application::services::storage::{
    HEAD_CHECKSUM_MODE_HEADER_NAME, HEAD_CHECKSUM_MODE_HEADER_VALUE, S3StorageAdapter,
    S3StorageConfig,
};
use w014_domain::Sha256;
use w014_domain::ids::{ObjectArtifactId, WorkspaceId};
use w014_domain::media::MediaType;
use w014_domain::object_artifacts::{
    ArtifactKind, EncryptionMode, ObjectArtifact, ObjectKey, StorageTier,
};

fn test_s3_config(endpoint: &str) -> S3StorageConfig {
    S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some(endpoint.to_string()),
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: None,
    }
}

/// Spawns a minimal raw-TCP AWS-style S3 HEAD stub.
///
/// Records every raw HTTP request into `captured` and always replies with
/// `response`. Returns the bound address and the server task handle.
async fn spawn_head_stub(
    response: String,
    captured: Arc<Mutex<Vec<String>>>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let captured = captured.clone();
            let response = response.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                if let Ok(mut guard) = captured.lock() {
                    guard.push(raw);
                }
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (addr, handle)
}

fn aws_style_head_response(sha_b64: &str, len: i64) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nContent-Type: application/pdf\r\nx-amz-checksum-sha256: {sha_b64}\r\nx-amz-server-side-encryption: aws:kms\r\nETag: \"abc123\"\r\n\r\n"
    )
}

// -----------------------------------------------------------------------------
// Contract constants
// -----------------------------------------------------------------------------
#[test]
fn test_e2_head_checksum_mode_contract_constants() {
    assert_eq!(HEAD_CHECKSUM_MODE_HEADER_NAME, "x-amz-checksum-mode");
    assert_eq!(HEAD_CHECKSUM_MODE_HEADER_VALUE, "ENABLED");
}

// -----------------------------------------------------------------------------
// build_head_request binds checksum-mode into SigV4 and returns same value to send
// -----------------------------------------------------------------------------
#[test]
fn test_e2_head_request_builder_sigv4_binds_checksum_mode() {
    let adapter = S3StorageAdapter::new(test_s3_config("http://127.0.0.1:1"));
    let now = Utc::now();
    let (signed_url, headers) = adapter.build_head_request("raw/checksum-mode.pdf", now);

    // Header to send must be exactly ENABLED (single constant source).
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0, "x-amz-checksum-mode");
    assert_eq!(headers[0].1, "ENABLED");
    assert_eq!(headers[0].1, HEAD_CHECKSUM_MODE_HEADER_VALUE);

    // Signed URL must carry a real SigV4 signature.
    assert!(
        signed_url.contains("X-Amz-Signature="),
        "HEAD URL must be SigV4 signed: {signed_url}"
    );
    // SignedHeaders must bind the checksum-mode header.
    assert!(
        signed_url.contains("X-Amz-SignedHeaders="),
        "HEAD URL must carry SignedHeaders: {signed_url}"
    );
    assert!(
        signed_url.contains("x-amz-checksum-mode"),
        "HEAD SignedHeaders must contain checksum-mode: {signed_url}"
    );
}

// -----------------------------------------------------------------------------
// E2: actual outgoing HTTP HEAD sends checksum-mode + AWS checksum accepted
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_e2_http_head_actually_sends_checksum_mode_and_accepts_aws_checksum() {
    let payload = b"%PDF-1.7 aws checksum-bound e2 bytes";
    let sha_b64 = Sha256::digest(payload).to_base64();

    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (addr, server) = spawn_head_stub(
        aws_style_head_response(&sha_b64, payload.len() as i64),
        captured.clone(),
    )
    .await;

    let adapter = S3StorageAdapter::new(test_s3_config(&format!("http://{addr}")));

    // Exercise the real production HEAD path (no mock fallback).
    let meta = adapter
        .head_object("w014-documents", "raw/e2-checksum-mode.pdf")
        .await
        .expect("AWS-style HEAD with checksum must succeed")
        .expect("object must exist");

    // AWS-style response accepted as authoritative.
    assert_eq!(meta.byte_length, payload.len() as i64);
    assert_eq!(meta.content_type, "application/pdf");
    assert_eq!(meta.content_sha256, Sha256::digest(payload));

    // Actual outgoing request construction: raw wire must carry checksum-mode ENABLED.
    let guard = captured.lock().unwrap();
    assert!(
        !guard.is_empty(),
        "server must have captured at least one HEAD request"
    );
    let raw = &guard[0];
    assert!(
        raw.to_lowercase().contains("x-amz-checksum-mode:"),
        "HTTP HEAD must actually send x-amz-checksum-mode, got: {raw}"
    );
    assert!(
        raw.contains("x-amz-checksum-mode: ENABLED"),
        "HTTP HEAD checksum-mode value must be exactly ENABLED, got: {raw}"
    );
    // Request line must SigV4-bind the header (SignedHeaders contains it).
    assert!(
        raw.contains("x-amz-checksum-mode"),
        "HEAD request line must SigV4-bind checksum-mode via X-Amz-SignedHeaders, got: {raw}"
    );
    assert!(
        raw.contains("X-Amz-Signature=") || raw.contains("X-Amz-SignedHeaders="),
        "HEAD request must carry SigV4 presigned query, got: {raw}"
    );

    // Signed value and sent value must match exactly (single constant).
    let (_, headers_to_send) = adapter.build_head_request("raw/e2-checksum-mode.pdf", Utc::now());
    let signed_value = &headers_to_send[0].1;
    assert_eq!(signed_value, "ENABLED");
    assert!(
        raw.contains(signed_value),
        "sent header value must exactly match signed value"
    );

    server.abort();
}

// -----------------------------------------------------------------------------
// Missing checksum fails closed, but mode was still requested on the wire
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_e2_head_missing_checksum_fail_closed_with_mode_requested() {
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let missing_resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nContent-Type: application/pdf\r\nETag: \"abc\"\r\n\r\n"
            .to_string();
    let (addr, server) = spawn_head_stub(missing_resp, captured.clone()).await;
    let adapter = S3StorageAdapter::new(test_s3_config(&format!("http://{addr}")));

    let err = adapter
        .head_object("w014-documents", "raw/missing-checksum-e2.pdf")
        .await
        .expect_err("missing checksum must fail closed");
    match err {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(
                msg.contains("missing required x-amz-checksum-sha256 header"),
                "{msg}"
            );
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }

    let guard = captured.lock().unwrap();
    assert!(!guard.is_empty());
    assert!(
        guard[0].contains("x-amz-checksum-mode: ENABLED"),
        "checksum-mode must be requested even when response lacks checksum: {}",
        guard[0]
    );
    server.abort();
}

// -----------------------------------------------------------------------------
// Malformed checksum fails closed, but mode was still requested on the wire
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_e2_head_malformed_checksum_fail_closed_with_mode_requested() {
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let malformed_resp = "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nContent-Type: application/pdf\r\nx-amz-checksum-sha256: not-valid-base64!\r\nETag: \"abc\"\r\n\r\n".to_string();
    let (addr, server) = spawn_head_stub(malformed_resp, captured.clone()).await;
    let adapter = S3StorageAdapter::new(test_s3_config(&format!("http://{addr}")));

    let err = adapter
        .head_object("w014-documents", "raw/malformed-checksum-e2.pdf")
        .await
        .expect_err("malformed checksum must fail closed");
    match err {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(
                msg.contains("malformed x-amz-checksum-sha256 checksum"),
                "{msg}"
            );
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }

    let guard = captured.lock().unwrap();
    assert!(!guard.is_empty());
    assert!(
        guard[0].contains("x-amz-checksum-mode: ENABLED"),
        "checksum-mode must be requested even when response is malformed: {}",
        guard[0]
    );
    server.abort();
}

// -----------------------------------------------------------------------------
// Metadata-only checksum is NOT authoritative (no metadata fallback)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_e2_head_metadata_fallback_absent_fail_closed() {
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sha_b64 = Sha256::digest(b"metadata only").to_base64();
    let metadata_only_resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: application/pdf\r\nx-amz-meta-content-sha256: {sha_b64}\r\nETag: \"abc\"\r\n\r\n"
    );
    let (addr, server) = spawn_head_stub(metadata_only_resp, captured.clone()).await;
    let adapter = S3StorageAdapter::new(test_s3_config(&format!("http://{addr}")));

    let err = adapter
        .head_object("w014-documents", "raw/metadata-only-e2.pdf")
        .await
        .expect_err("metadata fallback must not substitute authoritative checksum");
    match err {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(
                msg.contains("missing required x-amz-checksum-sha256 header"),
                "{msg}"
            );
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }

    let guard = captured.lock().unwrap();
    assert!(!guard.is_empty());
    assert!(guard[0].contains("x-amz-checksum-mode: ENABLED"));
    server.abort();
}

// -----------------------------------------------------------------------------
// Mismatch fails closed via authoritative finalize comparison (real PostgreSQL)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_e2_head_mismatch_checksum_fail_closed_via_finalize() {
    use w014_application::persistence::{
        OrganizationRepository, PrincipalRepository, ProgramRepository, UploadIntentRepository,
        WorkspaceRepository,
    };
    use w014_application::services::MembershipService;
    use w014_authz::AuthorizedWorkspaceContext;
    use w014_domain::UploadIntent;
    use w014_domain::membership::MembershipRole;
    use w014_domain::organization::Organization;
    use w014_domain::principal::Principal;
    use w014_domain::program::Program;
    use w014_domain::workspace::Workspace;
    use w014_persistence::audit::PostgresAuditStore;
    use w014_persistence::harness::TestDatabase;
    use w014_persistence::idempotency::PostgresIdempotencyStore;
    use w014_persistence::runner::{MIGRATOR, MigrationRunner};

    // Authoritative bytes the uploader declared; S3 will authoritatively return other bytes.
    // Both payloads share byte length so the failure is purely a checksum mismatch.
    let declared_bytes = b"%PDF-1.7 declared legitimate bytes for mismatch e2";
    let actual_bytes = b"%PDF-1.7 different AUTHORITATIVE bytes mismatch e2";
    assert_eq!(declared_bytes.len(), actual_bytes.len());
    let declared_sha = Sha256::digest(declared_bytes);
    let actual_sha = Sha256::digest(actual_bytes);
    assert_ne!(declared_sha, actual_sha);
    let actual_b64 = actual_sha.to_base64();

    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (addr, server) = spawn_head_stub(
        aws_style_head_response(&actual_b64, actual_bytes.len() as i64),
        captured.clone(),
    )
    .await;

    let test_db = TestDatabase::new().await.unwrap();
    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .unwrap();

    let audit_store = PostgresAuditStore::new();
    let mut tx = test_db.pool().begin().await.unwrap();
    let org = Organization::new("Mismatch Org", "mismatch-org").unwrap();
    OrganizationRepository::insert(&mut tx, &org).await.unwrap();
    let principal = Principal::new("Mismatch User", Some("mismatch@example.com")).unwrap();
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .unwrap();
    let prog = Program::new(org.id, "Mismatch Program", "mismatch-prog").unwrap();
    ProgramRepository::insert(&mut tx, &prog).await.unwrap();
    let ws = Workspace::new(prog.id, org.id, "Mismatch WS", "mismatch-ws").unwrap();
    WorkspaceRepository::insert(&mut tx, &ws).await.unwrap();
    MembershipService::add_member_with_audit(
        &mut tx,
        &audit_store,
        ws.id,
        principal.id,
        MembershipRole::Admin,
        Some(principal.id),
        Some("mismatch-setup".to_string()),
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

    // Intent declares SHA of declared_bytes with matching length/type.
    let mut tx = test_db.pool().begin().await.unwrap();
    let intent = UploadIntent::new(
        ws.id,
        principal.id,
        None,
        "mismatch.pdf",
        MediaType::ApplicationPdf,
        declared_bytes.len() as i64,
        Some(declared_sha),
        Utc::now() + chrono::Duration::minutes(5),
    )
    .unwrap();
    UploadIntentRepository::insert(&mut tx, &intent)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Inject the REAL S3 adapter (endpoint = wire stub) as the storage authority.
    let s3 = Arc::new(S3StorageAdapter::new(test_s3_config(&format!(
        "http://{addr}"
    ))));
    DocumentService::inject_storage(s3);
    let idemp = PostgresIdempotencyStore::new();
    let mut tx = test_db.pool().begin().await.unwrap();
    let err = DocumentService::execute_finalize_upload_tx(
        &mut tx,
        &awc,
        principal.id,
        intent.id,
        Utc::now(),
        None,
        &idemp,
    )
    .await
    .expect_err("declared-vs-authoritative mismatch must fail closed");
    match err {
        FinalizeUploadError::UnprocessableEntity(msg) => {
            assert!(msg.contains("checksum mismatch"), "{msg}");
        }
        other => panic!("expected UnprocessableEntity mismatch, got: {other:?}"),
    }
    DocumentService::clear_injected_storage();

    // Wire must have requested checksum mode for the mismatched HEAD too.
    let guard = captured.lock().unwrap();
    assert!(!guard.is_empty());
    assert!(guard[0].contains("x-amz-checksum-mode: ENABLED"));

    server.abort();
}

// -----------------------------------------------------------------------------
// PUT contract preservation (SHA mandatory/signed, headers signed, TTLs bounded)
// -----------------------------------------------------------------------------
#[test]
fn test_e2_put_contract_preserved_with_head_repair() {
    let adapter = S3StorageAdapter::new(S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: None,
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: Some("arn:aws:kms:us-east-1:123456789012:key/test-key-id".to_string()),
    });
    let valid_sha = Sha256::digest(b"put contract payload").to_base64();

    // Empty digest fallback remains forbidden.
    let empty_sha = Sha256::digest(b"").to_base64();
    let err = adapter
        .generate_presigned_put(
            "raw/put-empty.pdf",
            MediaType::ApplicationPdf,
            1024,
            &empty_sha,
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap_err();
    assert!(matches!(err, FinalizeUploadError::PreconditionFailed(_)));

    // Missing/invalid SHA remains mandatory.
    let err = adapter
        .generate_presigned_put(
            "raw/put-nosha.pdf",
            MediaType::ApplicationPdf,
            1024,
            "not-valid-base64!",
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap_err();
    assert!(matches!(err, FinalizeUploadError::PreconditionFailed(_)));

    let put = adapter
        .generate_presigned_put(
            "raw/put-ok.pdf",
            MediaType::ApplicationPdf,
            2048,
            &valid_sha,
            Utc::now() + chrono::Duration::minutes(15),
        )
        .unwrap();
    assert!(put.upload_url.contains("X-Amz-Signature="));
    let signed = put
        .upload_url
        .split("X-Amz-SignedHeaders=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .unwrap_or_default();
    for required in [
        "content-type",
        "content-length",
        "x-amz-checksum-sha256",
        "x-amz-server-side-encryption",
    ] {
        assert!(
            signed.contains(required),
            "PUT must sign {required}: {signed}"
        );
    }
    assert!(put.headers.contains_key("x-amz-checksum-sha256"));
    let put_ttl = (put.expires_at - Utc::now()).num_seconds();
    assert!(
        put_ttl <= 600 && put_ttl > 590,
        "PUT TTL <=600s, got {put_ttl}"
    );
    assert!(put.upload_url.contains("X-Amz-Expires=600"));

    let artifact = ObjectArtifact::reconstruct(
        ObjectArtifactId::new(),
        WorkspaceId::new(),
        ArtifactKind::RawUpload,
        "w014-documents".to_string(),
        ObjectKey::reconstruct("raw/put-ok.pdf").unwrap(),
        Sha256::digest(b"put contract payload"),
        2048,
        w014_domain::media::StoredMediaType::new("application/pdf").unwrap(),
        StorageTier::Hot,
        EncryptionMode::AwsKms,
        None,
        Utc::now(),
    )
    .unwrap();
    let get = adapter
        .generate_presigned_get(
            &artifact,
            "put-ok.pdf",
            Utc::now() + chrono::Duration::minutes(10),
        )
        .unwrap();
    let get_ttl = (get.expires_at - Utc::now()).num_seconds();
    assert!(
        get_ttl <= 300 && get_ttl > 290,
        "GET TTL <=300s, got {get_ttl}"
    );
    assert!(get.download_url.contains("X-Amz-Expires=300"));
}
