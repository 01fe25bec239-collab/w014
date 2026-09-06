//! E2 storage-authority forward completion (WI0203 encryption + WI0202/E24 download).
//!
//! Proves against the real [`S3StorageAdapter`] (no production mock fallback):
//! - Prior WI0203 HEAD checksum-mode closure preserved (ENABLED, SigV4-bound,
//!   actually sent; missing/malformed/mismatch fail closed; no empty fallback).
//! - Observed immutable encryption facts come ONLY from the authoritative HEAD
//!   response; configuration validates policy but never substitutes.
//! - Storage-level signed GET binds `response-cache-control=private, no-store`
//!   into the canonical SigV4 request (no unsigned post-sign mutation).
//! - PUT regressions preserved (SHA required/signed, headers signed, TTLs).

use std::sync::{Arc, Mutex};

use chrono::Utc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use w014_application::services::document_service::FinalizeUploadError;
use w014_application::services::storage::{
    HEAD_CHECKSUM_MODE_HEADER_NAME, HEAD_CHECKSUM_MODE_HEADER_VALUE, ObjectStorage,
    S3StorageAdapter, S3StorageConfig, SIGNED_GET_CACHE_CONTROL_VALUE,
    SIGNED_GET_RESPONSE_CACHE_CONTROL_PARAM, TestStorageAdapter,
};
use w014_domain::Sha256;
use w014_domain::ids::{ObjectArtifactId, WorkspaceId};
use w014_domain::media::MediaType;
use w014_domain::object_artifacts::{
    ArtifactKind, EncryptionMode, ObjectArtifact, ObjectKey, StorageTier,
};

const TEST_KMS_KEY: &str = "arn:aws:kms:us-east-1:123456789012:key/e2-forward-test-key";
const OTHER_KMS_KEY: &str = "arn:aws:kms:us-east-1:123456789012:key/e2-other-key";

fn kms_config(endpoint: &str, kms_key: Option<String>) -> S3StorageConfig {
    S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some(endpoint.to_string()),
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: kms_key,
    }
}

fn local_config(endpoint: &str) -> S3StorageConfig {
    S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some(endpoint.to_string()),
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "local".to_string(),
        kms_key_id: None,
    }
}

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

fn head_ok_response(
    sha_b64: &str,
    len: i64,
    sse_header: Option<&str>,
    kms_header: Option<&str>,
) -> String {
    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nContent-Type: application/pdf\r\nx-amz-checksum-sha256: {sha_b64}\r\n"
    );
    if let Some(sse) = sse_header {
        resp.push_str(&format!("x-amz-server-side-encryption: {sse}\r\n"));
    }
    if let Some(kms) = kms_header {
        resp.push_str(&format!(
            "x-amz-server-side-encryption-aws-kms-key-id: {kms}\r\n"
        ));
    }
    resp.push_str("ETag: \"abc123\"\r\n\r\n");
    resp
}

fn test_artifact(key: &str) -> ObjectArtifact {
    ObjectArtifact::reconstruct(
        ObjectArtifactId::new(),
        WorkspaceId::new(),
        ArtifactKind::RawUpload,
        "w014-documents".to_string(),
        ObjectKey::reconstruct(key).unwrap(),
        Sha256::digest(b"e2 forward download bytes"),
        1024,
        w014_domain::media::StoredMediaType::new("application/pdf").unwrap(),
        StorageTier::Hot,
        EncryptionMode::AwsKms,
        None,
        Utc::now(),
    )
    .unwrap()
}

// -----------------------------------------------------------------------------
// Prior WI0203 checksum-mode closure preserved
// -----------------------------------------------------------------------------
#[test]
fn test_e2_forward_head_checksum_mode_preserved() {
    assert_eq!(HEAD_CHECKSUM_MODE_HEADER_NAME, "x-amz-checksum-mode");
    assert_eq!(HEAD_CHECKSUM_MODE_HEADER_VALUE, "ENABLED");

    let adapter = S3StorageAdapter::new(kms_config("http://127.0.0.1:1", None));
    let now = Utc::now();
    let (signed_url, headers) = adapter.build_head_request("raw/e2-forward.pdf", now);
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0, "x-amz-checksum-mode");
    assert_eq!(headers[0].1, "ENABLED");
    assert!(signed_url.contains("X-Amz-Signature="));
    assert!(signed_url.contains("x-amz-checksum-mode"));
}

#[tokio::test]
async fn test_e2_forward_http_head_actually_sent_and_aws_checksum_accepted() {
    let payload = b"%PDF-1.7 e2 forward checksum bytes";
    let sha_b64 = Sha256::digest(payload).to_base64();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (addr, server) = spawn_head_stub(
        head_ok_response(&sha_b64, payload.len() as i64, Some("aws:kms"), None),
        captured.clone(),
    )
    .await;
    // No configured KMS key: observed aws:kms without KMS key header is allowed
    // (KMS identity required only where frozen contract requires it).
    let adapter = S3StorageAdapter::new(kms_config(&format!("http://{addr}"), None));
    let meta = adapter
        .head_object("w014-documents", "raw/e2-forward-checksum.pdf")
        .await
        .expect("AWS-style HEAD must succeed")
        .expect("object must exist");
    assert_eq!(meta.byte_length, payload.len() as i64);
    assert_eq!(meta.content_sha256, Sha256::digest(payload));
    assert_eq!(meta.sse_mode, EncryptionMode::AwsKms);

    let guard = captured.lock().unwrap();
    assert!(!guard.is_empty());
    assert!(guard[0].contains("x-amz-checksum-mode: ENABLED"));
    server.abort();
}

// -----------------------------------------------------------------------------
// Defect 1: observed SSE aws:kms passes
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_e2_forward_observed_sse_aws_kms_pass() {
    let payload = b"%PDF-1.7 observed kms bytes e2 forward";
    let sha_b64 = Sha256::digest(payload).to_base64();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (addr, server) = spawn_head_stub(
        head_ok_response(
            &sha_b64,
            payload.len() as i64,
            Some("aws:kms"),
            Some(TEST_KMS_KEY),
        ),
        captured.clone(),
    )
    .await;
    let adapter = S3StorageAdapter::new(kms_config(
        &format!("http://{addr}"),
        Some(TEST_KMS_KEY.to_string()),
    ));
    let meta = adapter
        .head_object("w014-documents", "raw/observed-kms.pdf")
        .await
        .expect("observed aws:kms with matching KMS key must succeed")
        .expect("object must exist");
    assert_eq!(meta.sse_mode, EncryptionMode::AwsKms);
    assert_eq!(meta.kms_key_id.as_deref(), Some(TEST_KMS_KEY));
    assert_eq!(meta.content_sha256, Sha256::digest(payload));
    // Wire still requests checksum mode.
    let guard = captured.lock().unwrap();
    assert!(guard[0].contains("x-amz-checksum-mode: ENABLED"));
    server.abort();
}

// -----------------------------------------------------------------------------
// Defect 1: missing SSE metadata fails closed (no config substitution)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_e2_forward_missing_sse_metadata_fail_closed() {
    let payload = b"%PDF-1.7 missing sse bytes e2";
    let sha_b64 = Sha256::digest(payload).to_base64();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    // Valid checksum/length/type but NO SSE header; configured mode is aws:kms.
    let (addr, server) = spawn_head_stub(
        head_ok_response(&sha_b64, payload.len() as i64, None, None),
        captured.clone(),
    )
    .await;
    let adapter = S3StorageAdapter::new(kms_config(
        &format!("http://{addr}"),
        Some(TEST_KMS_KEY.to_string()),
    ));
    let err = adapter
        .head_object("w014-documents", "raw/missing-sse.pdf")
        .await
        .expect_err("missing SSE metadata must fail closed");
    match err {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(
                msg.contains("missing required x-amz-server-side-encryption"),
                "unexpected message: {msg}"
            );
            assert!(
                msg.contains("configuration cannot substitute"),
                "must state config cannot substitute: {msg}"
            );
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
    let guard = captured.lock().unwrap();
    assert!(guard[0].contains("x-amz-checksum-mode: ENABLED"));
    server.abort();
}

// -----------------------------------------------------------------------------
// Defect 1: unexpected SSE mode fails closed
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_e2_forward_unexpected_sse_mode_fail_closed() {
    let payload = b"%PDF-1.7 unexpected sse e2 forward!";
    let sha_b64 = Sha256::digest(payload).to_base64();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (addr, server) = spawn_head_stub(
        head_ok_response(&sha_b64, payload.len() as i64, Some("AES256"), None),
        captured.clone(),
    )
    .await;
    let adapter = S3StorageAdapter::new(kms_config(&format!("http://{addr}"), None));
    let err = adapter
        .head_object("w014-documents", "raw/unexpected-sse.pdf")
        .await
        .expect_err("unexpected SSE mode must fail closed");
    match err {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(
                msg.contains("unexpected x-amz-server-side-encryption"),
                "{msg}"
            );
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
    let guard = captured.lock().unwrap();
    assert!(guard[0].contains("x-amz-checksum-mode: ENABLED"));
    server.abort();
}

// -----------------------------------------------------------------------------
// Defect 1: required KMS key missing fails closed
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_e2_forward_required_kms_key_missing_fail_closed() {
    let payload = b"%PDF-1.7 kms missing bytes e2 forward";
    let sha_b64 = Sha256::digest(payload).to_base64();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    // Observed aws:kms but NO KMS key header while configured policy requires one.
    let (addr, server) = spawn_head_stub(
        head_ok_response(&sha_b64, payload.len() as i64, Some("aws:kms"), None),
        captured.clone(),
    )
    .await;
    let adapter = S3StorageAdapter::new(kms_config(
        &format!("http://{addr}"),
        Some(TEST_KMS_KEY.to_string()),
    ));
    let err = adapter
        .head_object("w014-documents", "raw/kms-missing.pdf")
        .await
        .expect_err("missing KMS key must fail closed");
    match err {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(
                msg.contains("missing required x-amz-server-side-encryption-aws-kms-key-id"),
                "{msg}"
            );
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
    let guard = captured.lock().unwrap();
    assert!(guard[0].contains("x-amz-checksum-mode: ENABLED"));
    server.abort();
}

// -----------------------------------------------------------------------------
// Defect 1: configured KMS key cannot substitute for observed fact
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_e2_forward_configured_kms_key_cannot_substitute() {
    let payload = b"%PDF-1.7 no substitute bytes e2 fwd!";
    let sha_b64 = Sha256::digest(payload).to_base64();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (addr, server) = spawn_head_stub(
        head_ok_response(&sha_b64, payload.len() as i64, Some("aws:kms"), None),
        captured.clone(),
    )
    .await;
    // Even though configuration holds the KMS key, the observed fact is absent,
    // so HEAD must fail rather than persist the configured key.
    let adapter = S3StorageAdapter::new(kms_config(
        &format!("http://{addr}"),
        Some(TEST_KMS_KEY.to_string()),
    ));
    let result = adapter
        .head_object("w014-documents", "raw/no-substitute.pdf")
        .await;
    assert!(
        result.is_err(),
        "configured KMS key must NOT substitute for missing observed fact"
    );
    match result.unwrap_err() {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(msg.contains("cannot substitute"), "{msg}");
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
    let guard = captured.lock().unwrap();
    assert!(!guard.is_empty());
    server.abort();
}

// -----------------------------------------------------------------------------
// Defect 1: observed/configured encryption mismatch fails closed
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_e2_forward_observed_configured_encryption_mismatch_fail_closed() {
    let payload = b"%PDF-1.7 mismatch bytes e2 forward!!";
    let sha_b64 = Sha256::digest(payload).to_base64();

    // Case A: observed KMS key differs from configured KMS policy.
    let captured_a: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (addr_a, server_a) = spawn_head_stub(
        head_ok_response(
            &sha_b64,
            payload.len() as i64,
            Some("aws:kms"),
            Some(OTHER_KMS_KEY),
        ),
        captured_a.clone(),
    )
    .await;
    let adapter_a = S3StorageAdapter::new(kms_config(
        &format!("http://{addr_a}"),
        Some(TEST_KMS_KEY.to_string()),
    ));
    let err_a = adapter_a
        .head_object("w014-documents", "raw/kms-mismatch.pdf")
        .await
        .expect_err("KMS key mismatch must fail closed");
    match err_a {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(msg.contains("mismatches configured KMS policy"), "{msg}");
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
    server_a.abort();

    // Case B: configured local but observed aws:kms.
    let captured_b: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (addr_b, server_b) = spawn_head_stub(
        head_ok_response(
            &sha_b64,
            payload.len() as i64,
            Some("aws:kms"),
            Some(TEST_KMS_KEY),
        ),
        captured_b.clone(),
    )
    .await;
    let adapter_b = S3StorageAdapter::new(local_config(&format!("http://{addr_b}")));
    let err_b = adapter_b
        .head_object("w014-documents", "raw/local-mismatch.pdf")
        .await
        .expect_err("local vs aws:kms mismatch must fail closed");
    match err_b {
        FinalizeUploadError::PreconditionFailed(msg) => {
            assert!(msg.contains("mismatches configured 'local'"), "{msg}");
        }
        other => panic!("expected PreconditionFailed, got: {other:?}"),
    }
    server_b.abort();
}

// -----------------------------------------------------------------------------
// Local mode: frozen distinction, no AWS fact fabrication
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_e2_forward_local_mode_no_fabrication() {
    let payload = b"%PDF-1.7 local bytes e2 forward!!";
    let sha_b64 = Sha256::digest(payload).to_base64();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    // Local objects carry no AWS SSE headers; absent SSE persists as local.
    let (addr, server) = spawn_head_stub(
        head_ok_response(&sha_b64, payload.len() as i64, None, None),
        captured.clone(),
    )
    .await;
    let adapter = S3StorageAdapter::new(local_config(&format!("http://{addr}")));
    let meta = adapter
        .head_object("w014-documents", "raw/local-ok.pdf")
        .await
        .expect("local HEAD without SSE must succeed")
        .expect("object must exist");
    assert_eq!(meta.sse_mode, EncryptionMode::Local);
    assert_eq!(meta.kms_key_id, None);
    assert_eq!(meta.sse_mode.as_str(), "local");
    assert_eq!(EncryptionMode::AwsKms.as_str(), "aws:kms");
    let guard = captured.lock().unwrap();
    assert!(guard[0].contains("x-amz-checksum-mode: ENABLED"));
    server.abort();
}

// -----------------------------------------------------------------------------
// Defect 2: signed GET private/no-store bound to signature
// -----------------------------------------------------------------------------
#[test]
fn test_e2_forward_signed_get_private_no_store_bound() {
    assert_eq!(
        SIGNED_GET_RESPONSE_CACHE_CONTROL_PARAM,
        "response-cache-control"
    );
    assert_eq!(SIGNED_GET_CACHE_CONTROL_VALUE, "private, no-store");

    let adapter = S3StorageAdapter::new(S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: None,
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: None,
    });
    let artifact = test_artifact("raw/e2-download.pdf");
    let get = adapter
        .generate_presigned_get(
            &artifact,
            "e2-download.pdf",
            Utc::now() + chrono::Duration::minutes(10),
        )
        .expect("presigned GET must succeed");

    // TTL <= 300s.
    let ttl = (get.expires_at - Utc::now()).num_seconds();
    assert!(ttl <= 300 && ttl > 290, "GET TTL <=300s, got {ttl}");
    assert!(get.download_url.contains("X-Amz-Expires=300"));
    assert!(get.download_url.contains("X-Amz-Signature="));

    // Signed response-cache-control override present (percent-encoded).
    assert!(
        get.download_url
            .contains("response-cache-control=private%2C%20no-store"),
        "download URL must carry signed response-cache-control private,no-store: {}",
        get.download_url
    );

    // Bound to signature: override appears BEFORE X-Amz-Signature (part of the
    // canonical signed query), never appended after signing.
    let sig_pos = get
        .download_url
        .find("X-Amz-Signature=")
        .expect("signed URL must contain signature");
    let cc_pos = get
        .download_url
        .find("response-cache-control=")
        .expect("signed URL must contain cache-control override");
    assert!(
        cc_pos < sig_pos,
        "cache-control override must be bound before signature (canonical signed query)"
    );
    let after_sig = &get.download_url[sig_pos..];
    assert!(
        !after_sig.contains("response-cache-control"),
        "unsigned post-sign mutation absent: cache-control must not appear after signature"
    );
    assert!(
        !after_sig.to_lowercase().contains("cache-control"),
        "no cache-control mutation after signature"
    );
}

#[test]
fn test_e2_forward_unsigned_post_sign_mutation_absent() {
    let adapter = S3StorageAdapter::new(S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: None,
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: None,
    });
    let artifact = test_artifact("raw/e2-no-mutation.pdf");
    let get = adapter
        .generate_presigned_get(
            &artifact,
            "e2-no-mutation.pdf",
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap();
    // Exactly one signed occurrence, before the signature.
    assert_eq!(
        get.download_url.matches("response-cache-control=").count(),
        1,
        "exactly one signed cache-control override: {}",
        get.download_url
    );
    let sig_pos = get.download_url.find("X-Amz-Signature=").unwrap();
    let first_cc = get.download_url.find("response-cache-control=").unwrap();
    assert!(first_cc < sig_pos);
}

#[test]
fn test_e2_forward_test_adapter_get_private_no_store() {
    let adapter = TestStorageAdapter::new();
    let artifact = test_artifact("raw/e2-test-adapter.pdf");
    let get = adapter
        .generate_presigned_get(
            &artifact,
            "e2-test-adapter.pdf",
            Utc::now() + chrono::Duration::minutes(10),
        )
        .unwrap();
    let ttl = (get.expires_at - Utc::now()).num_seconds();
    assert!(ttl <= 300 && ttl > 290, "GET TTL <=300s, got {ttl}");
    assert!(
        get.download_url
            .contains("response-cache-control=private%2C%20no-store"),
        "test adapter GET must carry private,no-store posture: {}",
        get.download_url
    );
}

// -----------------------------------------------------------------------------
// PUT regressions preserved
// -----------------------------------------------------------------------------
#[test]
fn test_e2_forward_put_regressions_preserved() {
    let adapter = S3StorageAdapter::new(S3StorageConfig {
        bucket: "w014-documents".to_string(),
        region: "us-east-1".to_string(),
        endpoint: None,
        access_key_id: "test-key".to_string(),
        secret_access_key: "test-secret".to_string(),
        sse_mode: "aws:kms".to_string(),
        kms_key_id: Some(TEST_KMS_KEY.to_string()),
    });
    let valid_sha = Sha256::digest(b"e2 forward put payload").to_base64();

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
}
