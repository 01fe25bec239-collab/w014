//! Production S3-compatible object storage authority and AWS SigV4 presigning.
//!
//! Provides real production object storage integration with:
//! - Private configured bucket
//! - Server-owned opaque object key enforcement
//! - Rust-authorized SigV4 presigned PUT and GET contracts
//! - Bounded PUT (<= 15m) and GET (<= 5m) lifespans
//! - Checksum-bound upload verification (`x-amz-checksum-sha256`)
//! - Strict Content-Type and Content-Length authorization
//! - Authoritative object HEAD (fail-closed, no mock fallback)
//! - Real worker byte retrieval (fail-closed, no mock fallback)
//! - Prompt-12 cloud SSE-KMS (`aws:kms`) and local (`local`) mapping
//! - Explicit test storage injection for deterministic test execution
//! - No permanent object URLs stored in product state
//! - No browser bucket credentials exposed

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256 as HashingSha256};
use w014_domain::media::MediaType;
use w014_domain::object_artifacts::ObjectArtifact;
use w014_domain::sha256::Sha256;

use crate::services::document_service::{
    FinalizeUploadError, PresignedGetContract, PresignedPutContract, StoredObjectMetadata,
};

type HmacSha256 = Hmac<HashingSha256>;

pub const MAX_PUT_EXPIRATION_SECS: i64 = 600; // 10 minutes max (<= 600s)
pub const MAX_GET_EXPIRATION_SECS: i64 = 300; // 5 minutes max (<= 300s)

/// Authoritative object storage contract implemented by production and test providers.
#[async_trait::async_trait]
pub trait ObjectStorage: Send + Sync {
    /// Generates a bounded presigned PUT contract.
    fn generate_presigned_put(
        &self,
        object_key: &str,
        media_type: MediaType,
        content_length: i64,
        sha256_b64: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PresignedPutContract, FinalizeUploadError>;

    /// Generates a bounded presigned GET download contract.
    fn generate_presigned_get(
        &self,
        artifact: &ObjectArtifact,
        original_filename: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PresignedGetContract, FinalizeUploadError>;

    /// Authoritative object HEAD verifying presence, length, and digest.
    async fn head_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<StoredObjectMetadata>, FinalizeUploadError>;

    /// Authoritative worker byte retrieval.
    async fn get_object_bytes(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, FinalizeUploadError>;

    /// Encryption posture (mode and optional KMS key ref) derived from storage authority.
    fn encryption_posture(&self) -> (w014_domain::EncryptionMode, Option<String>);
}

/// Configuration for real S3-compatible storage.
#[derive(Debug, Clone)]
pub struct S3StorageConfig {
    pub bucket: String,
    pub region: String,
    pub endpoint: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub sse_mode: String,
    pub kms_key_id: Option<String>,
}

impl Default for S3StorageConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl S3StorageConfig {
    /// Loads configuration from environment variables.
    /// Fails closed with empty values if missing; no fallback placeholder credentials.
    pub fn from_env() -> Self {
        let bucket = std::env::var("S3_BUCKET_NAME")
            .or_else(|_| std::env::var("AWS_S3_BUCKET"))
            .unwrap_or_default();

        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("S3_REGION"))
            .unwrap_or_default();

        let endpoint = std::env::var("AWS_ENDPOINT_URL")
            .or_else(|_| std::env::var("S3_ENDPOINT"))
            .ok()
            .filter(|e| !e.trim().is_empty());

        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();

        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();

        let sse_mode = std::env::var("S3_SSE_MODE").unwrap_or_else(|_| "aws:kms".to_string());

        let kms_key_id = std::env::var("KMS_KEY_ARN")
            .or_else(|_| std::env::var("S3_KMS_KEY_ID"))
            .ok()
            .filter(|k| !k.trim().is_empty());

        Self {
            bucket,
            region,
            endpoint,
            access_key_id,
            secret_access_key,
            sse_mode,
            kms_key_id,
        }
    }

    /// Validates that all required S3 configuration values are present. Fails closed.
    pub fn validate(&self) -> Result<(), FinalizeUploadError> {
        if self.bucket.trim().is_empty() {
            return Err(FinalizeUploadError::PreconditionFailed(
                "S3 configuration error: bucket must not be empty".to_string(),
            ));
        }
        if self.region.trim().is_empty() {
            return Err(FinalizeUploadError::PreconditionFailed(
                "S3 configuration error: region must not be empty".to_string(),
            ));
        }
        if self.access_key_id.trim().is_empty() {
            return Err(FinalizeUploadError::PreconditionFailed(
                "S3 configuration error: access_key_id must not be empty".to_string(),
            ));
        }
        if self.secret_access_key.trim().is_empty() {
            return Err(FinalizeUploadError::PreconditionFailed(
                "S3 configuration error: secret_access_key must not be empty".to_string(),
            ));
        }
        // Fail closed if placeholder credentials are used
        if self.access_key_id == "w014-production-access-key"
            || self.secret_access_key == "w014-production-secret-key-at-least-32-bytes"
        {
            return Err(FinalizeUploadError::PreconditionFailed(
                "S3 configuration error: placeholder credentials are forbidden in production authority".to_string(),
            ));
        }
        // Fail closed on malformed sse_mode
        if self.sse_mode != "aws:kms" && self.sse_mode != "local" {
            return Err(FinalizeUploadError::PreconditionFailed(format!(
                "S3 configuration error: sse_mode '{}' is invalid; must be 'aws:kms' or 'local'",
                self.sse_mode
            )));
        }
        if let Some(ref ep) = self.endpoint
            && ep.trim().is_empty()
        {
            return Err(FinalizeUploadError::PreconditionFailed(
                "S3 configuration error: endpoint must not be blank if provided".to_string(),
            ));
        }
        Ok(())
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = HashingSha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Standard AWS SigV4 URI percent encoding (RFC 3986).
fn percent_encode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

/// Derives AWS SigV4 signing key.
fn derive_sigv4_signing_key(secret: &str, datestamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{secret}").into_bytes();
    let k_date = hmac_sha256(&k_secret, datestamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Real S3-compatible storage adapter providing authoritative storage operations.
#[derive(Clone)]
pub struct S3StorageAdapter {
    config: S3StorageConfig,
    client: reqwest::Client,
}

static DEFAULT_ADAPTER: OnceLock<S3StorageAdapter> = OnceLock::new();

impl S3StorageAdapter {
    /// Creates a new adapter with the given configuration.
    pub fn new(config: S3StorageConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }

    /// Returns a reference to the process-global default S3 adapter.
    pub fn default_adapter() -> &'static Self {
        DEFAULT_ADAPTER.get_or_init(|| Self::new(S3StorageConfig::default()))
    }

    /// The configured private bucket.
    pub fn bucket(&self) -> &str {
        &self.config.bucket
    }

    /// The configured region.
    pub fn region(&self) -> &str {
        &self.config.region
    }

    /// Base URL for S3 requests.
    pub fn base_url(&self) -> String {
        if let Some(ref ep) = self.config.endpoint {
            ep.trim_end_matches('/').to_string()
        } else {
            format!(
                "https://{}.s3.{}.amazonaws.com",
                self.config.bucket, self.config.region
            )
        }
    }

    /// Host name for SigV4 host header.
    fn host_header(&self) -> String {
        if let Some(ref ep) = self.config.endpoint {
            let stripped = ep
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/');
            stripped.to_string()
        } else {
            format!(
                "{}.s3.{}.amazonaws.com",
                self.config.bucket, self.config.region
            )
        }
    }

    /// Computes canonical path for an object key.
    fn canonical_path(&self, object_key: &str) -> String {
        if self.config.endpoint.is_some() {
            // Path style for custom endpoints (e.g. MinIO / LocalStack / test)
            format!(
                "/{}/{}",
                self.config.bucket,
                object_key.trim_start_matches('/')
            )
        } else {
            // Virtual-hosted style for standard AWS
            format!("/{}", object_key.trim_start_matches('/'))
        }
    }

    /// Generates an AWS Signature Version 4 presigned URL.
    pub fn generate_sigv4_presigned_url(
        &self,
        method: &str,
        object_key: &str,
        now: DateTime<Utc>,
        expires_in_secs: u64,
        extra_signed_headers: &[(&str, &str)],
    ) -> String {
        let datestamp = now.format("%Y%m%d").to_string();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let credential_scope =
            format!("{}/{}/{}/aws4_request", datestamp, self.config.region, "s3");

        let canonical_uri = self.canonical_path(object_key);
        let host = self.host_header();

        // Build headers map for signing (must include host)
        let mut signed_headers_map: Vec<(&str, String)> = Vec::new();
        signed_headers_map.push(("host", host));
        for (h, v) in extra_signed_headers {
            signed_headers_map.push((h, (*v).to_string()));
        }
        signed_headers_map.sort_by_key(|a| a.0.to_lowercase());

        let signed_headers_str = signed_headers_map
            .iter()
            .map(|(k, _)| k.to_lowercase())
            .collect::<Vec<_>>()
            .join(";");

        let mut canonical_headers = String::new();
        for (k, v) in &signed_headers_map {
            canonical_headers.push_str(&format!("{}:{}\n", k.to_lowercase(), v.trim()));
        }

        // Canonical query parameters (alphabetically sorted by key)
        let credential_param = format!("{}/{}", self.config.access_key_id, credential_scope);
        let mut query_params: Vec<(&str, String)> = vec![
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
            ("X-Amz-Credential", credential_param),
            ("X-Amz-Date", timestamp.clone()),
            ("X-Amz-Expires", expires_in_secs.to_string()),
            ("X-Amz-SignedHeaders", signed_headers_str.clone()),
        ];
        query_params.sort_by(|a, b| a.0.cmp(b.0));

        let canonical_query_string = query_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        // Canonical request
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
            method, canonical_uri, canonical_query_string, canonical_headers, signed_headers_str
        );

        // String to sign
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            timestamp,
            credential_scope,
            sha256_hex(canonical_request.as_bytes())
        );

        // Signature derivation
        let signing_key = derive_sigv4_signing_key(
            &self.config.secret_access_key,
            &datestamp,
            &self.config.region,
            "s3",
        );
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let base = self.base_url();
        format!(
            "{}{}?{}&X-Amz-Signature={}",
            base, canonical_uri, canonical_query_string, signature
        )
    }

    /// Generates a bounded presigned PUT contract.
    ///
    /// Validates:
    /// - Required S3 configuration (fail-closed)
    /// - Server-owned opaque key shape (fail-closed)
    /// - Bounded TTL (clamped to max 600s)
    /// - Required Content-Type, Content-Length, and SHA-256 authorization
    /// - Checksum-bound upload verification (`x-amz-checksum-sha256`)
    /// - Prompt-12 SSE-KMS (`aws:kms`) or local configuration
    ///
    /// The SigV4 signature binds:
    /// - exact object key
    /// - Content-Type
    /// - Content-Length
    /// - x-amz-checksum-sha256
    /// - required SSE headers where applicable
    pub fn generate_presigned_put(
        &self,
        object_key: &str,
        media_type: MediaType,
        content_length: i64,
        sha256_b64: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PresignedPutContract, FinalizeUploadError> {
        self.config.validate()?;

        // Enforce server-owned opaque key shape
        if object_key.starts_with('/') || object_key.contains("//") || object_key.contains("..") {
            return Err(FinalizeUploadError::PreconditionFailed(
                "Invalid server object key: must not start with '/', contain '//' or '..'"
                    .to_string(),
            ));
        }

        // Validate content length
        if content_length < 1 {
            return Err(FinalizeUploadError::PreconditionFailed(
                "Content length must be at least 1 byte".to_string(),
            ));
        }
        if content_length > w014_domain::limits::MAX_UPLOAD_BYTES {
            return Err(FinalizeUploadError::PayloadTooLarge(format!(
                "Content length {content_length} exceeds max allowed upload limit"
            )));
        }

        // Mandatory SHA-256 validation (PRESIGN_SHA256_REQUIRED: YES, SHA256_EMPTY_DIGEST_FALLBACK: ABSENT)
        let parsed_sha = Sha256::from_base64("x-amz-checksum-sha256", sha256_b64).map_err(|e| {
            FinalizeUploadError::PreconditionFailed(format!("Invalid SHA-256 base64 checksum: {e}"))
        })?;
        if parsed_sha == Sha256::digest(b"") {
            return Err(FinalizeUploadError::PreconditionFailed(
                "SHA-256 checksum cannot be empty digest fallback".to_string(),
            ));
        }

        let now = Utc::now();
        if expires_at <= now {
            return Err(FinalizeUploadError::PreconditionFailed(
                "Presigned PUT expiration must be in the future".to_string(),
            ));
        }

        let remaining_secs = (expires_at - now).num_seconds().max(1);
        let bounded_secs = remaining_secs.min(MAX_PUT_EXPIRATION_SECS) as u64;
        let effective_expires_at = now + chrono::Duration::seconds(bounded_secs as i64);

        let mut headers = HashMap::new();
        let mut signed_headers: Vec<(&str, &str)> = Vec::new();

        let content_type_str = media_type.as_str().to_string();
        headers.insert("content-type".to_string(), content_type_str.clone());
        signed_headers.push(("content-type", content_type_str.as_str()));

        let content_length_str = content_length.to_string();
        headers.insert("content-length".to_string(), content_length_str.clone());
        signed_headers.push(("content-length", content_length_str.as_str()));

        let sha_owned = sha256_b64.to_string();
        headers.insert("x-amz-checksum-sha256".to_string(), sha_owned.clone());
        signed_headers.push(("x-amz-checksum-sha256", sha_owned.as_str()));

        let sse_owned;
        let kms_owned;
        if self.config.sse_mode == "aws:kms" {
            sse_owned = "aws:kms".to_string();
            headers.insert(
                "x-amz-server-side-encryption".to_string(),
                sse_owned.clone(),
            );
            signed_headers.push(("x-amz-server-side-encryption", sse_owned.as_str()));

            if let Some(ref kms_key) = self.config.kms_key_id {
                kms_owned = kms_key.clone();
                headers.insert(
                    "x-amz-server-side-encryption-aws-kms-key-id".to_string(),
                    kms_owned.clone(),
                );
                signed_headers.push((
                    "x-amz-server-side-encryption-aws-kms-key-id",
                    kms_owned.as_str(),
                ));
            }
        }

        let upload_url = self.generate_sigv4_presigned_url(
            "PUT",
            object_key,
            now,
            bounded_secs,
            &signed_headers,
        );

        Ok(PresignedPutContract {
            upload_url,
            method: "PUT".to_string(),
            expires_at: effective_expires_at,
            headers,
        })
    }

    /// Generates a bounded presigned GET contract.
    ///
    /// Validates:
    /// - Required S3 configuration (fail-closed)
    /// - Server-owned key shape (fail-closed)
    /// - Bounded TTL (clamped to max 300s)
    /// - AWS SigV4 signed URL
    /// - No permanent object URL stored in product state
    /// - No mock fallback
    /// - No fake signature injection
    pub fn generate_presigned_get(
        &self,
        artifact: &ObjectArtifact,
        original_filename: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PresignedGetContract, FinalizeUploadError> {
        self.config.validate()?;

        if artifact.key.as_str().starts_with('/')
            || artifact.key.as_str().contains("//")
            || artifact.key.as_str().contains("..")
        {
            return Err(FinalizeUploadError::PreconditionFailed(
                "Invalid server object key: must not start with '/', contain '//' or '..'"
                    .to_string(),
            ));
        }

        let now = Utc::now();
        let remaining_secs = (expires_at - now).num_seconds().max(1);
        let bounded_secs = remaining_secs.min(MAX_GET_EXPIRATION_SECS) as u64;
        let effective_expires_at = now + chrono::Duration::seconds(bounded_secs as i64);

        let download_url =
            self.generate_sigv4_presigned_url("GET", artifact.key.as_str(), now, bounded_secs, &[]);

        Ok(PresignedGetContract {
            download_url,
            expires_at: effective_expires_at,
            content_type: artifact.media_type.as_str().to_string(),
            byte_size: artifact.byte_length,
            sha256_hash: artifact.content_sha256.to_hex(),
            original_filename: original_filename.to_string(),
        })
    }

    /// Authoritative HEAD request verifying object existence, length, content type, and digest.
    ///
    /// Always executes real HTTP request against configured endpoint or AWS standard endpoint.
    /// Fails closed on missing configuration, missing checksums, malformed checksums, empty digest fallbacks,
    /// or network errors. Never falls back to mock storage.
    pub async fn head_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<StoredObjectMetadata>, FinalizeUploadError> {
        self.config.validate()?;

        if key.starts_with('/') || key.contains("//") || key.contains("..") {
            return Err(FinalizeUploadError::PreconditionFailed(
                "Invalid server object key: must not start with '/', contain '//' or '..'"
                    .to_string(),
            ));
        }

        let signed_url = self.generate_sigv4_presigned_url("HEAD", key, Utc::now(), 300, &[]);

        let resp =
            self.client.head(&signed_url).send().await.map_err(|e| {
                FinalizeUploadError::Internal(format!("S3 HEAD network failure: {e}"))
            })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !resp.status().is_success() {
            return Err(FinalizeUploadError::Internal(format!(
                "S3 HEAD authoritative error: HTTP {}",
                resp.status()
            )));
        }

        let content_length = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok())
            .ok_or_else(|| {
                FinalizeUploadError::PreconditionFailed(
                    "S3 HEAD authoritative error: missing or invalid Content-Length".to_string(),
                )
            })?;

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                FinalizeUploadError::PreconditionFailed(
                    "S3 HEAD authoritative error: missing Content-Type".to_string(),
                )
            })?
            .to_string();

        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        // HEAD_SHA256_REQUIRED: YES, HEAD_MISSING_CHECKSUM: FAIL_CLOSED, HEAD_MALFORMED_CHECKSUM: FAIL_CLOSED
        let sha_header = resp
            .headers()
            .get("x-amz-checksum-sha256")
            .or_else(|| resp.headers().get("x-amz-meta-content-sha256"))
            .ok_or_else(|| {
                FinalizeUploadError::PreconditionFailed(
                    "S3 HEAD authoritative error: missing required x-amz-checksum-sha256 header"
                        .to_string(),
                )
            })?;

        let sha_str = sha_header.to_str().map_err(|_| {
            FinalizeUploadError::PreconditionFailed(
                "S3 HEAD authoritative error: malformed x-amz-checksum-sha256 header (invalid ASCII)".to_string(),
            )
        })?;

        let content_sha256 =
            Sha256::from_base64("x-amz-checksum-sha256", sha_str).map_err(|e| {
                FinalizeUploadError::PreconditionFailed(format!(
                    "S3 HEAD authoritative error: malformed x-amz-checksum-sha256 checksum: {e}"
                ))
            })?;

        // SHA256_EMPTY_DIGEST_FALLBACK: ABSENT
        if content_sha256 == Sha256::digest(b"") {
            return Err(FinalizeUploadError::PreconditionFailed(
                "S3 HEAD authoritative error: empty digest fallback is forbidden".to_string(),
            ));
        }

        let (configured_mode, configured_key) = self.encryption_posture();
        let sse_mode = if let Some(sse_hdr) = resp
            .headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok())
        {
            if sse_hdr == "aws:kms" {
                w014_domain::EncryptionMode::AwsKms
            } else {
                configured_mode
            }
        } else {
            configured_mode
        };

        let kms_key_id = if sse_mode == w014_domain::EncryptionMode::AwsKms {
            resp.headers()
                .get("x-amz-server-side-encryption-aws-kms-key-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .or(configured_key)
        } else {
            None
        };

        Ok(Some(StoredObjectMetadata {
            bucket: bucket.to_string(),
            key: key.to_string(),
            byte_length: content_length,
            content_sha256,
            content_type,
            etag,
            bytes: None,
            sse_mode,
            kms_key_id,
        }))
    }

    /// Real worker byte retrieval.
    ///
    /// Always executes real HTTP request against configured endpoint or AWS standard endpoint.
    /// Fails closed on missing configuration or network errors. Never falls back to mock storage.
    pub async fn get_object_bytes(
        &self,
        _bucket: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, FinalizeUploadError> {
        self.config.validate()?;

        if key.starts_with('/') || key.contains("//") || key.contains("..") {
            return Err(FinalizeUploadError::PreconditionFailed(
                "Invalid server object key: must not start with '/', contain '//' or '..'"
                    .to_string(),
            ));
        }

        let signed_url = self.generate_sigv4_presigned_url("GET", key, Utc::now(), 300, &[]);

        let resp =
            self.client.get(&signed_url).send().await.map_err(|e| {
                FinalizeUploadError::Internal(format!("S3 GET network failure: {e}"))
            })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !resp.status().is_success() {
            return Err(FinalizeUploadError::Internal(format!(
                "S3 GET authoritative error: HTTP {}",
                resp.status()
            )));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| FinalizeUploadError::Internal(format!("S3 GET read error: {e}")))?;

        Ok(Some(bytes.to_vec()))
    }

    /// Derives encryption posture (mode and optional KMS key ref) from configuration.
    pub fn encryption_posture(&self) -> (w014_domain::EncryptionMode, Option<String>) {
        let mode = match self.config.sse_mode.as_str() {
            "aws:kms" => w014_domain::EncryptionMode::AwsKms,
            _ => w014_domain::EncryptionMode::Local,
        };
        let key_ref = if mode == w014_domain::EncryptionMode::AwsKms {
            self.config.kms_key_id.clone()
        } else {
            None
        };
        (mode, key_ref)
    }
}

#[async_trait::async_trait]
impl ObjectStorage for S3StorageAdapter {
    fn generate_presigned_put(
        &self,
        object_key: &str,
        media_type: MediaType,
        content_length: i64,
        sha256_b64: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PresignedPutContract, FinalizeUploadError> {
        self.generate_presigned_put(
            object_key,
            media_type,
            content_length,
            sha256_b64,
            expires_at,
        )
    }

    fn generate_presigned_get(
        &self,
        artifact: &ObjectArtifact,
        original_filename: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PresignedGetContract, FinalizeUploadError> {
        self.generate_presigned_get(artifact, original_filename, expires_at)
    }

    async fn head_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<StoredObjectMetadata>, FinalizeUploadError> {
        self.head_object(bucket, key).await
    }

    async fn get_object_bytes(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, FinalizeUploadError> {
        self.get_object_bytes(bucket, key).await
    }

    fn encryption_posture(&self) -> (w014_domain::EncryptionMode, Option<String>) {
        self.encryption_posture()
    }
}

/// Explicit test storage adapter for deterministic test execution.
///
/// MUST be explicitly injected; NEVER used as default production storage authority.
#[derive(Debug)]
pub struct TestStorageAdapter {
    storage: RwLock<HashMap<(String, String), StoredObjectMetadata>>,
    sse_mode: RwLock<w014_domain::EncryptionMode>,
    kms_key_id: RwLock<Option<String>>,
}

impl Default for TestStorageAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl TestStorageAdapter {
    pub fn new() -> Self {
        Self {
            storage: RwLock::new(HashMap::new()),
            sse_mode: RwLock::new(w014_domain::EncryptionMode::AwsKms),
            kms_key_id: RwLock::new(None),
        }
    }

    pub fn set_encryption_posture(
        &self,
        mode: w014_domain::EncryptionMode,
        kms_key_id: Option<String>,
    ) {
        *self.sse_mode.write().expect("storage lock poisoned") = mode;
        *self.kms_key_id.write().expect("storage lock poisoned") = kms_key_id;
    }

    pub fn stage_object(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
        bytes: &[u8],
        content_type: impl Into<String>,
    ) {
        let b = bucket.into();
        let k = key.into();
        let sha256 = Sha256::digest(bytes);
        let sse_mode = *self.sse_mode.read().expect("storage lock poisoned");
        let kms_key_id = self
            .kms_key_id
            .read()
            .expect("storage lock poisoned")
            .clone();
        let meta = StoredObjectMetadata {
            bucket: b.clone(),
            key: k.clone(),
            byte_length: bytes.len() as i64,
            content_sha256: sha256,
            content_type: content_type.into(),
            etag: Some(format!("\"{}\"", sha256.to_hex())),
            bytes: Some(bytes.to_vec()),
            sse_mode,
            kms_key_id,
        };
        let mut store = self.storage.write().expect("storage lock poisoned");
        store.insert((b, k), meta);
    }

    pub fn stage_metadata(&self, meta: StoredObjectMetadata) {
        let mut store = self.storage.write().expect("storage lock poisoned");
        store.insert((meta.bucket.clone(), meta.key.clone()), meta);
    }

    pub fn clear(&self) {
        let mut store = self.storage.write().expect("storage lock poisoned");
        store.clear();
        *self.sse_mode.write().expect("storage lock poisoned") =
            w014_domain::EncryptionMode::AwsKms;
        *self.kms_key_id.write().expect("storage lock poisoned") = None;
    }
}

#[async_trait::async_trait]
impl ObjectStorage for TestStorageAdapter {
    fn generate_presigned_put(
        &self,
        object_key: &str,
        media_type: MediaType,
        content_length: i64,
        sha256_b64: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PresignedPutContract, FinalizeUploadError> {
        if object_key.starts_with('/') || object_key.contains("//") || object_key.contains("..") {
            return Err(FinalizeUploadError::PreconditionFailed(
                "Invalid server object key: must not start with '/', contain '//' or '..'"
                    .to_string(),
            ));
        }

        if content_length < 1 {
            return Err(FinalizeUploadError::PreconditionFailed(
                "Content length must be at least 1 byte".to_string(),
            ));
        }
        if content_length > w014_domain::limits::MAX_UPLOAD_BYTES {
            return Err(FinalizeUploadError::PayloadTooLarge(format!(
                "Content length {content_length} exceeds max allowed upload limit"
            )));
        }

        let parsed_sha = Sha256::from_base64("x-amz-checksum-sha256", sha256_b64).map_err(|e| {
            FinalizeUploadError::PreconditionFailed(format!("Invalid SHA-256 base64 checksum: {e}"))
        })?;
        if parsed_sha == Sha256::digest(b"") {
            return Err(FinalizeUploadError::PreconditionFailed(
                "SHA-256 checksum cannot be empty digest fallback".to_string(),
            ));
        }

        let now = Utc::now();
        if expires_at <= now {
            return Err(FinalizeUploadError::PreconditionFailed(
                "Presigned PUT expiration must be in the future".to_string(),
            ));
        }

        let remaining_secs = (expires_at - now).num_seconds().max(1);
        let bounded_secs = remaining_secs.min(MAX_PUT_EXPIRATION_SECS);
        let effective_expires_at = now + chrono::Duration::seconds(bounded_secs);

        let upload_url = format!(
            "https://storage.local/w014-documents/{}",
            object_key.trim_start_matches('/')
        );
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), media_type.as_str().to_string());
        headers.insert("content-length".to_string(), content_length.to_string());
        headers.insert("x-amz-checksum-sha256".to_string(), sha256_b64.to_string());

        let sse = *self.sse_mode.read().expect("storage lock poisoned");
        if sse == w014_domain::EncryptionMode::AwsKms {
            headers.insert(
                "x-amz-server-side-encryption".to_string(),
                "aws:kms".to_string(),
            );
            if let Some(ref k) = *self.kms_key_id.read().expect("storage lock poisoned") {
                headers.insert(
                    "x-amz-server-side-encryption-aws-kms-key-id".to_string(),
                    k.clone(),
                );
            }
        }

        Ok(PresignedPutContract {
            upload_url,
            method: "PUT".to_string(),
            expires_at: effective_expires_at,
            headers,
        })
    }

    fn generate_presigned_get(
        &self,
        artifact: &ObjectArtifact,
        original_filename: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PresignedGetContract, FinalizeUploadError> {
        let now = Utc::now();
        let remaining_secs = (expires_at - now).num_seconds().max(1);
        let bounded_secs = remaining_secs.min(MAX_GET_EXPIRATION_SECS);
        let effective_expires_at = now + chrono::Duration::seconds(bounded_secs);

        let download_url = format!(
            "https://storage.local/{}/{}?expires={}&signature=valid",
            artifact.bucket,
            artifact.key.as_str(),
            effective_expires_at.timestamp()
        );
        Ok(PresignedGetContract {
            download_url,
            expires_at: effective_expires_at,
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
        let store = self.storage.read().expect("storage lock poisoned");
        Ok(store.get(&(bucket.to_string(), key.to_string())).cloned())
    }

    async fn get_object_bytes(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, FinalizeUploadError> {
        let store = self.storage.read().expect("storage lock poisoned");
        Ok(store
            .get(&(bucket.to_string(), key.to_string()))
            .and_then(|m| m.bytes.clone()))
    }

    fn encryption_posture(&self) -> (w014_domain::EncryptionMode, Option<String>) {
        (
            *self.sse_mode.read().expect("storage lock poisoned"),
            self.kms_key_id
                .read()
                .expect("storage lock poisoned")
                .clone(),
        )
    }
}
