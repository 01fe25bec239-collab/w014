//! Application service orchestrating Document Pipeline domain operations.
//!
//! Enforces:
//! - Workspace scoping and tenant boundary isolation
//! - Capability authorization (DOCUMENT_READ, DOCUMENT_UPLOAD, DOCUMENT_MANAGE)
//! - Immutable versioning and optimistic concurrency (If-Match / row_version)
//! - Atomic AcceptVersion transaction (document pointer, audit, dependency key, change event, durable job, idempotency)
//! - Bounded upload intent and presigned URL generation (server-owned opaque object key, max TTLs)
//! - Download signing for immutable object artifacts (max 5 minutes TTL)

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
use w014_authz::authorized_workspace_context::AuthorizedWorkspaceContext;
use w014_authz::capability::Capability;
use w014_domain::ids::{DocumentVersionId, PrincipalId, UploadIntentId};
use w014_domain::{
    Document, DocumentClass, DocumentVersion, IntentStatus, MediaType, ObjectArtifact,
    QuarantineRecord, Sha256, UploadIntent,
};
use w014_jobs::job_identity::CanonicalJobIdentity;
use w014_jobs::kind::JobKind;
use w014_jobs::payload::JobPayload;
use w014_jobs::{FROZEN_BACKOFF_MAX_SECS, FROZEN_MAX_ATTEMPTS};
use w014_persistence::audit::{AppendAuditParams, AuditAppendContract, PostgresAuditStore};
use w014_persistence::error::PersistenceError;

use crate::error::ApplicationError;
use crate::persistence::{
    ChangeEventRepository, DependencyKeyRepository, DocumentRepository, DocumentVersionRepository,
    ObjectArtifactRepository, UploadIntentRepository,
};
use crate::services::IdempotencyCoordinator;
use crate::services::storage::{ObjectStorage, S3StorageAdapter, TestStorageAdapter};

/// Maximum presigned GET download URL lifetime: 5 minutes (300s).
pub const MAX_DOWNLOAD_TTL_SECS: i64 = 300;

/// Maximum attempt budget for malware scanning: 2 attempts (initial scan + exactly 1 retry).
pub const MALWARE_SCAN_MAX_ATTEMPTS: i32 = 2;

/// Explicitly injected storage authority (test-only override).
static INJECTED_STORAGE: RwLock<Option<Arc<dyn ObjectStorage>>> = RwLock::new(None);

/// Process-local test storage instance for deterministic test execution.
static TEST_STORAGE_INSTANCE: LazyLock<Arc<TestStorageAdapter>> =
    LazyLock::new(|| Arc::new(TestStorageAdapter::new()));

/// Authoritative object metadata returned by object storage HEAD queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredObjectMetadata {
    pub bucket: String,
    pub key: String,
    pub byte_length: i64,
    pub content_sha256: Sha256,
    pub content_type: String,
    pub etag: Option<String>,
    #[serde(skip)]
    pub bytes: Option<Vec<u8>>,
    pub sse_mode: w014_domain::EncryptionMode,
    pub kms_key_id: Option<String>,
}

/// Output bundle returned by authoritative upload finalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadFinalizeResult {
    pub intent: UploadIntent,
    pub document: Document,
    pub version: DocumentVersion,
    pub artifact: ObjectArtifact,
    pub quarantine: QuarantineRecord,
    pub job_id: Uuid,
}

/// Error type specific to the UploadFinalize workflow.
#[derive(Debug, thiserror::Error)]
pub enum FinalizeUploadError {
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Precondition failed: {0}")]
    PreconditionFailed(String),
    #[error("Unprocessable entity: {0}")]
    UnprocessableEntity(String),
    #[error("Unsupported media type: {0}")]
    UnsupportedMediaType(String),
    #[error("Payload too large: {0}")]
    PayloadTooLarge(String),
    #[error("Domain error: {0}")]
    Domain(#[from] w014_domain::error::DomainError),
    #[error("Persistence error: {0}")]
    Persistence(#[from] PersistenceError),
    #[error("Application error: {0}")]
    Application(#[from] ApplicationError),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<sqlx::Error> for FinalizeUploadError {
    fn from(err: sqlx::Error) -> Self {
        Self::Persistence(PersistenceError::Connection(err))
    }
}

/// Presigned PUT contract returned to the client for uploading bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresignedPutContract {
    pub upload_url: String,
    pub method: String,
    pub expires_at: DateTime<Utc>,
    pub headers: HashMap<String, String>,
}

/// Presigned GET download contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresignedGetContract {
    pub download_url: String,
    pub expires_at: DateTime<Utc>,
    pub content_type: String,
    pub byte_size: i64,
    pub sha256_hash: String,
    pub original_filename: String,
}

/// Checks whether the caller context has DOCUMENT_READ permission.
pub fn can_read_documents(awc: &AuthorizedWorkspaceContext) -> bool {
    awc.can_read_workspace() || awc.can(&Capability::Named("DOCUMENT_READ".to_string()))
}

/// Checks whether the caller context has DOCUMENT_UPLOAD permission.
pub fn can_upload_documents(awc: &AuthorizedWorkspaceContext) -> bool {
    awc.can_write_workspace() || awc.can(&Capability::Named("DOCUMENT_UPLOAD".to_string()))
}

/// Checks whether the caller context has DOCUMENT_MANAGE permission.
pub fn can_manage_documents(awc: &AuthorizedWorkspaceContext) -> bool {
    awc.can_admin_workspace() || awc.can(&Capability::Named("DOCUMENT_MANAGE".to_string()))
}

/// Service orchestrating Document Registry and Presign API domain operations.
pub struct DocumentService;

impl DocumentService {
    /// Generates a bounded presigned PUT contract for an opaque object key, propagating any error.
    pub fn try_generate_presigned_put(
        _bucket: &str,
        object_key: &str,
        media_type: MediaType,
        content_length: i64,
        sha256_b64: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PresignedPutContract, FinalizeUploadError> {
        Self::current_storage().generate_presigned_put(
            object_key,
            media_type,
            content_length,
            sha256_b64,
            expires_at,
        )
    }

    /// Generates a bounded presigned PUT contract for an opaque object key.
    ///
    /// Fails closed if presigning fails for any reason; NEVER produces an unsigned URL.
    pub fn generate_presigned_put(
        bucket: &str,
        object_key: &str,
        media_type: MediaType,
        content_length: i64,
        sha256_b64: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PresignedPutContract, FinalizeUploadError> {
        Self::try_generate_presigned_put(
            bucket,
            object_key,
            media_type,
            content_length,
            sha256_b64,
            expires_at,
        )
    }

    /// Generates a bounded presigned GET contract for an immutable object artifact.
    pub fn generate_presigned_get(
        artifact: &ObjectArtifact,
        original_filename: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PresignedGetContract, FinalizeUploadError> {
        Self::current_storage().generate_presigned_get(artifact, original_filename, expires_at)
    }

    /// Atomic AcceptVersion transaction execution.
    ///
    /// Atomically performs:
    /// 1. Fetch and lock document FOR UPDATE
    /// 2. Fetch and validate version
    /// 3. Verify optimistic concurrency (expected_row_version == document.row_version)
    /// 4. Update documents.current_version_id and advance row_version
    /// 5. Append authoritative audit event
    /// 6. Resolve/create canonical DependencyKey
    /// 7. Append ChangeEvent
    /// 8. Enqueue follow-on durable parse job in PostgreSQL jobs queue
    /// 9. Record idempotency completion if record_id provided
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_accept_version_tx(
        tx: &mut PgConnection,
        awc: &AuthorizedWorkspaceContext,
        principal_id: PrincipalId,
        version_id: DocumentVersionId,
        expected_row_version: i32,
        now: DateTime<Utc>,
        idemp_record_id: Option<Uuid>,
        idemp_store: &impl w014_persistence::idempotency::IdempotencyStore,
    ) -> Result<Document, ApplicationError> {
        // 1. Fetch immutable version
        let version = DocumentVersionRepository::get_by_id(tx, awc.workspace_id(), version_id)
            .await?
            .ok_or_else(|| {
                ApplicationError::NotFound(format!("DocumentVersion '{}' not found", version_id))
            })?;

        // 2. Fetch and lock target logical document FOR UPDATE
        let mut document =
            DocumentRepository::get_by_id_for_update(tx, awc.workspace_id(), version.document_id)
                .await?
                .ok_or_else(|| {
                    ApplicationError::NotFound(format!(
                        "Document '{}' not found",
                        version.document_id
                    ))
                })?;

        // 3. Verify document row_version matches If-Match precondition
        if document.row_version != expected_row_version {
            return Err(ApplicationError::Conflict(format!(
                "Document row_version conflict: expected {}, current is {}",
                expected_row_version, document.row_version
            )));
        }

        // 4. Update current_version_id and advance row_version
        let updated = DocumentRepository::update_current_version(
            tx,
            awc.workspace_id(),
            document.id,
            version.id,
            expected_row_version,
            now,
        )
        .await?;

        if !updated {
            return Err(ApplicationError::Conflict(format!(
                "Document row_version conflict: update affected 0 rows (expected version {})",
                expected_row_version
            )));
        }

        let new_row_version = expected_row_version + 1;
        document.current_version_id = Some(version.id);
        document.row_version = new_row_version;
        document.updated_at = now;

        // 5. Append authoritative audit event
        let audit_store = PostgresAuditStore::new();
        let audit_payload = serde_json::json!({
            "document_id": document.id.to_string(),
            "version_id": version.id.to_string(),
            "workspace_id": awc.workspace_id().to_string(),
            "version_number": version.version_ordinal.get(),
            "row_version": new_row_version,
        });

        let audit_params = AppendAuditParams {
            workspace_id: awc.workspace_id().into_uuid(),
            actor_type: "principal".to_string(),
            actor_id: Some(principal_id.into_uuid()),
            authority_snapshot: serde_json::json!({}),
            action_code: "ACCEPT_VERSION".to_string(),
            entity_type: "document".to_string(),
            entity_id: document.id.to_string(),
            entity_version: Some(new_row_version),
            request_id: None,
            correlation_id: None,
            job_id: None,
            source_state_hash: None,
            before_ref: document
                .current_version_id
                .map(|v| serde_json::json!(v.to_string())),
            after_ref: Some(serde_json::json!(version.id.to_string())),
            metadata: audit_payload,
        };

        audit_store
            .append_audit_event(tx, audit_params)
            .await
            .map_err(|e| PersistenceError::Operation(format!("Audit append failed: {e}")))?;

        // 6. Write or reuse canonical DependencyKey
        let dep_key_val = format!("{}:{}", document.id, version.id);
        let dep_key_id = DependencyKeyRepository::get_or_create(
            tx,
            awc.workspace_id(),
            "document",
            &dep_key_val,
        )
        .await?;

        // 7. Append ChangeEvent
        let change_payload = serde_json::json!({
            "document_id": document.id.to_string(),
            "version_id": version.id.to_string(),
            "version_number": version.version_ordinal.get(),
            "object_artifact_id": version.object_artifact_id.to_string(),
        });

        ChangeEventRepository::append(
            tx,
            awc.workspace_id(),
            Some(dep_key_id),
            "DOCUMENT_VERSION_ACCEPTED",
            "document",
            &document.id.to_string(),
            change_payload,
            now,
        )
        .await?;

        // 8. Enqueue follow-on durable parse job in PostgreSQL jobs queue
        let job_kind = match document.document_class {
            DocumentClass::Pdf => JobKind::ParseDocumentPdf,
            DocumentClass::Docx => JobKind::ParseDocumentDocxOcr,
        };

        let immutable_targets = vec![version.id.to_string()];
        let envelope = JobPayload::validate(&serde_json::json!({
            "payload_contract_version": 1,
            "producer_version": "w014-document-pipeline",
            "immutable_targets": immutable_targets.clone(),
            "dependency_hash": null,
            "parameters": {},
        }))
        .map_err(|e| ApplicationError::Internal(format!("Failed to build job payload: {e}")))?;

        let identity = CanonicalJobIdentity::new(
            job_kind.as_str(),
            awc.workspace_id().into_uuid(),
            immutable_targets,
            None,
            1,
            "w014-document-pipeline",
        );
        let idempotency_key = identity.idempotency_key();
        let payload_json = envelope.to_json();

        let inserted = sqlx::query(
            "INSERT INTO jobs \
             (workspace_id, queue_name, job_type, status, priority, payload, \
              idempotency_key, correlation_id, max_attempts, backoff_max_secs) \
             VALUES ($1, $2, $3, 'requested', 0, $4, $5, NULL, $6, $7) \
             ON CONFLICT (idempotency_key) DO NOTHING \
             RETURNING job_id",
        )
        .bind(awc.workspace_id().as_uuid())
        .bind(job_kind.default_queue())
        .bind(job_kind.as_str())
        .bind(&payload_json)
        .bind(&idempotency_key)
        .bind(FROZEN_MAX_ATTEMPTS)
        .bind(FROZEN_BACKOFF_MAX_SECS)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        if let Some(row) = inserted {
            let new_job_id: Uuid = row.get("job_id");
            sqlx::query(
                "UPDATE jobs SET status = 'queued', not_before = clock_timestamp(), \
                 row_version = row_version + 1 \
                 WHERE job_id = $1 AND status = 'requested'",
            )
            .bind(new_job_id)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;
        }

        // 9. Record idempotency completion if required
        if let Some(record_id) = idemp_record_id {
            let resp_body = serde_json::to_value(&document).ok();
            IdempotencyCoordinator::complete_record(tx, idemp_store, record_id, 200, resp_body)
                .await?;
        }

        Ok(document)
    }

    /// Stages an object into the mock storage registry for testing and deterministic verification.
    ///
    /// Explicitly activates test storage authority for deterministic test execution.
    pub fn stage_mock_upload(
        bucket: impl Into<String>,
        key: impl Into<String>,
        byte_length: i64,
        content_sha256: Sha256,
        content_type: impl Into<String>,
    ) {
        let b = bucket.into();
        let k = key.into();
        let ct = content_type.into();
        let (sse_mode, kms_key_id) = TEST_STORAGE_INSTANCE.encryption_posture();
        let meta = StoredObjectMetadata {
            bucket: b,
            key: k,
            byte_length,
            content_sha256,
            content_type: ct,
            etag: Some(format!("\"{}\"", content_sha256.to_hex())),
            bytes: None,
            sse_mode,
            kms_key_id,
        };
        TEST_STORAGE_INSTANCE.stage_metadata(meta);
        let mut w = INJECTED_STORAGE.write().expect("storage lock poisoned");
        *w = Some(TEST_STORAGE_INSTANCE.clone());
    }

    /// Configures the encryption posture on the process-local test storage adapter.
    pub fn set_test_storage_encryption_posture(
        mode: w014_domain::EncryptionMode,
        kms_key_id: Option<String>,
    ) {
        TEST_STORAGE_INSTANCE.set_encryption_posture(mode, kms_key_id);
    }

    /// Stages raw bytes into mock storage, computing SHA-256 and byte length automatically.
    ///
    /// Explicitly activates test storage authority for deterministic test execution.
    pub fn stage_mock_upload_bytes(
        bucket: impl Into<String>,
        key: impl Into<String>,
        bytes: &[u8],
        content_type: impl Into<String>,
    ) {
        TEST_STORAGE_INSTANCE.stage_object(bucket, key, bytes, content_type);
        let mut w = INJECTED_STORAGE.write().expect("storage lock poisoned");
        *w = Some(TEST_STORAGE_INSTANCE.clone());
    }

    /// Clears the mock storage registry and resets to production S3 storage authority.
    pub fn clear_mock_storage() {
        TEST_STORAGE_INSTANCE.clear();
        let mut w = INJECTED_STORAGE.write().expect("storage lock poisoned");
        *w = None;
    }

    /// Explicitly injects a custom storage authority (e.g. for testing).
    pub fn inject_storage(storage: Arc<dyn ObjectStorage>) {
        let mut w = INJECTED_STORAGE.write().expect("storage lock poisoned");
        *w = Some(storage);
    }

    /// Clears any explicitly injected storage, restoring default production S3 storage.
    pub fn clear_injected_storage() {
        let mut w = INJECTED_STORAGE.write().expect("storage lock poisoned");
        *w = None;
    }

    /// Returns true if an explicit test storage adapter is currently active.
    pub fn is_test_storage_active() -> bool {
        INJECTED_STORAGE
            .read()
            .expect("storage lock poisoned")
            .is_some()
    }

    /// Ensures test storage authority is active (used by legacy test fixtures).
    pub fn ensure_test_storage_injected() {
        let mut w = INJECTED_STORAGE.write().expect("storage lock poisoned");
        if w.is_none() {
            *w = Some(TEST_STORAGE_INSTANCE.clone());
        }
    }

    /// Returns the currently active storage authority (defaulting to production S3 adapter).
    pub fn current_storage() -> Arc<dyn ObjectStorage> {
        let r = INJECTED_STORAGE.read().expect("storage lock poisoned");
        if let Some(ref s) = *r {
            return s.clone();
        }
        Arc::new(S3StorageAdapter::default_adapter().clone())
    }

    /// Performs an authoritative HEAD query against the storage provider.
    pub async fn head_object(
        bucket: &str,
        key: &str,
    ) -> Result<Option<StoredObjectMetadata>, FinalizeUploadError> {
        Self::current_storage().head_object(bucket, key).await
    }

    /// Performs an authoritative byte retrieval query against the storage provider.
    pub async fn get_object_bytes(
        bucket: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, FinalizeUploadError> {
        Self::current_storage().get_object_bytes(bucket, key).await
    }

    /// Atomic UploadFinalize transaction execution (Prompt-16R / WI-0203).
    ///
    /// Atomically performs in ONE authoritative transaction:
    /// 1. Fetch and lock upload_intent FOR UPDATE
    /// 2. Verify workspace ownership, expiry, terminal status
    /// 3. HEAD authoritative storage using ONLY the server-owned opaque key
    /// 4. Verify exact byte length, SHA-256 digest, and Content-Type
    /// 5. Persist immutable ObjectArtifact fact
    /// 6. Persist immutable DocumentVersion fact (trust_state: pending)
    /// 7. Persist immutable QuarantineRecord fact (status: pending)
    /// 8. Consume / finalize upload_intent (status: verified, finalized_at: now)
    /// 9. Append authoritative audit event
    /// 10. Enqueue real durable malware-scan job in PostgreSQL jobs queue
    /// 11. Complete idempotency record
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_finalize_upload_tx(
        tx: &mut PgConnection,
        awc: &AuthorizedWorkspaceContext,
        principal_id: PrincipalId,
        intent_id: UploadIntentId,
        now: DateTime<Utc>,
        idemp_record_id: Option<Uuid>,
        idemp_store: &impl w014_persistence::idempotency::IdempotencyStore,
    ) -> Result<UploadFinalizeResult, FinalizeUploadError> {
        // 1. Fetch and lock upload_intent FOR UPDATE
        let mut intent =
            UploadIntentRepository::get_by_id_for_update(tx, awc.workspace_id(), intent_id)
                .await?
                .ok_or_else(|| {
                    FinalizeUploadError::NotFound(format!("UploadIntent '{}' not found", intent_id))
                })?;

        // 2. Validate status and expiry
        if intent.status == IntentStatus::Verified {
            return Err(FinalizeUploadError::Conflict(format!(
                "UploadIntent '{}' has already been finalized",
                intent_id
            )));
        }
        if intent.status == IntentStatus::Aborted {
            return Err(FinalizeUploadError::Conflict(format!(
                "UploadIntent '{}' has been abandoned",
                intent_id
            )));
        }
        if intent.status == IntentStatus::Expired || intent.is_expired_at(now) {
            return Err(FinalizeUploadError::PreconditionFailed(format!(
                "UploadIntent '{}' has expired",
                intent_id
            )));
        }
        if intent.status != IntentStatus::Initiated && intent.status != IntentStatus::Uploaded {
            return Err(FinalizeUploadError::PreconditionFailed(format!(
                "UploadIntent '{}' is in invalid status '{}'",
                intent_id,
                intent.status.as_str()
            )));
        }

        // 3. Storage HEAD verification (server-owned opaque key ONLY)
        let bucket = "w014-documents";
        let object_key = intent.opaque_object_key.as_str();

        let head_meta = Self::head_object(bucket, object_key).await?.ok_or_else(|| {
            FinalizeUploadError::PreconditionFailed(format!(
                "Uploaded object not found in storage: PUT was not completed for key '{object_key}'"
            ))
        })?;

        // Verify exact byte length matches declared expected_length
        if head_meta.byte_length != intent.expected_length {
            return Err(FinalizeUploadError::UnprocessableEntity(format!(
                "Object byte length mismatch: expected {}, got {}",
                intent.expected_length, head_meta.byte_length
            )));
        }

        // Enforce 1..100 MiB limits
        if head_meta.byte_length < 1 {
            return Err(FinalizeUploadError::UnprocessableEntity(
                "Uploaded object length must be at least 1 byte".to_string(),
            ));
        }
        if head_meta.byte_length > w014_domain::limits::MAX_UPLOAD_BYTES {
            return Err(FinalizeUploadError::PayloadTooLarge(format!(
                "Uploaded object size {} exceeds 100 MiB limit",
                head_meta.byte_length
            )));
        }

        // Mandatory SHA-256 verification (FINALIZE_WITHOUT_EXPECTED_CHECKSUM: IMPOSSIBLE)
        let declared_sha = intent.expected_sha256_b64.as_ref().ok_or_else(|| {
            FinalizeUploadError::PreconditionFailed(
                "UploadIntent missing mandatory expected SHA-256 checksum: finalize impossible"
                    .to_string(),
            )
        })?;

        if &head_meta.content_sha256 != declared_sha {
            return Err(FinalizeUploadError::UnprocessableEntity(format!(
                "Object SHA-256 checksum mismatch: declared '{}', actual '{}'",
                declared_sha.to_base64(),
                head_meta.content_sha256.to_base64()
            )));
        }

        // SHA256_EMPTY_DIGEST_FALLBACK: ABSENT
        if head_meta.content_sha256 == Sha256::digest(b"") {
            return Err(FinalizeUploadError::PreconditionFailed(
                "Uploaded object SHA-256 digest cannot be empty digest fallback".to_string(),
            ));
        }

        // Verify conservative Content-Type matches expected media type
        let expected_mime = intent.expected_media_type.as_str();
        if head_meta.content_type.trim().to_lowercase() != expected_mime.to_lowercase() {
            return Err(FinalizeUploadError::UnsupportedMediaType(format!(
                "Object Content-Type mismatch: expected '{expected_mime}', got '{}'",
                head_meta.content_type
            )));
        }

        let stored_media_type = w014_domain::StoredMediaType::new(expected_mime)
            .map_err(|e| FinalizeUploadError::UnsupportedMediaType(e.to_string()))?;

        // 4. Persist immutable ObjectArtifact fact derived directly from actual storage authority
        let artifact = ObjectArtifact::reconstruct(
            w014_domain::ids::ObjectArtifactId::new(),
            awc.workspace_id(),
            w014_domain::ArtifactKind::RawUpload,
            bucket.to_string(),
            intent.opaque_object_key.clone(),
            head_meta.content_sha256,
            head_meta.byte_length,
            stored_media_type,
            w014_domain::StorageTier::Hot,
            head_meta.sse_mode,
            head_meta.kms_key_id,
            now,
        )?;
        ObjectArtifactRepository::insert(tx, &artifact).await?;

        // 5. Persist immutable DocumentVersion fact & preserve Document relationship
        let (document, next_version_ordinal) = if let Some(doc_id) = intent.document_id {
            let doc = DocumentRepository::get_by_id(tx, awc.workspace_id(), doc_id)
                .await?
                .ok_or_else(|| {
                    FinalizeUploadError::NotFound(format!("Target Document '{}' not found", doc_id))
                })?;
            let next_ver =
                DocumentVersionRepository::get_next_version_number(tx, awc.workspace_id(), doc_id)
                    .await?;
            let ordinal = w014_domain::VersionOrdinal::new(next_ver)?;
            (doc, ordinal)
        } else {
            let doc_class = match intent.expected_media_type {
                MediaType::ApplicationPdf => DocumentClass::Pdf,
                MediaType::Docx => DocumentClass::Docx,
            };
            let doc = Document::new(
                awc.workspace_id(),
                &intent.filename,
                doc_class,
                Some(principal_id),
            )?;
            DocumentRepository::insert(tx, &doc).await?;
            let ordinal = w014_domain::VersionOrdinal::new(1)?;
            (doc, ordinal)
        };

        let version = DocumentVersion::new(
            &document,
            next_version_ordinal,
            artifact.id,
            artifact.byte_length,
            artifact.content_sha256,
            &intent.filename,
            Some(principal_id),
        )?;
        DocumentVersionRepository::insert(tx, &version).await?;

        // 6. Establish in-memory quarantine representation (pending scan)
        // Note: In accordance with M002R schema constraints (uq_quarantine_records_upload_intent UNIQUE
        // and fn_enforce_quarantine_records_insert_only), the immutable scan verdict record is inserted
        // atomically when the scanner runs (Clean/Malware/IntegrityFailed). We do not insert a premature
        // row that would violate the unique constraint on upload_intent_id upon scan completion.
        let quarantine = QuarantineRecord::from_outcome(
            awc.workspace_id(),
            intent.id,
            w014_domain::QuarantineStatus::Pending,
            "pipeline-intake",
            None,
            now,
        )?;

        // 7. Consume / finalize upload_intent
        if intent.status == IntentStatus::Initiated {
            intent.mark_uploaded()?;
        }
        intent.bind_object_artifact(artifact.id, awc.workspace_id())?;
        intent.finalize_verified(now)?;
        let finalized = UploadIntentRepository::finalize_intent(
            tx,
            awc.workspace_id(),
            intent.id,
            artifact.id,
            now,
        )
        .await?;
        if !finalized {
            return Err(FinalizeUploadError::Conflict(format!(
                "Failed to finalize upload intent '{}': already finalized or concurrently modified",
                intent_id
            )));
        }

        // 8. Append authoritative audit event in the same transaction
        let audit_store = PostgresAuditStore::new();
        let audit_params = AppendAuditParams {
            workspace_id: awc.workspace_id().into_uuid(),
            actor_type: "principal".to_string(),
            actor_id: Some(principal_id.into_uuid()),
            authority_snapshot: serde_json::json!({}),
            action_code: "UPLOAD_FINALIZE".to_string(),
            entity_type: "upload_intent".to_string(),
            entity_id: intent.id.to_string(),
            entity_version: Some(1),
            request_id: None,
            correlation_id: None,
            job_id: None,
            source_state_hash: None,
            before_ref: Some(serde_json::json!({ "status": "initiated" })),
            after_ref: Some(serde_json::json!({
                "status": "verified",
                "document_version_id": version.id.to_string(),
                "object_artifact_id": artifact.id.to_string(),
            })),
            metadata: serde_json::json!({
                "upload_intent_id": intent.id.to_string(),
                "document_id": document.id.to_string(),
                "document_version_id": version.id.to_string(),
                "object_artifact_id": artifact.id.to_string(),
                "quarantine_record_id": quarantine.id.to_string(),
                "byte_length": artifact.byte_length,
                "sha256_hash": artifact.content_sha256.to_hex(),
                "media_type": artifact.media_type.as_str(),
            }),
        };
        audit_store
            .append_audit_event(tx, audit_params)
            .await
            .map_err(|e| PersistenceError::Operation(format!("Audit append failed: {e}")))?;

        // 9. Enqueue required REAL durable malware-scan job in PostgreSQL jobs queue
        let job_kind = match intent.expected_media_type {
            MediaType::ApplicationPdf => JobKind::MalwareScanDocumentPdf,
            MediaType::Docx => JobKind::MalwareScanDocumentDocxOcr,
        };

        let immutable_targets = vec![version.id.to_string()];
        let envelope = JobPayload::validate(&serde_json::json!({
            "payload_contract_version": 1,
            "producer_version": "w014-document-pipeline",
            "immutable_targets": immutable_targets.clone(),
            "dependency_hash": null,
            "parameters": {
                "upload_intent_id": intent.id.to_string(),
                "object_artifact_id": artifact.id.to_string(),
                "document_version_id": version.id.to_string(),
            },
        }))
        .map_err(|e| FinalizeUploadError::Internal(format!("Failed to build job payload: {e}")))?;

        let identity = CanonicalJobIdentity::new(
            job_kind.as_str(),
            awc.workspace_id().into_uuid(),
            immutable_targets,
            None,
            1,
            "w014-document-pipeline",
        );
        let idempotency_key = identity.idempotency_key();
        let payload_json = envelope.to_json();

        let inserted = sqlx::query(
            "INSERT INTO jobs \
             (workspace_id, queue_name, job_type, status, priority, payload, \
              idempotency_key, correlation_id, max_attempts, backoff_max_secs) \
             VALUES ($1, $2, $3, 'requested', 0, $4, $5, NULL, $6, $7) \
             ON CONFLICT (idempotency_key) DO NOTHING \
             RETURNING job_id",
        )
        .bind(awc.workspace_id().as_uuid())
        .bind(job_kind.default_queue())
        .bind(job_kind.as_str())
        .bind(&payload_json)
        .bind(&idempotency_key)
        .bind(MALWARE_SCAN_MAX_ATTEMPTS)
        .bind(FROZEN_BACKOFF_MAX_SECS)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let job_id: Uuid = if let Some(row) = inserted {
            let new_job_id: Uuid = row.get("job_id");
            sqlx::query(
                "UPDATE jobs SET status = 'queued', not_before = clock_timestamp(), \
                 row_version = row_version + 1 \
                 WHERE job_id = $1 AND status = 'requested'",
            )
            .bind(new_job_id)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;
            new_job_id
        } else {
            let row = sqlx::query("SELECT job_id FROM jobs WHERE idempotency_key = $1")
                .bind(&idempotency_key)
                .fetch_one(&mut *tx)
                .await
                .map_err(PersistenceError::Connection)?;
            row.get("job_id")
        };

        // 10. Complete idempotency record if record_id was provided
        let finalize_res = UploadFinalizeResult {
            intent,
            document,
            version,
            artifact,
            quarantine,
            job_id,
        };

        if let Some(record_id) = idemp_record_id {
            let resp_body = serde_json::json!({
                "upload_intent_id": finalize_res.intent.id.to_string(),
                "document_id": finalize_res.document.id.to_string(),
                "document_version_id": finalize_res.version.id.to_string(),
                "version_number": finalize_res.version.version_ordinal.get(),
                "object_artifact_id": finalize_res.artifact.id.to_string(),
                "quarantine_record_id": finalize_res.quarantine.id.to_string(),
                "scan_job_id": finalize_res.job_id.to_string(),
                "status": "quarantined_processing",
                "trust_state": finalize_res.version.trust_state.as_str(),
            });
            IdempotencyCoordinator::complete_record(
                tx,
                idemp_store,
                record_id,
                202,
                Some(resp_body),
            )
            .await?;
        }

        Ok(finalize_res)
    }
}
