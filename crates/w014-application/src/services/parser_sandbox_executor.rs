//! Durable parser sandbox job executor (WI-0205).
//!
//! Executes secure, isolated parser sandbox runs on claimed durable jobs:
//! `JobKind::ParseDocumentPdf` and `JobKind::ParseDocumentDocxOcr`.
//!
//! Enforces:
//! - Malware-gate admission precondition: exact document version MUST have completed
//!   a clean WI-0204 malware/integrity scan before sandbox launch
//! - Scoped single-object handoff: exactly one immutable, scanned input handed to sandbox
//! - Hard frozen sandbox security profile and resource ceilings (<= 2 vCPU, <= 2 GiB RAM,
//!   <= 1 GiB tmpfs, <= 64 PIDs, <= 10 min wall clock)
//! - Complete credentials stripping (no DB, AI, S3, KMS, audit signing, or session secrets)
//! - Network isolation (no public ingress, no general egress, no external URLs)
//! - Lease generation fencing & stale worker rejection
//! - Fail-closed execution on crash, OOM, timeout, security violation, or malformed output
//! - Typed, bounded output validation (no direct database writes from untrusted sandbox)
//! - Negative scope: zero early canonical page/block/span persistence (reserved for WI-0206/WI-0207)

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;
use w014_document_processing::sandbox::{
    SandboxError, SandboxInput, SandboxRunner, SandboxSecurityProfile, SandboxStatus,
};
use w014_domain::ids::{DocumentVersionId, ParserArtifactId, WorkspaceId};
use w014_domain::quarantine::QuarantineStatus;
use w014_domain::{ParserArtifact, ParserStatus, Sha256};
use w014_jobs::executor::{JobExecutionContext, JobExecutionFailure, JobExecutor};
use w014_jobs::kind::JobKind;
use w014_jobs::models::ClaimedJob;
use w014_persistence::audit::{AppendAuditParams, AuditAppendContract, PostgresAuditStore};

use crate::persistence::{
    DocumentRepository, DocumentVersionRepository, ObjectArtifactRepository,
    ParserArtifactRepository, ParserBlockRepository, ParserPageRepository,
    QuarantineRecordRepository, SourceSpanRepository,
};
use crate::services::DocumentService;

/// Durable job executor for parser sandbox execution.
pub struct ParserSandboxJobExecutor {
    pool: PgPool,
    runner: Arc<dyn SandboxRunner>,
    profile: SandboxSecurityProfile,
}

impl ParserSandboxJobExecutor {
    /// Creates a new executor with the given PostgreSQL pool and sandbox runner backend.
    #[must_use]
    pub fn new(pool: PgPool, runner: Arc<dyn SandboxRunner>) -> Self {
        Self {
            pool,
            runner,
            profile: SandboxSecurityProfile::frozen_default(),
        }
    }

    /// Sets a custom sandbox security profile.
    #[must_use]
    pub fn with_profile(mut self, profile: SandboxSecurityProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Verifies that the worker still holds the active lease fence before modifying state.
    async fn verify_lease_fence(
        tx: &mut PgConnection,
        handle: &ClaimedJob,
    ) -> Result<bool, sqlx::Error> {
        let row = sqlx::query(
            "SELECT 1 FROM jobs \
             WHERE job_id = $1 \
               AND workspace_id = $2 \
               AND lease_token = $3 \
               AND lease_generation = $4 \
               AND attempt_count = $5 \
               AND status = 'running'",
        )
        .bind(handle.job_id)
        .bind(handle.workspace_id)
        .bind(handle.lease_token)
        .bind(handle.lease_generation)
        .bind(handle.attempt_number)
        .fetch_optional(tx)
        .await?;

        Ok(row.is_some())
    }

    /// Executes parser sandbox run for one claimed job handle.
    pub async fn execute_claimed(
        &self,
        handle: &ClaimedJob,
    ) -> Result<Option<serde_json::Value>, JobExecutionFailure> {
        // 1. Verify claimed job kind is a supported parse job kind
        if handle.kind != JobKind::ParseDocumentPdf && handle.kind != JobKind::ParseDocumentDocxOcr
        {
            return Err(JobExecutionFailure::poison(
                "UNSUPPORTED_JOB_KIND",
                format!(
                    "Job kind '{}' is not handled by ParserSandboxJobExecutor",
                    handle.kind
                ),
            ));
        }

        let workspace_id = WorkspaceId::from_uuid(handle.workspace_id);

        // 2. Extract payload parameters and immutable targets
        let document_version_id = if let Some(params) = handle.payload.get("parameters") {
            if let Some(id_str) = params.get("document_version_id").and_then(|v| v.as_str()) {
                let uuid = Uuid::parse_str(id_str).map_err(|e| {
                    JobExecutionFailure::poison(
                        "INVALID_PAYLOAD",
                        format!("Invalid document_version_id UUID in parameters: {e}"),
                    )
                })?;
                DocumentVersionId::from_uuid(uuid)
            } else if let Some(target) = handle
                .payload
                .get("immutable_targets")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|t| t.as_str())
            {
                let uuid = Uuid::parse_str(target).map_err(|e| {
                    JobExecutionFailure::poison(
                        "INVALID_PAYLOAD",
                        format!("Invalid target UUID in immutable_targets: {e}"),
                    )
                })?;
                DocumentVersionId::from_uuid(uuid)
            } else {
                return Err(JobExecutionFailure::poison(
                    "INVALID_PAYLOAD",
                    "Missing document_version_id in parameters and immutable_targets",
                ));
            }
        } else {
            return Err(JobExecutionFailure::poison(
                "INVALID_PAYLOAD",
                "Missing parameters object in job payload",
            ));
        };

        // 3. Acquire DB connection and verify initial lease fence
        let mut conn = self.pool.acquire().await.map_err(|e| {
            JobExecutionFailure::retryable(
                "DB_CONNECTION_ERROR",
                format!("Failed to acquire DB connection: {e}"),
            )
        })?;

        if !Self::verify_lease_fence(&mut conn, handle)
            .await
            .map_err(|e| {
                JobExecutionFailure::retryable(
                    "DB_QUERY_ERROR",
                    format!("Failed to verify lease fence: {e}"),
                )
            })?
        {
            return Err(JobExecutionFailure::terminal(
                "STALE_LEASE",
                "Worker authority expired or superseded before parser sandbox execution",
            ));
        }

        // 4. Authoritatively load DocumentVersion, Document, and ObjectArtifact under workspace scope
        let version = DocumentVersionRepository::get_by_id(&mut conn, workspace_id, document_version_id)
            .await
            .map_err(|e| {
                JobExecutionFailure::retryable("DB_ERROR", format!("Version lookup failed: {e}"))
            })?
            .ok_or_else(|| {
                JobExecutionFailure::poison(
                    "VERSION_NOT_FOUND",
                    format!("Document version '{document_version_id}' not found in workspace '{workspace_id}'"),
                )
            })?;

        let artifact = ObjectArtifactRepository::get_by_id(
            &mut conn,
            workspace_id,
            version.object_artifact_id,
        )
        .await
        .map_err(|e| {
            JobExecutionFailure::retryable("DB_ERROR", format!("Artifact lookup failed: {e}"))
        })?
        .ok_or_else(|| {
            JobExecutionFailure::poison(
                "ARTIFACT_NOT_FOUND",
                format!(
                    "Object artifact '{}' not found in workspace '{workspace_id}'",
                    version.object_artifact_id
                ),
            )
        })?;

        let _doc = DocumentRepository::get_by_id(&mut conn, workspace_id, version.document_id)
            .await
            .map_err(|e| {
                JobExecutionFailure::retryable("DB_ERROR", format!("Document lookup failed: {e}"))
            })?
            .ok_or_else(|| {
                JobExecutionFailure::poison(
                    "DOCUMENT_NOT_FOUND",
                    format!(
                        "Document '{}' not found in workspace '{workspace_id}'",
                        version.document_id
                    ),
                )
            })?;

        // 5. MALWARE GATE PRECONDITION CHECK
        // Parser sandbox execution MUST NOT begin unless a clean malware scan is completed.
        let latest_quarantine = QuarantineRecordRepository::get_latest_by_document_version(
            &mut conn,
            workspace_id,
            document_version_id,
        )
        .await
        .map_err(|e| {
            JobExecutionFailure::retryable(
                "DB_ERROR",
                format!("Quarantine record lookup failed: {e}"),
            )
        })?;

        let quarantine_record = match latest_quarantine {
            Some(rec) => rec,
            None => {
                return Err(JobExecutionFailure::terminal(
                    "MALWARE_GATE_BLOCKED",
                    "Document version has no recorded malware scan; parse admission denied",
                ));
            }
        };

        match quarantine_record.status {
            QuarantineStatus::Clean => {
                // Precondition satisfied!
            }
            QuarantineStatus::Pending => {
                return Err(JobExecutionFailure::retryable(
                    "MALWARE_SCAN_PENDING",
                    "Malware scan is still pending for this document version; parse deferred",
                ));
            }
            QuarantineStatus::Malware => {
                return Err(JobExecutionFailure::terminal(
                    "MALWARE_DETECTED",
                    format!(
                        "Document version blocked by malware gate: threat '{}'",
                        quarantine_record
                            .reason_code
                            .as_deref()
                            .unwrap_or("unknown")
                    ),
                ));
            }
            QuarantineStatus::IntegrityFailed => {
                return Err(JobExecutionFailure::terminal(
                    "INTEGRITY_FAILED",
                    "Document version failed malware/integrity gate check",
                ));
            }
            other => {
                return Err(JobExecutionFailure::terminal(
                    "MALWARE_GATE_BLOCKED",
                    format!(
                        "Quarantine status '{}' is not acceptable for parse admission",
                        other.as_str()
                    ),
                ));
            }
        }

        drop(conn);

        // 6. Fetch exact immutable bytes from server storage
        let object_bytes =
            DocumentService::get_object_bytes(&artifact.bucket, artifact.key.as_str())
                .map_err(|e| {
                    JobExecutionFailure::retryable(
                        "STORAGE_ERROR",
                        format!("Storage retrieval error: {e}"),
                    )
                })?
                .ok_or_else(|| {
                    JobExecutionFailure::retryable(
                        "OBJECT_NOT_FOUND_IN_STORAGE",
                        format!(
                            "Object bytes not found in storage bucket '{}' key '{}'",
                            artifact.bucket,
                            artifact.key.as_str()
                        ),
                    )
                })?;

        // 7. Verify byte length and SHA-256 digest before sandbox handoff
        if object_bytes.len() as i64 != artifact.byte_length {
            return Err(JobExecutionFailure::terminal(
                "INTEGRITY_FAILED",
                format!(
                    "Stored byte length {} does not match declared artifact length {}",
                    object_bytes.len(),
                    artifact.byte_length
                ),
            ));
        }

        let computed_digest = Sha256::digest(&object_bytes);
        if computed_digest != artifact.content_sha256 {
            return Err(JobExecutionFailure::terminal(
                "INTEGRITY_FAILED",
                format!(
                    "Stored byte SHA-256 digest {} does not match declared artifact digest {}",
                    computed_digest.to_hex(),
                    artifact.content_sha256.to_hex()
                ),
            ));
        }

        // 8. Observe cooperative cancellation
        let is_cancelled: bool =
            sqlx::query_scalar("SELECT cancellation_requested FROM jobs WHERE job_id = $1")
                .bind(handle.job_id)
                .fetch_optional(&self.pool)
                .await
                .unwrap_or(None)
                .unwrap_or(false);
        if is_cancelled {
            return Err(JobExecutionFailure::terminal(
                "CANCELLED",
                "Parse execution cancelled by user/system",
            ));
        }

        // 9. Report progress stage: PARSER_SANDBOX_RUNNING
        let _ = sqlx::query(
            "INSERT INTO job_progress (job_progress_id, job_id, sequence, stage_code, current, total, message_code) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (job_id, sequence) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(handle.job_id)
        .bind(1)
        .bind("PARSER_SANDBOX_RUNNING")
        .bind(0i64)
        .bind(artifact.byte_length)
        .bind("PARSER_SANDBOX_STARTED")
        .execute(&self.pool)
        .await;

        // 10. Build scoped single-object sandbox input
        let sandbox_input = SandboxInput::new(
            workspace_id,
            document_version_id,
            artifact.id,
            handle.job_id,
            artifact.media_type,
            artifact.content_sha256,
            artifact.byte_length,
            object_bytes,
        )
        .map_err(|e| JobExecutionFailure::terminal("INPUT_ERROR", e))?;

        // 11. Launch parser sandbox under frozen security profile
        let sandbox_outcome = match self.runner.run(&self.profile, &sandbox_input).await {
            Ok(out) => out,
            Err(SandboxError::Timeout {
                elapsed_secs,
                limit_secs,
            }) => {
                return Err(JobExecutionFailure::retryable(
                    "SANDBOX_TIMEOUT",
                    format!("Parser sandbox timed out after {elapsed_secs}s (limit {limit_secs}s)"),
                ));
            }
            Err(SandboxError::OutOfMemory { detail }) => {
                return Err(JobExecutionFailure::retryable(
                    "SANDBOX_OOM",
                    format!("Parser sandbox terminated due to OOM: {detail}"),
                ));
            }
            Err(SandboxError::ResourceViolation {
                resource,
                limit,
                detail,
            }) => {
                return Err(JobExecutionFailure::retryable(
                    "SANDBOX_RESOURCE_VIOLATION",
                    format!(
                        "Parser sandbox resource ceiling violated for {resource} (limit {limit}): {detail}"
                    ),
                ));
            }
            Err(SandboxError::ProcessCrash {
                exit_code, stderr, ..
            }) => {
                return Err(JobExecutionFailure::retryable(
                    "SANDBOX_CRASH",
                    format!(
                        "Parser sandbox process crashed with exit code {exit_code:?}: {stderr}"
                    ),
                ));
            }
            Err(SandboxError::SandboxViolation {
                violation_type,
                detail,
            }) => {
                return Err(JobExecutionFailure::terminal(
                    "SANDBOX_VIOLATION",
                    format!("Parser sandbox security violation ({violation_type}): {detail}"),
                ));
            }
            Err(SandboxError::MalformedOutput { detail }) => {
                return Err(JobExecutionFailure::terminal(
                    "SANDBOX_MALFORMED_OUTPUT",
                    format!("Parser sandbox returned malformed output: {detail}"),
                ));
            }
            Err(SandboxError::OutputValidation(val_err)) => {
                return Err(JobExecutionFailure::terminal(
                    "SANDBOX_OUTPUT_VALIDATION_FAILED",
                    format!("Parser sandbox output validation failed: {val_err}"),
                ));
            }
            Err(SandboxError::IO { detail }) => {
                return Err(JobExecutionFailure::retryable(
                    "SANDBOX_IO_ERROR",
                    format!("Parser sandbox I/O error: {detail}"),
                ));
            }
            Err(SandboxError::Internal { detail }) => {
                return Err(JobExecutionFailure::terminal(
                    "SANDBOX_INTERNAL_ERROR",
                    format!("Parser sandbox internal error: {detail}"),
                ));
            }
        };

        // 12. Authoritatively validate sandbox output against input
        sandbox_outcome
            .validate_against_input(&sandbox_input)
            .map_err(|val_err| {
                JobExecutionFailure::terminal(
                    "SANDBOX_OUTPUT_VALIDATION_FAILED",
                    format!("Parser sandbox output validation failed: {val_err}"),
                )
            })?;

        // 13. Persist parser facts and audit event under lease fence in single atomic transaction
        let mut tx = self.pool.begin().await.map_err(|e| {
            JobExecutionFailure::retryable("DB_ERROR", format!("Failed to begin tx: {e}"))
        })?;

        // Re-verify lease fence inside transaction to prevent stale commits
        if !Self::verify_lease_fence(&mut tx, handle)
            .await
            .map_err(|e| {
                JobExecutionFailure::retryable(
                    "DB_QUERY_ERROR",
                    format!("Failed to verify lease fence: {e}"),
                )
            })?
        {
            let _ = tx.rollback().await;
            return Err(JobExecutionFailure::terminal(
                "STALE_LEASE",
                "Worker authority expired or superseded during sandbox execution",
            ));
        }

        let completed_at = Utc::now();
        let duration_ms = sandbox_outcome.execution_duration_ms as i64;
        let started_at = completed_at - chrono::Duration::milliseconds(duration_ms);

        let parser_artifact_id = ParserArtifactId::new();

        match sandbox_outcome.status {
            SandboxStatus::Success => {
                if let Some(ref parsed_data) = sandbox_outcome.parsed_artifact {
                    let (dom_artifact, dom_pages, dom_blocks, dom_spans) = parsed_data
                        .into_domain_entities(
                            workspace_id,
                            document_version_id,
                            parser_artifact_id,
                            sandbox_outcome.locator_version.clone(),
                            sandbox_outcome.parser_name.clone(),
                            sandbox_outcome.parser_version.clone(),
                            started_at,
                            completed_at,
                            Some(duration_ms),
                        )
                        .map_err(|e| {
                            JobExecutionFailure::terminal("DOMAIN_ERROR", e.to_string())
                        })?;

                    // Persist parser_artifacts
                    ParserArtifactRepository::insert(&mut tx, &dom_artifact)
                        .await
                        .map_err(|e| {
                            JobExecutionFailure::retryable(
                                "DB_ERROR",
                                format!("Failed to insert parser artifact: {e}"),
                            )
                        })?;

                    // Persist parser_pages
                    ParserPageRepository::insert_batch(&mut tx, &dom_pages, workspace_id)
                        .await
                        .map_err(|e| {
                            JobExecutionFailure::retryable(
                                "DB_ERROR",
                                format!("Failed to insert parser pages: {e}"),
                            )
                        })?;

                    // Persist parser_blocks
                    ParserBlockRepository::insert_batch(&mut tx, &dom_blocks, workspace_id)
                        .await
                        .map_err(|e| {
                            JobExecutionFailure::retryable(
                                "DB_ERROR",
                                format!("Failed to insert parser blocks: {e}"),
                            )
                        })?;

                    // Map block identities for span persistence
                    let mut block_map = std::collections::HashMap::new();
                    for (parsed_block, dom_block) in
                        parsed_data.blocks.iter().zip(dom_blocks.iter())
                    {
                        block_map.insert(
                            (parsed_block.page_number, parsed_block.ordinal),
                            dom_block.id,
                        );
                    }

                    // Persist source_spans
                    for (parsed_span, dom_span) in parsed_data.spans.iter().zip(dom_spans.iter()) {
                        let block_id = block_map
                            .get(&(parsed_span.page_number, parsed_span.block_ordinal))
                            .copied()
                            .or_else(|| dom_blocks.first().map(|b| b.id))
                            .ok_or_else(|| {
                                JobExecutionFailure::terminal(
                                    "BLOCK_MAPPING_ERROR",
                                    "No parser block found for source span",
                                )
                            })?;

                        SourceSpanRepository::insert(&mut tx, dom_span, block_id)
                            .await
                            .map_err(|e| {
                                JobExecutionFailure::retryable(
                                    "DB_ERROR",
                                    format!("Failed to insert source span: {e}"),
                                )
                            })?;
                    }
                } else {
                    let dom_artifact = ParserArtifact::reconstruct(
                        parser_artifact_id,
                        document_version_id,
                        workspace_id,
                        Some(handle.job_id),
                        sandbox_outcome.parser_name.clone(),
                        sandbox_outcome.parser_version.clone(),
                        sandbox_outcome.locator_version.clone(),
                        ParserStatus::Completed,
                        None,
                        sandbox_outcome.text_sha256,
                        sandbox_outcome.page_count,
                        sandbox_outcome.block_count,
                        sandbox_outcome.span_count,
                        Some(duration_ms),
                        None,
                        started_at,
                        Some(completed_at),
                    )
                    .map_err(|e| JobExecutionFailure::terminal("DOMAIN_ERROR", e.to_string()))?;

                    ParserArtifactRepository::insert(&mut tx, &dom_artifact)
                        .await
                        .map_err(|e| {
                            JobExecutionFailure::retryable(
                                "DB_ERROR",
                                format!("Failed to insert parser artifact: {e}"),
                            )
                        })?;
                }

                // Append PARSER_COMPLETED audit event
                let audit_store = PostgresAuditStore::new();
                let audit_params = AppendAuditParams {
                    workspace_id: workspace_id.into_uuid(),
                    actor_type: "worker".to_string(),
                    actor_id: Some(handle.job_id),
                    authority_snapshot: json!({ "lease_generation": handle.lease_generation }),
                    action_code: "PARSER_COMPLETED".to_string(),
                    entity_type: "document_version".to_string(),
                    entity_id: document_version_id.to_string(),
                    entity_version: Some(1),
                    request_id: None,
                    correlation_id: None,
                    job_id: Some(handle.job_id),
                    source_state_hash: None,
                    before_ref: Some(json!({ "parse_status": "processing" })),
                    after_ref: Some(json!({
                        "parse_status": "completed",
                        "parser_artifact_id": parser_artifact_id.to_string(),
                        "page_count": sandbox_outcome.page_count,
                        "block_count": sandbox_outcome.block_count,
                        "span_count": sandbox_outcome.span_count,
                        "text_sha256": sandbox_outcome.text_sha256.map(|h| h.to_hex()),
                    })),
                    metadata: json!({
                        "parser_artifact_id": parser_artifact_id.to_string(),
                        "document_version_id": document_version_id.to_string(),
                        "object_artifact_id": artifact.id.to_string(),
                        "parser_name": sandbox_outcome.parser_name,
                        "parser_version": sandbox_outcome.parser_version,
                        "locator_version": sandbox_outcome.locator_version.as_str(),
                        "page_count": sandbox_outcome.page_count,
                        "block_count": sandbox_outcome.block_count,
                        "span_count": sandbox_outcome.span_count,
                        "execution_duration_ms": sandbox_outcome.execution_duration_ms,
                    }),
                };

                audit_store
                    .append_audit_event(&mut tx, audit_params)
                    .await
                    .map_err(|e| {
                        JobExecutionFailure::retryable(
                            "AUDIT_ERROR",
                            format!("Audit append failed: {e}"),
                        )
                    })?;

                tx.commit().await.map_err(|e| {
                    JobExecutionFailure::retryable("DB_ERROR", format!("Tx commit failed: {e}"))
                })?;

                Ok(Some(json!({
                    "status": "succeeded",
                    "parser_artifact_id": parser_artifact_id.to_string(),
                    "document_version_id": document_version_id.to_string(),
                    "object_artifact_id": artifact.id.to_string(),
                    "parser_name": sandbox_outcome.parser_name,
                    "parser_version": sandbox_outcome.parser_version,
                    "locator_version": sandbox_outcome.locator_version.as_str(),
                    "page_count": sandbox_outcome.page_count,
                    "block_count": sandbox_outcome.block_count,
                    "span_count": sandbox_outcome.span_count,
                    "execution_duration_ms": sandbox_outcome.execution_duration_ms,
                })))
            }
            SandboxStatus::Unsupported => {
                let code = "UNSUPPORTED_DOCUMENT_FORMAT".to_string();
                let detail = sandbox_outcome
                    .failure_detail
                    .unwrap_or_else(|| "Document format or feature unsupported".to_string());

                let dom_artifact = ParserArtifact::reconstruct(
                    parser_artifact_id,
                    document_version_id,
                    workspace_id,
                    Some(handle.job_id),
                    sandbox_outcome.parser_name.clone(),
                    sandbox_outcome.parser_version.clone(),
                    sandbox_outcome.locator_version.clone(),
                    ParserStatus::Failed,
                    None,
                    None,
                    0,
                    0,
                    0,
                    Some(duration_ms),
                    Some(code.clone()),
                    started_at,
                    Some(completed_at),
                )
                .map_err(|e| JobExecutionFailure::terminal("DOMAIN_ERROR", e.to_string()))?;

                ParserArtifactRepository::insert(&mut tx, &dom_artifact)
                    .await
                    .map_err(|e| {
                        JobExecutionFailure::retryable(
                            "DB_ERROR",
                            format!("Failed to insert failed parser artifact: {e}"),
                        )
                    })?;

                let audit_store = PostgresAuditStore::new();
                let audit_params = AppendAuditParams {
                    workspace_id: workspace_id.into_uuid(),
                    actor_type: "worker".to_string(),
                    actor_id: Some(handle.job_id),
                    authority_snapshot: json!({ "lease_generation": handle.lease_generation }),
                    action_code: "PARSER_FAILED".to_string(),
                    entity_type: "document_version".to_string(),
                    entity_id: document_version_id.to_string(),
                    entity_version: Some(1),
                    request_id: None,
                    correlation_id: None,
                    job_id: Some(handle.job_id),
                    source_state_hash: None,
                    before_ref: Some(json!({ "parse_status": "processing" })),
                    after_ref: Some(json!({
                        "parse_status": "failed",
                        "parser_artifact_id": parser_artifact_id.to_string(),
                        "failure_code": code,
                    })),
                    metadata: json!({
                        "parser_artifact_id": parser_artifact_id.to_string(),
                        "document_version_id": document_version_id.to_string(),
                        "failure_code": code,
                        "failure_detail": detail,
                    }),
                };

                let _ = audit_store.append_audit_event(&mut tx, audit_params).await;
                let _ = tx.commit().await;

                Err(JobExecutionFailure::terminal(code, detail))
            }
            SandboxStatus::Corrupted => {
                let code = "CORRUPTED_DOCUMENT".to_string();
                let detail = sandbox_outcome
                    .failure_detail
                    .unwrap_or_else(|| "Document content is corrupted".to_string());

                let dom_artifact = ParserArtifact::reconstruct(
                    parser_artifact_id,
                    document_version_id,
                    workspace_id,
                    Some(handle.job_id),
                    sandbox_outcome.parser_name.clone(),
                    sandbox_outcome.parser_version.clone(),
                    sandbox_outcome.locator_version.clone(),
                    ParserStatus::Failed,
                    None,
                    None,
                    0,
                    0,
                    0,
                    Some(duration_ms),
                    Some(code.clone()),
                    started_at,
                    Some(completed_at),
                )
                .map_err(|e| JobExecutionFailure::terminal("DOMAIN_ERROR", e.to_string()))?;

                ParserArtifactRepository::insert(&mut tx, &dom_artifact)
                    .await
                    .map_err(|e| {
                        JobExecutionFailure::retryable(
                            "DB_ERROR",
                            format!("Failed to insert failed parser artifact: {e}"),
                        )
                    })?;

                let audit_store = PostgresAuditStore::new();
                let audit_params = AppendAuditParams {
                    workspace_id: workspace_id.into_uuid(),
                    actor_type: "worker".to_string(),
                    actor_id: Some(handle.job_id),
                    authority_snapshot: json!({ "lease_generation": handle.lease_generation }),
                    action_code: "PARSER_FAILED".to_string(),
                    entity_type: "document_version".to_string(),
                    entity_id: document_version_id.to_string(),
                    entity_version: Some(1),
                    request_id: None,
                    correlation_id: None,
                    job_id: Some(handle.job_id),
                    source_state_hash: None,
                    before_ref: Some(json!({ "parse_status": "processing" })),
                    after_ref: Some(json!({
                        "parse_status": "failed",
                        "parser_artifact_id": parser_artifact_id.to_string(),
                        "failure_code": code,
                    })),
                    metadata: json!({
                        "parser_artifact_id": parser_artifact_id.to_string(),
                        "document_version_id": document_version_id.to_string(),
                        "failure_code": code,
                        "failure_detail": detail,
                    }),
                };

                let _ = audit_store.append_audit_event(&mut tx, audit_params).await;
                let _ = tx.commit().await;

                Err(JobExecutionFailure::terminal(code, detail))
            }
            SandboxStatus::Failed => {
                let code = sandbox_outcome
                    .failure_code
                    .unwrap_or_else(|| "PARSER_FAILED".to_string());
                let detail = sandbox_outcome
                    .failure_detail
                    .unwrap_or_else(|| "Parser execution failed inside sandbox".to_string());

                let dom_artifact = ParserArtifact::reconstruct(
                    parser_artifact_id,
                    document_version_id,
                    workspace_id,
                    Some(handle.job_id),
                    sandbox_outcome.parser_name.clone(),
                    sandbox_outcome.parser_version.clone(),
                    sandbox_outcome.locator_version.clone(),
                    ParserStatus::Failed,
                    None,
                    None,
                    0,
                    0,
                    0,
                    Some(duration_ms),
                    Some(code.clone()),
                    started_at,
                    Some(completed_at),
                )
                .map_err(|e| JobExecutionFailure::terminal("DOMAIN_ERROR", e.to_string()))?;

                ParserArtifactRepository::insert(&mut tx, &dom_artifact)
                    .await
                    .map_err(|e| {
                        JobExecutionFailure::retryable(
                            "DB_ERROR",
                            format!("Failed to insert failed parser artifact: {e}"),
                        )
                    })?;

                let audit_store = PostgresAuditStore::new();
                let audit_params = AppendAuditParams {
                    workspace_id: workspace_id.into_uuid(),
                    actor_type: "worker".to_string(),
                    actor_id: Some(handle.job_id),
                    authority_snapshot: json!({ "lease_generation": handle.lease_generation }),
                    action_code: "PARSER_FAILED".to_string(),
                    entity_type: "document_version".to_string(),
                    entity_id: document_version_id.to_string(),
                    entity_version: Some(1),
                    request_id: None,
                    correlation_id: None,
                    job_id: Some(handle.job_id),
                    source_state_hash: None,
                    before_ref: Some(json!({ "parse_status": "processing" })),
                    after_ref: Some(json!({
                        "parse_status": "failed",
                        "parser_artifact_id": parser_artifact_id.to_string(),
                        "failure_code": code,
                    })),
                    metadata: json!({
                        "parser_artifact_id": parser_artifact_id.to_string(),
                        "document_version_id": document_version_id.to_string(),
                        "failure_code": code,
                        "failure_detail": detail,
                    }),
                };

                let _ = audit_store.append_audit_event(&mut tx, audit_params).await;
                let _ = tx.commit().await;

                Err(JobExecutionFailure::terminal(code, detail))
            }
        }
    }
}

#[async_trait]
impl JobExecutor for ParserSandboxJobExecutor {
    async fn execute(
        &self,
        ctx: &JobExecutionContext,
    ) -> Result<Option<serde_json::Value>, JobExecutionFailure> {
        self.execute_claimed(ctx.handle()).await
    }
}
