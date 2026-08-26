//! Row contract for `parser_artifacts` (repaired M002R physical columns 1:1).
//!
//! The repaired physical catalog explicitly exposes the canonical
//! `locator_version` identity (REQUIRED), the optional `artifact_object_id`
//! derived-text reference, the optional `text_sha256` full-text digest, and
//! the guarded lifecycle facts (`started_at`, `failure_code`,
//! one-way terminal transitions). This contract consumes those columns
//! DIRECTLY: no caller-supplied locator or reference context exists.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;
use w014_domain::{
    DomainError, LocatorVersion, ObjectArtifactId, ParserArtifact, ParserArtifactId, ParserStatus,
    Sha256, WorkspaceId,
};

use crate::error::{ContractError, ContractResult};

/// Authoritative column list of the `parser_artifacts` physical read shape.
pub const PARSER_ARTIFACT_COLUMNS: &str = "parser_artifact_id, document_version_id, \
     workspace_id, job_id, parser_name, parser_version, locator_version, status, \
     artifact_object_id, text_sha256, page_count, block_count, span_count, \
     execution_duration_ms, failure_code, started_at, completed_at";

/// Exact read shape of a `parser_artifacts` row.
#[derive(Debug, Clone, FromRow)]
pub struct ParserArtifactRow {
    pub parser_artifact_id: Uuid,
    pub document_version_id: Uuid,
    pub workspace_id: Uuid,
    pub job_id: Option<Uuid>,
    pub parser_name: String,
    pub parser_version: String,
    /// Repaired explicit physical fact: REQUIRED locator identity.
    pub locator_version: String,
    pub status: String,
    /// Repaired explicit physical fact: optional derived-text object ref.
    pub artifact_object_id: Option<Uuid>,
    /// Repaired explicit physical fact: BYTEA digest (32 bytes when present).
    pub text_sha256: Option<Vec<u8>>,
    pub page_count: i32,
    pub block_count: i32,
    pub span_count: i32,
    pub execution_duration_ms: Option<i64>,
    /// Repaired explicit physical fact: required exactly when failed.
    pub failure_code: Option<String>,
    /// Repaired explicit physical fact: run-start timestamp.
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Exact insert shape of a new processing parser-artifact row.
#[derive(Debug, Clone)]
pub struct NewParserArtifactRow {
    pub parser_artifact_id: Uuid,
    pub document_version_id: Uuid,
    pub workspace_id: Uuid,
    pub job_id: Option<Uuid>,
    pub parser_name: String,
    pub parser_version: String,
    pub locator_version: String,
    pub status: String,
    pub artifact_object_id: Option<Uuid>,
    pub text_sha256: Option<Vec<u8>>,
    pub page_count: i32,
    pub block_count: i32,
    pub span_count: i32,
    pub execution_duration_ms: Option<i64>,
    pub failure_code: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Parameterized INSERT statement matching [`NewParserArtifactRow`] exactly.
pub const INSERT_PARSER_ARTIFACT: &str = "INSERT INTO parser_artifacts \
     (parser_artifact_id, document_version_id, workspace_id, job_id, parser_name, \
      parser_version, locator_version, status, artifact_object_id, text_sha256, page_count, \
      block_count, span_count, execution_duration_ms, failure_code, started_at, completed_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)";

/// Parameterized guarded terminal transition statement; the frozen trigger
/// enforces exactly-once semantics physically.
pub const COMPLETE_PARSER_ARTIFACT: &str = "UPDATE parser_artifacts SET status = 'completed', \
     completed_at = $1, page_count = $2, block_count = $3, span_count = $4, \
     execution_duration_ms = $5 WHERE parser_artifact_id = $6 AND workspace_id = $7 \
     AND status = 'processing'";

/// Parameterized guarded failure-transition statement.
pub const FAIL_PARSER_ARTIFACT: &str = "UPDATE parser_artifacts SET status = 'failed', \
     completed_at = $1, failure_code = $2 WHERE parser_artifact_id = $3 AND workspace_id = $4 \
     AND status = 'processing'";

/// Projects an authoritative [`ParserArtifact`] onto its insert shape.
///
/// # Errors
/// Propagates domain invariant validation.
pub fn new_row_from_parser_artifact(
    artifact: &ParserArtifact,
) -> ContractResult<NewParserArtifactRow> {
    Ok(NewParserArtifactRow {
        parser_artifact_id: artifact.id.into_uuid(),
        document_version_id: artifact.document_version_id.into_uuid(),
        workspace_id: artifact.workspace_id.into_uuid(),
        job_id: artifact.job_id,
        parser_name: artifact.parser_name.clone(),
        parser_version: artifact.parser_version.clone(),
        locator_version: artifact.locator_version.as_str().to_string(),
        status: artifact.status.as_str().to_string(),
        artifact_object_id: artifact.artifact_object_id.map(ObjectArtifactId::into_uuid),
        text_sha256: artifact.text_sha256.map(|d| d.as_bytes().to_vec()),
        page_count: artifact.page_count,
        block_count: artifact.block_count,
        span_count: artifact.span_count,
        execution_duration_ms: artifact.execution_duration_ms,
        failure_code: artifact.failure_code.clone(),
        started_at: artifact.started_at,
        completed_at: artifact.completed_at,
    })
}

/// Reconstructs the authoritative [`ParserArtifact`] from the stored row
/// ALONE. The locator identity and optional object/digest references are
/// consumed directly from their repaired explicit columns.
///
/// # Errors
/// Fails closed on closed-domain violations, digest-width violations, or
/// violated lifecycle invariants.
pub fn parser_artifact_from_row(row: &ParserArtifactRow) -> ContractResult<ParserArtifact> {
    let status = ParserStatus::parse(&row.status).map_err(|_| ContractError::RowShape {
        table: "parser_artifacts",
        field: "status",
        reason: format!("'{}' outside closed parser-status domain", row.status),
    })?;
    let locator =
        LocatorVersion::new(row.locator_version.clone()).map_err(|_| ContractError::RowShape {
            table: "parser_artifacts",
            field: "locator_version",
            reason: "stored locator identity violates the frozen label contract".to_string(),
        })?;
    let text_digest = match &row.text_sha256 {
        None => None,
        Some(bytes) => Some(Sha256::from_slice("text_sha256", bytes)?),
    };
    ParserArtifact::reconstruct(
        ParserArtifactId::from_uuid(row.parser_artifact_id),
        w014_domain::DocumentVersionId::from_uuid(row.document_version_id),
        WorkspaceId::from_uuid(row.workspace_id),
        row.job_id,
        row.parser_name.clone(),
        row.parser_version.clone(),
        locator,
        status,
        row.artifact_object_id.map(ObjectArtifactId::from_uuid),
        text_digest,
        row.page_count,
        row.block_count,
        row.span_count,
        row.execution_duration_ms,
        row.failure_code.clone(),
        row.started_at,
        row.completed_at,
    )
    .map_err(ContractError::from)
}

/// Validates that a candidate derived-text object reference stays within the
/// parser artifact's own workspace scope before it is issued.
///
/// # Errors
/// Fails with [`DomainError::CrossWorkspaceComposition`] on mismatch.
pub fn check_reference_scope(
    artifact_workspace_id: WorkspaceId,
    referenced_workspace_id: WorkspaceId,
) -> Result<(), DomainError> {
    if artifact_workspace_id != referenced_workspace_id {
        return Err(DomainError::CrossWorkspaceComposition {
            field: "parser_artifacts.artifact_object_id",
        });
    }
    Ok(())
}
