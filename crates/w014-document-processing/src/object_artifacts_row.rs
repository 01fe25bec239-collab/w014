//! Row contract for `object_artifacts` (repaired M002R physical columns 1:1).
//!
//! The repaired physical catalog explicitly exposes `artifact_kind`,
//! `object_key`, `content_sha256`, `byte_length`, `sse_mode`, and
//! `kms_key_ref` as authoritative immutable object facts. This contract
//! consumes those columns DIRECTLY; rows are insert-only.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;
use w014_domain::{
    ArtifactKind, EncryptionMode, ObjectArtifact, ObjectArtifactId, ObjectKey, Sha256, StorageTier,
    StoredMediaType, WorkspaceId,
};

use crate::error::{ContractError, ContractResult};

/// Authoritative column list of the `object_artifacts` physical read shape.
pub const OBJECT_ARTIFACT_COLUMNS: &str = "object_artifact_id, workspace_id, artifact_kind, \
     object_key, content_sha256, byte_length, media_type, \
     sse_mode, kms_key_ref, retention_until, created_at";

/// Exact read shape of an `object_artifacts` row.
#[derive(Debug, Clone, FromRow)]
pub struct ObjectArtifactRow {
    pub object_artifact_id: Uuid,
    pub workspace_id: Uuid,
    /// Repaired explicit physical fact: frozen kind domain.
    pub artifact_kind: String,
    /// Repaired explicit physical fact: server-owned key.
    pub object_key: String,
    /// Repaired explicit physical fact: BYTEA, exactly 32 bytes.
    pub content_sha256: Vec<u8>,
    pub byte_length: i64,
    pub media_type: String,
    /// Repaired explicit physical fact: frozen SSE posture.
    pub sse_mode: String,
    /// Repaired explicit physical fact: optional KMS identifier.
    pub kms_key_ref: Option<String>,
    pub retention_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Exact insert shape of a new immutable object-fact row.
#[derive(Debug, Clone)]
pub struct NewObjectArtifactRow {
    pub object_artifact_id: Uuid,
    pub workspace_id: Uuid,
    pub artifact_kind: String,
    pub object_key: String,
    pub content_sha256: Vec<u8>,
    pub byte_length: i64,
    pub media_type: String,
    pub sse_mode: String,
    pub kms_key_ref: Option<String>,
    pub retention_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Parameterized INSERT statement matching [`NewObjectArtifactRow`] exactly
/// (insert-only: no UPDATE/DELETE statements exist in this module).
pub const INSERT_OBJECT_ARTIFACT: &str = "INSERT INTO object_artifacts \
     (object_artifact_id, workspace_id, artifact_kind, object_key, content_sha256, byte_length, \
      media_type, sse_mode, kms_key_ref, retention_until, created_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";

/// Projects an authoritative [`ObjectArtifact`] onto its insert shape.
///
/// # Errors
/// Propagates domain invariant validation.
pub fn new_row_from_artifact(artifact: &ObjectArtifact) -> ContractResult<NewObjectArtifactRow> {
    Ok(NewObjectArtifactRow {
        object_artifact_id: artifact.id.into_uuid(),
        workspace_id: artifact.workspace_id.into_uuid(),
        artifact_kind: artifact.kind.as_str().to_string(),
        object_key: artifact.key.as_str().to_string(),
        content_sha256: artifact.content_sha256.as_bytes().to_vec(),
        byte_length: artifact.byte_length,
        media_type: artifact.media_type.as_str().to_string(),
        sse_mode: artifact.encryption.as_str().to_string(),
        kms_key_ref: artifact.kms_key_ref.clone(),
        retention_until: artifact.retention_until,
        created_at: artifact.created_at,
    })
}

/// Reconstructs the authoritative [`ObjectArtifact`] from the stored row
/// ALONE. All repaired explicit facts are consumed directly from physical
/// columns; nothing is supplied by callers and nothing hides in JSONB.
///
/// # Errors
/// Fails closed on closed-domain violations, digest-width violations, or
/// key-shape violations.
#[allow(clippy::too_many_arguments)]
pub fn artifact_from_parts(
    object_artifact_id: Uuid,
    workspace_id: Uuid,
    artifact_kind: &str,
    object_key: &str,
    content_sha256: &[u8],
    byte_length: i64,
    media_type: &str,
    sse_mode: &str,
    kms_key_ref: Option<&str>,
    retention_until: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
) -> ContractResult<ObjectArtifact> {
    let kind = ArtifactKind::parse(artifact_kind).map_err(|_| ContractError::RowShape {
        table: "object_artifacts",
        field: "artifact_kind",
        reason: format!("'{artifact_kind}' outside closed artifact-kind domain"),
    })?;
    let sse = EncryptionMode::parse(sse_mode).map_err(|_| ContractError::RowShape {
        table: "object_artifacts",
        field: "sse_mode",
        reason: format!("'{sse_mode}' outside closed sse-mode domain"),
    })?;
    let key =
        ObjectKey::reconstruct(object_key.to_string()).map_err(|_| ContractError::RowShape {
            table: "object_artifacts",
            field: "object_key",
            reason: format!("stored key '{object_key}' violates the frozen key-shape contract"),
        })?;
    ObjectArtifact::reconstruct_full(
        ObjectArtifactId::from_uuid(object_artifact_id),
        WorkspaceId::from_uuid(workspace_id),
        kind,
        "w014-documents".to_string(),
        key,
        Sha256::from_slice("content_sha256", content_sha256)?,
        byte_length,
        StoredMediaType::new(media_type).map_err(|_| ContractError::RowShape {
            table: "object_artifacts",
            field: "media_type",
            reason: format!("stored media type '{media_type}' is not well-formed"),
        })?,
        StorageTier::Hot,
        sse,
        kms_key_ref.map(str::to_string),
        retention_until,
        created_at,
    )
    .map_err(ContractError::from)
}

/// Reconstructs an [`ObjectArtifact`] from a fetched row.
///
/// # Errors
/// See [`artifact_from_parts`].
pub fn artifact_from_row(row: &ObjectArtifactRow) -> ContractResult<ObjectArtifact> {
    artifact_from_parts(
        row.object_artifact_id,
        row.workspace_id,
        &row.artifact_kind,
        &row.object_key,
        &row.content_sha256,
        row.byte_length,
        &row.media_type,
        &row.sse_mode,
        row.kms_key_ref.as_deref(),
        row.retention_until,
        row.created_at,
    )
}
