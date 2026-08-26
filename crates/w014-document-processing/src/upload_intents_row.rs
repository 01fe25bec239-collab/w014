//! Row contract for `upload_intents` (repaired M002R physical columns 1:1).
//!
//! The repaired physical catalog explicitly exposes `opaque_object_key`
//! (server-controlled authority), the expected media-type/length/sha256
//! declaration facts, the immutable `object_artifact_id` binding, and the
//! one-way `finalized_at` / `abandoned_at` terminal markers. This contract
//! consumes those columns DIRECTLY: no caller-supplied declaration or
//! binding context exists.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;
use w014_domain::{
    DomainError, IntentStatus, MediaType, ObjectArtifactId, ObjectKey, PrincipalId, Sha256,
    UploadIntent, UploadIntentId, WorkspaceId,
};

use crate::error::{ContractError, ContractResult};

/// Authoritative column list of the `upload_intents` physical read shape.
pub const UPLOAD_INTENT_COLUMNS: &str = "upload_intent_id, workspace_id, created_by, \
     document_id, filename, expected_media_type, expected_length, expected_sha256_b64, \
     object_artifact_id, opaque_object_key, status, expires_at, finalized_at, abandoned_at, \
     created_at";

/// Exact read shape of an `upload_intents` row.
#[derive(Debug, Clone, FromRow)]
pub struct UploadIntentRow {
    pub upload_intent_id: Uuid,
    pub workspace_id: Uuid,
    pub created_by: Uuid,
    /// NULL means the upload targets a future NEW logical document.
    pub document_id: Option<Uuid>,
    pub filename: String,
    /// Repaired explicit physical fact: frozen allowlist declaration.
    pub expected_media_type: String,
    /// Repaired explicit physical fact: declared 1..100 MiB length.
    pub expected_length: i64,
    /// Repaired explicit physical fact: canonical base64 digest declaration.
    pub expected_sha256_b64: Option<String>,
    /// Repaired explicit physical fact: immutable artifact binding.
    pub object_artifact_id: Option<Uuid>,
    /// Repaired explicit physical fact: server-controlled opaque key.
    pub opaque_object_key: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    /// One-way marker (present exactly when status = 'verified').
    pub finalized_at: Option<DateTime<Utc>>,
    /// One-way marker (present exactly when status = 'aborted').
    pub abandoned_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Exact insert shape of a new `upload_intents` row.
#[derive(Debug, Clone)]
pub struct NewUploadIntentRow {
    pub upload_intent_id: Uuid,
    pub workspace_id: Uuid,
    pub created_by: Uuid,
    pub document_id: Option<Uuid>,
    pub filename: String,
    pub expected_media_type: String,
    pub expected_length: i64,
    pub expected_sha256_b64: Option<String>,
    pub object_artifact_id: Option<Uuid>,
    pub opaque_object_key: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub finalized_at: Option<DateTime<Utc>>,
    pub abandoned_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Parameterized INSERT statement matching [`NewUploadIntentRow`] exactly.
pub const INSERT_UPLOAD_INTENT: &str = "INSERT INTO upload_intents \
     (upload_intent_id, workspace_id, created_by, document_id, filename, expected_media_type, \
      expected_length, expected_sha256_b64, object_artifact_id, opaque_object_key, status, \
      expires_at, finalized_at, abandoned_at, created_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";

/// Parameterized guarded terminal transition statement; the frozen trigger
/// enforces one-way semantics physically.
pub const UPDATE_INTENT_STATUS: &str = "UPDATE upload_intents SET status = $1, \
     finalized_at = COALESCE($2, finalized_at), abandoned_at = COALESCE($3, abandoned_at) \
     WHERE upload_intent_id = $4 AND workspace_id = $5";

/// Parameterized first-registration statement for the artifact binding.
pub const BIND_INTENT_ARTIFACT: &str = "UPDATE upload_intents SET object_artifact_id = $1 \
     WHERE upload_intent_id = $2 AND workspace_id = $3 AND object_artifact_id IS NULL";

/// Projects an authoritative [`UploadIntent`] onto its insert shape.
///
/// # Errors
/// Propagates domain invariant validation.
pub fn new_row_from_intent(intent: &UploadIntent) -> ContractResult<NewUploadIntentRow> {
    Ok(NewUploadIntentRow {
        upload_intent_id: intent.id.into_uuid(),
        workspace_id: intent.workspace_id.into_uuid(),
        created_by: intent.created_by.into_uuid(),
        document_id: intent.document_id.map(w014_domain::DocumentId::into_uuid),
        filename: intent.filename.clone(),
        expected_media_type: intent.expected_media_type.as_str().to_string(),
        expected_length: intent.expected_length,
        expected_sha256_b64: intent.expected_sha256_b64.map(|d| d.to_base64()),
        object_artifact_id: intent.object_artifact_id.map(ObjectArtifactId::into_uuid),
        opaque_object_key: intent.opaque_object_key.as_str().to_string(),
        status: intent.status.as_str().to_string(),
        expires_at: intent.expires_at,
        finalized_at: intent.finalized_at,
        abandoned_at: intent.abandoned_at,
        created_at: intent.created_at,
    })
}

/// Reconstructs the authoritative [`UploadIntent`] from the stored row ALONE.
///
/// Every repaired explicit fact — server key, declarations, artifact binding,
/// terminal markers — is consumed directly from the physical columns.
///
/// # Errors
/// Fails closed on closed-domain violations, malformed digest declarations,
/// marker/status contradictions, or violated bounds.
pub fn intent_from_row(row: &UploadIntentRow) -> ContractResult<UploadIntent> {
    let media =
        MediaType::parse(&row.expected_media_type).map_err(|_| ContractError::RowShape {
            table: "upload_intents",
            field: "expected_media_type",
            reason: format!(
                "'{}' outside frozen P0 media-type allowlist",
                row.expected_media_type
            ),
        })?;
    let status = IntentStatus::parse(&row.status).map_err(|_| ContractError::RowShape {
        table: "upload_intents",
        field: "status",
        reason: format!("'{}' outside closed intent-status domain", row.status),
    })?;
    let key = ObjectKey::reconstruct(row.opaque_object_key.clone()).map_err(|_| {
        ContractError::RowShape {
            table: "upload_intents",
            field: "opaque_object_key",
            reason: "stored key violates the frozen key-shape contract".to_string(),
        }
    })?;
    let declared_digest = match &row.expected_sha256_b64 {
        None => None,
        Some(b64) => Some(
            Sha256::from_base64("expected_sha256_b64", b64).map_err(|_| {
                ContractError::RowShape {
                    table: "upload_intents",
                    field: "expected_sha256_b64",
                    reason: format!("'{b64}' is not canonical 32-byte base64"),
                }
            })?,
        ),
    };
    UploadIntent::reconstruct(
        UploadIntentId::from_uuid(row.upload_intent_id),
        WorkspaceId::from_uuid(row.workspace_id),
        PrincipalId::from_uuid(row.created_by),
        row.document_id.map(w014_domain::DocumentId::from_uuid),
        row.filename.clone(),
        media,
        row.expected_length,
        declared_digest,
        row.object_artifact_id.map(ObjectArtifactId::from_uuid),
        key,
        status,
        row.expires_at,
        row.finalized_at,
        row.abandoned_at,
        row.created_at,
    )
    .map_err(ContractError::from)
}

/// Validates that a candidate artifact binding stays within the intent's own
/// workspace scope before it is issued (defense in depth alongside RLS and
/// the composite FK).
///
/// # Errors
/// Fails with [`DomainError::CrossWorkspaceComposition`] on mismatch.
pub fn check_binding_scope(
    intent_workspace_id: WorkspaceId,
    artifact_workspace_id: WorkspaceId,
) -> Result<(), DomainError> {
    if intent_workspace_id != artifact_workspace_id {
        return Err(DomainError::CrossWorkspaceComposition {
            field: "upload_intents.object_artifact_id",
        });
    }
    Ok(())
}
