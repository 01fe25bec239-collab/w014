//! Row contract for `document_versions` (repaired M002R physical columns 1:1).
//!
//! The repaired physical catalog explicitly exposes `object_artifact_id`
//! (mandatory immutable server-bytes binding) and `original_filename`
//! (display metadata). This contract consumes those columns DIRECTLY; no
//! caller-supplied binding or filename context exists.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;
use w014_domain::{
    DocumentId, DocumentVersion, DocumentVersionId, MediaType, ObjectArtifactId, PrincipalId,
    Sha256, TrustState, VersionOrdinal, WorkspaceId,
};

use crate::error::{ContractError, ContractResult};

/// Authoritative column list of the `document_versions` physical read shape.
pub const DOCUMENT_VERSION_COLUMNS: &str = "document_version_id, document_id, workspace_id, \
     version_number, object_artifact_id, byte_size, sha256_hash, content_type, \
     original_filename, trust_state, submitted_by, created_at";

/// Exact read shape of a `document_versions` row.
#[derive(Debug, Clone, FromRow)]
pub struct DocumentVersionRow {
    pub document_version_id: Uuid,
    pub document_id: Uuid,
    pub workspace_id: Uuid,
    pub version_number: i32,
    /// Repaired explicit physical fact: immutable object-artifact binding.
    pub object_artifact_id: Uuid,
    pub byte_size: i64,
    /// BYTEA; must decode to exactly 32 bytes.
    pub sha256_hash: Vec<u8>,
    pub content_type: String,
    /// Repaired explicit physical fact: display metadata only.
    pub original_filename: String,
    pub trust_state: String,
    pub submitted_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Exact insert shape of a new `document_versions` row.
#[derive(Debug, Clone)]
pub struct NewDocumentVersionRow {
    pub document_version_id: Uuid,
    pub document_id: Uuid,
    pub workspace_id: Uuid,
    pub version_number: i32,
    pub object_artifact_id: Uuid,
    pub byte_size: i64,
    pub sha256_hash: Vec<u8>,
    pub content_type: String,
    pub original_filename: String,
    pub trust_state: String,
    pub submitted_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Parameterized INSERT statement matching [`NewDocumentVersionRow`].
pub const INSERT_DOCUMENT_VERSION: &str = "INSERT INTO document_versions \
     (document_version_id, document_id, workspace_id, version_number, object_artifact_id, \
      byte_size, sha256_hash, content_type, original_filename, trust_state, submitted_by, \
      created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)";

/// Parameterized guarded trust-state transition statement (one-way chain is
/// enforced by the frozen trigger).
pub const UPDATE_TRUST_STATE: &str = "UPDATE document_versions SET trust_state = $1 \
     WHERE document_version_id = $2 AND workspace_id = $3";

/// Projects an authoritative [`DocumentVersion`] onto its insert shape.
///
/// # Errors
/// Propagates domain invariant validation.
pub fn new_row_from_version(version: &DocumentVersion) -> ContractResult<NewDocumentVersionRow> {
    Ok(NewDocumentVersionRow {
        document_version_id: version.id.into_uuid(),
        document_id: version.document_id.into_uuid(),
        workspace_id: version.workspace_id.into_uuid(),
        version_number: i32::try_from(version.version_ordinal.get()).map_err(|_| {
            ContractError::RowShape {
                table: "document_versions",
                field: "version_number",
                reason: format!("ordinal {} exceeds INT4", version.version_ordinal.get()),
            }
        })?,
        object_artifact_id: version.object_artifact_id.into_uuid(),
        byte_size: version.byte_size,
        sha256_hash: version.sha256_hash.as_bytes().to_vec(),
        content_type: version.content_type.as_str().to_string(),
        original_filename: version.original_filename.clone(),
        trust_state: version.trust_state.as_str().to_string(),
        submitted_by: version.submitted_by.map(PrincipalId::into_uuid),
        created_at: version.created_at,
    })
}

/// Reconstructs the authoritative [`DocumentVersion`] from the stored row
/// ALONE. Every repaired explicit fact (object binding + original filename)
/// is consumed directly from the row.
///
/// # Errors
/// Fails closed on closed-domain violations, digest-width violations, bound
/// violations, or zero ordinals.
#[allow(clippy::too_many_arguments)]
pub fn version_from_parts(
    document_version_id: Uuid,
    document_id: Uuid,
    workspace_id: Uuid,
    version_number: i32,
    object_artifact_id: Uuid,
    byte_size: i64,
    sha256_hash: &[u8],
    content_type: &str,
    original_filename: &str,
    trust_state: &str,
    submitted_by: Option<Uuid>,
    created_at: DateTime<Utc>,
) -> ContractResult<DocumentVersion> {
    let ordinal_value = u32::try_from(version_number).map_err(|_| ContractError::RowShape {
        table: "document_versions",
        field: "version_number",
        reason: format!("stored ordinal {version_number} is not representable"),
    })?;
    let media = MediaType::parse(content_type).map_err(|_| ContractError::RowShape {
        table: "document_versions",
        field: "content_type",
        reason: format!("'{content_type}' outside frozen P0 media-type allowlist"),
    })?;
    let state = TrustState::parse(trust_state).map_err(|_| ContractError::RowShape {
        table: "document_versions",
        field: "trust_state",
        reason: format!("'{trust_state}' outside closed trust-state domain"),
    })?;
    DocumentVersion::reconstruct(
        DocumentVersionId::from_uuid(document_version_id),
        DocumentId::from_uuid(document_id),
        WorkspaceId::from_uuid(workspace_id),
        VersionOrdinal::new(ordinal_value)?,
        ObjectArtifactId::from_uuid(object_artifact_id),
        byte_size,
        Sha256::from_slice("sha256_hash", sha256_hash)?,
        media,
        original_filename.to_string(),
        submitted_by.map(PrincipalId::from_uuid),
        state,
        created_at,
    )
    .map_err(ContractError::from)
}

/// Reconstructs a [`DocumentVersion`] from a fetched row.
///
/// # Errors
/// See [`version_from_parts`].
pub fn version_from_row(row: &DocumentVersionRow) -> ContractResult<DocumentVersion> {
    version_from_parts(
        row.document_version_id,
        row.document_id,
        row.workspace_id,
        row.version_number,
        row.object_artifact_id,
        row.byte_size,
        &row.sha256_hash,
        &row.content_type,
        &row.original_filename,
        &row.trust_state,
        row.submitted_by,
        row.created_at,
    )
}
