//! Row contract for `documents` (repaired M002R physical columns 1:1).
//!
//! The repaired physical catalog explicitly exposes
//! `documents.current_version_id` (nullable deferred pointer guarded by the
//! staged tri-column composite FK). This contract consumes that column
//! DIRECTLY: no caller-supplied projection context exists anywhere in this
//! module, and no JSONB substitute carries the pointer.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;
use w014_domain::{
    Document, DocumentClass, DocumentId, DocumentStatus, DocumentVersionId, DomainError,
    PrincipalId, WorkspaceId,
};

use crate::error::{ContractError, ContractResult};

/// Authoritative column list of the `documents` physical read shape.
pub const DOCUMENT_COLUMNS: &str = "document_id, workspace_id, title, document_type, status, \
     current_version_id, created_by, created_at, updated_at, row_version";

/// Exact read shape of a `documents` row.
#[derive(Debug, Clone, FromRow)]
pub struct DocumentRow {
    pub document_id: Uuid,
    pub workspace_id: Uuid,
    pub title: String,
    pub document_type: String,
    pub status: String,
    /// Repaired explicit physical fact: mutable deferred version pointer.
    pub current_version_id: Option<Uuid>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i32,
}

/// Exact insert shape of a new `documents` row.
#[derive(Debug, Clone)]
pub struct NewDocumentRow {
    pub document_id: Uuid,
    pub workspace_id: Uuid,
    pub title: String,
    pub document_type: String,
    pub status: String,
    pub current_version_id: Option<Uuid>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i32,
}

/// Parameterized INSERT statement matching [`NewDocumentRow`] exactly.
pub const INSERT_DOCUMENT: &str = "INSERT INTO documents (document_id, workspace_id, title, \
     document_type, status, current_version_id, created_by, created_at, updated_at, row_version) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";

/// Parameterized UPDATE statement advancing only the guarded projection
/// pointer under explicit row-version concurrency.
pub const UPDATE_CURRENT_VERSION: &str = "UPDATE documents SET current_version_id = $1, \
     updated_at = $2, row_version = row_version + 1 WHERE document_id = $3 AND workspace_id = $4 AND row_version = $5";

/// Projects an authoritative [`Document`] onto its insert shape.
///
/// # Errors
/// Propagates domain invariant validation.
pub fn new_row_from_document(document: &Document) -> ContractResult<NewDocumentRow> {
    Ok(NewDocumentRow {
        document_id: document.id.into_uuid(),
        workspace_id: document.workspace_id.into_uuid(),
        title: document.title.clone(),
        document_type: document.document_class.as_str().to_string(),
        status: document.status.as_str().to_string(),
        current_version_id: document
            .current_version_id
            .map(DocumentVersionId::into_uuid),
        created_by: document.created_by.map(PrincipalId::into_uuid),
        created_at: document.created_at,
        updated_at: document.updated_at,
        row_version: document.row_version,
    })
}

/// Reconstructs the authoritative [`Document`] from the stored row ALONE.
///
/// Every fact — including the current-version projection pointer — is read
/// from the repaired physical columns; nothing is supplied by the caller.
///
/// # Errors
/// Fails closed on closed-domain violations (`document_type`, `status`),
/// bound violations, or non-positive row versions.
pub fn document_from_row(row: &DocumentRow) -> ContractResult<Document> {
    let class = DocumentClass::parse(&row.document_type).map_err(|_| ContractError::RowShape {
        table: "documents",
        field: "document_type",
        reason: format!(
            "'{}' outside closed document-class domain",
            row.document_type
        ),
    })?;
    let status = DocumentStatus::parse(&row.status).map_err(|_| ContractError::RowShape {
        table: "documents",
        field: "status",
        reason: format!("'{}' outside closed document-status domain", row.status),
    })?;
    Document::reconstruct(
        DocumentId::from_uuid(row.document_id),
        WorkspaceId::from_uuid(row.workspace_id),
        row.title.clone(),
        class,
        status,
        row.current_version_id.map(DocumentVersionId::from_uuid),
        row.created_by.map(PrincipalId::from_uuid),
        row.created_at,
        row.updated_at,
        row.row_version,
    )
    .map_err(ContractError::from)
}

/// Validates that a candidate pointer update stays within the document's own
/// workspace scope before it is issued (defense in depth alongside RLS and
/// the staged composite FK).
///
/// # Errors
/// Fails with [`DomainError::CrossWorkspaceComposition`] on mismatch.
pub fn check_pointer_scope(
    document_workspace_id: WorkspaceId,
    pointer_workspace_id: WorkspaceId,
) -> Result<(), DomainError> {
    if document_workspace_id != pointer_workspace_id {
        return Err(DomainError::CrossWorkspaceComposition {
            field: "documents.current_version_id",
        });
    }
    Ok(())
}
