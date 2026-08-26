//! Row contract for `document_version_metadata`
//! (M002R physical columns 1:1).

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;
use w014_domain::{
    BoundedJson, DocumentVersionId, DocumentVersionMetadata, DocumentVersionMetadataId, WorkspaceId,
};

use crate::conventions;
use crate::error::{ContractError, ContractResult};

/// Authoritative column list of the `document_version_metadata` read shape.
pub const DOCUMENT_VERSION_METADATA_COLUMNS: &str = "document_version_metadata_id, \
     document_version_id, workspace_id, metadata, custom_fields, extracted_author, \
     extracted_title, page_count, word_count, created_at";

/// Exact read shape of a `document_version_metadata` row.
#[derive(Debug, Clone, FromRow)]
pub struct DocumentVersionMetadataRow {
    pub document_version_metadata_id: Uuid,
    pub document_version_id: Uuid,
    pub workspace_id: Uuid,
    /// Typed metadata snapshot (bounded JSON object).
    pub metadata: serde_json::Value,
    /// Typed custom-fields snapshot (bounded JSON object).
    pub custom_fields: serde_json::Value,
    pub extracted_author: Option<String>,
    pub extracted_title: Option<String>,
    pub page_count: Option<i32>,
    pub word_count: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// Exact insert shape of a new metadata snapshot row.
#[derive(Debug, Clone)]
pub struct NewDocumentVersionMetadataRow {
    pub document_version_metadata_id: Uuid,
    pub document_version_id: Uuid,
    pub workspace_id: Uuid,
    pub metadata: serde_json::Value,
    pub custom_fields: serde_json::Value,
    pub extracted_author: Option<String>,
    pub extracted_title: Option<String>,
    pub page_count: Option<i32>,
    pub word_count: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// Parameterized INSERT statement matching [`NewDocumentVersionMetadataRow`].
pub const INSERT_DOCUMENT_VERSION_METADATA: &str = "INSERT INTO document_version_metadata \
     (document_version_metadata_id, document_version_id, workspace_id, metadata, custom_fields, \
      extracted_author, extracted_title, page_count, word_count, created_at) \
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";

fn to_bounded(
    field: &'static str,
    table_field: &'static str,
    value: &serde_json::Value,
) -> ContractResult<BoundedJson> {
    BoundedJson::new(field, value.clone()).map_err(|_| ContractError::RowShape {
        table: "document_version_metadata",
        field: table_field,
        reason: "stored snapshot exceeds the frozen bounded-JSON contract".to_string(),
    })
}

/// Projects an authoritative [`DocumentVersionMetadata`] onto its insert
/// shape.
///
/// # Errors
/// Propagates domain invariant validation.
pub fn new_row_from_metadata(
    metadata: &DocumentVersionMetadata,
) -> ContractResult<NewDocumentVersionMetadataRow> {
    let mut metadata_json = metadata.metadata.as_value().clone();
    conventions::put_i64(
        &mut metadata_json,
        conventions::DECLARED_REVISION,
        metadata.declared_revision,
    )?;
    conventions::put_i64(
        &mut metadata_json,
        conventions::INTERNAL_REVISION,
        metadata.internal_revision,
    )?;
    let word_count = match metadata.word_count {
        Some(w) => Some(i32::try_from(w).map_err(|_| ContractError::RowShape {
            table: "document_version_metadata",
            field: "word_count",
            reason: format!("word count {w} exceeds INT4"),
        })?),
        None => None,
    };
    Ok(NewDocumentVersionMetadataRow {
        document_version_metadata_id: metadata.id.into_uuid(),
        document_version_id: metadata.document_version_id.into_uuid(),
        workspace_id: metadata.workspace_id.into_uuid(),
        metadata: metadata_json,
        custom_fields: metadata.custom_fields.as_value().clone(),
        extracted_author: metadata.extracted_author.clone(),
        extracted_title: metadata.extracted_title.clone(),
        page_count: metadata.page_count.map(|p| p as i32),
        word_count,
        created_at: metadata.created_at,
    })
}

/// Reconstructs the authoritative snapshot from the stored row ALONE.
///
/// # Errors
/// Fails closed on unbounded snapshots or negative stored counts.
pub fn metadata_from_row(
    row: &DocumentVersionMetadataRow,
) -> ContractResult<DocumentVersionMetadata> {
    let page_count = match row.page_count {
        Some(p) if p < 0 => {
            return Err(ContractError::RowShape {
                table: "document_version_metadata",
                field: "page_count",
                reason: format!("negative stored page count {p}"),
            });
        }
        Some(p) => Some(u32::try_from(p).map_err(|_| ContractError::RowShape {
            table: "document_version_metadata",
            field: "page_count",
            reason: format!("unrepresentable page count {p}"),
        })?),
        None => None,
    };
    let word_count = match row.word_count {
        Some(w) if w < 0 => {
            return Err(ContractError::RowShape {
                table: "document_version_metadata",
                field: "word_count",
                reason: format!("negative stored word count {w}"),
            });
        }
        Some(w) => Some(w as i64),
        None => None,
    };
    DocumentVersionMetadata::reconstruct(
        DocumentVersionMetadataId::from_uuid(row.document_version_metadata_id),
        DocumentVersionId::from_uuid(row.document_version_id),
        WorkspaceId::from_uuid(row.workspace_id),
        conventions::get_i64(
            &row.metadata,
            conventions::DECLARED_REVISION,
            "document_version_metadata",
        )?,
        conventions::get_i64(
            &row.metadata,
            conventions::INTERNAL_REVISION,
            "document_version_metadata",
        )?,
        page_count,
        word_count,
        row.extracted_author.clone(),
        row.extracted_title.clone(),
        to_bounded("metadata", "metadata", &row.metadata)?,
        to_bounded("custom_fields", "custom_fields", &row.custom_fields)?,
        row.created_at,
    )
    .map_err(ContractError::from)
}
