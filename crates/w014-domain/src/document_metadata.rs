//! Immutable typed metadata snapshot semantics
//! (M002R `document_version_metadata`).
//!
//! One metadata row per immutable version; declared/internal revisions are
//! data only. Replacement happens through a NEW immutable version, never by
//! mutating historical snapshots.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::ids::{DocumentVersionId, DocumentVersionMetadataId, WorkspaceId};
use crate::json::BoundedJson;
use crate::limits::MAX_SHORT_LABEL_BYTES;
use crate::validation::validate_bounded_non_empty;

/// Authoritative domain representation of one immutable version-metadata
/// snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentVersionMetadata {
    pub id: DocumentVersionMetadataId,
    pub document_version_id: DocumentVersionId,
    pub workspace_id: WorkspaceId,
    /// Declared revision as inert data (e.g. client-stated revision).
    pub declared_revision: Option<i64>,
    /// Internal revision as inert data.
    pub internal_revision: Option<i64>,
    /// Optional bounded page count (>= 0).
    pub page_count: Option<u32>,
    /// Optional word count (>= 0).
    pub word_count: Option<i64>,
    pub extracted_author: Option<String>,
    pub extracted_title: Option<String>,
    /// Bounded typed metadata snapshot.
    pub metadata: BoundedJson,
    /// Bounded typed custom fields snapshot.
    pub custom_fields: BoundedJson,
    pub created_at: DateTime<Utc>,
}

impl DocumentVersionMetadata {
    /// Creates a new immutable metadata snapshot for an exact version inside
    /// the exact workspace.
    ///
    /// # Errors
    /// Fails closed on unbounded/ill-formed snapshots or negative counts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        document_version_id: DocumentVersionId,
        workspace_id: WorkspaceId,
        declared_revision: Option<i64>,
        internal_revision: Option<i64>,
        page_count: Option<u32>,
        word_count: Option<i64>,
        extracted_author: Option<String>,
        extracted_title: Option<String>,
        metadata: BoundedJson,
        custom_fields: BoundedJson,
    ) -> Result<Self, DomainError> {
        let now = Utc::now();
        Self::reconstruct(
            DocumentVersionMetadataId::new(),
            document_version_id,
            workspace_id,
            declared_revision,
            internal_revision,
            page_count,
            word_count,
            extracted_author,
            extracted_title,
            metadata,
            custom_fields,
            now,
        )
    }

    /// Reconstructs a stored snapshot fail-closed.
    ///
    /// # Errors
    /// Fails closed on negative counts or over-bound labels.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: DocumentVersionMetadataId,
        document_version_id: DocumentVersionId,
        workspace_id: WorkspaceId,
        declared_revision: Option<i64>,
        internal_revision: Option<i64>,
        page_count: Option<u32>,
        word_count: Option<i64>,
        extracted_author: Option<String>,
        extracted_title: Option<String>,
        metadata: BoundedJson,
        custom_fields: BoundedJson,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        if let Some(words) = word_count
            && words < 0
        {
            return Err(DomainError::ValidationError {
                field: "word_count",
                reason: format!("word count must be non-negative, got {words}"),
            });
        }
        for (field, label) in [
            ("extracted_author", &extracted_author),
            ("extracted_title", &extracted_title),
        ] {
            if let Some(text) = label {
                validate_bounded_non_empty(field, text, MAX_SHORT_LABEL_BYTES)?;
            }
        }
        Ok(Self {
            id,
            document_version_id,
            workspace_id,
            declared_revision,
            internal_revision,
            page_count,
            word_count,
            extracted_author,
            extracted_title,
            metadata,
            custom_fields,
            created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_snapshot_construction() {
        let m = DocumentVersionMetadata::new(
            DocumentVersionId::new(),
            WorkspaceId::new(),
            Some(7),
            None,
            Some(12),
            Some(4_500),
            Some("Author".to_string()),
            None,
            BoundedJson::new("metadata", json!({"lang": "en"})).unwrap(),
            BoundedJson::empty(),
        )
        .unwrap();
        assert_eq!(m.page_count, Some(12));
        assert_eq!(m.metadata.as_value()["lang"], "en");
    }

    #[test]
    fn test_negative_word_count_rejected() {
        let now = Utc::now();
        assert!(
            DocumentVersionMetadata::reconstruct(
                DocumentVersionMetadataId::new(),
                DocumentVersionId::new(),
                WorkspaceId::new(),
                None,
                None,
                None,
                Some(-1),
                None,
                None,
                BoundedJson::empty(),
                BoundedJson::empty(),
                now,
            )
            .is_err()
        );
    }
}
