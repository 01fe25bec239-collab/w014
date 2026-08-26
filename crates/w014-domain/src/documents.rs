//! Logical document identity semantics (M002R `documents`).
//!
//! A Document is the workspace-scoped logical identity whose versions are
//! immutable children. `current_version_id` is a mutable projection pointer
//! onto an existing immutable version (physically realized by the repaired
//! `documents.current_version_id` column and its staged tri-column composite
//! FK); it never rewrites history.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::ids::{DocumentId, DocumentVersionId, PrincipalId, WorkspaceId};
use crate::limits::MAX_TITLE_BYTES;
use crate::validation::validate_bounded_non_empty;

/// Closed/frozen logical document class domain for the P0 pipeline.
///
/// The two classes mirror the two frozen P0 processing families (PDF native
/// path and DOCX/OCR path) already frozen by the W2 job kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DocumentClass {
    /// PDF processing family (`application/pdf`).
    Pdf,
    /// DOCX/OCR processing family (frozen DOCX MIME).
    Docx,
}

impl DocumentClass {
    /// Canonical physical `document_type` representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Docx => "docx",
        }
    }

    /// Parses a stored class into the closed domain; fails closed on unknowns.
    ///
    /// # Errors
    /// Fails closed for any value outside the closed class vocabulary.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "pdf" => Ok(Self::Pdf),
            "docx" => Ok(Self::Docx),
            other => Err(DomainError::ValidationError {
                field: "document_class",
                reason: format!("'{other}' is not in the closed document-class domain"),
            }),
        }
    }
}

/// Closed document-status domain (frozen to the physical CHECK vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DocumentStatus {
    /// Active logical document.
    Active,
    /// Archived (no new activity).
    Archived,
    /// Deleted (logical tombstone; immutable history remains evidence).
    Deleted,
}

impl DocumentStatus {
    /// Canonical physical representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::Deleted => "deleted",
        }
    }

    /// Parses a stored status into the closed domain; fails closed.
    ///
    /// # Errors
    /// Fails closed for any value outside the closed status vocabulary.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "active" => Ok(Self::Active),
            "archived" => Ok(Self::Archived),
            "deleted" => Ok(Self::Deleted),
            other => Err(DomainError::ValidationError {
                field: "document_status",
                reason: format!("'{other}' is not in the closed document-status domain"),
            }),
        }
    }
}

/// Authoritative domain representation of a logical Document.
///
/// Versions are immutable children; only the projection pointer
/// (`current_version_id`) and guarded lifecycle fields may change, each under
/// explicit row-version concurrency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Document {
    pub id: DocumentId,
    pub workspace_id: WorkspaceId,
    /// Bounded display name; display metadata only, never object authority.
    pub title: String,
    pub document_class: DocumentClass,
    pub status: DocumentStatus,
    /// Mutable projection pointer onto one existing immutable child version.
    pub current_version_id: Option<DocumentVersionId>,
    /// Preserved principal creator identity.
    pub created_by: Option<PrincipalId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Guarded projection concurrency token.
    pub row_version: i32,
}

impl Document {
    /// Creates a new logical document with no projected current version yet.
    ///
    /// # Errors
    /// Fails closed on empty or over-bound titles.
    pub fn new(
        workspace_id: WorkspaceId,
        title: impl AsRef<str>,
        document_class: DocumentClass,
        created_by: Option<PrincipalId>,
    ) -> Result<Self, DomainError> {
        let now = Utc::now();
        Self::reconstruct(
            DocumentId::new(),
            workspace_id,
            title.as_ref().to_string(),
            document_class,
            DocumentStatus::Active,
            None,
            created_by,
            now,
            now,
            1,
        )
    }

    /// Reconstructs a document from persistent storage, re-validating every
    /// invariant fail-closed. Every field comes from the stored row itself.
    ///
    /// # Errors
    /// Fails closed on any violated bound or ordering invariant.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: DocumentId,
        workspace_id: WorkspaceId,
        title: String,
        document_class: DocumentClass,
        status: DocumentStatus,
        current_version_id: Option<DocumentVersionId>,
        created_by: Option<PrincipalId>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        row_version: i32,
    ) -> Result<Self, DomainError> {
        let valid_title = validate_bounded_non_empty("title", &title, MAX_TITLE_BYTES)?.to_string();
        if row_version <= 0 {
            return Err(DomainError::ValidationError {
                field: "row_version",
                reason: format!("row_version must be positive, got {row_version}"),
            });
        }
        if updated_at < created_at {
            return Err(DomainError::ValidationError {
                field: "updated_at",
                reason: "updated_at cannot precede created_at".to_string(),
            });
        }
        Ok(Self {
            id,
            workspace_id,
            title: valid_title,
            document_class,
            status,
            current_version_id,
            created_by,
            created_at,
            updated_at,
            row_version,
        })
    }

    /// Projects an existing immutable child version as the current version.
    ///
    /// This is a pure pointer update under guarded concurrency: it does not
    /// create, mutate, or accept any version bytes and implements no
    /// WI-0202+ workflow behavior.
    ///
    /// # Errors
    /// Fails when `expected_row_version` does not match (optimistic
    /// concurrency conflict on the projection pointer).
    pub fn project_current_version(
        &mut self,
        version_id: DocumentVersionId,
        expected_row_version: i32,
        at: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        if self.row_version != expected_row_version {
            return Err(DomainError::IllegalStateTransition {
                from: format!("row_version={}", self.row_version),
                to: format!("row_version={expected_row_version}"),
                reason: "stale guarded projection: row_version conflict".to_string(),
            });
        }
        self.current_version_id = Some(version_id);
        self.row_version += 1;
        if at > self.updated_at {
            self.updated_at = at;
        }
        Ok(())
    }

    /// Guarded status transition within the closed status domain.
    ///
    /// Terminal states are one-way: archived/deleted documents can never be
    /// resurrected to active.
    ///
    /// # Errors
    /// Fails on row-version conflicts or transitions outside the frozen table.
    pub fn transition_status(
        &mut self,
        next: DocumentStatus,
        expected_row_version: i32,
    ) -> Result<(), DomainError> {
        if self.row_version != expected_row_version {
            return Err(DomainError::IllegalStateTransition {
                from: format!("row_version={}", self.row_version),
                to: format!("row_version={expected_row_version}"),
                reason: "stale guarded transition: row_version conflict".to_string(),
            });
        }
        let from = self.status;
        let allowed = matches!(
            (from, next),
            (DocumentStatus::Active, DocumentStatus::Archived)
                | (DocumentStatus::Active, DocumentStatus::Deleted)
                | (DocumentStatus::Archived, DocumentStatus::Deleted)
        );
        if !allowed {
            return Err(DomainError::IllegalStateTransition {
                from: from.as_str().to_string(),
                to: next.as_str().to_string(),
                reason: "archived/deleted documents cannot be resurrected to active".to_string(),
            });
        }
        self.status = next;
        self.row_version += 1;
        self.updated_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Document {
        Document::new(WorkspaceId::new(), "Q3 Contract", DocumentClass::Pdf, None).unwrap()
    }

    #[test]
    fn test_new_document_defaults() {
        let doc = sample();
        assert_eq!(doc.status, DocumentStatus::Active);
        assert_eq!(doc.current_version_id, None);
        assert_eq!(doc.row_version, 1);
    }

    #[test]
    fn test_title_bounds_enforced() {
        assert!(Document::new(WorkspaceId::new(), "   ", DocumentClass::Pdf, None).is_err());
        let big = "x".repeat(MAX_TITLE_BYTES + 1);
        assert!(Document::new(WorkspaceId::new(), big, DocumentClass::Docx, None).is_err());
    }

    #[test]
    fn test_projection_pointer_is_guarded() {
        let mut doc = sample();
        let stale = doc.row_version - 1;
        assert!(
            doc.project_current_version(DocumentVersionId::new(), stale, Utc::now())
                .is_err()
        );

        let vid = DocumentVersionId::new();
        doc.project_current_version(vid, doc.row_version, Utc::now())
            .unwrap();
        assert_eq!(doc.current_version_id, Some(vid));
        assert_eq!(doc.row_version, 2);
    }

    #[test]
    fn test_status_domain_closed_and_resurrection_blocked() {
        assert!(DocumentStatus::parse("active").is_ok());
        assert!(DocumentStatus::parse("paused").is_err());
        assert!(DocumentClass::parse("pdf").is_ok());
        assert!(DocumentClass::parse("spreadsheet").is_err());

        let mut doc = sample();
        doc.transition_status(DocumentStatus::Archived, doc.row_version)
            .unwrap();
        assert_eq!(doc.status, DocumentStatus::Archived);
        // Resurrection prohibited.
        assert!(
            doc.transition_status(DocumentStatus::Active, doc.row_version)
                .is_err()
        );
        // Archived documents may still be deleted.
        doc.transition_status(DocumentStatus::Deleted, doc.row_version)
            .unwrap();
        assert_eq!(doc.status, DocumentStatus::Deleted);
        assert!(
            doc.transition_status(DocumentStatus::Active, doc.row_version)
                .is_err()
        );
    }
}
