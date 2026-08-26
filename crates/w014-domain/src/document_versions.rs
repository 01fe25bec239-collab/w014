//! Immutable document version semantics (M002R `document_versions`).
//!
//! A version is immutable bytes + identity binding: exact workspace, exact
//! parent document, strictly positive ordinal, explicit server-owned
//! `object_artifact_id` binding, exact 32-byte content digest, the frozen P0
//! media-type allowlist, and `original_filename` as display metadata only.
//! Only the guarded one-way trust projection may advance after construction.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::documents::{Document, DocumentClass};
use crate::error::DomainError;
use crate::ids::{DocumentId, DocumentVersionId, ObjectArtifactId, PrincipalId, WorkspaceId};
use crate::limits::{MAX_FILENAME_BYTES, MAX_UPLOAD_BYTES, MIN_UPLOAD_BYTES};
use crate::media::MediaType;
use crate::sha256::Sha256;
use crate::validation::validate_bounded_non_empty;

/// Frozen integrity/malware trust-state domain of an immutable version.
///
/// Parser eligibility occurs only after the frozen trust transition into
/// [`TrustState::Trusted`]; quarantined and rejected versions are never
/// eligible. Matches the physical CHECK domain exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustState {
    /// Created, not yet scanned.
    Pending,
    /// Scanner accepted/processing the immutable bytes.
    Scanning,
    /// Integrity + malware trust transition complete: parser eligible.
    Trusted,
    /// Quarantined by malware/integrity verdict.
    Quarantined,
    /// Rejected without quarantine.
    Rejected,
}

impl TrustState {
    /// Canonical physical representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Scanning => "scanning",
            Self::Trusted => "trusted",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }

    /// Parses a stored state into the closed domain; fails closed.
    ///
    /// # Errors
    /// Fails closed for unknown vocabulary.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "pending" => Ok(Self::Pending),
            "scanning" => Ok(Self::Scanning),
            "trusted" => Ok(Self::Trusted),
            "quarantined" => Ok(Self::Quarantined),
            "rejected" => Ok(Self::Rejected),
            other => Err(DomainError::ValidationError {
                field: "trust_state",
                reason: format!("'{other}' is not in the closed trust-state domain"),
            }),
        }
    }

    /// Frozen one-way transition table:
    /// `pending -> scanning -> { trusted | quarantined | rejected }`;
    /// terminal states never regress or re-enter scanning.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Pending, Self::Scanning)
                | (
                    Self::Scanning,
                    Self::Trusted | Self::Quarantined | Self::Rejected
                )
        )
    }
}

/// Strictly positive immutable version ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VersionOrdinal(u32);

impl VersionOrdinal {
    /// Creates a strictly positive ordinal.
    ///
    /// # Errors
    /// Fails when zero.
    pub fn new(value: u32) -> Result<Self, DomainError> {
        if value == 0 {
            return Err(DomainError::ValidationError {
                field: "version_number",
                reason: "version ordinals are strictly positive".to_string(),
            });
        }
        Ok(Self(value))
    }

    /// The ordinal value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Authoritative domain representation of one immutable document version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentVersion {
    pub id: DocumentVersionId,
    pub document_id: DocumentId,
    pub workspace_id: WorkspaceId,
    pub version_ordinal: VersionOrdinal,
    /// Immutable object-artifact binding (server-owned bytes).
    pub object_artifact_id: ObjectArtifactId,
    /// Exact content digest: always 32 bytes.
    pub sha256_hash: Sha256,
    /// Byte length bounded by the frozen upload limit.
    pub byte_size: i64,
    /// P0 media type only.
    pub content_type: MediaType,
    /// Original filename: display metadata only, never object authority.
    pub original_filename: String,
    /// Preserved submitting principal identity.
    pub submitted_by: Option<PrincipalId>,
    /// Guarded integrity/malware trust projection.
    pub trust_state: TrustState,
    pub created_at: DateTime<Utc>,
}

impl DocumentVersion {
    /// Creates a new immutable version bound to its logical document.
    ///
    /// Construction is only possible through the parent document binding, so
    /// a version can never be created outside its document's workspace.
    ///
    /// # Errors
    /// Fails closed on zero ordinals, out-of-bounds byte sizes, or invalid
    /// filenames.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        document: &Document,
        version_ordinal: VersionOrdinal,
        object_artifact_id: ObjectArtifactId,
        byte_size: i64,
        sha256_hash: Sha256,
        original_filename: impl AsRef<str>,
        submitted_by: Option<PrincipalId>,
    ) -> Result<Self, DomainError> {
        let now = Utc::now();
        let version = Self::reconstruct(
            DocumentVersionId::new(),
            document.id,
            document.workspace_id,
            version_ordinal,
            object_artifact_id,
            byte_size,
            sha256_hash,
            MediaType::parse(document.document_class_media_type())?,
            original_filename.as_ref().to_string(),
            submitted_by,
            TrustState::Pending,
            now,
        )?;
        version.binds_to_document(document)?;
        Ok(version)
    }

    /// Composition check used by persistence-facing adapters when a stored
    /// version row is joined against its stored parent document row:
    /// rejects any cross-workspace or wrong-parent pairing fail-closed.
    ///
    /// # Errors
    /// Fails with [`DomainError::CrossWorkspaceComposition`] on workspace
    /// mismatch and [`DomainError::ValidationError`] on parent mismatch.
    pub fn binds_to_document(&self, document: &Document) -> Result<(), DomainError> {
        if self.workspace_id != document.workspace_id {
            return Err(DomainError::CrossWorkspaceComposition {
                field: "document_version.workspace_id",
            });
        }
        if self.document_id != document.id {
            return Err(DomainError::ValidationError {
                field: "document_version.document_id",
                reason: "version is not a child of the given document".to_string(),
            });
        }
        Ok(())
    }

    /// Reconstructs a version from persistent storage, fail-closed.
    ///
    /// # Errors
    /// Fails closed on any violated frozen invariant.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: DocumentVersionId,
        document_id: DocumentId,
        workspace_id: WorkspaceId,
        version_ordinal: VersionOrdinal,
        object_artifact_id: ObjectArtifactId,
        byte_size: i64,
        sha256_hash: Sha256,
        content_type: MediaType,
        original_filename: String,
        submitted_by: Option<PrincipalId>,
        trust_state: TrustState,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        if !(MIN_UPLOAD_BYTES..=MAX_UPLOAD_BYTES).contains(&byte_size) {
            return Err(DomainError::ValidationError {
                field: "byte_size",
                reason: format!("byte size {byte_size} outside frozen 1..100 MiB upload bound"),
            });
        }
        let valid_filename = validate_bounded_non_empty(
            "original_filename",
            &original_filename,
            MAX_FILENAME_BYTES,
        )?
        .to_string();
        Ok(Self {
            id,
            document_id,
            workspace_id,
            version_ordinal,
            object_artifact_id,
            sha256_hash,
            byte_size,
            content_type,
            original_filename: valid_filename,
            submitted_by,
            trust_state,
            created_at,
        })
    }

    /// Returns a NEW version instance with the trust projection advanced
    /// along the frozen one-way transition table.
    ///
    /// The original instance is untouched: versions are immutable facts; the
    /// trust state is a guarded projection, never a rewrite of history.
    ///
    /// # Errors
    /// Fails on transitions outside the frozen table (fail-closed).
    pub fn with_advanced_trust(&self, next: TrustState) -> Result<Self, DomainError> {
        if !self.trust_state.can_transition_to(next) {
            return Err(DomainError::IllegalStateTransition {
                from: self.trust_state.as_str().to_string(),
                to: next.as_str().to_string(),
                reason: "transition violates the frozen one-way trust table".to_string(),
            });
        }
        let mut advanced = self.clone();
        advanced.trust_state = next;
        Ok(advanced)
    }

    /// True when this version completed the frozen integrity/malware trust
    /// transition and is therefore parser eligible.
    #[must_use]
    pub const fn is_parser_eligible(&self) -> bool {
        matches!(self.trust_state, TrustState::Trusted)
    }
}

impl Document {
    /// The frozen P0 media type associated with this document's class.
    #[must_use]
    pub const fn document_class_media_type(&self) -> &'static str {
        match self.document_class {
            DocumentClass::Pdf => "application/pdf",
            DocumentClass::Docx => {
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::WorkspaceId;

    fn fixture() -> (Document, ObjectArtifactId) {
        let doc = Document::new(WorkspaceId::new(), "V Doc", DocumentClass::Pdf, None).unwrap();
        (doc, ObjectArtifactId::new())
    }

    #[test]
    fn test_version_construction_and_parent_binding() {
        let (doc, artifact) = fixture();
        let v = DocumentVersion::new(
            &doc,
            VersionOrdinal::new(1).unwrap(),
            artifact,
            1024,
            Sha256::digest(b"bytes"),
            "contract.pdf",
            None,
        )
        .unwrap();
        assert_eq!(v.version_ordinal.get(), 1);
        assert_eq!(v.object_artifact_id, artifact);
        assert_eq!(v.trust_state, TrustState::Pending);
        assert!(!v.is_parser_eligible());
        v.binds_to_document(&doc).unwrap();

        // Cross-workspace parent composition is rejected.
        let mut foreign = doc.clone();
        foreign.id = DocumentId::new();
        foreign.workspace_id = WorkspaceId::new();
        assert!(v.binds_to_document(&foreign).is_err());
    }

    #[test]
    fn test_zero_ordinal_and_bad_bytes_fail_closed() {
        let (doc, artifact) = fixture();
        assert!(VersionOrdinal::new(0).is_err());
        assert!(
            DocumentVersion::new(
                &doc,
                VersionOrdinal::new(1).unwrap(),
                artifact,
                0,
                Sha256::digest(b"x"),
                "a.pdf",
                None
            )
            .is_err()
        );
        assert!(
            DocumentVersion::new(
                &doc,
                VersionOrdinal::new(1).unwrap(),
                artifact,
                MAX_UPLOAD_BYTES + 1,
                Sha256::digest(b"x"),
                "a.pdf",
                None
            )
            .is_err()
        );
    }

    #[test]
    fn test_frozen_one_way_trust_table() {
        let (doc, artifact) = fixture();
        let v = DocumentVersion::new(
            &doc,
            VersionOrdinal::new(2).unwrap(),
            artifact,
            10,
            Sha256::digest(b"y"),
            "b.pdf",
            None,
        )
        .unwrap();

        // pending -> trusted skips scanning: rejected; original untouched.
        assert!(v.with_advanced_trust(TrustState::Trusted).is_err());
        assert_eq!(v.trust_state, TrustState::Pending);

        let scanning = v.with_advanced_trust(TrustState::Scanning).unwrap();
        let trusted = scanning.with_advanced_trust(TrustState::Trusted).unwrap();
        assert!(trusted.is_parser_eligible());
        assert!(trusted.with_advanced_trust(TrustState::Scanning).is_err());

        for terminal in [TrustState::Quarantined, TrustState::Rejected] {
            let s = v.with_advanced_trust(TrustState::Scanning).unwrap();
            let t = s.with_advanced_trust(terminal).unwrap();
            assert!(!t.is_parser_eligible());
            assert!(t.with_advanced_trust(TrustState::Scanning).is_err());
        }
    }

    #[test]
    fn test_filename_is_display_metadata_only() {
        let (doc, artifact) = fixture();
        assert!(
            DocumentVersion::new(
                &doc,
                VersionOrdinal::new(3).unwrap(),
                artifact,
                10,
                Sha256::digest(b"z"),
                "../evil.pdf",
                None,
            )
            .is_ok(),
            "filename stays display data; object authority remains server-side"
        );
        assert!(
            DocumentVersion::new(
                &doc,
                VersionOrdinal::new(4).unwrap(),
                artifact,
                10,
                Sha256::digest(b"z"),
                "   ",
                None,
            )
            .is_err()
        );
    }
}
