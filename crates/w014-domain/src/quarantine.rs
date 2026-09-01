//! Quarantine prerequisite semantics (M002R `quarantine_records`).
//!
//! Immutable scan-outcome facts tied to an exact upload intent. The outcome
//! rides the frozen closed status domain (pending/clean/malware/
//! integrity_failed/unsupported) with scanner version and optional reason
//! code as explicit facts — never hidden in JSONB, never rewritten: a rescan
//! appends a brand-new record. No scanner execution belongs here.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::ids::{
    DocumentVersionId, ObjectArtifactId, QuarantineRecordId, UploadIntentId, WorkspaceId,
};
use crate::json::BoundedJson;
use crate::limits::{MAX_REASON_CODE_BYTES, MAX_SHORT_LABEL_BYTES};
use crate::validation::validate_bounded_non_empty;

/// Frozen scan-outcome domain (matches physical CHECK vocabulary exactly).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuarantineStatus {
    /// Recorded before any verdict exists.
    Pending,
    /// No threat found; integrity intact.
    Clean,
    /// Malware detected.
    Malware,
    /// Declared digest/length mismatch or unreadable bytes.
    IntegrityFailed,
    /// Bytes outside the processable P0 families.
    Unsupported,
}

impl QuarantineStatus {
    /// Canonical physical representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Clean => "clean",
            Self::Malware => "malware",
            Self::IntegrityFailed => "integrity_failed",
            Self::Unsupported => "unsupported",
        }
    }

    /// Parses a stored status into the closed domain; fails closed.
    ///
    /// # Errors
    /// Fails closed for unknown vocabulary (including obsolete lifecycle
    /// substitutes such as 'quarantined'/'released'/'purged').
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "pending" => Ok(Self::Pending),
            "clean" => Ok(Self::Clean),
            "malware" => Ok(Self::Malware),
            "integrity_failed" => Ok(Self::IntegrityFailed),
            "unsupported" => Ok(Self::Unsupported),
            other => Err(DomainError::ValidationError {
                field: "quarantine_status",
                reason: format!("'{other}' is not in the frozen scan-outcome domain"),
            }),
        }
    }

    /// True when this outcome blocks any trust transition.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        !matches!(self, Self::Clean)
    }
}

/// Authoritative domain representation of one immutable scan-outcome record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub id: QuarantineRecordId,
    pub workspace_id: WorkspaceId,
    /// Exact scanned upload intent (physical tie).
    pub upload_intent_id: UploadIntentId,
    pub document_version_id: Option<DocumentVersionId>,
    pub object_artifact_id: Option<ObjectArtifactId>,
    pub status: QuarantineStatus,
    pub scanner_name: String,
    pub scanner_version: Option<String>,
    pub reason_code: Option<String>,
    pub checked_at: DateTime<Utc>,
    pub threat_details: BoundedJson,
}

impl QuarantineRecord {
    /// Records a new immutable scan outcome for an exact intent.
    ///
    /// # Errors
    /// Fails closed on over-bound labels or empty scanner identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        upload_intent_id: UploadIntentId,
        status: QuarantineStatus,
        scanner_name: impl AsRef<str>,
        scanner_version: Option<String>,
        reason_code: Option<String>,
        document_version_id: Option<DocumentVersionId>,
        object_artifact_id: Option<ObjectArtifactId>,
        checked_at: DateTime<Utc>,
        threat_details: BoundedJson,
    ) -> Result<Self, DomainError> {
        Self::reconstruct(
            QuarantineRecordId::new(),
            workspace_id,
            upload_intent_id,
            document_version_id,
            object_artifact_id,
            status,
            scanner_name.as_ref().to_string(),
            scanner_version,
            reason_code,
            checked_at,
            threat_details,
        )
    }

    /// Records a new immutable scan outcome using Prompt-12 physical facts.
    ///
    /// # Errors
    /// Fails closed on invalid scanner version or reason code.
    pub fn from_outcome(
        workspace_id: WorkspaceId,
        upload_intent_id: UploadIntentId,
        status: QuarantineStatus,
        scanner_version: impl Into<String>,
        reason_code: Option<String>,
        checked_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        let s_version = scanner_version.into();
        validate_bounded_non_empty("scanner_version", &s_version, MAX_SHORT_LABEL_BYTES)?;
        if let Some(ref code) = reason_code {
            validate_bounded_non_empty("reason_code", code, MAX_REASON_CODE_BYTES)?;
        }
        Ok(Self {
            id: QuarantineRecordId::new(),
            workspace_id,
            upload_intent_id,
            document_version_id: None,
            object_artifact_id: None,
            status,
            scanner_name: "clamav".to_string(),
            scanner_version: Some(s_version),
            reason_code,
            checked_at,
            threat_details: BoundedJson::empty(),
        })
    }

    /// Reconstructs a QuarantineRecord with a specific QuarantineRecordId.
    pub fn reconstruct_from_row(
        id: QuarantineRecordId,
        workspace_id: WorkspaceId,
        upload_intent_id: UploadIntentId,
        status: QuarantineStatus,
        scanner_version: impl Into<String>,
        reason_code: Option<String>,
        checked_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        let mut rec = Self::from_outcome(
            workspace_id,
            upload_intent_id,
            status,
            scanner_version,
            reason_code,
            checked_at,
        )?;
        rec.id = id;
        Ok(rec)
    }

    /// Opens a fresh pending record for a rescan of the same intent:
    /// rescans append brand-new records rather than rewriting history.
    ///
    /// # Errors
    /// Fails closed on invalid scanner identity.
    pub fn for_rescan(
        prior: &QuarantineRecord,
        scanner_name: impl AsRef<str>,
        scanner_version: Option<String>,
        checked_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        Self::new(
            prior.workspace_id,
            prior.upload_intent_id,
            QuarantineStatus::Pending,
            scanner_name,
            scanner_version,
            None,
            None,
            None,
            checked_at,
            BoundedJson::empty(),
        )
    }

    /// Reconstructs a stored record fail-closed.
    ///
    /// # Errors
    /// Fails closed on over-bound labels or empty scanner identity.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: QuarantineRecordId,
        workspace_id: WorkspaceId,
        upload_intent_id: UploadIntentId,
        document_version_id: Option<DocumentVersionId>,
        object_artifact_id: Option<ObjectArtifactId>,
        status: QuarantineStatus,
        scanner_name: String,
        scanner_version: Option<String>,
        reason_code: Option<String>,
        checked_at: DateTime<Utc>,
        threat_details: BoundedJson,
    ) -> Result<Self, DomainError> {
        let valid_scanner =
            validate_bounded_non_empty("scanner_name", &scanner_name, MAX_SHORT_LABEL_BYTES)?
                .to_string();
        if let Some(v) = &scanner_version {
            validate_bounded_non_empty("scanner_version", v, MAX_SHORT_LABEL_BYTES)?;
        }
        if let Some(code) = &reason_code {
            validate_bounded_non_empty("reason_code", code, MAX_REASON_CODE_BYTES)?;
        }
        Ok(Self {
            id,
            workspace_id,
            upload_intent_id,
            document_version_id,
            object_artifact_id,
            status,
            scanner_name: valid_scanner,
            scanner_version,
            reason_code,
            checked_at,
            threat_details,
        })
    }

    /// Composition check used by adapters joining stored rows: rejects any
    /// optional binding resolved from a foreign workspace fail-closed.
    ///
    /// # Errors
    /// Fails with [`DomainError::CrossWorkspaceComposition`] on mismatch.
    pub fn binds_within_workspace(
        &self,
        document_version_workspace: Option<WorkspaceId>,
        object_artifact_workspace: Option<WorkspaceId>,
    ) -> Result<(), DomainError> {
        for (field, bound) in [
            (
                "quarantine_record.document_version_id",
                document_version_workspace,
            ),
            (
                "quarantine_record.object_artifact_id",
                object_artifact_workspace,
            ),
        ] {
            if bound.is_some_and(|b| b != self.workspace_id) {
                return Err(DomainError::CrossWorkspaceComposition { field });
            }
        }
        Ok(())
    }

    /// True when this recorded outcome permits proceeding toward trust.
    #[must_use]
    pub fn allows_trust(&self) -> bool {
        self.status == QuarantineStatus::Clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(status: QuarantineStatus) -> QuarantineRecord {
        QuarantineRecord::new(
            WorkspaceId::new(),
            UploadIntentId::new(),
            status,
            "clamav-scanner",
            Some("1.3.0".to_string()),
            if status == QuarantineStatus::Clean {
                None
            } else {
                Some("EICAR".to_string())
            },
            None,
            None,
            Utc::now(),
            BoundedJson::new("threat", json!({})).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_closed_outcome_domain() {
        for raw in [
            "pending",
            "clean",
            "malware",
            "integrity_failed",
            "unsupported",
        ] {
            assert!(QuarantineStatus::parse(raw).is_ok());
        }
        for obsolete in ["quarantined", "released", "purged"] {
            assert!(QuarantineStatus::parse(obsolete).is_err());
        }
    }

    #[test]
    fn test_clean_alone_allows_trust() {
        assert!(record(QuarantineStatus::Clean).allows_trust());
        assert!(!record(QuarantineStatus::Malware).allows_trust());
        assert!(!record(QuarantineStatus::IntegrityFailed).allows_trust());
        assert!(!record(QuarantineStatus::Pending).allows_trust());
        assert!(!record(QuarantineStatus::Unsupported).allows_trust());
    }

    #[test]
    fn test_rescan_appends_new_pending_record() {
        let first = record(QuarantineStatus::Malware);
        let rescan = QuarantineRecord::for_rescan(
            &first,
            "clamav-scanner",
            Some("1.4.0".into()),
            Utc::now(),
        )
        .unwrap();
        assert_eq!(rescan.upload_intent_id, first.upload_intent_id);
        assert_eq!(rescan.status, QuarantineStatus::Pending);
        assert_ne!(rescan.id, first.id);
    }

    #[test]
    fn test_labels_fail_closed() {
        assert!(
            QuarantineRecord::new(
                WorkspaceId::new(),
                UploadIntentId::new(),
                QuarantineStatus::Clean,
                "   ",
                None,
                None,
                None,
                None,
                Utc::now(),
                BoundedJson::empty()
            )
            .is_err()
        );
        assert!(
            QuarantineRecord::new(
                WorkspaceId::new(),
                UploadIntentId::new(),
                QuarantineStatus::Malware,
                "clamav-scanner",
                None,
                Some("x".repeat(MAX_REASON_CODE_BYTES + 1)),
                None,
                None,
                Utc::now(),
                BoundedJson::empty()
            )
            .is_err()
        );
    }
}
