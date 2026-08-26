//! Upload-intent prerequisite semantics (M002R `upload_intents`).
//!
//! Implements only the frozen domain/persistence prerequisites: workspace
//! scoping, optional existing-document binding (NULL means a future new
//! logical document), server-controlled opaque object keys, frozen expected
//! media-type allowlist, 1..100 MiB declared length, optional canonical
//! base64 SHA-256 declaration, creator identity, expiry <= 10 minutes,
//! one-way finalized/abandoned terminal markers. No presigned PUT, S3
//! workflow, finalize behavior, or scan/parse enqueue behavior belongs here.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::ids::{DocumentId, ObjectArtifactId, PrincipalId, UploadIntentId, WorkspaceId};
use crate::limits::{MAX_FILENAME_BYTES, MAX_INTENT_TTL_SECS, MAX_UPLOAD_BYTES, MIN_UPLOAD_BYTES};
use crate::media::MediaType;
use crate::object_artifacts::ObjectKey;
use crate::sha256::Sha256;
use crate::validation::validate_bounded_non_empty;

/// Frozen upload-intent status domain (matches physical CHECK vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentStatus {
    /// Created; awaiting upload.
    Initiated,
    /// Bytes uploaded to the server-owned object key.
    Uploaded,
    /// Verified against declarations and finalized.
    Verified,
    /// Expired unused.
    Expired,
    /// Abandoned by the creator.
    Aborted,
}

impl IntentStatus {
    /// Canonical physical representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Initiated => "initiated",
            Self::Uploaded => "uploaded",
            Self::Verified => "verified",
            Self::Expired => "expired",
            Self::Aborted => "aborted",
        }
    }

    /// Parses a stored status into the closed domain; fails closed.
    ///
    /// # Errors
    /// Fails closed for unknown vocabulary.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "initiated" => Ok(Self::Initiated),
            "uploaded" => Ok(Self::Uploaded),
            "verified" => Ok(Self::Verified),
            "expired" => Ok(Self::Expired),
            "aborted" => Ok(Self::Aborted),
            other => Err(DomainError::ValidationError {
                field: "intent_status",
                reason: format!("'{other}' is not in the closed intent-status domain"),
            }),
        }
    }

    /// True for one-way terminal statuses (`verified` | `expired` | `aborted`).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Verified | Self::Expired | Self::Aborted)
    }
}

/// Authoritative domain representation of an upload-intent prerequisite row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadIntent {
    pub id: UploadIntentId,
    pub workspace_id: WorkspaceId,
    pub created_by: PrincipalId,
    /// `None` means the upload targets a future NEW logical document.
    pub document_id: Option<DocumentId>,
    pub filename: String,
    /// Frozen allowlist declaration.
    pub expected_media_type: MediaType,
    /// Declared length 1..100 MiB.
    pub expected_length: i64,
    /// Optional declared content digest (canonical base64 on the wire).
    pub expected_sha256_b64: Option<Sha256>,
    /// Immutable once registered; workspace-bound by construction.
    pub object_artifact_id: Option<ObjectArtifactId>,
    /// Server-controlled opaque key; clients never choose object authority.
    pub opaque_object_key: ObjectKey,
    pub status: IntentStatus,
    pub expires_at: DateTime<Utc>,
    /// One-way marker: present exactly when status is `verified`.
    pub finalized_at: Option<DateTime<Utc>>,
    /// One-way marker: present exactly when status is `aborted`.
    pub abandoned_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl UploadIntent {
    /// Creates a new initiated intent with a server-minted opaque key.
    ///
    /// # Errors
    /// Fails closed on out-of-bound lengths, over-bound filenames, missing
    /// expiry, or expiry beyond the frozen 10-minute horizon.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        created_by: PrincipalId,
        document_id: Option<DocumentId>,
        filename: impl AsRef<str>,
        expected_media_type: MediaType,
        expected_length: i64,
        expected_sha256_b64: Option<Sha256>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        let created_at = Utc::now();
        let filename =
            validate_bounded_non_empty("filename", filename.as_ref(), MAX_FILENAME_BYTES)?
                .to_string();
        if !(MIN_UPLOAD_BYTES..=MAX_UPLOAD_BYTES).contains(&expected_length) {
            return Err(DomainError::ValidationError {
                field: "expected_length",
                reason: format!(
                    "declared length {expected_length} outside frozen 1..100 MiB bound"
                ),
            });
        }
        let ttl_secs = expires_at.signed_duration_since(created_at).num_seconds();
        if ttl_secs <= 0 {
            return Err(DomainError::ValidationError {
                field: "expires_at",
                reason: "expiry must be after creation".to_string(),
            });
        }
        if ttl_secs > MAX_INTENT_TTL_SECS {
            return Err(DomainError::ValidationError {
                field: "expires_at",
                reason: format!("intent lifetime {ttl_secs}s exceeds the 10-minute horizon"),
            });
        }
        Ok(Self {
            id: UploadIntentId::new(),
            workspace_id,
            created_by,
            document_id,
            filename,
            expected_media_type,
            expected_length,
            expected_sha256_b64,
            object_artifact_id: None,
            opaque_object_key: ObjectKey::generate_server_key("upload-intents"),
            status: IntentStatus::Initiated,
            expires_at,
            finalized_at: None,
            abandoned_at: None,
            created_at,
        })
    }

    /// Reconstructs an intent from persistent storage, fail-closed. All facts
    /// come from the stored row itself.
    ///
    /// # Errors
    /// Fails closed on violated declaration bounds, marker/status
    /// contradictions, or post-terminal resurrection.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: UploadIntentId,
        workspace_id: WorkspaceId,
        created_by: PrincipalId,
        document_id: Option<DocumentId>,
        filename: String,
        expected_media_type: MediaType,
        expected_length: i64,
        expected_sha256_b64: Option<Sha256>,
        object_artifact_id: Option<ObjectArtifactId>,
        opaque_object_key: ObjectKey,
        status: IntentStatus,
        expires_at: DateTime<Utc>,
        finalized_at: Option<DateTime<Utc>>,
        abandoned_at: Option<DateTime<Utc>>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        validate_bounded_non_empty("filename", &filename, MAX_FILENAME_BYTES)?;
        if !(MIN_UPLOAD_BYTES..=MAX_UPLOAD_BYTES).contains(&expected_length) {
            return Err(DomainError::ValidationError {
                field: "expected_length",
                reason: format!(
                    "declared length {expected_length} outside frozen 1..100 MiB bound"
                ),
            });
        }
        // Marker/status agreement mirrors the physical marker CHECKs.
        if (status == IntentStatus::Verified) != finalized_at.is_some() {
            return Err(DomainError::ValidationError {
                field: "finalized_at",
                reason: "verified status requires finalized_at and nothing else does".to_string(),
            });
        }
        if (status == IntentStatus::Aborted) != abandoned_at.is_some() {
            return Err(DomainError::ValidationError {
                field: "abandoned_at",
                reason: "aborted status requires abandoned_at and nothing else does".to_string(),
            });
        }
        if finalized_at.is_some() && abandoned_at.is_some() {
            return Err(DomainError::ValidationError {
                field: "finalized_at",
                reason: "finalized and abandoned markers are mutually exclusive".to_string(),
            });
        }
        if expires_at <= created_at {
            return Err(DomainError::ValidationError {
                field: "expires_at",
                reason: "stored expiry must be after creation".to_string(),
            });
        }
        Ok(Self {
            id,
            workspace_id,
            created_by,
            document_id,
            filename,
            expected_media_type,
            expected_length,
            expected_sha256_b64,
            object_artifact_id,
            opaque_object_key,
            status,
            expires_at,
            finalized_at,
            abandoned_at,
            created_at,
        })
    }

    /// Advances `initiated` -> `uploaded`. Declaration fields never move.
    ///
    /// # Errors
    /// Fails outside the frozen progression or from terminal states.
    pub fn mark_uploaded(&mut self) -> Result<(), DomainError> {
        self.transition(IntentStatus::Uploaded)
    }

    /// Binds the uploaded object artifact exactly once; immutable afterwards.
    ///
    /// # Errors
    /// Fails when already bound or the intent reached a terminal state.
    pub fn bind_object_artifact(
        &mut self,
        artifact_id: ObjectArtifactId,
        artifact_workspace_id: WorkspaceId,
    ) -> Result<(), DomainError> {
        if artifact_workspace_id != self.workspace_id {
            return Err(DomainError::CrossWorkspaceComposition {
                field: "upload_intent.object_artifact_id",
            });
        }
        if self.status.is_terminal() {
            return Err(DomainError::IllegalStateTransition {
                from: self.status.as_str().to_string(),
                to: self.status.as_str().to_string(),
                reason: "terminal intents can no longer bind artifacts".to_string(),
            });
        }
        if self.object_artifact_id.replace(artifact_id).is_some() {
            return Err(DomainError::IllegalStateTransition {
                from: "bound".to_string(),
                to: "rebound".to_string(),
                reason: "object-artifact binding is immutable once registered".to_string(),
            });
        }
        Ok(())
    }

    /// One-way finalize: `verified` with `finalized_at` set.
    ///
    /// # Errors
    /// Fails when not in `uploaded` state.
    pub fn finalize_verified(&mut self, at: DateTime<Utc>) -> Result<(), DomainError> {
        self.expect_uploaded()?;
        self.finalized_at = Some(at.max(self.created_at));
        self.status = IntentStatus::Verified;
        Ok(())
    }

    /// One-way abandon: `aborted` with `abandoned_at` set.
    ///
    /// # Errors
    /// Fails from any state except `initiated`/`uploaded`.
    pub fn abandon(&mut self, at: DateTime<Utc>) -> Result<(), DomainError> {
        if self.status == IntentStatus::Uploaded || self.status == IntentStatus::Initiated {
            self.abandoned_at = Some(at.max(self.created_at));
            self.status = IntentStatus::Aborted;
            return Ok(());
        }
        Err(DomainError::IllegalStateTransition {
            from: self.status.as_str().to_string(),
            to: IntentStatus::Aborted.as_str().to_string(),
            reason: "only initiated/uploaded intents may be abandoned".to_string(),
        })
    }

    /// Expiry sweep for non-terminal intents.
    ///
    /// # Errors
    /// Fails when the intent has not actually expired at `at`.
    pub fn mark_expired(&mut self, at: DateTime<Utc>) -> Result<(), DomainError> {
        if !self.is_expired_at(at) {
            return Err(DomainError::IllegalStateTransition {
                from: self.status.as_str().to_string(),
                to: IntentStatus::Expired.as_str().to_string(),
                reason: "intent has not expired yet".to_string(),
            });
        }
        if self.status.is_terminal() {
            return Err(DomainError::IllegalStateTransition {
                from: self.status.as_str().to_string(),
                to: IntentStatus::Expired.as_str().to_string(),
                reason: "terminal intents are one-way".to_string(),
            });
        }
        self.status = IntentStatus::Expired;
        Ok(())
    }

    /// True when the intent's expiry instant has passed.
    #[must_use]
    pub fn is_expired_at(&self, at: DateTime<Utc>) -> bool {
        at > self.expires_at
    }

    fn expect_uploaded(&self) -> Result<(), DomainError> {
        if self.status != IntentStatus::Uploaded {
            return Err(DomainError::IllegalStateTransition {
                from: self.status.as_str().to_string(),
                to: IntentStatus::Verified.as_str().to_string(),
                reason: "only uploaded intents can be finalized verified".to_string(),
            });
        }
        Ok(())
    }

    fn transition(&mut self, next: IntentStatus) -> Result<(), DomainError> {
        let allowed = matches!(
            (self.status, next),
            (IntentStatus::Initiated, IntentStatus::Uploaded)
        );
        if !allowed {
            return Err(DomainError::IllegalStateTransition {
                from: self.status.as_str().to_string(),
                to: next.as_str().to_string(),
                reason: "transition violates the frozen intent progression".to_string(),
            });
        }
        self.status = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn within_ttl() -> DateTime<Utc> {
        Utc::now() + Duration::seconds(300)
    }

    fn new_intent() -> UploadIntent {
        UploadIntent::new(
            WorkspaceId::new(),
            PrincipalId::new(),
            None,
            "report.pdf",
            MediaType::ApplicationPdf,
            2048,
            None,
            within_ttl(),
        )
        .unwrap()
    }

    #[test]
    fn test_valid_and_invalid_construction() {
        let intent = new_intent();
        assert_eq!(intent.status, IntentStatus::Initiated);
        assert_eq!(intent.document_id, None);
        assert_eq!(intent.finalized_at, None);
        assert_eq!(intent.abandoned_at, None);
        // Server minted the key; client never chose it.
        assert!(
            intent
                .opaque_object_key
                .as_str()
                .starts_with("upload-intents/")
        );

        // Over-horizon TTL rejected (>10 minutes; generous margin avoids
        // clock-skew flakiness).
        assert!(
            UploadIntent::new(
                WorkspaceId::new(),
                PrincipalId::new(),
                None,
                "late.pdf",
                MediaType::ApplicationPdf,
                10,
                None,
                Utc::now() + Duration::seconds(3600),
            )
            .is_err()
        );

        // Zero-length and oversize declarations rejected.
        assert!(
            UploadIntent::new(
                WorkspaceId::new(),
                PrincipalId::new(),
                None,
                "zero.pdf",
                MediaType::ApplicationPdf,
                0,
                None,
                within_ttl()
            )
            .is_err()
        );
        assert!(
            UploadIntent::new(
                WorkspaceId::new(),
                PrincipalId::new(),
                None,
                "big.pdf",
                MediaType::ApplicationPdf,
                MAX_UPLOAD_BYTES + 1,
                None,
                within_ttl()
            )
            .is_err()
        );
    }

    #[test]
    fn test_one_way_finalize_abandon_and_expiry() {
        let mut intent = new_intent();
        intent.mark_uploaded().unwrap();
        intent.finalize_verified(Utc::now()).unwrap();
        assert_eq!(intent.status, IntentStatus::Verified);
        assert!(intent.finalized_at.is_some());
        // Terminal: no further movement.
        assert!(intent.abandon(Utc::now()).is_err());
        assert!(intent.mark_expired(Utc::now()).is_err());

        let mut second = new_intent();
        second.abandon(Utc::now()).unwrap();
        assert_eq!(second.status, IntentStatus::Aborted);
        assert!(second.abandoned_at.is_some());
        assert!(second.mark_uploaded().is_err());

        let mut third = new_intent();
        assert!(third.mark_expired(third.expires_at).is_err());
        third
            .mark_expired(third.expires_at + Duration::milliseconds(1))
            .unwrap();
        assert_eq!(third.status, IntentStatus::Expired);
    }

    #[test]
    fn test_artifact_binding_immutable_once_and_workspace_bound() {
        let ws = WorkspaceId::new();
        let mut intent = UploadIntent::new(
            ws,
            PrincipalId::new(),
            None,
            "bind.pdf",
            MediaType::ApplicationPdf,
            128,
            None,
            within_ttl(),
        )
        .unwrap();
        let artifact = ObjectArtifactId::new();
        intent.bind_object_artifact(artifact, ws).unwrap();
        assert_eq!(intent.object_artifact_id, Some(artifact));
        // Rebinding rejected.
        assert!(
            intent
                .bind_object_artifact(ObjectArtifactId::new(), ws)
                .is_err()
        );
        // Foreign-workspace binding rejected.
        assert!(
            intent
                .bind_object_artifact(ObjectArtifactId::new(), WorkspaceId::new())
                .is_err()
        );
    }

    #[test]
    fn test_declaration_digest_travels_as_canonical_base64() {
        let digest = Sha256::digest(b"declared bytes");
        let intent = UploadIntent::new(
            WorkspaceId::new(),
            PrincipalId::new(),
            Some(DocumentId::new()),
            "digest.pdf",
            MediaType::Docx,
            4096,
            Some(digest),
            within_ttl(),
        )
        .unwrap();
        assert_eq!(intent.expected_sha256_b64, Some(digest));
        assert_eq!(digest.to_base64().len(), 44);
    }
}
