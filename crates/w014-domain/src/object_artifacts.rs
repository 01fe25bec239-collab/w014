//! Object-artifact semantics (M002R `object_artifacts`).
//!
//! A workspace-scoped immutable object registry: frozen artifact kinds,
//! server-owned object keys, exact 32-byte content digests, non-negative
//! byte lengths, SSE posture, optional KMS identifier, and insert-only
//! authoritative facts. The object key authority is server side; clients
//! never compose storage paths.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;
use crate::ids::{ObjectArtifactId, WorkspaceId};
use crate::limits::MAX_OBJECT_KEY_BYTES;
use crate::media::StoredMediaType;
use crate::sha256::Sha256;
use crate::validation::validate_bounded_non_empty;

/// Frozen artifact-kind domain (matches physical CHECK vocabulary).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ArtifactKind {
    RawUpload,
    Ocr,
    Parser,
    PagePreview,
    ReportJson,
    ReportPdf,
    Temp,
    /// Superseded legacy variants for backward compatibility
    Original,
    Derived,
}

impl PartialEq for ArtifactKind {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for ArtifactKind {}

impl std::hash::Hash for ArtifactKind {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl ArtifactKind {
    /// Canonical physical representation matching Prompt-12 schema CHECK constraint.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RawUpload | Self::Original => "raw_upload",
            Self::Ocr => "ocr",
            Self::Parser | Self::Derived => "parser",
            Self::PagePreview => "page_preview",
            Self::ReportJson => "report_json",
            Self::ReportPdf => "report_pdf",
            Self::Temp => "temp",
        }
    }

    /// Parses a stored kind into the closed domain; fails closed.
    ///
    /// # Errors
    /// Fails closed for unknown vocabulary.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "raw_upload" | "original" => Ok(Self::RawUpload),
            "ocr" => Ok(Self::Ocr),
            "parser" | "derived" => Ok(Self::Parser),
            "page_preview" => Ok(Self::PagePreview),
            "report_json" => Ok(Self::ReportJson),
            "report_pdf" => Ok(Self::ReportPdf),
            "temp" => Ok(Self::Temp),
            other => Err(DomainError::ValidationError {
                field: "artifact_kind",
                reason: format!("'{other}' is not in the closed artifact-kind domain"),
            }),
        }
    }
}

/// Frozen storage-tier domain (matches physical CHECK vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageTier {
    Hot,
    Warm,
    Cold,
    Archive,
}

impl StorageTier {
    /// Canonical physical representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Warm => "warm",
            Self::Cold => "cold",
            Self::Archive => "archive",
        }
    }

    /// Parses a stored tier into the closed domain; fails closed.
    ///
    /// # Errors
    /// Fails closed for unknown vocabulary.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "hot" => Ok(Self::Hot),
            "warm" => Ok(Self::Warm),
            "cold" => Ok(Self::Cold),
            "archive" => Ok(Self::Archive),
            other => Err(DomainError::ValidationError {
                field: "storage_tier",
                reason: format!("'{other}' is not in the closed storage-tier domain"),
            }),
        }
    }
}

/// Frozen SSE posture domain (matches physical `sse_mode` CHECK vocabulary).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EncryptionMode {
    AwsKms,
    Local,
    None,
    SseAes256,
}

pub type SseMode = EncryptionMode;

impl PartialEq for EncryptionMode {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for EncryptionMode {}

impl std::hash::Hash for EncryptionMode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl EncryptionMode {
    /// Canonical physical representation matching Prompt-12 sse_mode CHECK constraint.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AwsKms | Self::SseAes256 => "aws:kms",
            Self::Local | Self::None => "local",
        }
    }

    /// Parses a stored SSE mode into the closed domain; fails closed.
    ///
    /// # Errors
    /// Fails closed for unknown vocabulary.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "aws:kms" | "sse_aes256" => Ok(Self::AwsKms),
            "local" | "none" => Ok(Self::Local),
            other => Err(DomainError::ValidationError {
                field: "sse_mode",
                reason: format!("'{other}' is not in the closed sse-mode domain"),
            }),
        }
    }
}

/// Server-controlled opaque storage key.
///
/// Shape mirrors the physical CHECK exactly: printable ASCII (`[!-~]+`),
/// at most 1024 bytes, no leading `/`, no `//` segment, and no `..`
/// traversal. Keys are minted by the server
/// ([`ObjectKey::generate_server_key`]); client-chosen keys are never an
/// authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectKey(String);

impl ObjectKey {
    /// Mints a fresh server-owned key under the given prefix:
    /// `{prefix}/{uuid}` — traversal-proof by construction.
    #[must_use]
    pub fn generate_server_key(prefix: &str) -> Self {
        Self(format!("{prefix}/{}", Uuid::new_v4().simple()))
    }

    /// Validates and wraps a stored key against the frozen shape.
    ///
    /// # Errors
    /// Fails closed on any shape violation (empty, oversized, whitespace,
    /// leading slash, double slash, or `..` traversal).
    pub fn reconstruct(raw: impl Into<String>) -> Result<Self, DomainError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(DomainError::EmptyField("object_key"));
        }
        if raw.len() > MAX_OBJECT_KEY_BYTES {
            return Err(DomainError::ValidationError {
                field: "object_key",
                reason: format!("key length {} exceeds 1024", raw.len()),
            });
        }
        if !raw.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
            return Err(DomainError::ValidationError {
                field: "object_key",
                reason: "key must be printable ASCII without spaces".to_string(),
            });
        }
        if raw.starts_with('/') || raw.contains("//") || raw.contains("..") {
            return Err(DomainError::ValidationError {
                field: "object_key",
                reason: "key must not start with '/', contain '//', or contain '..'".to_string(),
            });
        }
        Ok(Self(raw))
    }

    /// The validated key string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Authoritative domain representation of one immutable stored-object fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectArtifact {
    pub id: ObjectArtifactId,
    pub workspace_id: WorkspaceId,
    pub kind: ArtifactKind,
    pub bucket: String,
    /// Server-owned key; display/authority boundary preserved.
    pub key: ObjectKey,
    /// Exact content digest: always 32 bytes.
    pub content_sha256: Sha256,
    /// Non-negative stored byte length.
    pub byte_length: i64,
    /// Retained media type (inert data).
    pub media_type: StoredMediaType,
    pub tier: StorageTier,
    /// SSE posture.
    pub encryption: EncryptionMode,
    /// Optional KMS key reference.
    pub kms_key_ref: Option<String>,
    pub retention_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl ObjectArtifact {
    /// Registers a new immutable object fact with a server-minted key.
    ///
    /// # Errors
    /// Fails closed on negative lengths or over-bound bucket names.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        kind: ArtifactKind,
        bucket: impl AsRef<str>,
        media_type: StoredMediaType,
        content_sha256: Sha256,
        byte_length: i64,
        tier: StorageTier,
        encryption: EncryptionMode,
        kms_key_ref: Option<String>,
    ) -> Result<Self, DomainError> {
        let now = Utc::now();
        Self::reconstruct_full(
            ObjectArtifactId::new(),
            workspace_id,
            kind,
            bucket.as_ref().to_string(),
            ObjectKey::generate_server_key("documents"),
            content_sha256,
            byte_length,
            media_type,
            tier,
            encryption,
            kms_key_ref,
            None,
            now,
        )
    }

    /// Builder method to set retention_until.
    #[must_use]
    pub fn with_retention_until(mut self, retention_until: Option<DateTime<Utc>>) -> Self {
        self.retention_until = retention_until;
        self
    }

    /// Reconstructs an object fact from persistent storage, fail-closed.
    /// Every fact comes from the stored row itself.
    ///
    /// # Errors
    /// Fails closed on violated bounds or shape invariants.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: ObjectArtifactId,
        workspace_id: WorkspaceId,
        kind: ArtifactKind,
        bucket: String,
        key: ObjectKey,
        content_sha256: Sha256,
        byte_length: i64,
        media_type: StoredMediaType,
        tier: StorageTier,
        encryption: EncryptionMode,
        kms_key_ref: Option<String>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        Self::reconstruct_full(
            id,
            workspace_id,
            kind,
            bucket,
            key,
            content_sha256,
            byte_length,
            media_type,
            tier,
            encryption,
            kms_key_ref,
            None,
            created_at,
        )
    }

    /// Reconstructs an object fact with full Prompt-12 fields including retention_until.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct_full(
        id: ObjectArtifactId,
        workspace_id: WorkspaceId,
        kind: ArtifactKind,
        bucket: String,
        key: ObjectKey,
        content_sha256: Sha256,
        byte_length: i64,
        media_type: StoredMediaType,
        tier: StorageTier,
        encryption: EncryptionMode,
        kms_key_ref: Option<String>,
        retention_until: Option<DateTime<Utc>>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        validate_bounded_non_empty("storage_bucket", &bucket, MAX_OBJECT_KEY_BYTES)?;
        if byte_length < 0 {
            return Err(DomainError::ValidationError {
                field: "byte_length",
                reason: format!("byte length must be non-negative, got {byte_length}"),
            });
        }
        if let Some(kms) = &kms_key_ref {
            validate_bounded_non_empty("kms_key_ref", kms, MAX_OBJECT_KEY_BYTES)?;
        }
        Ok(Self {
            id,
            workspace_id,
            kind,
            bucket,
            key,
            content_sha256,
            byte_length,
            media_type,
            tier,
            encryption,
            kms_key_ref,
            retention_until,
            created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ObjectArtifact {
        ObjectArtifact::new(
            WorkspaceId::new(),
            ArtifactKind::Original,
            "w014-bucket",
            StoredMediaType::new("application/pdf").unwrap(),
            Sha256::digest(b"artifact bytes"),
            4096,
            StorageTier::Hot,
            EncryptionMode::SseAes256,
            Some("arn:aws:kms:us-east-1:1:key/abc".to_string()),
        )
        .unwrap()
    }

    #[test]
    fn test_server_minted_key_shape_and_authority() {
        let artifact = fixture();
        assert!(artifact.key.as_str().starts_with("documents/"));
        assert_eq!(artifact.encryption, EncryptionMode::SseAes256);
        assert_eq!(artifact.encryption.as_str(), "aws:kms");
        assert!(artifact.kms_key_ref.is_some());
    }

    #[test]
    fn test_client_traversal_keys_fail_closed() {
        for bad in [
            "../escape",
            "/leading-slash",
            "double//slash",
            "has space",
            "trailing\nnewline",
        ] {
            assert!(ObjectKey::reconstruct(bad).is_err(), "{bad} must fail");
        }
        let big = format!("documents/{}", "x".repeat(MAX_OBJECT_KEY_BYTES));
        assert!(ObjectKey::reconstruct(big).is_err());
        assert!(ObjectKey::reconstruct("documents/ok-key-1").is_ok());
    }

    #[test]
    fn test_negative_byte_length_rejected() {
        let now = Utc::now();
        assert!(
            ObjectArtifact::reconstruct(
                ObjectArtifactId::new(),
                WorkspaceId::new(),
                ArtifactKind::Derived,
                "bucket".to_string(),
                ObjectKey::reconstruct("derived/x").unwrap(),
                Sha256::digest(b"x"),
                -1,
                StoredMediaType::new("text/plain").unwrap(),
                StorageTier::Cold,
                EncryptionMode::None,
                None,
                now,
            )
            .is_err()
        );
    }

    #[test]
    fn test_closed_domains() {
        assert!(ArtifactKind::parse("replica").is_err());
        assert!(StorageTier::parse("ludicrous").is_err());
        assert!(EncryptionMode::parse("envelope").is_err());
        assert_eq!(ArtifactKind::RawUpload.as_str(), "raw_upload");
        assert_eq!(ArtifactKind::Original.as_str(), "raw_upload");
        assert_eq!(ArtifactKind::Parser.as_str(), "parser");
        assert_eq!(EncryptionMode::AwsKms.as_str(), "aws:kms");
        assert_eq!(EncryptionMode::SseAes256.as_str(), "aws:kms");
        assert_eq!(EncryptionMode::Local.as_str(), "local");
        assert_eq!(EncryptionMode::None.as_str(), "local");
    }
}
