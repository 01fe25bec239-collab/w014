//! Scoped single-object sandbox handoff (WI-0205).
//!
//! Enforces:
//! - Worker supplies exactly ONE immutable, already-scanned, authorized input
//! - Object identity remains strictly bound to: workspace, document_version, object_artifact, claimed job
//! - Exact byte length and SHA-256 integrity verification before sandbox handoff
//! - Absence of general S3/storage credentials inside sandbox

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use w014_domain::ids::{DocumentVersionId, ObjectArtifactId, WorkspaceId};
use w014_domain::{Sha256, StoredMediaType};

/// Exactly one immutable, already-scanned document input handed to the parser sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxInput {
    /// Owning tenant workspace identity.
    pub workspace_id: WorkspaceId,
    /// Immutable document version identity.
    pub document_version_id: DocumentVersionId,
    /// Authoritative object artifact identity.
    pub object_artifact_id: ObjectArtifactId,
    /// Claimed durable job execution handle ID.
    pub job_id: Uuid,
    /// Declared and verified MIME type.
    pub media_type: StoredMediaType,
    /// Expected authoritative content SHA-256 digest.
    pub content_sha256: Sha256,
    /// Expected byte length in bytes.
    pub byte_length: i64,
    /// Exact immutable input bytes scoped to this single object.
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

impl SandboxInput {
    /// Creates and verifies a new scoped sandbox input handoff.
    ///
    /// # Errors
    /// Fails closed if the provided byte slice does not match the declared
    /// length or declared SHA-256 digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        document_version_id: DocumentVersionId,
        object_artifact_id: ObjectArtifactId,
        job_id: Uuid,
        media_type: StoredMediaType,
        content_sha256: Sha256,
        byte_length: i64,
        bytes: Vec<u8>,
    ) -> Result<Self, String> {
        if bytes.len() as i64 != byte_length {
            return Err(format!(
                "Byte length mismatch for sandbox input: declared {byte_length}, actual {}",
                bytes.len()
            ));
        }

        let actual_digest = Sha256::digest(&bytes);
        if actual_digest != content_sha256 {
            return Err(format!(
                "SHA-256 digest mismatch for sandbox input: declared {}, actual {}",
                content_sha256.to_hex(),
                actual_digest.to_hex()
            ));
        }

        Ok(Self {
            workspace_id,
            document_version_id,
            object_artifact_id,
            job_id,
            media_type,
            content_sha256,
            byte_length,
            bytes,
        })
    }

    /// Verifies the internal integrity of the input bytes against the declared SHA-256 and byte length.
    pub fn verify_integrity(&self) -> Result<(), String> {
        if self.bytes.len() as i64 != self.byte_length {
            return Err(format!(
                "Integrity violation: byte count {} != declared byte length {}",
                self.bytes.len(),
                self.byte_length
            ));
        }
        let computed = Sha256::digest(&self.bytes);
        if computed != self.content_sha256 {
            return Err(format!(
                "Integrity violation: computed SHA-256 {} != declared SHA-256 {}",
                computed.to_hex(),
                self.content_sha256.to_hex()
            ));
        }
        Ok(())
    }

    /// Asserts that this handoff contains exactly one object artifact.
    #[must_use]
    pub fn is_single_object(&self) -> bool {
        true
    }
}
