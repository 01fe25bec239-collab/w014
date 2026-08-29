//! Typed bounded parser sandbox output contract (WI-0205).
//!
//! Enforces:
//! - Only typed, bounded results leave the sandbox
//! - Sandbox itself NEVER directly writes application databases or audit tables
//! - Worker-side Rust validation of protocol version, document identity, object identity,
//!   input hash, bounded payload size, and bounded counts
//! - Fail-closed rejection of any tampered, mismatched, or oversized output

use serde::{Deserialize, Serialize};
use w014_domain::ids::{DocumentVersionId, ObjectArtifactId};
use w014_domain::limits::MAX_PAGE_NUMBER;
use w014_domain::{LocatorVersion, Sha256};

use super::input::SandboxInput;

/// Canonical frozen protocol version for parser sandbox execution envelope.
pub const SANDBOX_PROTOCOL_VERSION: &str = "parser-sandbox-v1";

/// Maximum allowed page count in bounded output.
pub const MAX_BOUNDED_PAGE_COUNT: i32 = MAX_PAGE_NUMBER as i32;

/// Maximum allowed block count in bounded output.
pub const MAX_BOUNDED_BLOCK_COUNT: i32 = 500_000;

/// Maximum allowed span count in bounded output.
pub const MAX_BOUNDED_SPAN_COUNT: i32 = 1_000_000;

/// Maximum execution duration in milliseconds (10 minutes = 600,000 ms).
pub const MAX_EXECUTION_DURATION_MS: u64 = 600_000;

/// Closed outcome vocabulary for sandbox execution result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxStatus {
    /// Document was parsed successfully within bounded limits.
    Success,
    /// Document format or feature set is unsupported.
    Unsupported,
    /// Document bytes are corrupted / malformed at parse time.
    Corrupted,
    /// Parser process encountered a terminal internal failure.
    Failed,
}

impl SandboxStatus {
    /// String representation matching schema vocabulary.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Unsupported => "unsupported",
            Self::Corrupted => "corrupted",
            Self::Failed => "failed",
        }
    }

    /// Parses status string into closed enum.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "success" => Ok(Self::Success),
            "unsupported" => Ok(Self::Unsupported),
            "corrupted" => Ok(Self::Corrupted),
            "failed" => Ok(Self::Failed),
            other => Err(format!("Unknown sandbox status: '{other}'")),
        }
    }
}

/// Typed, bounded output produced by the parser sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxOutput {
    /// Protocol contract version (must match `SANDBOX_PROTOCOL_VERSION`).
    pub protocol_version: String,
    /// Bound document version identity (must match input).
    pub document_version_id: DocumentVersionId,
    /// Bound object artifact identity (must match input).
    pub object_artifact_id: ObjectArtifactId,
    /// SHA-256 digest of input bytes (must match input).
    pub input_sha256: Sha256,
    /// Execution status outcome.
    pub status: SandboxStatus,
    /// Name of parser engine used.
    pub parser_name: String,
    /// Version of parser engine used.
    pub parser_version: String,
    /// Canonical locator algorithm identity.
    pub locator_version: LocatorVersion,
    /// Total pages processed (bounded).
    pub page_count: i32,
    /// Total structural blocks extracted (bounded).
    pub block_count: i32,
    /// Total source spans recorded (bounded).
    pub span_count: i32,
    /// Full-text SHA-256 digest if available.
    pub text_sha256: Option<Sha256>,
    /// Execution duration in milliseconds.
    pub execution_duration_ms: u64,
    /// Machine-readable failure code when status is not Success.
    pub failure_code: Option<String>,
    /// Diagnostic failure detail when status is not Success.
    pub failure_detail: Option<String>,
}

/// Errors occurring during worker-side output validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutputValidationError {
    #[error("Protocol version mismatch: expected '{expected}', got '{actual}'")]
    ProtocolMismatch { expected: String, actual: String },
    #[error("DocumentVersionId mismatch: expected '{expected}', got '{actual}'")]
    DocumentVersionMismatch {
        expected: DocumentVersionId,
        actual: DocumentVersionId,
    },
    #[error("ObjectArtifactId mismatch: expected '{expected}', got '{actual}'")]
    ObjectArtifactMismatch {
        expected: ObjectArtifactId,
        actual: ObjectArtifactId,
    },
    #[error("Input SHA-256 digest mismatch: expected '{expected}', got '{actual}'")]
    InputHashMismatch { expected: String, actual: String },
    #[error("Page count {actual} outside bounded range 0..={MAX_BOUNDED_PAGE_COUNT}")]
    PageCountOutOfBounds { actual: i32 },
    #[error("Block count {actual} outside bounded range 0..={MAX_BOUNDED_BLOCK_COUNT}")]
    BlockCountOutOfBounds { actual: i32 },
    #[error("Span count {actual} outside bounded range 0..={MAX_BOUNDED_SPAN_COUNT}")]
    SpanCountOutOfBounds { actual: i32 },
    #[error("Execution duration {actual}ms exceeds maximum limit {MAX_EXECUTION_DURATION_MS}ms")]
    DurationOutOfBounds { actual: u64 },
    #[error("Failed status requires non-empty failure_code")]
    MissingFailureCode,
    #[error("Invalid field '{field}': {reason}")]
    InvalidField { field: &'static str, reason: String },
}

impl SandboxOutput {
    /// Validates the sandbox output envelope against the original input and security bounds.
    ///
    /// # Errors
    /// Fails closed if any identity, checksum, bound, or protocol invariant is violated.
    pub fn validate_against_input(
        &self,
        input: &SandboxInput,
    ) -> Result<(), OutputValidationError> {
        if self.protocol_version != SANDBOX_PROTOCOL_VERSION {
            return Err(OutputValidationError::ProtocolMismatch {
                expected: SANDBOX_PROTOCOL_VERSION.to_string(),
                actual: self.protocol_version.clone(),
            });
        }

        if self.document_version_id != input.document_version_id {
            return Err(OutputValidationError::DocumentVersionMismatch {
                expected: input.document_version_id,
                actual: self.document_version_id,
            });
        }

        if self.object_artifact_id != input.object_artifact_id {
            return Err(OutputValidationError::ObjectArtifactMismatch {
                expected: input.object_artifact_id,
                actual: self.object_artifact_id,
            });
        }

        if self.input_sha256 != input.content_sha256 {
            return Err(OutputValidationError::InputHashMismatch {
                expected: input.content_sha256.to_hex(),
                actual: self.input_sha256.to_hex(),
            });
        }

        if self.page_count < 0 || self.page_count > MAX_BOUNDED_PAGE_COUNT {
            return Err(OutputValidationError::PageCountOutOfBounds {
                actual: self.page_count,
            });
        }

        if self.block_count < 0 || self.block_count > MAX_BOUNDED_BLOCK_COUNT {
            return Err(OutputValidationError::BlockCountOutOfBounds {
                actual: self.block_count,
            });
        }

        if self.span_count < 0 || self.span_count > MAX_BOUNDED_SPAN_COUNT {
            return Err(OutputValidationError::SpanCountOutOfBounds {
                actual: self.span_count,
            });
        }

        if self.execution_duration_ms > MAX_EXECUTION_DURATION_MS {
            return Err(OutputValidationError::DurationOutOfBounds {
                actual: self.execution_duration_ms,
            });
        }

        if self.parser_name.trim().is_empty() || self.parser_name.len() > 128 {
            return Err(OutputValidationError::InvalidField {
                field: "parser_name",
                reason: "parser_name must be non-empty and <= 128 chars".to_string(),
            });
        }

        if self.parser_version.trim().is_empty() || self.parser_version.len() > 128 {
            return Err(OutputValidationError::InvalidField {
                field: "parser_version",
                reason: "parser_version must be non-empty and <= 128 chars".to_string(),
            });
        }

        if self.status == SandboxStatus::Failed && self.failure_code.is_none() {
            return Err(OutputValidationError::MissingFailureCode);
        }

        Ok(())
    }
}
