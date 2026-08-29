//! Fail-closed parser sandbox error taxonomy (WI-0205).
//!
//! Enforces:
//! - Strict classification between transient/retryable conditions and permanent terminal failures
//! - Security violations (network access, privilege escalation, credential access) are strictly terminal
//! - Malformed / invalid output is fail-closed
//! - No silent success, no AI fallback, no unsandboxed fallback

use thiserror::Error;

use super::output::OutputValidationError;

/// Typed, fail-closed errors occurring during parser sandbox execution.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SandboxError {
    /// Sandbox process exceeded the wall-clock time limit.
    #[error("Sandbox execution timed out after {elapsed_secs}s (limit: {limit_secs}s)")]
    Timeout { elapsed_secs: u64, limit_secs: u64 },

    /// Sandbox process killed due to memory ceiling exhaustion (OOM).
    #[error("Sandbox execution killed due to Out-Of-Memory (OOM): {detail}")]
    OutOfMemory { detail: String },

    /// Sandbox exceeded resource limit (e.g., PID count, CPU limit, TMPFS limit).
    #[error("Sandbox resource ceiling exceeded for {resource} (limit {limit}): {detail}")]
    ResourceViolation {
        resource: String,
        limit: String,
        detail: String,
    },

    /// Sandbox process crashed (non-zero exit code or abnormal termination).
    #[error("Sandbox process crashed with exit code {exit_code:?}, signal {signal:?}: {stderr}")]
    ProcessCrash {
        exit_code: Option<i32>,
        signal: Option<i32>,
        stderr: String,
    },

    /// Sandbox attempted an unauthorized action (network egress, privilege escalation, file escape).
    #[error("Sandbox security violation ({violation_type}): {detail}")]
    SandboxViolation {
        violation_type: String,
        detail: String,
    },

    /// Output from sandbox is malformed, truncated, or invalid JSON.
    #[error("Malformed sandbox output: {detail}")]
    MalformedOutput { detail: String },

    /// Sandbox output violated schema bounds or identity invariants.
    #[error("Sandbox output validation failed: {0}")]
    OutputValidation(#[from] OutputValidationError),

    /// File I/O or pipe communication error.
    #[error("Sandbox I/O error: {detail}")]
    IO { detail: String },

    /// Internal runtime configuration error.
    #[error("Sandbox internal error: {detail}")]
    Internal { detail: String },
}

impl SandboxError {
    /// Returns whether this error condition is transient and eligible for bounded retry.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Timeout { .. } => true,
            Self::OutOfMemory { .. } => true,
            Self::ResourceViolation { .. } => true,
            Self::ProcessCrash { .. } => true,
            Self::IO { .. } => true,
            Self::SandboxViolation { .. } => false,
            Self::MalformedOutput { .. } => false,
            Self::OutputValidation(_) => false,
            Self::Internal { .. } => false,
        }
    }

    /// Machine-readable bounded error code (<= 128 chars).
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Timeout { .. } => "SANDBOX_TIMEOUT",
            Self::OutOfMemory { .. } => "SANDBOX_OOM",
            Self::ResourceViolation { .. } => "SANDBOX_RESOURCE_VIOLATION",
            Self::ProcessCrash { .. } => "SANDBOX_CRASH",
            Self::SandboxViolation { .. } => "SANDBOX_VIOLATION",
            Self::MalformedOutput { .. } => "SANDBOX_MALFORMED_OUTPUT",
            Self::OutputValidation(_) => "SANDBOX_OUTPUT_VALIDATION_FAILED",
            Self::IO { .. } => "SANDBOX_IO_ERROR",
            Self::Internal { .. } => "SANDBOX_INTERNAL_ERROR",
        }
    }
}
