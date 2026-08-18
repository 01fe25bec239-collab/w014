//! Error types for worker lifecycle and runner execution.

use thiserror::Error;

/// Errors that can occur during worker process lifecycle and execution.
#[derive(Debug, Error)]
pub enum WorkerError {
    /// Failure during worker configuration parsing or validation.
    #[error("worker configuration error: {0}")]
    Configuration(String),

    /// Failure during worker startup or initialization.
    #[error("worker initialization error: {0}")]
    Initialization(String),

    /// Failure during worker runtime execution.
    #[error("worker runtime error: {0}")]
    Runtime(String),

    /// Failure during shutdown orchestration or cleanup.
    #[error("worker shutdown error: {0}")]
    Shutdown(String),

    /// Failure in signal listening or communication channel.
    #[error("worker signal error: {0}")]
    Signal(String),
}
