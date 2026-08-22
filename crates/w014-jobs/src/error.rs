//! Error types for worker lifecycle, runner execution, and the durable job runtime.

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

/// Meaningful, typed failures of the PostgreSQL durable job runtime.
///
/// Variants deliberately distinguish runtime conditions so callers (and tests)
/// can prove stale-worker rejection, dependency blocking, terminal-state
/// protection, and retry exhaustion without string matching.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JobError {
    /// Queue/runtime configuration problem.
    #[error("job queue configuration error: {0}")]
    Configuration(String),

    /// PostgreSQL persistence failure.
    #[error("job queue database error: {0}")]
    Database(String),

    /// The supplied job kind is outside the closed W2 vocabulary.
    #[error("invalid job kind: {0}")]
    InvalidJobKind(String),

    /// The payload violates the bounded, secret-free payload contract.
    #[error("invalid job payload: {0}")]
    InvalidPayload(String),

    /// A referenced job does not exist inside the caller's workspace scope.
    #[error("workspace violation: {0}")]
    WorkspaceViolation(String),

    /// No job satisfied the frozen claim predicate at this moment.
    #[error("no claimable job")]
    NotClaimable,

    /// A required predecessor has not reached `succeeded`.
    #[error(
        "dependency unsatisfied for job {job_id}: predecessor status is '{predecessor_status}'"
    )]
    DependencyUnsatisfied {
        /// Dependent job id.
        job_id: uuid::Uuid,
        /// Observed blocking predecessor status text.
        predecessor_status: String,
    },

    /// The calling worker no longer holds current valid execution authority
    /// (lease expired/superseded, wrong attempt, or fenced generation).
    #[error("lease lost: stale execution authority rejected ({0})")]
    LeaseLost(String),

    /// The job already reached a terminal status; it cannot legally reopen.
    #[error("job {job_id} is already terminal with status '{status}'")]
    AlreadyTerminal {
        /// Job id inspected.
        job_id: uuid::Uuid,
        /// Current terminal status text.
        status: String,
    },

    /// Retry budget is exhausted; the only legal continuation is dead-letter.
    #[error("retry exhausted for job {0}")]
    RetryExhausted(uuid::Uuid),

    /// Progress sequence is duplicate or non-monotonic under the frozen contract.
    #[error("progress sequence conflict: {0}")]
    ProgressSequenceConflict(String),

    /// Bounded JSON serialization/redaction failure.
    #[error("payload serialization error: {0}")]
    Serialization(String),
}

impl From<sqlx::Error> for JobError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err.to_string())
    }
}
