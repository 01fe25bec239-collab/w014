//! w014-jobs: Worker process lifecycle, runner foundation, and the minimum real
//! W2 PostgreSQL durable job runtime.
//!
//! Provides the core worker process primitives for the w014 platform:
//! - Worker identity and configuration (`WorkerId`, `WorkerConfig`)
//! - Lifecycle management and state transitions (`WorkerState`, `WorkerLifecycle`)
//! - Cooperative shutdown signal handling (`ShutdownSignal`, `ShutdownTrigger`, `ShutdownReason`)
//! - Worker runner composition (`WorkerRunner`)
//! - Structured error types (`WorkerError`, `JobError`)
//!
//! W2 durable runtime (authoritative queue = PostgreSQL only):
//! - Frozen job status / attempt-outcome vocabularies (`status`)
//! - Closed non-AI W2 job kinds and canonical queue identities (`kind`)
//! - Canonical SHA-256 enqueue idempotency identity (`job_identity`)
//! - Bounded, secret-free payload contract (`payload`)
//! - Authoritative durable queue: enqueue / claim / lease / fencing /
//!   heartbeat / retry with bounded backoff / safe completion / dead letter /
//!   append-only progress / dependency enforcement (`queue`, `models`)
//! - Executor abstraction and graceful-shutdown poll loop (`executor`, `poller`)

pub mod config;
pub mod error;
pub mod executor;
pub mod identity;
pub mod job_identity;
pub mod kind;
pub mod lifecycle;
pub mod models;
pub mod payload;
pub mod poller;
pub mod queue;
pub mod runner;
pub mod signal;
pub mod status;

pub use config::WorkerConfig;
pub use error::{JobError, WorkerError};
pub use executor::{ExecutorRegistry, JobExecutionContext, JobExecutionFailure, JobExecutor};
pub use identity::WorkerId;
pub use job_identity::CanonicalJobIdentity;
pub use kind::{JobKind, QUEUE_DOCUMENT_PARSE, QUEUE_MALWARE_SCAN};
pub use lifecycle::{WorkerLifecycle, WorkerState};
pub use models::{
    AttemptRecord, BACKOFF_SCHEDULE_SECS, CancellationOutcome, ClaimCriteria, ClaimedJob,
    DeadLetterRecord, EnqueueOutcome, EnqueueParams, FROZEN_BACKOFF_MAX_SECS, FROZEN_MAX_ATTEMPTS,
    FailureKind, FailureResolution, JobRecord, ProgressEvent, WorkspaceScope,
    backoff_delay_secs_after,
};
pub use payload::JobPayload;
pub use poller::{DurableJobLoop, DurableJobLoopConfig};
pub use queue::PgJobQueue;
pub use runner::WorkerRunner;
pub use signal::{ShutdownReason, ShutdownSignal, ShutdownTrigger};
pub use status::{AttemptOutcome, JobStatus};
