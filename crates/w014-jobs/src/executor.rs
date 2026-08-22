//! Executor abstraction for durable W2 jobs.
//!
//! An executor performs the actual document malware-scan / parse work AFTER a
//! claim transaction has committed (never inside it). The runtime never
//! fabricates successful work: only kinds with a registered executor are ever
//! claimed, and failures are classified explicitly.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::JobError;
use crate::kind::JobKind;
use crate::models::{ClaimedJob, FailureKind, ProgressEvent};
use crate::queue::PgJobQueue;

/// Context handed to an executor for one claimed job execution.
///
/// Exposes fenced progress reporting and cancellation observation; all
/// authoritative state transitions still flow through [`PgJobQueue`].
pub struct JobExecutionContext {
    queue: PgJobQueue,
    handle: ClaimedJob,
}

impl JobExecutionContext {
    pub(crate) fn new(queue: PgJobQueue, handle: ClaimedJob) -> Self {
        Self { queue, handle }
    }

    /// The claimed job's execution authority coordinates.
    #[must_use]
    pub fn handle(&self) -> &ClaimedJob {
        &self.handle
    }

    /// Appends one durable stage-level progress event under the current authority.
    ///
    /// Stale workers receive typed rejections; sequences must be strictly
    /// monotonic per job.
    pub async fn report_progress(
        &self,
        sequence: i32,
        stage_code: &str,
        current: i64,
        total: Option<i64>,
        message_code: Option<&str>,
    ) -> Result<ProgressEvent, JobError> {
        self.queue
            .record_progress(
                &self.handle,
                sequence,
                stage_code,
                current,
                total,
                message_code,
            )
            .await
    }

    /// Observes whether cancellation has been requested for this job.
    ///
    /// Executors SHOULD poll this between stages and stop early when flagged;
    /// stopping early simply lets the lease expire, after which the reclaim
    /// path deterministically finalizes the cancellation.
    pub async fn is_cancellation_requested(&self) -> Result<bool, JobError> {
        self.queue
            .is_cancellation_requested(self.handle.workspace_id, self.handle.job_id)
            .await
    }
}

/// Classified failure reported by an executor.
#[derive(Debug, Clone)]
pub struct JobExecutionFailure {
    /// How the runtime must treat this failure.
    pub kind: FailureKind,
    /// Bounded, non-secret machine-readable code (<=128 chars).
    pub error_code: String,
    /// Human/redacted detail; sanitized before durable storage by the queue.
    pub detail: String,
}

impl JobExecutionFailure {
    /// Transient failure eligible for bounded-backoff retry.
    #[must_use]
    pub fn retryable(error_code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Retryable,
            error_code: error_code.into(),
            detail: detail.into(),
        }
    }

    /// Permanent failure terminating the job as `failed`.
    #[must_use]
    pub fn terminal(error_code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Terminal,
            error_code: error_code.into(),
            detail: detail.into(),
        }
    }

    /// Poison message dead-lettering immediately.
    #[must_use]
    pub fn poison(error_code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Poison,
            error_code: error_code.into(),
            detail: detail.into(),
        }
    }
}

/// Trait implemented by concrete W2 job executors (scan/parse arrive in 0201-C+).
///
/// Returning `Ok(Some(result))` commits success; `Ok(None)` commits success
/// without a stored result payload; `Err(JobExecutionFailure)` records the
/// classified failure through the fenced completion path.
#[async_trait::async_trait]
pub trait JobExecutor: Send + Sync {
    /// Executes one claimed job attempt.
    async fn execute(
        &self,
        ctx: &JobExecutionContext,
    ) -> Result<Option<serde_json::Value>, JobExecutionFailure>;
}

/// Registry mapping closed job kinds to their executors.
///
/// Kinds without a registered executor are NEVER claimed: the runtime cannot
/// fabricate successful work.
#[derive(Clone, Default)]
pub struct ExecutorRegistry {
    executors: Arc<HashMap<JobKind, Arc<dyn JobExecutor>>>,
}

impl ExecutorRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style registration of one executor.
    #[must_use]
    pub fn with_executor(mut self, kind: JobKind, executor: Arc<dyn JobExecutor>) -> Self {
        let map = Arc::make_mut(&mut self.executors);
        map.insert(kind, executor);
        self
    }

    /// Returns the executor registered for a kind, if any.
    #[must_use]
    pub fn get(&self, kind: JobKind) -> Option<Arc<dyn JobExecutor>> {
        self.executors.get(&kind).cloned()
    }

    /// All kinds that currently have executors (the only claimable set).
    #[must_use]
    pub fn registered_kinds(&self) -> Vec<JobKind> {
        self.executors.keys().copied().collect()
    }

    /// True when no executors are registered (loop stays truthfully idle).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.executors.is_empty()
    }
}
