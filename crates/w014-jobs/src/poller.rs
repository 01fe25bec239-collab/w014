//! Durable job polling loop composing claim, execution, and graceful shutdown.
//!
//! The loop is a NON-AUTHORITATIVE process-local driver: every lifecycle
//! decision it makes is backed by PostgreSQL through [`PgJobQueue`]. Shutdown
//! is cooperative (Ctrl-C / SIGTERM / manual trigger): the loop stops claiming,
//! drains in-flight executions to their fenced completion, and returns.

use std::time::Duration;

use tracing::Instrument;

use crate::error::{JobError, WorkerError};
use crate::executor::{ExecutorRegistry, JobExecutionContext};
use crate::identity::WorkerId;
use crate::models::ClaimCriteria;
use crate::queue::PgJobQueue;
use crate::signal::ShutdownSignal;

/// Default lease duration for claimed jobs.
pub const DEFAULT_LEASE_SECS: u32 = 60;

/// Default pause between polls when the queue is empty.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(1000);

/// Heartbeat cadence (a fraction of the lease) while an executor runs.
const HEARTBEAT_FRACTION_NUM: u32 = 3;

/// Environment variable providing the comma-separated canonical queue names.
pub const ENV_JOB_QUEUES: &str = "W014_JOB_QUEUES";

/// Environment variable overriding the lease duration in seconds.
pub const ENV_LEASE_SECS: &str = "W014_JOB_LEASE_SECS";

/// Environment variable overriding the poll interval in milliseconds.
pub const ENV_POLL_INTERVAL_MS: &str = "W014_JOB_POLL_INTERVAL_MS";

/// Configuration for one durable job loop.
#[derive(Debug, Clone)]
pub struct DurableJobLoopConfig {
    /// Canonical frozen queue identities to poll.
    pub queues: Vec<String>,
    /// Lease duration granted by claims.
    pub lease_duration: Duration,
    /// Pause between polls when no work was found.
    pub poll_interval: Duration,
}

impl DurableJobLoopConfig {
    /// Loads loop configuration from the environment.
    ///
    /// Returns `Ok(None)` when the loop must stay inactive (no
    /// `W014_JOB_QUEUES` configured) so the worker remains truthfully idle.
    pub fn from_env() -> Result<Option<Self>, WorkerError> {
        let raw_queues = std::env::var(ENV_JOB_QUEUES).unwrap_or_default();
        let queues: Vec<String> = raw_queues
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if queues.is_empty() {
            return Ok(None);
        }

        let lease_secs = parse_env_u32(ENV_LEASE_SECS)?.unwrap_or(DEFAULT_LEASE_SECS);
        let poll_ms = parse_env_u32(ENV_POLL_INTERVAL_MS)?
            .unwrap_or(u32::try_from(DEFAULT_POLL_INTERVAL.as_millis()).unwrap_or(1000));

        Ok(Some(Self {
            queues,
            lease_duration: Duration::from_secs(u64::from(lease_secs.max(1))),
            poll_interval: Duration::from_millis(u64::from(poll_ms.max(10))),
        }))
    }
}

fn parse_env_u32(name: &str) -> Result<Option<u32>, WorkerError> {
    match std::env::var(name) {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<u32>()
            .map(Some)
            .map_err(|e| WorkerError::Configuration(format!("invalid {name} '{raw}': {e}"))),
        _ => Ok(None),
    }
}

/// Process-local driver executing claimed W2 jobs against registered executors.
///
/// Invariants preserved:
/// - only kinds with registered executors are ever claimed (no fake success);
/// - executors run strictly after the claim transaction commits;
/// - heartbeats renew leases only while authority remains valid;
/// - stale completions/failures/heartbeats are logged truthfully and mutate
///   zero authoritative rows;
/// - Ctrl-C / SIGTERM stop claiming and drain in-flight work.
pub struct DurableJobLoop {
    queue: PgJobQueue,
    worker_id: WorkerId,
    registry: ExecutorRegistry,
    config: DurableJobLoopConfig,
}

impl DurableJobLoop {
    /// Builds a loop bound to one authoritative queue and executor registry.
    #[must_use]
    pub fn new(
        queue: PgJobQueue,
        registry: ExecutorRegistry,
        worker_id: WorkerId,
        config: DurableJobLoopConfig,
    ) -> Self {
        Self {
            queue,
            worker_id,
            registry,
            config,
        }
    }

    /// Runs the loop until an OS signal arrives, then drains gracefully.
    pub async fn run(&self) -> Result<(), WorkerError> {
        self.run_with_signal(ShutdownSignal::os()).await
    }

    /// Runs the loop until the provided shutdown signal fires.
    pub async fn run_with_signal(&self, shutdown: ShutdownSignal) -> Result<(), WorkerError> {
        self.run_inner(shutdown).await
    }

    async fn run_inner(&self, shutdown: ShutdownSignal) -> Result<(), WorkerError> {
        if self.registry.is_empty() || self.config.queues.is_empty() {
            tracing::info!(
                event = "durable_loop_idle",
                worker_id = %self.worker_id,
                "no executors or queues registered; durable loop stays truthfully idle \
                 (no fabricated work)"
            );
            return match shutdown.wait().await {
                Ok(_) => Ok(()),
                Err(err) => Err(err),
            };
        }

        // The shutdown signal is consumed by a dedicated waiter task so the
        // poll loop can select on a cloneable notification channel.
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let signal_waiter = tokio::spawn(async move {
            let result = shutdown.wait().await;
            let _ = shutdown_tx.send(true);
            result
        });

        let mut in_flight = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    tracing::info!(
                        event = "durable_loop_shutdown",
                        worker_id = %self.worker_id,
                        in_flight = in_flight.len(),
                        "shutdown requested; draining in-flight executions"
                    );
                    break;
                }
                _ = tokio::time::sleep(self.config.poll_interval) => {
                    match self.poll_once().await {
                        Ok(Some(claimed)) => {
                            let queue = self.queue.clone();
                            let registry = self.registry.clone();
                            let worker_id = self.worker_id;
                            let lease_secs = u32::try_from(
                                self.config.lease_duration.as_secs().min(u64::from(u32::MAX)),
                            )
                            .unwrap_or(DEFAULT_LEASE_SECS);
                            in_flight.spawn(
                                execute_claimed(queue, registry, claimed, worker_id, lease_secs)
                                    .in_current_span(),
                            );
                        }
                        Ok(None) => {}
                        Err(JobError::NotClaimable) => {}
                        Err(err) => {
                            tracing::warn!(
                                event = "durable_poll_error",
                                worker_id = %self.worker_id,
                                error = %err,
                                "claim poll failed; retrying after interval"
                            );
                        }
                    }
                }
            }

            // Drain any completed tasks between iterations.
            while in_flight.try_join_next().is_some() {}
        }

        while in_flight.join_next().await.is_some() {}
        if let Ok(join_result) = signal_waiter.await {
            match join_result {
                Ok(reason) => tracing::info!(
                    event = "durable_loop_stopped",
                    worker_id = %self.worker_id,
                    signal = %reason,
                    "all in-flight executions drained; durable loop stopped"
                ),
                Err(err) => tracing::warn!(event = "durable_loop_signal_error", error = %err),
            }
        }
        Ok(())
    }

    /// Claims and dispatches at most one job. Public for deterministic tests.
    pub async fn poll_once(&self) -> Result<Option<crate::models::ClaimedJob>, JobError> {
        if self.registry.is_empty() || self.config.queues.is_empty() {
            return Ok(None);
        }
        let criteria = ClaimCriteria {
            queues: self.config.queues.clone(),
            kinds: self.registry.registered_kinds(),
            workspace: crate::models::WorkspaceScope::Unrestricted,
            lease_duration: self.config.lease_duration,
        };
        self.queue.claim(criteria, self.worker_id).await
    }
}

/// Executes one claimed job with heartbeat renewal and fenced completion.
async fn execute_claimed(
    queue: PgJobQueue,
    registry: ExecutorRegistry,
    claimed: crate::models::ClaimedJob,
    worker_id: WorkerId,
    lease_secs: u32,
) {
    let span = tracing::info_span!(
        "durable_job_execution",
        worker_id = %worker_id,
        job_id = %claimed.job_id,
        attempt = claimed.attempt_number,
        generation = claimed.lease_generation,
        kind = %claimed.kind,
    );

    async move {
        // Cooperative cancellation observed before spending compute.
        match queue
            .is_cancellation_requested(claimed.workspace_id, claimed.job_id)
            .await
        {
            Ok(true) => {
                tracing::warn!(
                    event = "job_cancelled_before_execution",
                    "cancellation requested; skipping compute (lease expiry finalizes)"
                );
                return;
            }
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(
                    event = "cancellation_check_failed",
                    error = %err,
                    "could not observe cancellation flag; proceeding"
                );
            }
        }

        let Some(executor) = registry.get(claimed.kind) else {
            // Unreachable via poller (kinds filter), guarded for direct callers:
            // never fabricate success for unhandled kinds.
            tracing::error!(
                event = "no_executor_registered",
                "no executor registered for claimed kind; abandoning compute without \
                 fabricating success"
            );
            return;
        };

        let heartbeat_task = spawn_heartbeat(queue.clone(), claimed.clone(), lease_secs);
        let ctx = JobExecutionContext::new(queue.clone(), claimed.clone());
        let outcome = executor.execute(&ctx).await;
        heartbeat_task.abort();

        match outcome {
            Ok(result) => match queue.complete_success(&claimed, result).await {
                Ok(()) => {
                    tracing::info!(
                        event = "job_succeeded",
                        "attempt committed as succeeded under current authority"
                    );
                }
                Err(
                    stale @ (JobError::LeaseLost(_)
                    | JobError::AlreadyTerminal { .. }
                    | JobError::WorkspaceViolation(_)),
                ) => {
                    tracing::warn!(
                        event = "stale_success_rejected",
                        error = %stale,
                        "success completion rejected: authority superseded/expired; \
                         zero authoritative rows mutated"
                    );
                }
                Err(err) => {
                    tracing::error!(
                        event = "success_completion_failed",
                        error = %err,
                        "unexpected failure committing success"
                    );
                }
            },
            Err(failure) => {
                match queue
                    .complete_failure(&claimed, &failure.error_code, &failure.detail, failure.kind)
                    .await
                {
                    Ok(resolution) => {
                        tracing::info!(
                            event = "job_failure_recorded",
                            error_code = %failure.error_code,
                            resolution = ?resolution,
                            "classified failure recorded durably"
                        );
                    }
                    Err(
                        stale @ (JobError::LeaseLost(_)
                        | JobError::AlreadyTerminal { .. }
                        | JobError::WorkspaceViolation(_)),
                    ) => {
                        tracing::warn!(
                            event = "stale_failure_rejected",
                            error_code = %failure.error_code,
                            error = %stale,
                            "failure recording rejected: authority superseded/expired; \
                             zero authoritative rows mutated"
                        );
                    }
                    Err(err) => {
                        tracing::error!(
                            event = "failure_recording_failed",
                            error_code = %failure.error_code,
                            error = %err,
                            "unexpected failure recording classified failure"
                        );
                    }
                }
            }
        }
    }
    .instrument(span)
    .await
}

/// Renews the lease on a fixed cadence while execution proceeds.
///
/// Exits silently once authority is lost (the completion path reports the
/// typed stale rejection); transient database errors are logged and retried
/// on the next tick.
fn spawn_heartbeat(
    queue: PgJobQueue,
    claimed: crate::models::ClaimedJob,
    lease_secs: u32,
) -> tokio::task::JoinHandle<()> {
    let interval = Duration::from_secs(
        u64::from(lease_secs.max(HEARTBEAT_FRACTION_NUM)) / u64::from(HEARTBEAT_FRACTION_NUM),
    )
    .max(Duration::from_millis(250));

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await; // immediate first tick aligns to claim instant

        loop {
            ticker.tick().await;
            match queue.heartbeat(&claimed, lease_secs).await {
                Ok(expires_at) => {
                    tracing::debug!(
                        event = "heartbeat_renewed",
                        lease_expires_at = %expires_at,
                        "lease renewed under current authority"
                    );
                }
                Err(JobError::LeaseLost(_))
                | Err(JobError::AlreadyTerminal { .. })
                | Err(JobError::WorkspaceViolation(_)) => {
                    tracing::warn!(
                        event = "heartbeat_stale_rejected",
                        "heartbeat rejected: authority expired/superseded; stopping renewal"
                    );
                    break;
                }
                Err(err) => {
                    tracing::warn!(
                        event = "heartbeat_error",
                        error = %err,
                        "transient heartbeat failure; retrying next tick"
                    );
                }
            }
        }
    })
}
