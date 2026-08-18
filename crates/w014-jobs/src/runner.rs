//! Worker execution runner orchestrating startup, idle wait, and graceful shutdown.

use std::sync::Arc;
use tracing::Instrument;

use crate::config::WorkerConfig;
use crate::error::WorkerError;
use crate::identity::WorkerId;
use crate::lifecycle::{WorkerLifecycle, WorkerState};
use crate::signal::ShutdownSignal;

/// Orchestrates the execution and lifecycle of a worker process.
///
/// The runner establishes structured span correlation for all lifecycle events,
/// manages state transitions (`Starting` -> `Ready` -> `ShuttingDown` -> `Stopped`),
/// and provides cooperative shutdown handling.
pub struct WorkerRunner {
    config: WorkerConfig,
    lifecycle: Arc<WorkerLifecycle>,
}

impl WorkerRunner {
    /// Creates a new `WorkerRunner` from the provided configuration.
    #[must_use]
    pub fn new(config: WorkerConfig) -> Self {
        let worker_id = config.worker_id.unwrap_or_default();
        let lifecycle = Arc::new(WorkerLifecycle::new(worker_id));
        Self { config, lifecycle }
    }

    /// Returns the unique worker instance ID.
    #[must_use]
    pub fn worker_id(&self) -> WorkerId {
        self.lifecycle.worker_id()
    }

    /// Returns a reference to the worker configuration.
    #[must_use]
    pub fn config(&self) -> &WorkerConfig {
        &self.config
    }

    /// Returns a shared reference to the worker lifecycle manager.
    #[must_use]
    pub fn lifecycle(&self) -> Arc<WorkerLifecycle> {
        Arc::clone(&self.lifecycle)
    }

    /// Returns the current state of the worker.
    #[must_use]
    pub fn state(&self) -> WorkerState {
        self.lifecycle.state()
    }

    /// Runs the worker process lifecycle with default OS signal handling.
    pub async fn run(&self) -> Result<(), WorkerError> {
        self.run_with_signal(ShutdownSignal::os()).await
    }

    /// Runs the worker process lifecycle using the provided shutdown signal source.
    ///
    /// Executes within an instrumented `worker_lifecycle` tracing span to correlate
    /// all lifecycle events for this worker instance.
    pub async fn run_with_signal(&self, signal: ShutdownSignal) -> Result<(), WorkerError> {
        let worker_id = self.worker_id();
        let worker_name = &self.config.worker_name;

        let lifecycle_span = tracing::info_span!(
            "worker_lifecycle",
            %worker_id,
            %worker_name,
        );

        async {
            // 1. Startup phase: initialize infrastructure and emit startup lifecycle event
            tracing::info!(
                event = "worker_started",
                %worker_id,
                %worker_name,
                state = %WorkerState::Starting,
                "worker process initialized and starting up"
            );

            // Transition to Ready state
            self.lifecycle.transition(WorkerState::Ready)?;

            tracing::info!(
                event = "worker_ready",
                %worker_id,
                %worker_name,
                state = %WorkerState::Ready,
                status_detail = "idle, awaiting work or shutdown (W0 bootstrap runtime)",
                "worker ready and idling (no persistent queue runtime configured in W0)"
            );

            // 2. Idle / Running phase: truthful wait for shutdown signal
            // In W0, no persistent database queue or job execution is authorized.
            // Future W2/W6 work items plug runner task loops into this lifecycle.
            let shutdown_reason = match signal.wait().await {
                Ok(reason) => reason,
                Err(err) => {
                    let _ = self.lifecycle.transition(WorkerState::Failed);
                    tracing::error!(
                        event = "signal_error",
                        %worker_id,
                        %worker_name,
                        state = %WorkerState::Failed,
                        error = %err,
                        "failed while awaiting shutdown signal"
                    );
                    return Err(err);
                }
            };

            // 3. Graceful shutdown phase
            self.lifecycle.transition(WorkerState::ShuttingDown)?;

            tracing::info!(
                event = "shutdown_requested",
                %worker_id,
                %worker_name,
                state = %WorkerState::ShuttingDown,
                signal = %shutdown_reason,
                "shutdown requested, initiating cooperative graceful shutdown"
            );

            // In future W2/W6, in-flight jobs and leases are drained cooperatively here.

            // 4. Completed phase
            self.lifecycle.transition(WorkerState::Stopped)?;

            tracing::info!(
                event = "shutdown_completed",
                %worker_id,
                %worker_name,
                state = %WorkerState::Stopped,
                "worker process stopped gracefully"
            );

            Ok(())
        }
        .instrument(lifecycle_span)
        .await
    }
}
