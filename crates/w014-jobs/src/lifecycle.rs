//! Worker lifecycle state and transition management.

use std::fmt;
use tokio::sync::watch;

use crate::error::WorkerError;
use crate::identity::WorkerId;

/// Explicit states of the worker lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkerState {
    /// Worker is initializing configuration and runtime resources.
    Starting,
    /// Worker has successfully started and is idling or awaiting work.
    Ready,
    /// Worker has received a shutdown signal and is gracefully stopping.
    ShuttingDown,
    /// Worker has completed shutdown and stopped cleanly.
    Stopped,
    /// Worker encountered an unrecoverable failure during lifecycle.
    Failed,
}

impl WorkerState {
    /// Returns true if the worker is in a terminal state (Stopped or Failed).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }

    /// Returns true if the worker is currently ready to accept or await work.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

impl fmt::Display for WorkerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Starting => write!(f, "Starting"),
            Self::Ready => write!(f, "Ready"),
            Self::ShuttingDown => write!(f, "ShuttingDown"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Tracks and manages state transitions for a worker instance.
#[derive(Debug)]
pub struct WorkerLifecycle {
    worker_id: WorkerId,
    state_tx: watch::Sender<WorkerState>,
    state_rx: watch::Receiver<WorkerState>,
}

impl WorkerLifecycle {
    /// Creates a new lifecycle manager initialized to `WorkerState::Starting`.
    #[must_use]
    pub fn new(worker_id: WorkerId) -> Self {
        let (state_tx, state_rx) = watch::channel(WorkerState::Starting);
        Self {
            worker_id,
            state_tx,
            state_rx,
        }
    }

    /// Returns the worker instance ID.
    #[must_use]
    pub fn worker_id(&self) -> WorkerId {
        self.worker_id
    }

    /// Returns the current state of the worker.
    #[must_use]
    pub fn state(&self) -> WorkerState {
        *self.state_rx.borrow()
    }

    /// Returns a watch receiver to subscribe to state changes.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<WorkerState> {
        self.state_rx.clone()
    }

    /// Attempts to transition the worker into a new state.
    ///
    /// Validates allowed state transitions:
    /// - Starting -> Ready | Failed
    /// - Ready -> ShuttingDown | Failed
    /// - ShuttingDown -> Stopped | Failed
    pub fn transition(&self, new_state: WorkerState) -> Result<(), WorkerError> {
        let current = self.state();
        if current == new_state {
            return Ok(());
        }

        let is_valid = matches!(
            (current, new_state),
            (
                WorkerState::Starting,
                WorkerState::Ready | WorkerState::Failed
            ) | (
                WorkerState::Ready,
                WorkerState::ShuttingDown | WorkerState::Failed
            ) | (
                WorkerState::ShuttingDown,
                WorkerState::Stopped | WorkerState::Failed
            )
        );

        if !is_valid {
            return Err(WorkerError::Runtime(format!(
                "invalid worker lifecycle state transition from {current} to {new_state}"
            )));
        }

        self.state_tx
            .send(new_state)
            .map_err(|e| WorkerError::Runtime(format!("failed to broadcast state change: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_lifecycle_transitions() {
        let lifecycle = WorkerLifecycle::new(WorkerId::new());
        assert_eq!(lifecycle.state(), WorkerState::Starting);
        assert!(!lifecycle.state().is_ready());
        assert!(!lifecycle.state().is_terminal());

        lifecycle
            .transition(WorkerState::Ready)
            .expect("Starting -> Ready should succeed");
        assert_eq!(lifecycle.state(), WorkerState::Ready);
        assert!(lifecycle.state().is_ready());

        lifecycle
            .transition(WorkerState::ShuttingDown)
            .expect("Ready -> ShuttingDown should succeed");
        assert_eq!(lifecycle.state(), WorkerState::ShuttingDown);

        lifecycle
            .transition(WorkerState::Stopped)
            .expect("ShuttingDown -> Stopped should succeed");
        assert_eq!(lifecycle.state(), WorkerState::Stopped);
        assert!(lifecycle.state().is_terminal());
    }

    #[test]
    fn test_invalid_lifecycle_transition() {
        let lifecycle = WorkerLifecycle::new(WorkerId::new());
        // Starting directly to Stopped is invalid
        let err = lifecycle.transition(WorkerState::Stopped);
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), WorkerError::Runtime(_)));
    }
}
