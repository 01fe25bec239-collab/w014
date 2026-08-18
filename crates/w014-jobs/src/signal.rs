//! Shutdown signal abstraction supporting OS signals and programmatic triggers.

use std::fmt;
use tokio::sync::watch;

use crate::error::WorkerError;

/// Reasons for a worker shutdown request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// Interrupted by Ctrl-C (SIGINT).
    SigInt,
    /// Terminated by system signal (SIGTERM).
    SigTerm,
    /// Triggered programmatically (e.g. test seam or parent controller).
    Manual,
}

impl fmt::Display for ShutdownReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigInt => write!(f, "SIGINT"),
            Self::SigTerm => write!(f, "SIGTERM"),
            Self::Manual => write!(f, "manual"),
        }
    }
}

/// A handle to programmatically trigger a shutdown signal.
#[derive(Clone, Debug)]
pub struct ShutdownTrigger {
    tx: watch::Sender<Option<ShutdownReason>>,
}

impl ShutdownTrigger {
    /// Triggers shutdown with a specific reason.
    pub fn trigger(&self, reason: ShutdownReason) -> Result<(), WorkerError> {
        self.tx
            .send(Some(reason))
            .map_err(|e| WorkerError::Shutdown(format!("failed to send shutdown trigger: {e}")))
    }

    /// Triggers shutdown with `ShutdownReason::Manual`.
    pub fn shutdown(&self) -> Result<(), WorkerError> {
        self.trigger(ShutdownReason::Manual)
    }
}

/// Signal receiver that waits for either OS signals (SIGINT/SIGTERM) or a programmatic trigger.
pub struct ShutdownSignal {
    listen_os: bool,
    manual_rx: Option<watch::Receiver<Option<ShutdownReason>>>,
}

impl ShutdownSignal {
    /// Creates a signal listener that listens for OS termination signals (SIGINT / SIGTERM).
    #[must_use]
    pub fn os() -> Self {
        Self {
            listen_os: true,
            manual_rx: None,
        }
    }

    /// Creates a manual shutdown pair (trigger, signal) for deterministic testing or programmatic control.
    #[must_use]
    pub fn manual() -> (ShutdownTrigger, Self) {
        let (tx, rx) = watch::channel(None);
        (
            ShutdownTrigger { tx },
            Self {
                listen_os: false,
                manual_rx: Some(rx),
            },
        )
    }

    /// Creates a combined signal listener that triggers on either OS signals or manual triggers.
    #[must_use]
    pub fn combined() -> (ShutdownTrigger, Self) {
        let (tx, rx) = watch::channel(None);
        (
            ShutdownTrigger { tx },
            Self {
                listen_os: true,
                manual_rx: Some(rx),
            },
        )
    }

    /// Awaits until a shutdown signal is received.
    pub async fn wait(mut self) -> Result<ShutdownReason, WorkerError> {
        match (self.listen_os, self.manual_rx.as_mut()) {
            (true, Some(rx)) => {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{SignalKind, signal};
                    let mut sigterm = signal(SignalKind::terminate()).map_err(|e| {
                        WorkerError::Signal(format!("failed to register SIGTERM handler: {e}"))
                    })?;
                    let mut sigint = signal(SignalKind::interrupt()).map_err(|e| {
                        WorkerError::Signal(format!("failed to register SIGINT handler: {e}"))
                    })?;

                    tokio::select! {
                        _ = sigterm.recv() => Ok(ShutdownReason::SigTerm),
                        _ = sigint.recv() => Ok(ShutdownReason::SigInt),
                        res = rx.changed() => {
                            match (res, *rx.borrow()) {
                                (Ok(()), Some(reason)) => Ok(reason),
                                _ => Ok(ShutdownReason::Manual),
                            }
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    tokio::select! {
                        res = tokio::signal::ctrl_c() => {
                            res.map_err(|e| WorkerError::Signal(format!("failed to register ctrl_c handler: {e}")))?;
                            Ok(ShutdownReason::SigInt)
                        }
                        res = rx.changed() => {
                            match (res, *rx.borrow()) {
                                (Ok(()), Some(reason)) => Ok(reason),
                                _ => Ok(ShutdownReason::Manual),
                            }
                        }
                    }
                }
            }
            (true, None) => {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{SignalKind, signal};
                    let mut sigterm = signal(SignalKind::terminate()).map_err(|e| {
                        WorkerError::Signal(format!("failed to register SIGTERM handler: {e}"))
                    })?;
                    let mut sigint = signal(SignalKind::interrupt()).map_err(|e| {
                        WorkerError::Signal(format!("failed to register SIGINT handler: {e}"))
                    })?;

                    tokio::select! {
                        _ = sigterm.recv() => Ok(ShutdownReason::SigTerm),
                        _ = sigint.recv() => Ok(ShutdownReason::SigInt),
                    }
                }
                #[cfg(not(unix))]
                {
                    tokio::signal::ctrl_c().await.map_err(|e| {
                        WorkerError::Signal(format!("failed to register ctrl_c handler: {e}"))
                    })?;
                    Ok(ShutdownReason::SigInt)
                }
            }
            (false, Some(rx)) => {
                while rx.borrow().is_none() {
                    rx.changed().await.map_err(|e| {
                        WorkerError::Signal(format!("shutdown trigger channel closed: {e}"))
                    })?;
                }
                Ok(rx.borrow().unwrap_or(ShutdownReason::Manual))
            }
            (false, None) => {
                std::future::pending::<()>().await;
                Ok(ShutdownReason::Manual)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_manual_shutdown_trigger() {
        let (trigger, signal) = ShutdownSignal::manual();
        let handle = tokio::spawn(async move { signal.wait().await });

        trigger
            .trigger(ShutdownReason::SigTerm)
            .expect("trigger should succeed");
        let result = handle
            .await
            .expect("join should succeed")
            .expect("signal should succeed");
        assert_eq!(result, ShutdownReason::SigTerm);
    }
}
