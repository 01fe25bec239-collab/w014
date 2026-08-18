//! w014-jobs: Worker process lifecycle, runner foundation, and asynchronous execution abstractions.
//!
//! Provides the core worker process primitives for the w014 platform:
//! - Worker identity and configuration (`WorkerId`, `WorkerConfig`)
//! - Lifecycle management and state transitions (`WorkerState`, `WorkerLifecycle`)
//! - Cooperative shutdown signal handling (`ShutdownSignal`, `ShutdownTrigger`, `ShutdownReason`)
//! - Worker runner composition (`WorkerRunner`)
//! - Structured error types (`WorkerError`)

pub mod config;
pub mod error;
pub mod identity;
pub mod lifecycle;
pub mod runner;
pub mod signal;

pub use config::WorkerConfig;
pub use error::WorkerError;
pub use identity::WorkerId;
pub use lifecycle::{WorkerLifecycle, WorkerState};
pub use runner::WorkerRunner;
pub use signal::{ShutdownReason, ShutdownSignal, ShutdownTrigger};
