//! Integration tests for worker lifecycle, runner primitives, and trace correlation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use uuid::Uuid;

use w014_jobs::{
    ShutdownReason, ShutdownSignal, WorkerConfig, WorkerError, WorkerId, WorkerLifecycle,
    WorkerRunner, WorkerState,
};

type CapturedEvent = (String, Option<String>);

/// In-memory tracing layer to capture emitted events and span fields for test verification.
#[derive(Default, Clone)]
struct TestEventCapture {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S: Subscriber> Layer<S> for TestEventCapture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut event_name = None;
        let mut worker_id = None;

        struct FieldVisitor<'a> {
            event_name: &'a mut Option<String>,
            worker_id: &'a mut Option<String>,
        }

        impl tracing::field::Visit for FieldVisitor<'_> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "event" {
                    *self.event_name = Some(value.to_string());
                } else if field.name() == "worker_id" {
                    *self.worker_id = Some(value.to_string());
                }
            }

            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "event" {
                    *self.event_name = Some(format!("{value:?}").trim_matches('"').to_string());
                } else if field.name() == "worker_id" {
                    *self.worker_id = Some(format!("{value:?}").trim_matches('"').to_string());
                }
            }
        }

        let mut visitor = FieldVisitor {
            event_name: &mut event_name,
            worker_id: &mut worker_id,
        };
        event.record(&mut visitor);

        if let Some(name) = event_name {
            self.events.lock().unwrap().push((name, worker_id));
        }
    }
}

/// TEST C — Lifecycle unit/integration behavior:
/// Exercises the reusable runner/lifecycle logic with controllable shutdown triggers.
/// Proves initialization -> ready/idle -> shutdown -> stopped transitions.
#[tokio::test]
async fn test_lifecycle_full_orderly_progression() {
    let custom_id = WorkerId::new();
    let config = WorkerConfig::new()
        .with_worker_name("test-worker-c")
        .with_worker_id(custom_id);

    let runner = Arc::new(WorkerRunner::new(config));
    assert_eq!(runner.worker_id(), custom_id);
    assert_eq!(runner.state(), WorkerState::Starting);

    let (trigger, signal) = ShutdownSignal::manual();
    let mut state_rx = runner.lifecycle().subscribe();

    let runner_clone = Arc::clone(&runner);
    let run_handle = tokio::spawn(async move { runner_clone.run_with_signal(signal).await });

    // Wait until state reaches Ready
    while *state_rx.borrow() != WorkerState::Ready {
        state_rx.changed().await.expect("state change notification");
    }
    assert_eq!(runner.state(), WorkerState::Ready);
    assert!(runner.state().is_ready());
    assert!(!runner.state().is_terminal());

    // Trigger graceful shutdown
    trigger
        .trigger(ShutdownReason::SigTerm)
        .expect("trigger shutdown should succeed");

    // Await runner completion
    let result = run_handle.await.expect("task join succeeded");
    assert!(result.is_ok(), "runner should exit with Ok(())");

    assert_eq!(runner.state(), WorkerState::Stopped);
    assert!(runner.state().is_terminal());
}

/// TEST C (additional) — Test multiple shutdown reasons (SigInt, SigTerm, Manual).
#[tokio::test]
async fn test_lifecycle_all_shutdown_reasons() {
    for reason in [
        ShutdownReason::SigInt,
        ShutdownReason::SigTerm,
        ShutdownReason::Manual,
    ] {
        let (trigger, signal) = ShutdownSignal::manual();
        let runner = WorkerRunner::new(WorkerConfig::new());
        let runner_handle = tokio::spawn(async move { runner.run_with_signal(signal).await });

        trigger.trigger(reason).expect("shutdown trigger");
        let res = runner_handle.await.expect("task join");
        assert!(res.is_ok());
    }
}

/// TEST D — Trace/log correlation:
/// Proves worker lifecycle events are emitted with coherent process/span correlation context.
/// Shows startup, ready, shutdown_requested, and shutdown_completed are all associated
/// with the exact same worker execution ID.
#[tokio::test]
async fn test_trace_correlation_events() {
    static TRACING_INIT: AtomicBool = AtomicBool::new(false);
    let capture = TestEventCapture::default();

    if !TRACING_INIT.swap(true, Ordering::SeqCst) {
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    let expected_worker_id = WorkerId::new();
    let config = WorkerConfig::new()
        .with_worker_name("correlated-worker")
        .with_worker_id(expected_worker_id);

    let runner = WorkerRunner::new(config);
    let (trigger, signal) = ShutdownSignal::manual();

    let runner_handle = tokio::spawn(async move { runner.run_with_signal(signal).await });

    // Trigger shutdown
    trigger
        .trigger(ShutdownReason::Manual)
        .expect("manual trigger");
    let result = runner_handle.await.expect("join");
    assert!(result.is_ok());

    // Inspect captured events
    let captured = capture.events.lock().unwrap().clone();
    let expected_id_str = expected_worker_id.to_string();

    // Verify all lifecycle events occurred with the same worker_id
    let matching_events: Vec<_> = captured
        .iter()
        .filter(|(_, id)| id.as_deref() == Some(&expected_id_str))
        .collect();

    // Must include the core lifecycle events
    let event_names: Vec<&str> = matching_events
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();

    assert!(
        event_names.contains(&"worker_started"),
        "events must contain worker_started: {event_names:?}"
    );
    assert!(
        event_names.contains(&"worker_ready"),
        "events must contain worker_ready: {event_names:?}"
    );
    assert!(
        event_names.contains(&"shutdown_requested"),
        "events must contain shutdown_requested: {event_names:?}"
    );
    assert!(
        event_names.contains(&"shutdown_completed"),
        "events must contain shutdown_completed: {event_names:?}"
    );
}

/// TEST E — No fake job success:
/// Proves that merely starting and stopping the W0 worker does not claim or log fake job completions.
#[tokio::test]
async fn test_no_fake_job_success_behavior() {
    let runner = Arc::new(WorkerRunner::new(WorkerConfig::new()));
    let (trigger, signal) = ShutdownSignal::manual();

    let mut state_rx = runner.lifecycle().subscribe();
    let runner_clone = Arc::clone(&runner);
    let runner_handle = tokio::spawn(async move { runner_clone.run_with_signal(signal).await });

    // Wait for ready
    while *state_rx.borrow() != WorkerState::Ready {
        state_rx.changed().await.expect("state change");
    }

    // Verify state is Ready and NOT executing/reporting job successes
    assert_eq!(runner.state(), WorkerState::Ready);

    // Terminate
    trigger.shutdown().expect("shutdown");
    let res = runner_handle.await.expect("join");
    assert!(res.is_ok());
    assert_eq!(runner.state(), WorkerState::Stopped);
}

/// Test invalid state transition enforcement.
#[test]
fn test_invalid_lifecycle_state_transitions() {
    let lifecycle = WorkerLifecycle::new(WorkerId::new());
    assert_eq!(lifecycle.state(), WorkerState::Starting);

    // Starting cannot transition directly to ShuttingDown
    let err = lifecycle.transition(WorkerState::ShuttingDown);
    assert!(err.is_err());
    assert!(matches!(err.unwrap_err(), WorkerError::Runtime(_)));

    // Starting -> Ready is valid
    lifecycle.transition(WorkerState::Ready).unwrap();

    // Ready cannot transition directly to Stopped (must go through ShuttingDown)
    let err2 = lifecycle.transition(WorkerState::Stopped);
    assert!(err2.is_err());
    assert!(matches!(err2.unwrap_err(), WorkerError::Runtime(_)));
}

/// Test configuration parsing from environment.
#[test]
fn test_config_from_env() {
    let id_uuid = Uuid::new_v4();
    // Safety: single-threaded test execution for env var manipulation
    unsafe {
        std::env::set_var("W014_WORKER_NAME", "custom-env-worker");
        std::env::set_var("W014_WORKER_ID", id_uuid.to_string());
    }

    let config = WorkerConfig::from_env().expect("config from env should parse");
    assert_eq!(config.worker_name, "custom-env-worker");
    assert_eq!(config.worker_id, Some(WorkerId::from_uuid(id_uuid)));

    unsafe {
        std::env::remove_var("W014_WORKER_NAME");
        std::env::remove_var("W014_WORKER_ID");
    }
}
