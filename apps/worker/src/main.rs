//! Worker process binary composition root for the w014 platform.
//!
//! Initializes structured lifecycle observability, loads configuration from the
//! environment, and executes the long-lived worker runner awaiting work or graceful shutdown.

use std::process::ExitCode;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use w014_jobs::{WorkerConfig, WorkerRunner};

#[tokio::main]
async fn main() -> ExitCode {
    // Initialize structured tracing subscriber
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,w014_worker=info,w014_jobs=info"));

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer());

    if let Err(e) = subscriber.try_init() {
        eprintln!("Failed to initialize tracing subscriber: {e}");
    }

    let config = match WorkerConfig::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Failed to load worker configuration: {err}");
            return ExitCode::FAILURE;
        }
    };

    let runner = WorkerRunner::new(config);

    match runner.run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "Worker process encountered fatal error");
            ExitCode::FAILURE
        }
    }
}
