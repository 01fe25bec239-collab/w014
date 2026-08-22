//! Worker process binary composition root for the w014 platform.
//!
//! Initializes structured lifecycle observability, loads configuration from the
//! environment, and executes the long-lived worker runner. When durable-queue
//! environment configuration is present (`W014_JOB_QUEUES`), a real W2
//! PostgreSQL durable job loop runs alongside the preserved W0 lifecycle;
//! otherwise the worker remains truthfully idle (no fake queue, no fake success).

use std::process::ExitCode;

use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use w014_jobs::{
    DurableJobLoop, DurableJobLoopConfig, ExecutorRegistry, PgJobQueue, WorkerConfig, WorkerId,
    WorkerRunner,
};
use w014_persistence::DatabaseConfig;

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

    let worker_id: WorkerId = config.worker_id.unwrap_or_default();
    let runner = WorkerRunner::new(config);

    // Compose the real W2 durable job loop only when explicitly configured.
    let durable_config = match DurableJobLoopConfig::from_env() {
        Ok(Some(cfg)) => Some(cfg),
        Ok(None) => None,
        Err(err) => {
            tracing::error!(error = %err, "invalid durable job loop configuration");
            return ExitCode::FAILURE;
        }
    };

    let Some(loop_config) = durable_config else {
        return match runner.run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                tracing::error!(error = %err, "Worker process encountered fatal error");
                ExitCode::FAILURE
            }
        };
    };

    let database_config = DatabaseConfig::from_env()
        .unwrap_or_else(|_| DatabaseConfig::from_url(w014_persistence::DEFAULT_LOCAL_DATABASE_URL));

    let pool = match database_config.create_pool().await {
        Ok(pool) => pool,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to connect to PostgreSQL for the durable job loop"
            );
            return ExitCode::FAILURE;
        }
    };

    // 0201-C and later phases register real scan/parse executors here.
    // With an empty registry the loop claims nothing and stays truthfully idle.
    let registry = ExecutorRegistry::new();
    let loop_runner = DurableJobLoop::new(
        PgJobQueue::new(pool),
        registry,
        WorkerId::from_uuid(*worker_id.as_uuid()),
        loop_config,
    );

    // Preserve the full W0 lifecycle (startup/ready/shutdown tracing) while the
    // durable loop drives PostgreSQL-backed claim/execution concurrently.
    let lifecycle_task = tokio::spawn(async move { runner.run().await });
    let durable_task = tokio::spawn(async move { loop_runner.run().await });

    let (lifecycle_result, durable_result) = tokio::join!(lifecycle_task, durable_task);

    if let Err(join_err) = &lifecycle_result {
        tracing::error!(error = %join_err, "worker lifecycle task panicked");
        return ExitCode::FAILURE;
    }
    if let Err(join_err) = &durable_result {
        tracing::error!(error = %join_err, "durable job loop task panicked");
        return ExitCode::FAILURE;
    }

    let mut exit = ExitCode::SUCCESS;
    if let Ok(Err(lifecycle_err)) = &lifecycle_result {
        tracing::error!(error = %lifecycle_err, "Worker process encountered fatal error");
        exit = ExitCode::FAILURE;
    }
    if let Ok(Err(durable_err)) = &durable_result {
        tracing::error!(error = %durable_err, "durable job loop encountered fatal error");
        exit = ExitCode::FAILURE;
    }
    exit
}
