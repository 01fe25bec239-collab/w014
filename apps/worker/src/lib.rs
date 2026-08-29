//! Worker library and production composition root for the w014 platform.
//!
//! Provides authoritative executor registration and sandbox runner factories
//! consumed by `main.rs` and verified by production composition tests.

use std::path::PathBuf;
use std::sync::Arc;

use sqlx::PgPool;
use w014_application::services::ParserSandboxJobExecutor;
use w014_document_processing::sandbox::{ProcessSandboxRunner, SandboxRunner};
use w014_jobs::executor::ExecutorRegistry;
use w014_jobs::kind::JobKind;

/// Default sandbox executable binary name.
pub const DEFAULT_PARSER_SANDBOX_BIN: &str = "w014-parser-sandbox";

/// Environment variable to override the parser sandbox binary path.
pub const ENV_PARSER_SANDBOX_BIN: &str = "W014_PARSER_SANDBOX_BIN";

/// Creates the production parser sandbox runner from environment configuration or default.
#[must_use]
pub fn create_default_sandbox_runner() -> Arc<dyn SandboxRunner> {
    let binary_path = std::env::var(ENV_PARSER_SANDBOX_BIN)
        .unwrap_or_else(|_| DEFAULT_PARSER_SANDBOX_BIN.to_string());
    Arc::new(ProcessSandboxRunner::new(PathBuf::from(binary_path)))
}

/// Builds the production `ExecutorRegistry` registering all authoritative job executors.
///
/// Registers:
/// - `JobKind::ParseDocumentPdf` -> `ParserSandboxJobExecutor`
/// - `JobKind::ParseDocumentDocxOcr` -> `ParserSandboxJobExecutor`
#[must_use]
pub fn build_production_executor_registry(
    pool: PgPool,
    runner: Arc<dyn SandboxRunner>,
) -> ExecutorRegistry {
    let parser_executor = Arc::new(ParserSandboxJobExecutor::new(pool, runner));
    ExecutorRegistry::new()
        .with_executor(JobKind::ParseDocumentPdf, parser_executor.clone())
        .with_executor(JobKind::ParseDocumentDocxOcr, parser_executor)
}
