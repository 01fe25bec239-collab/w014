//! Worker library and production composition root for the w014 platform.
//!
//! Provides authoritative executor registration and sandbox runner factories
//! consumed by `main.rs` and verified by production composition tests.

use std::path::PathBuf;
use std::sync::Arc;

use sqlx::PgPool;
use w014_application::services::{MalwareScanJobExecutor, ParserSandboxJobExecutor};
use w014_document_processing::sandbox::{ProcessSandboxRunner, SandboxRunner};
use w014_document_processing::scanner::{ClamAvClient, ClamAvConfig};
use w014_jobs::executor::ExecutorRegistry;
use w014_jobs::kind::JobKind;

/// Default sandbox executable binary name.
pub const DEFAULT_PARSER_SANDBOX_BIN: &str = "w014-parser-sandbox";

/// Environment variable to override the parser sandbox binary path.
pub const ENV_PARSER_SANDBOX_BIN: &str = "W014_PARSER_SANDBOX_BIN";

pub use w014_document_processing::sandbox::{
    ENV_PARSER_SANDBOX_WRAPPER_ARGS, ENV_PARSER_SANDBOX_WRAPPER_BIN,
};

/// Creates the production parser sandbox runner from environment configuration or default.
///
/// Hardened with the authoritative platform-native isolation wrapper mechanism (e.g. bubblewrap
/// on Linux, sandbox-exec on macOS), preserving server-controlled wrapper overrides
/// via `ENV_PARSER_SANDBOX_WRAPPER_BIN` and fail-closed semantics when isolation is missing.
#[must_use]
pub fn create_default_sandbox_runner() -> Arc<dyn SandboxRunner> {
    let binary_path = std::env::var(ENV_PARSER_SANDBOX_BIN)
        .unwrap_or_else(|_| DEFAULT_PARSER_SANDBOX_BIN.to_string());
    let runner = ProcessSandboxRunner::new(PathBuf::from(binary_path));

    let runner = if std::env::var_os(ENV_PARSER_SANDBOX_WRAPPER_BIN).is_some() {
        runner
    } else {
        runner.with_platform_wrapper()
    };

    Arc::new(runner)
}

/// Builds the production `ExecutorRegistry` registering all authoritative job executors.
///
/// Registers:
/// - `JobKind::MalwareScanDocumentPdf` -> `MalwareScanJobExecutor`
/// - `JobKind::MalwareScanDocumentDocxOcr` -> `MalwareScanJobExecutor`
/// - `JobKind::ParseDocumentPdf` -> `ParserSandboxJobExecutor`
/// - `JobKind::ParseDocumentDocxOcr` -> `ParserSandboxJobExecutor`
#[must_use]
pub fn build_production_executor_registry(
    pool: PgPool,
    runner: Arc<dyn SandboxRunner>,
) -> ExecutorRegistry {
    let clamav_config = ClamAvConfig::from_env();
    let scanner = Arc::new(ClamAvClient::new(clamav_config));
    let malware_executor = Arc::new(MalwareScanJobExecutor::new(pool.clone(), scanner));
    let parser_executor = Arc::new(ParserSandboxJobExecutor::new(pool, runner));
    ExecutorRegistry::new()
        .with_executor(JobKind::MalwareScanDocumentPdf, malware_executor.clone())
        .with_executor(JobKind::MalwareScanDocumentDocxOcr, malware_executor)
        .with_executor(JobKind::ParseDocumentPdf, parser_executor.clone())
        .with_executor(JobKind::ParseDocumentDocxOcr, parser_executor)
}
