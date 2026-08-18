//! Configuration structures for the observability subsystem.

use serde::{Deserialize, Serialize};

/// Supported log output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Structured JSON format for production telemetry collectors.
    #[default]
    Json,
    /// Human-readable compact format for local development.
    Compact,
    /// Pretty-printed multi-line format for local debugging.
    Pretty,
}

/// Typed configuration for the observability subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Service name recorded in telemetry spans and log events.
    pub service_name: String,
    /// Service version recorded in telemetry spans.
    pub service_version: String,
    /// Logging filter directive (e.g., "info", "debug,w014_api=trace").
    pub log_level: String,
    /// Structured log formatting mode.
    pub log_format: LogFormat,
    /// Optional OpenTelemetry Collector OTLP endpoint (e.g., "http://localhost:4317").
    pub otlp_endpoint: Option<String>,
    /// Whether observability telemetry emission is enabled.
    pub enabled: bool,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            service_name: "w014-api".to_string(),
            service_version: "0.1.0".to_string(),
            log_level: "info".to_string(),
            log_format: LogFormat::Json,
            otlp_endpoint: None,
            enabled: true,
        }
    }
}

impl ObservabilityConfig {
    /// Creates a configuration suitable for local development/testing.
    #[must_use]
    pub fn for_development() -> Self {
        Self {
            service_name: "w014-api".to_string(),
            service_version: "0.1.0".to_string(),
            log_level: "debug".to_string(),
            log_format: LogFormat::Compact,
            otlp_endpoint: None,
            enabled: true,
        }
    }

    /// Creates a configuration suitable for automated test suites.
    #[must_use]
    pub fn for_testing() -> Self {
        Self {
            service_name: "w014-api-test".to_string(),
            service_version: "0.1.0".to_string(),
            log_level: "warn".to_string(),
            log_format: LogFormat::Compact,
            otlp_endpoint: None,
            enabled: false,
        }
    }
}
