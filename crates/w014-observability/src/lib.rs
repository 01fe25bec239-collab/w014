//! w014-observability: Foundation observability, correlation, and safe telemetry crate.
//!
//! Provides:
//! - Correlation identifier parsing, generation, propagation, and safety validation
//! - Redaction and sanitization helpers to prevent leaking CUI, credentials, and secrets
//! - OpenTelemetry and structured tracing initialization and lifecycle guards
//! - Observability configuration types

pub mod config;
pub mod correlation;
pub mod init;
pub mod redaction;

pub use config::{LogFormat, ObservabilityConfig};
pub use correlation::{
    CorrelationId, HEADER_CORRELATION_ID, HEADER_REQUEST_ID, MAX_CORRELATION_ID_LENGTH,
};
pub use init::{ObservabilityError, ObservabilityGuard, init_tracing};
pub use redaction::{REDACTED_PLACEHOLDER, is_sensitive_key, redact_value, sanitize_headers};
