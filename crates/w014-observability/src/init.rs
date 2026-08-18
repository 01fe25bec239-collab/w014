//! Observability initialization and lifecycle management.

use crate::config::{LogFormat, ObservabilityConfig};
use opentelemetry_sdk::trace::SdkTracerProvider;
use thiserror::Error;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Errors that can occur during observability initialization.
#[derive(Debug, Error)]
pub enum ObservabilityError {
    #[error("Failed to parse log level/filter directive: {0}")]
    FilterParse(#[from] tracing_subscriber::filter::ParseError),
    #[error("Failed to initialize tracing subscriber: {0}")]
    Init(#[from] tracing_subscriber::util::TryInitError),
    #[error("OpenTelemetry initialization error: {0}")]
    OpenTelemetry(String),
}

/// RAII guard for the observability subsystem. Flushes providers on drop.
pub struct ObservabilityGuard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for ObservabilityGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

/// Initializes the tracing subscriber registry with formatting layers and optional OpenTelemetry.
pub fn init_tracing(
    config: &ObservabilityConfig,
) -> Result<ObservabilityGuard, ObservabilityError> {
    if !config.enabled {
        return Ok(ObservabilityGuard { provider: None });
    }

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    let registry = tracing_subscriber::registry().with(filter);

    match config.log_format {
        LogFormat::Json => {
            let formatting_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true);
            registry.with(formatting_layer).try_init()?;
        }
        LogFormat::Compact => {
            let formatting_layer = tracing_subscriber::fmt::layer().compact();
            registry.with(formatting_layer).try_init()?;
        }
        LogFormat::Pretty => {
            let formatting_layer = tracing_subscriber::fmt::layer().pretty();
            registry.with(formatting_layer).try_init()?;
        }
    }

    Ok(ObservabilityGuard { provider: None })
}
