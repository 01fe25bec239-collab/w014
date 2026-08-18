//! Worker process configuration.

use crate::error::WorkerError;
use crate::identity::WorkerId;

/// Configuration options for a worker process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerConfig {
    /// Optional explicitly specified worker ID; if None, a new UUID is generated.
    pub worker_id: Option<WorkerId>,
    /// Logical name or pool identifier for the worker process.
    pub worker_name: String,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            worker_id: None,
            worker_name: "w014-worker".to_string(),
        }
    }
}

impl WorkerConfig {
    /// Creates a new configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the worker name.
    #[must_use]
    pub fn with_worker_name(mut self, name: impl Into<String>) -> Self {
        self.worker_name = name.into();
        self
    }

    /// Sets the worker ID.
    #[must_use]
    pub fn with_worker_id(mut self, worker_id: WorkerId) -> Self {
        self.worker_id = Some(worker_id);
        self
    }

    /// Loads worker configuration from environment variables.
    ///
    /// - `W014_WORKER_NAME`: Optional worker name (defaults to "w014-worker")
    /// - `W014_WORKER_ID`: Optional explicit UUID string for worker instance
    pub fn from_env() -> Result<Self, WorkerError> {
        let worker_name =
            std::env::var("W014_WORKER_NAME").unwrap_or_else(|_| "w014-worker".to_string());

        let worker_id = match std::env::var("W014_WORKER_ID") {
            Ok(val) if !val.trim().is_empty() => Some(val.trim().parse::<WorkerId>()?),
            _ => None,
        };

        Ok(Self {
            worker_id,
            worker_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_config_builder() {
        let id = WorkerId::new();
        let config = WorkerConfig::new()
            .with_worker_name("custom-worker")
            .with_worker_id(id);

        assert_eq!(config.worker_name, "custom-worker");
        assert_eq!(config.worker_id, Some(id));
    }
}
