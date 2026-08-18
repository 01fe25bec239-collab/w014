//! Worker identity primitives for lifecycle tracking and trace correlation.

use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::WorkerError;

/// Unique identifier for a worker process instance.
///
/// Ensures all lifecycle events for a specific worker process execution
/// can be uniquely correlated across spans and log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerId(Uuid);

impl WorkerId {
    /// Generates a new random worker instance ID (UUID v4).
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wraps an existing UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the underlying UUID reference.
    #[must_use]
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for WorkerId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for WorkerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for WorkerId {
    type Err = WorkerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(s)
            .map_err(|e| WorkerError::Configuration(format!("invalid worker id format: {e}")))?;
        Ok(Self(uuid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_id_generation_and_formatting() {
        let id1 = WorkerId::new();
        let id2 = WorkerId::new();
        assert_ne!(id1, id2);

        let id_str = id1.to_string();
        let parsed: WorkerId = id_str.parse().expect("should parse valid uuid string");
        assert_eq!(id1, parsed);
        assert_eq!(id1.as_uuid(), parsed.as_uuid());
    }

    #[test]
    fn test_worker_id_invalid_parse() {
        let result = "not-a-valid-uuid".parse::<WorkerId>();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WorkerError::Configuration(_)));
    }
}
