//! Bounded JSON value object for typed metadata snapshots.
//!
//! Metadata is typed, bounded, inert data: it never becomes instruction
//! authority. Serialization size is capped by the frozen contract.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::DomainError;
use crate::limits::MAX_METADATA_JSON_BYTES;

/// A JSON object whose serialized form is bounded by
/// [`MAX_METADATA_JSON_BYTES`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BoundedJson(Value);

impl BoundedJson {
    /// An empty JSON object.
    #[must_use]
    pub fn empty() -> Self {
        Self(Value::Object(Map::new()))
    }

    /// Wraps a JSON value after enforcing object-shape and size bounds.
    ///
    /// # Errors
    /// Fails closed when the value is not a JSON object or its serialized
    /// form exceeds [`MAX_METADATA_JSON_BYTES`].
    pub fn new(field: &'static str, value: Value) -> Result<Self, DomainError> {
        if !value.is_object() {
            return Err(DomainError::ValidationError {
                field,
                reason: "metadata must be a JSON object".to_string(),
            });
        }
        let serialized = serde_json::to_vec(&value).map_err(|e| DomainError::ValidationError {
            field,
            reason: format!("metadata is not serializable: {e}"),
        })?;
        if serialized.len() > MAX_METADATA_JSON_BYTES {
            return Err(DomainError::ValidationError {
                field,
                reason: format!(
                    "metadata serialized size {} exceeds frozen bound {MAX_METADATA_JSON_BYTES}",
                    serialized.len()
                ),
            });
        }
        Ok(Self(value))
    }

    /// The underlying JSON object value.
    #[must_use]
    pub const fn as_value(&self) -> &Value {
        &self.0
    }

    /// Serialized byte length.
    ///
    /// # Errors
    /// Propagates serialization failure (unreachable for validated values).
    pub fn serialized_len(&self) -> Result<usize, DomainError> {
        serde_json::to_vec(&self.0)
            .map(|v| v.len())
            .map_err(|e| DomainError::ValidationError {
                field: "bounded_json",
                reason: format!("serialization failed: {e}"),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_bounded_json_rejects_oversized_and_non_object() {
        assert!(BoundedJson::new("m", json!({"a": 1})).is_ok());
        assert!(BoundedJson::new("m", json!([1, 2])).is_err());

        let big = json!({ "blob": "x".repeat(MAX_METADATA_JSON_BYTES + 1) });
        assert!(BoundedJson::new("m", big).is_err());
    }
}
