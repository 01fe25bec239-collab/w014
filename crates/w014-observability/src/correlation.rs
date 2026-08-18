//! Safe correlation identifier generation, validation, and propagation.
//!
//! Correlation identifiers are strictly operational trace metadata.
//! They MUST NOT be used as user identity, tenant identity, authorization,
//! or business object identifiers.

use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Primary HTTP header for correlation identifier propagation.
pub const HEADER_CORRELATION_ID: &str = "x-correlation-id";

/// Secondary/legacy HTTP header for correlation identifier propagation.
pub const HEADER_REQUEST_ID: &str = "x-request-id";

/// Maximum allowed length for untrusted incoming correlation header values.
pub const MAX_CORRELATION_ID_LENGTH: usize = 128;

/// Strongly-typed correlation identifier.
#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct CorrelationId(String);

impl CorrelationId {
    /// Generates a fresh, randomized UUID v4 correlation identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Creates a CorrelationId from a string slice after validating safety.
    ///
    /// Validation rules:
    /// - Non-empty and not exceeding `MAX_CORRELATION_ID_LENGTH` (128 bytes).
    /// - ASCII characters only.
    /// - Allowed characters: alphanumeric, hyphen (`-`), underscore (`_`), dot (`.`), colon (`:`).
    /// - Prohibits control characters, CR (`\r`), LF (`\n`), spaces, tabs, and shell/log delimiters.
    #[must_use]
    pub fn parse_safe(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_CORRELATION_ID_LENGTH {
            return None;
        }

        // Validate character set against injection attacks
        let is_safe = trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':');

        if is_safe {
            Some(Self(trimmed.to_string()))
        } else {
            None
        }
    }

    /// Extracts a valid correlation identifier from incoming HTTP headers,
    /// falling back to a freshly generated UUID v4 if absent or malformed.
    #[must_use]
    pub fn extract_or_generate(headers: &http::HeaderMap) -> Self {
        // Try x-correlation-id first
        if let Some(corr_id) = headers
            .get(HEADER_CORRELATION_ID)
            .and_then(|val| val.to_str().ok())
            .and_then(Self::parse_safe)
        {
            return corr_id;
        }

        // Try x-request-id next
        if let Some(corr_id) = headers
            .get(HEADER_REQUEST_ID)
            .and_then(|val| val.to_str().ok())
            .and_then(Self::parse_safe)
        {
            return corr_id;
        }

        Self::generate()
    }

    /// Returns the correlation identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::generate()
    }
}

impl AsRef<str> for CorrelationId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CorrelationId({})", self.0)
    }
}

impl FromStr for CorrelationId {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_safe(s).ok_or("invalid or unsafe correlation id format")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    #[test]
    fn test_generate_creates_valid_uuid() {
        let id = CorrelationId::generate();
        assert!(!id.as_str().is_empty());
        assert!(Uuid::parse_str(id.as_str()).is_ok());
    }

    #[test]
    fn test_parse_safe_valid_values() {
        assert!(CorrelationId::parse_safe("req-12345").is_some());
        assert!(CorrelationId::parse_safe("abc_123.456:789").is_some());
        assert!(CorrelationId::parse_safe("550e8400-e29b-41d4-a716-446655440000").is_some());
    }

    #[test]
    fn test_parse_safe_rejects_injections_and_invalid_chars() {
        // CRLF injection
        assert!(CorrelationId::parse_safe("id\r\nInjected-Header: evil").is_none());
        assert!(CorrelationId::parse_safe("id\nInjected").is_none());
        // Spaces and control chars
        assert!(CorrelationId::parse_safe("id with spaces").is_none());
        assert!(CorrelationId::parse_safe("id\twith\ttabs").is_none());
        assert!(CorrelationId::parse_safe("id\0null").is_none());
        // Quotes and brackets
        assert!(CorrelationId::parse_safe("id\"quote").is_none());
        assert!(CorrelationId::parse_safe("<script>alert(1)</script>").is_none());
        // Empty
        assert!(CorrelationId::parse_safe("").is_none());
        assert!(CorrelationId::parse_safe("   ").is_none());
        // Too long
        let too_long = "a".repeat(129);
        assert!(CorrelationId::parse_safe(&too_long).is_none());
    }

    #[test]
    fn test_extract_or_generate_propagation() {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_CORRELATION_ID, "corr-abc-123".parse().unwrap());
        let extracted = CorrelationId::extract_or_generate(&headers);
        assert_eq!(extracted.as_str(), "corr-abc-123");

        let mut headers_req = HeaderMap::new();
        headers_req.insert(HEADER_REQUEST_ID, "req-xyz-999".parse().unwrap());
        let extracted_req = CorrelationId::extract_or_generate(&headers_req);
        assert_eq!(extracted_req.as_str(), "req-xyz-999");
    }

    #[test]
    fn test_extract_or_generate_malformed_falls_back_to_generation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_CORRELATION_ID,
            "invalid value with spaces!".parse().unwrap(),
        );
        let extracted = CorrelationId::extract_or_generate(&headers);
        assert_ne!(extracted.as_str(), "invalid value with spaces!");
        assert!(Uuid::parse_str(extracted.as_str()).is_ok());
    }
}
