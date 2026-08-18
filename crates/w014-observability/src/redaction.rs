//! Redaction-safe telemetry helpers and data sanitization.
//!
//! Ensures sensitive telemetry, authentication tokens, credentials,
//! CUI, and business payloads are not emitted into trace or log sinks.

/// Common sensitive field names in headers, query parameters, or payloads.
pub const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "api_key",
    "api-key",
    "apikey",
    "private_key",
    "credential",
    "cui",
    "document_text",
    "prompt",
    "payload",
];

/// Redacted placeholder text.
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// Checks whether a given field/header key should be redacted.
#[must_use]
pub fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let normalized = lower.replace('-', "_");
    SENSITIVE_KEY_PATTERNS
        .iter()
        .any(|&pattern| lower.contains(pattern) || normalized.contains(&pattern.replace('-', "_")))
}

/// Redacts a value if the corresponding key matches sensitive naming patterns.
#[must_use]
pub fn redact_value<'a>(key: &str, value: &'a str) -> &'a str {
    if is_sensitive_key(key) {
        REDACTED_PLACEHOLDER
    } else {
        value
    }
}

/// Sanitizes a header map for safe logging, masking any sensitive header values.
#[must_use]
pub fn sanitize_headers(headers: &http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let key_str = name.as_str();
            let val_str = value.to_str().unwrap_or("<binary-data>");
            if is_sensitive_key(key_str) {
                (key_str.to_string(), REDACTED_PLACEHOLDER.to_string())
            } else {
                (key_str.to_string(), val_str.to_string())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    #[test]
    fn test_is_sensitive_key() {
        assert!(is_sensitive_key("Authorization"));
        assert!(is_sensitive_key("authorization"));
        assert!(is_sensitive_key("X-API-KEY"));
        assert!(is_sensitive_key("api-key"));
        assert!(is_sensitive_key("api_key"));
        assert!(is_sensitive_key("set-cookie"));
        assert!(is_sensitive_key("cui_content"));
        assert!(is_sensitive_key("user_password"));
        assert!(!is_sensitive_key("content-type"));
        assert!(!is_sensitive_key("x-correlation-id"));
        assert!(!is_sensitive_key("accept"));
    }

    #[test]
    fn test_redact_value() {
        assert_eq!(
            redact_value("Authorization", "Bearer secret123"),
            REDACTED_PLACEHOLDER
        );
        assert_eq!(
            redact_value("content-type", "application/json"),
            "application/json"
        );
    }

    #[test]
    fn test_sanitize_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer secret-token".parse().unwrap());
        headers.insert("X-Correlation-Id", "corr-123".parse().unwrap());
        headers.insert("Cookie", "session=xyz".parse().unwrap());

        let sanitized = sanitize_headers(&headers);
        for (k, v) in sanitized {
            if k == "authorization" || k == "cookie" {
                assert_eq!(v, REDACTED_PLACEHOLDER);
            } else if k == "x-correlation-id" {
                assert_eq!(v, "corr-123");
            }
        }
    }
}
