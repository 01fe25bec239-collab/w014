//! Bounded, secret-free durable-job payload contract.
//!
//! The authoritative `jobs.payload` JSONB document must be:
//! - a JSON object matching the W2 payload envelope;
//! - within strict size and nesting bounds;
//! - free of raw provider keys, session secrets, database credentials,
//!   presigned URLs, and untrusted document bytes.
//!
//! Untrusted document content is never treated as executable authority.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::JobError;

/// Maximum serialized payload size (bytes).
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum JSON nesting depth accepted inside `parameters`.
pub const MAX_PAYLOAD_DEPTH: usize = 12;

/// Current W2 payload envelope contract version produced/consumed by this runtime.
pub const PAYLOAD_CONTRACT_VERSION: u32 = 1;

/// Lowercase key fragments that indicate prohibited sensitive material
/// anywhere in the payload tree.
const PROHIBITED_KEY_FRAGMENTS: [&str; 14] = [
    "api_key",
    "apikey",
    "secret",
    "password",
    "passwd",
    "credential",
    "authorization",
    "cookie",
    "session_token",
    "access_token",
    "refresh_token",
    "private_key",
    "connection_string",
    "presigned",
];

/// Key fragments that would smuggle raw document bytes as executable content.
const PROHIBITED_BYTES_FRAGMENTS: [&str; 5] = [
    "document_bytes",
    "base64_content",
    "file_content",
    "raw_bytes",
    "embedded_document",
];

/// URL query signatures of presigned object-storage grants.
const PRESIGNED_URL_SIGNATURES: [&str; 3] = ["x-amz-signature", "x-amz-credential", "signature="];

/// The frozen W2 payload envelope persisted in `jobs.payload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobPayload {
    /// Version of this payload contract.
    pub payload_contract_version: u32,
    /// Identity of the producing component (never a secret).
    pub producer_version: String,
    /// Sorted immutable target references (document versions / storage keys).
    pub immutable_targets: Vec<String>,
    /// Optional dependency hash distinguishing re-analysis generations.
    #[serde(default)]
    pub dependency_hash: Option<String>,
    /// Bounded, screened free-form parameters for the executor.
    #[serde(default = "empty_object")]
    pub parameters: Value,
}

fn empty_object() -> Value {
    serde_json::json!({})
}

impl JobPayload {
    /// Validates an arbitrary JSON value against the full payload contract,
    /// returning the typed envelope on success.
    pub fn validate(raw: &Value) -> Result<Self, JobError> {
        let serialized = serde_json::to_vec(raw)
            .map_err(|e| JobError::InvalidPayload(format!("payload is not valid JSON: {e}")))?;

        if serialized.len() > MAX_PAYLOAD_BYTES {
            return Err(JobError::InvalidPayload(format!(
                "payload serialized size {} exceeds bound {MAX_PAYLOAD_BYTES}",
                serialized.len()
            )));
        }

        let envelope: Self = serde_json::from_value(raw.clone())
            .map_err(|e| JobError::InvalidPayload(format!("payload envelope mismatch: {e}")))?;

        if envelope.payload_contract_version != PAYLOAD_CONTRACT_VERSION {
            return Err(JobError::InvalidPayload(format!(
                "unsupported payload_contract_version {} (expected {PAYLOAD_CONTRACT_VERSION})",
                envelope.payload_contract_version
            )));
        }

        if envelope.producer_version.trim().is_empty() || envelope.producer_version.len() > 128 {
            return Err(JobError::InvalidPayload(
                "producer_version must be non-empty and bounded (<=128 chars)".to_string(),
            ));
        }

        if envelope.immutable_targets.is_empty() || envelope.immutable_targets.len() > 64 {
            return Err(JobError::InvalidPayload(
                "immutable_targets must contain between 1 and 64 entries".to_string(),
            ));
        }
        let mut sorted = envelope.immutable_targets.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != envelope.immutable_targets {
            return Err(JobError::InvalidPayload(
                "immutable_targets must be sorted and de-duplicated".to_string(),
            ));
        }
        for target in &envelope.immutable_targets {
            if target.trim().is_empty() || target.len() > 256 {
                return Err(JobError::InvalidPayload(format!(
                    "immutable target '{target}' is empty or exceeds 256 chars"
                )));
            }
        }

        screen_for_secrets("parameters", &envelope.parameters)?;

        Ok(envelope)
    }

    /// Serializes the envelope to the exact JSONB value persisted in `jobs.payload`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}))
    }

    /// Parses a stored payload back into the typed envelope.
    pub fn from_json(raw: &Value) -> Result<Self, JobError> {
        Self::validate(raw)
    }

    /// Builds a redacted, bounded failure detail string safe for
    /// `job_attempts.error_detail_redacted` / dead-letter evidence.
    ///
    /// Truncation is applied defensively so no unbounded or sensitive blob can
    /// enter durable history through error paths.
    #[must_use]
    pub fn redact_error_detail(detail: &str) -> String {
        const MAX_DETAIL_BYTES: usize = 1024;
        let mut owned = detail.to_string();
        for fragment in PRESIGNED_URL_SIGNATURES {
            // Replace presigned-query remnants with a fixed marker.
            if owned.to_ascii_lowercase().contains(fragment) {
                owned = "[redacted_presigned_url]".to_string();
                break;
            }
        }
        if owned.len() > MAX_DETAIL_BYTES {
            owned.truncate(MAX_DETAIL_BYTES);
            owned.push_str("...[truncated]");
        }
        owned
    }
}

/// Recursively screens a JSON subtree for prohibited sensitive material.
fn screen_for_secrets(path: &str, node: &Value) -> Result<(), JobError> {
    match node {
        Value::Object(map) => {
            if map.len() > 64 {
                return Err(JobError::InvalidPayload(format!(
                    "object at '{path}' exceeds 64 members"
                )));
            }
            for (key, value) in map {
                let lower_key = key.to_ascii_lowercase();
                for fragment in PROHIBITED_KEY_FRAGMENTS {
                    if lower_key.contains(fragment) {
                        return Err(JobError::InvalidPayload(format!(
                            "prohibited sensitive key '{key}' at '{path}'"
                        )));
                    }
                }
                for fragment in PROHIBITED_BYTES_FRAGMENTS {
                    if lower_key.contains(fragment) {
                        return Err(JobError::InvalidPayload(format!(
                            "prohibited raw-bytes key '{key}' at '{path}': \
                             untrusted document content may not travel in payloads"
                        )));
                    }
                }
                screen_for_secrets(&format!("{path}.{key}"), value)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            if items.len() > 256 {
                return Err(JobError::InvalidPayload(format!(
                    "array at '{path}' exceeds 256 items"
                )));
            }
            for (index, item) in items.iter().enumerate() {
                screen_for_secrets(&format!("{path}[{index}]"), item)?;
            }
            Ok(())
        }
        Value::String(text) => {
            if text.len() > 4096 {
                return Err(JobError::InvalidPayload(format!(
                    "string at '{path}' exceeds 4096 chars"
                )));
            }
            let lower = text.to_ascii_lowercase();
            for signature in PRESIGNED_URL_SIGNATURES {
                if lower.contains(signature) {
                    return Err(JobError::InvalidPayload(format!(
                        "presigned URL material detected at '{path}'"
                    )));
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_envelope(parameters: Value) -> Value {
        json!({
            "payload_contract_version": 1,
            "producer_version": "w014-test-producer",
            "immutable_targets": ["dv_11111111"],
            "dependency_hash": null,
            "parameters": parameters
        })
    }

    #[test]
    fn valid_payload_round_trips() {
        let raw = base_envelope(json!({"priority_pages": [1, 2, 3]}));
        let parsed = JobPayload::validate(&raw).expect("valid payload must pass");
        assert_eq!(parsed.producer_version, "w014-test-producer");
        assert_eq!(parsed.immutable_targets, vec!["dv_11111111".to_string()]);
        let round = JobPayload::from_json(&parsed.to_json()).expect("round-trip must pass");
        assert_eq!(parsed, round);
    }

    #[test]
    fn provider_keys_and_secrets_are_rejected() {
        for secret_key in [
            "api_key",
            "apiKey",
            "openai_api_key",
            "session_token",
            "db_connection_string",
            "private_key_pem",
            "authorization_header",
        ] {
            let raw = base_envelope(json!({ secret_key: "hunter2" }));
            let err = JobPayload::validate(&raw)
                .expect_err(&format!("secret key '{secret_key}' must be rejected"));
            assert!(matches!(err, JobError::InvalidPayload(_)));
        }
    }

    #[test]
    fn presigned_urls_are_rejected() {
        let raw = base_envelope(json!({
            "upload_hint": "https://bucket.s3.example/doc?X-Amz-Signature=abc&X-Amz-Credential=x/y"
        }));
        assert!(JobPayload::validate(&raw).is_err());
    }

    #[test]
    fn document_bytes_are_rejected() {
        let raw = base_envelope(json!({"document_bytes": "JVBERi0xLjQK"}));
        let err = JobPayload::validate(&raw).expect_err("document bytes must be rejected");
        assert!(matches!(err, JobError::InvalidPayload(_)));
    }

    #[test]
    fn oversize_payload_is_rejected() {
        let big = "x".repeat(MAX_PAYLOAD_BYTES + 1);
        let raw = base_envelope(json!({"blob": big}));
        assert!(JobPayload::validate(&raw).is_err());
    }

    #[test]
    fn wrong_contract_version_rejected() {
        let mut raw = base_envelope(json!({}));
        raw["payload_contract_version"] = json!(99);
        assert!(JobPayload::validate(&raw).is_err());
    }

    #[test]
    fn unsorted_targets_rejected() {
        let mut raw = base_envelope(json!({}));
        raw["immutable_targets"] = json!(["b_target", "a_target"]);
        assert!(JobPayload::validate(&raw).is_err());
    }

    #[test]
    fn error_redaction_bounds_and_masks() {
        let long = "y".repeat(5000);
        let redacted = JobPayload::redact_error_detail(&long);
        assert!(redacted.len() <= 1100);
        let presigned =
            JobPayload::redact_error_detail("GET https://s3.example/x?X-Amz-Signature=zzz failed");
        assert_eq!(presigned, "[redacted_presigned_url]");
    }
}
