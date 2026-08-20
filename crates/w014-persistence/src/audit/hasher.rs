//! Authoritative SHA-256 Audit Chain Hash Contract and RFC-8785 JSON Canonicalization.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::audit::envelope::{AuditEventRecord, CanonicalAuditEnvelope};
use crate::error::AuditIntegrityError;

/// Serializes a `serde_json::Value` according to RFC-8785 JSON Canonicalization Scheme (JCS).
///
/// Rules:
/// - Deterministic UTF-8 encoding
/// - Strict lexicographical UTF-16 code unit sorting of object keys
/// - No whitespace outside JSON strings
/// - Standard ECMAScript number representations
/// - Minimal character escaping (`\"`, `\\`, and control characters `\u0000`..`\u001F`)
pub fn canonicalize_json(val: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::new();
    canonicalize_value(val, &mut out);
    out
}

fn canonicalize_value(val: &serde_json::Value, out: &mut Vec<u8>) {
    match val {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(b) => {
            if *b {
                out.extend_from_slice(b"true");
            } else {
                out.extend_from_slice(b"false");
            }
        }
        serde_json::Value::Number(n) => {
            out.extend_from_slice(n.to_string().as_bytes());
        }
        serde_json::Value::String(s) => {
            canonicalize_string(s, out);
        }
        serde_json::Value::Array(arr) => {
            out.push(b'[');
            for (idx, item) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                canonicalize_value(item, out);
            }
            out.push(b']');
        }
        serde_json::Value::Object(map) => {
            // RFC-8785: Sort keys by UTF-16 code units
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|(k1, _), (k2, _)| k1.encode_utf16().cmp(k2.encode_utf16()));

            out.push(b'{');
            for (idx, (k, v)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                canonicalize_string(k, out);
                out.push(b':');
                canonicalize_value(v, out);
            }
            out.push(b'}');
        }
    }
}

fn canonicalize_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\x08' => out.extend_from_slice(b"\\b"),
            '\x0C' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                let formatted = format!("\\u{:04x}", c as u32);
                out.extend_from_slice(formatted.as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                let enc = c.encode_utf8(&mut buf);
                out.extend_from_slice(enc.as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Contract defining canonical audit envelope hashing and chain integrity verification.
pub trait AuditChainHashContract: Send + Sync {
    /// Computes the deterministic SHA-256 hash:
    /// `SHA256(previous_event_hash || 0x00 || canonical_event_bytes)`
    fn compute_event_hash(
        &self,
        previous_event_hash: Option<&[u8]>,
        envelope: &CanonicalAuditEnvelope,
    ) -> Vec<u8>;

    /// Verifies whether the computed hash matches the expected recorded hash.
    fn verify_event_hash(
        &self,
        previous_event_hash: Option<&[u8]>,
        envelope: &CanonicalAuditEnvelope,
        expected_hash: &[u8],
    ) -> bool {
        let computed = self.compute_event_hash(previous_event_hash, envelope);
        computed == expected_hash
    }

    /// Verifies the complete cryptographic and sequential integrity of an ordered audit chain.
    fn verify_chain_integrity(
        &self,
        events: &[AuditEventRecord],
    ) -> Result<(), AuditIntegrityError>;
}

/// Default production implementation of `AuditChainHashContract` using SHA-256 and RFC-8785.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuditChainHasher;

impl AuditChainHasher {
    /// Helper to compute hash directly from a canonical envelope and preceding hash.
    pub fn hash_envelope(
        previous_event_hash: Option<&[u8]>,
        envelope: &CanonicalAuditEnvelope,
    ) -> Vec<u8> {
        let json_val = envelope.to_json_value();
        let canonical_bytes = canonicalize_json(&json_val);

        let mut hasher = Sha256::new();
        if let Some(prev) = previous_event_hash {
            hasher.update(prev);
        }
        hasher.update([0x00]);
        hasher.update(&canonical_bytes);

        hasher.finalize().to_vec()
    }
}

impl AuditChainHashContract for AuditChainHasher {
    fn compute_event_hash(
        &self,
        previous_event_hash: Option<&[u8]>,
        envelope: &CanonicalAuditEnvelope,
    ) -> Vec<u8> {
        Self::hash_envelope(previous_event_hash, envelope)
    }

    fn verify_chain_integrity(
        &self,
        events: &[AuditEventRecord],
    ) -> Result<(), AuditIntegrityError> {
        if events.is_empty() {
            return Ok(());
        }

        let expected_workspace_id: Uuid = events[0].workspace_id;
        let mut prev_hash: Option<Vec<u8>> = None;

        for (idx, event) in events.iter().enumerate() {
            let expected_seq = (idx as i64) + 1;

            // 1. Check workspace consistency
            if event.workspace_id != expected_workspace_id {
                return Err(AuditIntegrityError::WorkspaceMismatch {
                    sequence: event.sequence,
                    expected: expected_workspace_id,
                    actual: event.workspace_id,
                });
            }

            // 2. Check strict sequence ordering
            if event.sequence != expected_seq {
                if event.sequence < expected_seq {
                    return Err(AuditIntegrityError::SequenceDisorder {
                        index: idx,
                        previous: expected_seq - 1,
                        current: event.sequence,
                    });
                } else {
                    return Err(AuditIntegrityError::SequenceGap {
                        index: idx,
                        expected: expected_seq,
                        actual: event.sequence,
                    });
                }
            }

            // 3. Check previous event hash linkage
            if event.previous_event_hash != prev_hash {
                return Err(AuditIntegrityError::PreviousHashMismatch {
                    sequence: event.sequence,
                    expected: prev_hash
                        .as_ref()
                        .map(hex::encode)
                        .unwrap_or_else(|| "NULL".to_string()),
                    actual: event
                        .previous_event_hash
                        .as_ref()
                        .map(hex::encode)
                        .unwrap_or_else(|| "NULL".to_string()),
                });
            }

            // 4. Verify cryptographic hash of this event's canonical envelope
            let envelope = CanonicalAuditEnvelope::from_record(event);
            let computed_hash = self.compute_event_hash(prev_hash.as_deref(), &envelope);
            if computed_hash != event.event_hash {
                return Err(AuditIntegrityError::HashTamperDetected {
                    sequence: event.sequence,
                    recorded_hash: hex::encode(&event.event_hash),
                    computed_hash: hex::encode(computed_hash),
                });
            }

            prev_hash = Some(event.event_hash.clone());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn test_rfc8785_canonicalization_key_sorting() {
        let val1 = json!({"b": 1, "a": 2, "c": 3});
        let val2 = json!({"c": 3, "a": 2, "b": 1});
        let bytes1 = canonicalize_json(&val1);
        let bytes2 = canonicalize_json(&val2);
        assert_eq!(bytes1, bytes2);
        assert_eq!(
            String::from_utf8(bytes1).unwrap(),
            "{\"a\":2,\"b\":1,\"c\":3}"
        );
    }

    #[test]
    fn test_compute_event_hash_deterministic() {
        let hasher = AuditChainHasher;
        let ws_id = Uuid::new_v4();
        let ev_id = Uuid::new_v4();
        let now = Utc::now();

        let env1 = CanonicalAuditEnvelope {
            audit_event_id: ev_id,
            workspace_id: ws_id,
            sequence: 1,
            occurred_at: now,
            actor_type: "user".to_string(),
            actor_id: None,
            authority_snapshot: json!({}),
            action_code: "WORKSPACE_CREATE".to_string(),
            entity_type: "workspace".to_string(),
            entity_id: ws_id.to_string(),
            entity_version: Some(1),
            request_id: Some("req-1".to_string()),
            correlation_id: Some("corr-123".to_string()),
            job_id: None,
            source_state_hash: None,
            before_ref: None,
            after_ref: Some(json!({"name": "Test Workspace"})),
            metadata: json!({"environment": "test"}),
        };

        let env2 = env1.clone();

        let hash1 = hasher.compute_event_hash(None, &env1);
        let hash2 = hasher.compute_event_hash(None, &env2);

        assert_eq!(hash1.len(), 32);
        assert_eq!(hash1, hash2);
        assert!(hasher.verify_event_hash(None, &env1, &hash1));
    }

    #[test]
    fn test_tamper_detection_on_modified_metadata() {
        let hasher = AuditChainHasher;
        let ws_id = Uuid::new_v4();
        let ev_id = Uuid::new_v4();
        let now = Utc::now();

        let env = CanonicalAuditEnvelope {
            audit_event_id: ev_id,
            workspace_id: ws_id,
            sequence: 1,
            occurred_at: now,
            actor_type: "user".to_string(),
            actor_id: None,
            authority_snapshot: json!({}),
            action_code: "CAPABILITY_GRANT".to_string(),
            entity_type: "capability_grant".to_string(),
            entity_id: "cap-1".to_string(),
            entity_version: Some(1),
            request_id: None,
            correlation_id: None,
            job_id: None,
            source_state_hash: None,
            before_ref: None,
            after_ref: None,
            metadata: json!({"capability": "admin"}),
        };

        let original_hash = hasher.compute_event_hash(None, &env);

        let mut tampered_env = env.clone();
        tampered_env.metadata = json!({"capability": "superadmin"});

        assert!(!hasher.verify_event_hash(None, &tampered_env, &original_hash));
    }
}
