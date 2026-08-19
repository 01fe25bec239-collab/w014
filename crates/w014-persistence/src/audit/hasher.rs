//! Authoritative SHA-256 Audit Chain Hash Contract and Integrity Verification.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::audit::envelope::{AuditEventRecord, CanonicalAuditEnvelope};
use crate::error::AuditIntegrityError;

/// Authoritative genesis hash used as the root for all workspace audit chains.
/// 64 zeros representing a null / genesis state.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Contract defining canonical audit envelope hashing and chain integrity verification.
pub trait AuditChainHashContract: Send + Sync {
    /// Returns the authoritative genesis hash anchored for new workspace chains.
    fn genesis_hash(&self) -> &str;

    /// Computes the deterministic SHA-256 hash of a canonical audit envelope.
    fn compute_event_hash(&self, envelope: &CanonicalAuditEnvelope) -> String;

    /// Verifies whether the computed hash of an envelope matches the expected recorded hash.
    fn verify_event_hash(&self, envelope: &CanonicalAuditEnvelope, expected_hash: &str) -> bool {
        let computed = self.compute_event_hash(envelope);
        computed.eq_ignore_ascii_case(expected_hash)
    }

    /// Verifies the complete cryptographic and sequential integrity of an ordered audit chain.
    ///
    /// Checks:
    /// 1. Strict sequence monotonicity: sequence starts at 1 and increments by 1 for each event.
    /// 2. Previous hash linkage: sequence 1 links to genesis_hash, subsequent events link to prior event hash.
    /// 3. Event hash validity: recomputed canonical envelope hash matches stored `event_hash`.
    /// 4. Workspace consistency: all events in the chain belong to the same workspace.
    fn verify_chain_integrity(
        &self,
        events: &[AuditEventRecord],
    ) -> Result<(), AuditIntegrityError>;
}

/// Default production implementation of `AuditChainHashContract` using SHA-256.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuditChainHasher;

impl AuditChainHasher {
    /// Returns the static genesis hash string.
    pub fn genesis_hash_static() -> &'static str {
        GENESIS_HASH
    }

    /// Helper to compute hash directly from a canonical envelope.
    pub fn hash_envelope(envelope: &CanonicalAuditEnvelope) -> String {
        let canonical_bytes = serde_json::to_vec(envelope).unwrap_or_default();
        let digest = Sha256::digest(&canonical_bytes);
        hex::encode(digest)
    }
}

impl AuditChainHashContract for AuditChainHasher {
    fn genesis_hash(&self) -> &str {
        GENESIS_HASH
    }

    fn compute_event_hash(&self, envelope: &CanonicalAuditEnvelope) -> String {
        Self::hash_envelope(envelope)
    }

    fn verify_chain_integrity(
        &self,
        events: &[AuditEventRecord],
    ) -> Result<(), AuditIntegrityError> {
        if events.is_empty() {
            return Ok(());
        }

        let expected_workspace_id: Uuid = events[0].workspace_id;
        let mut previous_hash = self.genesis_hash().to_string();

        for (idx, event) in events.iter().enumerate() {
            let expected_seq = (idx as i64) + 1;

            // 1. Check workspace consistency
            if event.workspace_id != expected_workspace_id {
                return Err(AuditIntegrityError::WorkspaceMismatch {
                    sequence_num: event.sequence_num,
                    expected: expected_workspace_id,
                    actual: event.workspace_id,
                });
            }

            // 2. Check strict sequence ordering
            if event.sequence_num != expected_seq {
                if event.sequence_num < expected_seq {
                    return Err(AuditIntegrityError::SequenceDisorder {
                        index: idx,
                        previous: expected_seq - 1,
                        current: event.sequence_num,
                    });
                } else {
                    return Err(AuditIntegrityError::SequenceGap {
                        index: idx,
                        expected: expected_seq,
                        actual: event.sequence_num,
                    });
                }
            }

            // 3. Check previous event hash linkage
            if !event
                .previous_event_hash
                .eq_ignore_ascii_case(&previous_hash)
            {
                return Err(AuditIntegrityError::PreviousHashMismatch {
                    sequence_num: event.sequence_num,
                    expected: previous_hash,
                    actual: event.previous_event_hash.clone(),
                });
            }

            // 4. Verify cryptographic hash of this event's canonical envelope
            let envelope = CanonicalAuditEnvelope::from_record(event);
            let computed_hash = self.compute_event_hash(&envelope);
            if !computed_hash.eq_ignore_ascii_case(&event.event_hash) {
                return Err(AuditIntegrityError::HashTamperDetected {
                    sequence_num: event.sequence_num,
                    recorded_hash: event.event_hash.clone(),
                    computed_hash,
                });
            }

            previous_hash = event.event_hash.clone();
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
    fn test_genesis_hash_format() {
        let hasher = AuditChainHasher;
        assert_eq!(hasher.genesis_hash().len(), 64);
        assert_eq!(
            hasher.genesis_hash(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_compute_event_hash_deterministic() {
        let hasher = AuditChainHasher;
        let ws_id = Uuid::new_v4();
        let now = Utc::now();

        let env1 = CanonicalAuditEnvelope {
            workspace_id: ws_id,
            sequence_num: 1,
            previous_event_hash: hasher.genesis_hash().to_string(),
            event_type: "workspace.created".to_string(),
            actor_principal_id: None,
            action: "CREATE".to_string(),
            resource_type: "workspace".to_string(),
            resource_id: ws_id.to_string(),
            payload: json!({"name": "Test Workspace"}),
            correlation_id: Some("corr-123".to_string()),
            recorded_at: now,
        };

        let env2 = env1.clone();

        let hash1 = hasher.compute_event_hash(&env1);
        let hash2 = hasher.compute_event_hash(&env2);

        assert_eq!(hash1.len(), 64);
        assert_eq!(hash1, hash2);
        assert!(hasher.verify_event_hash(&env1, &hash1));
    }

    #[test]
    fn test_tamper_detection_on_modified_payload() {
        let hasher = AuditChainHasher;
        let ws_id = Uuid::new_v4();
        let now = Utc::now();

        let env = CanonicalAuditEnvelope {
            workspace_id: ws_id,
            sequence_num: 1,
            previous_event_hash: hasher.genesis_hash().to_string(),
            event_type: "capability.granted".to_string(),
            actor_principal_id: None,
            action: "GRANT".to_string(),
            resource_type: "capability_grant".to_string(),
            resource_id: "cap-1".to_string(),
            payload: json!({"capability": "admin"}),
            correlation_id: None,
            recorded_at: now,
        };

        let original_hash = hasher.compute_event_hash(&env);

        let mut tampered_env = env.clone();
        tampered_env.payload = json!({"capability": "superadmin"});

        assert!(!hasher.verify_event_hash(&tampered_env, &original_hash));
    }

    #[test]
    fn test_verify_chain_integrity_valid_sequence() {
        let hasher = AuditChainHasher;
        let ws_id = Uuid::new_v4();
        let now = Utc::now();

        let mut events = Vec::new();
        let mut prev_hash = hasher.genesis_hash().to_string();

        for seq in 1..=5 {
            let env = CanonicalAuditEnvelope {
                workspace_id: ws_id,
                sequence_num: seq,
                previous_event_hash: prev_hash.clone(),
                event_type: format!("event.type.{seq}"),
                actor_principal_id: None,
                action: "UPDATE".to_string(),
                resource_type: "resource".to_string(),
                resource_id: format!("res-{seq}"),
                payload: json!({"step": seq}),
                correlation_id: None,
                recorded_at: now,
            };
            let event_hash = hasher.compute_event_hash(&env);

            let record = AuditEventRecord {
                id: Uuid::new_v4(),
                workspace_id: ws_id,
                sequence_num: seq,
                previous_event_hash: prev_hash,
                event_hash: event_hash.clone(),
                event_type: env.event_type,
                actor_principal_id: env.actor_principal_id,
                action: env.action,
                resource_type: env.resource_type,
                resource_id: env.resource_id,
                payload: env.payload,
                job_id: None,
                correlation_id: env.correlation_id,
                recorded_at: env.recorded_at,
            };

            prev_hash = event_hash;
            events.push(record);
        }

        assert!(hasher.verify_chain_integrity(&events).is_ok());
    }

    #[test]
    fn test_verify_chain_integrity_detects_gap() {
        let hasher = AuditChainHasher;
        let ws_id = Uuid::new_v4();
        let now = Utc::now();

        let mut events = Vec::new();
        let prev_hash = hasher.genesis_hash().to_string();

        // Event 1
        let env1 = CanonicalAuditEnvelope {
            workspace_id: ws_id,
            sequence_num: 1,
            previous_event_hash: prev_hash.clone(),
            event_type: "event.1".to_string(),
            actor_principal_id: None,
            action: "A".to_string(),
            resource_type: "R".to_string(),
            resource_id: "1".to_string(),
            payload: json!({}),
            correlation_id: None,
            recorded_at: now,
        };
        let hash1 = hasher.compute_event_hash(&env1);
        events.push(AuditEventRecord {
            id: Uuid::new_v4(),
            workspace_id: ws_id,
            sequence_num: 1,
            previous_event_hash: prev_hash,
            event_hash: hash1.clone(),
            event_type: env1.event_type,
            actor_principal_id: None,
            action: env1.action,
            resource_type: env1.resource_type,
            resource_id: env1.resource_id,
            payload: env1.payload,
            job_id: None,
            correlation_id: None,
            recorded_at: now,
        });

        // Event 3 (skipping seq 2 -> GAP)
        let env3 = CanonicalAuditEnvelope {
            workspace_id: ws_id,
            sequence_num: 3,
            previous_event_hash: hash1.clone(),
            event_type: "event.3".to_string(),
            actor_principal_id: None,
            action: "A".to_string(),
            resource_type: "R".to_string(),
            resource_id: "3".to_string(),
            payload: json!({}),
            correlation_id: None,
            recorded_at: now,
        };
        let hash3 = hasher.compute_event_hash(&env3);
        events.push(AuditEventRecord {
            id: Uuid::new_v4(),
            workspace_id: ws_id,
            sequence_num: 3,
            previous_event_hash: hash1,
            event_hash: hash3,
            event_type: env3.event_type,
            actor_principal_id: None,
            action: env3.action,
            resource_type: env3.resource_type,
            resource_id: env3.resource_id,
            payload: env3.payload,
            job_id: None,
            correlation_id: None,
            recorded_at: now,
        });

        let res = hasher.verify_chain_integrity(&events);
        match res {
            Err(AuditIntegrityError::SequenceGap {
                expected: 2,
                actual: 3,
                ..
            }) => {}
            other => panic!("Expected SequenceGap error, got: {other:?}"),
        }
    }
}
