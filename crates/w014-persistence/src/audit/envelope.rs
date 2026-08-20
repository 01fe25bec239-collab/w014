//! Canonical audit envelope and database record definitions conforming to Prompt-12 / Prompt-13.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authoritative audit chain head row in `audit_chain_heads`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditChainHeadRecord {
    /// Workspace identifier uniquely identifying the audit chain.
    pub workspace_id: Uuid,
    /// Current head sequence number (0 if empty/genesis, increments monotonically).
    pub last_sequence: i64,
    /// 32-byte SHA-256 hash of the latest event in the chain (or NULL for sequence 0).
    pub last_event_hash: Option<Vec<u8>>,
    /// Timestamp of last record update.
    pub updated_at: DateTime<Utc>,
}

/// Immutable audit event row in `audit_events`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditEventRecord {
    /// Primary key UUID of the audit event.
    pub audit_event_id: Uuid,
    /// Workspace to which this audit event strictly belongs.
    pub workspace_id: Uuid,
    /// Monotonically increasing sequence number within the workspace (starts at 1).
    pub sequence: i64,
    /// Authoritative UTC timestamp when event occurred (DB clock_timestamp()).
    pub occurred_at: DateTime<Utc>,
    /// Actor type (e.g., "user", "system", "worker", "service").
    pub actor_type: String,
    /// Principal UUID who performed the action, if applicable.
    pub actor_id: Option<Uuid>,
    /// Security / capability snapshot at the time of execution.
    pub authority_snapshot: serde_json::Value,
    /// Specific action code performed (e.g., "WORKSPACE_CREATE", "CAPABILITY_GRANT").
    pub action_code: String,
    /// Target entity type (e.g., "workspace", "membership", "capability_grant").
    pub entity_type: String,
    /// Target entity identifier.
    pub entity_id: String,
    /// Entity version at the time of mutation.
    pub entity_version: Option<i32>,
    /// Inbound HTTP request ID.
    pub request_id: Option<String>,
    /// Distributed tracing or request correlation identifier.
    pub correlation_id: Option<String>,
    /// Deferred staged FK to jobs table (nullable in W1/R1).
    pub job_id: Option<Uuid>,
    /// Source contract state hash if applicable.
    pub source_state_hash: Option<Vec<u8>>,
    /// State snapshot before mutation.
    pub before_ref: Option<serde_json::Value>,
    /// State snapshot after mutation.
    pub after_ref: Option<serde_json::Value>,
    /// Additional structured metadata.
    pub metadata: serde_json::Value,
    /// 32-byte SHA-256 hash of the preceding event (NULL for seq 1).
    pub previous_event_hash: Option<Vec<u8>>,
    /// 32-byte SHA-256 hash of this event's canonical envelope.
    pub event_hash: Vec<u8>,
}

/// Canonical audit envelope used for RFC-8785 canonicalization and deterministic SHA-256 event hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalAuditEnvelope {
    pub audit_event_id: Uuid,
    pub workspace_id: Uuid,
    pub sequence: i64,
    pub occurred_at: DateTime<Utc>,
    pub actor_type: String,
    pub actor_id: Option<Uuid>,
    pub authority_snapshot: serde_json::Value,
    pub action_code: String,
    pub entity_type: String,
    pub entity_id: String,
    pub entity_version: Option<i32>,
    pub request_id: Option<String>,
    pub correlation_id: Option<String>,
    pub job_id: Option<Uuid>,
    pub source_state_hash: Option<Vec<u8>>,
    pub before_ref: Option<serde_json::Value>,
    pub after_ref: Option<serde_json::Value>,
    pub metadata: serde_json::Value,
}

impl CanonicalAuditEnvelope {
    /// Serializes the canonical envelope fields into a JSON Value with standard representations.
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "action_code": self.action_code,
            "actor_id": self.actor_id.map(|id| id.to_string()),
            "actor_type": self.actor_type,
            "after_ref": self.after_ref,
            "audit_event_id": self.audit_event_id.to_string(),
            "authority_snapshot": self.authority_snapshot,
            "before_ref": self.before_ref,
            "correlation_id": self.correlation_id,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "entity_version": self.entity_version,
            "job_id": self.job_id.map(|id| id.to_string()),
            "metadata": self.metadata,
            "occurred_at": self.occurred_at.to_rfc3339(),
            "request_id": self.request_id,
            "sequence": self.sequence,
            "source_state_hash": self.source_state_hash.as_ref().map(hex::encode),
            "workspace_id": self.workspace_id.to_string(),
        })
    }

    /// Constructs a canonical envelope from an existing audit event record.
    pub fn from_record(record: &AuditEventRecord) -> Self {
        Self {
            audit_event_id: record.audit_event_id,
            workspace_id: record.workspace_id,
            sequence: record.sequence,
            occurred_at: record.occurred_at,
            actor_type: record.actor_type.clone(),
            actor_id: record.actor_id,
            authority_snapshot: record.authority_snapshot.clone(),
            action_code: record.action_code.clone(),
            entity_type: record.entity_type.clone(),
            entity_id: record.entity_id.clone(),
            entity_version: record.entity_version,
            request_id: record.request_id.clone(),
            correlation_id: record.correlation_id.clone(),
            job_id: record.job_id,
            source_state_hash: record.source_state_hash.clone(),
            before_ref: record.before_ref.clone(),
            after_ref: record.after_ref.clone(),
            metadata: record.metadata.clone(),
        }
    }
}
