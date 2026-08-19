//! Canonical audit envelope and database record definitions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authoritative audit chain head row in `audit_chain_heads`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditChainHeadRecord {
    /// Workspace identifier uniquely identifying the audit chain.
    pub workspace_id: Uuid,
    /// Current head sequence number (0 if empty/genesis, increments monotonically).
    pub head_sequence_num: i64,
    /// 64-character SHA-256 hash of the latest event in the chain (or genesis hash).
    pub head_event_hash: String,
    /// 64-character genesis hash anchored at chain initialization.
    pub genesis_hash: String,
    /// Timestamp of the last appended event.
    pub last_appended_at: DateTime<Utc>,
    /// Timestamp of last record update.
    pub updated_at: DateTime<Utc>,
}

/// Immutable audit event row in `audit_events`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditEventRecord {
    /// Primary key UUID of the audit event.
    pub id: Uuid,
    /// Workspace to which this audit event strictly belongs.
    pub workspace_id: Uuid,
    /// Monotonically increasing sequence number within the workspace (starts at 1).
    pub sequence_num: i64,
    /// 64-character SHA-256 hash of the preceding event (or genesis hash for seq 1).
    pub previous_event_hash: String,
    /// 64-character SHA-256 hash of this event's canonical envelope.
    pub event_hash: String,
    /// High-level event category/type (e.g., "membership.granted", "workspace.updated").
    pub event_type: String,
    /// Principal UUID who performed the action, if applicable.
    pub actor_principal_id: Option<Uuid>,
    /// Specific action performed (e.g., "CREATE", "UPDATE", "GRANT").
    pub action: String,
    /// Resource entity type affected (e.g., "membership", "workspace", "capability_grant").
    pub resource_type: String,
    /// Resource entity identifier.
    pub resource_id: String,
    /// Structured event payload JSON.
    pub payload: serde_json::Value,
    /// Deferred staged FK to jobs table (nullable in W1).
    pub job_id: Option<Uuid>,
    /// Distributed tracing or request correlation identifier.
    pub correlation_id: Option<String>,
    /// Authoritative UTC timestamp when event was recorded.
    pub recorded_at: DateTime<Utc>,
}

/// Canonical audit envelope used to compute deterministic SHA-256 event hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalAuditEnvelope {
    pub workspace_id: Uuid,
    pub sequence_num: i64,
    pub previous_event_hash: String,
    pub event_type: String,
    pub actor_principal_id: Option<Uuid>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub payload: serde_json::Value,
    pub correlation_id: Option<String>,
    pub recorded_at: DateTime<Utc>,
}

impl CanonicalAuditEnvelope {
    /// Constructs a canonical envelope from an existing audit event record.
    pub fn from_record(record: &AuditEventRecord) -> Self {
        Self {
            workspace_id: record.workspace_id,
            sequence_num: record.sequence_num,
            previous_event_hash: record.previous_event_hash.clone(),
            event_type: record.event_type.clone(),
            actor_principal_id: record.actor_principal_id,
            action: record.action.clone(),
            resource_type: record.resource_type.clone(),
            resource_id: record.resource_id.clone(),
            payload: record.payload.clone(),
            correlation_id: record.correlation_id.clone(),
            recorded_at: record.recorded_at,
        }
    }
}
