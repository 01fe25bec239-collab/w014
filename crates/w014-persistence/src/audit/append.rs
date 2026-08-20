//! Authoritative PostgreSQL Audit Append Implementation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::audit::envelope::{AuditChainHeadRecord, AuditEventRecord, CanonicalAuditEnvelope};
use crate::audit::hasher::{AuditChainHashContract, AuditChainHasher};
use crate::error::PersistenceError;

/// Input parameters for appending an authoritative audit event to a workspace's audit chain.
#[derive(Debug, Clone)]
pub struct AppendAuditParams {
    pub workspace_id: Uuid,
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

/// Authoritative contract for audit chain initialization, retrieval, and append operations.
#[async_trait]
pub trait AuditAppendContract: Send + Sync {
    /// Appends an authoritative audit event to the workspace chain within a database transaction.
    ///
    /// Preserves:
    /// - Strict per-workspace monotonically increasing sequence numbers.
    /// - Cryptographic hash chain linkage anchored at genesis.
    /// - Short row lock serialization on the workspace's `audit_chain_heads` record.
    /// - Atomic insertion into `audit_events` and advancement of `audit_chain_heads`.
    async fn append_audit_event(
        &self,
        tx: &mut PgConnection,
        params: AppendAuditParams,
    ) -> Result<AuditEventRecord, PersistenceError>;

    /// Explicitly initializes an audit chain head for a workspace with sequence 0 and NULL last hash.
    async fn initialize_chain_head(
        &self,
        tx: &mut PgConnection,
        workspace_id: Uuid,
    ) -> Result<AuditChainHeadRecord, PersistenceError>;

    /// Retrieves the current authoritative chain head record for a workspace.
    async fn get_chain_head(
        &self,
        tx: &mut PgConnection,
        workspace_id: Uuid,
    ) -> Result<Option<AuditChainHeadRecord>, PersistenceError>;

    /// Fetches all audit events for a workspace ordered by sequence number ascending.
    async fn fetch_audit_events(
        &self,
        tx: &mut PgConnection,
        workspace_id: Uuid,
    ) -> Result<Vec<AuditEventRecord>, PersistenceError>;
}

/// PostgreSQL production implementation of `AuditAppendContract`.
#[derive(Debug, Clone, Default)]
pub struct PostgresAuditStore {
    hasher: AuditChainHasher,
}

impl PostgresAuditStore {
    pub fn new() -> Self {
        Self {
            hasher: AuditChainHasher,
        }
    }

    pub fn with_hasher(hasher: AuditChainHasher) -> Self {
        Self { hasher }
    }
}

#[async_trait]
impl AuditAppendContract for PostgresAuditStore {
    async fn initialize_chain_head(
        &self,
        tx: &mut PgConnection,
        workspace_id: Uuid,
    ) -> Result<AuditChainHeadRecord, PersistenceError> {
        let row = sqlx::query(
            "INSERT INTO audit_chain_heads (
                workspace_id, last_sequence, last_event_hash, updated_at
            ) VALUES ($1, 0, NULL, clock_timestamp())
            ON CONFLICT (workspace_id) DO UPDATE SET updated_at = clock_timestamp()
            RETURNING workspace_id, last_sequence, last_event_hash, updated_at",
        )
        .bind(workspace_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(AuditChainHeadRecord {
            workspace_id: row.get("workspace_id"),
            last_sequence: row.get("last_sequence"),
            last_event_hash: row.get("last_event_hash"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn get_chain_head(
        &self,
        tx: &mut PgConnection,
        workspace_id: Uuid,
    ) -> Result<Option<AuditChainHeadRecord>, PersistenceError> {
        let maybe_row = sqlx::query(
            "SELECT workspace_id, last_sequence, last_event_hash, updated_at
             FROM audit_chain_heads
             WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(maybe_row.map(|row| AuditChainHeadRecord {
            workspace_id: row.get("workspace_id"),
            last_sequence: row.get("last_sequence"),
            last_event_hash: row.get("last_event_hash"),
            updated_at: row.get("updated_at"),
        }))
    }

    async fn append_audit_event(
        &self,
        tx: &mut PgConnection,
        params: AppendAuditParams,
    ) -> Result<AuditEventRecord, PersistenceError> {
        // 1. Ensure chain head exists (idempotent insert), then acquire exclusive row lock FOR UPDATE
        sqlx::query(
            "INSERT INTO audit_chain_heads (
                workspace_id, last_sequence, last_event_hash, updated_at
            ) VALUES ($1, 0, NULL, clock_timestamp())
            ON CONFLICT (workspace_id) DO NOTHING",
        )
        .bind(params.workspace_id)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let head_row = sqlx::query(
            "SELECT last_sequence, last_event_hash, clock_timestamp() as now_ts
             FROM audit_chain_heads
             WHERE workspace_id = $1
             FOR UPDATE",
        )
        .bind(params.workspace_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let current_seq: i64 = head_row.get("last_sequence");
        let prev_hash: Option<Vec<u8>> = head_row.get("last_event_hash");
        let occurred_at: DateTime<Utc> = head_row.get("now_ts");

        let next_seq = current_seq + 1;
        let audit_event_id = Uuid::new_v4();

        // 2. Build canonical audit envelope and compute deterministic SHA-256 hash
        let envelope = CanonicalAuditEnvelope {
            audit_event_id,
            workspace_id: params.workspace_id,
            sequence: next_seq,
            occurred_at,
            actor_type: params.actor_type.clone(),
            actor_id: params.actor_id,
            authority_snapshot: params.authority_snapshot.clone(),
            action_code: params.action_code.clone(),
            entity_type: params.entity_type.clone(),
            entity_id: params.entity_id.clone(),
            entity_version: params.entity_version,
            request_id: params.request_id.clone(),
            correlation_id: params.correlation_id.clone(),
            job_id: params.job_id,
            source_state_hash: params.source_state_hash.clone(),
            before_ref: params.before_ref.clone(),
            after_ref: params.after_ref.clone(),
            metadata: params.metadata.clone(),
        };

        let event_hash = self
            .hasher
            .compute_event_hash(prev_hash.as_deref(), &envelope);

        // 3. Insert immutable event into audit_events
        let insert_row = sqlx::query(
            "INSERT INTO audit_events (
                audit_event_id, workspace_id, sequence, occurred_at,
                actor_type, actor_id, authority_snapshot, action_code,
                entity_type, entity_id, entity_version, request_id,
                correlation_id, job_id, source_state_hash, before_ref,
                after_ref, metadata, previous_event_hash, event_hash
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
            RETURNING audit_event_id, workspace_id, sequence, occurred_at,
                      actor_type, actor_id, authority_snapshot, action_code,
                      entity_type, entity_id, entity_version, request_id,
                      correlation_id, job_id, source_state_hash, before_ref,
                      after_ref, metadata, previous_event_hash, event_hash",
        )
        .bind(audit_event_id)
        .bind(params.workspace_id)
        .bind(next_seq)
        .bind(occurred_at)
        .bind(&params.actor_type)
        .bind(params.actor_id)
        .bind(&params.authority_snapshot)
        .bind(&params.action_code)
        .bind(&params.entity_type)
        .bind(&params.entity_id)
        .bind(params.entity_version)
        .bind(&params.request_id)
        .bind(&params.correlation_id)
        .bind(params.job_id)
        .bind(&params.source_state_hash)
        .bind(&params.before_ref)
        .bind(&params.after_ref)
        .bind(&params.metadata)
        .bind(&prev_hash)
        .bind(&event_hash)
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        // 4. Update audit_chain_heads with new sequence and head event hash
        sqlx::query(
            "UPDATE audit_chain_heads
             SET last_sequence = $2,
                 last_event_hash = $3,
                 updated_at = $4
             WHERE workspace_id = $1",
        )
        .bind(params.workspace_id)
        .bind(next_seq)
        .bind(&event_hash)
        .bind(occurred_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(AuditEventRecord {
            audit_event_id: insert_row.get("audit_event_id"),
            workspace_id: insert_row.get("workspace_id"),
            sequence: insert_row.get("sequence"),
            occurred_at: insert_row.get("occurred_at"),
            actor_type: insert_row.get("actor_type"),
            actor_id: insert_row.get("actor_id"),
            authority_snapshot: insert_row.get("authority_snapshot"),
            action_code: insert_row.get("action_code"),
            entity_type: insert_row.get("entity_type"),
            entity_id: insert_row.get("entity_id"),
            entity_version: insert_row.get("entity_version"),
            request_id: insert_row.get("request_id"),
            correlation_id: insert_row.get("correlation_id"),
            job_id: insert_row.get("job_id"),
            source_state_hash: insert_row.get("source_state_hash"),
            before_ref: insert_row.get("before_ref"),
            after_ref: insert_row.get("after_ref"),
            metadata: insert_row.get("metadata"),
            previous_event_hash: insert_row.get("previous_event_hash"),
            event_hash: insert_row.get("event_hash"),
        })
    }

    async fn fetch_audit_events(
        &self,
        tx: &mut PgConnection,
        workspace_id: Uuid,
    ) -> Result<Vec<AuditEventRecord>, PersistenceError> {
        let rows = sqlx::query(
            "SELECT audit_event_id, workspace_id, sequence, occurred_at,
                    actor_type, actor_id, authority_snapshot, action_code,
                    entity_type, entity_id, entity_version, request_id,
                    correlation_id, job_id, source_state_hash, before_ref,
                    after_ref, metadata, previous_event_hash, event_hash
             FROM audit_events
             WHERE workspace_id = $1
             ORDER BY sequence ASC",
        )
        .bind(workspace_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let records = rows
            .into_iter()
            .map(|row| AuditEventRecord {
                audit_event_id: row.get("audit_event_id"),
                workspace_id: row.get("workspace_id"),
                sequence: row.get("sequence"),
                occurred_at: row.get("occurred_at"),
                actor_type: row.get("actor_type"),
                actor_id: row.get("actor_id"),
                authority_snapshot: row.get("authority_snapshot"),
                action_code: row.get("action_code"),
                entity_type: row.get("entity_type"),
                entity_id: row.get("entity_id"),
                entity_version: row.get("entity_version"),
                request_id: row.get("request_id"),
                correlation_id: row.get("correlation_id"),
                job_id: row.get("job_id"),
                source_state_hash: row.get("source_state_hash"),
                before_ref: row.get("before_ref"),
                after_ref: row.get("after_ref"),
                metadata: row.get("metadata"),
                previous_event_hash: row.get("previous_event_hash"),
                event_hash: row.get("event_hash"),
            })
            .collect();

        Ok(records)
    }
}
