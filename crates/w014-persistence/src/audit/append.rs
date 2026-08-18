//! Authoritative PostgreSQL Audit Append Implementation.

use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::audit::envelope::{AuditChainHeadRecord, AuditEventRecord, CanonicalAuditEnvelope};
use crate::audit::hasher::{AuditChainHashContract, AuditChainHasher};
use crate::error::PersistenceError;

/// Input parameters for appending an authoritative audit event to a workspace's audit chain.
#[derive(Debug, Clone)]
pub struct AppendAuditParams {
    pub workspace_id: Uuid,
    pub event_type: String,
    pub actor_principal_id: Option<Uuid>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub payload: serde_json::Value,
    pub correlation_id: Option<String>,
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

    /// Explicitly initializes an audit chain head for a workspace with sequence 0 and genesis hash.
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
        let genesis = self.hasher.genesis_hash();
        let row = sqlx::query(
            "INSERT INTO audit_chain_heads (
                workspace_id, head_sequence_num, head_event_hash, genesis_hash, last_appended_at, updated_at
            ) VALUES ($1, 0, $2, $2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (workspace_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
            RETURNING workspace_id, head_sequence_num, head_event_hash, genesis_hash, last_appended_at, updated_at"
        )
        .bind(workspace_id)
        .bind(genesis)
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(AuditChainHeadRecord {
            workspace_id: row.get("workspace_id"),
            head_sequence_num: row.get("head_sequence_num"),
            head_event_hash: row.get("head_event_hash"),
            genesis_hash: row.get("genesis_hash"),
            last_appended_at: row.get("last_appended_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn get_chain_head(
        &self,
        tx: &mut PgConnection,
        workspace_id: Uuid,
    ) -> Result<Option<AuditChainHeadRecord>, PersistenceError> {
        let maybe_row = sqlx::query(
            "SELECT workspace_id, head_sequence_num, head_event_hash, genesis_hash, last_appended_at, updated_at
             FROM audit_chain_heads
             WHERE workspace_id = $1"
        )
        .bind(workspace_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(maybe_row.map(|row| AuditChainHeadRecord {
            workspace_id: row.get("workspace_id"),
            head_sequence_num: row.get("head_sequence_num"),
            head_event_hash: row.get("head_event_hash"),
            genesis_hash: row.get("genesis_hash"),
            last_appended_at: row.get("last_appended_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    async fn append_audit_event(
        &self,
        tx: &mut PgConnection,
        params: AppendAuditParams,
    ) -> Result<AuditEventRecord, PersistenceError> {
        // 1. Ensure chain head exists (idempotent insert), then acquire exclusive row lock FOR UPDATE
        let genesis = self.hasher.genesis_hash();
        sqlx::query(
            "INSERT INTO audit_chain_heads (
                workspace_id, head_sequence_num, head_event_hash, genesis_hash, last_appended_at, updated_at
            ) VALUES ($1, 0, $2, $2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (workspace_id) DO NOTHING"
        )
        .bind(params.workspace_id)
        .bind(genesis)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let head_row = sqlx::query(
            "SELECT head_sequence_num, head_event_hash, genesis_hash
             FROM audit_chain_heads
             WHERE workspace_id = $1
             FOR UPDATE",
        )
        .bind(params.workspace_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let current_seq: i64 = head_row.get("head_sequence_num");
        let prev_hash: String = head_row.get("head_event_hash");

        let next_seq = current_seq + 1;
        let recorded_at = Utc::now();

        // 2. Build canonical audit envelope and compute deterministic SHA-256 hash
        let envelope = CanonicalAuditEnvelope {
            workspace_id: params.workspace_id,
            sequence_num: next_seq,
            previous_event_hash: prev_hash.clone(),
            event_type: params.event_type.clone(),
            actor_principal_id: params.actor_principal_id,
            action: params.action.clone(),
            resource_type: params.resource_type.clone(),
            resource_id: params.resource_id.clone(),
            payload: params.payload.clone(),
            correlation_id: params.correlation_id.clone(),
            recorded_at,
        };

        let event_hash = self.hasher.compute_event_hash(&envelope);

        // 3. Insert immutable event into audit_events
        let insert_row = sqlx::query(
            "INSERT INTO audit_events (
                workspace_id, sequence_num, previous_event_hash, event_hash,
                event_type, actor_principal_id, action, resource_type, resource_id,
                payload, job_id, correlation_id, recorded_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, $11, $12)
            RETURNING id, workspace_id, sequence_num, previous_event_hash, event_hash,
                      event_type, actor_principal_id, action, resource_type, resource_id,
                      payload, job_id, correlation_id, recorded_at",
        )
        .bind(params.workspace_id)
        .bind(next_seq)
        .bind(&prev_hash)
        .bind(&event_hash)
        .bind(&params.event_type)
        .bind(params.actor_principal_id)
        .bind(&params.action)
        .bind(&params.resource_type)
        .bind(&params.resource_id)
        .bind(&params.payload)
        .bind(&params.correlation_id)
        .bind(recorded_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        // 4. Update audit_chain_heads with new sequence and head event hash
        sqlx::query(
            "UPDATE audit_chain_heads
             SET head_sequence_num = $2,
                 head_event_hash = $3,
                 last_appended_at = $4,
                 updated_at = CURRENT_TIMESTAMP
             WHERE workspace_id = $1",
        )
        .bind(params.workspace_id)
        .bind(next_seq)
        .bind(&event_hash)
        .bind(recorded_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(AuditEventRecord {
            id: insert_row.get("id"),
            workspace_id: insert_row.get("workspace_id"),
            sequence_num: insert_row.get("sequence_num"),
            previous_event_hash: insert_row.get("previous_event_hash"),
            event_hash: insert_row.get("event_hash"),
            event_type: insert_row.get("event_type"),
            actor_principal_id: insert_row.get("actor_principal_id"),
            action: insert_row.get("action"),
            resource_type: insert_row.get("resource_type"),
            resource_id: insert_row.get("resource_id"),
            payload: insert_row.get("payload"),
            job_id: insert_row.get("job_id"),
            correlation_id: insert_row.get("correlation_id"),
            recorded_at: insert_row.get("recorded_at"),
        })
    }

    async fn fetch_audit_events(
        &self,
        tx: &mut PgConnection,
        workspace_id: Uuid,
    ) -> Result<Vec<AuditEventRecord>, PersistenceError> {
        let rows = sqlx::query(
            "SELECT id, workspace_id, sequence_num, previous_event_hash, event_hash,
                    event_type, actor_principal_id, action, resource_type, resource_id,
                    payload, job_id, correlation_id, recorded_at
             FROM audit_events
             WHERE workspace_id = $1
             ORDER BY sequence_num ASC",
        )
        .bind(workspace_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let records = rows
            .into_iter()
            .map(|row| AuditEventRecord {
                id: row.get("id"),
                workspace_id: row.get("workspace_id"),
                sequence_num: row.get("sequence_num"),
                previous_event_hash: row.get("previous_event_hash"),
                event_hash: row.get("event_hash"),
                event_type: row.get("event_type"),
                actor_principal_id: row.get("actor_principal_id"),
                action: row.get("action"),
                resource_type: row.get("resource_type"),
                resource_id: row.get("resource_id"),
                payload: row.get("payload"),
                job_id: row.get("job_id"),
                correlation_id: row.get("correlation_id"),
                recorded_at: row.get("recorded_at"),
            })
            .collect();

        Ok(records)
    }
}
