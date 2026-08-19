//! Authoritative PostgreSQL Idempotency Store Implementation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::error::PersistenceError;

/// Status lifecycle of an idempotency record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdempotencyStatus {
    InProgress,
    Completed,
    Failed,
}

impl IdempotencyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "in_progress" => Some(Self::InProgress),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Authoritative idempotency record stored in `idempotency_records`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct IdempotencyRecord {
    pub id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub idempotency_key: String,
    pub request_hash: String,
    pub status: String,
    pub response_status_code: Option<i32>,
    pub response_headers: Option<serde_json::Value>,
    pub response_body: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Result of evaluating an idempotency key against the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdempotencyCheckResult {
    /// Newly acquired key in 'in_progress' state. Caller is authorized to execute mutation.
    Acquired { record_id: Uuid },
    /// Key is currently being processed by another concurrent in-flight request.
    InProgress,
    /// Key was previously completed with an identical request payload. Authoritative replay.
    Replay {
        status_code: u16,
        headers: Option<serde_json::Value>,
        body: Option<serde_json::Value>,
    },
    /// The idempotency key was previously used with a DIFFERENT request payload. Mismatch rejected!
    Mismatch {
        expected_hash: String,
        actual_hash: String,
    },
}

/// Authoritative contract for storing and evaluating request idempotency records.
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Checks for an existing idempotency record or acquires an 'in_progress' lock.
    ///
    /// Preserves:
    /// - Replay semantics for identical request hashes on completed records.
    /// - Strict rejection (`Mismatch`) if the same key is reused with a different request hash.
    /// - In-flight serialization for concurrent requests.
    /// - No history deletion as a recovery mechanism.
    async fn start_or_get(
        &self,
        tx: &mut PgConnection,
        workspace_id: Option<Uuid>,
        idempotency_key: &str,
        request_hash: &str,
        ttl_seconds: i64,
    ) -> Result<IdempotencyCheckResult, PersistenceError>;

    /// Completes the idempotency record with authoritative response status, headers, and body.
    async fn complete(
        &self,
        tx: &mut PgConnection,
        record_id: Uuid,
        status_code: u16,
        headers: Option<serde_json::Value>,
        body: Option<serde_json::Value>,
    ) -> Result<(), PersistenceError>;

    /// Marks the idempotency record as failed.
    async fn fail(&self, tx: &mut PgConnection, record_id: Uuid) -> Result<(), PersistenceError>;

    /// Retrieves an idempotency record by ID.
    async fn get_record(
        &self,
        tx: &mut PgConnection,
        record_id: Uuid,
    ) -> Result<Option<IdempotencyRecord>, PersistenceError>;
}

/// Helper for deterministic SHA-256 request payload hashing.
pub struct IdempotencyHasher;

impl IdempotencyHasher {
    /// Computes the 64-character lowercase hex SHA-256 hash of raw bytes.
    pub fn compute_request_hash(data: &[u8]) -> String {
        let digest = Sha256::digest(data);
        hex::encode(digest)
    }

    /// Computes the 64-character lowercase hex SHA-256 hash of a JSON value.
    pub fn compute_json_hash(val: &serde_json::Value) -> String {
        let canonical_bytes = serde_json::to_vec(val).unwrap_or_default();
        Self::compute_request_hash(&canonical_bytes)
    }
}

/// PostgreSQL production implementation of `IdempotencyStore`.
#[derive(Debug, Clone, Default)]
pub struct PostgresIdempotencyStore;

impl PostgresIdempotencyStore {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl IdempotencyStore for PostgresIdempotencyStore {
    async fn start_or_get(
        &self,
        tx: &mut PgConnection,
        workspace_id: Option<Uuid>,
        idempotency_key: &str,
        request_hash: &str,
        ttl_seconds: i64,
    ) -> Result<IdempotencyCheckResult, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, workspace_id, idempotency_key, request_hash, status,
                    response_status_code, response_headers, response_body,
                    created_at, expires_at, completed_at
             FROM idempotency_records
             WHERE (workspace_id = $1 OR (workspace_id IS NULL AND $1 IS NULL))
               AND idempotency_key = $2
             FOR UPDATE",
        )
        .bind(workspace_id)
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        if let Some(row) = row_opt {
            let stored_hash: String = row.get("request_hash");
            let status: String = row.get("status");
            let id: Uuid = row.get("id");
            let expires_at: DateTime<Utc> = row.get("expires_at");

            // 1. Check request hash matching
            if !stored_hash.eq_ignore_ascii_case(request_hash) {
                return Ok(IdempotencyCheckResult::Mismatch {
                    expected_hash: stored_hash,
                    actual_hash: request_hash.to_string(),
                });
            }

            // 2. Handle completed record replay
            if status == "completed" {
                let status_code: i32 = row
                    .get::<Option<i32>, _>("response_status_code")
                    .unwrap_or(200);
                let headers: Option<serde_json::Value> = row.get("response_headers");
                let body: Option<serde_json::Value> = row.get("response_body");

                return Ok(IdempotencyCheckResult::Replay {
                    status_code: status_code as u16,
                    headers,
                    body,
                });
            }

            // 3. Handle in-progress record
            if status == "in_progress" {
                let now = Utc::now();
                if expires_at < now {
                    // Lock expired; reacquire with renewed TTL
                    sqlx::query(
                        "UPDATE idempotency_records
                         SET expires_at = CURRENT_TIMESTAMP + ($2 || ' seconds')::INTERVAL,
                             created_at = CURRENT_TIMESTAMP
                         WHERE id = $1",
                    )
                    .bind(id)
                    .bind(ttl_seconds.to_string())
                    .execute(&mut *tx)
                    .await
                    .map_err(PersistenceError::Connection)?;

                    return Ok(IdempotencyCheckResult::Acquired { record_id: id });
                }

                return Ok(IdempotencyCheckResult::InProgress);
            }

            // 4. Handle failed record; allow retry with renewed TTL
            if status == "failed" {
                sqlx::query(
                    "UPDATE idempotency_records
                     SET status = 'in_progress',
                         expires_at = CURRENT_TIMESTAMP + ($2 || ' seconds')::INTERVAL,
                         created_at = CURRENT_TIMESTAMP
                     WHERE id = $1",
                )
                .bind(id)
                .bind(ttl_seconds.to_string())
                .execute(&mut *tx)
                .await
                .map_err(PersistenceError::Connection)?;

                return Ok(IdempotencyCheckResult::Acquired { record_id: id });
            }
        }

        // 5. Insert new record in 'in_progress' state
        let insert_row = sqlx::query(
            "INSERT INTO idempotency_records (
                workspace_id, idempotency_key, request_hash, status, expires_at
            ) VALUES (
                $1, $2, $3, 'in_progress', CURRENT_TIMESTAMP + ($4 || ' seconds')::INTERVAL
            )
            RETURNING id",
        )
        .bind(workspace_id)
        .bind(idempotency_key)
        .bind(request_hash)
        .bind(ttl_seconds.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let record_id: Uuid = insert_row.get("id");
        Ok(IdempotencyCheckResult::Acquired { record_id })
    }

    async fn complete(
        &self,
        tx: &mut PgConnection,
        record_id: Uuid,
        status_code: u16,
        headers: Option<serde_json::Value>,
        body: Option<serde_json::Value>,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "UPDATE idempotency_records
             SET status = 'completed',
                 response_status_code = $2,
                 response_headers = $3,
                 response_body = $4,
                 completed_at = CURRENT_TIMESTAMP
             WHERE id = $1",
        )
        .bind(record_id)
        .bind(status_code as i32)
        .bind(headers)
        .bind(body)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    async fn fail(&self, tx: &mut PgConnection, record_id: Uuid) -> Result<(), PersistenceError> {
        sqlx::query(
            "UPDATE idempotency_records
             SET status = 'failed'
             WHERE id = $1",
        )
        .bind(record_id)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    async fn get_record(
        &self,
        tx: &mut PgConnection,
        record_id: Uuid,
    ) -> Result<Option<IdempotencyRecord>, PersistenceError> {
        let maybe_row = sqlx::query(
            "SELECT id, workspace_id, idempotency_key, request_hash, status,
                    response_status_code, response_headers, response_body,
                    created_at, expires_at, completed_at
             FROM idempotency_records
             WHERE id = $1",
        )
        .bind(record_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(maybe_row.map(|row| IdempotencyRecord {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            idempotency_key: row.get("idempotency_key"),
            request_hash: row.get("request_hash"),
            status: row.get("status"),
            response_status_code: row.get("response_status_code"),
            response_headers: row.get("response_headers"),
            response_body: row.get("response_body"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            completed_at: row.get("completed_at"),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compute_request_hash() {
        let payload = json!({"action": "create_item", "amount": 100});
        let hash1 = IdempotencyHasher::compute_json_hash(&payload);
        let hash2 = IdempotencyHasher::compute_json_hash(&payload);

        assert_eq!(hash1.len(), 64);
        assert_eq!(hash1, hash2);

        let modified_payload = json!({"action": "create_item", "amount": 200});
        let hash3 = IdempotencyHasher::compute_json_hash(&modified_payload);
        assert_ne!(hash1, hash3);
    }
}
