//! Authoritative PostgreSQL Idempotency Store Implementation conforming to Prompt-12 / Prompt-13.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::audit::hasher::canonicalize_json;
use crate::error::PersistenceError;

type HmacSha256 = Hmac<Sha256>;

/// Authoritative idempotency record stored in `idempotency_records`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct IdempotencyRecord {
    pub idempotency_record_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub principal_id: Uuid,
    pub route_code: String,
    pub key_hash: Vec<u8>,
    pub request_hash: Vec<u8>,
    pub response_status: Option<i16>,
    pub response_body: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
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
    /// - FILL-ONCE response behavior (never overwrites completed responses).
    #[allow(clippy::too_many_arguments)]
    async fn start_or_get(
        &self,
        tx: &mut PgConnection,
        workspace_id: Option<Uuid>,
        principal_id: Uuid,
        route_code: &str,
        key_hash: &[u8],
        request_hash: &[u8],
        ttl_seconds: i64,
    ) -> Result<IdempotencyCheckResult, PersistenceError>;

    /// Completes the idempotency record with authoritative response status and body (fill-once).
    async fn complete(
        &self,
        tx: &mut PgConnection,
        record_id: Uuid,
        status_code: u16,
        body: Option<serde_json::Value>,
    ) -> Result<(), PersistenceError>;

    /// Removes an in-progress idempotency record on unhandled failure to allow immediate retry.
    async fn fail(&self, tx: &mut PgConnection, record_id: Uuid) -> Result<(), PersistenceError>;

    /// Retrieves an idempotency record by ID.
    async fn get_record(
        &self,
        tx: &mut PgConnection,
        record_id: Uuid,
    ) -> Result<Option<IdempotencyRecord>, PersistenceError>;
}

/// Helper for deterministic HMAC key hashing and SHA-256 payload hashing.
pub struct IdempotencyHasher;

impl IdempotencyHasher {
    /// Computes HMAC-SHA256 of the raw client key to avoid persisting plaintext keys.
    pub fn compute_key_hash(hmac_secret: &[u8], raw_client_key: &str) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(hmac_secret)
            .unwrap_or_else(|_| HmacSha256::new_from_slice(&[0u8; 32]).expect("fallback"));
        mac.update(raw_client_key.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Computes the 32-byte SHA-256 hash of raw bytes.
    pub fn compute_request_hash(data: &[u8]) -> Vec<u8> {
        let digest = Sha256::digest(data);
        digest.to_vec()
    }

    /// Computes the 32-byte SHA-256 hash of a JSON value after RFC-8785 canonicalization.
    pub fn compute_json_hash(val: &serde_json::Value) -> Vec<u8> {
        let canonical_bytes = canonicalize_json(val);
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
    #[allow(clippy::too_many_arguments)]
    async fn start_or_get(
        &self,
        tx: &mut PgConnection,
        workspace_id: Option<Uuid>,
        principal_id: Uuid,
        route_code: &str,
        key_hash: &[u8],
        request_hash: &[u8],
        ttl_seconds: i64,
    ) -> Result<IdempotencyCheckResult, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT idempotency_record_id, workspace_id, principal_id, route_code,
                    key_hash, request_hash, response_status, response_body,
                    created_at, expires_at
             FROM idempotency_records
             WHERE (workspace_id = $1 OR (workspace_id IS NULL AND $1 IS NULL))
               AND principal_id = $2
               AND route_code = $3
               AND key_hash = $4
             FOR UPDATE",
        )
        .bind(workspace_id)
        .bind(principal_id)
        .bind(route_code)
        .bind(key_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        if let Some(row) = row_opt {
            let stored_hash: Vec<u8> = row.get("request_hash");
            let response_status: Option<i16> = row.get("response_status");
            let id: Uuid = row.get("idempotency_record_id");
            let expires_at: DateTime<Utc> = row.get("expires_at");

            // 1. Check request hash matching
            if stored_hash != request_hash {
                return Ok(IdempotencyCheckResult::Mismatch {
                    expected_hash: hex::encode(&stored_hash),
                    actual_hash: hex::encode(request_hash),
                });
            }

            // 2. Handle completed record replay
            if let Some(status) = response_status {
                let body: Option<serde_json::Value> = row.get("response_body");
                return Ok(IdempotencyCheckResult::Replay {
                    status_code: status as u16,
                    body,
                });
            }

            // 3. Handle in-progress record
            let now = Utc::now();
            if expires_at < now {
                // Lock expired; reacquire with renewed TTL
                sqlx::query(
                    "UPDATE idempotency_records
                     SET expires_at = clock_timestamp() + ($2 || ' seconds')::INTERVAL,
                         created_at = clock_timestamp()
                     WHERE idempotency_record_id = $1",
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

        // 4. Insert new record in 'in_progress' state
        let insert_row = sqlx::query(
            "INSERT INTO idempotency_records (
                workspace_id, principal_id, route_code, key_hash, request_hash, expires_at
            ) VALUES (
                $1, $2, $3, $4, $5, clock_timestamp() + ($6 || ' seconds')::INTERVAL
            )
            RETURNING idempotency_record_id",
        )
        .bind(workspace_id)
        .bind(principal_id)
        .bind(route_code)
        .bind(key_hash)
        .bind(request_hash)
        .bind(ttl_seconds.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let record_id: Uuid = insert_row.get("idempotency_record_id");
        Ok(IdempotencyCheckResult::Acquired { record_id })
    }

    async fn complete(
        &self,
        tx: &mut PgConnection,
        record_id: Uuid,
        status_code: u16,
        body: Option<serde_json::Value>,
    ) -> Result<(), PersistenceError> {
        // Fill once semantics: only update if response_status is NULL
        sqlx::query(
            "UPDATE idempotency_records
             SET response_status = $2,
                 response_body = $3
             WHERE idempotency_record_id = $1 AND response_status IS NULL",
        )
        .bind(record_id)
        .bind(status_code as i16)
        .bind(body)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    async fn fail(&self, tx: &mut PgConnection, record_id: Uuid) -> Result<(), PersistenceError> {
        // On unhandled failure of in-progress record, delete it so it can be cleanly retried
        sqlx::query(
            "DELETE FROM idempotency_records
             WHERE idempotency_record_id = $1 AND response_status IS NULL",
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
            "SELECT idempotency_record_id, workspace_id, principal_id, route_code,
                    key_hash, request_hash, response_status, response_body,
                    created_at, expires_at
             FROM idempotency_records
             WHERE idempotency_record_id = $1",
        )
        .bind(record_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(maybe_row.map(|row| IdempotencyRecord {
            idempotency_record_id: row.get("idempotency_record_id"),
            workspace_id: row.get("workspace_id"),
            principal_id: row.get("principal_id"),
            route_code: row.get("route_code"),
            key_hash: row.get("key_hash"),
            request_hash: row.get("request_hash"),
            response_status: row.get("response_status"),
            response_body: row.get("response_body"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
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

        assert_eq!(hash1.len(), 32);
        assert_eq!(hash1, hash2);

        let modified_payload = json!({"action": "create_item", "amount": 200});
        let hash3 = IdempotencyHasher::compute_json_hash(&modified_payload);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_compute_key_hash() {
        let secret = b"secret-key-material";
        let key1 = "client-idempotency-key-001";
        let key2 = "client-idempotency-key-002";

        let hash1 = IdempotencyHasher::compute_key_hash(secret, key1);
        let hash2 = IdempotencyHasher::compute_key_hash(secret, key1);
        let hash3 = IdempotencyHasher::compute_key_hash(secret, key2);

        assert_eq!(hash1.len(), 32);
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
