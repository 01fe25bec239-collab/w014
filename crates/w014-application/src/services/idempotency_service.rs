//! Idempotency integration service consuming the accepted IdempotencyStore.
//!
//! Preserves:
//! - Exact consumption of accepted `IdempotencyStore` without creating second stores or tables.
//! - Replay of completed responses for matching request hashes.
//! - Rejection (`IdempotencyMismatch`) for mismatched request hashes.
//! - Handling of in-progress operations.

use sqlx::PgConnection;
use uuid::Uuid;
use w014_domain::ids::{PrincipalId, WorkspaceId};
use w014_persistence::idempotency::{IdempotencyCheckResult, IdempotencyHasher, IdempotencyStore};

use crate::error::ApplicationError;

/// Coordinator for idempotent domain command execution.
pub struct IdempotencyCoordinator;

impl IdempotencyCoordinator {
    /// Computes the deterministic request hash of a JSON payload.
    pub fn compute_payload_hash(payload: &serde_json::Value) -> Vec<u8> {
        IdempotencyHasher::compute_json_hash(payload)
    }

    /// Computes HMAC-SHA256 of the raw client key.
    pub fn compute_key_hash(hmac_secret: &[u8], raw_client_key: &str) -> Vec<u8> {
        IdempotencyHasher::compute_key_hash(hmac_secret, raw_client_key)
    }

    /// Evaluates the idempotency key against the store within the current transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_key(
        tx: &mut PgConnection,
        store: &impl IdempotencyStore,
        workspace_id: Option<WorkspaceId>,
        principal_id: PrincipalId,
        route_code: &str,
        key_hash: &[u8],
        request_hash: &[u8],
        ttl_seconds: i64,
    ) -> Result<IdempotencyCheckResult, ApplicationError> {
        let ws_uuid = workspace_id.map(|w| w.into_uuid());
        store
            .start_or_get(
                tx,
                ws_uuid,
                principal_id.into_uuid(),
                route_code,
                key_hash,
                request_hash,
                ttl_seconds,
            )
            .await
            .map_err(ApplicationError::from)
    }

    /// Marks the idempotency record as completed with authoritative status and body.
    pub async fn complete_record(
        tx: &mut PgConnection,
        store: &impl IdempotencyStore,
        record_id: Uuid,
        status_code: u16,
        body: Option<serde_json::Value>,
    ) -> Result<(), ApplicationError> {
        store
            .complete(tx, record_id, status_code, body)
            .await
            .map_err(ApplicationError::from)
    }

    /// Marks the idempotency record as failed.
    pub async fn fail_record(
        tx: &mut PgConnection,
        store: &impl IdempotencyStore,
        record_id: Uuid,
    ) -> Result<(), ApplicationError> {
        store
            .fail(tx, record_id)
            .await
            .map_err(ApplicationError::from)
    }
}
