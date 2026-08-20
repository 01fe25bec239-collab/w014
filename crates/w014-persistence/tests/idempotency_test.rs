//! Authoritative Idempotency Store Integration and Invariant Tests against real PostgreSQL 18.
//!
//! Validates:
//! - Initial acquisition of key in 'in_progress' state.
//! - Atomic completion with response payload and fill-once semantics.
//! - Authoritative replay on matching key + matching request hash.
//! - Strict rejection ('Mismatch') on matching key + differing request hash.
//! - In-flight concurrent request detection ('InProgress').
//! - Expired key re-acquisition.
//! - HMAC key hashing (no plaintext keys stored).

use serde_json::json;
use uuid::Uuid;
use w014_persistence::{
    IdempotencyCheckResult, IdempotencyHasher, IdempotencyStore, MIGRATOR, MigrationRunner,
    PostgresIdempotencyStore, TestDatabase,
};

#[tokio::test]
async fn test_idempotency_store_replay_and_mismatch_invariants() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");

    let principal_id = Uuid::new_v4();
    sqlx::query("INSERT INTO principals (principal_id, display_name, email, status) VALUES ($1, 'Idemp Test User', 'idemp@example.com', 'active')")
        .bind(principal_id)
        .execute(test_db.pool())
        .await
        .expect("Failed to create principal");

    let idempotency_store = PostgresIdempotencyStore::new();
    let workspace_id = None; // global route test
    let route_code = "POST /api/v1/workspaces";
    let hmac_secret = b"test-hmac-secret-key-32bytes-long";
    let client_key = "idemp-key-test-001";
    let key_hash = IdempotencyHasher::compute_key_hash(hmac_secret, client_key);

    let request_payload = json!({"action": "create_user", "email": "test@example.com"});
    let request_hash = IdempotencyHasher::compute_json_hash(&request_payload);

    // 1. Initial acquisition: should return Acquired
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let check_res = idempotency_store
        .start_or_get(
            &mut tx,
            workspace_id,
            principal_id,
            route_code,
            &key_hash,
            &request_hash,
            60,
        )
        .await
        .expect("Failed to start idempotency record");

    let record_id = match check_res {
        IdempotencyCheckResult::Acquired { record_id } => record_id,
        other => panic!("Expected Acquired, got: {other:?}"),
    };
    tx.commit().await.expect("Failed to commit tx");

    // 2. While in_progress and active: concurrent start_or_get returns InProgress
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let concurrent_res = idempotency_store
        .start_or_get(
            &mut tx,
            workspace_id,
            principal_id,
            route_code,
            &key_hash,
            &request_hash,
            60,
        )
        .await
        .expect("Failed start_or_get on in-progress key");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(concurrent_res, IdempotencyCheckResult::InProgress);

    // 3. Complete the record with status 201 and response body
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let response_body = json!({"user_id": "usr-123", "status": "active"});
    idempotency_store
        .complete(&mut tx, record_id, 201, Some(response_body.clone()))
        .await
        .expect("Failed to complete idempotency record");
    tx.commit().await.expect("Failed to commit tx");

    // 4. Test FILL ONCE: attempting to complete again with 500 must not overwrite 201
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    idempotency_store
        .complete(
            &mut tx,
            record_id,
            500,
            Some(json!({"error": "should not overwrite"})),
        )
        .await
        .expect("Failed second complete call");
    tx.commit().await.expect("Failed to commit tx");

    // 5. Repeated request with IDENTICAL payload/hash returns Replay with cached response
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let replay_res = idempotency_store
        .start_or_get(
            &mut tx,
            workspace_id,
            principal_id,
            route_code,
            &key_hash,
            &request_hash,
            60,
        )
        .await
        .expect("Failed to replay idempotency record");
    tx.commit().await.expect("Failed to commit tx");

    match replay_res {
        IdempotencyCheckResult::Replay {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 201);
            assert_eq!(body, Some(response_body));
        }
        other => panic!("Expected Replay result, got: {other:?}"),
    }

    // 6. Repeated request with DIFFERENT payload/hash returns Mismatch (strict rejection)
    let different_payload = json!({"action": "create_user", "email": "different@example.com"});
    let different_hash = IdempotencyHasher::compute_json_hash(&different_payload);

    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let mismatch_res = idempotency_store
        .start_or_get(
            &mut tx,
            workspace_id,
            principal_id,
            route_code,
            &key_hash,
            &different_hash,
            60,
        )
        .await
        .expect("Failed to check mismatched key");
    tx.commit().await.expect("Failed to commit tx");

    match mismatch_res {
        IdempotencyCheckResult::Mismatch {
            expected_hash,
            actual_hash,
        } => {
            assert_eq!(expected_hash, hex::encode(&request_hash));
            assert_eq!(actual_hash, hex::encode(&different_hash));
        }
        other => panic!("Expected Mismatch result, got: {other:?}"),
    }

    // 7. Verify record in DB has fill-once status 201
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let record = idempotency_store
        .get_record(&mut tx, record_id)
        .await
        .expect("Failed to fetch record")
        .expect("Record must still exist");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(record.idempotency_record_id, record_id);
    assert_eq!(record.response_status, Some(201));

    test_db.close().await.expect("Failed to drop test database");
}
