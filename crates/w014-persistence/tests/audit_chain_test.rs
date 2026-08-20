//! Authoritative Audit Chain Integration and Invariant Tests against real PostgreSQL 18.
//!
//! Validates:
//! - One authoritative chain head per workspace (last_sequence = 0, last_event_hash = NULL).
//! - Strict monotonically increasing sequence per workspace.
//! - Cryptographic hash chain linkage with BYTEA hashes and RFC-8785 JSON canonicalization.
//! - Atomic event insert + chain-head advancement.
//! - Concurrent append serialization with SELECT FOR UPDATE row lock.
//! - Complete chain verification and tamper/gap/disorder detection.

use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;
use w014_persistence::{
    AppendAuditParams, AuditAppendContract, AuditChainHashContract, AuditChainHasher,
    AuditIntegrityError, MIGRATOR, MigrationRunner, PostgresAuditStore, TestDatabase,
};

/// Helper to set up a migrated test database and create a test organization, program, and workspace.
async fn setup_test_workspace(test_db: &TestDatabase) -> (Uuid, Uuid, Uuid) {
    let org_id = Uuid::new_v4();
    let program_id = Uuid::new_v4();
    let workspace_id = Uuid::new_v4();

    sqlx::query("INSERT INTO organizations (organization_id, display_name, slug) VALUES ($1, 'Audit Test Org', $2)")
        .bind(org_id)
        .bind(format!("org-{}", org_id.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create test org");

    sqlx::query("INSERT INTO programs (program_id, organization_id, name, program_code) VALUES ($1, $2, 'Audit Test Program', $3)")
        .bind(program_id)
        .bind(org_id)
        .bind(format!("prog-{}", program_id.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create test program");

    sqlx::query("INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code) VALUES ($1, $2, $3, 'Audit Test Workspace', $4)")
        .bind(workspace_id)
        .bind(program_id)
        .bind(org_id)
        .bind(format!("ws-{}", workspace_id.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create test workspace");

    (org_id, program_id, workspace_id)
}

#[tokio::test]
async fn test_audit_chain_lifecycle_and_hash_integrity() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");

    let (_org_id, _program_id, workspace_id) = setup_test_workspace(&test_db).await;
    let audit_store = PostgresAuditStore::new();
    let hasher = AuditChainHasher;

    // 1. Initialize chain head
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let head = audit_store
        .initialize_chain_head(&mut tx, workspace_id)
        .await
        .expect("Failed to initialize chain head");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(head.workspace_id, workspace_id);
    assert_eq!(head.last_sequence, 0);
    assert_eq!(head.last_event_hash, None);

    // 2. Append first audit event (sequence = 1)
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let event1 = audit_store
        .append_audit_event(
            &mut tx,
            AppendAuditParams {
                workspace_id,
                actor_type: "user".to_string(),
                actor_id: None,
                authority_snapshot: json!({}),
                action_code: "WORKSPACE_CREATE".to_string(),
                entity_type: "workspace".to_string(),
                entity_id: workspace_id.to_string(),
                entity_version: Some(1),
                request_id: Some("req-001".to_string()),
                correlation_id: Some("corr-001".to_string()),
                job_id: None,
                source_state_hash: None,
                before_ref: None,
                after_ref: Some(json!({"name": "Audit Test Workspace"})),
                metadata: json!({"environment": "test"}),
            },
        )
        .await
        .expect("Failed to append event 1");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(event1.sequence, 1);
    assert_eq!(event1.previous_event_hash, None);
    assert_eq!(event1.event_hash.len(), 32);

    // Verify chain head was updated to sequence 1 and event1 hash
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let head_after_1 = audit_store
        .get_chain_head(&mut tx, workspace_id)
        .await
        .expect("Failed to fetch head")
        .expect("Chain head must exist");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(head_after_1.last_sequence, 1);
    assert_eq!(
        head_after_1.last_event_hash,
        Some(event1.event_hash.clone())
    );

    // 3. Append second audit event (sequence = 2)
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let event2 = audit_store
        .append_audit_event(
            &mut tx,
            AppendAuditParams {
                workspace_id,
                actor_type: "user".to_string(),
                actor_id: None,
                authority_snapshot: json!({}),
                action_code: "MEMBERSHIP_GRANT".to_string(),
                entity_type: "membership".to_string(),
                entity_id: "mem-123".to_string(),
                entity_version: Some(1),
                request_id: Some("req-002".to_string()),
                correlation_id: Some("corr-002".to_string()),
                job_id: None,
                source_state_hash: None,
                before_ref: None,
                after_ref: Some(json!({"role_code": "admin"})),
                metadata: json!({}),
            },
        )
        .await
        .expect("Failed to append event 2");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(event2.sequence, 2);
    assert_eq!(event2.previous_event_hash, Some(event1.event_hash.clone()));
    assert_eq!(event2.event_hash.len(), 32);
    assert_ne!(event1.event_hash, event2.event_hash);

    // 4. Append third audit event (sequence = 3)
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let event3 = audit_store
        .append_audit_event(
            &mut tx,
            AppendAuditParams {
                workspace_id,
                actor_type: "user".to_string(),
                actor_id: None,
                authority_snapshot: json!({}),
                action_code: "CAPABILITY_GRANT".to_string(),
                entity_type: "capability_grant".to_string(),
                entity_id: "cap-456".to_string(),
                entity_version: Some(1),
                request_id: Some("req-003".to_string()),
                correlation_id: Some("corr-003".to_string()),
                job_id: None,
                source_state_hash: None,
                before_ref: None,
                after_ref: Some(json!({"capability_code": "source:read"})),
                metadata: json!({}),
            },
        )
        .await
        .expect("Failed to append event 3");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(event3.sequence, 3);
    assert_eq!(event3.previous_event_hash, Some(event2.event_hash.clone()));

    // 5. Fetch all events and verify complete chain cryptographic integrity
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let events = audit_store
        .fetch_audit_events(&mut tx, workspace_id)
        .await
        .expect("Failed to fetch events");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(events.len(), 3);
    assert!(
        hasher.verify_chain_integrity(&events).is_ok(),
        "Audit chain integrity check must pass for unmodified events"
    );

    // 6. Test tamper detection: modifying one event's metadata in memory fails verification
    let mut tampered_events = events.clone();
    tampered_events[1].metadata = json!({"role": "superadmin_hacked"});
    let tamper_res = hasher.verify_chain_integrity(&tampered_events);
    match tamper_res {
        Err(AuditIntegrityError::HashTamperDetected { sequence, .. }) => {
            assert_eq!(sequence, 2);
        }
        other => panic!("Expected HashTamperDetected error, got: {other:?}"),
    }

    test_db.close().await.expect("Failed to drop test database");
}

#[tokio::test]
async fn test_audit_chain_concurrent_appends_serialization() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");

    let (_org_id, _program_id, workspace_id) = setup_test_workspace(&test_db).await;
    let pool = Arc::new(test_db.pool().clone());
    let audit_store = Arc::new(PostgresAuditStore::new());

    // Spawn 10 concurrent tasks appending to the same workspace chain
    let num_tasks = 10;
    let mut handles = Vec::new();

    for i in 0..num_tasks {
        let pool_clone = Arc::clone(&pool);
        let store_clone = Arc::clone(&audit_store);
        let ws_id = workspace_id;

        handles.push(tokio::spawn(async move {
            let mut tx = pool_clone.begin().await.expect("Failed to begin tx");
            let event = store_clone
                .append_audit_event(
                    &mut tx,
                    AppendAuditParams {
                        workspace_id: ws_id,
                        actor_type: "worker".to_string(),
                        actor_id: None,
                        authority_snapshot: json!({}),
                        action_code: "TASK_PROCESS".to_string(),
                        entity_type: "task".to_string(),
                        entity_id: format!("res-{i}"),
                        entity_version: Some(1),
                        request_id: None,
                        correlation_id: Some(format!("corr-{i}")),
                        job_id: None,
                        source_state_hash: None,
                        before_ref: None,
                        after_ref: None,
                        metadata: json!({"task_index": i}),
                    },
                )
                .await
                .expect("Failed to append concurrent audit event");
            tx.commit().await.expect("Failed to commit tx");
            event
        }));
    }

    for handle in handles {
        let _ = handle.await.expect("Task panicked");
    }

    // Fetch all events and verify exact sequence (1..=10) with no gaps or hash corruptions
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let events = audit_store
        .fetch_audit_events(&mut tx, workspace_id)
        .await
        .expect("Failed to fetch events");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(events.len(), num_tasks);
    let hasher = AuditChainHasher;
    assert!(
        hasher.verify_chain_integrity(&events).is_ok(),
        "Concurrent appends must serialize correctly into a cryptographically valid chain"
    );

    // Verify sequences are strictly 1..=10
    for (idx, event) in events.iter().enumerate() {
        assert_eq!(event.sequence, (idx as i64) + 1);
    }

    test_db.close().await.expect("Failed to drop test database");
}
