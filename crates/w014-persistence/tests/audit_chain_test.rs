//! Authoritative Audit Chain Integration and Invariant Tests against real PostgreSQL 18.
//!
//! Validates:
//! - One authoritative chain head per workspace.
//! - Strict monotonically increasing sequence per workspace.
//! - Cryptographic hash chain linkage anchored at genesis.
//! - Atomic event insert + chain-head advancement.
//! - Concurrent append serialization and integrity.
//! - Complete chain verification and tamper/gap detection.

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

    sqlx::query("INSERT INTO organizations (id, name, slug) VALUES ($1, 'Audit Test Org', $2)")
        .bind(org_id)
        .bind(format!("org-{}", org_id.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create test org");

    sqlx::query("INSERT INTO programs (id, organization_id, name, slug) VALUES ($1, $2, 'Audit Test Program', $3)")
        .bind(program_id)
        .bind(org_id)
        .bind(format!("prog-{}", program_id.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create test program");

    sqlx::query("INSERT INTO workspaces (id, program_id, organization_id, name, slug) VALUES ($1, $2, $3, 'Audit Test Workspace', $4)")
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
    assert_eq!(head.head_sequence_num, 0);
    assert_eq!(head.head_event_hash, hasher.genesis_hash());
    assert_eq!(head.genesis_hash, hasher.genesis_hash());

    // 2. Append first audit event (sequence = 1)
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let event1 = audit_store
        .append_audit_event(
            &mut tx,
            AppendAuditParams {
                workspace_id,
                event_type: "workspace.created".to_string(),
                actor_principal_id: None,
                action: "CREATE".to_string(),
                resource_type: "workspace".to_string(),
                resource_id: workspace_id.to_string(),
                payload: json!({"name": "Audit Test Workspace"}),
                correlation_id: Some("corr-001".to_string()),
            },
        )
        .await
        .expect("Failed to append event 1");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(event1.sequence_num, 1);
    assert_eq!(event1.previous_event_hash, hasher.genesis_hash());
    assert_eq!(event1.event_hash.len(), 64);

    // Verify chain head was updated to sequence 1 and event1 hash
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let head_after_1 = audit_store
        .get_chain_head(&mut tx, workspace_id)
        .await
        .expect("Failed to fetch head")
        .expect("Chain head must exist");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(head_after_1.head_sequence_num, 1);
    assert_eq!(head_after_1.head_event_hash, event1.event_hash);

    // 3. Append second audit event (sequence = 2)
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let event2 = audit_store
        .append_audit_event(
            &mut tx,
            AppendAuditParams {
                workspace_id,
                event_type: "membership.granted".to_string(),
                actor_principal_id: None,
                action: "GRANT".to_string(),
                resource_type: "membership".to_string(),
                resource_id: "mem-123".to_string(),
                payload: json!({"role": "admin"}),
                correlation_id: Some("corr-002".to_string()),
            },
        )
        .await
        .expect("Failed to append event 2");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(event2.sequence_num, 2);
    assert_eq!(event2.previous_event_hash, event1.event_hash);
    assert_eq!(event2.event_hash.len(), 64);
    assert_ne!(event1.event_hash, event2.event_hash);

    // 4. Append third audit event (sequence = 3)
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let event3 = audit_store
        .append_audit_event(
            &mut tx,
            AppendAuditParams {
                workspace_id,
                event_type: "capability.granted".to_string(),
                actor_principal_id: None,
                action: "GRANT".to_string(),
                resource_type: "capability_grant".to_string(),
                resource_id: "cap-456".to_string(),
                payload: json!({"capability": "source:read"}),
                correlation_id: Some("corr-003".to_string()),
            },
        )
        .await
        .expect("Failed to append event 3");
    tx.commit().await.expect("Failed to commit tx");

    assert_eq!(event3.sequence_num, 3);
    assert_eq!(event3.previous_event_hash, event2.event_hash);

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

    // 6. Test tamper detection: modifying one event's payload in memory fails verification
    let mut tampered_events = events.clone();
    tampered_events[1].payload = json!({"role": "superadmin_hacked"});
    let tamper_res = hasher.verify_chain_integrity(&tampered_events);
    match tamper_res {
        Err(AuditIntegrityError::HashTamperDetected { sequence_num, .. }) => {
            assert_eq!(sequence_num, 2);
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
                        event_type: format!("concurrent.event.{i}"),
                        actor_principal_id: None,
                        action: "MUTATE".to_string(),
                        resource_type: "item".to_string(),
                        resource_id: format!("res-{i}"),
                        payload: json!({"task_index": i}),
                        correlation_id: Some(format!("corr-{i}")),
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
        assert_eq!(event.sequence_num, (idx as i64) + 1);
    }

    test_db.close().await.expect("Failed to drop test database");
}
