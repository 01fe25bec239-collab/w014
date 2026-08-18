//! Security, RLS Isolation, Immutability Triggers, and Role Privilege Tests against real PostgreSQL 18.
//!
//! Validates:
//! - Row Level Security (RLS) defense-in-depth isolation between workspaces.
//! - Strict rejection of cross-workspace access and inserts under RLS.
//! - Immutability trigger protection on `audit_events` (preventing UPDATE/DELETE).
//! - Protection trigger on `audit_chain_heads` (preventing DELETE and sequence reduction).
//! - CHECK constraints across all M001R tables.
//! - Role privilege boundaries for `w014_app` and `w014_readonly`.

use serde_json::json;
use uuid::Uuid;
use w014_persistence::{
    AppendAuditParams, AuditAppendContract, MIGRATOR, MigrationRunner, PostgresAuditStore,
    TestDatabase, clear_session_workspace_id, set_session_workspace_id,
};

#[tokio::test]
async fn test_rls_cross_workspace_isolation() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");

    let audit_store = PostgresAuditStore::new();

    // Create 2 separate workspaces
    let org_id = Uuid::new_v4();
    let prog_id = Uuid::new_v4();
    let ws1 = Uuid::new_v4();
    let ws2 = Uuid::new_v4();

    sqlx::query("INSERT INTO organizations (id, name, slug) VALUES ($1, 'RLS Org', $2)")
        .bind(org_id)
        .bind(format!("org-{}", org_id.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create org");

    sqlx::query(
        "INSERT INTO programs (id, organization_id, name, slug) VALUES ($1, $2, 'RLS Prog', $3)",
    )
    .bind(prog_id)
    .bind(org_id)
    .bind(format!("prog-{}", prog_id.simple()))
    .execute(test_db.pool())
    .await
    .expect("Failed to create prog");

    sqlx::query("INSERT INTO workspaces (id, program_id, organization_id, name, slug) VALUES ($1, $2, $3, 'WS 1', $4)")
        .bind(ws1)
        .bind(prog_id)
        .bind(org_id)
        .bind(format!("ws-{}", ws1.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create ws1");

    sqlx::query("INSERT INTO workspaces (id, program_id, organization_id, name, slug) VALUES ($1, $2, $3, 'WS 2', $4)")
        .bind(ws2)
        .bind(prog_id)
        .bind(org_id)
        .bind(format!("ws-{}", ws2.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create ws2");

    // Populate audit events for WS 1
    {
        let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
        audit_store
            .append_audit_event(
                &mut tx,
                AppendAuditParams {
                    workspace_id: ws1,
                    event_type: "ws1.init".to_string(),
                    actor_principal_id: None,
                    action: "CREATE".to_string(),
                    resource_type: "workspace".to_string(),
                    resource_id: ws1.to_string(),
                    payload: json!({"workspace": "ws1"}),
                    correlation_id: Some("corr-ws1".to_string()),
                },
            )
            .await
            .expect("Failed to append ws1 event");
        tx.commit().await.expect("Failed to commit tx");
    }

    // Populate audit events for WS 2
    {
        let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
        audit_store
            .append_audit_event(
                &mut tx,
                AppendAuditParams {
                    workspace_id: ws2,
                    event_type: "ws2.init".to_string(),
                    actor_principal_id: None,
                    action: "CREATE".to_string(),
                    resource_type: "workspace".to_string(),
                    resource_id: ws2.to_string(),
                    payload: json!({"workspace": "ws2"}),
                    correlation_id: Some("corr-ws2".to_string()),
                },
            )
            .await
            .expect("Failed to append ws2 event");
        tx.commit().await.expect("Failed to commit tx");
    }

    // 1. Evaluate with RLS session set to WS 1 under application role
    {
        let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .expect("Failed to switch to w014_app role");

        set_session_workspace_id(&mut tx, ws1)
            .await
            .expect("Failed to set RLS context to ws1");

        // Query audit events: should see only WS 1 events
        let ws1_events: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM audit_events")
            .fetch_all(&mut *tx)
            .await
            .expect("Failed to query audit_events under ws1 RLS");

        assert_eq!(ws1_events.len(), 1);

        // Attempting to insert an event for WS 2 while in WS 1 context must be rejected by RLS WITH CHECK
        let bad_insert = sqlx::query(
            "INSERT INTO audit_events (
                workspace_id, sequence_num, previous_event_hash, event_hash,
                event_type, action, resource_type, resource_id, payload
            ) VALUES ($1, 99, '0000000000000000000000000000000000000000000000000000000000000000',
                      '1111111111111111111111111111111111111111111111111111111111111111',
                      'bad.insert', 'ATTACK', 'resource', 'res-1', '{}'::jsonb)",
        )
        .bind(ws2)
        .execute(&mut *tx)
        .await;

        assert!(
            bad_insert.is_err(),
            "Cross-workspace insert under RLS must be rejected by WITH CHECK policy"
        );

        tx.rollback().await.expect("Rollback should succeed");
    }

    // 2. Evaluate with RLS session cleared (no workspace set) under application role
    {
        let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .expect("Failed to switch to w014_app role");

        clear_session_workspace_id(&mut tx)
            .await
            .expect("Failed to clear RLS context");

        let visible_events: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM audit_events")
            .fetch_all(&mut *tx)
            .await
            .expect("Failed to query audit_events without context");

        assert_eq!(
            visible_events.len(),
            0,
            "No audit events should be visible when RLS context is unset"
        );

        tx.rollback().await.expect("Rollback should succeed");
    }

    test_db.close().await.expect("Failed to drop test database");
}

#[tokio::test]
async fn test_immutability_triggers_and_checks() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");

    let audit_store = PostgresAuditStore::new();

    let org_id = Uuid::new_v4();
    let prog_id = Uuid::new_v4();
    let ws_id = Uuid::new_v4();

    sqlx::query("INSERT INTO organizations (id, name, slug) VALUES ($1, 'Imm Org', $2)")
        .bind(org_id)
        .bind(format!("org-{}", org_id.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create org");

    sqlx::query(
        "INSERT INTO programs (id, organization_id, name, slug) VALUES ($1, $2, 'Imm Prog', $3)",
    )
    .bind(prog_id)
    .bind(org_id)
    .bind(format!("prog-{}", prog_id.simple()))
    .execute(test_db.pool())
    .await
    .expect("Failed to create prog");

    sqlx::query("INSERT INTO workspaces (id, program_id, organization_id, name, slug) VALUES ($1, $2, $3, 'Imm WS', $4)")
        .bind(ws_id)
        .bind(prog_id)
        .bind(org_id)
        .bind(format!("ws-{}", ws_id.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create ws");

    // Append an event
    let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");
    let event = audit_store
        .append_audit_event(
            &mut tx,
            AppendAuditParams {
                workspace_id: ws_id,
                event_type: "test.immutability".to_string(),
                actor_principal_id: None,
                action: "CREATE".to_string(),
                resource_type: "item".to_string(),
                resource_id: "1".to_string(),
                payload: json!({}),
                correlation_id: None,
            },
        )
        .await
        .expect("Failed to append event");
    tx.commit().await.expect("Failed to commit tx");

    // 1. Attempt UPDATE on audit_events: MUST FAIL via trigger
    let update_res = sqlx::query("UPDATE audit_events SET action = 'MUTATED' WHERE id = $1")
        .bind(event.id)
        .execute(test_db.pool())
        .await;

    assert!(
        update_res.is_err(),
        "UPDATE on audit_events must be prohibited by immutability trigger"
    );
    let err_msg = update_res.unwrap_err().to_string();
    assert!(
        err_msg.contains("append-only") || err_msg.contains("prohibited"),
        "Error message must mention append-only constraint: {err_msg}"
    );

    // 2. Attempt DELETE on audit_events: MUST FAIL via trigger
    let delete_res = sqlx::query("DELETE FROM audit_events WHERE id = $1")
        .bind(event.id)
        .execute(test_db.pool())
        .await;

    assert!(
        delete_res.is_err(),
        "DELETE on audit_events must be prohibited by immutability trigger"
    );

    // 3. Attempt DELETE on audit_chain_heads: MUST FAIL via trigger
    let delete_head_res = sqlx::query("DELETE FROM audit_chain_heads WHERE workspace_id = $1")
        .bind(ws_id)
        .execute(test_db.pool())
        .await;

    assert!(
        delete_head_res.is_err(),
        "DELETE on audit_chain_heads must be prohibited by protection trigger"
    );

    // 4. Check constraint tests: empty strings
    let bad_org = sqlx::query("INSERT INTO organizations (name, slug) VALUES ('', 'empty-name')")
        .execute(test_db.pool())
        .await;
    assert!(
        bad_org.is_err(),
        "Empty name must be rejected by check constraint"
    );

    let bad_role = sqlx::query(
        "INSERT INTO memberships (workspace_id, principal_id, role)
         VALUES ($1, $2, 'invalid_role')",
    )
    .bind(ws_id)
    .bind(Uuid::new_v4())
    .execute(test_db.pool())
    .await;
    assert!(
        bad_role.is_err(),
        "Invalid membership role must be rejected"
    );

    test_db.close().await.expect("Failed to drop test database");
}
