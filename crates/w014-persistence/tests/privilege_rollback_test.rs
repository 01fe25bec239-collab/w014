//! Privileged Mutation Rollback on Audit Failure Test against real PostgreSQL 18.
//!
//! Validates:
//! - An atomic database transaction encompassing domain mutation + authoritative audit append.
//! - Successful audit append commits both domain mutation and audit event.
//! - Failed audit append rolls back the privileged domain mutation.

use serde_json::json;
use uuid::Uuid;
use w014_persistence::{
    AppendAuditParams, AuditAppendContract, MIGRATOR, MigrationRunner, PostgresAuditStore,
    TestDatabase,
};

#[tokio::test]
async fn test_privileged_mutation_rollback_on_audit_failure() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");

    let audit_store = PostgresAuditStore::new();

    // 1. Success case: Domain mutation + audit append succeeds atomically
    let org_id = Uuid::new_v4();
    let program_id = Uuid::new_v4();
    let workspace_id = Uuid::new_v4();

    {
        let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");

        // Privileged domain mutation 1: Insert organization
        sqlx::query("INSERT INTO organizations (organization_id, display_name, slug) VALUES ($1, 'Org Success', $2)")
            .bind(org_id)
            .bind(format!("org-{}", org_id.simple()))
            .execute(&mut *tx)
            .await
            .expect("Failed to insert org");

        // Privileged domain mutation 2: Insert program & workspace
        sqlx::query("INSERT INTO programs (program_id, organization_id, name, program_code) VALUES ($1, $2, 'Prog Success', $3)")
            .bind(program_id)
            .bind(org_id)
            .bind(format!("prog-{}", program_id.simple()))
            .execute(&mut *tx)
            .await
            .expect("Failed to insert prog");

        sqlx::query("INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code) VALUES ($1, $2, $3, 'WS Success', $4)")
            .bind(workspace_id)
            .bind(program_id)
            .bind(org_id)
            .bind(format!("ws-{}", workspace_id.simple()))
            .execute(&mut *tx)
            .await
            .expect("Failed to insert ws");

        // Authoritative audit append
        let audit_res = audit_store
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
                    request_id: None,
                    correlation_id: Some("corr-success".to_string()),
                    job_id: None,
                    source_state_hash: None,
                    before_ref: None,
                    after_ref: Some(json!({"name": "WS Success"})),
                    metadata: json!({}),
                },
            )
            .await;

        match audit_res {
            Ok(_) => {
                tx.commit().await.expect("Commit should succeed");
            }
            Err(e) => {
                tx.rollback().await.expect("Rollback should succeed");
                panic!("Audit append unexpectedly failed: {e:?}");
            }
        }
    }

    // Verify workspace was persisted
    let ws_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM workspaces WHERE workspace_id = $1)")
            .bind(workspace_id)
            .fetch_one(test_db.pool())
            .await
            .expect("Failed to query workspace");
    assert!(
        ws_exists,
        "Workspace should be persisted on successful audit append"
    );

    // 2. Failure case: Privileged domain mutation attempted, but audit append fails -> ROLLBACK
    let failed_org_id = Uuid::new_v4();
    let failed_program_id = Uuid::new_v4();
    let failed_workspace_id = Uuid::new_v4();

    {
        let mut tx = test_db.pool().begin().await.expect("Failed to begin tx");

        // Privileged domain mutation: Insert organization
        sqlx::query(
            "INSERT INTO organizations (organization_id, display_name, slug) VALUES ($1, 'Org Failure Target', $2)",
        )
        .bind(failed_org_id)
        .bind(format!("org-{}", failed_org_id.simple()))
        .execute(&mut *tx)
        .await
        .expect("Failed to insert org");

        // Privileged domain mutation: Insert program & workspace
        sqlx::query("INSERT INTO programs (program_id, organization_id, name, program_code) VALUES ($1, $2, 'Prog Failure Target', $3)")
            .bind(failed_program_id)
            .bind(failed_org_id)
            .bind(format!("prog-{}", failed_program_id.simple()))
            .execute(&mut *tx)
            .await
            .expect("Failed to insert prog");

        sqlx::query("INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code) VALUES ($1, $2, $3, 'WS Failure Target', $4)")
            .bind(failed_workspace_id)
            .bind(failed_program_id)
            .bind(failed_org_id)
            .bind(format!("ws-{}", failed_workspace_id.simple()))
            .execute(&mut *tx)
            .await
            .expect("Failed to insert ws");

        // Simulate audit failure by violating a check constraint (empty action_code)
        let simulated_bad_params = AppendAuditParams {
            workspace_id: failed_workspace_id,
            actor_type: "user".to_string(),
            actor_id: None,
            authority_snapshot: json!({}),
            action_code: "".to_string(), // Violates chk_audit_events_action_code_non_empty CHECK constraint!
            entity_type: "workspace".to_string(),
            entity_id: failed_workspace_id.to_string(),
            entity_version: Some(1),
            request_id: None,
            correlation_id: None,
            job_id: None,
            source_state_hash: None,
            before_ref: None,
            after_ref: None,
            metadata: json!({}),
        };

        let audit_res = audit_store
            .append_audit_event(&mut tx, simulated_bad_params)
            .await;

        assert!(
            audit_res.is_err(),
            "Audit append with empty action_code must fail check constraint"
        );

        // On audit failure, roll back the transaction
        tx.rollback().await.expect("Rollback should succeed");
    }

    // Verify that NEITHER the organization, program, NOR the workspace was persisted
    let failed_org_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM organizations WHERE organization_id = $1)",
    )
    .bind(failed_org_id)
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to query failed org");

    let failed_ws_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM workspaces WHERE workspace_id = $1)")
            .bind(failed_workspace_id)
            .fetch_one(test_db.pool())
            .await
            .expect("Failed to query failed workspace");

    assert!(
        !failed_org_exists,
        "Organization must be rolled back when audit append fails"
    );
    assert!(
        !failed_ws_exists,
        "Workspace must be rolled back when audit append fails"
    );

    test_db.close().await.expect("Failed to drop test database");
}
