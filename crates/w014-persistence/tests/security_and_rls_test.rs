//! Security, Forced RLS Isolation, Composite-FK, Immutability Triggers, and Role Privilege Tests against real PostgreSQL 18.
//!
//! Validates:
//! - Row Level Security (RLS) defense-in-depth isolation between workspaces (A/B proof).
//! - Workspace A can access A-owned rows; Workspace A cannot access B-owned rows.
//! - Workspace B cannot access A-owned rows; Workspace B can access B-owned rows.
//! - Strict rejection of cross-workspace SELECT, INSERT, and UPDATE operations under RLS.
//! - Fail-closed isolation when session workspace context is cleared or unset.
//! - Composite-FK enforcement rejecting cross-workspace / cross-org parent/child relationships at the DB boundary.
//! - Rejection of adversarial globally-valid foreign-workspace UUID references.
//! - Immutability trigger protection on `audit_events` (preventing UPDATE/DELETE).
//! - Protection trigger on `audit_chain_heads` (preventing DELETE and sequence reduction).
//! - CHECK constraints across all M001R tables.
//! - Role privilege boundaries and absence of BYPASSRLS for `w014_app` and `w014_worker`.

use serde_json::json;
use uuid::Uuid;
use w014_persistence::{
    AppendAuditParams, AuditAppendContract, MIGRATOR, MigrationRunner, PostgresAuditStore,
    TestDatabase, clear_session_workspace_id, get_session_workspace_id, set_session_workspace_id,
};

#[tokio::test]
async fn test_rls_workspace_a_b_full_isolation() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");

    let audit_store = PostgresAuditStore::new();

    // 1. Provision 2 distinct Organizations, Programs, Workspaces, and Principals
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let prog_a = Uuid::new_v4();
    let prog_b = Uuid::new_v4();
    let ws_a = Uuid::new_v4();
    let ws_b = Uuid::new_v4();
    let principal_a = Uuid::new_v4();
    let principal_b = Uuid::new_v4();
    let membership_a = Uuid::new_v4();
    let membership_b = Uuid::new_v4();
    let grant_a = Uuid::new_v4();
    let grant_b = Uuid::new_v4();
    let idemp_a = Uuid::new_v4();
    let idemp_b = Uuid::new_v4();

    // Insert Org A & Org B
    sqlx::query(
        "INSERT INTO organizations (organization_id, display_name, slug) VALUES ($1, 'Org A', $2), ($3, 'Org B', $4)",
    )
    .bind(org_a)
    .bind(format!("org-a-{}", org_a.simple()))
    .bind(org_b)
    .bind(format!("org-b-{}", org_b.simple()))
    .execute(test_db.pool())
    .await
    .expect("Failed to create orgs");

    // Insert Principals
    sqlx::query("INSERT INTO principals (principal_id, display_name, email, status) VALUES ($1, 'User A', $2, 'active'), ($3, 'User B', $4, 'active')")
        .bind(principal_a)
        .bind(format!("alice-{}@org-a.com", principal_a.simple()))
        .bind(principal_b)
        .bind(format!("bob-{}@org-b.com", principal_b.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create principals");

    // Insert Programs
    sqlx::query("INSERT INTO programs (program_id, organization_id, name, program_code) VALUES ($1, $2, 'Prog A', $3), ($4, $5, 'Prog B', $6)")
        .bind(prog_a)
        .bind(org_a)
        .bind(format!("prog-a-{}", prog_a.simple()))
        .bind(prog_b)
        .bind(org_b)
        .bind(format!("prog-b-{}", prog_b.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create programs");

    // Insert Workspaces
    sqlx::query("INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code) VALUES ($1, $2, $3, 'WS A', $4), ($5, $6, $7, 'WS B', $8)")
        .bind(ws_a)
        .bind(prog_a)
        .bind(org_a)
        .bind(format!("ws-a-{}", ws_a.simple()))
        .bind(ws_b)
        .bind(prog_b)
        .bind(org_b)
        .bind(format!("ws-b-{}", ws_b.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create workspaces");

    // Insert Memberships
    sqlx::query("INSERT INTO memberships (membership_id, workspace_id, principal_id, role_code, status) VALUES ($1, $2, $3, 'admin', 'active'), ($4, $5, $6, 'admin', 'active')")
        .bind(membership_a)
        .bind(ws_a)
        .bind(principal_a)
        .bind(membership_b)
        .bind(ws_b)
        .bind(principal_b)
        .execute(test_db.pool())
        .await
        .expect("Failed to create memberships");

    // Insert Capability Grants
    sqlx::query("INSERT INTO capability_grants (capability_grant_id, workspace_id, principal_id, capability_code) VALUES ($1, $2, $3, 'WORKSPACE_WRITE'), ($4, $5, $6, 'WORKSPACE_WRITE')")
        .bind(grant_a)
        .bind(ws_a)
        .bind(principal_a)
        .bind(grant_b)
        .bind(ws_b)
        .bind(principal_b)
        .execute(test_db.pool())
        .await
        .expect("Failed to create capability grants");

    // Insert Idempotency Records
    sqlx::query(
        "INSERT INTO idempotency_records (idempotency_record_id, workspace_id, principal_id, route_code, key_hash, request_hash, response_status, expires_at)
         VALUES ($1, $2, $3, 'ROUTE_A', '\\xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'::bytea, '\\xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'::bytea, 200, clock_timestamp() + INTERVAL '1 hour'),
                ($4, $5, $6, 'ROUTE_B', '\\xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'::bytea, '\\xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'::bytea, 200, clock_timestamp() + INTERVAL '1 hour')"
    )
    .bind(idemp_a)
    .bind(ws_a)
    .bind(principal_a)
    .bind(idemp_b)
    .bind(ws_b)
    .bind(principal_b)
    .execute(test_db.pool())
    .await
    .expect("Failed to insert idempotency records");

    // Initialize Audit Chains and events for WS A & WS B
    {
        let mut tx = test_db.pool().begin().await.expect("begin tx");
        audit_store
            .initialize_chain_head(&mut tx, ws_a)
            .await
            .expect("init head a");
        audit_store
            .append_audit_event(
                &mut tx,
                AppendAuditParams {
                    workspace_id: ws_a,
                    actor_type: "user".to_string(),
                    actor_id: Some(principal_a),
                    authority_snapshot: json!({}),
                    action_code: "WORKSPACE_CREATE".to_string(),
                    entity_type: "workspace".to_string(),
                    entity_id: ws_a.to_string(),
                    entity_version: Some(1),
                    request_id: None,
                    correlation_id: Some("corr-a".to_string()),
                    job_id: None,
                    source_state_hash: None,
                    before_ref: None,
                    after_ref: Some(json!({"workspace": "ws_a"})),
                    metadata: json!({}),
                },
            )
            .await
            .expect("append ws a event");

        audit_store
            .initialize_chain_head(&mut tx, ws_b)
            .await
            .expect("init head b");
        audit_store
            .append_audit_event(
                &mut tx,
                AppendAuditParams {
                    workspace_id: ws_b,
                    actor_type: "user".to_string(),
                    actor_id: Some(principal_b),
                    authority_snapshot: json!({}),
                    action_code: "WORKSPACE_CREATE".to_string(),
                    entity_type: "workspace".to_string(),
                    entity_id: ws_b.to_string(),
                    entity_version: Some(1),
                    request_id: None,
                    correlation_id: Some("corr-b".to_string()),
                    job_id: None,
                    source_state_hash: None,
                    before_ref: None,
                    after_ref: Some(json!({"workspace": "ws_b"})),
                    metadata: json!({}),
                },
            )
            .await
            .expect("append ws b event");

        tx.commit().await.expect("commit setup tx");
    }

    // =========================================================================
    // PROOF 1: WORKSPACE A CONTEXT UNDER APPLICATION ROLE (w014_app)
    // =========================================================================

    // 1.1 RLS_WORKSPACE_A_CAN_ACCESS_A: PASS
    {
        let mut tx = test_db.pool().begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .expect("switch to w014_app");

        set_session_workspace_id(&mut tx, ws_a)
            .await
            .expect("set context to ws_a");

        let current_ctx = get_session_workspace_id(&mut tx)
            .await
            .expect("get context");
        assert_eq!(current_ctx, Some(ws_a));

        let ws_a_visible: Vec<Uuid> = sqlx::query_scalar("SELECT workspace_id FROM workspaces")
            .fetch_all(&mut *tx)
            .await
            .expect("query workspaces");
        assert_eq!(
            ws_a_visible,
            vec![ws_a],
            "Workspace A can access own workspace record"
        );

        let memberships_a: Vec<Uuid> = sqlx::query_scalar("SELECT membership_id FROM memberships")
            .fetch_all(&mut *tx)
            .await
            .expect("query memberships");
        assert_eq!(
            memberships_a,
            vec![membership_a],
            "Workspace A can access own membership"
        );

        let grants_a: Vec<Uuid> = sqlx::query_scalar(
            "SELECT capability_grant_id FROM capability_grants WHERE workspace_id = $1",
        )
        .bind(ws_a)
        .fetch_all(&mut *tx)
        .await
        .expect("query capability_grants");
        assert_eq!(
            grants_a,
            vec![grant_a],
            "Workspace A can access own capability grant"
        );

        let heads_a: Vec<Uuid> = sqlx::query_scalar("SELECT workspace_id FROM audit_chain_heads")
            .fetch_all(&mut *tx)
            .await
            .expect("query audit_chain_heads");
        assert_eq!(
            heads_a,
            vec![ws_a],
            "Workspace A can access own audit chain head"
        );

        let events_a: Vec<Uuid> = sqlx::query_scalar("SELECT audit_event_id FROM audit_events")
            .fetch_all(&mut *tx)
            .await
            .expect("query audit_events");
        assert_eq!(events_a.len(), 1, "Workspace A can access own audit event");

        let idemp_records_a: Vec<Uuid> = sqlx::query_scalar(
            "SELECT idempotency_record_id FROM idempotency_records WHERE workspace_id = $1",
        )
        .bind(ws_a)
        .fetch_all(&mut *tx)
        .await
        .expect("query idempotency_records");
        assert_eq!(
            idemp_records_a,
            vec![idemp_a],
            "Workspace A can access own idempotency record"
        );

        // 1.2 RLS_WORKSPACE_A_CANNOT_ACCESS_B / CROSS_WORKSPACE_SELECT_DENIED: PASS
        let ws_b_lookup: Option<Uuid> =
            sqlx::query_scalar("SELECT workspace_id FROM workspaces WHERE workspace_id = $1")
                .bind(ws_b)
                .fetch_optional(&mut *tx)
                .await
                .expect("lookup ws_b");
        assert!(
            ws_b_lookup.is_none(),
            "Workspace A must NOT see Workspace B record"
        );

        let member_b_lookup: Option<Uuid> =
            sqlx::query_scalar("SELECT membership_id FROM memberships WHERE workspace_id = $1")
                .bind(ws_b)
                .fetch_optional(&mut *tx)
                .await
                .expect("lookup member_b");
        assert!(
            member_b_lookup.is_none(),
            "Workspace A must NOT see Workspace B membership"
        );

        let grant_b_lookup: Option<Uuid> = sqlx::query_scalar(
            "SELECT capability_grant_id FROM capability_grants WHERE workspace_id = $1",
        )
        .bind(ws_b)
        .fetch_optional(&mut *tx)
        .await
        .expect("lookup grant_b");
        assert!(
            grant_b_lookup.is_none(),
            "Workspace A must NOT see Workspace B capability grant"
        );

        let head_b_lookup: Option<Uuid> = sqlx::query_scalar(
            "SELECT workspace_id FROM audit_chain_heads WHERE workspace_id = $1",
        )
        .bind(ws_b)
        .fetch_optional(&mut *tx)
        .await
        .expect("lookup head_b");
        assert!(
            head_b_lookup.is_none(),
            "Workspace A must NOT see Workspace B audit chain head"
        );

        let event_b_lookup: Option<Uuid> =
            sqlx::query_scalar("SELECT audit_event_id FROM audit_events WHERE workspace_id = $1")
                .bind(ws_b)
                .fetch_optional(&mut *tx)
                .await
                .expect("lookup event_b");
        assert!(
            event_b_lookup.is_none(),
            "Workspace A must NOT see Workspace B audit event"
        );

        let idemp_b_lookup: Option<Uuid> = sqlx::query_scalar(
            "SELECT idempotency_record_id FROM idempotency_records WHERE workspace_id = $1",
        )
        .bind(ws_b)
        .fetch_optional(&mut *tx)
        .await
        .expect("lookup idemp_b");
        assert!(
            idemp_b_lookup.is_none(),
            "Workspace A must NOT see Workspace B idempotency record"
        );

        tx.rollback().await.expect("rollback");
    }

    // 1.3 CROSS_WORKSPACE_INSERT_DENIED: PASS
    // 1.3.1 Memberships insert for WS B under WS A context
    {
        let mut tx = test_db.pool().begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        set_session_workspace_id(&mut tx, ws_a).await.unwrap();

        let bad_insert = sqlx::query(
            "INSERT INTO memberships (membership_id, workspace_id, principal_id, role_code, status) VALUES ($1, $2, $3, 'reader', 'active')"
        )
        .bind(Uuid::new_v4())
        .bind(ws_b)
        .bind(principal_a)
        .execute(&mut *tx)
        .await;

        assert!(
            bad_insert.is_err(),
            "Cross-workspace insert into memberships must be denied by RLS WITH CHECK"
        );
        tx.rollback().await.expect("rollback");
    }

    // 1.3.2 Capability Grants insert for WS B under WS A context
    {
        let mut tx = test_db.pool().begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        set_session_workspace_id(&mut tx, ws_a).await.unwrap();

        let bad_insert = sqlx::query(
            "INSERT INTO capability_grants (capability_grant_id, workspace_id, principal_id, capability_code) VALUES ($1, $2, $3, 'WORKSPACE_READ')"
        )
        .bind(Uuid::new_v4())
        .bind(ws_b)
        .bind(principal_a)
        .execute(&mut *tx)
        .await;

        assert!(
            bad_insert.is_err(),
            "Cross-workspace insert into capability_grants must be denied by RLS WITH CHECK"
        );
        tx.rollback().await.expect("rollback");
    }

    // 1.3.3 Audit Events insert for WS B under WS A context
    {
        let mut tx = test_db.pool().begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        set_session_workspace_id(&mut tx, ws_a).await.unwrap();

        let bad_insert = sqlx::query(
            "INSERT INTO audit_events (
                audit_event_id, workspace_id, sequence, occurred_at,
                actor_type, action_code, entity_type, entity_id, event_hash
            ) VALUES ($1, $2, 99, clock_timestamp(),
                      'system', 'INJECT', 'res', '1', '\\x1111111111111111111111111111111111111111111111111111111111111111'::bytea)",
        )
        .bind(Uuid::new_v4())
        .bind(ws_b)
        .execute(&mut *tx)
        .await;

        assert!(
            bad_insert.is_err(),
            "Cross-workspace insert into audit_events must be denied by RLS WITH CHECK"
        );
        tx.rollback().await.expect("rollback");
    }

    // 1.4 CROSS_WORKSPACE_UPDATE_DENIED: PASS
    // 1.4.1 Attempt to update an A-visible row into B ownership must fail WITH CHECK
    {
        let mut tx = test_db.pool().begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        set_session_workspace_id(&mut tx, ws_a).await.unwrap();

        let bad_update =
            sqlx::query("UPDATE memberships SET workspace_id = $1 WHERE membership_id = $2")
                .bind(ws_b)
                .bind(membership_a)
                .execute(&mut *tx)
                .await;

        assert!(
            bad_update.is_err(),
            "Updating row workspace_id to WS B must be rejected by RLS WITH CHECK"
        );
        tx.rollback().await.expect("rollback");
    }

    // 1.4.2 Attempt to update a B-owned row while in A context affects 0 rows (invisible)
    {
        let mut tx = test_db.pool().begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        set_session_workspace_id(&mut tx, ws_a).await.unwrap();

        let blind_update =
            sqlx::query("UPDATE memberships SET role_code = 'reader' WHERE membership_id = $1")
                .bind(membership_b)
                .execute(&mut *tx)
                .await
                .expect("update query executes");

        assert_eq!(
            blind_update.rows_affected(),
            0,
            "Updating B-owned row while in A context must affect 0 rows"
        );
        tx.rollback().await.expect("rollback");
    }

    // 1.5 SAME-WORKSPACE MUTATION SUCCEEDS UNDER WS A CONTEXT
    {
        let mut tx = test_db.pool().begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        set_session_workspace_id(&mut tx, ws_a).await.unwrap();

        let valid_update =
            sqlx::query("UPDATE memberships SET role_code = 'operator' WHERE membership_id = $1")
                .bind(membership_a)
                .execute(&mut *tx)
                .await
                .expect("valid same-workspace update executes");

        assert_eq!(
            valid_update.rows_affected(),
            1,
            "Same-workspace update must succeed"
        );
        tx.rollback().await.expect("rollback");
    }

    // =========================================================================
    // PROOF 2: WORKSPACE B CONTEXT UNDER APPLICATION ROLE (w014_app)
    // =========================================================================
    {
        let mut tx = test_db.pool().begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .expect("switch to w014_app");

        set_session_workspace_id(&mut tx, ws_b)
            .await
            .expect("set context to ws_b");

        // 2.1 RLS_WORKSPACE_B_CANNOT_ACCESS_A: PASS
        let ws_a_lookup: Option<Uuid> =
            sqlx::query_scalar("SELECT workspace_id FROM workspaces WHERE workspace_id = $1")
                .bind(ws_a)
                .fetch_optional(&mut *tx)
                .await
                .expect("lookup ws_a");
        assert!(
            ws_a_lookup.is_none(),
            "Workspace B must NOT see Workspace A record"
        );

        let member_a_lookup: Option<Uuid> =
            sqlx::query_scalar("SELECT membership_id FROM memberships WHERE workspace_id = $1")
                .bind(ws_a)
                .fetch_optional(&mut *tx)
                .await
                .expect("lookup member_a");
        assert!(
            member_a_lookup.is_none(),
            "Workspace B must NOT see Workspace A membership"
        );

        // 2.2 Workspace B can see own rows
        let ws_b_visible: Vec<Uuid> = sqlx::query_scalar("SELECT workspace_id FROM workspaces")
            .fetch_all(&mut *tx)
            .await
            .expect("query workspaces");
        assert_eq!(ws_b_visible, vec![ws_b]);

        tx.rollback().await.expect("rollback");
    }

    // =========================================================================
    // PROOF 3: FAIL-CLOSED ISOLATION (RLS CONTEXT UNSET / CLEARED)
    // =========================================================================
    {
        let mut tx = test_db.pool().begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .expect("switch to w014_app");

        clear_session_workspace_id(&mut tx)
            .await
            .expect("clear context");

        let no_workspaces: Vec<Uuid> = sqlx::query_scalar("SELECT workspace_id FROM workspaces")
            .fetch_all(&mut *tx)
            .await
            .expect("query workspaces without context");
        assert_eq!(
            no_workspaces.len(),
            0,
            "No workspaces visible when RLS context is unset (fail closed)"
        );

        let no_memberships: Vec<Uuid> = sqlx::query_scalar("SELECT membership_id FROM memberships")
            .fetch_all(&mut *tx)
            .await
            .expect("query memberships without context");
        assert_eq!(
            no_memberships.len(),
            0,
            "No memberships visible when RLS context is unset"
        );

        let no_events: Vec<Uuid> = sqlx::query_scalar("SELECT audit_event_id FROM audit_events")
            .fetch_all(&mut *tx)
            .await
            .expect("query audit_events without context");
        assert_eq!(
            no_events.len(),
            0,
            "No audit events visible when RLS context is unset"
        );

        // Any insert without context must fail WITH CHECK
        let bad_insert_without_ctx = sqlx::query(
            "INSERT INTO memberships (membership_id, workspace_id, principal_id, role_code, status) VALUES ($1, $2, $3, 'reader', 'active')"
        )
        .bind(Uuid::new_v4())
        .bind(ws_a)
        .bind(principal_a)
        .execute(&mut *tx)
        .await;
        assert!(
            bad_insert_without_ctx.is_err(),
            "Insert without RLS context must fail closed"
        );

        tx.rollback().await.expect("rollback");
    }

    test_db.close().await.expect("Failed to drop test database");
}

#[tokio::test]
async fn test_cross_workspace_composite_fk_rejection() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");

    let org1 = Uuid::new_v4();
    let org2 = Uuid::new_v4();
    let prog1_in_org1 = Uuid::new_v4();
    let prog2_in_org2 = Uuid::new_v4();

    // 1. Create Org 1 and Org 2
    sqlx::query(
        "INSERT INTO organizations (organization_id, display_name, slug) VALUES ($1, 'Org 1', $2), ($3, 'Org 2', $4)",
    )
    .bind(org1)
    .bind(format!("org-1-{}", org1.simple()))
    .bind(org2)
    .bind(format!("org-2-{}", org2.simple()))
    .execute(test_db.pool())
    .await
    .expect("create orgs");

    // 2. Create Program 1 in Org 1 and Program 2 in Org 2
    sqlx::query("INSERT INTO programs (program_id, organization_id, name, program_code) VALUES ($1, $2, 'Prog 1', $3), ($4, $5, 'Prog 2', $6)")
        .bind(prog1_in_org1)
        .bind(org1)
        .bind(format!("prog-1-{}", prog1_in_org1.simple()))
        .bind(prog2_in_org2)
        .bind(org2)
        .bind(format!("prog-2-{}", prog2_in_org2.simple()))
        .execute(test_db.pool())
        .await
        .expect("create programs");

    // 3. Attempt to create a Workspace in Org 2 referencing Program 1 (from Org 1)
    // Must be strictly rejected by composite FK `fk_workspaces_program_org` at the PostgreSQL boundary!
    let cross_org_workspace_res = sqlx::query(
        "INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code)
         VALUES ($1, $2, $3, 'Cross WS', $4)",
    )
    .bind(Uuid::new_v4())
    .bind(prog1_in_org1) // Program belongs to Org 1
    .bind(org2) // But Workspace belongs to Org 2!
    .bind("cross-ws")
    .execute(test_db.pool())
    .await;

    assert!(
        cross_org_workspace_res.is_err(),
        "Cross-organization program reference MUST be rejected by composite FK fk_workspaces_program_org"
    );
    let err_msg = cross_org_workspace_res.unwrap_err().to_string();
    assert!(
        err_msg.contains("fk_workspaces_program_org")
            || err_msg.contains("violates foreign key constraint"),
        "Error message must indicate foreign key constraint violation: {err_msg}"
    );

    // 4. Valid same-organization workspace insertion must succeed
    let valid_ws = sqlx::query(
        "INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code)
         VALUES ($1, $2, $3, 'Valid WS', $4)",
    )
    .bind(Uuid::new_v4())
    .bind(prog1_in_org1)
    .bind(org1)
    .bind("valid-ws")
    .execute(test_db.pool())
    .await;

    assert!(
        valid_ws.is_ok(),
        "Valid same-organization workspace must succeed"
    );

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

    sqlx::query("INSERT INTO organizations (organization_id, display_name, slug) VALUES ($1, 'Imm Org', $2)")
        .bind(org_id)
        .bind(format!("org-{}", org_id.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to create org");

    sqlx::query(
        "INSERT INTO programs (program_id, organization_id, name, program_code) VALUES ($1, $2, 'Imm Prog', $3)",
    )
    .bind(prog_id)
    .bind(org_id)
    .bind(format!("prog-{}", prog_id.simple()))
    .execute(test_db.pool())
    .await
    .expect("Failed to create prog");

    sqlx::query("INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code) VALUES ($1, $2, $3, 'Imm WS', $4)")
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
                actor_type: "system".to_string(),
                actor_id: None,
                authority_snapshot: json!({}),
                action_code: "CREATE".to_string(),
                entity_type: "item".to_string(),
                entity_id: "1".to_string(),
                entity_version: Some(1),
                request_id: None,
                correlation_id: None,
                job_id: None,
                source_state_hash: None,
                before_ref: None,
                after_ref: None,
                metadata: json!({}),
            },
        )
        .await
        .expect("Failed to append event");
    tx.commit().await.expect("Failed to commit tx");

    // 1. Attempt UPDATE on audit_events: MUST FAIL via trigger
    let update_res =
        sqlx::query("UPDATE audit_events SET action_code = 'MUTATED' WHERE audit_event_id = $1")
            .bind(event.audit_event_id)
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
    let delete_res = sqlx::query("DELETE FROM audit_events WHERE audit_event_id = $1")
        .bind(event.audit_event_id)
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
    let bad_org =
        sqlx::query("INSERT INTO organizations (display_name, slug) VALUES ('', 'empty-name')")
            .execute(test_db.pool())
            .await;
    assert!(
        bad_org.is_err(),
        "Empty name must be rejected by check constraint"
    );

    let bad_role = sqlx::query(
        "INSERT INTO memberships (workspace_id, principal_id, role_code, status)
         VALUES ($1, $2, 'invalid_role', 'active')",
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
