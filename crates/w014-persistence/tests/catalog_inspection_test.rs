//! Direct PostgreSQL Catalog Inspection and Conformance Verification against real PostgreSQL 18.
//!
//! Validates:
//! - Catalog existence of all 13 M001R tables.
//! - Absence of W2 durable-job tables.
//! - Absence of deferred staged FK constraints.
//! - Verification of RLS enabled (`relrowsecurity`) and forced (`relforcerowsecurity`) states.
//! - Verification of RLS policies in `pg_policy`.
//! - Verification of database roles and restricted privileges in `information_schema.table_privileges`.
//! - Verification of immutability triggers in `information_schema.triggers`.

use sqlx::Row;
use w014_persistence::{MIGRATOR, MigrationRunner, TestDatabase};

#[tokio::test]
async fn test_database_catalog_state_and_security_mechanics() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");

    // 1. Verify exact 13 M001R tables exist
    let expected_tables = vec![
        "organizations",
        "principals",
        "programs",
        "workspaces",
        "memberships",
        "capability_grants",
        "oidc_identities",
        "sessions",
        "session_rotations",
        "oidc_transactions",
        "audit_chain_heads",
        "audit_events",
        "idempotency_records",
    ];

    for table in &expected_tables {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = $1
            )",
        )
        .bind(table)
        .fetch_one(test_db.pool())
        .await
        .expect("Failed to query table existence");

        assert!(exists, "Table '{table}' must exist in public schema");
    }

    // 2. Verify all W2 job tables are strictly absent
    let forbidden_tables = vec![
        "jobs",
        "job_attempts",
        "job_dependencies",
        "job_progress",
        "dead_letter_entries",
    ];

    for table in &forbidden_tables {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = $1
            )",
        )
        .bind(table)
        .fetch_one(test_db.pool())
        .await
        .expect("Failed to query forbidden table existence");

        assert!(!exists, "W2 job table '{table}' must NOT exist in W1 M001R");
    }

    // 3. Verify Staged FK 1: workspaces.current_source_state_id FK is ABSENT
    let ws_fk_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
              AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'FOREIGN KEY'
              AND tc.table_name = 'workspaces'
              AND kcu.column_name = 'current_source_state_id'
        )",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to inspect workspaces FKs");

    assert!(
        !ws_fk_exists,
        "workspaces.current_source_state_id must NOT have a foreign key in W1"
    );

    // 4. Verify Staged FK 2: audit_events.job_id FK is ABSENT
    let audit_job_fk_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
              AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'FOREIGN KEY'
              AND tc.table_name = 'audit_events'
              AND kcu.column_name = 'job_id'
        )",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to inspect audit_events FKs");

    assert!(
        !audit_job_fk_exists,
        "audit_events.job_id must NOT have a foreign key in W1"
    );

    // 5. Verify RLS enabled and forced on tenant tables
    let rls_tables = vec![
        "workspaces",
        "memberships",
        "capability_grants",
        "sessions",
        "audit_chain_heads",
        "audit_events",
        "idempotency_records",
    ];

    for table in &rls_tables {
        let row = sqlx::query(
            "SELECT relrowsecurity, relforcerowsecurity
             FROM pg_class
             WHERE relname = $1 AND relnamespace = 'public'::regnamespace",
        )
        .bind(table)
        .fetch_one(test_db.pool())
        .await
        .unwrap_or_else(|e| panic!("Failed to inspect RLS flags for '{table}': {e}"));

        let rowsecurity: bool = row.get("relrowsecurity");
        let forcerowsecurity: bool = row.get("relforcerowsecurity");

        assert!(
            rowsecurity,
            "Table '{table}' must have relrowsecurity = true"
        );
        assert!(
            forcerowsecurity,
            "Table '{table}' must have relforcerowsecurity = true (FORCE RLS)"
        );
    }

    // 6. Verify RLS policies exist in pg_policy
    for table in &rls_tables {
        let policy_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)
             FROM pg_policy pol
             JOIN pg_class cls ON pol.polrelid = cls.oid
             WHERE cls.relname = $1 AND cls.relnamespace = 'public'::regnamespace",
        )
        .bind(table)
        .fetch_one(test_db.pool())
        .await
        .expect("Failed to query pg_policy");

        assert!(
            policy_count >= 1,
            "Table '{table}' must have at least 1 RLS policy defined"
        );
    }

    // 7. Verify immutability triggers exist on audit tables
    let audit_events_trigger_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT trigger_name)
         FROM information_schema.triggers
         WHERE event_object_table = 'audit_events'
           AND trigger_name = 'trg_prevent_audit_events_mutation'",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to check audit_events triggers");

    assert_eq!(
        audit_events_trigger_count, 1,
        "audit_events must have trg_prevent_audit_events_mutation trigger"
    );

    let chain_heads_trigger_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT trigger_name)
         FROM information_schema.triggers
         WHERE event_object_table = 'audit_chain_heads'
           AND trigger_name = 'trg_prevent_audit_chain_heads_deletion'",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to check audit_chain_heads triggers");

    assert_eq!(
        chain_heads_trigger_count, 1,
        "audit_chain_heads must have trg_prevent_audit_chain_heads_deletion trigger"
    );

    // 8. Verify database roles exist
    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT rolname FROM pg_roles WHERE rolname IN ('w014_app', 'w014_readonly')",
    )
    .fetch_all(test_db.pool())
    .await
    .expect("Failed to query pg_roles");

    assert!(
        roles.contains(&"w014_app".to_string()),
        "Role 'w014_app' must exist"
    );
    assert!(
        roles.contains(&"w014_readonly".to_string()),
        "Role 'w014_readonly' must exist"
    );

    // 9. Verify w014_app has NO UPDATE or DELETE grant on audit_events
    let prohibited_grants: Vec<String> = sqlx::query_scalar(
        "SELECT privilege_type
         FROM information_schema.table_privileges
         WHERE grantee = 'w014_app'
           AND table_name = 'audit_events'
           AND privilege_type IN ('UPDATE', 'DELETE')",
    )
    .fetch_all(test_db.pool())
    .await
    .expect("Failed to query table_privileges for w014_app on audit_events");

    assert!(
        prohibited_grants.is_empty(),
        "w014_app must NOT have UPDATE or DELETE grants on audit_events, found: {prohibited_grants:?}"
    );

    test_db.close().await.expect("Failed to drop test database");
}
