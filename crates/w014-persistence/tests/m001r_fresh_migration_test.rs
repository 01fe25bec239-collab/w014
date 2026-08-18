//! Fresh M001R Migration Test against real PostgreSQL 18.
//!
//! Validates:
//! - Fresh application of the embedded M001R production migration bundle.
//! - Creation of all 13 M001R tables.
//! - Absence of deferred staged FKs (current_source_state_id, job_id).
//! - Absence of W2 job tables.
//! - Repeat run idempotency.

use w014_persistence::{MIGRATOR, TestDatabase, run_fresh_migration_harness};

#[tokio::test]
async fn test_m001r_fresh_migration_and_catalog_invariants() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    // 1. Run fresh migration harness with embedded M001R migrator
    let result = run_fresh_migration_harness(test_db.pool(), &MIGRATOR)
        .await
        .expect("M001R fresh migration harness failed");

    // 2. Assert initial status was clean
    assert_eq!(result.initial_status.applied.len(), 0);
    assert_eq!(result.initial_status.current_version, None);
    assert!(!result.initial_status.is_up_to_date);

    // 3. Assert M001R applied successfully
    assert_eq!(
        result.first_run_report.newly_applied_versions,
        vec![20260819000001]
    );
    assert_eq!(result.first_run_report.total_applied_count, 1);
    assert_eq!(result.first_run_report.latest_version, Some(20260819000001));
    assert!(!result.first_run_report.already_up_to_date);

    // 4. Assert repeat run idempotency
    assert!(result.repeat_run_report.newly_applied_versions.is_empty());
    assert_eq!(result.repeat_run_report.total_applied_count, 1);
    assert!(result.repeat_run_report.already_up_to_date);

    // 5. Assert all 13 expected M001R tables exist in public schema
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
        .unwrap_or_else(|e| panic!("Failed to check table '{table}': {e}"));

        assert!(
            exists,
            "Expected table '{table}' to exist after M001R migration"
        );
    }

    // 6. Assert W2 durable-job tables are strictly ABSENT
    let forbidden_w2_tables = vec![
        "jobs",
        "job_attempts",
        "job_dependencies",
        "job_progress",
        "dead_letter_entries",
    ];

    for table in &forbidden_w2_tables {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = $1
            )",
        )
        .bind(table)
        .fetch_one(test_db.pool())
        .await
        .unwrap_or_else(|e| panic!("Failed to check forbidden table '{table}': {e}"));

        assert!(
            !exists,
            "Forbidden W2 table '{table}' must NOT exist in M001R"
        );
    }

    // 7. Assert Staged FK: workspaces.current_source_state_id has NO foreign key constraint
    let current_source_state_fk_exists: bool = sqlx::query_scalar(
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
    .expect("Failed to check workspaces.current_source_state_id FK");

    assert!(
        !current_source_state_fk_exists,
        "Staged FK workspaces.current_source_state_id must NOT have a foreign key constraint in W1"
    );

    // 8. Assert Staged FK: audit_events.job_id has NO foreign key constraint
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
    .expect("Failed to check audit_events.job_id FK");

    assert!(
        !audit_job_fk_exists,
        "Staged FK audit_events.job_id must NOT have a foreign key constraint in W1"
    );

    // Cleanup
    test_db.close().await.expect("Failed to drop test database");
}
