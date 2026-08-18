use std::fs;
use tempfile::tempdir;
use w014_persistence::{Migrator, TestDatabase, run_fresh_migration_harness};

#[tokio::test]
async fn test_fresh_migration_harness_against_postgres18() {
    // 1. Provision isolated test database on real PostgreSQL 18
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    // 2. Create a test-only migration fixture in a temporary directory
    let dir = tempdir().expect("Failed to create temporary directory for migrations");
    let migration_file = dir.path().join("20260818000001_create_harness_table.sql");
    fs::write(
        &migration_file,
        "CREATE TABLE t_fresh_harness_test (
            id SERIAL PRIMARY KEY,
            label TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
    )
    .expect("Failed to write migration file");

    let migrator = Migrator::new(dir.path())
        .await
        .expect("Failed to load migrator from temp directory");

    // 3. Execute the reusable fresh migration harness
    let result = run_fresh_migration_harness(test_db.pool(), &migrator)
        .await
        .expect("Fresh migration harness failed");

    // 4. Assert initial clean state
    assert_eq!(result.initial_status.applied.len(), 0);
    assert_eq!(result.initial_status.current_version, None);
    assert_eq!(result.initial_status.pending.len(), 1);
    assert!(!result.initial_status.is_up_to_date);

    // 5. Assert first migration run report
    assert_eq!(
        result.first_run_report.newly_applied_versions,
        vec![20260818000001]
    );
    assert_eq!(result.first_run_report.total_applied_count, 1);
    assert_eq!(result.first_run_report.latest_version, Some(20260818000001));
    assert!(!result.first_run_report.already_up_to_date);

    // 6. Assert post-migration status inspection
    assert_eq!(result.post_migration_status.applied.len(), 1);
    assert_eq!(
        result.post_migration_status.applied[0].version,
        20260818000001
    );
    assert_eq!(
        result.post_migration_status.applied[0].description,
        "create harness table"
    );
    assert!(result.post_migration_status.applied[0].success);
    assert_eq!(result.post_migration_status.pending.len(), 0);
    assert!(result.post_migration_status.is_up_to_date);

    // 7. Assert repeat run idempotency (second execution)
    assert!(result.repeat_run_report.newly_applied_versions.is_empty());
    assert_eq!(result.repeat_run_report.total_applied_count, 1);
    assert_eq!(
        result.repeat_run_report.latest_version,
        Some(20260818000001)
    );
    assert!(result.repeat_run_report.already_up_to_date);

    // 8. Assert final status matches
    assert_eq!(result.final_status.applied.len(), 1);
    assert_eq!(result.final_status.pending.len(), 0);
    assert!(result.final_status.is_up_to_date);

    // 9. Verify created table is functional in PostgreSQL
    sqlx::query("INSERT INTO t_fresh_harness_test (label) VALUES ($1)")
        .bind("smoke_test_row")
        .execute(test_db.pool())
        .await
        .expect("Failed to insert into migrated table");

    // 10. Clean up isolated test database
    test_db
        .close()
        .await
        .expect("Failed to drop test database cleanly");
}
