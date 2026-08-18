use std::fs;
use tempfile::tempdir;
use w014_persistence::{MigrationRunner, Migrator, TestDatabase, run_failing_migration_harness};

#[tokio::test]
async fn test_failing_migration_propagates_error() {
    // 1. Provision isolated test database
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    // 2. Prepare migration fixture with invalid SQL syntax
    let dir = tempdir().expect("Failed to create temporary directory for migrations");
    let bad_migration = dir.path().join("20260818000001_syntax_error.sql");
    fs::write(
        &bad_migration,
        "THIS IS NOT VALID SQL SYNTAX AND MUST FAIL;",
    )
    .expect("Failed to write bad migration");

    let migrator = Migrator::new(dir.path())
        .await
        .expect("Failed to load migrator from temp directory");

    // 3. Execute failing harness
    let err = run_failing_migration_harness(test_db.pool(), &migrator)
        .await
        .expect("Expected migration to return failure error");

    // 4. Assert error details are exposed
    let err_str = err.to_string();
    assert!(
        err_str.contains("syntax error") || err_str.contains("syntax"),
        "Error message should mention syntax error, got: {err_str}"
    );

    // 5. Verify status still reports the migration as unapplied / failed rather than success
    let runner = MigrationRunner::new(&migrator);
    let status = runner
        .status(test_db.pool())
        .await
        .expect("Failed to get migration status");

    assert_eq!(status.applied.len(), 0);
    assert!(!status.is_up_to_date);

    // 6. Cleanup test database
    test_db
        .close()
        .await
        .expect("Failed to drop test database cleanly");
}
