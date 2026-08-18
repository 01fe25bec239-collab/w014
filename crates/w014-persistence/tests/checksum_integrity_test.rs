use std::fs;
use tempfile::tempdir;
use w014_persistence::{MigrationRunner, Migrator, PersistenceError, TestDatabase};

#[tokio::test]
async fn test_checksum_mismatch_detected_on_tampered_migration() {
    // 1. Provision isolated test database
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    // 2. Prepare migration fixture
    let dir = tempdir().expect("Failed to create temporary directory for migrations");
    let migration_file = dir.path().join("20260818000001_original.sql");
    fs::write(
        &migration_file,
        "CREATE TABLE t_checksum_test (id INT PRIMARY KEY);",
    )
    .expect("Failed to write initial migration");

    let migrator1 = Migrator::new(dir.path())
        .await
        .expect("Failed to load migrator");

    let runner1 = MigrationRunner::new(&migrator1);
    runner1
        .run(test_db.pool())
        .await
        .expect("Initial migration should succeed");

    // 3. Tamper with the applied migration file content (changing its checksum)
    fs::write(
        &migration_file,
        "CREATE TABLE t_checksum_test (id INT PRIMARY KEY, tampered_column TEXT);",
    )
    .expect("Failed to tamper with migration file");

    let migrator2 = Migrator::new(dir.path())
        .await
        .expect("Failed to load migrator with tampered content");

    let runner2 = MigrationRunner::new(&migrator2);
    let run_res = runner2.run(test_db.pool()).await;

    // 4. Assert SQLx detects checksum mismatch and fails
    match run_res {
        Err(PersistenceError::Migration(sqlx::migrate::MigrateError::VersionMismatch(version))) => {
            assert_eq!(version, 20260818000001);
        }
        other => panic!("Expected VersionMismatch checksum error, got: {other:?}"),
    }

    // 5. Cleanup test database
    test_db
        .close()
        .await
        .expect("Failed to drop test database cleanly");
}
