use sha2::{Digest, Sha256};
use std::fs;
use tempfile::tempdir;
use w014_persistence::{MIGRATOR, MigrationRunner, Migrator, PersistenceError, TestDatabase};

#[tokio::test]
async fn test_published_m001r_and_m001r_f1_checksum_integrity() {
    let m001r_content = fs::read(
        "migrations/20260819000001_m001r_identity_session_audit_idempotency.sql",
    )
    .or_else(|_| {
        fs::read(
            "crates/w014-persistence/migrations/20260819000001_m001r_identity_session_audit_idempotency.sql",
        )
    })
    .expect("Failed to read published M001R migration file");

    let mut hasher = Sha256::new();
    hasher.update(&m001r_content);
    let checksum = hex::encode(hasher.finalize());

    assert_eq!(
        checksum, "9b23eaddb0fa1df6c7af4745d909a0f916a9b8aa308c015300ec8d1d6ba0e0fb",
        "Published M001R migration file MUST remain byte-for-byte unchanged"
    );

    // Verify forward repair migration exists
    let m001r_f1_exists = fs::metadata("migrations/20260820000001_m001r_prompt12_conformance_repair.sql")
        .or_else(|_| fs::metadata("crates/w014-persistence/migrations/20260820000001_m001r_prompt12_conformance_repair.sql"))
        .is_ok();
    assert!(
        m001r_f1_exists,
        "M001R-F1 forward repair migration must exist"
    );

    // Verify MIGRATOR includes both migrations in exact sequence
    let versions: Vec<i64> = MIGRATOR.iter().map(|m| m.version).collect();
    assert_eq!(
        versions,
        vec![20260819000001, 20260820000001],
        "MIGRATOR must contain 20260819000001 followed by 20260820000001"
    );
}

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
