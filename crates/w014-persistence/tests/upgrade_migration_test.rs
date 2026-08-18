use std::fs;
use tempfile::tempdir;
use w014_persistence::{Migrator, TestDatabase, run_upgrade_migration_harness};

#[tokio::test]
async fn test_upgrade_migration_harness_against_postgres18() {
    // 1. Provision isolated test database on real PostgreSQL 18
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    // 2. Prepare initial (baseline) migration fixture
    let initial_dir = tempdir().expect("Failed to create tempdir for initial migrations");
    fs::write(
        initial_dir
            .path()
            .join("20260818000001_baseline_schema.sql"),
        "CREATE TABLE t_upgrade_baseline (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL
        );",
    )
    .expect("Failed to write initial migration");

    let initial_migrator = Migrator::new(initial_dir.path())
        .await
        .expect("Failed to load initial migrator");

    // 3. Prepare target (upgraded) migration fixture containing both baseline + new migration
    let upgrade_dir = tempdir().expect("Failed to create tempdir for upgrade migrations");
    fs::write(
        upgrade_dir
            .path()
            .join("20260818000001_baseline_schema.sql"),
        "CREATE TABLE t_upgrade_baseline (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL
        );",
    )
    .expect("Failed to write initial migration to upgrade set");

    fs::write(
        upgrade_dir
            .path()
            .join("20260818000002_extended_feature.sql"),
        "CREATE TABLE t_upgrade_extended (
            id SERIAL PRIMARY KEY,
            baseline_id INT NOT NULL REFERENCES t_upgrade_baseline(id),
            extra_data TEXT NOT NULL
        );",
    )
    .expect("Failed to write upgrade migration");

    let target_migrator = Migrator::new(upgrade_dir.path())
        .await
        .expect("Failed to load target migrator");

    // 4. Run upgrade migration harness
    let result = run_upgrade_migration_harness(test_db.pool(), &initial_migrator, &target_migrator)
        .await
        .expect("Upgrade migration harness failed");

    // 5. Assert baseline migration report
    assert_eq!(
        result.initial_migration_report.newly_applied_versions,
        vec![20260818000001]
    );
    assert_eq!(result.initial_migration_report.total_applied_count, 1);
    assert_eq!(
        result.initial_migration_report.latest_version,
        Some(20260818000001)
    );

    // 6. Assert intermediate state
    assert_eq!(result.intermediate_status.applied.len(), 1);
    assert_eq!(
        result.intermediate_status.current_version,
        Some(20260818000001)
    );

    // 7. Assert forward upgrade applied version 2 without manual repair
    assert_eq!(
        result.upgrade_migration_report.newly_applied_versions,
        vec![20260818000002]
    );
    assert_eq!(result.upgrade_migration_report.total_applied_count, 2);
    assert_eq!(
        result.upgrade_migration_report.latest_version,
        Some(20260818000002)
    );

    // 8. Assert final state has all migrations applied and is up-to-date
    assert_eq!(result.final_status.applied.len(), 2);
    assert_eq!(result.final_status.current_version, Some(20260818000002));
    assert_eq!(result.final_status.pending.len(), 0);
    assert!(result.final_status.is_up_to_date);

    // 9. Assert repeat upgrade is idempotent
    assert!(
        result
            .repeat_upgrade_report
            .newly_applied_versions
            .is_empty()
    );
    assert_eq!(result.repeat_upgrade_report.total_applied_count, 2);
    assert!(result.repeat_upgrade_report.already_up_to_date);

    // 10. Verify tables and foreign key relationship work in PostgreSQL
    sqlx::query("INSERT INTO t_upgrade_baseline (id, name) VALUES (1, 'base_item')")
        .execute(test_db.pool())
        .await
        .expect("Failed to insert into baseline table");

    sqlx::query("INSERT INTO t_upgrade_extended (id, baseline_id, extra_data) VALUES (1, 1, 'extended_item')")
        .execute(test_db.pool())
        .await
        .expect("Failed to insert into upgraded table with foreign key");

    // 11. Cleanup test database
    test_db
        .close()
        .await
        .expect("Failed to drop test database cleanly");
}
