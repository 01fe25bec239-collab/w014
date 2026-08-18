//! Upgrade Migration Test from W0 Baseline to M001R against real PostgreSQL 18.
//!
//! Validates:
//! - Initial baseline state is applied cleanly.
//! - Upgrading to M001R succeeds without manual database repair.
//! - Target migration bundle version is recorded as applied.
//! - Repeat upgrade execution is idempotent.

use std::fs;
use tempfile::tempdir;
use w014_persistence::{Migrator, TestDatabase, run_upgrade_migration_harness};

#[tokio::test]
async fn test_upgrade_from_w0_baseline_to_m001r() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    // 1. Prepare initial baseline migration fixture (representing initial platform state)
    let baseline_dir = tempdir().expect("Failed to create baseline migration dir");
    fs::write(
        baseline_dir
            .path()
            .join("20260818000001_w0_platform_scaffold.sql"),
        "CREATE TABLE IF NOT EXISTS t_w0_platform_info (
            id SERIAL PRIMARY KEY,
            version TEXT NOT NULL,
            installed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
    )
    .expect("Failed to write baseline migration");

    let initial_migrator = Migrator::new(baseline_dir.path())
        .await
        .expect("Failed to load initial migrator");

    // 2. Prepare upgrade migrator containing both baseline + M001R
    let upgrade_dir = tempdir().expect("Failed to create upgrade migration dir");
    fs::write(
        upgrade_dir
            .path()
            .join("20260818000001_w0_platform_scaffold.sql"),
        "CREATE TABLE IF NOT EXISTS t_w0_platform_info (
            id SERIAL PRIMARY KEY,
            version TEXT NOT NULL,
            installed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
    )
    .expect("Failed to write baseline to upgrade set");

    let m001r_content = fs::read_to_string(
        "migrations/20260819000001_m001r_identity_session_audit_idempotency.sql",
    )
    .expect("Failed to read M001R migration file");

    fs::write(
        upgrade_dir
            .path()
            .join("20260819000001_m001r_identity_session_audit_idempotency.sql"),
        m001r_content,
    )
    .expect("Failed to write M001R to upgrade set");

    let target_migrator = Migrator::new(upgrade_dir.path())
        .await
        .expect("Failed to load target migrator");

    // 3. Execute upgrade migration harness
    let result = run_upgrade_migration_harness(test_db.pool(), &initial_migrator, &target_migrator)
        .await
        .expect("Upgrade migration harness failed");

    // 4. Assert baseline migration report
    assert_eq!(
        result.initial_migration_report.newly_applied_versions,
        vec![20260818000001]
    );
    assert_eq!(result.initial_migration_report.total_applied_count, 1);
    assert_eq!(
        result.initial_migration_report.latest_version,
        Some(20260818000001)
    );

    // 5. Assert intermediate state
    assert_eq!(result.intermediate_status.applied.len(), 1);
    assert_eq!(
        result.intermediate_status.current_version,
        Some(20260818000001)
    );

    // 6. Assert forward upgrade applied M001R without manual repair
    assert_eq!(
        result.upgrade_migration_report.newly_applied_versions,
        vec![20260819000001]
    );
    assert_eq!(result.upgrade_migration_report.total_applied_count, 2);
    assert_eq!(
        result.upgrade_migration_report.latest_version,
        Some(20260819000001)
    );

    // 7. Assert final state is up to date
    assert_eq!(result.final_status.applied.len(), 2);
    assert_eq!(result.final_status.pending.len(), 0);
    assert!(result.final_status.is_up_to_date);

    // 8. Assert repeat upgrade is idempotent
    assert!(
        result
            .repeat_upgrade_report
            .newly_applied_versions
            .is_empty()
    );
    assert_eq!(result.repeat_upgrade_report.total_applied_count, 2);
    assert!(result.repeat_upgrade_report.already_up_to_date);

    // 9. Verify functional behavior on upgraded database
    sqlx::query("INSERT INTO organizations (name, slug) VALUES ('Test Org', 'test-org')")
        .execute(test_db.pool())
        .await
        .expect("Failed to insert into organizations after upgrade");

    // Cleanup
    test_db.close().await.expect("Failed to drop test database");
}
