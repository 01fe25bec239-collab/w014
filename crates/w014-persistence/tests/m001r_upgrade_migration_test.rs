//! Upgrade Migration Test from Published M001R Baseline to M001R-F1 Conformance Repair against real PostgreSQL 18.
//!
//! Validates:
//! - Initial published M001R baseline state is applied cleanly.
//! - Upgrading from M001R to M001R-F1 succeeds on empty/clean databases without manual repair.
//! - Target migration bundle versions are recorded as applied.
//! - Repeat upgrade execution is idempotent.
//! - Fail-closed behavior on semantically ambiguous historical state.

use std::fs;
use tempfile::tempdir;
use uuid::Uuid;
use w014_persistence::{
    MigrationRunner, Migrator, PersistenceError, TestDatabase, run_upgrade_migration_harness,
};

#[tokio::test]
async fn test_upgrade_from_m001r_to_m001r_f1_conformance_repair() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    let m001r_content = fs::read_to_string(
        "crates/w014-persistence/migrations/20260819000001_m001r_identity_session_audit_idempotency.sql",
    )
    .or_else(|_| fs::read_to_string("migrations/20260819000001_m001r_identity_session_audit_idempotency.sql"))
    .expect("Failed to read M001R migration file");

    let m001r_f1_content = fs::read_to_string(
        "crates/w014-persistence/migrations/20260820000001_m001r_prompt12_conformance_repair.sql",
    )
    .or_else(|_| {
        fs::read_to_string("migrations/20260820000001_m001r_prompt12_conformance_repair.sql")
    })
    .expect("Failed to read M001R-F1 migration file");

    // 1. Prepare initial baseline migrator (published M001R only)
    let baseline_dir = tempdir().expect("Failed to create baseline migration dir");
    fs::write(
        baseline_dir
            .path()
            .join("20260819000001_m001r_identity_session_audit_idempotency.sql"),
        &m001r_content,
    )
    .expect("Failed to write baseline migration");

    let initial_migrator = Migrator::new(baseline_dir.path())
        .await
        .expect("Failed to load initial migrator");

    // 2. Prepare upgrade migrator (M001R + M001R-F1)
    let upgrade_dir = tempdir().expect("Failed to create upgrade migration dir");
    fs::write(
        upgrade_dir
            .path()
            .join("20260819000001_m001r_identity_session_audit_idempotency.sql"),
        &m001r_content,
    )
    .expect("Failed to write baseline to upgrade set");

    fs::write(
        upgrade_dir
            .path()
            .join("20260820000001_m001r_prompt12_conformance_repair.sql"),
        &m001r_f1_content,
    )
    .expect("Failed to write M001R-F1 to upgrade set");

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
        vec![20260819000001]
    );
    assert_eq!(result.initial_migration_report.total_applied_count, 1);
    assert_eq!(
        result.initial_migration_report.latest_version,
        Some(20260819000001)
    );

    // 5. Assert intermediate state
    assert_eq!(result.intermediate_status.applied.len(), 1);
    assert_eq!(
        result.intermediate_status.current_version,
        Some(20260819000001)
    );

    // 6. Assert forward upgrade applied M001R-F1 without manual repair
    assert_eq!(
        result.upgrade_migration_report.newly_applied_versions,
        vec![20260820000001]
    );
    assert_eq!(result.upgrade_migration_report.total_applied_count, 2);
    assert_eq!(
        result.upgrade_migration_report.latest_version,
        Some(20260820000001)
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

    // 9. Verify functional Prompt-12 behavior on upgraded database
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (organization_id, display_name, slug) VALUES ($1, 'Upgraded Org', $2)")
        .bind(org_id)
        .bind(format!("upgraded-{}", org_id.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to insert into organizations after upgrade");

    // Cleanup
    test_db.close().await.expect("Failed to drop test database");
}

#[tokio::test]
async fn test_upgrade_fails_closed_on_ambiguous_legacy_data() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    let m001r_content = fs::read_to_string(
        "crates/w014-persistence/migrations/20260819000001_m001r_identity_session_audit_idempotency.sql",
    )
    .or_else(|_| fs::read_to_string("migrations/20260819000001_m001r_identity_session_audit_idempotency.sql"))
    .expect("Failed to read M001R migration file");

    let m001r_f1_content = fs::read_to_string(
        "crates/w014-persistence/migrations/20260820000001_m001r_prompt12_conformance_repair.sql",
    )
    .or_else(|_| {
        fs::read_to_string("migrations/20260820000001_m001r_prompt12_conformance_repair.sql")
    })
    .expect("Failed to read M001R-F1 migration file");

    // 1. Run baseline M001R
    let baseline_dir = tempdir().expect("tempdir");
    fs::write(
        baseline_dir
            .path()
            .join("20260819000001_m001r_identity_session_audit_idempotency.sql"),
        &m001r_content,
    )
    .expect("write baseline");

    let baseline_migrator = Migrator::new(baseline_dir.path()).await.expect("migrator");
    MigrationRunner::new(&baseline_migrator)
        .run(test_db.pool())
        .await
        .expect("run baseline");

    // 2. Populate legacy ambiguous data into principals
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name, slug) VALUES ($1, 'Legacy Org', 'leg-org')")
        .bind(org_id)
        .execute(test_db.pool())
        .await
        .expect("insert org");

    sqlx::query("INSERT INTO principals (id, organization_id, principal_type, display_name) VALUES ($1, $2, 'user', 'Legacy User')")
        .bind(Uuid::new_v4())
        .bind(org_id)
        .execute(test_db.pool())
        .await
        .expect("insert principal");

    // 3. Attempt forward upgrade to M001R-F1 -> MUST FAIL CLOSED
    let upgrade_dir = tempdir().expect("tempdir");
    fs::write(
        upgrade_dir
            .path()
            .join("20260819000001_m001r_identity_session_audit_idempotency.sql"),
        &m001r_content,
    )
    .expect("write baseline");
    fs::write(
        upgrade_dir
            .path()
            .join("20260820000001_m001r_prompt12_conformance_repair.sql"),
        &m001r_f1_content,
    )
    .expect("write f1");

    let target_migrator = Migrator::new(upgrade_dir.path()).await.expect("migrator");
    let upgrade_res = MigrationRunner::new(&target_migrator)
        .run(test_db.pool())
        .await;

    assert!(
        upgrade_res.is_err(),
        "M001R-F1 must fail closed when ambiguous legacy records exist"
    );
    match upgrade_res {
        Err(PersistenceError::Migration(sqlx::migrate::MigrateError::ExecuteMigration(
            db_err,
            version,
        ))) => {
            assert_eq!(version, 20260820000001);
            let msg = db_err.to_string();
            assert!(
                msg.contains("Ambiguous legacy data")
                    || msg.contains("rebuilt from corrected migration chain"),
                "Expected fail-closed error message, got: {msg}"
            );
        }
        other => panic!("Expected ExecuteMigration error, got: {other:?}"),
    }

    test_db.close().await.expect("Failed to drop test database");
}
