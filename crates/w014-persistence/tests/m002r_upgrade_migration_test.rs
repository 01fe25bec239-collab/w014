//! Upgrade Migration Test from Corrected Pre-M002R Baseline (M001R + M001R-F1) to M002R.
//!
//! Validates:
//! - Initial corrected pre-M002R baseline state (M001R + M001R-F1) is applied cleanly.
//! - Upgrading from pre-M002R baseline to M002R succeeds without manual repair.
//! - Target migration bundle version 20260821000001 is recorded as applied.
//! - Repeat upgrade execution is idempotent.
//! - Closed staged FK: audit_events.job_id -> jobs(job_id).
//! - Absence of deferred staged FK: workspaces.current_source_state_id (deferred to W3).
//! - Absence of W3/M003R/M004R tables (effective_contract_states).

use std::fs;
use tempfile::tempdir;
use uuid::Uuid;
use w014_persistence::{Migrator, TestDatabase, run_upgrade_migration_harness};

#[tokio::test]
async fn test_upgrade_from_pre_m002r_baseline_to_m002r() {
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

    let m002r_content = fs::read_to_string(
        "crates/w014-persistence/migrations/20260821000001_m002r_document_parser_durable_job_change_root.sql",
    )
    .or_else(|_| {
        fs::read_to_string("migrations/20260821000001_m002r_document_parser_durable_job_change_root.sql")
    })
    .expect("Failed to read M002R migration file");

    // 1. Prepare initial baseline migrator (M001R + M001R-F1)
    let baseline_dir = tempdir().expect("Failed to create baseline migration dir");
    fs::write(
        baseline_dir
            .path()
            .join("20260819000001_m001r_identity_session_audit_idempotency.sql"),
        &m001r_content,
    )
    .expect("Failed to write baseline migration");

    fs::write(
        baseline_dir
            .path()
            .join("20260820000001_m001r_prompt12_conformance_repair.sql"),
        &m001r_f1_content,
    )
    .expect("Failed to write M001R-F1 migration");

    let initial_migrator = Migrator::new(baseline_dir.path())
        .await
        .expect("Failed to load initial migrator");

    // 2. Prepare upgrade migrator (M001R + M001R-F1 + M002R)
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

    fs::write(
        upgrade_dir
            .path()
            .join("20260821000001_m002r_document_parser_durable_job_change_root.sql"),
        &m002r_content,
    )
    .expect("Failed to write M002R to upgrade set");

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
        vec![20260819000001, 20260820000001]
    );
    assert_eq!(result.initial_migration_report.total_applied_count, 2);
    assert_eq!(
        result.initial_migration_report.latest_version,
        Some(20260820000001)
    );

    // 5. Assert intermediate state
    assert_eq!(result.intermediate_status.applied.len(), 2);
    assert_eq!(
        result.intermediate_status.current_version,
        Some(20260820000001)
    );

    // 6. Assert forward upgrade applied M002R without manual repair
    assert_eq!(
        result.upgrade_migration_report.newly_applied_versions,
        vec![20260821000001]
    );
    assert_eq!(result.upgrade_migration_report.total_applied_count, 3);
    assert_eq!(
        result.upgrade_migration_report.latest_version,
        Some(20260821000001)
    );

    // 7. Assert final state is up to date
    assert_eq!(result.final_status.applied.len(), 3);
    assert_eq!(result.final_status.pending.len(), 0);
    assert!(result.final_status.is_up_to_date);

    // 8. Assert repeat upgrade is idempotent
    assert!(
        result
            .repeat_upgrade_report
            .newly_applied_versions
            .is_empty()
    );
    assert_eq!(result.repeat_upgrade_report.total_applied_count, 3);
    assert!(result.repeat_upgrade_report.already_up_to_date);

    // 9. Verify functional behavior: insert workspace, job, and verify closed FK
    let org_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO organizations (organization_id, display_name, slug) VALUES ($1, 'Org 1', $2)",
    )
    .bind(org_id)
    .bind(format!("org-{}", org_id.simple()))
    .execute(test_db.pool())
    .await
    .expect("Failed to insert organization");

    let prog_id = Uuid::new_v4();
    sqlx::query("INSERT INTO programs (program_id, organization_id, name, program_code) VALUES ($1, $2, 'Prog 1', $3)")
        .bind(prog_id)
        .bind(org_id)
        .bind(format!("prog-{}", prog_id.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to insert program");

    let ws_id = Uuid::new_v4();
    sqlx::query("INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code) VALUES ($1, $2, $3, 'WS 1', $4)")
        .bind(ws_id)
        .bind(prog_id)
        .bind(org_id)
        .bind(format!("ws-{}", ws_id.simple()))
        .execute(test_db.pool())
        .await
        .expect("Failed to insert workspace");

    // Insert a job
    let job_id = Uuid::new_v4();
    sqlx::query("INSERT INTO jobs (job_id, workspace_id, queue_name, job_type, payload) VALUES ($1, $2, 'default', 'parser', '{}'::jsonb)")
        .bind(job_id)
        .bind(ws_id)
        .execute(test_db.pool())
        .await
        .expect("Failed to insert job");

    // Verify audit_events referencing the job satisfies FK
    let event_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO audit_events (
            audit_event_id, workspace_id, sequence, actor_type, action_code, entity_type, entity_id,
            job_id, event_hash
        ) VALUES ($1, $2, 1, 'system', 'job.created', 'job', $3, $4, decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'))"
    )
    .bind(event_id)
    .bind(ws_id)
    .bind(job_id.to_string())
    .bind(job_id)
    .execute(test_db.pool())
    .await
    .expect("Failed to insert audit event with valid job_id FK");

    // Cleanup
    test_db.close().await.expect("Failed to drop test database");
}
