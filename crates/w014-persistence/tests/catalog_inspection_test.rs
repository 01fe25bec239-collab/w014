//! Direct PostgreSQL Catalog Inspection and Conformance Verification against real PostgreSQL 18.
//!
//! Validates:
//! - Exact Prompt-12 / Prompt-13 physical schema across ALL 13 M001R tables:
//!   1. organizations
//!   2. principals
//!   3. programs
//!   4. workspaces
//!   5. memberships
//!   6. capability_grants
//!   7. oidc_identities
//!   8. sessions
//!   9. session_rotations
//!   10. oidc_transactions
//!   11. audit_chain_heads
//!   12. audit_events
//!   13. idempotency_records
//! - Absence of W2 durable-job tables and document pipeline tables.
//! - Absence of deferred staged FK constraints (`workspaces.current_source_state_id`, `audit_events.job_id`).
//! - Verification of RLS enabled (`relrowsecurity`) and forced (`relforcerowsecurity`) states on tenant tables.
//! - Verification that global sessions table does NOT have RLS enabled.
//! - Verification of RLS policies in `pg_policy`.
//! - Verification of database roles and restricted privileges in `information_schema.table_privileges`.
//! - Verification of immutability triggers in `information_schema.triggers`.

use sqlx::Row;
use std::collections::HashMap;
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

    // 1. Verify exact 30 tables exist (13 M001R + 17 M002R)
    let expected_tables = vec![
        // M001R (13)
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
        // M002R (17)
        "documents",
        "document_versions",
        "document_version_metadata",
        "upload_intents",
        "object_artifacts",
        "quarantine_records",
        "parser_artifacts",
        "parser_pages",
        "parser_blocks",
        "source_spans",
        "jobs",
        "job_attempts",
        "job_dependencies",
        "job_progress",
        "dead_letter_entries",
        "dependency_keys",
        "change_events",
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

    // 2. Verify later-wave tables (W3/M003R/M004R) are strictly absent
    let forbidden_tables = vec!["effective_contract_states"];

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

        assert!(
            !exists,
            "Forbidden table '{table}' must NOT exist in W2 M002R"
        );
    }

    // 3. Verify Staged FK 1: workspaces.current_source_state_id FK is ABSENT (deferred to W3)
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
        "workspaces.current_source_state_id must NOT have a foreign key in W2"
    );

    // 4. Verify Staged FK 2: audit_events.job_id -> jobs FK is CLOSED and PRESENT in W2
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
        audit_job_fk_exists,
        "audit_events.job_id MUST have a foreign key to jobs table in W2"
    );

    // 5. Verify RLS enabled and forced on all 23 tenant tables
    let rls_tables = vec![
        "workspaces",
        "memberships",
        "capability_grants",
        "audit_chain_heads",
        "audit_events",
        "idempotency_records",
        "documents",
        "document_versions",
        "document_version_metadata",
        "upload_intents",
        "object_artifacts",
        "quarantine_records",
        "jobs",
        "job_attempts",
        "job_dependencies",
        "job_progress",
        "dead_letter_entries",
        "parser_artifacts",
        "parser_pages",
        "parser_blocks",
        "source_spans",
        "dependency_keys",
        "change_events",
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

    // Verify sessions does NOT have RLS enabled (Prompt-12)
    let sessions_rls = sqlx::query(
        "SELECT relrowsecurity, relforcerowsecurity
         FROM pg_class
         WHERE relname = 'sessions' AND relnamespace = 'public'::regnamespace",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to inspect sessions RLS flags");
    let sessions_rowsecurity: bool = sessions_rls.get("relrowsecurity");
    assert!(
        !sessions_rowsecurity,
        "Table 'sessions' must NOT have relrowsecurity enabled in Prompt-12"
    );

    // 6. Verify RLS policies exist in pg_policy for tenant tables
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

    let chain_heads_del_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT trigger_name)
         FROM information_schema.triggers
         WHERE event_object_table = 'audit_chain_heads'
           AND trigger_name = 'trg_prevent_audit_chain_heads_deletion'",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to check audit_chain_heads triggers");

    assert_eq!(
        chain_heads_del_count, 1,
        "audit_chain_heads must have trg_prevent_audit_chain_heads_deletion trigger"
    );

    let chain_heads_prog_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT trigger_name)
         FROM information_schema.triggers
         WHERE event_object_table = 'audit_chain_heads'
           AND trigger_name = 'trg_enforce_audit_chain_heads_progression'",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to check audit_chain_heads progression trigger");

    assert_eq!(
        chain_heads_prog_count, 1,
        "audit_chain_heads must have trg_enforce_audit_chain_heads_progression trigger"
    );

    // 8. Verify database roles exist and have NO BYPASSRLS privilege
    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT rolname FROM pg_roles WHERE rolname IN ('w014_app', 'w014_worker', 'audit_append', 'ops_readonly')",
    )
    .fetch_all(test_db.pool())
    .await
    .expect("Failed to query pg_roles");

    assert!(
        roles.contains(&"w014_app".to_string()),
        "Role 'w014_app' must exist"
    );
    assert!(
        roles.contains(&"w014_worker".to_string()),
        "Role 'w014_worker' must exist"
    );
    assert!(
        roles.contains(&"audit_append".to_string()),
        "Role 'audit_append' must exist"
    );
    assert!(
        roles.contains(&"ops_readonly".to_string()),
        "Role 'ops_readonly' must exist"
    );

    // Verify roles do NOT have BYPASSRLS
    let bypass_roles: Vec<String> = sqlx::query_scalar(
        "SELECT rolname FROM pg_roles WHERE rolname IN ('w014_app', 'w014_worker', 'audit_append', 'ops_readonly') AND rolbypassrls = true",
    )
    .fetch_all(test_db.pool())
    .await
    .expect("Failed to query rolbypassrls");

    assert!(
        bypass_roles.is_empty(),
        "Roles must NOT have BYPASSRLS privilege, found: {bypass_roles:?}"
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

    // 10. Verify composite unique constraints and composite foreign keys
    let expected_constraints = vec![
        // M001R (8)
        ("programs", "uq_programs_id_org"),
        ("workspaces", "uq_workspaces_id_org"),
        ("workspaces", "fk_workspaces_program_org"),
        ("memberships", "uq_memberships_id_workspace"),
        ("capability_grants", "uq_capability_grants_id_workspace"),
        ("audit_events", "uq_audit_events_id_workspace"),
        ("idempotency_records", "uq_idempotency_records_id_workspace"),
        ("idempotency_records", "uq_idempotency_records_identity"),
        // M002R (20)
        ("documents", "uq_documents_id_workspace"),
        ("document_versions", "uq_document_versions_id_workspace"),
        (
            "document_versions",
            "fk_document_versions_document_workspace",
        ),
        (
            "document_version_metadata",
            "uq_doc_ver_metadata_id_workspace",
        ),
        (
            "document_version_metadata",
            "fk_doc_ver_metadata_ver_workspace",
        ),
        ("upload_intents", "fk_upload_intents_document_ws"),
        ("upload_intents", "fk_upload_intents_artifact_ws"),
        ("upload_intents", "uq_upload_intents_opaque_object_key"),
        ("upload_intents", "uq_upload_intents_id_workspace"),
        ("object_artifacts", "uq_object_artifacts_object_key"),
        ("object_artifacts", "uq_object_artifacts_id_workspace"),
        ("quarantine_records", "fk_quarantine_records_intent_ws"),
        ("quarantine_records", "uq_quarantine_records_upload_intent"),
        ("quarantine_records", "uq_quarantine_records_id_workspace"),
        ("document_versions", "fk_document_versions_artifact_ws"),
        ("jobs", "uq_jobs_id_workspace"),
        ("jobs", "uq_jobs_idempotency_key"),
        ("job_attempts", "uq_job_attempts_job_attempt"),
        ("job_dependencies", "uq_job_dependencies_pair"),
        ("job_progress", "uq_job_progress_job_sequence"),
        ("dead_letter_entries", "uq_dead_letter_job"),
        ("parser_artifacts", "uq_parser_artifacts_id_workspace"),
        ("parser_artifacts", "fk_parser_artifacts_doc_version_ws"),
        ("parser_pages", "uq_parser_pages_id_workspace"),
        ("parser_pages", "fk_parser_pages_artifact_workspace"),
        ("parser_blocks", "uq_parser_blocks_id_workspace"),
        ("parser_blocks", "fk_parser_blocks_page_workspace"),
        ("source_spans", "uq_source_spans_id_workspace"),
        ("source_spans", "fk_source_spans_block_workspace"),
        // M002R document physical contract repair
        ("documents", "fk_documents_current_version_workspace"),
        ("parser_artifacts", "fk_parser_artifacts_artifact_ws"),
        ("dependency_keys", "uq_dependency_keys_id_workspace"),
        ("dependency_keys", "uq_dependency_keys_workspace_hash"),
        ("change_events", "uq_change_events_id_workspace"),
        ("audit_events", "fk_audit_events_job"),
    ];

    for (table, constraint) in expected_constraints {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1
                FROM information_schema.table_constraints
                WHERE table_schema = 'public'
                  AND table_name = $1
                  AND constraint_name = $2
            )",
        )
        .bind(table)
        .bind(constraint)
        .fetch_one(test_db.pool())
        .await
        .unwrap_or_else(|e| {
            panic!("Failed to inspect constraint '{constraint}' on '{table}': {e}")
        });

        assert!(
            exists,
            "Constraint '{constraint}' on table '{table}' must exist in PostgreSQL catalog"
        );
    }

    test_db.close().await.expect("Failed to drop test database");
}

async fn get_table_columns(
    pool: &sqlx::PgPool,
    table: &'static str,
) -> HashMap<String, (String, String)> {
    let cols: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT column_name, data_type, is_nullable
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = $1
         ORDER BY ordinal_position",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .expect("Failed to query columns");

    let map: HashMap<String, (String, String)> = cols
        .into_iter()
        .map(|(name, dt, nullable)| (name, (dt, nullable)))
        .collect();
    map
}

#[tokio::test]
async fn test_exact_13_table_physical_prompt12_conformance() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");

    let pool = test_db.pool();

    // 1. organizations
    let org_cols = get_table_columns(pool, "organizations").await;
    assert!(
        org_cols.contains_key("organization_id"),
        "organizations.organization_id must exist"
    );
    assert!(
        org_cols.contains_key("slug"),
        "organizations.slug must exist"
    );
    assert!(
        org_cols.contains_key("display_name"),
        "organizations.display_name must exist"
    );
    assert!(
        org_cols.contains_key("created_at"),
        "organizations.created_at must exist"
    );
    assert!(
        !org_cols.contains_key("id"),
        "legacy 'id' must not exist in organizations"
    );
    assert!(
        !org_cols.contains_key("name"),
        "legacy 'name' must not exist in organizations"
    );
    assert!(
        !org_cols.contains_key("updated_at"),
        "legacy 'updated_at' must not exist in organizations"
    );

    // 2. principals
    let prin_cols = get_table_columns(pool, "principals").await;
    assert!(
        prin_cols.contains_key("principal_id"),
        "principals.principal_id must exist"
    );
    assert!(
        prin_cols.contains_key("display_name"),
        "principals.display_name must exist"
    );
    assert!(
        prin_cols.contains_key("email"),
        "principals.email must exist"
    );
    assert!(
        prin_cols.contains_key("status"),
        "principals.status must exist"
    );
    assert!(
        prin_cols.contains_key("created_at"),
        "principals.created_at must exist"
    );
    assert!(
        !prin_cols.contains_key("id"),
        "legacy 'id' must not exist in principals"
    );
    assert!(
        !prin_cols.contains_key("organization_id"),
        "legacy 'organization_id' must not exist in principals"
    );
    assert!(
        !prin_cols.contains_key("principal_type"),
        "legacy 'principal_type' must not exist in principals"
    );
    assert!(
        !prin_cols.contains_key("is_active"),
        "legacy 'is_active' must not exist in principals"
    );
    assert!(
        !prin_cols.contains_key("updated_at"),
        "legacy 'updated_at' must not exist in principals"
    );

    // 3. programs
    let prog_cols = get_table_columns(pool, "programs").await;
    assert!(
        prog_cols.contains_key("program_id"),
        "programs.program_id must exist"
    );
    assert!(
        prog_cols.contains_key("organization_id"),
        "programs.organization_id must exist"
    );
    assert!(
        prog_cols.contains_key("program_code"),
        "programs.program_code must exist"
    );
    assert!(prog_cols.contains_key("name"), "programs.name must exist");
    assert!(
        prog_cols.contains_key("row_version"),
        "programs.row_version must exist"
    );
    assert!(
        prog_cols.contains_key("created_at"),
        "programs.created_at must exist"
    );
    assert!(
        !prog_cols.contains_key("id"),
        "legacy 'id' must not exist in programs"
    );
    assert!(
        !prog_cols.contains_key("slug"),
        "legacy 'slug' must not exist in programs"
    );
    assert!(
        !prog_cols.contains_key("description"),
        "legacy 'description' must not exist in programs"
    );

    // 4. workspaces
    let ws_cols = get_table_columns(pool, "workspaces").await;
    assert!(
        ws_cols.contains_key("workspace_id"),
        "workspaces.workspace_id must exist"
    );
    assert!(
        ws_cols.contains_key("organization_id"),
        "workspaces.organization_id must exist"
    );
    assert!(
        ws_cols.contains_key("program_id"),
        "workspaces.program_id must exist"
    );
    assert!(
        ws_cols.contains_key("workspace_code"),
        "workspaces.workspace_code must exist"
    );
    assert!(ws_cols.contains_key("name"), "workspaces.name must exist");
    assert!(
        ws_cols.contains_key("current_source_state_id"),
        "workspaces.current_source_state_id must exist"
    );
    assert_eq!(
        ws_cols["current_source_state_id"].1, "YES",
        "current_source_state_id must be nullable"
    );
    assert!(
        ws_cols.contains_key("row_version"),
        "workspaces.row_version must exist"
    );
    assert!(
        ws_cols.contains_key("created_at"),
        "workspaces.created_at must exist"
    );
    assert!(
        !ws_cols.contains_key("id"),
        "legacy 'id' must not exist in workspaces"
    );
    assert!(
        !ws_cols.contains_key("slug"),
        "legacy 'slug' must not exist in workspaces"
    );

    // 5. memberships
    let mem_cols = get_table_columns(pool, "memberships").await;
    assert!(
        mem_cols.contains_key("membership_id"),
        "memberships.membership_id must exist"
    );
    assert!(
        mem_cols.contains_key("workspace_id"),
        "memberships.workspace_id must exist"
    );
    assert!(
        mem_cols.contains_key("principal_id"),
        "memberships.principal_id must exist"
    );
    assert!(
        mem_cols.contains_key("role_code"),
        "memberships.role_code must exist"
    );
    assert!(
        mem_cols.contains_key("status"),
        "memberships.status must exist"
    );
    assert!(
        mem_cols.contains_key("valid_from"),
        "memberships.valid_from must exist"
    );
    assert!(
        mem_cols.contains_key("valid_until"),
        "memberships.valid_until must exist"
    );
    assert_eq!(
        mem_cols["valid_until"].1, "YES",
        "valid_until must be nullable"
    );
    assert!(
        mem_cols.contains_key("row_version"),
        "memberships.row_version must exist"
    );
    assert!(
        mem_cols.contains_key("created_at"),
        "memberships.created_at must exist"
    );
    assert!(
        !mem_cols.contains_key("role"),
        "legacy 'role' must not exist in memberships"
    );

    // 6. capability_grants
    let cap_cols = get_table_columns(pool, "capability_grants").await;
    assert!(
        cap_cols.contains_key("capability_grant_id"),
        "capability_grants.capability_grant_id must exist"
    );
    assert!(
        cap_cols.contains_key("workspace_id"),
        "capability_grants.workspace_id must exist"
    );
    assert_eq!(
        cap_cols["workspace_id"].1, "YES",
        "capability_grants.workspace_id must be nullable"
    );
    assert!(
        cap_cols.contains_key("program_id"),
        "capability_grants.program_id must exist"
    );
    assert_eq!(
        cap_cols["program_id"].1, "YES",
        "capability_grants.program_id must be nullable"
    );
    assert!(
        cap_cols.contains_key("principal_id"),
        "capability_grants.principal_id must exist"
    );
    assert!(
        cap_cols.contains_key("capability_code"),
        "capability_grants.capability_code must exist"
    );
    assert!(
        cap_cols.contains_key("granted_by_principal_id"),
        "capability_grants.granted_by_principal_id must exist"
    );
    assert!(
        cap_cols.contains_key("granted_at"),
        "capability_grants.granted_at must exist"
    );
    assert!(
        cap_cols.contains_key("expires_at"),
        "capability_grants.expires_at must exist"
    );
    assert!(
        cap_cols.contains_key("revoked_at"),
        "capability_grants.revoked_at must exist"
    );
    assert!(
        cap_cols.contains_key("revoked_by_principal_id"),
        "capability_grants.revoked_by_principal_id must exist"
    );
    assert!(
        cap_cols.contains_key("grant_reason"),
        "capability_grants.grant_reason must exist"
    );
    assert!(
        !cap_cols.contains_key("capability"),
        "legacy 'capability' must not exist in capability_grants"
    );
    assert!(
        !cap_cols.contains_key("granted_by"),
        "legacy 'granted_by' must not exist in capability_grants"
    );

    // 7. oidc_identities
    let oidc_id_cols = get_table_columns(pool, "oidc_identities").await;
    assert!(
        oidc_id_cols.contains_key("oidc_identity_id"),
        "oidc_identities.oidc_identity_id must exist"
    );
    assert!(
        oidc_id_cols.contains_key("principal_id"),
        "oidc_identities.principal_id must exist"
    );
    assert!(
        oidc_id_cols.contains_key("issuer"),
        "oidc_identities.issuer must exist"
    );
    assert!(
        oidc_id_cols.contains_key("subject"),
        "oidc_identities.subject must exist"
    );
    assert!(
        oidc_id_cols.contains_key("email_at_link"),
        "oidc_identities.email_at_link must exist"
    );
    assert!(
        oidc_id_cols.contains_key("linked_at"),
        "oidc_identities.linked_at must exist"
    );
    assert!(
        oidc_id_cols.contains_key("last_login_at"),
        "oidc_identities.last_login_at must exist"
    );
    assert!(
        !oidc_id_cols.contains_key("claims"),
        "legacy 'claims' must not exist in oidc_identities"
    );

    // 8. sessions
    let sess_cols = get_table_columns(pool, "sessions").await;
    assert!(
        sess_cols.contains_key("session_id"),
        "sessions.session_id must exist"
    );
    assert!(
        sess_cols.contains_key("principal_id"),
        "sessions.principal_id must exist"
    );
    assert!(
        sess_cols.contains_key("handle_hash"),
        "sessions.handle_hash must exist"
    );
    assert_eq!(sess_cols["handle_hash"].0, "bytea");
    assert!(
        sess_cols.contains_key("csrf_secret_hash"),
        "sessions.csrf_secret_hash must exist"
    );
    assert_eq!(sess_cols["csrf_secret_hash"].0, "bytea");
    assert!(
        sess_cols.contains_key("created_at"),
        "sessions.created_at must exist"
    );
    assert!(
        sess_cols.contains_key("last_seen_at"),
        "sessions.last_seen_at must exist"
    );
    assert!(
        sess_cols.contains_key("idle_expires_at"),
        "sessions.idle_expires_at must exist"
    );
    assert!(
        sess_cols.contains_key("absolute_expires_at"),
        "sessions.absolute_expires_at must exist"
    );
    assert!(
        sess_cols.contains_key("revoked_at"),
        "sessions.revoked_at must exist"
    );
    assert!(
        sess_cols.contains_key("rotation_counter"),
        "sessions.rotation_counter must exist"
    );

    // 9. session_rotations
    let rot_cols = get_table_columns(pool, "session_rotations").await;
    assert!(
        rot_cols.contains_key("session_rotation_id"),
        "session_rotations.session_rotation_id must exist"
    );
    assert!(
        rot_cols.contains_key("session_id"),
        "session_rotations.session_id must exist"
    );
    assert!(
        rot_cols.contains_key("rotation_number"),
        "session_rotations.rotation_number must exist"
    );
    assert!(
        rot_cols.contains_key("old_handle_hash"),
        "session_rotations.old_handle_hash must exist"
    );
    assert_eq!(rot_cols["old_handle_hash"].0, "bytea");
    assert!(
        rot_cols.contains_key("new_handle_hash"),
        "session_rotations.new_handle_hash must exist"
    );
    assert_eq!(rot_cols["new_handle_hash"].0, "bytea");
    assert!(
        rot_cols.contains_key("reason"),
        "session_rotations.reason must exist"
    );
    assert!(
        rot_cols.contains_key("rotated_at"),
        "session_rotations.rotated_at must exist"
    );
    assert!(
        !rot_cols.contains_key("ip_address"),
        "legacy 'ip_address' must not exist in session_rotations"
    );

    // 10. oidc_transactions
    let tx_cols = get_table_columns(pool, "oidc_transactions").await;
    assert!(
        tx_cols.contains_key("oidc_transaction_id"),
        "oidc_transactions.oidc_transaction_id must exist"
    );
    assert!(
        tx_cols.contains_key("state_hash"),
        "oidc_transactions.state_hash must exist"
    );
    assert_eq!(tx_cols["state_hash"].0, "bytea");
    assert!(
        tx_cols.contains_key("nonce_hash"),
        "oidc_transactions.nonce_hash must exist"
    );
    assert_eq!(tx_cols["nonce_hash"].0, "bytea");
    assert!(
        tx_cols.contains_key("pkce_verifier_ciphertext"),
        "oidc_transactions.pkce_verifier_ciphertext must exist"
    );
    assert_eq!(tx_cols["pkce_verifier_ciphertext"].0, "bytea");
    assert!(
        tx_cols.contains_key("return_path"),
        "oidc_transactions.return_path must exist"
    );
    assert!(
        tx_cols.contains_key("created_at"),
        "oidc_transactions.created_at must exist"
    );
    assert!(
        tx_cols.contains_key("expires_at"),
        "oidc_transactions.expires_at must exist"
    );
    assert!(
        tx_cols.contains_key("consumed_at"),
        "oidc_transactions.consumed_at must exist"
    );
    assert!(
        !tx_cols.contains_key("state_token"),
        "legacy 'state_token' must not exist in oidc_transactions"
    );
    assert!(
        !tx_cols.contains_key("nonce"),
        "legacy 'nonce' must not exist in oidc_transactions"
    );
    assert!(
        !tx_cols.contains_key("pkce_verifier"),
        "legacy 'pkce_verifier' must not exist in oidc_transactions"
    );

    // 11. audit_chain_heads
    let head_cols = get_table_columns(pool, "audit_chain_heads").await;
    assert!(
        head_cols.contains_key("workspace_id"),
        "audit_chain_heads.workspace_id must exist"
    );
    assert!(
        head_cols.contains_key("last_sequence"),
        "audit_chain_heads.last_sequence must exist"
    );
    assert_eq!(head_cols["last_sequence"].0, "bigint");
    assert!(
        head_cols.contains_key("last_event_hash"),
        "audit_chain_heads.last_event_hash must exist"
    );
    assert_eq!(head_cols["last_event_hash"].0, "bytea");
    assert_eq!(
        head_cols["last_event_hash"].1, "YES",
        "last_event_hash must be nullable"
    );
    assert!(
        head_cols.contains_key("updated_at"),
        "audit_chain_heads.updated_at must exist"
    );
    assert!(
        !head_cols.contains_key("head_sequence_num"),
        "legacy 'head_sequence_num' must not exist"
    );
    assert!(
        !head_cols.contains_key("head_event_hash"),
        "legacy 'head_event_hash' must not exist"
    );
    assert!(
        !head_cols.contains_key("genesis_hash"),
        "legacy 'genesis_hash' must not exist"
    );

    // 12. audit_events
    let ev_cols = get_table_columns(pool, "audit_events").await;
    assert!(
        ev_cols.contains_key("audit_event_id"),
        "audit_events.audit_event_id must exist"
    );
    assert!(
        ev_cols.contains_key("workspace_id"),
        "audit_events.workspace_id must exist"
    );
    assert!(
        ev_cols.contains_key("sequence"),
        "audit_events.sequence must exist"
    );
    assert_eq!(ev_cols["sequence"].0, "bigint");
    assert!(
        ev_cols.contains_key("occurred_at"),
        "audit_events.occurred_at must exist"
    );
    assert!(
        ev_cols.contains_key("actor_type"),
        "audit_events.actor_type must exist"
    );
    assert!(
        ev_cols.contains_key("actor_id"),
        "audit_events.actor_id must exist"
    );
    assert!(
        ev_cols.contains_key("authority_snapshot"),
        "audit_events.authority_snapshot must exist"
    );
    assert!(
        ev_cols.contains_key("action_code"),
        "audit_events.action_code must exist"
    );
    assert!(
        ev_cols.contains_key("entity_type"),
        "audit_events.entity_type must exist"
    );
    assert!(
        ev_cols.contains_key("entity_id"),
        "audit_events.entity_id must exist"
    );
    assert!(
        ev_cols.contains_key("entity_version"),
        "audit_events.entity_version must exist"
    );
    assert!(
        ev_cols.contains_key("request_id"),
        "audit_events.request_id must exist"
    );
    assert!(
        ev_cols.contains_key("correlation_id"),
        "audit_events.correlation_id must exist"
    );
    assert!(
        ev_cols.contains_key("job_id"),
        "audit_events.job_id must exist"
    );
    assert!(
        ev_cols.contains_key("source_state_hash"),
        "audit_events.source_state_hash must exist"
    );
    assert_eq!(ev_cols["source_state_hash"].0, "bytea");
    assert!(
        ev_cols.contains_key("before_ref"),
        "audit_events.before_ref must exist"
    );
    assert!(
        ev_cols.contains_key("after_ref"),
        "audit_events.after_ref must exist"
    );
    assert!(
        ev_cols.contains_key("metadata"),
        "audit_events.metadata must exist"
    );
    assert!(
        ev_cols.contains_key("previous_event_hash"),
        "audit_events.previous_event_hash must exist"
    );
    assert_eq!(ev_cols["previous_event_hash"].0, "bytea");
    assert_eq!(
        ev_cols["previous_event_hash"].1, "YES",
        "previous_event_hash must be nullable"
    );
    assert!(
        ev_cols.contains_key("event_hash"),
        "audit_events.event_hash must exist"
    );
    assert_eq!(ev_cols["event_hash"].0, "bytea");
    assert!(
        !ev_cols.contains_key("sequence_num"),
        "legacy 'sequence_num' must not exist"
    );
    assert!(
        !ev_cols.contains_key("event_type"),
        "legacy 'event_type' must not exist"
    );
    assert!(
        !ev_cols.contains_key("payload"),
        "legacy 'payload' must not exist"
    );

    // 13. idempotency_records
    let idem_cols = get_table_columns(pool, "idempotency_records").await;
    assert!(
        idem_cols.contains_key("idempotency_record_id"),
        "idempotency_records.idempotency_record_id must exist"
    );
    assert!(
        idem_cols.contains_key("workspace_id"),
        "idempotency_records.workspace_id must exist"
    );
    assert_eq!(
        idem_cols["workspace_id"].1, "YES",
        "idempotency_records.workspace_id must be nullable"
    );
    assert!(
        idem_cols.contains_key("principal_id"),
        "idempotency_records.principal_id must exist"
    );
    assert!(
        idem_cols.contains_key("route_code"),
        "idempotency_records.route_code must exist"
    );
    assert!(
        idem_cols.contains_key("key_hash"),
        "idempotency_records.key_hash must exist"
    );
    assert_eq!(idem_cols["key_hash"].0, "bytea");
    assert!(
        idem_cols.contains_key("request_hash"),
        "idempotency_records.request_hash must exist"
    );
    assert_eq!(idem_cols["request_hash"].0, "bytea");
    assert!(
        idem_cols.contains_key("response_status"),
        "idempotency_records.response_status must exist"
    );
    assert!(
        idem_cols.contains_key("response_body"),
        "idempotency_records.response_body must exist"
    );
    assert!(
        idem_cols.contains_key("created_at"),
        "idempotency_records.created_at must exist"
    );
    assert!(
        idem_cols.contains_key("expires_at"),
        "idempotency_records.expires_at must exist"
    );
    assert!(
        !idem_cols.contains_key("idempotency_key"),
        "legacy plaintext 'idempotency_key' must NOT exist"
    );
    assert!(
        !idem_cols.contains_key("status"),
        "legacy 'status' string must NOT exist"
    );
    assert!(
        !idem_cols.contains_key("response_status_code"),
        "legacy 'response_status_code' must NOT exist"
    );

    test_db.close().await.expect("Failed to drop test database");
}

#[tokio::test]
async fn test_exact_17_table_m002r_physical_prompt12_conformance() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R + M002R migrations");

    let pool = test_db.pool();

    // 1. documents (repaired: deferred current-version pointer is a physical fact)
    let doc_cols = get_table_columns(pool, "documents").await;
    assert!(doc_cols.contains_key("document_id"));
    assert_eq!(doc_cols["document_id"].1, "NO");
    assert!(doc_cols.contains_key("workspace_id"));
    assert_eq!(doc_cols["workspace_id"].1, "NO");
    assert!(doc_cols.contains_key("title"));
    assert!(doc_cols.contains_key("document_type"));
    assert!(doc_cols.contains_key("status"));
    assert!(
        doc_cols.contains_key("current_version_id"),
        "documents.current_version_id must exist as the frozen deferred pointer"
    );
    assert_eq!(
        doc_cols["current_version_id"].1, "YES",
        "documents.current_version_id must be nullable"
    );
    assert!(doc_cols.contains_key("created_by"));
    assert_eq!(doc_cols["created_by"].1, "YES");
    assert!(doc_cols.contains_key("created_at"));
    assert!(doc_cols.contains_key("updated_at"));
    assert!(doc_cols.contains_key("row_version"));

    // 2. document_versions (repaired: object binding + original filename are physical facts)
    let ver_cols = get_table_columns(pool, "document_versions").await;
    assert!(ver_cols.contains_key("document_version_id"));
    assert!(ver_cols.contains_key("document_id"));
    assert!(ver_cols.contains_key("workspace_id"));
    assert!(ver_cols.contains_key("version_number"));
    assert!(
        ver_cols.contains_key("object_artifact_id"),
        "document_versions.object_artifact_id must be an explicit authoritative fact"
    );
    assert_eq!(
        ver_cols["object_artifact_id"].1, "NO",
        "document_versions.object_artifact_id must be NOT NULL (immutable binding)"
    );
    assert!(ver_cols.contains_key("byte_size"));
    assert!(ver_cols.contains_key("sha256_hash"));
    assert_eq!(ver_cols["sha256_hash"].0, "bytea");
    assert!(ver_cols.contains_key("content_type"));
    assert!(
        ver_cols.contains_key("original_filename"),
        "document_versions.original_filename must be an explicit physical fact, not hidden JSONB"
    );
    assert_eq!(ver_cols["original_filename"].1, "NO");
    assert!(ver_cols.contains_key("trust_state"));
    assert!(ver_cols.contains_key("submitted_by"));
    assert_eq!(ver_cols["submitted_by"].1, "YES");
    assert!(
        !ver_cols.contains_key("created_by"),
        "legacy 'created_by' must not remain in document_versions (frozen name: submitted_by)"
    );
    assert!(ver_cols.contains_key("created_at"));

    // 3. document_version_metadata
    let meta_cols = get_table_columns(pool, "document_version_metadata").await;
    assert!(meta_cols.contains_key("document_version_metadata_id"));
    assert!(meta_cols.contains_key("document_version_id"));
    assert!(meta_cols.contains_key("workspace_id"));
    assert!(meta_cols.contains_key("metadata"));
    assert_eq!(meta_cols["metadata"].0, "jsonb");
    assert!(meta_cols.contains_key("custom_fields"));
    assert_eq!(meta_cols["custom_fields"].0, "jsonb");
    assert!(meta_cols.contains_key("extracted_author"));
    assert_eq!(meta_cols["extracted_author"].1, "YES");
    assert!(meta_cols.contains_key("extracted_title"));
    assert_eq!(meta_cols["extracted_title"].1, "YES");
    assert!(meta_cols.contains_key("page_count"));
    assert_eq!(meta_cols["page_count"].1, "YES");
    assert!(meta_cols.contains_key("word_count"));
    assert_eq!(meta_cols["word_count"].1, "YES");

    // 4. upload_intents (repaired: exact frozen Prompt-12 declaration facts)
    let upload_cols = get_table_columns(pool, "upload_intents").await;
    assert!(upload_cols.contains_key("upload_intent_id"));
    assert!(upload_cols.contains_key("workspace_id"));
    assert!(upload_cols.contains_key("created_by"));
    assert_eq!(upload_cols["created_by"].1, "NO");
    assert!(upload_cols.contains_key("document_id"));
    assert_eq!(upload_cols["document_id"].1, "YES");
    assert!(upload_cols.contains_key("filename"));
    assert!(
        upload_cols.contains_key("expected_media_type"),
        "upload_intents.expected_media_type must be an explicit authoritative fact"
    );
    assert!(
        upload_cols.contains_key("expected_length"),
        "upload_intents.expected_length must be an explicit authoritative fact"
    );
    assert!(
        upload_cols.contains_key("expected_sha256_b64"),
        "upload_intents.expected_sha256_b64 must be an explicit physical declaration column"
    );
    assert_eq!(
        upload_cols["expected_sha256_b64"].1, "YES",
        "expected_sha256_b64 must be nullable (declaration is optional)"
    );
    assert!(upload_cols.contains_key("object_artifact_id"));
    assert_eq!(upload_cols["object_artifact_id"].1, "YES");
    assert!(
        upload_cols.contains_key("opaque_object_key"),
        "upload_intents.opaque_object_key must be the server-generated authority column"
    );
    assert!(upload_cols.contains_key("status"));
    assert!(upload_cols.contains_key("expires_at"));
    assert!(upload_cols.contains_key("finalized_at"));
    assert_eq!(upload_cols["finalized_at"].1, "YES");
    assert!(upload_cols.contains_key("abandoned_at"));
    assert_eq!(upload_cols["abandoned_at"].1, "YES");
    assert!(upload_cols.contains_key("created_at"));
    // Defective substitutes must NOT remain.
    assert!(
        !upload_cols.contains_key("principal_id"),
        "defective 'principal_id' must not remain in upload_intents (frozen name: created_by)"
    );
    assert!(
        !upload_cols.contains_key("content_type"),
        "defective 'content_type' must not remain in upload_intents (frozen name: expected_media_type)"
    );
    assert!(
        !upload_cols.contains_key("expected_size_bytes"),
        "defective 'expected_size_bytes' must not remain in upload_intents (frozen name: expected_length)"
    );
    assert!(
        !upload_cols.contains_key("storage_key"),
        "defective 'storage_key' must not remain in upload_intents (frozen name: opaque_object_key)"
    );
    assert!(
        !upload_cols.contains_key("completed_at"),
        "defective 'completed_at' must not remain in upload_intents (frozen markers: finalized_at/abandoned_at)"
    );

    // 5. object_artifacts (repaired: exact frozen Prompt-12 object facts)
    let obj_cols = get_table_columns(pool, "object_artifacts").await;
    assert!(obj_cols.contains_key("object_artifact_id"));
    assert!(obj_cols.contains_key("workspace_id"));
    assert!(
        obj_cols.contains_key("artifact_kind"),
        "object_artifacts.artifact_kind must be an explicit closed-domain fact"
    );
    assert!(
        obj_cols.contains_key("object_key"),
        "object_artifacts.object_key must be the server-owned authority column"
    );
    assert!(
        obj_cols.contains_key("byte_length"),
        "object_artifacts.byte_length must be an explicit frozen fact"
    );
    assert!(obj_cols.contains_key("content_sha256"));
    assert_eq!(obj_cols["content_sha256"].0, "bytea");
    assert!(
        obj_cols.contains_key("media_type"),
        "object_artifacts.media_type must be the explicit frozen column"
    );
    assert!(
        obj_cols.contains_key("sse_mode"),
        "object_artifacts.sse_mode must be an explicit encryption-posture fact"
    );
    assert!(obj_cols.contains_key("kms_key_ref"));
    assert_eq!(obj_cols["kms_key_ref"].1, "YES");
    assert!(
        obj_cols.contains_key("retention_until"),
        "object_artifacts.retention_until must be an explicit nullable timestamptz column"
    );
    assert_eq!(obj_cols["retention_until"].1, "YES");
    assert!(obj_cols.contains_key("created_at"));
    // Defective substitutes must NOT remain.
    assert!(
        !obj_cols.contains_key("storage_bucket"),
        "defective 'storage_bucket' must not remain in object_artifacts"
    );
    assert!(
        !obj_cols.contains_key("storage_tier"),
        "defective 'storage_tier' must not remain in object_artifacts"
    );
    assert!(
        !obj_cols.contains_key("content_type"),
        "defective 'content_type' must not remain in object_artifacts (frozen name: media_type)"
    );
    assert!(
        !obj_cols.contains_key("storage_key"),
        "defective 'storage_key' must not remain in object_artifacts (frozen name: object_key)"
    );
    assert!(
        !obj_cols.contains_key("byte_size"),
        "defective 'byte_size' must not remain in object_artifacts (frozen name: byte_length)"
    );
    assert!(
        !obj_cols.contains_key("sha256_hash"),
        "defective 'sha256_hash' must not remain in object_artifacts (frozen name: content_sha256)"
    );

    // 6. quarantine_records (repaired: intent tie + frozen outcome domain are physical)
    let qr_cols = get_table_columns(pool, "quarantine_records").await;
    assert!(qr_cols.contains_key("quarantine_record_id"));
    assert!(qr_cols.contains_key("workspace_id"));
    assert!(
        qr_cols.contains_key("upload_intent_id"),
        "quarantine_records.upload_intent_id must be a physical tie to the scanned bytes"
    );
    assert_eq!(
        qr_cols["upload_intent_id"].1, "NO",
        "quarantine_records.upload_intent_id must be NOT NULL"
    );
    assert!(
        qr_cols.contains_key("scanner_version"),
        "quarantine_records.scanner_version must be an explicit frozen column"
    );
    assert_eq!(
        qr_cols["scanner_version"].1, "NO",
        "quarantine_records.scanner_version must be NOT NULL"
    );
    assert!(
        qr_cols.contains_key("reason_code"),
        "quarantine_records.reason_code must be the explicit frozen reason column"
    );
    assert_eq!(qr_cols["reason_code"].1, "YES");
    assert!(qr_cols.contains_key("status"));
    assert!(qr_cols.contains_key("checked_at"));
    // Defective / non-frozen substitutes must NOT remain.
    assert!(
        !qr_cols.contains_key("document_version_id"),
        "non-frozen 'document_version_id' must not remain in quarantine_records"
    );
    assert!(
        !qr_cols.contains_key("object_artifact_id"),
        "non-frozen 'object_artifact_id' must not remain in quarantine_records"
    );
    assert!(
        !qr_cols.contains_key("scanner_name"),
        "non-frozen 'scanner_name' must not remain in quarantine_records"
    );
    assert!(
        !qr_cols.contains_key("threat_details"),
        "non-frozen 'threat_details' must not remain in quarantine_records"
    );
    assert!(
        !qr_cols.contains_key("quarantine_reason"),
        "defective 'quarantine_reason' must not remain in quarantine_records (frozen name: reason_code)"
    );
    assert!(
        !qr_cols.contains_key("quarantined_at"),
        "defective 'quarantined_at' must not remain in quarantine_records (frozen name: checked_at)"
    );
    assert!(
        !qr_cols.contains_key("reviewed_at"),
        "non-frozen 'reviewed_at' lifecycle projection must not remain in quarantine_records"
    );
    assert!(
        !qr_cols.contains_key("reviewed_by"),
        "non-frozen 'reviewed_by' lifecycle projection must not remain in quarantine_records"
    );
    assert!(
        !qr_cols.contains_key("review_decision"),
        "non-frozen 'review_decision' lifecycle projection must not remain in quarantine_records"
    );

    // 7. jobs
    let job_cols = get_table_columns(pool, "jobs").await;
    assert!(job_cols.contains_key("job_id"));
    assert!(job_cols.contains_key("workspace_id"));
    assert!(job_cols.contains_key("queue_name"));
    assert!(job_cols.contains_key("job_type"));
    assert!(job_cols.contains_key("status"));
    assert!(job_cols.contains_key("priority"));
    assert!(job_cols.contains_key("payload"));
    assert_eq!(job_cols["payload"].0, "jsonb");
    assert!(job_cols.contains_key("result"));
    assert_eq!(job_cols["result"].1, "YES");
    assert!(job_cols.contains_key("error_details"));
    assert_eq!(job_cols["error_details"].1, "YES");
    assert!(job_cols.contains_key("idempotency_key"));
    assert_eq!(job_cols["idempotency_key"].1, "YES");
    assert!(job_cols.contains_key("correlation_id"));
    assert_eq!(job_cols["correlation_id"].1, "YES");
    assert!(
        job_cols.contains_key("cancellation_requested"),
        "jobs.cancellation_requested must exist for frozen claim predicate"
    );
    assert!(job_cols.contains_key("lease_holder"));
    assert_eq!(job_cols["lease_holder"].1, "YES");
    assert!(job_cols.contains_key("lease_token"));
    assert_eq!(job_cols["lease_token"].1, "YES");
    assert!(job_cols.contains_key("lease_generation"));
    assert!(job_cols.contains_key("lease_expires_at"));
    assert_eq!(job_cols["lease_expires_at"].1, "YES");
    assert!(job_cols.contains_key("last_heartbeat_at"));
    assert_eq!(job_cols["last_heartbeat_at"].1, "YES");
    assert!(job_cols.contains_key("attempt_count"));
    assert!(job_cols.contains_key("max_attempts"));
    assert!(job_cols.contains_key("backoff_base_secs"));
    assert!(job_cols.contains_key("backoff_max_secs"));
    assert!(
        job_cols.contains_key("not_before"),
        "jobs.not_before must exist for frozen claim predicate"
    );
    assert!(
        !job_cols.contains_key("next_run_at"),
        "defective 'next_run_at' must not remain in jobs"
    );
    assert!(job_cols.contains_key("created_at"));
    assert!(job_cols.contains_key("started_at"));
    assert_eq!(job_cols["started_at"].1, "YES");
    assert!(job_cols.contains_key("completed_at"));
    assert_eq!(job_cols["completed_at"].1, "YES");
    assert!(job_cols.contains_key("row_version"));

    // 8. job_attempts (exact frozen Prompt-12 columns)
    let att_cols = get_table_columns(pool, "job_attempts").await;
    assert!(att_cols.contains_key("job_attempt_id"));
    assert!(att_cols.contains_key("job_id"));
    assert!(att_cols.contains_key("attempt_number"));
    assert!(att_cols.contains_key("worker_id"));
    assert!(att_cols.contains_key("started_at"));
    assert!(att_cols.contains_key("completed_at"));
    assert_eq!(att_cols["completed_at"].1, "YES");
    assert!(att_cols.contains_key("outcome"));
    assert!(att_cols.contains_key("error_code"));
    assert_eq!(att_cols["error_code"].1, "YES");
    assert!(att_cols.contains_key("error_detail_redacted"));
    assert_eq!(att_cols["error_detail_redacted"].1, "YES");
    // Defective 0201-A substitutions must NOT remain.
    assert!(
        !att_cols.contains_key("workspace_id"),
        "defective 'workspace_id' must not remain in job_attempts"
    );
    assert!(
        !att_cols.contains_key("lease_token"),
        "defective 'lease_token' must not remain in job_attempts"
    );
    assert!(
        !att_cols.contains_key("status"),
        "defective 'status' must not remain in job_attempts"
    );
    assert!(
        !att_cols.contains_key("heartbeat_at"),
        "defective 'heartbeat_at' must not remain in job_attempts"
    );
    assert!(
        !att_cols.contains_key("finished_at"),
        "defective 'finished_at' must not remain in job_attempts"
    );
    assert!(
        !att_cols.contains_key("error_message"),
        "defective 'error_message' must not remain in job_attempts"
    );
    assert!(
        !att_cols.contains_key("error_details"),
        "defective 'error_details' must not remain in job_attempts"
    );
    assert!(
        !att_cols.contains_key("metadata"),
        "defective 'metadata' must not remain in job_attempts"
    );

    // 9. job_dependencies
    let dep_cols = get_table_columns(pool, "job_dependencies").await;
    assert!(dep_cols.contains_key("job_dependency_id"));
    assert!(dep_cols.contains_key("job_id"));
    assert!(dep_cols.contains_key("depends_on_job_id"));
    assert!(dep_cols.contains_key("created_at"));
    assert!(
        !dep_cols.contains_key("workspace_id"),
        "defective 'workspace_id' must not remain in job_dependencies"
    );

    // 10. job_progress (exact frozen Prompt-12 sequence-event columns)
    let prog_cols = get_table_columns(pool, "job_progress").await;
    assert!(prog_cols.contains_key("job_progress_id"));
    assert!(prog_cols.contains_key("job_id"));
    assert!(prog_cols.contains_key("sequence"));
    assert!(prog_cols.contains_key("stage_code"));
    assert!(prog_cols.contains_key("current"));
    assert!(prog_cols.contains_key("total"));
    assert_eq!(prog_cols["total"].1, "YES");
    assert!(prog_cols.contains_key("message_code"));
    assert_eq!(prog_cols["message_code"].1, "YES");
    assert!(prog_cols.contains_key("created_at"));
    // Defective mutable-current-row representation must NOT remain.
    assert!(
        !prog_cols.contains_key("stage"),
        "defective 'stage' must not remain in job_progress"
    );
    assert!(
        !prog_cols.contains_key("progress_pct"),
        "defective 'progress_pct' must not remain in job_progress"
    );
    assert!(
        !prog_cols.contains_key("message"),
        "defective 'message' must not remain in job_progress"
    );
    assert!(
        !prog_cols.contains_key("details"),
        "defective 'details' must not remain in job_progress"
    );
    assert!(
        !prog_cols.contains_key("updated_at"),
        "defective 'updated_at' must not remain in job_progress"
    );
    assert!(
        !prog_cols.contains_key("workspace_id"),
        "defective 'workspace_id' must not remain in job_progress"
    );

    // 11. dead_letter_entries
    let dl_cols = get_table_columns(pool, "dead_letter_entries").await;
    assert!(dl_cols.contains_key("dead_letter_entry_id"));
    assert!(dl_cols.contains_key("job_id"));
    assert!(dl_cols.contains_key("queue_name"));
    assert!(dl_cols.contains_key("job_type"));
    assert!(dl_cols.contains_key("failed_at"));
    assert!(dl_cols.contains_key("attempt_count"));
    assert!(dl_cols.contains_key("failure_reason"));
    assert!(dl_cols.contains_key("error_details"));
    assert_eq!(dl_cols["error_details"].0, "jsonb");
    assert!(dl_cols.contains_key("payload"));
    assert_eq!(dl_cols["payload"].0, "jsonb");
    assert!(dl_cols.contains_key("resolved_at"));
    assert_eq!(dl_cols["resolved_at"].1, "YES");
    assert!(dl_cols.contains_key("resolved_by"));
    assert_eq!(dl_cols["resolved_by"].1, "YES");
    assert!(dl_cols.contains_key("resolution_notes"));
    assert_eq!(dl_cols["resolution_notes"].1, "YES");
    assert!(
        !dl_cols.contains_key("workspace_id"),
        "defective 'workspace_id' must not remain in dead_letter_entries"
    );

    // 12. parser_artifacts (repaired: locator identity + object/digest refs + exact lifecycle)
    let pa_cols = get_table_columns(pool, "parser_artifacts").await;
    assert!(pa_cols.contains_key("parser_artifact_id"));
    assert!(pa_cols.contains_key("document_version_id"));
    assert!(pa_cols.contains_key("workspace_id"));
    assert!(pa_cols.contains_key("job_id"));
    assert_eq!(pa_cols["job_id"].1, "YES");
    assert!(pa_cols.contains_key("parser_name"));
    assert!(pa_cols.contains_key("parser_version"));
    assert!(
        pa_cols.contains_key("locator_version"),
        "parser_artifacts.locator_version must be a REQUIRED physical identity column"
    );
    assert_eq!(pa_cols["locator_version"].1, "NO");
    assert!(pa_cols.contains_key("status"));
    assert!(pa_cols.contains_key("artifact_object_id"));
    assert_eq!(pa_cols["artifact_object_id"].1, "YES");
    assert!(pa_cols.contains_key("text_sha256"));
    assert_eq!(pa_cols["text_sha256"].1, "YES");
    assert!(pa_cols.contains_key("page_count"));
    assert!(pa_cols.contains_key("block_count"));
    assert!(pa_cols.contains_key("span_count"));
    assert!(pa_cols.contains_key("execution_duration_ms"));
    assert_eq!(pa_cols["execution_duration_ms"].1, "YES");
    assert!(
        pa_cols.contains_key("failure_code"),
        "parser_artifacts.failure_code must be the explicit frozen failure column"
    );
    assert_eq!(pa_cols["failure_code"].1, "YES");
    assert!(
        pa_cols.contains_key("started_at"),
        "parser_artifacts.started_at is the exact frozen Prompt-12 start timestamp"
    );
    assert!(pa_cols.contains_key("completed_at"));
    assert_eq!(pa_cols["completed_at"].1, "YES");
    // Defective substitutes must NOT remain.
    assert!(
        !pa_cols.contains_key("error_message"),
        "defective 'error_message' must not remain in parser_artifacts (frozen name: failure_code)"
    );
    assert!(
        !pa_cols.contains_key("created_at"),
        "defective 'created_at' must not remain in parser_artifacts (frozen name: started_at)"
    );

    // 13. parser_pages
    let pp_cols = get_table_columns(pool, "parser_pages").await;
    assert!(pp_cols.contains_key("parser_page_id"));
    assert!(pp_cols.contains_key("parser_artifact_id"));
    assert!(pp_cols.contains_key("workspace_id"));
    assert!(pp_cols.contains_key("page_number"));
    assert!(pp_cols.contains_key("width"));
    assert_eq!(pp_cols["width"].1, "YES");
    assert!(pp_cols.contains_key("height"));
    assert_eq!(pp_cols["height"].1, "YES");
    assert!(pp_cols.contains_key("rotation"));
    assert!(pp_cols.contains_key("text_content"));
    assert!(pp_cols.contains_key("metadata"));
    assert_eq!(pp_cols["metadata"].0, "jsonb");
    assert!(pp_cols.contains_key("created_at"));

    // 14. parser_blocks
    let pb_cols = get_table_columns(pool, "parser_blocks").await;
    assert!(pb_cols.contains_key("parser_block_id"));
    assert!(pb_cols.contains_key("parser_page_id"));
    assert!(pb_cols.contains_key("workspace_id"));
    assert!(pb_cols.contains_key("block_sequence"));
    assert!(pb_cols.contains_key("block_type"));
    assert!(pb_cols.contains_key("bounding_box"));
    assert_eq!(pb_cols["bounding_box"].1, "YES");
    assert!(pb_cols.contains_key("text_content"));
    assert!(pb_cols.contains_key("confidence"));
    assert_eq!(pb_cols["confidence"].1, "YES");
    assert!(pb_cols.contains_key("metadata"));
    assert_eq!(pb_cols["metadata"].0, "jsonb");
    assert!(pb_cols.contains_key("created_at"));

    // 15. source_spans
    let ss_cols = get_table_columns(pool, "source_spans").await;
    assert!(ss_cols.contains_key("source_span_id"));
    assert!(ss_cols.contains_key("parser_block_id"));
    assert!(ss_cols.contains_key("workspace_id"));
    assert!(ss_cols.contains_key("span_sequence"));
    assert!(ss_cols.contains_key("start_char"));
    assert!(ss_cols.contains_key("end_char"));
    assert!(ss_cols.contains_key("text_content"));
    assert!(ss_cols.contains_key("bounding_box"));
    assert_eq!(ss_cols["bounding_box"].1, "YES");
    assert!(ss_cols.contains_key("confidence"));
    assert_eq!(ss_cols["confidence"].1, "YES");
    assert!(ss_cols.contains_key("metadata"));
    assert_eq!(ss_cols["metadata"].0, "jsonb");
    assert!(ss_cols.contains_key("created_at"));

    // 16. dependency_keys
    let dk_cols = get_table_columns(pool, "dependency_keys").await;
    assert!(dk_cols.contains_key("dependency_key_id"));
    assert!(dk_cols.contains_key("workspace_id"));
    assert!(dk_cols.contains_key("key_type"));
    assert!(dk_cols.contains_key("key_value"));
    assert!(dk_cols.contains_key("key_hash"));
    assert_eq!(dk_cols["key_hash"].0, "bytea");
    assert!(dk_cols.contains_key("created_at"));

    // 17. change_events
    let ce_cols = get_table_columns(pool, "change_events").await;
    assert!(ce_cols.contains_key("change_event_id"));
    assert!(ce_cols.contains_key("workspace_id"));
    assert!(ce_cols.contains_key("dependency_key_id"));
    assert_eq!(ce_cols["dependency_key_id"].1, "YES");
    assert!(ce_cols.contains_key("event_type"));
    assert!(ce_cols.contains_key("entity_type"));
    assert!(ce_cols.contains_key("entity_id"));
    assert!(ce_cols.contains_key("change_payload"));
    assert_eq!(ce_cols["change_payload"].0, "jsonb");
    assert!(ce_cols.contains_key("detected_at"));
    assert!(ce_cols.contains_key("created_at"));

    test_db.close().await.expect("Failed to drop test database");
}
