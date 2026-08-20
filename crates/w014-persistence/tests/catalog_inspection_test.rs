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

    // 1. Verify exact 13 M001R tables exist
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
        .expect("Failed to query table existence");

        assert!(exists, "Table '{table}' must exist in public schema");
    }

    // 2. Verify all W2 job and document tables are strictly absent
    let forbidden_tables = vec![
        "jobs",
        "job_attempts",
        "job_dependencies",
        "job_progress",
        "dead_letter_entries",
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
        "dependency_keys",
        "change_events",
        "effective_contract_states",
    ];

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
            "Forbidden table '{table}' must NOT exist in W1 M001R"
        );
    }

    // 3. Verify Staged FK 1: workspaces.current_source_state_id FK is ABSENT
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
        "workspaces.current_source_state_id must NOT have a foreign key in W1"
    );

    // 4. Verify Staged FK 2: audit_events.job_id FK is ABSENT
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
        !audit_job_fk_exists,
        "audit_events.job_id must NOT have a foreign key in W1"
    );

    // 5. Verify RLS enabled and forced on tenant tables
    let rls_tables = vec![
        "workspaces",
        "memberships",
        "capability_grants",
        "audit_chain_heads",
        "audit_events",
        "idempotency_records",
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
        ("programs", "uq_programs_id_org"),
        ("workspaces", "uq_workspaces_id_org"),
        ("workspaces", "fk_workspaces_program_org"),
        ("memberships", "uq_memberships_id_workspace"),
        ("capability_grants", "uq_capability_grants_id_workspace"),
        ("audit_events", "uq_audit_events_id_workspace"),
        ("idempotency_records", "uq_idempotency_records_id_workspace"),
        ("idempotency_records", "uq_idempotency_records_identity"),
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
