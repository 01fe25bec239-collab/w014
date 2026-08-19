//! Direct PostgreSQL Catalog Inspection and Conformance Verification against real PostgreSQL 18.
//!
//! Validates:
//! - Catalog existence of all 13 M001R tables.
//! - Absence of W2 durable-job tables.
//! - Absence of deferred staged FK constraints.
//! - Verification of RLS enabled (`relrowsecurity`) and forced (`relforcerowsecurity`) states.
//! - Verification of RLS policies in `pg_policy`.
//! - Verification of database roles and restricted privileges in `information_schema.table_privileges`.
//! - Verification of immutability triggers in `information_schema.triggers`.

use sqlx::Row;
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

    // 2. Verify all W2 job tables are strictly absent
    let forbidden_tables = vec![
        "jobs",
        "job_attempts",
        "job_dependencies",
        "job_progress",
        "dead_letter_entries",
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

        assert!(!exists, "W2 job table '{table}' must NOT exist in W1 M001R");
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
        "sessions",
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

    // 6. Verify RLS policies exist in pg_policy
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

    let chain_heads_trigger_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT trigger_name)
         FROM information_schema.triggers
         WHERE event_object_table = 'audit_chain_heads'
           AND trigger_name = 'trg_prevent_audit_chain_heads_deletion'",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to check audit_chain_heads triggers");

    assert_eq!(
        chain_heads_trigger_count, 1,
        "audit_chain_heads must have trg_prevent_audit_chain_heads_deletion trigger"
    );

    // 8. Verify database roles exist and have NO BYPASSRLS privilege
    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT rolname FROM pg_roles WHERE rolname IN ('w014_app', 'w014_readonly')",
    )
    .fetch_all(test_db.pool())
    .await
    .expect("Failed to query pg_roles");

    assert!(
        roles.contains(&"w014_app".to_string()),
        "Role 'w014_app' must exist"
    );
    assert!(
        roles.contains(&"w014_readonly".to_string()),
        "Role 'w014_readonly' must exist"
    );

    // Verify neither role has BYPASSRLS
    let bypass_roles: Vec<String> = sqlx::query_scalar(
        "SELECT rolname FROM pg_roles WHERE rolname IN ('w014_app', 'w014_readonly') AND rolbypassrls = true",
    )
    .fetch_all(test_db.pool())
    .await
    .expect("Failed to query rolbypassrls");

    assert!(
        bypass_roles.is_empty(),
        "Neither w014_app nor w014_readonly should have BYPASSRLS privilege, found: {bypass_roles:?}"
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
        ("principals", "uq_principals_id_org"),
        ("workspaces", "uq_workspaces_id_org"),
        ("workspaces", "fk_workspaces_program_org"),
        ("memberships", "uq_memberships_id_workspace"),
        ("capability_grants", "uq_capability_grants_id_workspace"),
        ("audit_events", "uq_audit_events_id_workspace"),
        ("idempotency_records", "uq_idempotency_id_workspace"),
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

#[tokio::test]
async fn test_m001r_session_schema_prompt12_conformance() {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");

    // 1. Check sessions columns in information_schema.columns
    let columns: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT column_name, data_type, is_nullable
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'sessions'
         ORDER BY ordinal_position",
    )
    .fetch_all(test_db.pool())
    .await
    .expect("Failed to query sessions columns");

    let col_map: std::collections::HashMap<String, (String, String)> = columns
        .into_iter()
        .map(|(name, dt, nullable)| (name, (dt, nullable)))
        .collect();

    // sessions.session_id: uuid, NOT NULL
    assert!(
        col_map.contains_key("session_id"),
        "session_id column must exist"
    );
    assert_eq!(col_map["session_id"].0, "uuid");
    assert_eq!(col_map["session_id"].1, "NO");

    // sessions.principal_id: uuid, NOT NULL
    assert!(
        col_map.contains_key("principal_id"),
        "principal_id column must exist"
    );
    assert_eq!(col_map["principal_id"].0, "uuid");
    assert_eq!(col_map["principal_id"].1, "NO");

    // sessions.handle_hash: bytea, NOT NULL
    assert!(
        col_map.contains_key("handle_hash"),
        "handle_hash column must exist"
    );
    assert_eq!(col_map["handle_hash"].0, "bytea");
    assert_eq!(col_map["handle_hash"].1, "NO");

    // sessions.csrf_secret_hash: bytea, NOT NULL
    assert!(
        col_map.contains_key("csrf_secret_hash"),
        "csrf_secret_hash column must exist"
    );
    assert_eq!(col_map["csrf_secret_hash"].0, "bytea");
    assert_eq!(col_map["csrf_secret_hash"].1, "NO");

    // sessions.created_at: timestamp with time zone, NOT NULL
    assert!(
        col_map.contains_key("created_at"),
        "created_at column must exist"
    );
    assert_eq!(col_map["created_at"].0, "timestamp with time zone");
    assert_eq!(col_map["created_at"].1, "NO");

    // sessions.last_seen_at: timestamp with time zone, NOT NULL
    assert!(
        col_map.contains_key("last_seen_at"),
        "last_seen_at column must exist"
    );
    assert_eq!(col_map["last_seen_at"].0, "timestamp with time zone");
    assert_eq!(col_map["last_seen_at"].1, "NO");

    // sessions.idle_expires_at: timestamp with time zone, NOT NULL
    assert!(
        col_map.contains_key("idle_expires_at"),
        "idle_expires_at column must exist"
    );
    assert_eq!(col_map["idle_expires_at"].0, "timestamp with time zone");
    assert_eq!(col_map["idle_expires_at"].1, "NO");

    // sessions.absolute_expires_at: timestamp with time zone, NOT NULL
    assert!(
        col_map.contains_key("absolute_expires_at"),
        "absolute_expires_at column must exist"
    );
    assert_eq!(col_map["absolute_expires_at"].0, "timestamp with time zone");
    assert_eq!(col_map["absolute_expires_at"].1, "NO");

    // sessions.revoked_at: timestamp with time zone, NULLABLE
    assert!(
        col_map.contains_key("revoked_at"),
        "revoked_at column must exist"
    );
    assert_eq!(col_map["revoked_at"].0, "timestamp with time zone");
    assert_eq!(col_map["revoked_at"].1, "YES");

    // sessions.rotation_counter: integer, NOT NULL
    assert!(
        col_map.contains_key("rotation_counter"),
        "rotation_counter column must exist"
    );
    assert_eq!(col_map["rotation_counter"].0, "integer");
    assert_eq!(col_map["rotation_counter"].1, "NO");

    // sessions.session_token_hash must NOT exist
    assert!(
        !col_map.contains_key("session_token_hash"),
        "session_token_hash must NOT exist in sessions"
    );

    // sessions old defective columns must NOT exist
    assert!(
        !col_map.contains_key("status"),
        "status column must NOT exist in Prompt 12 sessions"
    );
    assert!(
        !col_map.contains_key("expires_at"),
        "expires_at column must NOT exist in Prompt 12 sessions"
    );

    // 2. Verify UNIQUE(handle_hash)
    let handle_hash_unique: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM pg_index i
            JOIN pg_class c ON c.oid = i.indrelid
            JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
            WHERE c.relname = 'sessions'
              AND a.attname = 'handle_hash'
              AND i.indisunique = true
        )",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to check handle_hash unique constraint");
    assert!(
        handle_hash_unique,
        "sessions.handle_hash must have a UNIQUE index"
    );

    // 3. Verify BTREE(principal_id, revoked_at)
    let principal_revoked_index_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM pg_indexes
            WHERE tablename = 'sessions'
              AND indexdef LIKE '%(principal_id, revoked_at)%'
        )",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to check principal_id, revoked_at index");
    assert!(
        principal_revoked_index_exists,
        "BTREE(principal_id, revoked_at) index must exist on sessions"
    );

    // 4. Verify BTREE(idle_expires_at)
    let idle_expires_index_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM pg_indexes
            WHERE tablename = 'sessions'
              AND indexdef LIKE '%(idle_expires_at)%'
        )",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to check idle_expires_at index");
    assert!(
        idle_expires_index_exists,
        "BTREE(idle_expires_at) index must exist on sessions"
    );

    // 5. Verify Check Constraints on sessions
    let constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname
         FROM pg_constraint
         WHERE conrelid = 'sessions'::regclass AND contype = 'c'",
    )
    .fetch_all(test_db.pool())
    .await
    .expect("Failed to query check constraints on sessions");

    assert!(
        constraints.contains(&"chk_sessions_idle_expires".to_string()),
        "chk_sessions_idle_expires constraint must exist"
    );
    assert!(
        constraints.contains(&"chk_sessions_absolute_expires".to_string()),
        "chk_sessions_absolute_expires constraint must exist"
    );
    assert!(
        constraints.contains(&"chk_sessions_rotation_counter".to_string()),
        "chk_sessions_rotation_counter constraint must exist"
    );

    // 6. Verify session_rotations columns
    let rot_columns: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT column_name, data_type, is_nullable
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'session_rotations'
         ORDER BY ordinal_position",
    )
    .fetch_all(test_db.pool())
    .await
    .expect("Failed to query session_rotations columns");

    let rot_col_map: std::collections::HashMap<String, (String, String)> = rot_columns
        .into_iter()
        .map(|(name, dt, nullable)| (name, (dt, nullable)))
        .collect();

    // old_handle_hash: bytea, NOT NULL
    assert!(
        rot_col_map.contains_key("old_handle_hash"),
        "old_handle_hash column must exist"
    );
    assert_eq!(rot_col_map["old_handle_hash"].0, "bytea");
    assert_eq!(rot_col_map["old_handle_hash"].1, "NO");

    // new_handle_hash: bytea, NOT NULL
    assert!(
        rot_col_map.contains_key("new_handle_hash"),
        "new_handle_hash column must exist"
    );
    assert_eq!(rot_col_map["new_handle_hash"].0, "bytea");
    assert_eq!(rot_col_map["new_handle_hash"].1, "NO");

    // old_token_hash and new_token_hash must NOT exist
    assert!(
        !rot_col_map.contains_key("old_token_hash"),
        "old_token_hash must NOT exist in session_rotations"
    );
    assert!(
        !rot_col_map.contains_key("new_token_hash"),
        "new_token_hash must NOT exist in session_rotations"
    );

    // 7. Verify NO compatibility representation exists
    let views_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.views WHERE table_schema = 'public'",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to query views");
    assert_eq!(views_count, 0, "No compatibility views should exist");

    let session_triggers_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.triggers WHERE event_object_table = 'sessions'",
    )
    .fetch_one(test_db.pool())
    .await
    .expect("Failed to query sessions triggers");
    assert_eq!(
        session_triggers_count, 0,
        "No compatibility translation triggers should exist on sessions"
    );

    test_db.close().await.expect("Failed to drop test database");
}
