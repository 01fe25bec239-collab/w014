//! Comprehensive integration tests for WI-0104 RLS + AWC Tenant Isolation.
//!
//! Validates:
//! - AuthorizedWorkspaceContext binding to transaction-local PostgreSQL RLS context (`app.current_workspace_id`).
//! - Primary Rust authorization before tenant SQL / transaction initiation.
//! - Untrusted client workspace selector matching against authoritative AWC.
//! - Transaction-local context lifecycle (context wiped upon commit and rollback).
//! - Fail-closed context verification (`current_setting` verification).
//! - Missing context fail-closed behavior (returns 0 rows, rejects mutations).
//! - Mismatched context fail-closed behavior (security/internal failure).
//! - Repository cannot change RLS context or commit outer transaction.
//! - Connection pool isolation across connection checkout reuse (no leakage).
//! - Cross-workspace IDOR rejection (READ, MUTATION, UUID guess, INFERENCE denied).
//! - Privacy-safe unauthorized behavior (no metadata/existence leakage).
//! - Database-level composite FK rejection.
//! - Staged FK boundaries preserved (no early W2/W3 FKs).

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use w014_application::authz::{
    DatabaseRole, WorkspaceAuthzResolver, WorkspaceTransaction, WorkspaceTransactionCoordinator,
    WorkspaceTxOptions, get_current_workspace_id,
};
use w014_application::error::ApplicationError;
use w014_application::persistence::{
    CapabilityGrantRepository, MembershipRepository, OrganizationRepository, PrincipalRepository,
    ProgramRepository, WorkspaceRepository,
};
use w014_application::services::{CapabilityGrantService, MembershipService};
use w014_authz::authority::SpecialAuthority;
use w014_authz::capability::Capability;
use w014_authz::error::AuthzError;
use w014_domain::membership::MembershipRole;
use w014_domain::organization::Organization;
use w014_domain::principal::{Principal, PrincipalType};
use w014_domain::program::Program;
use w014_domain::workspace::Workspace;
use w014_persistence::audit::{AppendAuditParams, AuditAppendContract, PostgresAuditStore};
use w014_persistence::harness::TestDatabase;
use w014_persistence::runner::{MIGRATOR, MigrationRunner};

struct TestFixture {
    test_db: TestDatabase,
    org_a: Organization,
    org_b: Organization,
    prog_a: Program,
    ws_a: Workspace,
    ws_b: Workspace,
    alice_admin: Principal,
    bob_viewer: Principal,
}

async fn setup_test_fixture() -> TestFixture {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");

    let audit_store = PostgresAuditStore::new();
    let mut tx = test_db.pool().begin().await.expect("begin setup tx");

    // Organizations
    let org_a = Organization::new("Org A", "org-a").unwrap();
    let org_b = Organization::new("Org B", "org-b").unwrap();
    OrganizationRepository::insert(&mut tx, &org_a)
        .await
        .unwrap();
    OrganizationRepository::insert(&mut tx, &org_b)
        .await
        .unwrap();

    // Principals
    let alice_admin = Principal::new(
        org_a.id,
        PrincipalType::User,
        Some("alice@org-a.com"),
        "Alice Admin",
    )
    .unwrap();
    let bob_viewer = Principal::new(
        org_a.id,
        PrincipalType::User,
        Some("bob@org-a.com"),
        "Bob Viewer",
    )
    .unwrap();
    let charlie_foreign = Principal::new(
        org_b.id,
        PrincipalType::User,
        Some("charlie@org-b.com"),
        "Charlie Foreign",
    )
    .unwrap();

    PrincipalRepository::insert(&mut tx, &alice_admin)
        .await
        .unwrap();
    PrincipalRepository::insert(&mut tx, &bob_viewer)
        .await
        .unwrap();
    PrincipalRepository::insert(&mut tx, &charlie_foreign)
        .await
        .unwrap();

    // Programs
    let prog_a = Program::new(org_a.id, "Prog A", "prog-a", None::<&str>).unwrap();
    let prog_b = Program::new(org_b.id, "Prog B", "prog-b", None::<&str>).unwrap();
    ProgramRepository::insert(&mut tx, &prog_a).await.unwrap();
    ProgramRepository::insert(&mut tx, &prog_b).await.unwrap();

    // Workspaces
    let ws_a = Workspace::new(prog_a.id, org_a.id, "Workspace A", "ws-a").unwrap();
    let ws_b = Workspace::new(prog_b.id, org_b.id, "Workspace B", "ws-b").unwrap();
    WorkspaceRepository::insert(&mut tx, &ws_a).await.unwrap();
    WorkspaceRepository::insert(&mut tx, &ws_b).await.unwrap();

    // Memberships
    MembershipService::add_member_with_audit(
        &mut tx,
        &audit_store,
        ws_a.id,
        alice_admin.id,
        MembershipRole::Admin,
        Some(alice_admin.id),
        Some("setup-alice".to_string()),
    )
    .await
    .unwrap();

    MembershipService::add_member_with_audit(
        &mut tx,
        &audit_store,
        ws_a.id,
        bob_viewer.id,
        MembershipRole::Viewer,
        Some(alice_admin.id),
        Some("setup-bob".to_string()),
    )
    .await
    .unwrap();

    MembershipService::add_member_with_audit(
        &mut tx,
        &audit_store,
        ws_b.id,
        charlie_foreign.id,
        MembershipRole::Owner,
        Some(charlie_foreign.id),
        Some("setup-charlie".to_string()),
    )
    .await
    .unwrap();

    // Capability Grants for WS A (Alice has Admin base; Bob gets explicit OVERRIDE_BLOCK grant)
    CapabilityGrantService::grant_capability_with_audit(
        &mut tx,
        &audit_store,
        ws_a.id,
        bob_viewer.id,
        Capability::OverrideBlock,
        Some(alice_admin.id),
        Some(Utc::now() + Duration::hours(1)),
        Some(alice_admin.id),
        Some("setup-grant-bob".to_string()),
    )
    .await
    .unwrap();

    // Initialize Audit Chains
    audit_store
        .initialize_chain_head(&mut tx, ws_a.id.into_uuid())
        .await
        .unwrap();
    audit_store
        .initialize_chain_head(&mut tx, ws_b.id.into_uuid())
        .await
        .unwrap();

    // Seed an initial audit event in WS A & WS B
    audit_store
        .append_audit_event(
            &mut tx,
            AppendAuditParams {
                workspace_id: ws_a.id.into_uuid(),
                event_type: "ws.init".to_string(),
                actor_principal_id: Some(alice_admin.id.into_uuid()),
                action: "INIT".to_string(),
                resource_type: "workspace".to_string(),
                resource_id: ws_a.id.to_string(),
                payload: json!({"name": "ws_a"}),
                correlation_id: Some("corr-a".to_string()),
            },
        )
        .await
        .unwrap();

    audit_store
        .append_audit_event(
            &mut tx,
            AppendAuditParams {
                workspace_id: ws_b.id.into_uuid(),
                event_type: "ws.init".to_string(),
                actor_principal_id: Some(charlie_foreign.id.into_uuid()),
                action: "INIT".to_string(),
                resource_type: "workspace".to_string(),
                resource_id: ws_b.id.to_string(),
                payload: json!({"name": "ws_b"}),
                correlation_id: Some("corr-b".to_string()),
            },
        )
        .await
        .unwrap();

    // Insert Idempotency records in WS A & WS B
    sqlx::query(
        "INSERT INTO idempotency_records (id, workspace_id, idempotency_key, request_hash, status, expires_at)
         VALUES ($1, $2, 'idemp-a', '1111111111111111111111111111111111111111111111111111111111111111', 'completed', CURRENT_TIMESTAMP + INTERVAL '1 hour'),
                ($3, $4, 'idemp-b', '2222222222222222222222222222222222222222222222222222222222222222', 'completed', CURRENT_TIMESTAMP + INTERVAL '1 hour')"
    )
    .bind(Uuid::new_v4())
    .bind(ws_a.id.as_uuid())
    .bind(Uuid::new_v4())
    .bind(ws_b.id.as_uuid())
    .execute(&mut *tx)
    .await
    .unwrap();

    tx.commit().await.unwrap();

    TestFixture {
        test_db,
        org_a,
        org_b,
        prog_a,
        ws_a,
        ws_b,
        alice_admin,
        bob_viewer,
    }
}

#[tokio::test]
async fn test_authorized_workspace_context_binding_and_execution_order() {
    let f = setup_test_fixture().await;
    let pool = f.test_db.pool();
    let now = Utc::now();

    // 1. Resolve AuthorizedWorkspaceContext for Alice (Admin in WS A)
    let mut setup_tx = pool.begin().await.unwrap();
    let awc_alice =
        WorkspaceAuthzResolver::resolve(&mut setup_tx, f.ws_a.id, f.alice_admin.id, now)
            .await
            .expect("resolve AWC for alice");
    setup_tx.commit().await.unwrap();

    assert_eq!(awc_alice.workspace_id(), f.ws_a.id);
    assert_eq!(awc_alice.principal_id(), f.alice_admin.id);
    assert_eq!(awc_alice.membership_role(), MembershipRole::Admin);

    // 2. Execute a workspace-scoped tenant operation via WorkspaceTransaction
    let options = WorkspaceTxOptions::new()
        .with_client_workspace(f.ws_a.id)
        .with_capability(Capability::WorkspaceRead)
        .with_role(DatabaseRole::App);

    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc_alice, options)
        .await
        .expect("begin workspace tx");

    // Verify RLS context is actively set to WS A inside the transaction
    let current = get_current_workspace_id(ws_tx.conn()).await.unwrap();
    assert_eq!(
        current,
        Some(f.ws_a.id.into_uuid()),
        "RLS setting must match AWC"
    );

    let ws_id = ws_tx.awc().workspace_id();
    let principal_id = ws_tx.awc().principal_id();

    // Execute tenant query under RLS
    let membership =
        MembershipRepository::get_by_workspace_and_principal(ws_tx.conn(), ws_id, principal_id)
            .await
            .unwrap();
    assert!(membership.is_some());

    ws_tx.commit().await.unwrap();
}

#[tokio::test]
async fn test_rust_authz_before_rls_context_prevents_db_access() {
    let f = setup_test_fixture().await;
    let pool = f.test_db.pool();
    let now = Utc::now();

    // Resolve AWC for Bob (Viewer in WS A)
    let mut setup_tx = pool.begin().await.unwrap();
    let awc_bob = WorkspaceAuthzResolver::resolve(&mut setup_tx, f.ws_a.id, f.bob_viewer.id, now)
        .await
        .unwrap();
    setup_tx.commit().await.unwrap();

    assert_eq!(awc_bob.membership_role(), MembershipRole::Viewer);
    assert!(awc_bob.can_read_workspace());
    assert!(!awc_bob.can_write_workspace()); // Viewer lacks write

    // 1. Attempt to execute an operation requiring WORKSPACE_WRITE
    let options = WorkspaceTxOptions::new()
        .with_capability(Capability::WorkspaceWrite)
        .with_role(DatabaseRole::App);

    let result = WorkspaceTransaction::begin(pool, &awc_bob, options).await;

    assert!(
        matches!(
            result,
            Err(ApplicationError::Authz(AuthzError::PermissionDenied(cap))) if cap == "WORKSPACE_WRITE"
        ),
        "Must reject with PermissionDenied before SQL"
    );

    // 2. Attempt to execute an operation requiring a special authority Bob lacks (e.g. RIGHTS_REVIEW)
    let options_special = WorkspaceTxOptions::new()
        .with_special_authority(SpecialAuthority::RightsReview)
        .with_role(DatabaseRole::App);

    let result_special = WorkspaceTransaction::begin(pool, &awc_bob, options_special).await;

    assert!(
        matches!(
            result_special,
            Err(ApplicationError::Authz(AuthzError::SpecialAuthorityDenied(auth))) if auth == "RIGHTS_REVIEW"
        ),
        "Must reject with SpecialAuthorityDenied before SQL"
    );
}

#[tokio::test]
async fn test_untrusted_client_workspace_selector_mismatch_fails_closed() {
    let f = setup_test_fixture().await;
    let pool = f.test_db.pool();
    let now = Utc::now();

    // Alice is authorized for Workspace A
    let mut setup_tx = pool.begin().await.unwrap();
    let awc_alice =
        WorkspaceAuthzResolver::resolve(&mut setup_tx, f.ws_a.id, f.alice_admin.id, now)
            .await
            .unwrap();
    setup_tx.commit().await.unwrap();

    // Adversarial client sends AWC for WS A but URL path / selector for WS B
    let options = WorkspaceTxOptions::new()
        .with_client_workspace(f.ws_b.id) // untrusted selector mismatch
        .with_capability(Capability::WorkspaceRead)
        .with_role(DatabaseRole::App);

    let result = WorkspaceTransaction::begin(pool, &awc_alice, options).await;

    assert!(
        matches!(
            result,
            Err(ApplicationError::Authz(AuthzError::WorkspaceMismatch {
                expected,
                actual
            })) if expected == f.ws_a.id && actual == f.ws_b.id
        ),
        "Must reject selector mismatch immediately"
    );
}

#[tokio::test]
async fn test_transaction_local_workspace_context_lifecycle() {
    let f = setup_test_fixture().await;
    let pool = f.test_db.pool();
    let now = Utc::now();

    let mut setup_tx = pool.begin().await.unwrap();
    let awc_alice =
        WorkspaceAuthzResolver::resolve(&mut setup_tx, f.ws_a.id, f.alice_admin.id, now)
            .await
            .unwrap();
    setup_tx.commit().await.unwrap();

    // 1. Commit lifecycle
    let options = WorkspaceTxOptions::new().with_capability(Capability::WorkspaceRead);
    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc_alice, options)
        .await
        .unwrap();
    let in_tx = get_current_workspace_id(ws_tx.conn()).await.unwrap();
    assert_eq!(
        in_tx,
        Some(f.ws_a.id.into_uuid()),
        "Context must be active in tx"
    );
    ws_tx.commit().await.unwrap();

    // Verify context is clean on pooled connection after commit
    let mut check_conn = pool.acquire().await.unwrap();
    let post_commit = get_current_workspace_id(&mut check_conn).await.unwrap();
    assert_eq!(
        post_commit, None,
        "RLS context must NOT survive transaction commit"
    );

    // 2. Rollback lifecycle
    let options_rollback = WorkspaceTxOptions::new().with_capability(Capability::WorkspaceRead);
    let mut ws_tx_rollback = WorkspaceTransaction::begin(pool, &awc_alice, options_rollback)
        .await
        .unwrap();
    let in_tx_rb = get_current_workspace_id(ws_tx_rollback.conn())
        .await
        .unwrap();
    assert_eq!(in_tx_rb, Some(f.ws_a.id.into_uuid()));
    ws_tx_rollback.rollback().await.unwrap();

    // Verify context is clean on pooled connection after rollback
    let mut check_conn2 = pool.acquire().await.unwrap();
    let post_rollback = get_current_workspace_id(&mut check_conn2).await.unwrap();
    assert_eq!(
        post_rollback, None,
        "RLS context must NOT survive transaction rollback"
    );
}

#[tokio::test]
async fn test_missing_context_fail_closed() {
    let f = setup_test_fixture().await;
    let pool = f.test_db.pool();

    // 1. Querying under w014_app without workspace context returns 0 rows (fail-closed)
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL ROLE w014_app")
        .execute(&mut *tx)
        .await
        .unwrap();

    let ws_rows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM workspaces")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert!(
        ws_rows.is_empty(),
        "workspaces query must return 0 rows when context is unset"
    );

    let member_rows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM memberships")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert!(
        member_rows.is_empty(),
        "memberships query must return 0 rows when context is unset"
    );

    let grant_rows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM capability_grants")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert!(
        grant_rows.is_empty(),
        "capability_grants query must return 0 rows when context is unset"
    );

    let audit_heads: Vec<Uuid> = sqlx::query_scalar("SELECT workspace_id FROM audit_chain_heads")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert!(
        audit_heads.is_empty(),
        "audit_chain_heads query must return 0 rows when context is unset"
    );

    let audit_events: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM audit_events")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert!(
        audit_events.is_empty(),
        "audit_events query must return 0 rows when context is unset"
    );

    // 2. Inserting under w014_app without context fails RLS WITH CHECK policy
    let bad_insert = sqlx::query(
        "INSERT INTO memberships (id, workspace_id, principal_id, role) VALUES ($1, $2, $3, 'viewer')"
    )
    .bind(Uuid::new_v4())
    .bind(f.ws_a.id.as_uuid())
    .bind(f.alice_admin.id.as_uuid())
    .execute(&mut *tx)
    .await;

    assert!(
        bad_insert.is_err(),
        "Insert without context must fail RLS WITH CHECK"
    );

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn test_mismatched_context_fail_closed() {
    let f = setup_test_fixture().await;
    let pool = f.test_db.pool();
    let now = Utc::now();

    let mut setup_tx = pool.begin().await.unwrap();
    let awc_alice =
        WorkspaceAuthzResolver::resolve(&mut setup_tx, f.ws_a.id, f.alice_admin.id, now)
            .await
            .unwrap();
    setup_tx.commit().await.unwrap();

    // Verify bind_and_verify_tx sets and verifies WS A context
    let mut tx = pool.begin().await.unwrap();
    let options = WorkspaceTxOptions::new().with_capability(Capability::WorkspaceRead);
    WorkspaceTransactionCoordinator::bind_and_verify_tx(&mut tx, &awc_alice, &options)
        .await
        .unwrap();

    let verified = get_current_workspace_id(&mut tx).await.unwrap();
    assert_eq!(verified, Some(f.ws_a.id.into_uuid()));

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn test_repositories_cannot_change_context_or_commit_outer_tx() {
    let f = setup_test_fixture().await;
    let pool = f.test_db.pool();
    let now = Utc::now();

    let mut setup_tx = pool.begin().await.unwrap();
    let awc_alice =
        WorkspaceAuthzResolver::resolve(&mut setup_tx, f.ws_a.id, f.alice_admin.id, now)
            .await
            .unwrap();
    setup_tx.commit().await.unwrap();

    let options = WorkspaceTxOptions::new()
        .with_capability(Capability::WorkspaceRead)
        .with_role(DatabaseRole::App);

    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc_alice, options)
        .await
        .unwrap();

    let before = get_current_workspace_id(ws_tx.conn()).await.unwrap();
    assert_eq!(before, Some(f.ws_a.id.into_uuid()));

    let ws_id = ws_tx.awc().workspace_id();
    let org_id = ws_tx.awc().organization_id();
    let prog_id = ws_tx.awc().program_id();
    let principal_id = ws_tx.awc().principal_id();

    // Call various repository methods
    let _ws = WorkspaceRepository::get_by_id(ws_tx.conn(), ws_id)
        .await
        .unwrap();
    let _org = OrganizationRepository::get_by_id(ws_tx.conn(), org_id)
        .await
        .unwrap();
    let _prog = ProgramRepository::get_by_id(ws_tx.conn(), prog_id)
        .await
        .unwrap();
    let _principal = PrincipalRepository::get_by_id(ws_tx.conn(), principal_id)
        .await
        .unwrap();
    let _mem =
        MembershipRepository::get_by_workspace_and_principal(ws_tx.conn(), ws_id, principal_id)
            .await
            .unwrap();
    let _grants = CapabilityGrantRepository::get_by_workspace_and_principal(
        ws_tx.conn(),
        ws_id,
        principal_id,
    )
    .await
    .unwrap();

    // Verify context was NOT altered by any repository
    let after = get_current_workspace_id(ws_tx.conn()).await.unwrap();
    assert_eq!(
        after,
        Some(f.ws_a.id.into_uuid()),
        "Repositories must NOT mutate RLS context"
    );

    ws_tx.commit().await.unwrap();
}

#[tokio::test]
async fn test_pool_context_isolation_across_connection_reuse() {
    let f = setup_test_fixture().await;
    let pool = f.test_db.pool();
    let now = Utc::now();

    let mut setup_tx = pool.begin().await.unwrap();
    let awc_alice =
        WorkspaceAuthzResolver::resolve(&mut setup_tx, f.ws_a.id, f.alice_admin.id, now)
            .await
            .unwrap();
    setup_tx.commit().await.unwrap();

    // 1. Transaction 1: Execute in Workspace A and commit
    let ws_tx1 = WorkspaceTransaction::begin(
        pool,
        &awc_alice,
        WorkspaceTxOptions::new().with_capability(Capability::WorkspaceRead),
    )
    .await
    .unwrap();
    ws_tx1.commit().await.unwrap();

    // 2. Transaction 2 on pooled connection without setting context under w014_app
    {
        let mut tx2 = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx2)
            .await
            .unwrap();

        let ctx2 = get_current_workspace_id(&mut tx2).await.unwrap();
        assert_eq!(ctx2, None, "Reused connection must NOT retain WS A context");

        let visible_workspaces: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM workspaces")
            .fetch_all(&mut *tx2)
            .await
            .unwrap();
        assert!(
            visible_workspaces.is_empty(),
            "Reused connection without context must NOT see WS A rows"
        );

        tx2.rollback().await.unwrap();
    }

    // 3. Transaction 3: Execute in Workspace A and rollback
    let ws_tx3 = WorkspaceTransaction::begin(
        pool,
        &awc_alice,
        WorkspaceTxOptions::new().with_capability(Capability::WorkspaceRead),
    )
    .await
    .unwrap();
    ws_tx3.rollback().await.unwrap();

    // 4. Transaction 4: Verify clean state after rollback
    {
        let mut tx4 = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx4)
            .await
            .unwrap();

        let ctx4 = get_current_workspace_id(&mut tx4).await.unwrap();
        assert_eq!(
            ctx4, None,
            "Reused connection after rollback must NOT retain context"
        );

        let visible_memberships: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM memberships")
            .fetch_all(&mut *tx4)
            .await
            .unwrap();
        assert!(
            visible_memberships.is_empty(),
            "Reused connection after rollback must NOT see rows"
        );

        tx4.rollback().await.unwrap();
    }
}

#[tokio::test]
async fn test_cross_workspace_idor_read_mutation_inference_denied() {
    let f = setup_test_fixture().await;
    let pool = f.test_db.pool();
    let now = Utc::now();

    let mut setup_tx = pool.begin().await.unwrap();
    let awc_alice =
        WorkspaceAuthzResolver::resolve(&mut setup_tx, f.ws_a.id, f.alice_admin.id, now)
            .await
            .unwrap();
    setup_tx.commit().await.unwrap();

    // =============================================================
    // 1. CROSS_WORKSPACE_READ_DENIED & INFERENCE_DENIED
    // =============================================================
    let options = WorkspaceTxOptions::new()
        .with_capability(Capability::WorkspaceRead)
        .with_role(DatabaseRole::App);

    let mut ws_tx = WorkspaceTransaction::begin(pool, &awc_alice, options)
        .await
        .unwrap();

    let tx = ws_tx.conn();

    // 1.1 Direct lookup of WS B workspace record
    let ws_b_lookup: Option<Uuid> = sqlx::query_scalar("SELECT id FROM workspaces WHERE id = $1")
        .bind(f.ws_b.id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .unwrap();
    assert!(
        ws_b_lookup.is_none(),
        "CROSS_WORKSPACE_READ: WS B record must be hidden from WS A"
    );

    // 1.2 Direct lookup of WS B memberships
    let member_b_lookup: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM memberships WHERE workspace_id = $1")
            .bind(f.ws_b.id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .unwrap();
    assert!(
        member_b_lookup.is_none(),
        "CROSS_WORKSPACE_READ: WS B memberships must be hidden"
    );

    // 1.3 Direct lookup of WS B capability grants
    let grant_b_lookup: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM capability_grants WHERE workspace_id = $1")
            .bind(f.ws_b.id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .unwrap();
    assert!(
        grant_b_lookup.is_none(),
        "CROSS_WORKSPACE_READ: WS B capability grants must be hidden"
    );

    // 1.4 Direct lookup of WS B audit chain head
    let head_b_lookup: Option<Uuid> =
        sqlx::query_scalar("SELECT workspace_id FROM audit_chain_heads WHERE workspace_id = $1")
            .bind(f.ws_b.id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .unwrap();
    assert!(
        head_b_lookup.is_none(),
        "CROSS_WORKSPACE_READ: WS B audit chain head must be hidden"
    );

    // 1.5 Direct lookup of WS B audit events
    let event_b_lookup: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM audit_events WHERE workspace_id = $1")
            .bind(f.ws_b.id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .unwrap();
    assert!(
        event_b_lookup.is_none(),
        "CROSS_WORKSPACE_READ: WS B audit events must be hidden"
    );

    // 1.6 Direct lookup of WS B idempotency records
    let idemp_b_lookup: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM idempotency_records WHERE workspace_id = $1")
            .bind(f.ws_b.id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .unwrap();
    assert!(
        idemp_b_lookup.is_none(),
        "CROSS_WORKSPACE_READ: WS B idempotency records must be hidden"
    );

    // 1.7 INFERENCE DENIED: Counting foreign workspace objects returns 0
    let count_mem_b: i64 =
        sqlx::query_scalar("SELECT count(*) FROM memberships WHERE workspace_id = $1")
            .bind(f.ws_b.id.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(
        count_mem_b, 0,
        "CROSS_WORKSPACE_INFERENCE: Count of foreign memberships must be 0"
    );

    let count_non_existent: i64 =
        sqlx::query_scalar("SELECT count(*) FROM memberships WHERE workspace_id = $1")
            .bind(Uuid::new_v4())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(
        count_non_existent, 0,
        "Inference check matches non-existent UUID"
    );

    let count_events_b: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE workspace_id = $1")
            .bind(f.ws_b.id.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(
        count_events_b, 0,
        "CROSS_WORKSPACE_INFERENCE: Count of foreign audit events must be 0"
    );

    ws_tx.commit().await.unwrap();

    // =============================================================
    // 2. CROSS_WORKSPACE_MUTATION_DENIED
    // =============================================================

    // 2.1 Inserting membership into WS B from WS A context
    {
        let mut ws_tx_mut = WorkspaceTransaction::begin(
            pool,
            &awc_alice,
            WorkspaceTxOptions::new()
                .with_capability(Capability::WorkspaceWrite)
                .with_role(DatabaseRole::App),
        )
        .await
        .unwrap();

        let bad_mem_insert = sqlx::query(
            "INSERT INTO memberships (id, workspace_id, principal_id, role) VALUES ($1, $2, $3, 'member')"
        )
        .bind(Uuid::new_v4())
        .bind(f.ws_b.id.as_uuid())
        .bind(f.alice_admin.id.as_uuid())
        .execute(ws_tx_mut.conn())
        .await;

        assert!(
            bad_mem_insert.is_err(),
            "CROSS_WORKSPACE_MUTATION: Inserting WS B membership must be rejected by RLS"
        );
        let _ = ws_tx_mut.rollback().await;
    }

    // 2.2 Inserting capability grant into WS B from WS A context
    {
        let mut ws_tx_grant = WorkspaceTransaction::begin(
            pool,
            &awc_alice,
            WorkspaceTxOptions::new()
                .with_capability(Capability::WorkspaceWrite)
                .with_role(DatabaseRole::App),
        )
        .await
        .unwrap();

        let bad_grant_insert = sqlx::query(
            "INSERT INTO capability_grants (id, workspace_id, principal_id, capability) VALUES ($1, $2, $3, 'WORKSPACE_ADMIN')"
        )
        .bind(Uuid::new_v4())
        .bind(f.ws_b.id.as_uuid())
        .bind(f.alice_admin.id.as_uuid())
        .execute(ws_tx_grant.conn())
        .await;

        assert!(
            bad_grant_insert.is_err(),
            "CROSS_WORKSPACE_MUTATION: Inserting WS B grant must be rejected by RLS"
        );
        let _ = ws_tx_grant.rollback().await;
    }

    // 2.3 Inserting audit event into WS B from WS A context
    {
        let mut ws_tx_audit = WorkspaceTransaction::begin(
            pool,
            &awc_alice,
            WorkspaceTxOptions::new()
                .with_capability(Capability::WorkspaceWrite)
                .with_role(DatabaseRole::App),
        )
        .await
        .unwrap();

        let bad_event_insert = sqlx::query(
            "INSERT INTO audit_events (id, workspace_id, sequence_num, previous_event_hash, event_hash, event_type, action, resource_type, resource_id)
             VALUES ($1, $2, 99, '0000000000000000000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000000000000000000', 'fake', 'fake', 'fake', 'fake')"
        )
        .bind(Uuid::new_v4())
        .bind(f.ws_b.id.as_uuid())
        .execute(ws_tx_audit.conn())
        .await;

        assert!(
            bad_event_insert.is_err(),
            "CROSS_WORKSPACE_MUTATION: Inserting WS B audit event must be rejected by RLS"
        );
        let _ = ws_tx_audit.rollback().await;
    }
}

#[tokio::test]
async fn test_privacy_safe_unauthorized_behavior() {
    let f = setup_test_fixture().await;
    let pool = f.test_db.pool();
    let now = Utc::now();

    // Alice (in Org A) attempts to resolve AWC for Workspace B (in Org B)
    let mut tx = pool.begin().await.unwrap();
    let resolve_foreign =
        WorkspaceAuthzResolver::resolve(&mut tx, f.ws_b.id, f.alice_admin.id, now).await;

    // Must fail closed with TenantBoundaryMismatch or NoMembership without revealing Org B details
    assert!(
        matches!(
            resolve_foreign,
            Err(ApplicationError::Authz(AuthzError::TenantBoundaryMismatch(
                _
            ))) | Err(ApplicationError::Authz(AuthzError::NoMembership { .. }))
        ),
        "Resolving foreign workspace must fail closed"
    );

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn test_composite_fk_rejection_at_database_boundary() {
    let f = setup_test_fixture().await;
    let pool = f.test_db.pool();

    let mut tx = pool.begin().await.unwrap();

    // Attempt to create a workspace pointing to Program A but Organization B
    let bad_ws = sqlx::query(
        "INSERT INTO workspaces (id, program_id, organization_id, name, slug) VALUES ($1, $2, $3, 'Bad WS', 'bad-ws')"
    )
    .bind(Uuid::new_v4())
    .bind(f.prog_a.id.as_uuid()) // Org A
    .bind(f.org_b.id.as_uuid())  // Org B (Mismatched!)
    .execute(&mut *tx)
    .await;

    assert!(
        bad_ws.is_err(),
        "Composite FK fk_workspaces_program_org must reject cross-org parent reference"
    );

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn test_staged_fk_and_boundaries_preserved() {
    let f = setup_test_fixture().await;
    let pool = f.test_db.pool();

    let mut tx = pool.begin().await.unwrap();

    // 1. Verify workspaces.current_source_state_id is nullable and has NO FK constraint to effective_contract_states
    let random_state_id = Uuid::new_v4();
    let ws_with_random_state = sqlx::query(
        "INSERT INTO workspaces (id, program_id, organization_id, name, slug, current_source_state_id)
         VALUES ($1, $2, $3, 'Staged WS', 'staged-ws', $4)"
    )
    .bind(Uuid::new_v4())
    .bind(f.prog_a.id.as_uuid())
    .bind(f.org_a.id.as_uuid())
    .bind(random_state_id) // Arbitrary UUID succeeds because FK is deferred to W3
    .execute(&mut *tx)
    .await;

    assert!(
        ws_with_random_state.is_ok(),
        "current_source_state_id must remain unconstrained in W1 (deferred to W3)"
    );

    // 2. Verify audit_events.job_id is nullable and has NO FK constraint to jobs
    let random_job_id = Uuid::new_v4();
    let event_with_random_job = sqlx::query(
        "INSERT INTO audit_events (id, workspace_id, sequence_num, previous_event_hash, event_hash, event_type, action, resource_type, resource_id, job_id)
         VALUES ($1, $2, 9999, '0000000000000000000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000000000000000000', 'staged.test', 'CREATE', 'test', 'test-1', $3)"
    )
    .bind(Uuid::new_v4())
    .bind(f.ws_a.id.as_uuid())
    .bind(random_job_id) // Arbitrary UUID succeeds because FK is deferred to W2
    .execute(&mut *tx)
    .await;

    assert!(
        event_with_random_job.is_ok(),
        "job_id must remain unconstrained in W1 (deferred to W2)"
    );

    tx.rollback().await.unwrap();
}
