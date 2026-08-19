//! Comprehensive integration test suite for WI-0101 Identity Semantics.
//!
//! Validates:
//! - Tenant / Organization / Principal / Program / Workspace / Membership semantics.
//! - Workspace-head initialization and atomic audit chain head creation.
//! - Privileged domain mutation + audit append atomicity with rollback on failure.
//! - Capability grant lifecycle, distinct special authorities, and one-way revocation.
//! - OIDC identity persistence and composite (issuer, subject) lookup.
//! - Server-side session persistence, append-style rotation, and revocation.
//! - Transient OIDC transaction storage and single-use consumption.
//! - Consumption of accepted `IdempotencyStore` and `AuditAppendContract`.
//! - Verification that staged FKs (current_source_state_id, job_id) remain deferred.

use chrono::{Duration, Utc};
use w014_application::persistence::{
    CapabilityGrantRepository, OrganizationRepository, PrincipalRepository, ProgramRepository,
    SessionRepository, WorkspaceRepository,
};
use w014_application::services::{
    CapabilityGrantService, IdempotencyCoordinator, OidcPersistenceService, SessionService,
    WorkspaceInitializationService,
};
use w014_authz::capability::Capability;
use w014_domain::membership::MembershipRole;
use w014_domain::organization::Organization;
use w014_domain::principal::{Principal, PrincipalType};
use w014_domain::program::Program;
use w014_domain::workspace::Workspace;
use w014_persistence::audit::{
    AppendAuditParams, AuditAppendContract, AuditChainHashContract, AuditChainHasher,
    PostgresAuditStore,
};
use w014_persistence::harness::TestDatabase;
use w014_persistence::idempotency::{IdempotencyCheckResult, PostgresIdempotencyStore};
use w014_persistence::runner::{MIGRATOR, MigrationRunner};

async fn provision_migrated_db() -> TestDatabase {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision test database");
    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply migrations");
    test_db
}

#[tokio::test]
async fn test_organization_principal_program_workspace_persistence() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool();
    let mut tx = pool.begin().await.expect("begin tx");

    // 1. Create Organization
    let org = Organization::new("Acme Corp", "acme-corp").expect("valid org");
    OrganizationRepository::insert(&mut tx, &org)
        .await
        .expect("insert org");

    let fetched_org = OrganizationRepository::get_by_id(&mut tx, org.id)
        .await
        .expect("get org")
        .expect("org exists");
    assert_eq!(fetched_org.id, org.id);
    assert_eq!(fetched_org.name, "Acme Corp");
    assert_eq!(fetched_org.slug, "acme-corp");

    // 2. Create Principal (email is informational snapshot)
    let principal = Principal::new(
        org.id,
        PrincipalType::User,
        Some("alice@acme.com"),
        "Alice Smith",
    )
    .expect("valid principal");
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .expect("insert principal");

    let fetched_principal = PrincipalRepository::get_by_id(&mut tx, principal.id)
        .await
        .expect("get principal")
        .expect("principal exists");
    assert_eq!(fetched_principal.id, principal.id);
    assert_eq!(fetched_principal.organization_id, org.id);
    assert_eq!(fetched_principal.principal_type, PrincipalType::User);
    assert_eq!(fetched_principal.email.as_deref(), Some("alice@acme.com"));
    assert_eq!(fetched_principal.display_name, "Alice Smith");
    assert!(fetched_principal.is_active);

    // 3. Create Program
    let program = Program::new(
        org.id,
        "Engineering",
        "engineering",
        Some("Core engineering program"),
    )
    .expect("valid program");
    ProgramRepository::insert(&mut tx, &program)
        .await
        .expect("insert program");

    let fetched_program = ProgramRepository::get_by_id(&mut tx, program.id)
        .await
        .expect("get program")
        .expect("program exists");
    assert_eq!(fetched_program.id, program.id);
    assert_eq!(fetched_program.organization_id, org.id);

    // 4. Create Workspace (current_source_state_id is None / staged FK)
    let ws = Workspace::new(program.id, org.id, "Sprint 1", "sprint-1").expect("valid workspace");
    WorkspaceRepository::insert(&mut tx, &ws)
        .await
        .expect("insert workspace");

    let fetched_ws = WorkspaceRepository::get_by_id(&mut tx, ws.id)
        .await
        .expect("get workspace")
        .expect("workspace exists");
    assert_eq!(fetched_ws.id, ws.id);
    assert_eq!(fetched_ws.program_id, program.id);
    assert_eq!(fetched_ws.organization_id, org.id);
    assert_eq!(fetched_ws.current_source_state_id, None);

    tx.commit().await.expect("commit tx");
    test_db.close().await.expect("drop test db");
}

#[tokio::test]
async fn test_workspace_head_initialization_and_audit_atomicity() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool();
    let audit_store = PostgresAuditStore::new();

    // 1. Set up org & program
    let mut tx = pool.begin().await.expect("begin tx");
    let org =
        WorkspaceInitializationService::create_organization(&mut tx, "Global Corp", "global-corp")
            .await
            .expect("create org");
    let principal = WorkspaceInitializationService::create_principal(
        &mut tx,
        org.id,
        PrincipalType::User,
        Some("bob@global.com"),
        "Bob Builder",
    )
    .await
    .expect("create principal");
    let program = WorkspaceInitializationService::create_program(
        &mut tx,
        org.id,
        "Logistics",
        "logistics",
        None::<&str>,
    )
    .await
    .expect("create program");
    tx.commit().await.expect("commit setup tx");

    // 2. Atomically create workspace and initialize audit chain head
    let mut ws_tx = pool.begin().await.expect("begin ws tx");
    let ws = WorkspaceInitializationService::create_workspace_with_audit_head(
        &mut ws_tx,
        &audit_store,
        program.id,
        org.id,
        "Logistics West",
        "logistics-west",
        Some(principal.id),
        Some("corr-init-001".to_string()),
    )
    .await
    .expect("create ws with audit head");

    // 3. Atomically assign workspace owner
    let membership = WorkspaceInitializationService::assign_workspace_owner_with_audit(
        &mut ws_tx,
        &audit_store,
        ws.id,
        principal.id,
        Some(principal.id),
        Some("corr-init-002".to_string()),
    )
    .await
    .expect("assign owner");
    assert_eq!(membership.role, MembershipRole::Owner);

    ws_tx.commit().await.expect("commit ws tx");

    // 4. Verify authoritative audit chain state
    let mut verify_tx = pool.begin().await.expect("begin verify tx");
    let head = audit_store
        .get_chain_head(&mut verify_tx, ws.id.into_uuid())
        .await
        .expect("get chain head")
        .expect("head exists");

    assert_eq!(head.workspace_id, ws.id.into_uuid());
    assert_eq!(head.head_sequence_num, 2);

    let events = audit_store
        .fetch_audit_events(&mut verify_tx, ws.id.into_uuid())
        .await
        .expect("fetch events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].sequence_num, 1);
    assert_eq!(events[0].event_type, "workspace.created");
    assert_eq!(events[1].sequence_num, 2);
    assert_eq!(events[1].event_type, "membership.created");

    // Verify cryptographic hash chain integrity using AuditChainHasher
    let hasher = AuditChainHasher;
    assert!(
        hasher.verify_chain_integrity(&events).is_ok(),
        "Hash chain verification must pass"
    );

    verify_tx.commit().await.expect("commit verify tx");
    test_db.close().await.expect("drop test db");
}

#[tokio::test]
async fn test_privileged_mutation_rollback_on_audit_append_failure() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool();
    let audit_store = PostgresAuditStore::new();

    // Setup org, principal, program, workspace
    let mut tx = pool.begin().await.unwrap();
    let org = Organization::new("Secure Bank", "secure-bank").unwrap();
    OrganizationRepository::insert(&mut tx, &org).await.unwrap();

    let admin_principal =
        Principal::new(org.id, PrincipalType::User, None::<&str>, "Admin").unwrap();
    PrincipalRepository::insert(&mut tx, &admin_principal)
        .await
        .unwrap();

    let target_principal =
        Principal::new(org.id, PrincipalType::User, None::<&str>, "Target").unwrap();
    PrincipalRepository::insert(&mut tx, &target_principal)
        .await
        .unwrap();

    let program = Program::new(org.id, "Vault", "vault", None::<&str>).unwrap();
    ProgramRepository::insert(&mut tx, &program).await.unwrap();

    let ws = WorkspaceInitializationService::create_workspace_with_audit_head(
        &mut tx,
        &audit_store,
        program.id,
        org.id,
        "Gold Vault",
        "gold-vault",
        Some(admin_principal.id),
        None,
    )
    .await
    .unwrap();

    tx.commit().await.unwrap();

    // Now attempt a privileged capability grant, but simulate an audit failure in the transaction
    let mut failing_tx = pool.begin().await.unwrap();

    // 1. Insert capability grant directly
    let grant = w014_authz::grant::CapabilityGrant::new(
        ws.id,
        target_principal.id,
        Capability::OverrideBlock,
        Some(admin_principal.id),
        Some(Utc::now() + Duration::hours(1)),
    )
    .unwrap();
    CapabilityGrantRepository::insert(&mut failing_tx, &grant)
        .await
        .unwrap();

    // 2. Inject an invalid audit event that violates sequence or DB check (empty action triggers chk_audit_events_action_non_empty)
    let bad_audit_params = AppendAuditParams {
        workspace_id: ws.id.into_uuid(),
        event_type: "capability.granted".to_string(),
        actor_principal_id: Some(admin_principal.id.into_uuid()),
        action: "   ".to_string(), // Empty action violates DB check constraint!
        resource_type: "capability_grant".to_string(),
        resource_id: grant.id.to_string(),
        payload: serde_json::json!({}),
        correlation_id: None,
    };

    let audit_res = audit_store
        .append_audit_event(&mut failing_tx, bad_audit_params)
        .await;
    assert!(
        audit_res.is_err(),
        "Audit append MUST fail on empty action constraint"
    );

    // 3. Roll back transaction
    failing_tx.rollback().await.unwrap();

    // 4. Verify capability grant was NOT committed to the database
    let mut check_tx = pool.begin().await.unwrap();
    let grant_lookup = CapabilityGrantRepository::get_by_id(&mut check_tx, grant.id)
        .await
        .unwrap();
    assert!(
        grant_lookup.is_none(),
        "Privileged mutation MUST be rolled back when audit append fails!"
    );
    check_tx.commit().await.unwrap();
    test_db.close().await.expect("drop test db");
}

#[tokio::test]
async fn test_capability_grant_and_one_way_revocation_lifecycle() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool();
    let audit_store = PostgresAuditStore::new();

    let mut tx = pool.begin().await.unwrap();
    let org = Organization::new("Gov Org", "gov-org").unwrap();
    OrganizationRepository::insert(&mut tx, &org).await.unwrap();

    let grantor = Principal::new(org.id, PrincipalType::User, None::<&str>, "Grantor").unwrap();
    PrincipalRepository::insert(&mut tx, &grantor)
        .await
        .unwrap();

    let grantee = Principal::new(org.id, PrincipalType::User, None::<&str>, "Grantee").unwrap();
    PrincipalRepository::insert(&mut tx, &grantee)
        .await
        .unwrap();

    let prog = Program::new(org.id, "Security", "security", None::<&str>).unwrap();
    ProgramRepository::insert(&mut tx, &prog).await.unwrap();

    let ws = WorkspaceInitializationService::create_workspace_with_audit_head(
        &mut tx,
        &audit_store,
        prog.id,
        org.id,
        "Sec Ops",
        "sec-ops",
        Some(grantor.id),
        None,
    )
    .await
    .unwrap();

    // 1. Grant special authority: OVERRIDE_BLOCK
    let grant = CapabilityGrantService::grant_capability_with_audit(
        &mut tx,
        &audit_store,
        ws.id,
        grantee.id,
        Capability::OverrideBlock,
        Some(grantor.id),
        Some(Utc::now() + Duration::hours(2)),
        Some(grantor.id),
        Some("corr-grant-01".to_string()),
    )
    .await
    .unwrap();
    assert_eq!(grant.capability, Capability::OverrideBlock);

    // 2. Grant special authority: RIGHTS_REVIEW
    let grant2 = CapabilityGrantService::grant_capability_with_audit(
        &mut tx,
        &audit_store,
        ws.id,
        grantee.id,
        Capability::RightsReview,
        Some(grantor.id),
        Some(Utc::now() + Duration::hours(2)),
        Some(grantor.id),
        Some("corr-grant-02".to_string()),
    )
    .await
    .unwrap();
    assert_eq!(grant2.capability, Capability::RightsReview);

    // 3. Revoke OVERRIDE_BLOCK
    CapabilityGrantService::revoke_capability_with_audit(
        &mut tx,
        &audit_store,
        grant.id,
        Some(grantor.id),
        Some("corr-revoke-01".to_string()),
    )
    .await
    .unwrap();

    tx.commit().await.unwrap();

    // 4. Verify revocation state in DB
    let mut check_tx = pool.begin().await.unwrap();
    let fetched_grant = CapabilityGrantRepository::get_by_id(&mut check_tx, grant.id)
        .await
        .unwrap()
        .unwrap();
    assert!(fetched_grant.is_expired_at(Utc::now() + Duration::seconds(1)));

    let events = audit_store
        .fetch_audit_events(&mut check_tx, ws.id.into_uuid())
        .await
        .unwrap();
    // 1 workspace.created + 2 capability.granted + 1 capability.revoked = 4
    assert_eq!(events.len(), 4);
    assert_eq!(events[3].event_type, "capability.revoked");
    check_tx.commit().await.unwrap();
    test_db.close().await.expect("drop test db");
}

#[tokio::test]
async fn test_oidc_identity_persistence_and_lookup() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool();
    let mut tx = pool.begin().await.unwrap();

    let org = Organization::new("Oidc Org", "oidc-org").unwrap();
    OrganizationRepository::insert(&mut tx, &org).await.unwrap();

    let principal = Principal::new(org.id, PrincipalType::User, None::<&str>, "Oidc User").unwrap();
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .unwrap();

    let claims = serde_json::json!({
        "iss": "https://accounts.google.com",
        "sub": "google-sub-998877",
        "email": "user@google.com",
        "email_verified": true
    });

    let oidc_id = OidcPersistenceService::link_identity(
        &mut tx,
        principal.id,
        "https://accounts.google.com",
        "google-sub-998877",
        Some("user@google.com"),
        claims.clone(),
    )
    .await
    .unwrap();

    assert_eq!(oidc_id.principal_id, principal.id);
    assert_eq!(oidc_id.issuer, "https://accounts.google.com");
    assert_eq!(oidc_id.subject, "google-sub-998877");

    let found = OidcPersistenceService::find_by_issuer_subject(
        &mut tx,
        "https://accounts.google.com",
        "google-sub-998877",
    )
    .await
    .unwrap()
    .expect("identity found");

    assert_eq!(found.id, oidc_id.id);
    assert_eq!(found.principal_id, principal.id);
    assert_eq!(found.email.as_deref(), Some("user@google.com"));

    tx.commit().await.unwrap();
    test_db.close().await.expect("drop test db");
}

#[tokio::test]
async fn test_session_persistence_rotation_and_revocation() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool();
    let mut tx = pool.begin().await.unwrap();

    let org = Organization::new("Session Org", "session-org").unwrap();
    OrganizationRepository::insert(&mut tx, &org).await.unwrap();

    let principal =
        Principal::new(org.id, PrincipalType::User, None::<&str>, "Session User").unwrap();
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .unwrap();

    let now = Utc::now();
    let idle_expires = now + Duration::hours(12);
    let abs_expires = now + Duration::days(7);
    let initial_hash = b"initial_handle_hash_123456789012".to_vec();
    let csrf_hash = b"csrf_secret_hash_123456789012345".to_vec();

    let session = SessionService::create_session(
        &mut tx,
        principal.id,
        initial_hash.clone(),
        csrf_hash,
        idle_expires,
        abs_expires,
    )
    .await
    .unwrap();

    assert_eq!(session.principal_id, principal.id);
    assert_eq!(session.handle_hash, initial_hash);

    // 1. Query by handle hash
    let found = SessionService::get_session_by_handle_hash(&mut tx, &initial_hash)
        .await
        .unwrap()
        .expect("session found");
    assert_eq!(found.session_id, session.session_id);

    // 2. Rotate session
    let new_idle_expires = Utc::now() + Duration::hours(12);
    let new_abs_expires = Utc::now() + Duration::days(7);
    let rotated_hash = b"rotated_handle_hash_678901234567".to_vec();
    let rotation = SessionService::rotate_session(
        &mut tx,
        session.session_id,
        rotated_hash.clone(),
        new_idle_expires,
        new_abs_expires,
        Some("127.0.0.2"),
    )
    .await
    .unwrap();
    assert_eq!(rotation.session_id, session.session_id);
    assert_eq!(rotation.old_handle_hash, initial_hash);
    assert_eq!(rotation.new_handle_hash, rotated_hash);

    // Verify old hash no longer resolves active session
    let old_lookup = SessionService::get_session_by_handle_hash(&mut tx, &initial_hash)
        .await
        .unwrap();
    assert!(old_lookup.is_none());

    // Verify new hash resolves updated session
    let new_lookup = SessionService::get_session_by_handle_hash(&mut tx, &rotated_hash)
        .await
        .unwrap()
        .expect("new token resolves");
    assert_eq!(new_lookup.session_id, session.session_id);

    // 3. Revoke session
    SessionService::revoke_session(&mut tx, session.session_id)
        .await
        .unwrap();

    let revoked = SessionRepository::get_by_id(&mut tx, session.session_id)
        .await
        .unwrap()
        .unwrap();
    assert!(revoked.revoked_at.is_some());
    assert!(!revoked.is_active_at(Utc::now()));

    tx.commit().await.unwrap();
    test_db.close().await.expect("drop test db");
}

#[tokio::test]
async fn test_oidc_transaction_single_use_consumption() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool();
    let mut tx = pool.begin().await.unwrap();

    let expires = Utc::now() + Duration::minutes(15);
    let stored = OidcPersistenceService::store_transaction(
        &mut tx,
        "state_tok_abc",
        "nonce_tok_123",
        Some("pkce_verif_xyz"),
        "https://app.example.com/auth/callback",
        expires,
    )
    .await
    .unwrap();

    assert_eq!(stored.state_token, "state_tok_abc");

    // Consume transaction (single-use)
    let consumed = OidcPersistenceService::consume_transaction(&mut tx, "state_tok_abc")
        .await
        .unwrap()
        .expect("transaction consumed");
    assert_eq!(consumed.id, stored.id);

    // Second consumption must return None
    let replay = OidcPersistenceService::consume_transaction(&mut tx, "state_tok_abc")
        .await
        .unwrap();
    assert!(replay.is_none(), "Transaction MUST be single-use only");

    tx.commit().await.unwrap();
    test_db.close().await.expect("drop test db");
}

#[tokio::test]
async fn test_idempotency_store_consumption_invariants() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool();
    let idempotency_store = PostgresIdempotencyStore::new();

    let payload = serde_json::json!({"action": "create_item", "item_id": 42});
    let req_hash = IdempotencyCoordinator::compute_payload_hash(&payload);

    let mut tx = pool.begin().await.unwrap();

    // 1. Initial acquisition
    let check1 = IdempotencyCoordinator::evaluate_key(
        &mut tx,
        &idempotency_store,
        None,
        "req-idemp-001",
        &req_hash,
        300,
    )
    .await
    .unwrap();

    let record_id = match check1 {
        IdempotencyCheckResult::Acquired { record_id } => record_id,
        other => panic!("Expected Acquired, got {:?}", other),
    };

    // 2. Mark as completed
    let resp_body = serde_json::json!({"status": "created", "id": 42});
    IdempotencyCoordinator::complete_record(
        &mut tx,
        &idempotency_store,
        record_id,
        201,
        None,
        Some(resp_body.clone()),
    )
    .await
    .unwrap();

    // 3. Replay with identical hash returns Replay result
    let replay_check = IdempotencyCoordinator::evaluate_key(
        &mut tx,
        &idempotency_store,
        None,
        "req-idemp-001",
        &req_hash,
        300,
    )
    .await
    .unwrap();

    match replay_check {
        IdempotencyCheckResult::Replay {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 201);
            assert_eq!(body, Some(resp_body));
        }
        other => panic!("Expected Replay, got {:?}", other),
    }

    // 4. Request with DIFFERENT payload and same key returns Mismatch
    let diff_payload = serde_json::json!({"action": "create_item", "item_id": 99});
    let diff_hash = IdempotencyCoordinator::compute_payload_hash(&diff_payload);

    let mismatch_check = IdempotencyCoordinator::evaluate_key(
        &mut tx,
        &idempotency_store,
        None,
        "req-idemp-001",
        &diff_hash,
        300,
    )
    .await
    .unwrap();

    match mismatch_check {
        IdempotencyCheckResult::Mismatch {
            expected_hash,
            actual_hash,
        } => {
            assert_eq!(expected_hash, req_hash);
            assert_eq!(actual_hash, diff_hash);
        }
        other => panic!("Expected Mismatch, got {:?}", other),
    }

    tx.commit().await.unwrap();
    test_db.close().await.expect("drop test db");
}

#[tokio::test]
async fn test_staged_fks_and_boundary_checks() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool();

    // 1. Verify workspaces.current_source_state_id is nullable and has NO foreign key
    let ws_fk_count: i64 = sqlx::query_scalar(
        "SELECT count(*)
         FROM information_schema.table_constraints tc
         JOIN information_schema.key_column_usage kcu
           ON tc.constraint_name = kcu.constraint_name
         WHERE tc.table_name = 'workspaces'
           AND kcu.column_name = 'current_source_state_id'
           AND tc.constraint_type = 'FOREIGN KEY'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        ws_fk_count, 0,
        "STAGED FK VIOLATION: current_source_state_id must NOT have a foreign key in W1"
    );

    // 2. Verify audit_events.job_id is nullable and has NO foreign key
    let job_fk_count: i64 = sqlx::query_scalar(
        "SELECT count(*)
         FROM information_schema.table_constraints tc
         JOIN information_schema.key_column_usage kcu
           ON tc.constraint_name = kcu.constraint_name
         WHERE tc.table_name = 'audit_events'
           AND kcu.column_name = 'job_id'
           AND tc.constraint_type = 'FOREIGN KEY'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        job_fk_count, 0,
        "STAGED FK VIOLATION: audit_events.job_id must NOT have a foreign key in W1"
    );

    // 3. Verify W2 jobs execution tables do not exist
    let jobs_table_count: i64 = sqlx::query_scalar(
        "SELECT count(*)
         FROM information_schema.tables
         WHERE table_schema = 'public'
           AND table_name = 'jobs'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        jobs_table_count, 0,
        "W2 BOUNDARY VIOLATION: jobs table must not exist in W1"
    );

    test_db.close().await.expect("drop test db");
}
