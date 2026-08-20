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
use sha2::{Digest, Sha256};
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
use w014_domain::principal::Principal;
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
    assert_eq!(fetched_org.name(), "Acme Corp");
    assert_eq!(fetched_org.slug, "acme-corp");

    // 2. Create Principal (email is informational snapshot)
    let principal = Principal::new("Alice Smith", Some("alice@acme.com")).expect("valid principal");
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .expect("insert principal");

    let fetched_principal = PrincipalRepository::get_by_id(&mut tx, principal.id)
        .await
        .expect("get principal")
        .expect("principal exists");
    assert_eq!(fetched_principal.id, principal.id);
    assert_eq!(fetched_principal.email.as_deref(), Some("alice@acme.com"));
    assert_eq!(fetched_principal.display_name, "Alice Smith");
    assert!(fetched_principal.is_active());

    // 3. Create Program
    let program = Program::new(org.id, "Engineering", "engineering").expect("valid program");
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
        "Bob Builder",
        Some("bob@global.com"),
    )
    .await
    .expect("create principal");
    let program =
        WorkspaceInitializationService::create_program(&mut tx, org.id, "Logistics", "logistics")
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

    // 3. Atomically assign workspace admin
    let membership = WorkspaceInitializationService::assign_workspace_admin_with_audit(
        &mut ws_tx,
        &audit_store,
        ws.id,
        principal.id,
        Some(principal.id),
        Some("corr-init-002".to_string()),
    )
    .await
    .expect("assign admin");
    assert_eq!(membership.role(), MembershipRole::Admin);

    ws_tx.commit().await.expect("commit ws tx");

    // 4. Verify authoritative audit chain state
    let mut verify_tx = pool.begin().await.expect("begin verify tx");
    let head = audit_store
        .get_chain_head(&mut verify_tx, ws.id.into_uuid())
        .await
        .expect("get chain head")
        .expect("head exists");

    assert_eq!(head.workspace_id, ws.id.into_uuid());
    assert_eq!(head.last_sequence, 2);

    let events = audit_store
        .fetch_audit_events(&mut verify_tx, ws.id.into_uuid())
        .await
        .expect("fetch events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].sequence, 1);
    assert_eq!(events[0].action_code, "WORKSPACE_CREATE");
    assert_eq!(events[1].sequence, 2);
    assert_eq!(events[1].action_code, "MEMBERSHIP_CREATE");

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

    let admin_principal = Principal::new("Admin", None::<&str>).unwrap();
    PrincipalRepository::insert(&mut tx, &admin_principal)
        .await
        .unwrap();

    let target_principal = Principal::new("Target", None::<&str>).unwrap();
    PrincipalRepository::insert(&mut tx, &target_principal)
        .await
        .unwrap();

    let program = Program::new(org.id, "Vault", "vault").unwrap();
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
        actor_type: "principal".to_string(),
        actor_id: Some(admin_principal.id.into_uuid()),
        authority_snapshot: serde_json::json!({}),
        action_code: "   ".to_string(), // Empty action violates DB check constraint!
        entity_type: "capability_grant".to_string(),
        entity_id: grant.id.to_string(),
        entity_version: Some(1),
        request_id: None,
        correlation_id: None,
        job_id: None,
        source_state_hash: None,
        before_ref: None,
        after_ref: None,
        metadata: serde_json::json!({}),
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

    let grantor = Principal::new("Grantor", None::<&str>).unwrap();
    PrincipalRepository::insert(&mut tx, &grantor)
        .await
        .unwrap();

    let grantee = Principal::new("Grantee", None::<&str>).unwrap();
    PrincipalRepository::insert(&mut tx, &grantee)
        .await
        .unwrap();

    let prog = Program::new(org.id, "Security", "security").unwrap();
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
    assert!(!fetched_grant.is_active_at(Utc::now() + Duration::seconds(1)));

    let events = audit_store
        .fetch_audit_events(&mut check_tx, ws.id.into_uuid())
        .await
        .unwrap();
    // 1 workspace.created + 2 capability.granted + 1 capability.revoked = 4
    assert_eq!(events.len(), 4);
    assert_eq!(events[3].action_code, "CAPABILITY_REVOKE");
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

    let principal = Principal::new("Oidc User", None::<&str>).unwrap();
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .unwrap();

    let oidc_id = OidcPersistenceService::link_identity(
        &mut tx,
        principal.id,
        "https://accounts.google.com",
        "google-sub-998877",
        Some("user@google.com"),
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
    assert_eq!(found.email_at_link.as_deref(), Some("user@google.com"));

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

    let principal = Principal::new("Session User", None::<&str>).unwrap();
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
        Some("periodic"),
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
    let state_hash = Sha256::digest(b"state_tok_abc").to_vec();
    let nonce_hash = Sha256::digest(b"nonce_tok_123").to_vec();
    let stored = OidcPersistenceService::store_transaction(
        &mut tx,
        state_hash.clone(),
        nonce_hash,
        Some(b"pkce_verif_xyz".to_vec()),
        "https://app.example.com/auth/callback",
        expires,
    )
    .await
    .unwrap();

    assert_eq!(stored.state_hash, state_hash);

    // Consume transaction (single-use)
    let consumed = OidcPersistenceService::consume_transaction(&mut tx, &state_hash)
        .await
        .unwrap()
        .expect("transaction consumed");
    assert_eq!(consumed.id, stored.id);

    // Second consumption must return None
    let replay = OidcPersistenceService::consume_transaction(&mut tx, &state_hash)
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

    let mut tx = pool.begin().await.unwrap();
    let principal = Principal::new("Idemp User", None::<&str>).unwrap();
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .unwrap();

    let payload = serde_json::json!({"action": "create_item", "item_id": 42});
    let req_hash = IdempotencyCoordinator::compute_payload_hash(&payload);
    let key_hash = IdempotencyCoordinator::compute_key_hash(b"test_secret", "req-idemp-001");

    // 1. Initial acquisition
    let check1 = IdempotencyCoordinator::evaluate_key(
        &mut tx,
        &idempotency_store,
        None,
        principal.id,
        "TEST_ROUTE",
        &key_hash,
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
        Some(resp_body.clone()),
    )
    .await
    .unwrap();

    // 3. Replay with identical hash returns Replay result
    let replay_check = IdempotencyCoordinator::evaluate_key(
        &mut tx,
        &idempotency_store,
        None,
        principal.id,
        "TEST_ROUTE",
        &key_hash,
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
        principal.id,
        "TEST_ROUTE",
        &key_hash,
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
            assert_eq!(expected_hash, hex::encode(&req_hash));
            assert_eq!(actual_hash, hex::encode(&diff_hash));
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

#[tokio::test]
async fn test_workspace_authz_resolver_end_to_end() {
    use w014_application::authz::WorkspaceAuthzResolver;
    use w014_authz::authority::SpecialAuthority;
    use w014_authz::error::AuthzError;

    let test_db = provision_migrated_db().await;
    let pool = test_db.pool();
    let audit_store = PostgresAuditStore::new();

    let mut tx = pool.begin().await.unwrap();
    let org = Organization::new("Authz Org", "authz-org").unwrap();
    OrganizationRepository::insert(&mut tx, &org).await.unwrap();

    let prog = Program::new(org.id, "Core Platform", "core-platform").unwrap();
    ProgramRepository::insert(&mut tx, &prog).await.unwrap();

    let creator = Principal::new("Creator", None::<&str>).unwrap();
    PrincipalRepository::insert(&mut tx, &creator)
        .await
        .unwrap();

    let member_user = Principal::new("Member User", None::<&str>).unwrap();
    PrincipalRepository::insert(&mut tx, &member_user)
        .await
        .unwrap();

    let non_member_user = Principal::new("Non Member", None::<&str>).unwrap();
    PrincipalRepository::insert(&mut tx, &non_member_user)
        .await
        .unwrap();

    let mut inactive_user = Principal::new("Inactive User", None::<&str>).unwrap();
    inactive_user.deactivate();
    PrincipalRepository::insert(&mut tx, &inactive_user)
        .await
        .unwrap();

    // Create workspace with creator as actor
    let ws = WorkspaceInitializationService::create_workspace_with_audit_head(
        &mut tx,
        &audit_store,
        prog.id,
        org.id,
        "Authz WS",
        "authz-ws",
        Some(creator.id),
        None,
    )
    .await
    .unwrap();

    // Assign creator as Admin
    w014_application::services::MembershipService::add_member_with_audit(
        &mut tx,
        &audit_store,
        ws.id,
        creator.id,
        MembershipRole::Admin,
        Some(creator.id),
        Some("corr-add-creator".to_string()),
    )
    .await
    .unwrap();

    // Add member_user with Operator role
    w014_application::services::MembershipService::add_member_with_audit(
        &mut tx,
        &audit_store,
        ws.id,
        member_user.id,
        MembershipRole::Operator,
        Some(creator.id),
        Some("corr-add-member".to_string()),
    )
    .await
    .unwrap();

    // Add inactive_user with Reader role
    w014_application::services::MembershipService::add_member_with_audit(
        &mut tx,
        &audit_store,
        ws.id,
        inactive_user.id,
        MembershipRole::Reader,
        Some(creator.id),
        Some("corr-add-inactive".to_string()),
    )
    .await
    .unwrap();

    // Add an explicit active grant for OVERRIDE_BLOCK to member_user
    let now = Utc::now();
    CapabilityGrantService::grant_capability_with_audit(
        &mut tx,
        &audit_store,
        ws.id,
        member_user.id,
        Capability::OverrideBlock,
        Some(creator.id),
        Some(now + Duration::hours(2)),
        Some(creator.id),
        Some("corr-grant-override".to_string()),
    )
    .await
    .unwrap();

    // Add an expired grant for RIGHTS_REVIEW to member_user
    let expired_grant = w014_authz::grant::CapabilityGrant::reconstruct(
        w014_authz::CapabilityGrantId::new(),
        Some(ws.id),
        None,
        member_user.id,
        Capability::RightsReview,
        Some(creator.id),
        now - Duration::hours(3),
        Some(now - Duration::hours(1)),
        None,
        None,
        None,
    );
    CapabilityGrantRepository::insert(&mut tx, &expired_grant)
        .await
        .unwrap();

    // 1. Resolve context for creator (Admin)
    let creator_ctx = WorkspaceAuthzResolver::resolve(&mut tx, ws.id, creator.id, now)
        .await
        .unwrap();
    assert_eq!(creator_ctx.membership_role(), MembershipRole::Admin);
    assert!(creator_ctx.can_admin_workspace());
    assert!(creator_ctx.can_read_workspace());
    assert!(creator_ctx.can_write_workspace());
    assert!(creator_ctx.can_read_audit());
    // Admin does NOT have special authorities by default
    assert!(!creator_ctx.can_override_block());
    assert!(!creator_ctx.can_review_rights());
    assert!(!creator_ctx.can_activate_rule());
    assert!(!creator_ctx.can_grant_authority());

    // 2. Resolve context for member_user (Operator + OVERRIDE_BLOCK grant)
    let member_ctx = WorkspaceAuthzResolver::resolve(&mut tx, ws.id, member_user.id, now)
        .await
        .unwrap();
    assert_eq!(member_ctx.membership_role(), MembershipRole::Operator);
    assert!(member_ctx.can_read_workspace());
    assert!(member_ctx.can_write_workspace());
    assert!(!member_ctx.can_admin_workspace());
    assert!(
        member_ctx.can_override_block(),
        "Explicit active grant must resolve"
    );
    assert!(
        !member_ctx.can_review_rights(),
        "Expired grant must NOT resolve"
    );
    assert!(member_ctx.has_special_authority(SpecialAuthority::OverrideBlock));
    assert!(!member_ctx.has_special_authority(SpecialAuthority::RightsReview));

    // 3. Resolve context for non_member_user -> Fails closed with NoMembership
    let non_member_res =
        WorkspaceAuthzResolver::resolve(&mut tx, ws.id, non_member_user.id, now).await;
    assert!(matches!(
        non_member_res,
        Err(w014_application::ApplicationError::Authz(
            AuthzError::NoMembership { .. }
        ))
    ));

    // 4. Resolve context for inactive_user -> Fails closed with InactivePrincipal
    let inactive_res = WorkspaceAuthzResolver::resolve(&mut tx, ws.id, inactive_user.id, now).await;
    assert!(matches!(
        inactive_res,
        Err(w014_application::ApplicationError::Authz(
            AuthzError::InactivePrincipal(_)
        ))
    ));

    tx.commit().await.unwrap();
    test_db.close().await.expect("drop test db");
}
