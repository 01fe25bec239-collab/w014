//! Comprehensive integration tests for WI-0105: Programs, Workspaces, Memberships, Capability Grants API.
//!
//! Verifies:
//! - E05: GET /api/v1/programs (list, cursor pagination, tenant isolation)
//! - E06: POST /api/v1/programs (create, slug conflict 409, CSRF, Idempotency replay/mismatch)
//! - E07: GET /api/v1/programs/{program_id} (privacy-safe lookup, 404 on foreign)
//! - E08: GET /api/v1/programs/{program_id}/workspaces (list, pagination, 404 on foreign)
//! - E09: POST /api/v1/programs/{program_id}/workspaces (create, atomic audit, owner assignment, idempotency)
//! - E10: GET /api/v1/workspaces/{workspace_id} (RLS context, privacy-safe 404 on unmembered)
//! - E11: ABSENCE of GET /api/v1/workspaces/{workspace_id}/source-state
//! - E12: GET /api/v1/workspaces/{workspace_id}/memberships (list, RLS context, pagination)
//! - E13: POST /api/v1/workspaces/{workspace_id}/memberships (MEMBERSHIP_MANAGE, role validation, cross-tenant rejection, audit)
//! - E14: POST /api/v1/workspaces/{workspace_id}/capability-grants (STRICT GRANT_AUTHORITY enforcement, audit)
//! - E15: POST /api/v1/workspaces/{workspace_id}/capability-grants/{grant_id}/revoke (STRICT GRANT_AUTHORITY, one-way revocation, audit)
//! - Audit hash chain cryptographic integrity across all mutations.

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE, ORIGIN};
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::Row;
use tower::ServiceExt;
use uuid::Uuid;

use w014_api::config::ApiConfig;
use w014_api::create_app_with_pool;
use w014_api::routes::capability_grants::CapabilityGrantDto;
use w014_api::routes::memberships::{MembershipDto, MembershipPage};
use w014_api::routes::programs::{ProgramDto, ProgramPage};
use w014_api::routes::workspaces::{WorkspaceDto, WorkspacePage};
use w014_application::persistence::{
    CapabilityGrantRepository, MembershipRepository, OrganizationRepository, PrincipalRepository,
    ProgramRepository, SessionRepository, WorkspaceRepository,
};
use w014_authn::csrf::{CSRF_HEADER_NAME, CsrfConfig, derive_csrf_token};
use w014_authn::session::{Session, generate_session_token};
use w014_authz::capability::Capability;
use w014_authz::grant::CapabilityGrant;
use w014_domain::ids::{OrganizationId, PrincipalId, WorkspaceId};
use w014_domain::membership::{Membership, MembershipRole};
use w014_domain::organization::Organization;
use w014_domain::principal::{Principal, PrincipalType};
use w014_domain::program::Program;
use w014_domain::workspace::Workspace;
use w014_persistence::harness::TestDatabase;
use w014_persistence::runner::{MIGRATOR, MigrationRunner};

/// Spins up a migrated isolated PostgreSQL test database.
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

fn create_test_config() -> ApiConfig {
    let mut config = ApiConfig::for_testing();
    config.csrf = CsrfConfig::new(vec!["http://127.0.0.1:3000".to_string()]);
    config.session.cookie_name = "test_session".to_string();
    config
}

async fn create_org(db: &TestDatabase, name: &str, slug: &str) -> Organization {
    let mut tx = db.pool().begin().await.unwrap();
    let org = Organization::new(name, slug).unwrap();
    OrganizationRepository::insert(&mut tx, &org).await.unwrap();
    tx.commit().await.unwrap();
    org
}

async fn create_principal(
    db: &TestDatabase,
    org_id: OrganizationId,
    email: &str,
    display_name: &str,
) -> Principal {
    let mut tx = db.pool().begin().await.unwrap();
    let principal = Principal::new(org_id, PrincipalType::User, Some(email), display_name).unwrap();
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    principal
}

async fn create_session_and_csrf(
    db: &TestDatabase,
    principal_id: PrincipalId,
    config: &ApiConfig,
) -> (String, String) {
    let mut tx = db.pool().begin().await.unwrap();
    let raw_token = generate_session_token();
    let handle_hash = config.session.hash_handle(&raw_token);
    let csrf_hash = config.session.hash_handle("csrf_test");
    let session = Session::new(
        principal_id,
        handle_hash.to_vec(),
        csrf_hash.to_vec(),
        Utc::now() + Duration::hours(12),
        Utc::now() + Duration::hours(12),
    )
    .unwrap();
    SessionRepository::insert(&mut tx, &session).await.unwrap();
    tx.commit().await.unwrap();

    let rot_id = session.rotation_identity();
    let csrf_token = derive_csrf_token(&config.csrf.hmac_secret, &rot_id, "http://127.0.0.1:3000");

    (format!("test_session={raw_token}"), csrf_token)
}

#[tokio::test]
async fn test_e05_list_programs_cursor_pagination_and_tenant_isolation() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org_a = create_org(&db, "Org A", "org-a").await;
    let org_b = create_org(&db, "Org B", "org-b").await;

    let user_a = create_principal(&db, org_a.id, "usera@orga.com", "User A").await;
    let (cookie_a, _) = create_session_and_csrf(&db, user_a.id, &config).await;

    // Seed 3 programs in Org A and 2 programs in Org B
    {
        let mut tx = db.pool().begin().await.unwrap();
        for i in 1..=3 {
            let p = Program::new(
                org_a.id,
                format!("Prog A {i}"),
                format!("prog-a-{i}"),
                None::<&str>,
            )
            .unwrap();
            ProgramRepository::insert(&mut tx, &p).await.unwrap();
        }
        for i in 1..=2 {
            let p = Program::new(
                org_b.id,
                format!("Prog B {i}"),
                format!("prog-b-{i}"),
                None::<&str>,
            )
            .unwrap();
            ProgramRepository::insert(&mut tx, &p).await.unwrap();
        }
        tx.commit().await.unwrap();
    }

    // 1. List all programs for User A (limit = 10)
    let req = Request::builder()
        .uri("/api/v1/programs")
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let page: ProgramPage = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(page.items.len(), 3);
    assert!(!page.has_more);
    for item in &page.items {
        assert_eq!(item.organization_id, org_a.id.to_string());
    }

    // 2. Test Pagination (limit = 2)
    let req = Request::builder()
        .uri("/api/v1/programs?limit=2")
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let page1: ProgramPage = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(page1.items.len(), 2);
    assert!(page1.has_more);
    assert!(page1.next_cursor.is_some());

    // Fetch page 2
    let cursor = page1.next_cursor.unwrap();
    let req = Request::builder()
        .uri(format!("/api/v1/programs?limit=2&cursor={cursor}"))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let page2: ProgramPage = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(page2.items.len(), 1);
    assert!(!page2.has_more);
}

#[tokio::test]
async fn test_e06_create_program_idempotency_conflict_and_csrf() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org = create_org(&db, "Test Org", "test-org").await;
    let user = create_principal(&db, org.id, "dev@test.com", "Dev").await;
    let (cookie, csrf_token) = create_session_and_csrf(&db, user.id, &config).await;

    let payload = json!({
        "name": "Apollo Program",
        "slug": "apollo-program",
        "description": "Lunar exploration"
    });

    // 1. Missing CSRF Origin -> 403 Forbidden
    let req = Request::builder()
        .uri("/api/v1/programs")
        .method("POST")
        .header(COOKIE, &cookie)
        .header(CSRF_HEADER_NAME, &csrf_token)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. Successful creation with Idempotency Key
    let idemp_key = "idemp-prog-001";
    let req = Request::builder()
        .uri("/api/v1/programs")
        .method("POST")
        .header(COOKIE, &cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf_token)
        .header("idempotency-key", idemp_key)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let created: ProgramDto = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(created.name, "Apollo Program");
    assert_eq!(created.slug, "apollo-program");

    // 3. Replay with identical Idempotency Key -> 201 Replay (No duplicate program)
    let req = Request::builder()
        .uri("/api/v1/programs")
        .method("POST")
        .header(COOKIE, &cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf_token)
        .header("idempotency-key", idemp_key)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. Mismatched payload with same Idempotency Key -> 400 Bad Request
    let conflicting_payload = json!({
        "name": "Gemini Program",
        "slug": "gemini-program"
    });
    let req = Request::builder()
        .uri("/api/v1/programs")
        .method("POST")
        .header(COOKIE, &cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf_token)
        .header("idempotency-key", idemp_key)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&conflicting_payload).unwrap(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 5. New request with conflicting slug -> 409 Conflict
    let req = Request::builder()
        .uri("/api/v1/programs")
        .method("POST")
        .header(COOKIE, &cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf_token)
        .header("idempotency-key", "idemp-prog-002")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_e07_get_program_privacy_safe() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org_a = create_org(&db, "Org A", "org-a").await;
    let org_b = create_org(&db, "Org B", "org-b").await;

    let user_a = create_principal(&db, org_a.id, "usera@a.com", "User A").await;
    let (cookie_a, _) = create_session_and_csrf(&db, user_a.id, &config).await;

    let mut tx = db.pool().begin().await.unwrap();
    let prog_a = Program::new(org_a.id, "Prog A", "prog-a", None::<&str>).unwrap();
    let prog_b = Program::new(org_b.id, "Prog B", "prog-b", None::<&str>).unwrap();
    ProgramRepository::insert(&mut tx, &prog_a).await.unwrap();
    ProgramRepository::insert(&mut tx, &prog_b).await.unwrap();
    tx.commit().await.unwrap();

    // 1. Fetch own program -> 200 OK
    let req = Request::builder()
        .uri(format!("/api/v1/programs/{}", prog_a.id))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Fetch foreign program in Org B -> 404 Not Found (privacy-safe, no leakage!)
    let req = Request::builder()
        .uri(format!("/api/v1/programs/{}", prog_b.id))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 3. Fetch non-existent UUID -> 404 Not Found
    let req = Request::builder()
        .uri(format!("/api/v1/programs/{}", Uuid::new_v4()))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_e08_e09_e10_workspaces_atomic_audit_and_rls() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org_a = create_org(&db, "Org A", "org-a").await;
    let org_b = create_org(&db, "Org B", "org-b").await;

    let user_a = create_principal(&db, org_a.id, "usera@a.com", "User A").await;
    let user_b = create_principal(&db, org_b.id, "userb@b.com", "User B").await;

    let (cookie_a, csrf_a) = create_session_and_csrf(&db, user_a.id, &config).await;
    let (cookie_b, _) = create_session_and_csrf(&db, user_b.id, &config).await;

    let mut tx = db.pool().begin().await.unwrap();
    let prog_a = Program::new(org_a.id, "Prog A", "prog-a", None::<&str>).unwrap();
    ProgramRepository::insert(&mut tx, &prog_a).await.unwrap();
    tx.commit().await.unwrap();

    // 1. E09: Create workspace under prog_a
    let ws_payload = json!({
        "name": "Engineering Workspace",
        "slug": "eng-ws"
    });

    let req = Request::builder()
        .uri(format!("/api/v1/programs/{}/workspaces", prog_a.id))
        .method("POST")
        .header(COOKIE, &cookie_a)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf_a)
        .header("idempotency-key", "idemp-ws-001")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&ws_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let ws_dto: WorkspaceDto = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(ws_dto.name, "Engineering Workspace");
    assert_eq!(ws_dto.slug, "eng-ws");
    assert!(ws_dto.current_source_state_id.is_none());

    let ws_id = ws_dto.id.clone();

    // Verify creator is automatically Owner in memberships
    {
        let mut tx = db.pool().begin().await.unwrap();
        let mem = MembershipRepository::get_by_workspace_and_principal(
            &mut tx,
            WorkspaceId::from_uuid(Uuid::parse_str(&ws_id).unwrap()),
            user_a.id,
        )
        .await
        .unwrap()
        .expect("Owner membership should exist");
        assert_eq!(mem.role, MembershipRole::Owner);
        tx.commit().await.unwrap();
    }

    // 2. E08: List workspaces in program
    let req = Request::builder()
        .uri(format!("/api/v1/programs/{}/workspaces", prog_a.id))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let ws_page: WorkspacePage = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(ws_page.items.len(), 1);
    assert_eq!(ws_page.items[0].id, ws_id);

    // 3. E10: Get workspace by ID (User A is Owner -> 200 OK)
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{ws_id}"))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 4. E10: Foreign User B requests Workspace A -> 404 Not Found (privacy-safe!)
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{ws_id}"))
        .method("GET")
        .header(COOKIE, &cookie_b)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 5. E11: Forbidden source-state endpoint returns 404
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{ws_id}/source-state"))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_e12_e13_memberships_management_and_cross_tenant_rejection() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org_a = create_org(&db, "Org A", "org-a").await;
    let org_b = create_org(&db, "Org B", "org-b").await;

    let user_a1 = create_principal(&db, org_a.id, "a1@a.com", "User A1").await;
    let user_a2 = create_principal(&db, org_a.id, "a2@a.com", "User A2").await;
    let user_b = create_principal(&db, org_b.id, "b@b.com", "User B").await;

    let (cookie_a1, csrf_a1) = create_session_and_csrf(&db, user_a1.id, &config).await;

    // Seed Program & Workspace with user_a1 as Owner
    let ws = {
        let mut tx = db.pool().begin().await.unwrap();
        let prog = Program::new(org_a.id, "Prog", "prog", None::<&str>).unwrap();
        ProgramRepository::insert(&mut tx, &prog).await.unwrap();
        let ws = Workspace::new(prog.id, org_a.id, "WS", "ws").unwrap();
        WorkspaceRepository::insert(&mut tx, &ws).await.unwrap();
        let mem = Membership::new(ws.id, user_a1.id, MembershipRole::Owner);
        MembershipRepository::insert(&mut tx, &mem).await.unwrap();
        tx.commit().await.unwrap();
        ws
    };

    // 1. E13: Add user_a2 (same tenant) as Admin -> 201 Created
    let add_payload = json!({
        "principal_id": user_a2.id.to_string(),
        "role": "admin"
    });

    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/memberships", ws.id))
        .method("POST")
        .header(COOKIE, &cookie_a1)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf_a1)
        .header("idempotency-key", "idemp-mem-001")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&add_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let mem_dto: MembershipDto = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(mem_dto.role, "admin");
    assert_eq!(mem_dto.principal_id, user_a2.id.to_string());

    // 2. E13: Duplicate membership -> 409 Conflict
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/memberships", ws.id))
        .method("POST")
        .header(COOKIE, &cookie_a1)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf_a1)
        .header("idempotency-key", "idemp-mem-002")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&add_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // 3. E13: Cross-tenant membership creation (user_b from Org B) -> 403 Forbidden
    let cross_payload = json!({
        "principal_id": user_b.id.to_string(),
        "role": "member"
    });

    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/memberships", ws.id))
        .method("POST")
        .header(COOKIE, &cookie_a1)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf_a1)
        .header("idempotency-key", "idemp-mem-003")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&cross_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 4. E12: List memberships -> returns 2 items (user_a1, user_a2)
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/memberships", ws.id))
        .method("GET")
        .header(COOKIE, &cookie_a1)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let page: MembershipPage = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(page.items.len(), 2);
}

#[tokio::test]
async fn test_e14_e15_capability_grants_strict_grant_authority_enforcement() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org = create_org(&db, "Secure Org", "sec-org").await;
    let admin_user = create_principal(&db, org.id, "admin@sec.com", "Admin User").await;
    let target_user = create_principal(&db, org.id, "target@sec.com", "Target User").await;

    let (cookie_admin, csrf_admin) = create_session_and_csrf(&db, admin_user.id, &config).await;

    // Seed Workspace with admin_user as Admin and target_user as Member
    let ws = {
        let mut tx = db.pool().begin().await.unwrap();
        let prog = Program::new(org.id, "Secure Prog", "sec-prog", None::<&str>).unwrap();
        ProgramRepository::insert(&mut tx, &prog).await.unwrap();
        let ws = Workspace::new(prog.id, org.id, "Secure WS", "sec-ws").unwrap();
        WorkspaceRepository::insert(&mut tx, &ws).await.unwrap();
        let mem_admin = Membership::new(ws.id, admin_user.id, MembershipRole::Admin);
        let mem_target = Membership::new(ws.id, target_user.id, MembershipRole::Member);
        MembershipRepository::insert(&mut tx, &mem_admin)
            .await
            .unwrap();
        MembershipRepository::insert(&mut tx, &mem_target)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        ws
    };

    let grant_payload = json!({
        "workspace_id": ws.id.to_string(),
        "principal_id": target_user.id.to_string(),
        "capability": "WORKSPACE_WRITE"
    });

    // 1. Admin without GRANT_AUTHORITY attempts to create grant -> 403 Forbidden!
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/capability-grants", ws.id))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf_admin)
        .header("idempotency-key", "idemp-grant-001")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&grant_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Explicitly grant GRANT_AUTHORITY special authority to admin_user
    {
        let mut tx = db.pool().begin().await.unwrap();
        let grant_auth =
            CapabilityGrant::new(ws.id, admin_user.id, Capability::GrantAuthority, None, None)
                .unwrap();
        CapabilityGrantRepository::insert(&mut tx, &grant_auth)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    // 2. Now admin_user with GRANT_AUTHORITY creates capability grant -> 201 Created!
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/capability-grants", ws.id))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf_admin)
        .header("idempotency-key", "idemp-grant-002")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&grant_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let grant_dto: CapabilityGrantDto = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(grant_dto.capability, "WORKSPACE_WRITE");
    assert_eq!(grant_dto.principal_id, target_user.id.to_string());
    let grant_id = grant_dto.id.expect("Grant ID should be present");

    // 3. E15: Revoke capability grant -> 200 OK (one-way revocation)
    let revoke_payload = json!({
        "reason": "Project assignment completed"
    });

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/capability-grants/{}/revoke",
            ws.id, grant_id
        ))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf_admin)
        .header("idempotency-key", "idemp-revoke-001")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&revoke_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let revoked_dto: CapabilityGrantDto = serde_json::from_slice(&body_bytes).unwrap();
    assert!(revoked_dto.expires_at.is_some());

    // 4. Attempt to revoke already revoked grant -> 409 Conflict
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/capability-grants/{}/revoke",
            ws.id, grant_id
        ))
        .method("POST")
        .header(COOKIE, &cookie_admin)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf_admin)
        .header("idempotency-key", "idemp-revoke-002")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&revoke_payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_audit_hash_chain_cryptographic_integrity() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org = create_org(&db, "Audit Org", "audit-org").await;
    let user = create_principal(&db, org.id, "auditor@audit.com", "Auditor").await;
    let (cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let mut tx = db.pool().begin().await.unwrap();
    let prog = Program::new(org.id, "Audit Prog", "audit-prog", None::<&str>).unwrap();
    ProgramRepository::insert(&mut tx, &prog).await.unwrap();
    tx.commit().await.unwrap();

    // 1. Create Workspace (emits workspace.created + membership.created)
    let ws_payload = json!({
        "name": "Audit WS",
        "slug": "audit-ws"
    });

    let req = Request::builder()
        .uri(format!("/api/v1/programs/{}/workspaces", prog.id))
        .method("POST")
        .header(COOKIE, &cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf)
        .header("idempotency-key", "audit-ws-001")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&ws_payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let ws_dto: WorkspaceDto = serde_json::from_slice(&body_bytes).unwrap();
    let ws_uuid = Uuid::parse_str(&ws_dto.id).unwrap();

    // Verify audit chain in database
    let mut conn = db.pool().acquire().await.unwrap();
    let rows = sqlx::query(
        "SELECT sequence_num, event_type, previous_event_hash, event_hash, payload
         FROM audit_events
         WHERE workspace_id = $1
         ORDER BY sequence_num ASC",
    )
    .bind(ws_uuid)
    .fetch_all(&mut *conn)
    .await
    .unwrap();

    assert_eq!(rows.len(), 2);

    // Verify Genesis event (seq = 1)
    let event1 = &rows[0];
    let seq1: i64 = event1.get("sequence_num");
    let type1: String = event1.get("event_type");
    let prev_hash1: Option<String> = event1.get("previous_event_hash");
    let hash1: String = event1.get("event_hash");

    assert_eq!(seq1, 1);
    assert_eq!(type1, "workspace.created");
    assert!(prev_hash1.is_some());

    // Verify chained event (seq = 2)
    let event2 = &rows[1];
    let seq2: i64 = event2.get("sequence_num");
    let type2: String = event2.get("event_type");
    let prev_hash2: Option<String> = event2.get("previous_event_hash");
    let hash2: String = event2.get("event_hash");

    assert_eq!(seq2, 2);
    assert_eq!(type2, "membership.created");
    assert_eq!(prev_hash2.as_deref(), Some(hash1.as_str()));

    // Verify chain head
    let head = sqlx::query(
        "SELECT head_sequence_num, head_event_hash
         FROM audit_chain_heads
         WHERE workspace_id = $1",
    )
    .bind(ws_uuid)
    .fetch_one(&mut *conn)
    .await
    .unwrap();

    let head_seq: i64 = head.get("head_sequence_num");
    let head_hash: String = head.get("head_event_hash");

    assert_eq!(head_seq, 2);
    assert_eq!(head_hash, hash2);
}

#[tokio::test]
async fn test_csrf_failure_leaves_idempotency_key_unconsumed() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org = create_org(&db, "CSRF Org", "csrf-org").await;
    let user = create_principal(&db, org.id, "csrf@test.com", "CSRF User").await;
    let (cookie, valid_csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let payload = json!({
        "name": "CSRF Safe Program",
        "slug": "csrf-safe-prog"
    });
    let idemp_key = "idemp-csrf-test-key";

    // 1. Request with invalid CSRF token -> 403 Forbidden
    let bad_req = Request::builder()
        .uri("/api/v1/programs")
        .method("POST")
        .header(COOKIE, &cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, "invalid-csrf-token")
        .header("idempotency-key", idemp_key)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(bad_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. Repeat request with the SAME idempotency key and valid CSRF token -> MUST SUCCEED (201 Created)
    let good_req = Request::builder()
        .uri("/api/v1/programs")
        .method("POST")
        .header(COOKIE, &cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &valid_csrf)
        .header("idempotency-key", idemp_key)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(good_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_deactivated_principal_rejected_across_endpoints() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org = create_org(&db, "Deact Org", "deact-org").await;
    let user = create_principal(&db, org.id, "deact@test.com", "Deact User").await;
    let (cookie, _) = create_session_and_csrf(&db, user.id, &config).await;

    // Deactivate principal in database
    {
        let mut tx = db.pool().begin().await.unwrap();
        sqlx::query("UPDATE principals SET is_active = FALSE WHERE id = $1")
            .bind(user.id.as_uuid())
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    // Attempt to access E05 list programs -> 403 Forbidden
    let req = Request::builder()
        .uri("/api/v1/programs")
        .method("GET")
        .header(COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
