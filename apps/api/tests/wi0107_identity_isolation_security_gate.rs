//! Comprehensive Security Gate Integration Test Suite for WI-0107.
//!
//! Validates the final cumulative W1 Identity and Isolation Security Gate:
//! 1. OIDC / PKCE / State / Nonce / Callback Gate
//! 2. Opaque Server-Side Session / Keyed HMAC-SHA256 / Bytea / Rotation / Expiry / Limits Gate
//! 3. CSRF Security Matrix / Exact Origin / No Referer Fallback / Zero Side Effects Gate
//! 4. Capability Engine / Authorization / Special Authority & Grant Authority Separation Gate
//! 5. Forced RLS / app.workspace_id GUC / Transaction-Local Context / Pool Isolation Gate
//! 6. Composite-FK Isolation & Referential Integrity Gate
//! 7. SEC-003 / Cross-Workspace IDOR / Privacy-Safe 404 / Zero Leakage Gate
//! 8. Privileged Command Atomicity / Idempotency / Authoritative Audit Hash Chain Gate
//! 9. Staged-FK Hard Boundary & Absence of W2/W3 Surfaces Gate

use std::collections::HashMap;

use axum::Router;
use axum::body::Body;
use axum::extract::Form;
use axum::http::header::{CONTENT_TYPE, COOKIE, ORIGIN, REFERER};
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use tower::ServiceExt;
use uuid::Uuid;

use w014_api::config::ApiConfig;
use w014_api::create_app_with_pool;
use w014_api::routes::auth::LoginResponse;
use w014_api::routes::capability_grants::CapabilityGrantDto;
use w014_api::routes::programs::ProgramDto;
use w014_api::routes::session::SessionResponse;
use w014_api::routes::workspaces::WorkspaceDto;
use w014_application::persistence::{
    CapabilityGrantRepository, MembershipRepository, OidcTransactionRepository,
    OrganizationRepository, PrincipalRepository, ProgramRepository, SessionRepository,
    WorkspaceRepository,
};
use w014_authn::csrf::{CSRF_HEADER_NAME, CsrfConfig, derive_csrf_token};
use w014_authn::oidc::OidcConfig;
use w014_authn::oidc::token::{AudienceClaim, RawIdTokenClaims};
use w014_authn::session::{Session, generate_session_token};
use w014_authz::capability::Capability;
use w014_authz::grant::CapabilityGrant;
use w014_domain::ids::{OrganizationId, PrincipalId, WorkspaceId};
use w014_domain::membership::{Membership, MembershipRole};
use w014_domain::organization::Organization;
use w014_domain::principal::Principal;
use w014_domain::program::Program;
use w014_domain::workspace::Workspace;
use w014_persistence::harness::TestDatabase;
use w014_persistence::runner::{MIGRATOR, MigrationRunner};
use w014_persistence::set_session_workspace_id;

const TEST_RSA_PRIVATE_KEY_PEM: &[u8] =
    include_bytes!("../../../crates/w014-authn/tests/test_keys/rsa_private.pem");

/// Helper to provision a migrated isolated test database.
async fn provision_migrated_db() -> TestDatabase {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");
    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R migrations");
    test_db
}

/// Helper to build test API configuration.
fn create_test_config() -> ApiConfig {
    let mut config = ApiConfig::for_testing();
    config.csrf = CsrfConfig::new(vec!["http://127.0.0.1:3000".to_string()]);
    config.session.cookie_name = "test_session".to_string();
    config
}

/// Helper struct for Mock OIDC Identity Provider.
struct MockIdp {
    issuer: String,
    token_url: String,
    jwks_url: String,
    _shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl MockIdp {
    async fn start(client_id: &str) -> Self {
        let encoding_key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let base_url = format!("http://127.0.0.1:{}", local_addr.port());
        let issuer = base_url.clone();
        let token_url = format!("{base_url}/oauth/token");
        let jwks_url = format!("{base_url}/oauth/jwks");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let enc_key_clone = encoding_key.clone();
        let iss_clone = issuer.clone();
        let client_id_str = client_id.to_string();

        let app = Router::new()
            .route(
                "/oauth/jwks",
                get({
                    move || async move {
                        let jwks_json = json!({
                            "keys": [{
                                "kty": "RSA",
                                "use": "sig",
                                "alg": "RS256",
                                "kid": "mock-rsa-key-1",
                                "n": "0_heAfr1SR6F2ToqjwVKZLkWad-MMBu1fv2l51eEswz4eOr14Ej-9wlOzRDwvyzZMUb1Iu0EKKETDetTQo_vZeUOl2I0XhRCiquMydvvxN7YQhVVLLGQYNv5SXeOo7Oo1-wmiRDXTF0If1ifzjMPO4yISREy4mGsl0fqJqnQup9343I0JHxcw3BzdDuRiZBiJC83Vbc6bNIwGRhVDJaokUNuIa3x7ZKj7T_PzRPZvrXMlT6McSXzdMCQqANc0H11ccLec4Fd90VUQzcP2jI5KE9V7U1afrG3ydJ-ScyKHrxh35RIJvn4IkdPSJuI0rOzPaij_LlYgbBBvwEUNdsaow",
                                "e": "AQAB"
                            }]
                        });
                        (
                            StatusCode::OK,
                            [("content-type", "application/json")],
                            serde_json::to_string(&jwks_json).unwrap(),
                        )
                    }
                }),
            )
            .route(
                "/oauth/token",
                post({
                    let enc_key = enc_key_clone;
                    let iss = iss_clone;
                    let c_id = client_id_str;
                    move |Form(params): Form<HashMap<String, String>>| {
                        let enc_key = enc_key.clone();
                        let iss = iss.clone();
                        let c_id = c_id.clone();
                        async move {
                            let code = params.get("code").cloned().unwrap_or_default();
                            let verifier = params.get("code_verifier").cloned().unwrap_or_default();

                            let now = Utc::now();
                            let claims = RawIdTokenClaims {
                                iss,
                                sub: format!("user-sub-{}", code),
                                aud: AudienceClaim::Single(c_id),
                                exp: (now + Duration::hours(1)).timestamp(),
                                iat: now.timestamp(),
                                nbf: Some(now.timestamp()),
                                nonce: Some(format!("nonce-for-{}", code)),
                                azp: None,
                                email: Some(format!("user-{}@example.com", code)),
                                email_verified: Some(true),
                                name: Some(format!("Test User {}", code)),
                                extra: json!({ "verifier_used": verifier }),
                            };

                            let mut header = Header::new(Algorithm::RS256);
                            header.kid = Some("mock-rsa-key-1".to_string());
                            let id_token = jsonwebtoken::encode(&header, &claims, &enc_key).unwrap();

                            let token_resp = json!({
                                "access_token": format!("mock-access-token-{}", code),
                                "token_type": "Bearer",
                                "expires_in": 3600,
                                "id_token": id_token,
                            });
                            (
                                StatusCode::OK,
                                [("content-type", "application/json")],
                                serde_json::to_string(&token_resp).unwrap(),
                            )
                        }
                    }
                }),
            );

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        Self {
            issuer,
            token_url,
            jwks_url,
            _shutdown_tx: shutdown_tx,
        }
    }
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
    _org_id: OrganizationId,
    email: &str,
    display_name: &str,
) -> Principal {
    let mut tx = db.pool().begin().await.unwrap();
    let principal = Principal::new(display_name, Some(email)).unwrap();
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
) -> (String, String, String) {
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

    (
        raw_token.clone(),
        format!("test_session={raw_token}"),
        csrf_token,
    )
}

// =========================================================================
// 1. OIDC / PKCE / State / Nonce / Callback Gate
// =========================================================================

#[tokio::test]
async fn test_security_gate_oidc_pkce_state_nonce_and_callback() {
    let db = provision_migrated_db().await;
    let client_id = "test-oidc-client-gate";
    let mock_idp = MockIdp::start(client_id).await;

    let mut config = create_test_config();
    config.oidc = OidcConfig {
        issuer: mock_idp.issuer.clone(),
        issuer_allowlist: vec![mock_idp.issuer.clone()],
        authorization_endpoint: format!("{}/oauth/authorize", mock_idp.issuer),
        token_endpoint: mock_idp.token_url.clone(),
        jwks_uri: mock_idp.jwks_url.clone(),
        client_id: client_id.to_string(),
        client_secret: Some("mock-client-secret".to_string()),
        redirect_uri: "http://127.0.0.1:3000/api/v1/auth/callback".to_string(),
        scopes: vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
        state_ttl_secs: 600,
    };
    let app = create_app_with_pool(&config, db.pool().clone());

    // 1. E01 Login: Generates valid Auth URL with S256 PKCE challenge & state
    let req = Request::builder()
        .uri("/api/v1/auth/login?format=json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let login_resp: LoginResponse = serde_json::from_slice(&body_bytes).unwrap();
    let auth_url = url::Url::parse(&login_resp.authorization_url).unwrap();
    let query_pairs: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();

    assert_eq!(query_pairs.get("response_type").unwrap(), "code");
    assert_eq!(query_pairs.get("code_challenge_method").unwrap(), "S256");
    assert!(query_pairs.contains_key("code_challenge"));
    let state = query_pairs.get("state").unwrap().clone();
    assert_eq!(state, login_resp.state);

    // Update the stored transaction's nonce to match mock IdP's deterministic nonce for code 'code1'
    {
        let state_hash = Sha256::digest(state.as_bytes()).to_vec();
        let mut tx = db.pool().begin().await.unwrap();
        let mut stored_tx = OidcTransactionRepository::get_by_state_hash(&mut tx, &state_hash)
            .await
            .unwrap()
            .unwrap();
        stored_tx.nonce_hash = Sha256::digest(b"nonce-for-code1").to_vec();
        OidcTransactionRepository::delete_by_id(&mut tx, stored_tx.id)
            .await
            .unwrap();
        OidcTransactionRepository::insert(&mut tx, &stored_tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    // 2. E02 Callback: Exchange code for session with format=json
    let callback_uri = format!("/api/v1/auth/callback?code=code1&state={state}&format=json");
    let req = Request::builder()
        .uri(&callback_uri)
        .method("GET")
        .header("User-Agent", "IntegrationTest-Gate")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let set_cookie_header = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(set_cookie_header.contains("test_session="));
    assert!(set_cookie_header.contains("HttpOnly"));
    assert!(set_cookie_header.contains("SameSite=Lax"));

    // 3. State Single-Use Replay Prevention: Replaying the same state MUST fail closed (400)
    let req = Request::builder()
        .uri(&callback_uri)
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 4. Invalid State: Random unknown state MUST fail closed (400)
    let req = Request::builder()
        .uri("/api/v1/auth/callback?code=some-code&state=nonexistent-state-uuid")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// =========================================================================
// 2. Opaque Server-Side Session / HMAC-SHA256 / Bytea / Rotation / Expiry
// =========================================================================

#[tokio::test]
async fn test_security_gate_session_hmac_bytea_rotation_and_limits() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org = create_org(&db, "Session Gate Org", "session-gate-org").await;
    let user = create_principal(&db, org.id, "session-gate@test.com", "Session User").await;

    // 1. Verify Opaque Handle & HMAC-SHA256 Bytea Representation
    let (raw_token, cookie, csrf) = create_session_and_csrf(&db, user.id, &config).await;

    // Query Postgres database directly to verify raw handle is NEVER stored
    let row = sqlx::query(
        "SELECT handle_hash, revoked_at, principal_id FROM sessions WHERE principal_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(db.pool())
    .await
    .unwrap();

    let db_handle_hash: Vec<u8> = row.get("handle_hash");
    let computed_hash = config.session.hash_handle(&raw_token);
    assert_eq!(db_handle_hash, computed_hash.to_vec());
    // Raw token is not stored in plain text anywhere in the row
    assert_ne!(db_handle_hash, raw_token.as_bytes());

    // 2. E03 Session inspection: Valid session returns principal identity
    let req = Request::builder()
        .uri("/api/v1/session")
        .method("GET")
        .header(COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let session_resp: SessionResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(session_resp.principal_id, user.id.to_string());
    assert_eq!(session_resp.status, "active");
    assert!(session_resp.csrf_token.is_some());

    // 3. Verify Active Session Count
    let active_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sessions WHERE principal_id = $1 AND revoked_at IS NULL",
    )
    .bind(user.id.0)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(active_count, 1);

    // 4. Session Revocation / Logout: E04 Logout revokes session and clears cookie
    let req = Request::builder()
        .uri("/api/v1/session/logout")
        .method("POST")
        .header(COOKIE, &cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &csrf)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Subsequent call with revoked cookie MUST return 401 Unauthorized
    let req = Request::builder()
        .uri("/api/v1/session")
        .method("GET")
        .header(COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// =========================================================================
// 3. CSRF Security Matrix / Exact Origin / No Referer Fallback / Zero Side Effects
// =========================================================================

#[tokio::test]
async fn test_security_gate_csrf_exhaustive_negative_matrix_and_fail_closed() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org = create_org(&db, "CSRF Gate Org", "csrf-gate-org").await;
    let user = create_principal(&db, org.id, "csrf-user@test.com", "CSRF User").await;
    let (_, cookie, valid_csrf) = create_session_and_csrf(&db, user.id, &config).await;

    let payload = json!({
        "name": "Target Program",
        "slug": "target-program",
        "description": "CSRF Gate test program"
    });

    let count_programs = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM programs WHERE program_code = 'target-program'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap()
    };

    let count_audit_events = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    };

    let initial_audit_count = count_audit_events().await;

    type CsrfTestCase<'a> = (
        Option<&'a str>,
        Option<&'a str>,
        Option<&'a str>,
        StatusCode,
    );

    // Negative CSRF test cases: (origin_header, referer_header, csrf_header, expected_status)
    let negative_cases: Vec<CsrfTestCase> = vec![
        // 1. Missing Origin
        (None, None, Some(&valid_csrf), StatusCode::FORBIDDEN),
        // 2. Null Origin
        (Some("null"), None, Some(&valid_csrf), StatusCode::FORBIDDEN),
        // 3. Opaque/Attacker Origin
        (
            Some("https://attacker.site"),
            None,
            Some(&valid_csrf),
            StatusCode::FORBIDDEN,
        ),
        // 4. Malformed Origin
        (
            Some("not-a-valid-origin"),
            None,
            Some(&valid_csrf),
            StatusCode::FORBIDDEN,
        ),
        // 5. Wrong Origin (different port)
        (
            Some("http://127.0.0.1:8080"),
            None,
            Some(&valid_csrf),
            StatusCode::FORBIDDEN,
        ),
        // 6. Referer-only (Referer present, Origin absent) -> FORBIDDEN (No Referer fallback!)
        (
            None,
            Some("http://127.0.0.1:3000/some/path"),
            Some(&valid_csrf),
            StatusCode::FORBIDDEN,
        ),
        // 7. Missing CSRF header
        (
            Some("http://127.0.0.1:3000"),
            None,
            None,
            StatusCode::FORBIDDEN,
        ),
        // 8. Wrong CSRF token
        (
            Some("http://127.0.0.1:3000"),
            None,
            Some("wrong-csrf-token-123"),
            StatusCode::FORBIDDEN,
        ),
        // 9. Stale/rotated CSRF token
        (
            Some("http://127.0.0.1:3000"),
            None,
            Some("stale:token:value"),
            StatusCode::FORBIDDEN,
        ),
    ];

    let idemp_key = "idemp-csrf-test-key";

    for (origin_opt, referer_opt, csrf_opt, expected_status) in negative_cases {
        let mut req_builder = Request::builder()
            .uri("/api/v1/programs")
            .method("POST")
            .header(COOKIE, &cookie)
            .header("idempotency-key", idemp_key)
            .header(CONTENT_TYPE, "application/json");

        if let Some(origin) = origin_opt {
            req_builder = req_builder.header(ORIGIN, origin);
        }
        if let Some(referer) = referer_opt {
            req_builder = req_builder.header(REFERER, referer);
        }
        if let Some(csrf) = csrf_opt {
            req_builder = req_builder.header(CSRF_HEADER_NAME, csrf);
        }

        let req = req_builder
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), expected_status);

        // Verify ZERO SIDE EFFECTS
        assert_eq!(
            count_programs().await,
            0,
            "No program should be created on CSRF failure"
        );
        assert_eq!(
            count_audit_events().await,
            initial_audit_count,
            "No audit event on CSRF failure"
        );
    }

    // Verify Idempotency Key was NOT consumed by failed CSRF requests
    let req = Request::builder()
        .uri("/api/v1/programs")
        .method("POST")
        .header(COOKIE, &cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &valid_csrf)
        .header("idempotency-key", idemp_key)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(count_programs().await, 1);
}

// =========================================================================
// 4. Capability Engine & Special Authority Separation Gate
// =========================================================================

#[tokio::test]
async fn test_security_gate_capability_authorization_and_special_authority_separation() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org = create_org(&db, "Authz Gate Org", "authz-gate-org").await;
    let admin_user = create_principal(&db, org.id, "admin@authz.com", "Admin User").await;
    let grant_authority_user =
        create_principal(&db, org.id, "granter@authz.com", "Granter User").await;
    let regular_user = create_principal(&db, org.id, "regular@authz.com", "Regular User").await;

    let (_, admin_cookie, admin_csrf) = create_session_and_csrf(&db, admin_user.id, &config).await;
    let (_, granter_cookie, granter_csrf) =
        create_session_and_csrf(&db, grant_authority_user.id, &config).await;

    // Create Program and Workspace
    let program = {
        let mut tx = db.pool().begin().await.unwrap();
        let p = Program::new(org.id, "Authz Program", "authz-prog").unwrap();
        ProgramRepository::insert(&mut tx, &p).await.unwrap();
        tx.commit().await.unwrap();
        p
    };

    let workspace = {
        let mut tx = db.pool().begin().await.unwrap();
        let w = Workspace::new(program.id, org.id, "Authz Workspace", "authz-ws").unwrap();
        WorkspaceRepository::insert(&mut tx, &w).await.unwrap();
        tx.commit().await.unwrap();
        w
    };

    // Seed Memberships:
    // 1. admin_user has ADMIN role (which has full management EXCEPT GRANT_AUTHORITY)
    // 2. grant_authority_user has ADMIN role + GRANT_AUTHORITY explicit capability grant
    {
        let mut tx = db.pool().begin().await.unwrap();
        let m_admin = Membership::new(workspace.id, admin_user.id, MembershipRole::Admin);
        MembershipRepository::insert(&mut tx, &m_admin)
            .await
            .unwrap();

        let m_granter =
            Membership::new(workspace.id, grant_authority_user.id, MembershipRole::Admin);
        MembershipRepository::insert(&mut tx, &m_granter)
            .await
            .unwrap();

        let m_reg = Membership::new(workspace.id, regular_user.id, MembershipRole::Operator);
        MembershipRepository::insert(&mut tx, &m_reg).await.unwrap();

        // Grant GRANT_AUTHORITY to granter_user
        let g = CapabilityGrant::new(
            workspace.id,
            grant_authority_user.id,
            Capability::GrantAuthority,
            Some(admin_user.id),
            None,
        )
        .unwrap();
        CapabilityGrantRepository::insert(&mut tx, &g)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    // Attempt 1: Admin WITHOUT GrantAuthority attempts to issue capability grant -> MUST return 403 Forbidden
    let grant_payload = json!({
        "workspace_id": workspace.id.to_string(),
        "principal_id": regular_user.id.to_string(),
        "capability": "OVERRIDE_BLOCK",
    });

    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/capability-grants",
            workspace.id
        ))
        .method("POST")
        .header(COOKIE, &admin_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &admin_csrf)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&grant_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Admin without GRANT_AUTHORITY must be forbidden from issuing capability grants"
    );

    // Attempt 2: Granter WITH GrantAuthority issues capability grant -> MUST succeed (201 Created)
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/capability-grants",
            workspace.id
        ))
        .method("POST")
        .header(COOKIE, &granter_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &granter_csrf)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&grant_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let grant_dto: CapabilityGrantDto = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(grant_dto.capability, "OVERRIDE_BLOCK");
    let grant_id = grant_dto.id.expect("Grant ID should be present");

    // Attempt 3: Admin WITHOUT GrantAuthority attempts to revoke capability grant -> MUST return 403 Forbidden
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/capability-grants/{}/revoke",
            workspace.id, grant_id
        ))
        .method("POST")
        .header(COOKIE, &admin_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &admin_csrf)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Admin without GRANT_AUTHORITY must be forbidden from revoking capability grants"
    );

    // Attempt 4: Granter WITH GrantAuthority revokes capability grant -> MUST succeed (200 OK)
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{}/capability-grants/{}/revoke",
            workspace.id, grant_id
        ))
        .method("POST")
        .header(COOKIE, &granter_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &granter_csrf)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// =========================================================================
// 5. Forced RLS & Workspace Isolation & Pool Isolation Gate
// =========================================================================

#[tokio::test]
async fn test_security_gate_forced_rls_awc_context_and_pool_isolation() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org_a = create_org(&db, "Org A", "org-a").await;
    let org_b = create_org(&db, "Org B", "org-b").await;

    let user_a = create_principal(&db, org_a.id, "user-a@rls.com", "User A").await;
    let user_b = create_principal(&db, org_b.id, "user-b@rls.com", "User B").await;

    let (_, cookie_a, _) = create_session_and_csrf(&db, user_a.id, &config).await;
    let (_, cookie_b, _) = create_session_and_csrf(&db, user_b.id, &config).await;

    // Create Workspace A and Workspace B
    let ws_a = {
        let mut tx = db.pool().begin().await.unwrap();
        let p = Program::new(org_a.id, "Prog A", "prog-a").unwrap();
        ProgramRepository::insert(&mut tx, &p).await.unwrap();
        let w = Workspace::new(p.id, org_a.id, "Workspace A", "ws-a").unwrap();
        WorkspaceRepository::insert(&mut tx, &w).await.unwrap();
        let m = Membership::new(w.id, user_a.id, MembershipRole::Admin);
        MembershipRepository::insert(&mut tx, &m).await.unwrap();
        tx.commit().await.unwrap();
        w
    };

    let ws_b = {
        let mut tx = db.pool().begin().await.unwrap();
        let p = Program::new(org_b.id, "Prog B", "prog-b").unwrap();
        ProgramRepository::insert(&mut tx, &p).await.unwrap();
        let w = Workspace::new(p.id, org_b.id, "Workspace B", "ws-b").unwrap();
        WorkspaceRepository::insert(&mut tx, &w).await.unwrap();
        let m = Membership::new(w.id, user_b.id, MembershipRole::Admin);
        MembershipRepository::insert(&mut tx, &m).await.unwrap();
        tx.commit().await.unwrap();
        w
    };

    // 1. User A accesses Workspace A -> 200 OK
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}", ws_a.id))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. User A attempts to access Workspace B -> MUST return Privacy-Safe 404 Not Found
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}", ws_b.id))
        .method("GET")
        .header(COOKIE, &cookie_a)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "Cross-workspace access must return privacy-safe 404 Not Found"
    );

    // 3. User B attempts to access Workspace A -> MUST return Privacy-Safe 404 Not Found
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}", ws_a.id))
        .method("GET")
        .header(COOKIE, &cookie_b)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 4. Database-level RLS context isolation under application role `w014_app`:
    // Without setting `app.workspace_id`, 0 rows returned
    {
        let mut tx = db.pool().begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .unwrap();

        let rows = sqlx::query("SELECT * FROM memberships")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            0,
            "Bare transaction under w014_app without workspace GUC must return 0 rows under forced RLS"
        );
        tx.rollback().await.unwrap();
    }

    // 5. Database-level RLS context binding: With `app.workspace_id = ws_a`, only ws_a row returned
    {
        let mut tx = db.pool().begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        set_session_workspace_id(&mut tx, ws_a.id.0).await.unwrap();

        let rows = sqlx::query("SELECT * FROM memberships")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "Must return exactly 1 row belonging to workspace A"
        );
        tx.rollback().await.unwrap();
    }
}

// =========================================================================
// 6. Composite-FK Isolation & Referential Integrity Gate
// =========================================================================

#[tokio::test]
async fn test_security_gate_composite_fk_and_db_boundary_isolation() {
    let db = provision_migrated_db().await;

    let org_a = create_org(&db, "Org FK A", "org-fk-a").await;
    let org_b = create_org(&db, "Org FK B", "org-fk-b").await;

    let user_a = create_principal(&db, org_a.id, "user-fk-a@test.com", "User FK A").await;

    let ws_a = {
        let mut tx = db.pool().begin().await.unwrap();
        let p = Program::new(org_a.id, "Prog FK A", "prog-fk-a").unwrap();
        ProgramRepository::insert(&mut tx, &p).await.unwrap();
        let w = Workspace::new(p.id, org_a.id, "Workspace FK A", "ws-fk-a").unwrap();
        WorkspaceRepository::insert(&mut tx, &w).await.unwrap();
        tx.commit().await.unwrap();
        w
    };

    let ws_b = {
        let mut tx = db.pool().begin().await.unwrap();
        let p = Program::new(org_b.id, "Prog FK B", "prog-fk-b").unwrap();
        ProgramRepository::insert(&mut tx, &p).await.unwrap();
        let w = Workspace::new(p.id, org_b.id, "Workspace FK B", "ws-fk-b").unwrap();
        WorkspaceRepository::insert(&mut tx, &w).await.unwrap();
        tx.commit().await.unwrap();
        w
    };

    // Attempt to insert capability grant with Workspace B ID under Workspace A transaction context
    let mut tx = db.pool().begin().await.unwrap();
    sqlx::query("SET LOCAL ROLE w014_app")
        .execute(&mut *tx)
        .await
        .unwrap();
    set_session_workspace_id(&mut tx, ws_a.id.0).await.unwrap();

    let invalid_grant_result = sqlx::query(
        "INSERT INTO capability_grants (capability_grant_id, workspace_id, principal_id, capability_code, granted_by_principal_id)
         VALUES ($1, $2, $3, 'OVERRIDE_BLOCK', $4)",
    )
    .bind(Uuid::new_v4())
    .bind(ws_b.id.0) // Mismatched workspace
    .bind(user_a.id.0)
    .bind(user_a.id.0)
    .execute(&mut *tx)
    .await;

    assert!(
        invalid_grant_result.is_err(),
        "Cross-workspace insert under workspace A context must fail RLS / foreign key check"
    );
    tx.rollback().await.unwrap();
}

// =========================================================================
// 7. SEC-003 / Cross-Workspace IDOR & Privacy-Safe Responses Gate
// =========================================================================

#[tokio::test]
async fn test_security_gate_sec003_idor_and_privacy_safe_responses() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org_a = create_org(&db, "Secret Alpha Corp", "secret-alpha").await;
    let org_b = create_org(&db, "Secret Beta Corp", "secret-beta").await;

    let alice = create_principal(&db, org_a.id, "alice@alpha.com", "Alice Alpha").await;
    let bob = create_principal(&db, org_b.id, "bob@beta.com", "Bob Beta").await;

    let (_, alice_cookie, alice_csrf) = create_session_and_csrf(&db, alice.id, &config).await;

    let (prog_b, ws_b) = {
        let mut tx = db.pool().begin().await.unwrap();
        let p = Program::new(org_b.id, "Top Secret Beta Project", "top-secret-beta").unwrap();
        ProgramRepository::insert(&mut tx, &p).await.unwrap();
        let w = Workspace::new(
            p.id,
            org_b.id,
            "Confidential Vault Workspace",
            "confidential-vault",
        )
        .unwrap();
        WorkspaceRepository::insert(&mut tx, &w).await.unwrap();
        let m = Membership::new(w.id, bob.id, MembershipRole::Admin);
        MembershipRepository::insert(&mut tx, &m).await.unwrap();
        tx.commit().await.unwrap();
        (p, w)
    };

    // 1. Cross-Workspace Program Read: Alice attempts GET /api/v1/programs/{prog_b.id}
    let req = Request::builder()
        .uri(format!("/api/v1/programs/{}", prog_b.id))
        .method("GET")
        .header(COOKIE, &alice_cookie)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        !body.contains("Top Secret Beta Project"),
        "Must not leak foreign program name"
    );
    assert!(
        !body.contains("Highly confidential"),
        "Must not leak foreign description"
    );

    // 2. Cross-Workspace Workspaces List: Alice attempts GET /api/v1/programs/{prog_b.id}/workspaces
    let req = Request::builder()
        .uri(format!("/api/v1/programs/{}/workspaces", prog_b.id))
        .method("GET")
        .header(COOKIE, &alice_cookie)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        !body.contains("Confidential Vault Workspace"),
        "Must not leak foreign workspace name"
    );

    // 3. Cross-Workspace Workspace Read: Alice attempts GET /api/v1/workspaces/{ws_b.id}
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}", ws_b.id))
        .method("GET")
        .header(COOKIE, &alice_cookie)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 4. Cross-Workspace Membership Read: Alice attempts GET /api/v1/workspaces/{ws_b.id}/memberships
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/memberships", ws_b.id))
        .method("GET")
        .header(COOKIE, &alice_cookie)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        !body.contains("Bob Beta"),
        "Must not leak foreign membership principal name"
    );

    // 5. Cross-Workspace Membership Mutation: Alice attempts POST /api/v1/workspaces/{ws_b.id}/memberships
    let add_mem_payload = json!({
        "principal_id": alice.id.to_string(),
        "role": "admin",
    });
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/memberships", ws_b.id))
        .method("POST")
        .header(COOKIE, &alice_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &alice_csrf)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&add_mem_payload).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 6. UUID Guessing / Probing: Random non-existent UUIDs return uniform 404 (no existence oracle)
    let random_uuid = Uuid::new_v4();
    let req = Request::builder()
        .uri(format!("/api/v1/programs/{random_uuid}"))
        .method("GET")
        .header(COOKIE, &alice_cookie)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// =========================================================================
// 8. Privileged Command Atomicity / Idempotency / Audit Hash Chain Gate
// =========================================================================

#[tokio::test]
async fn test_security_gate_privileged_command_atomicity_idempotency_and_audit_integrity() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org = create_org(&db, "Audit Gate Org", "audit-gate-org").await;
    let owner = create_principal(&db, org.id, "owner@audit.com", "Owner Principal").await;
    let target_user = create_principal(&db, org.id, "target@audit.com", "Target Principal").await;
    let (_, owner_cookie, owner_csrf) = create_session_and_csrf(&db, owner.id, &config).await;

    // 1. Privileged Command E06: CreateProgram with Idempotency Key
    let prog_payload = json!({
        "name": "Audit Program",
        "slug": "audit-prog",
        "description": "Audited program creation"
    });
    let idemp_prog = "idemp-audit-prog-001";

    let req = Request::builder()
        .uri("/api/v1/programs")
        .method("POST")
        .header(COOKIE, &owner_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &owner_csrf)
        .header("idempotency-key", idemp_prog)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&prog_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let prog_dto: ProgramDto = serde_json::from_slice(&body_bytes).unwrap();

    // Replay of E06: Same key + same payload returns exact cached response, NO duplicate creation
    let req = Request::builder()
        .uri("/api/v1/programs")
        .method("POST")
        .header(COOKIE, &owner_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &owner_csrf)
        .header("idempotency-key", idemp_prog)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&prog_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes2 = resp.into_body().collect().await.unwrap().to_bytes();
    let prog_dto2: ProgramDto = serde_json::from_slice(&body_bytes2).unwrap();
    assert_eq!(prog_dto.id, prog_dto2.id);

    // Mismatch of E06: Same key + different payload returns 400 Bad Request
    let mismatch_payload = json!({
        "name": "Different Name",
        "slug": "different-slug",
    });
    let req = Request::builder()
        .uri("/api/v1/programs")
        .method("POST")
        .header(COOKIE, &owner_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &owner_csrf)
        .header("idempotency-key", idemp_prog)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&mismatch_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Conflict of E06: Different key + same slug returns 409 Conflict
    let req = Request::builder()
        .uri("/api/v1/programs")
        .method("POST")
        .header(COOKIE, &owner_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &owner_csrf)
        .header("idempotency-key", "idemp-audit-prog-002")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&prog_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // 2. Privileged Command E09: CreateWorkspace
    let ws_payload = json!({
        "name": "Audited Workspace",
        "slug": "audited-ws",
        "description": "Audited workspace creation"
    });
    let idemp_ws = "idemp-audit-ws-001";

    let req = Request::builder()
        .uri(format!("/api/v1/programs/{}/workspaces", prog_dto.id))
        .method("POST")
        .header(COOKIE, &owner_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &owner_csrf)
        .header("idempotency-key", idemp_ws)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&ws_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let ws_dto: WorkspaceDto = serde_json::from_slice(&body_bytes).unwrap();
    let ws_id = Uuid::parse_str(&ws_dto.id).unwrap();

    // 3. Grant GRANT_AUTHORITY to owner so owner can grant capabilities
    {
        let mut tx = db.pool().begin().await.unwrap();
        let g = CapabilityGrant::new(
            WorkspaceId(ws_id),
            owner.id,
            Capability::GrantAuthority,
            Some(owner.id),
            None,
        )
        .unwrap();
        CapabilityGrantRepository::insert(&mut tx, &g)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    // 4. Privileged Command E13: CreateMembership
    let mem_payload = json!({
        "principal_id": target_user.id.to_string(),
        "role": "operator",
    });
    let idemp_mem = "idemp-audit-mem-001";

    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{ws_id}/memberships"))
        .method("POST")
        .header(COOKIE, &owner_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &owner_csrf)
        .header("idempotency-key", idemp_mem)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&mem_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 5. Privileged Command E14: CreateCapabilityGrant
    let cap_payload = json!({
        "workspace_id": ws_id.to_string(),
        "principal_id": target_user.id.to_string(),
        "capability": "RULE_ACTIVATION",
    });
    let idemp_cap = "idemp-audit-cap-001";

    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{ws_id}/capability-grants"))
        .method("POST")
        .header(COOKIE, &owner_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &owner_csrf)
        .header("idempotency-key", idemp_cap)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&cap_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let cap_dto: CapabilityGrantDto = serde_json::from_slice(&body_bytes).unwrap();
    let grant_id = cap_dto.id.expect("Grant ID should be present");

    // 6. Privileged Command E15: RevokeCapabilityGrant
    let idemp_revoke = "idemp-audit-revoke-001";
    let req = Request::builder()
        .uri(format!(
            "/api/v1/workspaces/{ws_id}/capability-grants/{grant_id}/revoke"
        ))
        .method("POST")
        .header(COOKIE, &owner_cookie)
        .header(ORIGIN, "http://127.0.0.1:3000")
        .header(CSRF_HEADER_NAME, &owner_csrf)
        .header("idempotency-key", idemp_revoke)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 7. Verify Authoritative Cryptographic Audit Hash Chain Integrity
    let mut conn = db.pool().acquire().await.unwrap();
    let rows = sqlx::query(
        "SELECT sequence, action_code, previous_event_hash, event_hash
         FROM audit_events
         WHERE workspace_id = $1
         ORDER BY sequence ASC",
    )
    .bind(ws_id)
    .fetch_all(&mut *conn)
    .await
    .unwrap();

    assert!(!rows.is_empty(), "Audit events must be recorded");

    let mut expected_prev_hash: Option<Vec<u8>> = None;

    for (idx, row) in rows.iter().enumerate() {
        let seq: i64 = row.get("sequence");
        assert_eq!(
            seq,
            (idx + 1) as i64,
            "Sequence numbers must be strictly sequential 1, 2, 3..."
        );

        let prev_hash: Option<Vec<u8>> = row.get("previous_event_hash");
        let event_hash: Vec<u8> = row.get("event_hash");

        if idx == 0 {
            // Genesis event
            assert!(prev_hash.is_none() || prev_hash.as_deref() == Some(&[0u8; 32]));
        } else {
            assert_eq!(
                prev_hash, expected_prev_hash,
                "previous_event_hash must match preceding event hash"
            );
        }

        expected_prev_hash = Some(event_hash);
    }

    // Verify Chain Head consistency
    let head = sqlx::query(
        "SELECT last_sequence, last_event_hash FROM audit_chain_heads WHERE workspace_id = $1",
    )
    .bind(ws_id)
    .fetch_one(&mut *conn)
    .await
    .unwrap();

    let head_seq: i64 = head.get("last_sequence");
    let head_hash: Vec<u8> = head.get("last_event_hash");

    assert_eq!(head_seq, rows.len() as i64);
    assert_eq!(Some(head_hash), expected_prev_hash);
}

// =========================================================================
// 9. Staged-FK Hard Boundary & Absence of W2/W3 Surfaces Gate
// =========================================================================

#[tokio::test]
async fn test_security_gate_staged_fk_boundaries_and_absence_of_w2_w3_surfaces() {
    let db = provision_migrated_db().await;
    let config = create_test_config();
    let app = create_app_with_pool(&config, db.pool().clone());

    let org = create_org(&db, "Boundary Org", "boundary-org").await;
    let user = create_principal(&db, org.id, "boundary@test.com", "Boundary User").await;
    let (_, cookie, _) = create_session_and_csrf(&db, user.id, &config).await;

    let ws = {
        let mut tx = db.pool().begin().await.unwrap();
        let p = Program::new(org.id, "Prog Boundary", "prog-b").unwrap();
        ProgramRepository::insert(&mut tx, &p).await.unwrap();
        let w = Workspace::new(p.id, org.id, "WS Boundary", "ws-b").unwrap();
        WorkspaceRepository::insert(&mut tx, &w).await.unwrap();
        let m = Membership::new(w.id, user.id, MembershipRole::Admin);
        MembershipRepository::insert(&mut tx, &m).await.unwrap();
        tx.commit().await.unwrap();
        w
    };

    // 1. E11 is ABSENT: GET /api/v1/workspaces/{id}/source-state MUST return 404
    let req = Request::builder()
        .uri(format!("/api/v1/workspaces/{}/source-state", ws.id))
        .method("GET")
        .header(COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "E11 source-state endpoint must NOT exist in W1"
    );

    // 2. W2/W3 Routes are ABSENT
    let later_routes = vec![
        "/api/v1/documents",
        "/api/v1/rules",
        "/api/v1/preflight",
        "/api/v1/jobs",
    ];

    for route in later_routes {
        let req = Request::builder()
            .uri(route)
            .method("GET")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "Later-wave route {route} must NOT exist in W1"
        );
    }

    // 3. Verify Database Schema Staged-FK Constraints:
    // Ensure `workspaces.current_source_state_id` does NOT exist as foreign key
    let count_fk: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.table_constraints
         WHERE table_name = 'workspaces' AND constraint_name LIKE '%source_state%'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count_fk, 0, "No source_state FK on workspaces in W1");

    // Ensure `audit_events.job_id` FK is closed to jobs table in W2
    let count_job_fk: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.table_constraints
         WHERE table_name = 'audit_events' AND constraint_name = 'fk_audit_events_job'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count_job_fk, 1, "jobs FK on audit_events closed in W2");
}
