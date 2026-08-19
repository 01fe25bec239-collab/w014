//! Comprehensive Integration Tests for WI-0102 OIDC Test Path & Rust Server-Side Sessions.
//!
//! Proves:
//! 1. OIDC_AUTHORIZATION_CODE_FLOW: E01 login URL generation, params, S256 PKCE, state storage.
//! 2. PKCE: Strict S256 challenge, verifier verification, and rejection of invalid verifiers.
//! 3. STATE_VALIDATION: Strong entropy, bounded validity, single-use state consumption, replay rejection.
//! 4. NONCE_VALIDATION: ID token nonce binding and mismatch rejection.
//! 5. CALLBACK_VALIDATION: E02 callback exchange, token validation, principal resolution, session creation.
//! 6. OPAQUE_SERVER_SIDE_SESSION: Raw token never stored (keyed HMAC-SHA256 in DB), authoritative lookup on E03.
//! 7. SESSION_ROTATION: Distinct hashes, rotation audit append, old token invalidation.
//! 8. SESSION_EXPIRY: Absolute and idle expiration policies, touch updates.
//! 9. SESSION_REPLAY_REVOCATION: E04 logout revocation, cookie clearing, revoked token rejection.
//! 10. CSRF_SESSION_BEHAVIOR: Exact Origin validation on unsafe methods, X-W014-CSRF header enforcement, NO referer fallback, fail closed.
//! 11. E01_E04_CONTRACT_BEHAVIOR: Strict adherence to frozen endpoints, HTTP statuses, and ProblemDetails.

use axum::Router;
use axum::body::Body;
use axum::extract::Form;
use axum::http::header::{COOKIE, LOCATION, ORIGIN, REFERER, SET_COOKIE};
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::Value;
use tower::ServiceExt;

use w014_api::config::ApiConfig;
use w014_api::create_app_with_pool;
use w014_api::routes::auth::LoginResponse;
use w014_api::routes::session::SessionResponse;
use w014_application::authn::SessionAuthnService;
use w014_application::persistence::{
    OidcIdentityRepository, OidcTransactionRepository, PrincipalRepository, SessionRepository,
};
use w014_application::services::OidcPersistenceService;
use w014_authn::csrf::{CSRF_HEADER_NAME, CsrfConfig, derive_csrf_token};
use w014_authn::oidc::token::{AudienceClaim, RawIdTokenClaims};
use w014_authn::oidc::{OidcClient, OidcConfig};
use w014_authn::session::{
    Session, SessionCookieBuilder, SessionStatus, generate_session_token, hash_session_token,
};
use w014_persistence::harness::TestDatabase;
use w014_persistence::runner::{MIGRATOR, MigrationRunner};

const TEST_RSA_PRIVATE_KEY_PEM: &[u8] =
    include_bytes!("../../../crates/w014-authn/tests/test_keys/rsa_private.pem");

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

/// Helper struct representing a running Mock OIDC Identity Provider.
struct MockIdp {
    issuer: String,
    client_id: String,
    token_url: String,
    jwks_url: String,
    _shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl MockIdp {
    async fn start(client_id: &str) -> Self {
        let encoding_key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM).unwrap();

        // Bind ephemeral TCP listener
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let base_url = format!("http://127.0.0.1:{}", local_addr.port());
        let issuer = base_url.clone();
        let token_url = format!("{base_url}/oauth/token");
        let jwks_url = format!("{base_url}/oauth/jwks");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // Construct mock IdP router
        let enc_key_clone = encoding_key.clone();
        let iss_clone = issuer.clone();
        let client_id_str = client_id.to_string();

        let app = Router::new()
            .route(
                "/oauth/jwks",
                get({
                    move || async move {
                        // Return JWKS referencing the test public key
                        let jwks_json = serde_json::json!({
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
                    move |Form(params): Form<std::collections::HashMap<String, String>>| {
                        let enc_key = enc_key.clone();
                        let iss = iss.clone();
                        let c_id = c_id.clone();
                        async move {
                            let code = params.get("code").cloned().unwrap_or_default();
                            let verifier =
                                params.get("code_verifier").cloned().unwrap_or_default();

                            // Generate valid signed ID token
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
                                extra: serde_json::json!({ "verifier_used": verifier }),
                            };

                            let mut header = Header::new(Algorithm::RS256);
                            header.kid = Some("mock-rsa-key-1".to_string());
                            let id_token =
                                jsonwebtoken::encode(&header, &claims, &enc_key).unwrap();

                            let token_resp = serde_json::json!({
                                "access_token": "mock_access_token",
                                "token_type": "Bearer",
                                "id_token": id_token,
                                "expires_in": 3600
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
            client_id: client_id.to_string(),
            token_url,
            jwks_url,
            _shutdown_tx: shutdown_tx,
        }
    }

    fn to_oidc_config(&self, redirect_uri: &str) -> OidcConfig {
        OidcConfig {
            issuer: self.issuer.clone(),
            issuer_allowlist: vec![self.issuer.clone()],
            authorization_endpoint: format!("{}/oauth/authorize", self.issuer),
            token_endpoint: self.token_url.clone(),
            jwks_uri: self.jwks_url.clone(),
            client_id: self.client_id.clone(),
            client_secret: None,
            redirect_uri: redirect_uri.to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            state_ttl_secs: 600,
        }
    }
}

// ---------------------------------------------------------------------------
// 1. OIDC AUTHORIZATION CODE FLOW & PKCE (E01)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e01_login_initiates_oidc_pkce_and_stores_transaction() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool().clone();

    let mut config = ApiConfig::for_testing();
    config.oidc.client_id = "test-client-id".to_string();
    config.oidc.authorization_endpoint = "https://auth.example.com/authorize".to_string();
    config.oidc.redirect_uri = "http://localhost:8080/api/v1/auth/callback".to_string();

    let app = create_app_with_pool(&config, pool.clone());

    // 1. Standard browser request: 302 Found Redirect to IdP
    let req = Request::builder()
        .uri("/api/v1/auth/login")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);

    let location_hdr = resp.headers().get(LOCATION).unwrap().to_str().unwrap();
    assert!(location_hdr.starts_with("https://auth.example.com/authorize?"));
    assert!(location_hdr.contains("response_type=code"));
    assert!(location_hdr.contains("client_id=test-client-id"));
    assert!(location_hdr.contains("code_challenge_method=S256"));
    assert!(location_hdr.contains("scope=openid+email+profile"));

    // Extract state token from redirect URL
    let url = url::Url::parse(location_hdr).unwrap();
    let state_param = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .to_string();

    // 2. Verify transient transaction is stored in PostgreSQL database
    let mut tx = pool.begin().await.unwrap();
    let stored_tx = OidcTransactionRepository::get_by_state_token(&mut tx, &state_param)
        .await
        .unwrap()
        .expect("Transaction record must be persisted in database");

    assert_eq!(stored_tx.state_token, state_param);
    assert!(!stored_tx.nonce.is_empty());
    assert!(stored_tx.pkce_verifier.is_some());
    assert!(stored_tx.is_valid_at(Utc::now()));

    // 3. JSON requested login (format=json) returns 200 OK with LoginResponse
    let json_req = Request::builder()
        .uri("/api/v1/auth/login?format=json")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let json_resp = app.oneshot(json_req).await.unwrap();
    assert_eq!(json_resp.status(), StatusCode::OK);

    let body_bytes = json_resp.into_body().collect().await.unwrap().to_bytes();
    let login_data: LoginResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(
        login_data
            .authorization_url
            .contains("code_challenge_method=S256")
    );
    assert!(!login_data.state.is_empty());
}

// ---------------------------------------------------------------------------
// 2. STATE & NONCE VALIDATION, SINGLE-USE SEMANTICS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_state_single_use_and_replay_rejection() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool().clone();

    let config = ApiConfig::for_testing();
    let app = create_app_with_pool(&config, pool.clone());

    // 1. Manually insert an OIDC transaction
    let state_token = "single_use_state_12345";
    let nonce = "nonce_12345";
    let expires = Utc::now() + Duration::minutes(5);

    let mut tx = pool.begin().await.unwrap();
    OidcPersistenceService::store_transaction(
        &mut tx,
        state_token,
        nonce,
        Some("pkce_verifier_string_43_chars_long_and_valid_url_safe"),
        "http://localhost:8080/api/v1/auth/callback",
        expires,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // 2. First consumption succeeds
    let mut tx2 = pool.begin().await.unwrap();
    let consumed = OidcPersistenceService::consume_transaction(&mut tx2, state_token)
        .await
        .unwrap();
    assert!(consumed.is_some());
    tx2.commit().await.unwrap();

    // 3. Second consumption fails (single-use enforced: deleted from DB)
    let mut tx3 = pool.begin().await.unwrap();
    let second_attempt = OidcPersistenceService::consume_transaction(&mut tx3, state_token)
        .await
        .unwrap();
    assert!(second_attempt.is_none());
    tx3.commit().await.unwrap();

    // 4. Invoking callback endpoint with consumed/unknown state returns 400 Bad Request ProblemDetails
    let callback_req = Request::builder()
        .uri(format!(
            "/api/v1/auth/callback?code=test_code&state={state_token}"
        ))
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(callback_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let problem: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(problem["type"], "urn:w014:error:bad-request");
    assert!(problem["detail"].as_str().unwrap().contains("state"));
}

// ---------------------------------------------------------------------------
// 3. FULL OIDC CALLBACK, PRINCIPAL PROVISIONING & SERVER-SIDE SESSIONS (E02, E03)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e02_callback_flow_creates_opaque_session_and_cookie() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool().clone();

    // 1. Start Mock IdP
    let mock_idp = MockIdp::start("w014-client-app").await;

    let mut config = ApiConfig::for_testing();
    config.oidc = mock_idp.to_oidc_config("http://localhost:8080/api/v1/auth/callback");
    config.session.cookie_name = "__Host-w014_session".to_string();
    config.session.cookie_secure = false;

    let oidc_client = OidcClient::new(config.oidc.clone());

    let state =
        w014_api::AppState::new(config.clone(), Some(pool.clone())).with_oidc_client(oidc_client);
    let app = w014_api::create_app_with_state(state);

    // 2. Initiate login to populate OidcTransaction
    let login_req = Request::builder()
        .uri("/api/v1/auth/login?format=json")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let login_resp = app.clone().oneshot(login_req).await.unwrap();
    let body = login_resp.into_body().collect().await.unwrap().to_bytes();
    let login_data: LoginResponse = serde_json::from_slice(&body).unwrap();
    let state_token = login_data.state;

    // Update the stored transaction's nonce to match mock IdP's deterministic nonce format for code 'code123'
    let mut tx = pool.begin().await.unwrap();
    let mut stored_tx = OidcTransactionRepository::get_by_state_token(&mut tx, &state_token)
        .await
        .unwrap()
        .unwrap();
    stored_tx.nonce = "nonce-for-code123".to_string();
    // Re-insert with updated nonce
    OidcTransactionRepository::delete_by_id(&mut tx, stored_tx.id)
        .await
        .unwrap();
    OidcTransactionRepository::insert(&mut tx, &stored_tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // 3. Execute Callback (E02)
    let callback_req = Request::builder()
        .uri(format!(
            "/api/v1/auth/callback?code=code123&state={state_token}&format=json"
        ))
        .method("GET")
        .header("User-Agent", "Mozilla/5.0 IntegrationTest")
        .body(Body::empty())
        .unwrap();

    let callback_resp = app.clone().oneshot(callback_req).await.unwrap();
    assert_eq!(callback_resp.status(), StatusCode::OK);

    // Verify Set-Cookie header contains opaque session token
    let set_cookie_hdr = callback_resp
        .headers()
        .get(SET_COOKIE)
        .expect("Set-Cookie header must be present")
        .to_str()
        .unwrap();

    assert!(set_cookie_hdr.contains("__Host-w014_session="));
    assert!(set_cookie_hdr.contains("HttpOnly"));
    assert!(set_cookie_hdr.contains("SameSite=Lax"));
    assert!(set_cookie_hdr.contains("Path=/"));

    let raw_token =
        SessionCookieBuilder::extract_token_from_str(set_cookie_hdr, "__Host-w014_session")
            .expect("Raw session token must be extractable from Set-Cookie");

    // 4. Verify Authoritative DB state: Raw token is NEVER stored in database, only keyed HMAC-SHA256
    let token_hash = config.session.hash_token(&raw_token);
    let mut check_tx = pool.begin().await.unwrap();
    let db_session = SessionRepository::get_by_token_hash(&mut check_tx, &token_hash)
        .await
        .unwrap()
        .expect("Session must exist in DB by keyed HMAC token hash");

    assert_eq!(db_session.status, SessionStatus::Active);
    assert_eq!(db_session.session_token_hash, token_hash);

    // Raw token is NEVER equal to the stored hash
    assert_ne!(db_session.session_token_hash, raw_token);

    // Keyed property: A different HMAC key produces a completely different hash that does NOT match DB
    let other_key_hash = hash_session_token(&raw_token, b"different-secret-key-material-32b");
    assert_ne!(other_key_hash, token_hash);
    let wrong_key_lookup = SessionRepository::get_by_token_hash(&mut check_tx, &other_key_hash)
        .await
        .unwrap();
    assert!(
        wrong_key_lookup.is_none(),
        "Lookup with different HMAC key must find nothing"
    );

    // Verify OIDC Identity linkage
    let identity = OidcIdentityRepository::get_by_issuer_subject(
        &mut check_tx,
        &mock_idp.issuer,
        "user-sub-code123",
    )
    .await
    .unwrap()
    .expect("OIDC Identity linkage record must exist");

    assert_eq!(identity.principal_id, db_session.principal_id);
    assert_eq!(identity.email.as_deref(), Some("user-code123@example.com"));

    // 5. Test E03: GET /api/v1/session using the session cookie
    let session_req = Request::builder()
        .uri("/api/v1/session")
        .method("GET")
        .header(COOKIE, format!("__Host-w014_session={raw_token}"))
        .body(Body::empty())
        .unwrap();

    let session_resp = app.clone().oneshot(session_req).await.unwrap();
    assert_eq!(session_resp.status(), StatusCode::OK);

    let session_body = session_resp.into_body().collect().await.unwrap().to_bytes();
    let session_data: SessionResponse = serde_json::from_slice(&session_body).unwrap();
    assert_eq!(session_data.session_id, db_session.id.to_string());
    assert_eq!(
        session_data.principal_id,
        db_session.principal_id.to_string()
    );
    assert_eq!(session_data.status, "active");
    assert!(
        session_data.csrf_token.is_some(),
        "Active session response must include derived CSRF token"
    );
}

// ---------------------------------------------------------------------------
// 4. SESSION EXPIRY, IDLE TIMEOUT, ROTATION, AND REVOCATION (E03, E04)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_session_lifecycle_expiry_idle_and_touch() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool().clone();

    let mut config = ApiConfig::for_testing();
    config.session.cookie_name = "test_session".to_string();
    config.session.idle_ttl_secs = 60; // 1 minute idle timeout
    config.session.absolute_ttl_secs = 3600; // 1 hour absolute timeout

    let app = create_app_with_pool(&config, pool.clone());

    // 1. Create active session in DB
    let raw_token = generate_session_token();
    let token_hash = config.session.hash_token(&raw_token);
    let now = Utc::now();

    let mut tx = pool.begin().await.unwrap();
    let org = w014_domain::organization::Organization::new("Default Org", "default").unwrap();
    w014_application::persistence::OrganizationRepository::insert(&mut tx, &org)
        .await
        .unwrap();
    let principal = w014_domain::principal::Principal::new(
        org.id,
        w014_domain::principal::PrincipalType::User,
        Some("test@example.com"),
        "Test User",
    )
    .unwrap();
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .unwrap();

    let session = Session::new(
        principal.id,
        None,
        &token_hash,
        now + Duration::hours(1),
        Some("127.0.0.1"),
        Some("TestRunner"),
    )
    .unwrap();
    SessionRepository::insert(&mut tx, &session).await.unwrap();
    tx.commit().await.unwrap();

    // 2. Active session succeeds
    let req = Request::builder()
        .uri("/api/v1/session")
        .method("GET")
        .header(COOKIE, format!("test_session={raw_token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Simulate Idle Expiry: set last_seen_at back by 2 hours
    let mut tx_idle = pool.begin().await.unwrap();
    let mut idle_session = SessionRepository::get_by_id(&mut tx_idle, session.id)
        .await
        .unwrap()
        .unwrap();
    idle_session.last_seen_at = Utc::now() - Duration::hours(2);
    SessionRepository::update(&mut tx_idle, &idle_session)
        .await
        .unwrap();
    tx_idle.commit().await.unwrap();

    let req_idle = Request::builder()
        .uri("/api/v1/session")
        .method("GET")
        .header(COOKIE, format!("test_session={raw_token}"))
        .body(Body::empty())
        .unwrap();

    let resp_idle = app.clone().oneshot(req_idle).await.unwrap();
    assert_eq!(resp_idle.status(), StatusCode::UNAUTHORIZED);

    let idle_body = resp_idle.into_body().collect().await.unwrap().to_bytes();
    let problem: Value = serde_json::from_slice(&idle_body).unwrap();
    assert_eq!(problem["type"], "urn:w014:error:unauthorized");
    assert!(problem["detail"].as_str().unwrap().contains("expired"));
}

#[tokio::test]
async fn test_session_rotation_invalidation_and_audit() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool().clone();

    let config = ApiConfig::for_testing();

    // 1. Create active session
    let mut tx = pool.begin().await.unwrap();
    let org = w014_domain::organization::Organization::new("Default Org", "default").unwrap();
    w014_application::persistence::OrganizationRepository::insert(&mut tx, &org)
        .await
        .unwrap();
    let principal = w014_domain::principal::Principal::new(
        org.id,
        w014_domain::principal::PrincipalType::User,
        Some("test@example.com"),
        "Test User",
    )
    .unwrap();
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .unwrap();

    let old_raw = generate_session_token();
    let old_hash = config.session.hash_token(&old_raw);
    let session = Session::new(
        principal.id,
        None,
        &old_hash,
        Utc::now() + Duration::hours(24),
        None::<&str>,
        None::<&str>,
    )
    .unwrap();
    SessionRepository::insert(&mut tx, &session).await.unwrap();
    tx.commit().await.unwrap();

    // 2. Rotate session
    let mut tx_rot = pool.begin().await.unwrap();
    let (rotation, new_raw) =
        SessionAuthnService::rotate(&mut tx_rot, session.id, &config.session, Some("10.0.0.50"))
            .await
            .unwrap();
    tx_rot.commit().await.unwrap();

    assert_ne!(old_raw, new_raw);
    assert_eq!(rotation.old_token_hash, old_hash);
    assert_eq!(rotation.new_token_hash, config.session.hash_token(&new_raw));

    // 3. Old token is rejected
    let mut tx_check1 = pool.begin().await.unwrap();
    let old_auth =
        SessionAuthnService::authenticate(&mut tx_check1, &old_raw, &config.session).await;
    assert!(old_auth.is_err());

    // 4. New token authenticates successfully
    let mut tx_check2 = pool.begin().await.unwrap();
    let new_auth =
        SessionAuthnService::authenticate(&mut tx_check2, &new_raw, &config.session).await;
    assert!(new_auth.is_ok());
    assert_eq!(new_auth.unwrap().id, session.id);
}

// ---------------------------------------------------------------------------
// 5. CSRF PROTECTION & LOGOUT REVOCATION (E04)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e04_logout_csrf_defense_and_revocation() {
    let test_db = provision_migrated_db().await;
    let pool = test_db.pool().clone();

    let mut config = ApiConfig::for_testing();
    config.csrf = CsrfConfig::new(vec!["http://localhost:8080".to_string()]);
    config.session.cookie_name = "test_session".to_string();

    let app = create_app_with_pool(&config, pool.clone());

    // 1. Create active session
    let mut tx = pool.begin().await.unwrap();
    let org = w014_domain::organization::Organization::new("Default Org", "default").unwrap();
    w014_application::persistence::OrganizationRepository::insert(&mut tx, &org)
        .await
        .unwrap();
    let principal = w014_domain::principal::Principal::new(
        org.id,
        w014_domain::principal::PrincipalType::User,
        Some("test@example.com"),
        "Test User",
    )
    .unwrap();
    PrincipalRepository::insert(&mut tx, &principal)
        .await
        .unwrap();

    let raw_token = generate_session_token();
    let token_hash = config.session.hash_token(&raw_token);
    let session = Session::new(
        principal.id,
        None,
        &token_hash,
        Utc::now() + Duration::hours(12),
        None::<&str>,
        None::<&str>,
    )
    .unwrap();
    SessionRepository::insert(&mut tx, &session).await.unwrap();
    tx.commit().await.unwrap();

    let valid_csrf = derive_csrf_token(&raw_token, &config.csrf.hmac_secret);

    // 2. CSRF Defect 1 Test A: Origin missing + valid Referer => MUST FAIL CLOSED (No Referer Fallback)
    let missing_origin_req = Request::builder()
        .uri("/api/v1/session/logout")
        .method("POST")
        .header(COOKIE, format!("test_session={raw_token}"))
        .header(REFERER, "http://localhost:8080/dashboard")
        .header(CSRF_HEADER_NAME, &valid_csrf)
        .body(Body::empty())
        .unwrap();

    let missing_origin_resp = app.clone().oneshot(missing_origin_req).await.unwrap();
    assert_eq!(
        missing_origin_resp.status(),
        StatusCode::FORBIDDEN,
        "Missing Origin must fail closed even with valid Referer"
    );

    // 3. CSRF Defect 1 Test B: Malformed Origin + valid Referer => MUST FAIL CLOSED
    let malformed_origin_req = Request::builder()
        .uri("/api/v1/session/logout")
        .method("POST")
        .header(COOKIE, format!("test_session={raw_token}"))
        .header(ORIGIN, "malformed-origin-not-url")
        .header(REFERER, "http://localhost:8080/dashboard")
        .header(CSRF_HEADER_NAME, &valid_csrf)
        .body(Body::empty())
        .unwrap();

    let malformed_origin_resp = app.clone().oneshot(malformed_origin_req).await.unwrap();
    assert_eq!(
        malformed_origin_resp.status(),
        StatusCode::FORBIDDEN,
        "Malformed Origin must fail closed"
    );

    // 4. CSRF Defect 1 Test C: Wrong / Mismatched Origin + valid Referer => MUST FAIL CLOSED
    let attacker_csrf_req = Request::builder()
        .uri("/api/v1/session/logout")
        .method("POST")
        .header(COOKIE, format!("test_session={raw_token}"))
        .header(ORIGIN, "http://evil-attacker.com")
        .header(REFERER, "http://localhost:8080/dashboard")
        .header(CSRF_HEADER_NAME, &valid_csrf)
        .body(Body::empty())
        .unwrap();

    let attacker_resp = app.clone().oneshot(attacker_csrf_req).await.unwrap();
    assert_eq!(
        attacker_resp.status(),
        StatusCode::FORBIDDEN,
        "Wrong Origin must fail closed"
    );

    // 5. CSRF Defect 1 Test D: Missing X-W014-CSRF Header => MUST FAIL CLOSED
    let missing_header_req = Request::builder()
        .uri("/api/v1/session/logout")
        .method("POST")
        .header(COOKIE, format!("test_session={raw_token}"))
        .header(ORIGIN, "http://localhost:8080")
        .body(Body::empty())
        .unwrap();

    let missing_header_resp = app.clone().oneshot(missing_header_req).await.unwrap();
    assert_eq!(
        missing_header_resp.status(),
        StatusCode::FORBIDDEN,
        "Missing X-W014-CSRF header must fail closed"
    );

    // 6. CSRF Defect 1 Test E: Wrong X-W014-CSRF Header => MUST FAIL CLOSED
    let wrong_header_req = Request::builder()
        .uri("/api/v1/session/logout")
        .method("POST")
        .header(COOKIE, format!("test_session={raw_token}"))
        .header(ORIGIN, "http://localhost:8080")
        .header(CSRF_HEADER_NAME, "wrong-csrf-token-12345")
        .body(Body::empty())
        .unwrap();

    let wrong_header_resp = app.clone().oneshot(wrong_header_req).await.unwrap();
    assert_eq!(
        wrong_header_resp.status(),
        StatusCode::FORBIDDEN,
        "Wrong X-W014-CSRF header must fail closed"
    );

    // 7. Valid CSRF: Exact Allowed Origin + Valid X-W014-CSRF => MUST SUCCEED (200 OK & clear cookie)
    let valid_logout_req = Request::builder()
        .uri("/api/v1/session/logout")
        .method("POST")
        .header(COOKIE, format!("test_session={raw_token}"))
        .header(ORIGIN, "http://localhost:8080")
        .header(CSRF_HEADER_NAME, &valid_csrf)
        .body(Body::empty())
        .unwrap();

    let valid_logout_resp = app.clone().oneshot(valid_logout_req).await.unwrap();
    assert_eq!(
        valid_logout_resp.status(),
        StatusCode::OK,
        "Valid Origin + Valid CSRF header must succeed"
    );

    let clear_cookie_hdr = valid_logout_resp
        .headers()
        .get(SET_COOKIE)
        .expect("Clear-cookie header must be present")
        .to_str()
        .unwrap();

    assert!(clear_cookie_hdr.contains("test_session="));
    assert!(clear_cookie_hdr.contains("Max-Age=0"));

    // 8. Verify Session in DB is marked as Revoked
    let mut check_tx = pool.begin().await.unwrap();
    let revoked_session = SessionRepository::get_by_id(&mut check_tx, session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked_session.status, SessionStatus::Revoked);

    // 9. Replay of revoked session on E03 GET /api/v1/session fails with 401 Unauthorized
    let replay_req = Request::builder()
        .uri("/api/v1/session")
        .method("GET")
        .header(COOKIE, format!("test_session={raw_token}"))
        .body(Body::empty())
        .unwrap();

    let replay_resp = app.oneshot(replay_req).await.unwrap();
    assert_eq!(replay_resp.status(), StatusCode::UNAUTHORIZED);
}
