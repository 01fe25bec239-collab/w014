//! Integration tests for W-014 Foundation Platform API.
//!
//! Validates:
//! 1. Operational health contract (/healthz and /health)
//! 2. RFC 9457 Problem Details error responses and content types
//! 3. Correlation ID generation, propagation, and injection defense
//! 4. OpenAPI platform health schema exposure and absence of business endpoints
//! 5. Observability and data sanitization safety

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;
use w014_api::config::ApiConfig;
use w014_api::create_app;
use w014_api::error::PROBLEM_JSON_MEDIA_TYPE;
use w014_observability::{HEADER_CORRELATION_ID, HEADER_REQUEST_ID};

fn setup_test_app() -> axum::Router {
    let config = ApiConfig::for_testing();
    create_app(&config)
}

// ---------------------------------------------------------------------------
// 1. HEALTH CONTRACT TESTS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_healthz_endpoint_returns_ok_and_metadata() {
    let app = setup_test_app();

    let request = Request::builder()
        .uri("/healthz")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert!(response.headers().contains_key(HEADER_CORRELATION_ID));
    assert!(response.headers().contains_key(HEADER_REQUEST_ID));

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "w014-api");
    assert!(json["version"].is_string());

    // Verify no host internal or sensitive fields exist
    assert!(json.get("db").is_none());
    assert!(json.get("host").is_none());
    assert!(json.get("secret").is_none());
    assert!(json.get("password").is_none());
    assert!(json.get("customer").is_none());
    assert!(json.get("document").is_none());
}

#[tokio::test]
async fn test_health_alias_endpoint_returns_identical_response() {
    let app = setup_test_app();

    let request = Request::builder()
        .uri("/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "w014-api");
}

// ---------------------------------------------------------------------------
// 2. RFC 9457 PROBLEM DETAILS ERROR TESTS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_rfc9457_not_found_fallback_response() {
    let app = setup_test_app();

    let request = Request::builder()
        .uri("/unregistered/non-existent-endpoint")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        PROBLEM_JSON_MEDIA_TYPE
    );

    let corr_header = response
        .headers()
        .get(HEADER_CORRELATION_ID)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(json["type"], "urn:w014:error:not-found");
    assert_eq!(json["title"], "Not Found");
    assert_eq!(json["status"], 404);
    assert_eq!(json["code"], "NOT_FOUND");
    assert_eq!(json["instance"], "/unregistered/non-existent-endpoint");
    assert!(json["detail"].as_str().unwrap().contains("not found"));
    assert_eq!(json["correlation_id"], corr_header);

    // Verify internal details/stack traces are NOT leaked
    let json_str = json.to_string();
    assert!(!json_str.contains("stacktrace"));
    assert!(!json_str.contains("src/"));
    assert!(!json_str.contains(".rs:"));
    assert!(!json_str.contains("panic"));
}

// ---------------------------------------------------------------------------
// 3. CORRELATION ID TESTS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_correlation_id_propagates_valid_incoming_header() {
    let app = setup_test_app();
    let custom_id = "trace-test-uuid-12345";

    let request = Request::builder()
        .uri("/healthz")
        .method("GET")
        .header(HEADER_CORRELATION_ID, custom_id)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(HEADER_CORRELATION_ID).unwrap(),
        custom_id
    );
    assert_eq!(
        response.headers().get(HEADER_REQUEST_ID).unwrap(),
        custom_id
    );
}

#[tokio::test]
async fn test_correlation_id_propagates_from_request_id_header() {
    let app = setup_test_app();
    let req_id = "req-custom-999";

    let request = Request::builder()
        .uri("/healthz")
        .method("GET")
        .header(HEADER_REQUEST_ID, req_id)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(HEADER_CORRELATION_ID).unwrap(),
        req_id
    );
}

#[tokio::test]
async fn test_correlation_id_generated_when_absent() {
    let app = setup_test_app();

    let request = Request::builder()
        .uri("/healthz")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let corr_val = response
        .headers()
        .get(HEADER_CORRELATION_ID)
        .unwrap()
        .to_str()
        .unwrap();

    // Verify it is a valid UUID v4
    assert!(Uuid::parse_str(corr_val).is_ok());
}

#[tokio::test]
async fn test_correlation_id_sanitizes_malformed_input() {
    let app = setup_test_app();

    let request = Request::builder()
        .uri("/healthz")
        .method("GET")
        .header(
            HEADER_CORRELATION_ID,
            "malformed value with spaces and symbols!@#",
        )
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let corr_val = response
        .headers()
        .get(HEADER_CORRELATION_ID)
        .unwrap()
        .to_str()
        .unwrap();

    // Malformed value must be rejected and replaced with a safe UUID
    assert_ne!(corr_val, "malformed value with spaces and symbols!@#");
    assert!(Uuid::parse_str(corr_val).is_ok());
}

#[tokio::test]
async fn test_correlation_id_in_rfc9457_error_response() {
    let app = setup_test_app();
    let client_corr_id = "client-provided-corr-456";

    let request = Request::builder()
        .uri("/non-existent")
        .method("GET")
        .header(HEADER_CORRELATION_ID, client_corr_id)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers().get(HEADER_CORRELATION_ID).unwrap(),
        client_corr_id
    );

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["correlation_id"], client_corr_id);
}

// ---------------------------------------------------------------------------
// 4. OPENAPI HEALTH CONTRACT TESTS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_openapi_endpoint_exposes_production_surface() {
    let app = setup_test_app();

    let request = Request::builder()
        .uri("/openapi.json")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body_bytes).unwrap();

    // Verify OpenAPI version and title
    assert!(json["openapi"].as_str().unwrap().starts_with('3'));
    assert_eq!(json["info"]["title"], "W-014 Foundation Platform API");

    // Verify /healthz is present
    let paths = &json["paths"];
    assert!(paths.get("/healthz").is_some());

    // Verify HealthResponse and ProblemDetails schemas are present
    let schemas = &json["components"]["schemas"];
    assert!(schemas.get("HealthResponse").is_some());
    assert!(schemas.get("ProblemDetails").is_some());

    // Verify WI-0105 endpoints and schemas are present
    assert!(paths.get("/api/v1/programs").is_some());
    assert!(paths.get("/api/v1/workspaces/{workspace_id}").is_some());
    assert!(schemas.get("ProgramDto").is_some());
    assert!(schemas.get("WorkspaceDto").is_some());
    assert!(schemas.get("MembershipDto").is_some());
    assert!(schemas.get("CapabilityGrantDto").is_some());

    // Verify WI-0202 endpoints and schemas are present (E16-E24)
    assert!(
        paths
            .get("/api/v1/workspaces/{workspace_id}/documents")
            .is_some()
    );
    assert!(
        paths
            .get("/api/v1/workspaces/{workspace_id}/documents/{document_id}")
            .is_some()
    );
    assert!(
        paths
            .get("/api/v1/workspaces/{workspace_id}/documents/{document_id}/versions")
            .is_some()
    );
    assert!(
        paths
            .get("/api/v1/workspaces/{workspace_id}/documents/{document_id}/upload-intents")
            .is_some()
    );
    assert!(
        paths
            .get("/api/v1/workspaces/{workspace_id}/upload-intents/{intent_id}/finalize")
            .is_some()
    );
    assert!(
        paths
            .get("/api/v1/workspaces/{workspace_id}/document-versions/{version_id}")
            .is_some()
    );
    assert!(
        paths
            .get("/api/v1/workspaces/{workspace_id}/document-versions/{version_id}/accept")
            .is_some()
    );
    assert!(
        paths
            .get("/api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download")
            .is_some()
    );

    assert!(schemas.get("DocumentDto").is_some());
    assert!(schemas.get("CreateDocumentDto").is_some());
    assert!(schemas.get("DocumentPage").is_some());
    assert!(schemas.get("DocumentVersionDto").is_some());
    assert!(schemas.get("DocumentVersionPage").is_some());
    assert!(schemas.get("CreateUploadIntentDto").is_some());
    assert!(schemas.get("PresignedPutDto").is_some());
    assert!(schemas.get("UploadIntentDto").is_some());
    assert!(schemas.get("DownloadDto").is_some());

    // Strictly verify forbidden/deferred domain endpoints or models are NOT present
    let json_str = json.to_string();
    assert!(!json_str.contains("source-state"));
    assert!(!json_str.contains("/api/v1/requirements"));
    assert!(!json_str.contains("/api/v1/findings"));
    assert!(!json_str.contains("findings"));
    assert!(!json_str.contains("cdrl"));
}

#[tokio::test]
async fn test_production_router_activates_wi0202_document_endpoints() {
    let ws_id = Uuid::new_v4();
    let doc_id = Uuid::new_v4();
    let intent_id = Uuid::new_v4();
    let ver_id = Uuid::new_v4();

    async fn check_route(
        method: &str,
        uri: &str,
        body_str: Option<&str>,
        expected_status: StatusCode,
    ) {
        let app = setup_test_app();
        let body = match body_str {
            Some(b) => Body::from(b.to_string()),
            None => Body::empty(),
        };
        let mut req_builder = Request::builder().method(method).uri(uri);
        if body_str.is_some() {
            req_builder = req_builder.header(header::CONTENT_TYPE, "application/json");
        }
        let request = req_builder.body(body).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            expected_status,
            "Route {method} {uri} expected status {expected_status}, got {}",
            response.status()
        );
    }

    // E16: GET /api/v1/workspaces/{workspace_id}/documents -> 401 Unauthenticated (route is registered, not 404)
    check_route(
        "GET",
        &format!("/api/v1/workspaces/{ws_id}/documents"),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    // E17: POST /api/v1/workspaces/{workspace_id}/documents -> 401 Unauthenticated (route is registered, not 404)
    check_route(
        "POST",
        &format!("/api/v1/workspaces/{ws_id}/documents"),
        Some(r#"{"title":"Test Document","document_class":"INCOMING"}"#),
        StatusCode::UNAUTHORIZED,
    )
    .await;

    // E18: GET /api/v1/workspaces/{workspace_id}/documents/{document_id} -> 401 Unauthenticated (route is registered, not 404)
    check_route(
        "GET",
        &format!("/api/v1/workspaces/{ws_id}/documents/{doc_id}"),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    // E19: GET /api/v1/workspaces/{workspace_id}/documents/{document_id}/versions -> 401 Unauthenticated (route is registered, not 404)
    check_route(
        "GET",
        &format!("/api/v1/workspaces/{ws_id}/documents/{doc_id}/versions"),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    // E20: POST /api/v1/workspaces/{workspace_id}/documents/{document_id}/upload-intents -> 401 Unauthenticated (route is registered, not 404)
    check_route(
        "POST",
        &format!("/api/v1/workspaces/{ws_id}/documents/{doc_id}/upload-intents"),
        Some(r#"{"filename":"test.pdf","media_type":"application/pdf","byte_length":1024}"#),
        StatusCode::UNAUTHORIZED,
    )
    .await;

    // E21: POST /api/v1/workspaces/{workspace_id}/upload-intents/{intent_id}/finalize -> 501 Not Implemented (deferred to WI-0203, not 404)
    check_route(
        "POST",
        &format!("/api/v1/workspaces/{ws_id}/upload-intents/{intent_id}/finalize"),
        None,
        StatusCode::NOT_IMPLEMENTED,
    )
    .await;

    // E22: GET /api/v1/workspaces/{workspace_id}/document-versions/{version_id} -> 401 Unauthenticated (route is registered, not 404)
    check_route(
        "GET",
        &format!("/api/v1/workspaces/{ws_id}/document-versions/{ver_id}"),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    // E23: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/accept -> 401 Unauthenticated (route is registered, not 404)
    check_route(
        "POST",
        &format!("/api/v1/workspaces/{ws_id}/document-versions/{ver_id}/accept"),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    // E24: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download -> 401 Unauthenticated (route is registered, not 404)
    check_route(
        "POST",
        &format!("/api/v1/workspaces/{ws_id}/document-versions/{ver_id}/download"),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    // Unregistered path returns 404 Not Found via global fallback
    check_route(
        "GET",
        &format!("/api/v1/workspaces/{ws_id}/unregistered-surface"),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;
}

#[tokio::test]
async fn test_swagger_ui_surface_is_absent() {
    let app = setup_test_app();

    let request = Request::builder()
        .uri("/swagger-ui")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // /swagger-ui is removed per dependency-minimization rules; fallback 404 is returned
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        PROBLEM_JSON_MEDIA_TYPE
    );
}

#[tokio::test]
async fn test_utoipa_axum_openapi_router_composition() {
    use tower::ServiceExt;
    let (router, openapi) = w014_api::openapi::build_openapi_router();
    let state = w014_api::AppState::new(w014_api::config::ApiConfig::for_testing(), None);
    let app = router.with_state(state);

    // Verify OpenAPI spec contains the operational health endpoint collected via utoipa-axum routes! macro
    assert!(openapi.paths.paths.contains_key("/healthz"));
    assert_eq!(openapi.info.title, "W-014 Foundation Platform API");
    assert_eq!(openapi.info.version, "0.1.0");

    // Verify router directly dispatches /healthz successfully
    let request = Request::builder()
        .uri("/healthz")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
