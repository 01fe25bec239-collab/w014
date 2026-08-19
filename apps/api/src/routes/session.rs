//! Session inspection and lifecycle endpoints (E03: Get Session, E04: Logout).

use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use w014_application::authn::SessionAuthnService;
use w014_authn::error::AuthnError;
use w014_authn::session::SessionCookieBuilder;

use crate::AppState;
use crate::error::ProblemDetails;

/// Authoritative Session Response payload (E03).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SessionResponse {
    pub session_id: String,
    pub principal_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
}

/// Logout Response payload (E04).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LogoutResponse {
    pub status: String,
}

/// E03: GET /api/v1/session
/// Retrieves current active session details, validating and touching the session.
#[utoipa::path(
    get,
    path = "/api/v1/session",
    responses(
        (status = 200, description = "Active session details", body = SessionResponse),
        (status = 401, description = "Unauthorized: unauthenticated, expired, or revoked session", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "Session"
)]
pub async fn get_session_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    // 1. Extract session token from Cookie header
    let raw_token =
        SessionCookieBuilder::extract_token(&headers, &state.config.session.cookie_name)
            .ok_or(AuthnError::Unauthenticated)?;

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| ProblemDetails::internal_server_error(Some("/api/v1/session".into())))?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some("/api/v1/session".into())))?;

    // 2. Authenticate session, evaluate timeouts, and touch
    let session = SessionAuthnService::authenticate(&mut tx, &raw_token, &state.config.session)
        .await
        .map_err(ProblemDetails::from)?;

    tx.commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some("/api/v1/session".into())))?;

    let csrf_token = state.csrf_protector.derive_token(&raw_token);

    let payload = SessionResponse {
        session_id: session.id.to_string(),
        principal_id: session.principal_id.to_string(),
        workspace_id: session.workspace_id.map(|w| w.to_string()),
        status: session.status.to_string(),
        created_at: session.created_at,
        expires_at: session.expires_at,
        last_seen_at: session.last_seen_at,
        csrf_token: Some(csrf_token),
    };

    Ok((StatusCode::OK, axum::Json(payload)).into_response())
}

/// E04: POST /api/v1/session/logout
/// Revokes the current session and clears the session cookie.
#[utoipa::path(
    post,
    path = "/api/v1/session/logout",
    responses(
        (status = 200, description = "Logged out successfully; session revoked and cookie cleared", body = LogoutResponse),
        (status = 401, description = "Unauthorized: session cookie missing or invalid", body = ProblemDetails),
        (status = 403, description = "Forbidden: CSRF check failed", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "Session"
)]
pub async fn logout_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    // 1. Extract session token from Cookie
    let raw_token =
        SessionCookieBuilder::extract_token(&headers, &state.config.session.cookie_name)
            .ok_or(AuthnError::Unauthenticated)?;

    // 2. CSRF Exact Origin and X-W014-CSRF token validation for POST
    let expected_csrf = state.csrf_protector.derive_token(&raw_token);
    state
        .csrf_protector
        .validate_request(&Method::POST, &headers, true, Some(&expected_csrf))
        .map_err(ProblemDetails::from)?;

    let pool = state.pool.as_ref().ok_or_else(|| {
        ProblemDetails::internal_server_error(Some("/api/v1/session/logout".into()))
    })?;

    let mut tx = pool.begin().await.map_err(|_| {
        ProblemDetails::internal_server_error(Some("/api/v1/session/logout".into()))
    })?;

    // 3. Look up and revoke session by keyed HMAC-SHA256 hash
    let token_hash = state.config.session.hash_token(&raw_token);
    if let Some(session) =
        w014_application::persistence::SessionRepository::get_by_token_hash(&mut tx, &token_hash)
            .await
            .map_err(ProblemDetails::from)?
    {
        SessionAuthnService::revoke(&mut tx, session.id)
            .await
            .map_err(ProblemDetails::from)?;
    }

    tx.commit().await.map_err(|_| {
        ProblemDetails::internal_server_error(Some("/api/v1/session/logout".into()))
    })?;

    // 4. Build clear cookie header
    let clear_cookie = SessionCookieBuilder::build_clear_cookie(&state.config.session);

    let mut resp = (
        StatusCode::OK,
        axum::Json(LogoutResponse {
            status: "logged_out".to_string(),
        }),
    )
        .into_response();

    if let Ok(cookie_val) = HeaderValue::from_str(&clear_cookie) {
        resp.headers_mut().insert(SET_COOKIE, cookie_val);
    }

    Ok(resp)
}
