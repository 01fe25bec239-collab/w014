//! Authentication endpoints (E01: Login, E02: Callback).

use axum::extract::{Query, State};
use axum::http::header::{ACCEPT, LOCATION, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use w014_application::authn::OidcFlowService;
use w014_authn::session::SessionCookieBuilder;

use crate::AppState;
use crate::error::ProblemDetails;

/// Query parameters for initiating login (E01).
#[derive(Debug, Deserialize, IntoParams)]
pub struct LoginQuery {
    /// Optional format override ("json" to receive JSON response instead of 302 redirect).
    pub format: Option<String>,
}

/// JSON payload returned when login is requested as JSON.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LoginResponse {
    pub authorization_url: String,
    pub state: String,
    pub expires_at: DateTime<Utc>,
}

/// Query parameters returned on authorization callback (E02).
#[derive(Debug, Deserialize, IntoParams)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    /// Optional format override.
    pub format: Option<String>,
}

/// Session payload summary returned upon successful login callback.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CallbackResponse {
    pub session_id: String,
    pub principal_id: String,
    pub status: String,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
}

/// E01: GET /api/v1/auth/login
/// Initiates the OIDC Authorization Code + S256 PKCE flow.
#[utoipa::path(
    get,
    path = "/api/v1/auth/login",
    params(LoginQuery),
    responses(
        (status = 302, description = "Redirect to OIDC Identity Provider authorization endpoint"),
        (status = 200, description = "JSON authorization URL and state token", body = LoginResponse),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "Authentication"
)]
pub async fn login_handler(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    let auth_params = if let Some(ref pool) = state.pool {
        let mut tx = pool.begin().await.map_err(|_| {
            ProblemDetails::internal_server_error(Some("/api/v1/auth/login".into()))
        })?;

        let params = OidcFlowService::initiate_login(&mut tx, &state.oidc_client)
            .await
            .map_err(ProblemDetails::from)?;

        tx.commit().await.map_err(|_| {
            ProblemDetails::internal_server_error(Some("/api/v1/auth/login".into()))
        })?;

        params
    } else {
        state
            .oidc_client
            .create_authorization_request()
            .map_err(ProblemDetails::from)?
    };

    let wants_json = query.format.as_deref() == Some("json")
        || headers
            .get(ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("application/json"))
            .unwrap_or(false);

    if wants_json {
        let resp_payload = LoginResponse {
            authorization_url: auth_params.authorization_url.to_string(),
            state: auth_params.state_token,
            expires_at: auth_params.expires_at,
        };
        Ok((StatusCode::OK, axum::Json(resp_payload)).into_response())
    } else {
        let mut resp = StatusCode::FOUND.into_response();
        if let Ok(loc_hdr) = HeaderValue::from_str(auth_params.authorization_url.as_str()) {
            resp.headers_mut().insert(LOCATION, loc_hdr);
        }
        Ok(resp)
    }
}

/// E02: GET /api/v1/auth/callback
/// Validates OIDC callback, exchanges authorization code with PKCE verifier, creates session.
#[utoipa::path(
    get,
    path = "/api/v1/auth/callback",
    params(CallbackQuery),
    responses(
        (status = 302, description = "Redirect to application home with session cookie set"),
        (status = 200, description = "JSON session summary with session cookie set", body = CallbackResponse),
        (status = 400, description = "Bad Request: missing code/state or OIDC error", body = ProblemDetails),
        (status = 500, description = "Internal server error", body = ProblemDetails)
    ),
    tag = "Authentication"
)]
pub async fn callback_handler(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, ProblemDetails> {
    // 1. Check for IdP errors
    if let Some(err) = query.error {
        let desc = query
            .error_description
            .unwrap_or_else(|| "OIDC provider returned an error".to_string());
        return Err(ProblemDetails::bad_request(
            format!("OIDC Error: {err} - {desc}"),
            Some("/api/v1/auth/callback".into()),
        ));
    }

    let code = query.code.ok_or_else(|| {
        ProblemDetails::bad_request(
            "Missing 'code' query parameter in OIDC callback",
            Some("/api/v1/auth/callback".into()),
        )
    })?;

    let state_token = query.state.ok_or_else(|| {
        ProblemDetails::bad_request(
            "Missing 'state' query parameter in OIDC callback",
            Some("/api/v1/auth/callback".into()),
        )
    })?;

    let user_agent = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());

    let pool = state.pool.as_ref().ok_or_else(|| {
        ProblemDetails::internal_server_error(Some("/api/v1/auth/callback".into()))
    })?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some("/api/v1/auth/callback".into())))?;

    let (session, raw_token, principal_id) = OidcFlowService::handle_callback(
        &mut tx,
        &state.oidc_client,
        &code,
        &state_token,
        &state.config.session,
        None,
        None,
        user_agent,
    )
    .await
    .map_err(ProblemDetails::from)?;

    tx.commit()
        .await
        .map_err(|_| ProblemDetails::internal_server_error(Some("/api/v1/auth/callback".into())))?;

    // Build Set-Cookie header
    let cookie_header = SessionCookieBuilder::build_set_cookie(&state.config.session, &raw_token);

    let wants_json = query.format.as_deref() == Some("json")
        || headers
            .get(ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("application/json"))
            .unwrap_or(false);

    if wants_json {
        let resp_payload = CallbackResponse {
            session_id: session.session_id.to_string(),
            principal_id: principal_id.to_string(),
            status: "active".to_string(),
            idle_expires_at: session.idle_expires_at,
            absolute_expires_at: session.absolute_expires_at,
        };

        let mut resp = (StatusCode::OK, axum::Json(resp_payload)).into_response();
        if let Ok(cookie_val) = HeaderValue::from_str(&cookie_header) {
            resp.headers_mut().insert(SET_COOKIE, cookie_val);
        }
        Ok(resp)
    } else {
        let mut resp = StatusCode::FOUND.into_response();
        resp.headers_mut()
            .insert(LOCATION, HeaderValue::from_static("/"));
        if let Ok(cookie_val) = HeaderValue::from_str(&cookie_header) {
            resp.headers_mut().insert(SET_COOKIE, cookie_val);
        }
        Ok(resp)
    }
}
