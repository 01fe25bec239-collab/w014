//! Authentication and CSRF Axum middleware layers.

use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use w014_application::persistence::SessionRepository;
use w014_authn::middleware::AuthenticatedSession;
use w014_authn::session::{Session, SessionCookieBuilder, SessionStatus};

use crate::AppState;
use crate::error::ProblemDetails;

/// Middleware extracting and validating session cookie, injecting `AuthenticatedSession` into extensions.
pub async fn authn_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, ProblemDetails> {
    if let Some(session) = try_authenticate(&state, req.headers()).await {
        req.extensions_mut()
            .insert(AuthenticatedSession::from_session(&session));
    }

    Ok(next.run(req).await)
}

async fn try_authenticate(state: &AppState, headers: &HeaderMap) -> Option<Session> {
    let token = SessionCookieBuilder::extract_token(headers, &state.config.session.cookie_name)?;
    let pool = state.pool.as_ref()?;
    let mut tx = pool.begin().await.ok()?;

    let active_hash = state.config.session.hash_token(&token);
    let session = match SessionRepository::get_by_token_hash(&mut tx, &active_hash).await {
        Ok(Some(s)) => Some(s),
        _ => match state.config.session.hash_token_previous(&token) {
            Some(prev_hash) => SessionRepository::get_by_token_hash(&mut tx, &prev_hash)
                .await
                .ok()
                .flatten(),
            None => None,
        },
    };

    session.filter(|s| s.status == SessionStatus::Active)
}
