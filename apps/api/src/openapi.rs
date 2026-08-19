//! OpenAPI specification and routing aggregation for Foundation API.

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::AppState;
use crate::error::ProblemDetails;
use crate::routes::auth::{CallbackResponse, LoginResponse};
use crate::routes::health::HealthResponse;
use crate::routes::session::{LogoutResponse, SessionResponse};

/// Aggregated OpenAPI documentation metadata and schemas for the Foundation Platform API.
#[derive(OpenApi)]
#[openapi(
    components(
        schemas(
            HealthResponse,
            ProblemDetails,
            LoginResponse,
            CallbackResponse,
            SessionResponse,
            LogoutResponse
        )
    ),
    tags(
        (name = "Health", description = "Operational health and readiness endpoints"),
        (name = "Authentication", description = "OIDC login and callback authentication endpoints (E01-E02)"),
        (name = "Session", description = "Server-side session inspection and revocation endpoints (E03-E04)")
    ),
    info(
        title = "W-014 Foundation Platform API",
        version = "0.1.0",
        description = "Authoritative Rust backend API skeleton and platform composition root."
    )
)]
pub struct ApiDoc;

/// Constructs the OpenApiRouter integrating routes and OpenAPI documentation via utoipa-axum.
pub fn build_openapi_router() -> (axum::Router<AppState>, utoipa::openapi::OpenApi) {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(crate::routes::health::healthz_handler))
        .routes(routes!(crate::routes::auth::login_handler))
        .routes(routes!(crate::routes::auth::callback_handler))
        .routes(routes!(crate::routes::session::get_session_handler))
        .routes(routes!(crate::routes::session::logout_handler))
        .split_for_parts()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_spec_generation() {
        let (_router, spec) = build_openapi_router();
        let json =
            serde_json::to_string_pretty(&spec).expect("OpenAPI spec should serialize to JSON");

        // Verify required paths and components exist
        assert!(json.contains("/healthz"));
        assert!(json.contains("/api/v1/auth/login"));
        assert!(json.contains("/api/v1/auth/callback"));
        assert!(json.contains("/api/v1/session"));
        assert!(json.contains("/api/v1/session/logout"));
        assert!(json.contains("HealthResponse"));
        assert!(json.contains("ProblemDetails"));
        assert!(json.contains("LoginResponse"));
        assert!(json.contains("SessionResponse"));
        assert!(json.contains("LogoutResponse"));

        // Verify strictly no business domain endpoints or DTOs exist
        assert!(!json.contains("programs"));
        assert!(!json.contains("workspaces"));
        assert!(!json.contains("cdrl"));
        assert!(!json.contains("findings"));
    }
}
