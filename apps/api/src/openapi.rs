//! OpenAPI specification and routing aggregation for Foundation API.

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::ProblemDetails;
use crate::routes::health::HealthResponse;

/// Aggregated OpenAPI documentation metadata and schemas for the Foundation Platform API.
#[derive(OpenApi)]
#[openapi(
    components(
        schemas(HealthResponse, ProblemDetails)
    ),
    tags(
        (name = "Health", description = "Operational health and readiness endpoints")
    ),
    info(
        title = "W-014 Foundation Platform API",
        version = "0.1.0",
        description = "Authoritative Rust backend API skeleton and platform composition root."
    )
)]
pub struct ApiDoc;

/// Constructs the OpenApiRouter integrating routes and OpenAPI documentation via utoipa-axum.
pub fn build_openapi_router() -> (axum::Router, utoipa::openapi::OpenApi) {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(crate::routes::health::healthz_handler))
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
        assert!(json.contains("HealthResponse"));
        assert!(json.contains("ProblemDetails"));

        // Verify no business domain endpoints or DTOs exist
        assert!(!json.contains("programs"));
        assert!(!json.contains("workspaces"));
        assert!(!json.contains("cdrl"));
        assert!(!json.contains("findings"));
    }
}
