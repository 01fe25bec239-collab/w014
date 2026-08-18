//! OpenAPI specification and Swagger UI aggregation for Foundation API.

use axum::Json;
use axum::response::IntoResponse;
use utoipa::OpenApi;

use crate::error::ProblemDetails;
use crate::routes::health::HealthResponse;

/// Aggregated OpenAPI documentation for the Foundation Platform API.
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routes::health::healthz_handler,
    ),
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

/// Handler returning the generated OpenAPI 3.x JSON specification.
pub async fn openapi_json_handler() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_spec_generation() {
        let spec = ApiDoc::openapi();
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
