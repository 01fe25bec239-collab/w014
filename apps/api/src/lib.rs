//! w014-api: Foundation API composition root and HTTP server skeleton.
//!
//! Provides the authoritative Rust backend API server, operational health probes,
//! RFC 9457 problem details, correlation middleware, and OpenAPI documentation.

pub mod config;
pub mod error;
pub mod middleware;
pub mod openapi;
pub mod routes;

use axum::Router;
use axum::middleware as axum_middleware;
use axum::routing::get;

pub use config::ApiConfig;
pub use error::{ApiError, PROBLEM_JSON_MEDIA_TYPE, ProblemDetails};
pub use openapi::{ApiDoc, build_openapi_router};

/// Builds and configures the top-level Axum router for the Foundation API.
pub fn create_app(_config: &ApiConfig) -> Router {
    let (router, api) = build_openapi_router();

    router
        // Operational health alias probe
        .route("/health", get(routes::health::health_alias_handler))
        // Machine-readable OpenAPI 3.x specification JSON
        .route(
            "/openapi.json",
            get({
                let openapi_json = axum::Json(api);
                move || async move { openapi_json.clone() }
            }),
        )
        // Global fallback for unmatched routes returning RFC 9457 404 Problem Details
        .fallback(error::fallback_404_handler)
        // Correlation middleware (runs on all requests and responses)
        .layer(axum_middleware::from_fn(
            middleware::correlation::correlation_middleware,
        ))
}
