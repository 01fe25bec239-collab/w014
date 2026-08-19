//! w014-api: Foundation API composition root and HTTP server skeleton.
//!
//! Provides the authoritative Rust backend API server, operational health probes,
//! RFC 9457 problem details, correlation middleware, authentication/session management (E01-E04),
//! and OpenAPI documentation.

pub mod config;
pub mod error;
pub mod middleware;
pub mod openapi;
pub mod routes;

use axum::Router;
use axum::middleware as axum_middleware;
use axum::routing::get;
use sqlx::PgPool;
use w014_authn::csrf::CsrfProtector;
use w014_authn::oidc::OidcClient;

pub use config::ApiConfig;
pub use error::{ApiError, PROBLEM_JSON_MEDIA_TYPE, ProblemDetails};
pub use openapi::{ApiDoc, build_openapi_router};

/// Top-level application state shared across handlers and middleware.
#[derive(Clone)]
pub struct AppState {
    pub config: ApiConfig,
    pub oidc_client: OidcClient,
    pub csrf_protector: CsrfProtector,
    pub pool: Option<PgPool>,
}

impl AppState {
    pub fn new(config: ApiConfig, pool: Option<PgPool>) -> Self {
        let oidc_client = OidcClient::new(config.oidc.clone());
        let csrf_protector = CsrfProtector::new(config.csrf.clone());
        Self {
            config,
            oidc_client,
            csrf_protector,
            pool,
        }
    }

    pub fn with_oidc_client(mut self, client: OidcClient) -> Self {
        self.oidc_client = client;
        self
    }
}

/// Builds and configures the top-level Axum router for the Foundation API without DB pool.
pub fn create_app(config: &ApiConfig) -> Router {
    let state = AppState::new(config.clone(), None);
    create_app_with_state(state)
}

/// Builds and configures the top-level Axum router with a specific database pool.
pub fn create_app_with_pool(config: &ApiConfig, pool: PgPool) -> Router {
    let state = AppState::new(config.clone(), Some(pool));
    create_app_with_state(state)
}

/// Builds the top-level router given an initialized `AppState`.
pub fn create_app_with_state(state: AppState) -> Router {
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
        // Authn middleware
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::authn::authn_middleware,
        ))
        // Correlation middleware (runs on all requests and responses)
        .layer(axum_middleware::from_fn(
            middleware::correlation::correlation_middleware,
        ))
        .with_state(state)
}
