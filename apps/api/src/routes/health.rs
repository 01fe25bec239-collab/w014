//! Health check operational endpoints.
//!
//! Provides deterministic, safe process and platform health information.
//! Strictly excludes secrets, host internals, and business state.

use axum::Json;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Operational health check response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    /// Overall platform service operational status (e.g. "ok").
    pub status: String,
    /// Authoritative service identifier.
    pub service: String,
    /// Build / package version of the running process.
    pub version: String,
}

/// Operational health check endpoint.
///
/// Returns 200 OK with safe process metadata if the service is live.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "Health",
    responses(
        (status = 200, description = "Service is operational", body = HealthResponse)
    )
)]
pub async fn healthz_handler() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        service: "w014-api".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Alias handler for `/health` route.
pub async fn health_alias_handler() -> impl IntoResponse {
    healthz_handler().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_response_structure() {
        let response = Json(HealthResponse {
            status: "ok".to_string(),
            service: "w014-api".to_string(),
            version: "0.1.0".to_string(),
        });

        assert_eq!(response.status, "ok");
        assert_eq!(response.service, "w014-api");
        assert_eq!(response.version, "0.1.0");
    }
}
