//! OpenAPI specification and routing aggregation for Foundation API.

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::AppState;
use crate::error::ProblemDetails;
use crate::routes::auth::{CallbackResponse, LoginResponse};
use crate::routes::capability_grants::{CapabilityGrantDto, RevokeGrantDto};
use crate::routes::health::HealthResponse;
use crate::routes::memberships::{CreateMembershipDto, MembershipDto, MembershipPage};
use crate::routes::programs::{CreateProgramDto, ProgramDto, ProgramPage};
use crate::routes::session::{LogoutResponse, SessionResponse};
use crate::routes::workspaces::{CreateWorkspaceDto, WorkspaceDto, WorkspacePage};

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
            LogoutResponse,
            ProgramDto,
            CreateProgramDto,
            ProgramPage,
            WorkspaceDto,
            CreateWorkspaceDto,
            WorkspacePage,
            MembershipDto,
            CreateMembershipDto,
            MembershipPage,
            CapabilityGrantDto,
            RevokeGrantDto
        )
    ),
    tags(
        (name = "Health", description = "Operational health and readiness endpoints"),
        (name = "Authentication", description = "OIDC login and callback authentication endpoints (E01-E02)"),
        (name = "Session", description = "Server-side session inspection and revocation endpoints (E03-E04)"),
        (name = "Programs", description = "Program management endpoints (E05-E07)"),
        (name = "Workspaces", description = "Workspace management endpoints (E08-E10)"),
        (name = "Memberships", description = "Workspace membership endpoints (E12-E13)"),
        (name = "CapabilityGrants", description = "Capability grant authority endpoints (E14-E15)")
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
        .routes(routes!(crate::routes::programs::list_programs_handler))
        .routes(routes!(crate::routes::programs::create_program_handler))
        .routes(routes!(crate::routes::programs::get_program_handler))
        .routes(routes!(crate::routes::workspaces::list_workspaces_handler))
        .routes(routes!(crate::routes::workspaces::create_workspace_handler))
        .routes(routes!(crate::routes::workspaces::get_workspace_handler))
        .routes(routes!(
            crate::routes::memberships::list_memberships_handler
        ))
        .routes(routes!(
            crate::routes::memberships::create_membership_handler
        ))
        .routes(routes!(
            crate::routes::capability_grants::create_capability_grant_handler
        ))
        .routes(routes!(
            crate::routes::capability_grants::revoke_capability_grant_handler
        ))
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

        // Verify foundation and authn paths exist
        assert!(json.contains("/healthz"));
        assert!(json.contains("/api/v1/auth/login"));
        assert!(json.contains("/api/v1/auth/callback"));
        assert!(json.contains("/api/v1/session"));
        assert!(json.contains("/api/v1/session/logout"));

        // Verify WI-0105 endpoints exist (E05-E10, E12-E15)
        assert!(json.contains("/api/v1/programs"));
        assert!(json.contains("/api/v1/programs/{program_id}"));
        assert!(json.contains("/api/v1/programs/{program_id}/workspaces"));
        assert!(json.contains("/api/v1/workspaces/{workspace_id}"));
        assert!(json.contains("/api/v1/workspaces/{workspace_id}/memberships"));
        assert!(json.contains("/api/v1/workspaces/{workspace_id}/capability-grants"));
        assert!(
            json.contains("/api/v1/workspaces/{workspace_id}/capability-grants/{grant_id}/revoke")
        );

        // Verify schemas exist
        assert!(json.contains("HealthResponse"));
        assert!(json.contains("ProblemDetails"));
        assert!(json.contains("LoginResponse"));
        assert!(json.contains("SessionResponse"));
        assert!(json.contains("LogoutResponse"));
        assert!(json.contains("ProgramDto"));
        assert!(json.contains("CreateProgramDto"));
        assert!(json.contains("ProgramPage"));
        assert!(json.contains("WorkspaceDto"));
        assert!(json.contains("CreateWorkspaceDto"));
        assert!(json.contains("WorkspacePage"));
        assert!(json.contains("MembershipDto"));
        assert!(json.contains("CreateMembershipDto"));
        assert!(json.contains("MembershipPage"));
        assert!(json.contains("CapabilityGrantDto"));
        assert!(json.contains("RevokeGrantDto"));

        // Verify strictly forbidden endpoints are ABSENT (E11 / source-state, CDRL, findings, W2)
        assert!(!json.contains("source-state"));
        assert!(!json.contains("cdrl"));
        assert!(!json.contains("findings"));
    }
}
