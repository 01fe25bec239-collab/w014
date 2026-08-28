//! OpenAPI specification and routing aggregation for Foundation API.

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::AppState;
use crate::error::ProblemDetails;
use crate::routes::auth::{CallbackResponse, LoginResponse};
use crate::routes::capability_grants::{CapabilityGrantDto, RevokeGrantDto};
use crate::routes::documents::{
    CreateDocumentDto, CreateUploadIntentDto, DocumentDto, DocumentPage, DocumentVersionDto,
    DocumentVersionPage, DownloadDto, PresignedPutDto, UploadIntentDto,
};
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
            RevokeGrantDto,
            DocumentDto,
            CreateDocumentDto,
            DocumentPage,
            DocumentVersionDto,
            DocumentVersionPage,
            CreateUploadIntentDto,
            PresignedPutDto,
            UploadIntentDto,
            DownloadDto
        )
    ),
    tags(
        (name = "Health", description = "Operational health and readiness endpoints"),
        (name = "Authentication", description = "OIDC login and callback authentication endpoints (E01-E02)"),
        (name = "Session", description = "Server-side session inspection and revocation endpoints (E03-E04)"),
        (name = "Programs", description = "Program management endpoints (E05-E07)"),
        (name = "Workspaces", description = "Workspace management endpoints (E08-E10)"),
        (name = "Memberships", description = "Workspace membership endpoints (E12-E13)"),
        (name = "CapabilityGrants", description = "Capability grant authority endpoints (E14-E15)"),
        (name = "Documents", description = "Document registry, presign, and version acceptance endpoints (E16-E24)")
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
        .routes(routes!(crate::routes::documents::list_documents_handler))
        .routes(routes!(crate::routes::documents::create_document_handler))
        .routes(routes!(crate::routes::documents::get_document_handler))
        .routes(routes!(
            crate::routes::documents::list_document_versions_handler
        ))
        .routes(routes!(
            crate::routes::documents::create_upload_intent_handler
        ))
        .routes(routes!(
            crate::routes::documents::finalize_upload_intent_handler
        ))
        .routes(routes!(
            crate::routes::documents::get_document_version_handler
        ))
        .routes(routes!(crate::routes::documents::accept_version_handler))
        .routes(routes!(crate::routes::documents::download_version_handler))
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

        // Verify WI-0202 endpoints exist (E16-E24)
        assert!(json.contains("/api/v1/workspaces/{workspace_id}/documents"));
        assert!(json.contains("/api/v1/workspaces/{workspace_id}/documents/{document_id}"));
        assert!(
            json.contains("/api/v1/workspaces/{workspace_id}/documents/{document_id}/versions")
        );
        assert!(
            json.contains(
                "/api/v1/workspaces/{workspace_id}/documents/{document_id}/upload-intents"
            )
        );
        assert!(
            json.contains("/api/v1/workspaces/{workspace_id}/upload-intents/{intent_id}/finalize")
        );
        assert!(json.contains("/api/v1/workspaces/{workspace_id}/document-versions/{version_id}"));
        assert!(
            json.contains(
                "/api/v1/workspaces/{workspace_id}/document-versions/{version_id}/accept"
            )
        );
        assert!(
            json.contains(
                "/api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download"
            )
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
        assert!(json.contains("DocumentDto"));
        assert!(json.contains("CreateDocumentDto"));
        assert!(json.contains("DocumentPage"));
        assert!(json.contains("DocumentVersionDto"));
        assert!(json.contains("DocumentVersionPage"));
        assert!(json.contains("CreateUploadIntentDto"));
        assert!(json.contains("PresignedPutDto"));
        assert!(json.contains("UploadIntentDto"));
        assert!(json.contains("DownloadDto"));

        // Verify strictly forbidden endpoints are ABSENT (E11 / source-state, CDRL, findings, W3)
        assert!(!json.contains("source-state"));
        assert!(!json.contains("cdrl"));
        assert!(!json.contains("findings"));
    }

    #[test]
    fn test_wi0202_openapi_methods_and_paths() {
        let (_router, spec) = build_openapi_router();
        let paths = &spec.paths.paths;

        // E16: GET /api/v1/workspaces/{workspace_id}/documents
        let e16_e17 = paths
            .get("/api/v1/workspaces/{workspace_id}/documents")
            .expect("E16/E17 path must exist");
        assert!(e16_e17.get.is_some(), "E16 GET method must exist");
        // E17: POST /api/v1/workspaces/{workspace_id}/documents
        assert!(e16_e17.post.is_some(), "E17 POST method must exist");

        // E18: GET /api/v1/workspaces/{workspace_id}/documents/{document_id}
        let e18 = paths
            .get("/api/v1/workspaces/{workspace_id}/documents/{document_id}")
            .expect("E18 path must exist");
        assert!(e18.get.is_some(), "E18 GET method must exist");

        // E19: GET /api/v1/workspaces/{workspace_id}/documents/{document_id}/versions
        let e19 = paths
            .get("/api/v1/workspaces/{workspace_id}/documents/{document_id}/versions")
            .expect("E19 path must exist");
        assert!(e19.get.is_some(), "E19 GET method must exist");

        // E20: POST /api/v1/workspaces/{workspace_id}/documents/{document_id}/upload-intents
        let e20 = paths
            .get("/api/v1/workspaces/{workspace_id}/documents/{document_id}/upload-intents")
            .expect("E20 path must exist");
        assert!(e20.post.is_some(), "E20 POST method must exist");

        // E21: POST /api/v1/workspaces/{workspace_id}/upload-intents/{intent_id}/finalize
        let e21 = paths
            .get("/api/v1/workspaces/{workspace_id}/upload-intents/{intent_id}/finalize")
            .expect("E21 path must exist");
        assert!(e21.post.is_some(), "E21 POST method must exist");
        let e21_op = e21.post.as_ref().unwrap();
        assert!(
            e21_op.responses.responses.contains_key("501"),
            "E21 must declare 501 deferred response"
        );

        // E22: GET /api/v1/workspaces/{workspace_id}/document-versions/{version_id}
        let e22 = paths
            .get("/api/v1/workspaces/{workspace_id}/document-versions/{version_id}")
            .expect("E22 path must exist");
        assert!(e22.get.is_some(), "E22 GET method must exist");

        // E23: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/accept
        let e23 = paths
            .get("/api/v1/workspaces/{workspace_id}/document-versions/{version_id}/accept")
            .expect("E23 path must exist");
        assert!(e23.post.is_some(), "E23 POST method must exist");

        // E24: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download
        let e24 = paths
            .get("/api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download")
            .expect("E24 path must exist");
        assert!(e24.post.is_some(), "E24 POST method must exist");
    }
}
