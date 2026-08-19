//! API route handlers module.

pub mod auth;
pub mod capability_grants;
pub mod health;
pub mod memberships;
pub mod programs;
pub mod session;
pub mod workspaces;

pub use auth::{
    CallbackQuery, CallbackResponse, LoginQuery, LoginResponse, callback_handler, login_handler,
};
pub use capability_grants::{
    CapabilityGrantDto, RevokeGrantDto, create_capability_grant_handler,
    revoke_capability_grant_handler,
};
pub use health::{HealthResponse, health_alias_handler, healthz_handler};
pub use memberships::{
    CreateMembershipDto, MembershipDto, MembershipPage, create_membership_handler,
    list_memberships_handler,
};
pub use programs::{
    CreateProgramDto, PaginationQuery, ProgramDto, ProgramPage, create_program_handler,
    get_program_handler, list_programs_handler,
};
pub use session::{LogoutResponse, SessionResponse, get_session_handler, logout_handler};
pub use workspaces::{
    CreateWorkspaceDto, WorkspaceDto, WorkspacePage, create_workspace_handler,
    get_workspace_handler, list_workspaces_handler,
};
