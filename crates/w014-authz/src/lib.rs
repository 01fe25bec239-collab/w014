//! Authorization primitives, capability engine, and AuthorizedWorkspaceContext for W-014.
//!
//! Frozen Semantics:
//! - Authorization is strictly capability-based.
//! - Roles (`Owner`, `Admin`, `Member`, `Viewer`, `Auditor`) are convenience capability profiles only.
//! - Special authorities (`OVERRIDE_BLOCK`, `RIGHTS_REVIEW`, `RULE_ACTIVATION`, `GRANT_AUTHORITY`)
//!   are strictly separated and never implied by role name.
//! - `AuthorizedWorkspaceContext` provides the typed, fail-closed authorization boundary.

pub mod authority;
pub mod authorized_workspace_context;
pub mod capability;
pub mod capability_set;
pub mod error;
pub mod grant;
pub mod policy;
pub mod role_profile;

pub use authority::SpecialAuthority;
pub use authorized_workspace_context::AuthorizedWorkspaceContext;
pub use capability::{Capability, CapabilityGrantId};
pub use capability_set::CapabilitySet;
pub use error::AuthzError;
pub use grant::CapabilityGrant;
pub use policy::{Decision, DenyReason, PolicyEngine, PolicyRule};
pub use role_profile::RoleProfile;
