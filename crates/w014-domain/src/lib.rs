//! Domain model for W-014 Identity, Organization, Program, Workspace, and Membership.
//!
//! Provides infrastructure-free, strongly-typed domain primitives enforcing
//! invariants, identifier safety, and multi-tenant domain boundaries.

pub mod error;
pub mod ids;
pub mod membership;
pub mod organization;
pub mod principal;
pub mod program;
pub mod validation;
pub mod workspace;

pub use error::DomainError;
pub use ids::{MembershipId, OrganizationId, PrincipalId, ProgramId, WorkspaceId};
pub use membership::{Membership, MembershipRole};
pub use organization::Organization;
pub use principal::{Principal, PrincipalType};
pub use program::Program;
pub use workspace::Workspace;
