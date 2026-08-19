//! Application layer for W-014 Identity, Access, and Workspace semantics.
//!
//! Provides transactional service coordination, repository implementations mapping
//! domain models to PostgreSQL, and consumption of authoritative Persistence contracts
//! (`AuditAppendContract`, `AuditChainHashContract`, `IdempotencyStore`).

pub mod authz;
pub mod error;
pub mod persistence;
pub mod services;

pub use authz::WorkspaceAuthzResolver;
pub use error::ApplicationError;
pub use persistence::{
    CapabilityGrantRepository, MembershipRepository, OidcIdentityRepository,
    OidcTransactionRepository, OrganizationRepository, PrincipalRepository, ProgramRepository,
    SessionRepository, SessionRotationRepository, WorkspaceRepository,
};
pub use services::{
    CapabilityGrantService, IdempotencyCoordinator, MembershipService, OidcPersistenceService,
    SessionService, WorkspaceInitializationService,
};
