//! Persistence repository implementations mapping domain entities to PostgreSQL tables.

pub mod authn_repo;
pub mod capability_repo;
pub mod document_repo;
pub mod identity_repo;

pub use authn_repo::{
    OidcIdentityRepository, OidcTransactionRepository, SessionRepository, SessionRotationRepository,
};
pub use capability_repo::CapabilityGrantRepository;
pub use document_repo::{
    ChangeEventRepository, DependencyKeyRepository, DocumentRepository, DocumentVersionRepository,
    ObjectArtifactRepository, QuarantineRecordRepository, UploadIntentRepository,
};
pub use identity_repo::{
    MembershipRepository, OrganizationRepository, PrincipalRepository, ProgramRepository,
    WorkspaceRepository,
};
