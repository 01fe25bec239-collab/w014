//! Application services orchestrating domain mutations and persistence.

pub mod capability_service;
pub mod document_service;
pub mod idempotency_service;
pub mod malware_scan_executor;
pub mod membership_service;
pub mod oidc_service;
pub mod parser_sandbox_executor;
pub mod session_service;
pub mod storage;
pub mod workspace_init;

pub use capability_service::CapabilityGrantService;
pub use document_service::{
    DocumentService, FinalizeUploadError, MALWARE_SCAN_MAX_ATTEMPTS, MAX_DOWNLOAD_TTL_SECS,
    PresignedGetContract, PresignedPutContract, StoredObjectMetadata, UploadFinalizeResult,
    can_manage_documents, can_read_documents, can_upload_documents,
};
pub use idempotency_service::IdempotencyCoordinator;
pub use malware_scan_executor::MalwareScanJobExecutor;
pub use membership_service::MembershipService;
pub use oidc_service::OidcPersistenceService;
pub use parser_sandbox_executor::ParserSandboxJobExecutor;
pub use session_service::SessionService;
pub use storage::{S3StorageAdapter, S3StorageConfig};
pub use workspace_init::WorkspaceInitializationService;
