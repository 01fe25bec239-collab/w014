//! Domain model for W-014 Identity, Access, Workspace, and the WI-0201
//! Document-Pipeline contract surface.
//!
//! Provides infrastructure-free, strongly-typed domain primitives enforcing
//! invariants, identifier safety, and multi-tenant domain boundaries.
//!
//! WI-0201-C adds the ten frozen Document-Pipeline-owned M002R objects:
//! documents, document_versions, document_version_metadata, upload_intents,
//! object_artifacts, quarantine_records, parser_artifacts, parser_pages,
//! parser_blocks, and source_spans (canonical span identity).

pub mod document_metadata;
pub mod document_versions;
pub mod documents;
pub mod error;
pub mod ids;
pub mod json;
pub mod limits;
pub mod media;
pub mod membership;
pub mod object_artifacts;
pub mod organization;
pub mod parser;
pub mod principal;
pub mod program;
pub mod quarantine;
pub mod sha256;
pub mod source_spans;
pub mod upload_intents;
pub mod validation;
pub mod workspace;

pub use document_metadata::DocumentVersionMetadata;
pub use document_versions::{DocumentVersion, TrustState, VersionOrdinal};
pub use documents::{Document, DocumentClass, DocumentStatus};
pub use error::DomainError;
pub use ids::{
    DocumentId, DocumentVersionId, DocumentVersionMetadataId, MembershipId, ObjectArtifactId,
    OrganizationId, ParserArtifactId, ParserBlockId, ParserPageId, PrincipalId, ProgramId,
    QuarantineRecordId, SourceSpanId, UploadIntentId, WorkspaceId,
};
pub use json::BoundedJson;
pub use media::{MediaType, StoredMediaType};
pub use membership::{Membership, MembershipRole};
pub use object_artifacts::{ArtifactKind, EncryptionMode, ObjectArtifact, ObjectKey, StorageTier};
pub use organization::Organization;
pub use parser::{
    BlockKind, BoundingBox, ExtractionMethod, LocatorVersion, ParserArtifact, ParserBlock,
    ParserPage, ParserStatus, Rotation,
};
pub use principal::{Principal, PrincipalType};
pub use program::Program;
pub use quarantine::{QuarantineRecord, QuarantineStatus};
pub use sha256::Sha256;
pub use source_spans::{OffsetRange, SectionPath, SourceSpan, SpanProvenance};
pub use upload_intents::IntentStatus;
pub use upload_intents::UploadIntent;
pub use workspace::Workspace;

/// The ten frozen Document-Pipeline-owned M002R objects, in canonical order.
pub const DOCUMENT_PIPELINE_OWNED_OBJECTS: [&str; 10] = [
    "documents",
    "document_versions",
    "document_version_metadata",
    "upload_intents",
    "object_artifacts",
    "quarantine_records",
    "parser_artifacts",
    "parser_pages",
    "parser_blocks",
    "source_spans",
];
