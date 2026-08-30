//! WI-0201-C Document-Pipeline persistence-facing contract layer.
//!
//! Row contracts mapping the ten Document-Pipeline-owned M002R objects onto
//! the REPAIRED explicit PostgreSQL physical columns:
//! `documents`, `document_versions`, `document_version_metadata`,
//! `upload_intents`, `object_artifacts`, `quarantine_records`,
//! `parser_artifacts`, `parser_pages`, `parser_blocks`, `source_spans`.
//!
//! Contract rules enforced module-wide:
//! - every repaired explicit physical column is consumed DIRECTLY
//!   (`documents.current_version_id`,
//!   `document_versions.object_artifact_id`/`.original_filename`,
//!   `upload_intents.opaque_object_key`/`.expected_media_type`/
//!   `.expected_length`/`.expected_sha256_b64`,
//!   `object_artifacts.artifact_kind`/`.object_key`/`.content_sha256`/
//!   `.sse_mode`/`.kms_key_ref`,
//!   `quarantine_records.upload_intent_id`/`.status`/`.scanner_version`/
//!   `.reason_code`,
//!   `parser_artifacts.locator_version`/`.artifact_object_id`/
//!   `.text_sha256`);
//! - no caller-context substitute exists for any physical fact;
//! - no JSONB alternate truth exists for any explicit Prompt-12 field;
//! - provenance for spans resolves exclusively through authoritative joins.

pub mod conventions;
pub mod document_version_metadata_row;
pub mod document_versions_row;
pub mod documents_row;
pub mod error;
pub mod object_artifacts_row;
pub mod parser;
pub mod parser_artifacts_row;
pub mod parser_blocks_row;
pub mod parser_pages_row;
pub mod quarantine_records_row;
pub mod sandbox;
pub mod scanner;
pub mod source_spans_row;
pub mod upload_intents_row;

pub use document_version_metadata_row::{
    DocumentVersionMetadataRow, NewDocumentVersionMetadataRow,
};
pub use document_versions_row::{DocumentVersionRow, NewDocumentVersionRow};
pub use documents_row::{DocumentRow, NewDocumentRow};
pub use error::{ContractError, ContractResult};
pub use object_artifacts_row::{NewObjectArtifactRow, ObjectArtifactRow};
pub use parser::{
    DEFAULT_LOCATOR_VERSION, DEFAULT_PARSER_PROFILE_VERSION, DEFAULT_TEXT_NORMALIZATION_VERSION,
    NormalizationResult, PageGeometry, ParsedBlockData, ParsedPageData, ParsedSpanData,
    ParserArtifactData, ParserFailure, ParserLimits, ParserQualityMetrics, ParserRequest,
    ParserWarning, PdfSafeParser, TextWarning, map_normalized_range_to_raw, normalize_text_nfc,
};
pub use parser_artifacts_row::{NewParserArtifactRow, ParserArtifactRow};
pub use parser_blocks_row::{NewParserBlockRow, ParserBlockRow};
pub use parser_pages_row::{NewParserPageRow, ParserPageRow};
pub use quarantine_records_row::{NewQuarantineRecordRow, QuarantineRecordRow};
pub use sandbox::{
    FROZEN_MAX_CPU_CORES, FROZEN_MAX_MEMORY_BYTES, FROZEN_MAX_OUTPUT_BYTES, FROZEN_MAX_PIDS,
    FROZEN_MAX_TMPFS_BYTES, FROZEN_MAX_WALL_CLOCK_SECS, MAX_BOUNDED_BLOCK_COUNT,
    MAX_BOUNDED_PAGE_COUNT, MAX_BOUNDED_SPAN_COUNT, MAX_EXECUTION_DURATION_MS, MockSandboxBehavior,
    MockSandboxRunner, NON_ROOT_GID, NON_ROOT_UID, OutputValidationError, PdfSandboxRunner,
    ProcessSandboxRunner, SANDBOX_PROTOCOL_VERSION, SandboxCredentialsPolicy, SandboxError,
    SandboxFilesystemPolicy, SandboxInput, SandboxNetworkPolicy, SandboxOutput,
    SandboxProcessPolicy, SandboxResourceCeilings, SandboxRunner, SandboxSecurityProfile,
    SandboxStatus,
};
pub use scanner::{
    ClamAvClient, ClamAvConfig, EICAR_TEST_SIGNATURE, EICAR_THREAT_NAME, MalwareScanner,
    MockClamAvScanner, MockScanMode, ScanOutcome, ScanVerdict, ScannerError, SignatureHealth,
    SignatureHealthPolicy, SignatureStatus,
};
pub use source_spans_row::{NewSourceSpanRow, SourceSpanRow, SpanProvenanceJoin};
pub use upload_intents_row::{NewUploadIntentRow, UploadIntentRow};

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
