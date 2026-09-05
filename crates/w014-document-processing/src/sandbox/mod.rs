//! Parser sandbox execution boundary and security profiles (WI-0205).
//!
//! Provides:
//! - Security profiles and hard frozen resource ceilings (`SandboxSecurityProfile`, `SandboxResourceCeilings`)
//! - Scoped single-object handoff input (`SandboxInput`)
//! - Typed, bounded output contract (`SandboxOutput`, `SandboxStatus`, `OutputValidationError`)
//! - Fail-closed error taxonomy (`SandboxError`)
//! - Runner abstraction trait (`SandboxRunner`)
//! - Deterministic test double runner (`MockSandboxRunner`, `MockSandboxBehavior`)
//! - Isolated process runner (`ProcessSandboxRunner`)

pub mod error;
pub mod input;
pub mod mock;
pub mod oci;
pub mod output;
pub mod pdf;
pub mod process;
pub mod profile;
pub mod traits;

pub use error::SandboxError;
pub use input::SandboxInput;
pub use mock::{MockSandboxBehavior, MockSandboxRunner};
pub use oci::{
    APPROVED_DOCKER_CANDIDATE_PATHS, APPROVED_ISOLATION_BINARY_NAME, AUTHORITATIVE_OCI_IMAGE,
    CLIENT_REAP_TIMEOUT_SECS, CONTAINER_INSPECT_TIMEOUT_SECS, CONTAINER_NAME_PREFIX,
    CONTAINER_RM_TIMEOUT_SECS, DEFAULT_EXPECTED_IMAGE_REVISION, DEFAULT_OCI_IMAGE,
    ENV_EXPECTED_IMAGE_REVISION, EXPECTED_OOXMLSDK_VERSION, EXPECTED_PARSER_BINARY_NAME,
    EXPECTED_PDFIUM_SHA256, EXPECTED_PDFIUM_VERSION, IMAGE_PREFLIGHT_TIMEOUT_SECS,
    LABEL_IMAGE_REVISION, LABEL_OOXMLSDK_VERSION, LABEL_PARSER_BINARY, LABEL_PDFIUM_SHA256,
    LABEL_PDFIUM_VERSION, build_docker_run_argv, build_docker_run_argv_with_container_name,
    container_present, discover_docker_binary, expected_image_revision, generate_container_name,
    is_approved_isolation_binary, is_authoritative_image, is_valid_container_name,
    preflight_local_image, resolve_approved_docker_binary, terminate_container_by_name,
};
pub use output::{
    MAX_BOUNDED_BLOCK_COUNT, MAX_BOUNDED_PAGE_COUNT, MAX_BOUNDED_SPAN_COUNT,
    MAX_EXECUTION_DURATION_MS, OutputValidationError, SANDBOX_PROTOCOL_VERSION, SandboxOutput,
    SandboxStatus,
};
pub use pdf::PdfSandboxRunner;
pub use process::{
    ENV_PARSER_SANDBOX_WRAPPER_ARGS, ENV_PARSER_SANDBOX_WRAPPER_BIN, ProcessSandboxRunner,
};
pub use profile::{
    FROZEN_MAX_CPU_CORES, FROZEN_MAX_MEMORY_BYTES, FROZEN_MAX_OUTPUT_BYTES, FROZEN_MAX_PIDS,
    FROZEN_MAX_TMPFS_BYTES, FROZEN_MAX_WALL_CLOCK_SECS, NON_ROOT_GID, NON_ROOT_UID,
    SandboxCredentialsPolicy, SandboxFilesystemPolicy, SandboxNetworkPolicy, SandboxProcessPolicy,
    SandboxResourceCeilings, SandboxSecurityProfile,
};
pub use traits::SandboxRunner;
