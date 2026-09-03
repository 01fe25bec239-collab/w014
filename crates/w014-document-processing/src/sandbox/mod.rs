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
pub mod output;
pub mod pdf;
pub mod process;
pub mod profile;
pub mod traits;

pub use error::SandboxError;
pub use input::SandboxInput;
pub use mock::{MockSandboxBehavior, MockSandboxRunner};
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
