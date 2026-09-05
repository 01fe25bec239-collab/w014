//! Authoritative OCI/container isolation policy generator (WI-0205 D3).
//!
//! This module is the single W014-controlled authority for production parser
//! sandbox isolation. It generates the complete `docker run` policy; caller
//! configuration may only select/locate the approved `docker` backend binary.
//! Configuration can never remove, replace, or weaken mandatory isolation
//! arguments.
//!
//! Enforced production semantics (every property actually passed to the
//! container runtime, not merely declared):
//! - network: NONE (`--network=none`)
//! - root filesystem: READ ONLY (`--read-only`)
//! - host volume mounts: NONE (no `-v`/`--volume`/bind mounts emitted)
//! - secret mounts: NONE (no `--secret`/secret mounts emitted)
//! - Docker socket: NONE (no `/var/run/docker.sock` mount emitted)
//! - scratch tmpfs: `<=1 GiB` (`--mount type=tmpfs,destination=/tmp,...`)
//! - user: NON-ROOT (`--user 65534:65534`)
//! - capabilities: DROP ALL (`--cap-drop=ALL`, never `--cap-add`/`--privileged`)
//! - no-new-privileges: YES (`--security-opt=no-new-privileges:true`)
//! - seccomp/platform equivalent: RESTRICTIVE (Linux: explicit default
//!   profile; other platforms: daemon default restrictive profile applies and
//!   `unconfined` is never emitted)
//! - CPU capacity: `<=2 vCPU` actually enforced via `--cpus` quota
//!   (CFS bandwidth control, not accumulated-time accounting)
//! - memory: `<=2 GiB` via `--memory` + `--memory-swap` (equal, no swap escape)
//! - PIDs: `<=64` via `--pids-limit`
//! - wall-clock: `<=600s` enforced by the runner timeout (container killed)
//! - stdin: ONLY scoped object/protocol bytes (piped, no other mounts)
//! - stdout/stderr: HARD BOUNDED during streaming consumption
//! - credentials: NOT INJECTED (only `W014_*` scoped metadata via `-e`)
//! - image pull: NEVER (`--pull=never`; missing local image fails closed,
//!   registry resolution as fallback is impossible)
//! - container identity: server-generated `--name w014-parser-sandbox-<uuid>`
//!   so the ACTUAL container (not just the `docker run` client) can be
//!   deterministically terminated (`docker rm -f <name>`)
//! - image authority: local `w014-parser-sandbox:local` preflighted via
//!   `docker image inspect` (existence + `org.opencontainers.image.revision`
//!   match against the server-controlled expected revision +
//!   `w014.parser.binary` / PDFium / ooxmlsdk identity labels)

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use super::error::SandboxError;
use super::input::SandboxInput;
use super::profile::{
    FROZEN_MAX_CPU_CORES, FROZEN_MAX_MEMORY_BYTES, FROZEN_MAX_PIDS, FROZEN_MAX_TMPFS_BYTES,
    NON_ROOT_GID, NON_ROOT_UID, SandboxSecurityProfile,
};

/// Default OCI image containing the concrete `w014-parser-sandbox` binary.
///
/// The image is W014-controlled build truth: it carries the parser binary and
/// its native dependencies (PDFium, tesseract data) on an immutable,
/// read-only root filesystem. No host paths are mounted into it.
pub const DEFAULT_OCI_IMAGE: &str = "w014-parser-sandbox:local";

/// Authoritative production parser sandbox image.
///
/// Alias of [`DEFAULT_OCI_IMAGE`]. Production Docker invocation always
/// targets this exact reference with `--pull=never`; a missing local image
/// fails closed and registry resolution as fallback is impossible.
pub const AUTHORITATIVE_OCI_IMAGE: &str = DEFAULT_OCI_IMAGE;

/// Canonical in-image parser binary identity carried by the authoritative image.
pub const EXPECTED_PARSER_BINARY_NAME: &str = "w014-parser-sandbox";

/// Server-controlled selector for the expected authoritative image revision.
///
/// When set to a non-empty value it overrides [`DEFAULT_EXPECTED_IMAGE_REVISION`].
/// It is read from the server process environment only; browser input, job
/// payloads, document bytes, and parser output can never supply it.
pub const ENV_EXPECTED_IMAGE_REVISION: &str = "W014_PARSER_SANDBOX_EXPECTED_REVISION";

/// Compiled default expected `org.opencontainers.image.revision`.
///
/// Build truth of the authoritative image (Foundation `build-image.sh` stamps
/// `git rev-parse HEAD` at image build time). Must be refreshed (DP-owned)
/// whenever the authoritative image is rebuilt from a new revision; the
/// [`ENV_EXPECTED_IMAGE_REVISION`] server environment selector takes
/// precedence without a code change.
pub const DEFAULT_EXPECTED_IMAGE_REVISION: &str = "0e90b96c5a2bc8214a02e78ec13327c389b69f27";

/// Expected authoritative PDFium version label (`w014.pdfium.version`).
pub const EXPECTED_PDFIUM_VERSION: &str = "pdfium-151.0.7881.0";

/// Expected authoritative PDFium SHA-256 label (`w014.pdfium.sha256`, linux/arm64).
pub const EXPECTED_PDFIUM_SHA256: &str =
    "6252fce3da45e7f0dc5b27f4d4e1a1456ca3f7734cdb04f927967df772127478";

/// Expected authoritative DOCX engine version label (`w014.ooxmlsdk.version`).
pub const EXPECTED_OOXMLSDK_VERSION: &str = "0.12.0";

/// OCI label carrying the image build revision.
pub const LABEL_IMAGE_REVISION: &str = "org.opencontainers.image.revision";

/// OCI label carrying the in-image parser binary identity.
pub const LABEL_PARSER_BINARY: &str = "w014.parser.binary";

/// OCI label carrying the authoritative PDFium version.
pub const LABEL_PDFIUM_VERSION: &str = "w014.pdfium.version";

/// OCI label carrying the authoritative PDFium artifact SHA-256.
pub const LABEL_PDFIUM_SHA256: &str = "w014.pdfium.sha256";

/// OCI label carrying the authoritative DOCX engine version.
pub const LABEL_OOXMLSDK_VERSION: &str = "w014.ooxmlsdk.version";

/// Server-generated container name prefix.
///
/// The suffix is a fresh random UUID (never browser/job/document/parser
/// controlled), so every parser container has a deterministic W014-generated
/// identity that abort paths can terminate via `docker rm -f <name>`.
pub const CONTAINER_NAME_PREFIX: &str = "w014-parser-sandbox-";

/// Bounded preflight budget for `docker image inspect` (seconds).
pub const IMAGE_PREFLIGHT_TIMEOUT_SECS: u64 = 30;

/// Bounded budget for `docker rm -f <container>` termination (seconds).
pub const CONTAINER_RM_TIMEOUT_SECS: u64 = 30;

/// Bounded budget for post-termination `docker inspect <container>` proof (seconds).
pub const CONTAINER_INSPECT_TIMEOUT_SECS: u64 = 15;

/// Bounded budget for reaping the `docker run` client process (seconds).
pub const CLIENT_REAP_TIMEOUT_SECS: u64 = 10;

/// Resolves the server-controlled expected authoritative image revision.
///
/// Server process environment ([`ENV_EXPECTED_IMAGE_REVISION`]) wins when
/// non-empty; otherwise the compiled build truth
/// ([`DEFAULT_EXPECTED_IMAGE_REVISION`]) applies. Never derived from browser
/// input, job payloads, document bytes, or parser output.
#[must_use]
pub fn expected_image_revision() -> String {
    std::env::var(ENV_EXPECTED_IMAGE_REVISION)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_EXPECTED_IMAGE_REVISION.to_string())
}

/// Returns true only for the authoritative production image reference.
#[must_use]
pub fn is_authoritative_image(image: &str) -> bool {
    image == AUTHORITATIVE_OCI_IMAGE
}

/// Generates a fresh server-generated unique OCI container name.
///
/// Shape: `w014-parser-sandbox-<32 lowercase hex>` (UUID v4, no hyphens).
/// The identity is never derived from browser input, job payloads, document
/// bytes, or parser output.
#[must_use]
pub fn generate_container_name() -> String {
    format!("{CONTAINER_NAME_PREFIX}{}", uuid::Uuid::new_v4().simple())
}

/// Validates a W014-generated container identity (defense in depth).
///
/// Docker names must match `[a-zA-Z0-9][a-zA-Z0-9_.-]+`; anything else
/// (empty, path separators, shell metacharacters, whitespace) fails closed.
#[must_use]
pub fn is_valid_container_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// Canonical file name of the approved isolation backend.
pub const APPROVED_ISOLATION_BINARY_NAME: &str = "docker";

/// Canonical search paths for the approved `docker` backend binary.
pub const APPROVED_DOCKER_CANDIDATE_PATHS: &[&str] = &[
    "/usr/local/bin/docker",
    "/usr/bin/docker",
    "/opt/homebrew/bin/docker",
];

/// Returns true only for the approved `docker` isolation backend binary.
///
/// Any other executable name (shells, env wrappers, bubblewrap, sandbox-exec,
/// custom harnesses) is NOT approved, even when the path exists on disk.
#[must_use]
pub fn is_approved_isolation_binary(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == APPROVED_ISOLATION_BINARY_NAME)
}

fn which_in_path(executable: &Path) -> Option<PathBuf> {
    if executable.is_absolute() || executable.components().count() > 1 {
        if executable.is_file() {
            return Some(executable.to_path_buf());
        }
        return None;
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(executable);
        if candidate.is_file() && is_approved_isolation_binary(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Returns true when the path exists on the host (absolute file or `PATH` lookup).
fn exists_on_host(path: &Path) -> bool {
    if path.is_file() {
        return true;
    }
    if path.is_absolute() || path.components().count() > 1 {
        return false;
    }
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path_var) {
        if dir.join(path).is_file() {
            return true;
        }
    }
    false
}

/// Discovers the approved `docker` backend on the host, if present.
#[must_use]
pub fn discover_docker_binary() -> Option<PathBuf> {
    for candidate in APPROVED_DOCKER_CANDIDATE_PATHS {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    which_in_path(Path::new(APPROVED_ISOLATION_BINARY_NAME))
}

/// Resolves the approved `docker` backend binary.
///
/// Only explicit runner configuration or the server-controlled
/// `W014_PARSER_SANDBOX_WRAPPER_BIN` environment selector is consulted; there
/// is no implicit host execution fallback. Stored and environment-provided
/// wrapper *arguments* are never consulted (see `build_docker_run_argv`).
///
/// # Errors
/// Fails closed with:
/// - `ISOLATION_WRAPPER_NOT_FOUND` when the named backend is absent from the host.
/// - `UNAPPROVED_ISOLATION_BACKEND` when an existing host executable other
///   than the approved `docker` backend is named (existence on disk does NOT
///   confer authority).
/// - `MISSING_ISOLATION_WRAPPER` when no backend is configured or discoverable.
///   Direct unsandboxed execution is strictly prohibited.
pub fn resolve_approved_docker_binary(explicit: Option<&PathBuf>) -> Result<PathBuf, SandboxError> {
    if let Some(wrapper) = explicit {
        if !exists_on_host(wrapper) {
            return Err(SandboxError::SandboxViolation {
                violation_type: "ISOLATION_WRAPPER_NOT_FOUND".to_string(),
                detail: format!(
                    "Configured sandbox isolation backend '{wrapper:?}' was not found on host filesystem"
                ),
            });
        }
        if !is_approved_isolation_binary(wrapper) {
            return Err(SandboxError::SandboxViolation {
                violation_type: "UNAPPROVED_ISOLATION_BACKEND".to_string(),
                detail: format!(
                    "Isolation backend '{wrapper:?}' is not the W014-approved OCI backend ('docker'); arbitrary executables are never accepted as sandbox authority merely because the path exists"
                ),
            });
        }
        if wrapper.is_file() {
            return Ok(wrapper.clone());
        }
        if let Some(resolved) = which_in_path(wrapper) {
            return Ok(resolved);
        }
        return Err(SandboxError::SandboxViolation {
            violation_type: "ISOLATION_WRAPPER_NOT_FOUND".to_string(),
            detail: format!(
                "Approved isolation backend '{wrapper:?}' was not found on host filesystem"
            ),
        });
    }

    if let Ok(env_wrapper) = std::env::var(super::process::ENV_PARSER_SANDBOX_WRAPPER_BIN) {
        let trimmed = env_wrapper.trim();
        if trimmed.is_empty() {
            return Err(SandboxError::SandboxViolation {
                violation_type: "MISSING_ISOLATION_WRAPPER".to_string(),
                detail: "Parser sandbox wrapper configuration is empty; unsandboxed direct execution is strictly prohibited".to_string(),
            });
        }
        let wrapper_path = PathBuf::from(trimmed);
        if !exists_on_host(&wrapper_path) {
            return Err(SandboxError::SandboxViolation {
                violation_type: "ISOLATION_WRAPPER_NOT_FOUND".to_string(),
                detail: format!(
                    "Environment isolation backend '{trimmed}' was not found on host filesystem"
                ),
            });
        }
        if !is_approved_isolation_binary(&wrapper_path) {
            return Err(SandboxError::SandboxViolation {
                violation_type: "UNAPPROVED_ISOLATION_BACKEND".to_string(),
                detail: format!(
                    "Environment isolation backend '{trimmed}' is not the W014-approved OCI backend ('docker'); arbitrary executables are never accepted as sandbox authority"
                ),
            });
        }
        if wrapper_path.is_file() {
            return Ok(wrapper_path);
        }
        if let Some(resolved) = which_in_path(&wrapper_path) {
            return Ok(resolved);
        }
        return Err(SandboxError::SandboxViolation {
            violation_type: "ISOLATION_WRAPPER_NOT_FOUND".to_string(),
            detail: format!(
                "Environment isolation backend '{trimmed}' was not found on host filesystem"
            ),
        });
    }

    Err(SandboxError::SandboxViolation {
        violation_type: "MISSING_ISOLATION_WRAPPER".to_string(),
        detail: "Parser sandbox security profile requires the approved OCI isolation backend ('docker') to enforce OS isolation boundaries (read-only root, network isolation, drop capabilities, non-root uid, CPU/memory/PID quotas); unsandboxed direct execution is strictly prohibited".to_string(),
    })
}

/// Builds the authoritative `docker run` argument vector (excluding the
/// `docker` binary itself, starting with `run`).
///
/// A fresh server-generated container identity is minted per call so every
/// invocation carries a deterministic `--name` for actual-container
/// termination. Callers that must know the identity for abort cleanup use
/// [`build_docker_run_argv_with_container_name`] instead.
///
/// The returned policy is fully generated by W014 from the validated frozen
/// profile and the scoped input identity. Stored or environment-provided
/// wrapper arguments are NEVER consulted here, so configuration cannot
/// weaken mandatory isolation.
///
/// # Errors
/// Fails closed with `SandboxViolation` when the profile violates any frozen
/// ceiling or boundary invariant.
#[allow(clippy::too_many_lines)]
pub fn build_docker_run_argv(
    profile: &SandboxSecurityProfile,
    image: &str,
    in_image_binary: &str,
    extra_args: &[String],
    input: &SandboxInput,
) -> Result<Vec<String>, SandboxError> {
    let container_name = generate_container_name();
    build_docker_run_argv_with_container_name(
        profile,
        image,
        in_image_binary,
        extra_args,
        input,
        &container_name,
    )
}

/// Builds the authoritative `docker run` argument vector with an explicit
/// server-generated container identity (excluding the `docker` binary
/// itself, starting with `run`).
///
/// `container_name` MUST be W014-generated (see [`generate_container_name`]);
/// it is validated as Docker-safe and fail-closed, never derived from
/// browser input, job payloads, document bytes, or parser output.
///
/// Mandatory lifecycle flags emitted here:
/// - `--pull=never`: the local authoritative image is the only truth; a
///   missing local image fails closed and registry pulls are impossible.
/// - `--name <container_name>`: deterministic actual-container identity so
///   abort paths terminate the real OCI container, not just the client.
///
/// # Errors
/// Fails closed with `SandboxViolation` when the profile violates any frozen
/// ceiling or boundary invariant, the image/binary reference is invalid, or
/// the container identity is not W014-safe.
#[allow(clippy::too_many_lines)]
pub fn build_docker_run_argv_with_container_name(
    profile: &SandboxSecurityProfile,
    image: &str,
    in_image_binary: &str,
    extra_args: &[String],
    input: &SandboxInput,
    container_name: &str,
) -> Result<Vec<String>, SandboxError> {
    super::process::ProcessSandboxRunner::validate_frozen_boundary_for_oci(profile)?;

    if image.trim().is_empty() {
        return Err(SandboxError::SandboxViolation {
            violation_type: "INVALID_OCI_IMAGE".to_string(),
            detail: "OCI image reference must be non-empty".to_string(),
        });
    }
    if in_image_binary.trim().is_empty() {
        return Err(SandboxError::SandboxViolation {
            violation_type: "INVALID_PARSER_BINARY".to_string(),
            detail: "In-image parser binary path must be non-empty".to_string(),
        });
    }
    if !is_valid_container_name(container_name) {
        return Err(SandboxError::SandboxViolation {
            violation_type: "INVALID_CONTAINER_IDENTITY".to_string(),
            detail: "OCI container identity must be W014-generated ([a-zA-Z0-9][a-zA-Z0-9_.-]+)"
                .to_string(),
        });
    }
    if is_authoritative_image(image) {
        let binary_name = Path::new(in_image_binary.trim())
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if binary_name != EXPECTED_PARSER_BINARY_NAME {
            return Err(SandboxError::SandboxViolation {
                violation_type: "INVALID_PARSER_BINARY_IDENTITY".to_string(),
                detail: format!(
                    "Authoritative image '{AUTHORITATIVE_OCI_IMAGE}' must execute '{EXPECTED_PARSER_BINARY_NAME}', got '{in_image_binary}'"
                ),
            });
        }
    }

    // Clamp to frozen ceilings (profile already validated <= frozen; clamping
    // is defense-in-depth so emitted quotas can never exceed frozen maxima).
    let cpu_cores = profile.ceilings.max_cpu_cores.min(FROZEN_MAX_CPU_CORES);
    if cpu_cores <= 0.0 {
        return Err(SandboxError::SandboxViolation {
            violation_type: "INVALID_CPU_CEILING".to_string(),
            detail: "CPU quota must be positive".to_string(),
        });
    }
    let memory_bytes = profile
        .ceilings
        .max_memory_bytes
        .min(FROZEN_MAX_MEMORY_BYTES);
    let pids_limit = profile.ceilings.max_pids.min(FROZEN_MAX_PIDS);
    let tmpfs_bytes = profile
        .filesystem
        .tmpfs_max_bytes
        .min(FROZEN_MAX_TMPFS_BYTES);

    let mut argv: Vec<String> = vec!["run".to_string(), "--rm".to_string(), "-i".to_string()];

    // Image pull policy: NEVER. The local authoritative image is the only
    // truth; a missing local image fails closed during preflight and no
    // registry pull or network resolution fallback can occur.
    argv.push("--pull=never".to_string());
    // Deterministic actual-container identity (W014-generated): abort paths
    // terminate THIS container via `docker rm -f`, because killing the
    // `docker run` client alone leaves the container alive.
    argv.push("--name".to_string());
    argv.push(container_name.to_string());

    // Network: NONE.
    argv.push("--network=none".to_string());
    // Root filesystem: READ ONLY.
    argv.push("--read-only".to_string());
    // Scratch tmpfs bounded <=1 GiB. No host bind mounts, no secret mounts,
    // no Docker socket mount are ever emitted.
    argv.push("--mount".to_string());
    argv.push(format!(
        "type=tmpfs,destination=/tmp,tmpfs-size={tmpfs_bytes},tmpfs-mode=1777"
    ));
    // User: NON-ROOT.
    argv.push("--user".to_string());
    argv.push(format!("{NON_ROOT_UID}:{NON_ROOT_GID}"));
    // Capabilities: DROP ALL. Never --privileged, never --cap-add.
    argv.push("--cap-drop=ALL".to_string());
    // no-new-privileges: YES.
    argv.push("--security-opt=no-new-privileges:true".to_string());
    // Restrictive syscall filter on Linux production. Other platforms enforce
    // the daemon default restrictive profile; `unconfined` is never emitted.
    #[cfg(target_os = "linux")]
    {
        argv.push("--security-opt=seccomp=default".to_string());
    }
    // CPU capacity <=2 vCPU via CFS quota (actual capacity enforcement, not
    // accumulated-time accounting).
    argv.push(format!("--cpus={cpu_cores:.1}"));
    // Memory <=2 GiB with equal swap cap (no swap escape).
    argv.push(format!("--memory={memory_bytes}"));
    argv.push(format!("--memory-swap={memory_bytes}"));
    // PIDs <=64.
    argv.push(format!("--pids-limit={pids_limit}"));

    // Scoped single-object identity/metadata. ONLY these W014-controlled keys
    // enter the container; host credentials are never injected.
    let scoped_env: Vec<(String, String)> = vec![
        ("W014_PARSER_SANDBOX".to_string(), "1".to_string()),
        (
            "W014_SANDBOX_PROTOCOL".to_string(),
            super::output::SANDBOX_PROTOCOL_VERSION.to_string(),
        ),
        (
            "W014_WORKSPACE_ID".to_string(),
            input.workspace_id.to_string(),
        ),
        (
            "W014_DOCUMENT_VERSION_ID".to_string(),
            input.document_version_id.to_string(),
        ),
        (
            "W014_OBJECT_ARTIFACT_ID".to_string(),
            input.object_artifact_id.to_string(),
        ),
        ("W014_JOB_ID".to_string(), input.job_id.to_string()),
        (
            "W014_MEDIA_TYPE".to_string(),
            input.media_type.as_str().to_string(),
        ),
        (
            "W014_INPUT_SHA256".to_string(),
            input.content_sha256.to_hex(),
        ),
        (
            "W014_BYTE_LENGTH".to_string(),
            input.byte_length.to_string(),
        ),
        (
            "W014_SANDBOX_MAX_CPU_CORES".to_string(),
            profile.ceilings.max_cpu_cores.to_string(),
        ),
        (
            "W014_SANDBOX_MAX_MEMORY_BYTES".to_string(),
            profile.ceilings.max_memory_bytes.to_string(),
        ),
        (
            "W014_SANDBOX_MAX_PIDS".to_string(),
            profile.ceilings.max_pids.to_string(),
        ),
        (
            "W014_SANDBOX_MAX_WALL_CLOCK_SECS".to_string(),
            profile.ceilings.max_wall_clock_seconds.to_string(),
        ),
        (
            "W014_SANDBOX_MAX_OUTPUT_BYTES".to_string(),
            profile.ceilings.max_output_bytes.to_string(),
        ),
    ];
    for (key, value) in scoped_env {
        argv.push("-e".to_string());
        argv.push(format!("{key}={value}"));
    }

    // Image + in-image parser binary + static parser arguments. Parser
    // arguments are consumed by the parser binary inside the container; they
    // cannot alter container isolation flags above.
    argv.push(image.to_string());
    argv.push(in_image_binary.to_string());
    argv.extend(extra_args.iter().cloned());

    Ok(argv)
}

/// Runs a `docker` subcommand with a hard bound, no shell, and no inherited
/// product environment.
///
/// The child is spawned with `kill_on_drop(true)` so a timeout always kills
/// the helper process; stdin is null and only `PATH` is propagated.
async fn run_docker_bounded(
    docker: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let mut cmd = tokio::process::Command::new(docker);
    cmd.args(args);
    cmd.env_clear();
    if let Ok(host_path) = std::env::var("PATH") {
        cmd.env("PATH", host_path);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    let child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn docker helper '{args:?}': {e}"))?;
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(e)) => Err(format!("Docker helper '{args:?}' failed: {e}")),
        Err(_) => Err(format!("Docker helper '{args:?}' exceeded bound")),
    }
}

/// Validates the local authoritative image before parser execution (fail closed).
///
/// Required checks (local-only `docker image inspect`; never a pull):
/// - the image exists locally (absent image or inspect failure fails closed),
/// - for the authoritative image, `org.opencontainers.image.revision` is
///   present and equals the server-controlled expected revision,
/// - for the authoritative image, `w014.parser.binary` is
///   `w014-parser-sandbox` and the PDFium/ooxmlsdk identity labels match the
///   pinned build truth.
///
/// Non-authoritative image references (test doubles) receive an
/// existence-only preflight so tests fail closed on missing images without
/// weakening production authority.
///
/// # Errors
/// Fails closed with `SandboxViolation`:
/// - `MISSING_LOCAL_IMAGE` when the image is absent locally (never pulled),
/// - `IMAGE_INSPECT_FAILED` when local inspection cannot run,
/// - `IMAGE_REVISION_LABEL_MISSING` / `IMAGE_REVISION_MISMATCH` /
///   `INVALID_PARSER_BINARY_IDENTITY` / `IMAGE_IDENTITY_MISMATCH` for
///   authoritative label violations.
pub async fn preflight_local_image(docker: &Path, image: &str) -> Result<(), SandboxError> {
    if image.trim().is_empty() {
        return Err(SandboxError::SandboxViolation {
            violation_type: "INVALID_OCI_IMAGE".to_string(),
            detail: "OCI image reference must be non-empty".to_string(),
        });
    }
    let output = run_docker_bounded(
        docker,
        &[
            "image",
            "inspect",
            "--format={{json .Config.Labels}}",
            image,
        ],
        Duration::from_secs(IMAGE_PREFLIGHT_TIMEOUT_SECS),
    )
    .await
    .map_err(|detail| SandboxError::SandboxViolation {
        violation_type: "IMAGE_INSPECT_FAILED".to_string(),
        detail,
    })?;
    if !output.status.success() {
        return Err(SandboxError::SandboxViolation {
            violation_type: "MISSING_LOCAL_IMAGE".to_string(),
            detail: format!(
                "Local OCI image '{image}' is absent (docker image inspect failed); registry pull is prohibited (--pull=never)"
            ),
        });
    }
    if !is_authoritative_image(image) {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let labels: serde_json::Value =
        serde_json::from_str(stdout.trim()).map_err(|e| SandboxError::SandboxViolation {
            violation_type: "IMAGE_INSPECT_FAILED".to_string(),
            detail: format!("Local image '{image}' labels are not valid JSON: {e}"),
        })?;
    let get_label = |key: &str| {
        labels
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    let Some(revision) = get_label(LABEL_IMAGE_REVISION) else {
        return Err(SandboxError::SandboxViolation {
            violation_type: "IMAGE_REVISION_LABEL_MISSING".to_string(),
            detail: format!(
                "Local image '{image}' is missing required label '{LABEL_IMAGE_REVISION}'"
            ),
        });
    };
    let expected = expected_image_revision();
    if revision != expected {
        return Err(SandboxError::SandboxViolation {
            violation_type: "IMAGE_REVISION_MISMATCH".to_string(),
            detail: format!(
                "Local image '{image}' revision '{revision}' does not match server-controlled expected revision '{expected}'"
            ),
        });
    }
    if get_label(LABEL_PARSER_BINARY).as_deref() != Some(EXPECTED_PARSER_BINARY_NAME) {
        return Err(SandboxError::SandboxViolation {
            violation_type: "INVALID_PARSER_BINARY_IDENTITY".to_string(),
            detail: format!(
                "Local image '{image}' must carry label '{LABEL_PARSER_BINARY}={EXPECTED_PARSER_BINARY_NAME}'"
            ),
        });
    }
    if get_label(LABEL_PDFIUM_VERSION).as_deref() != Some(EXPECTED_PDFIUM_VERSION)
        || get_label(LABEL_PDFIUM_SHA256).as_deref() != Some(EXPECTED_PDFIUM_SHA256)
        || get_label(LABEL_OOXMLSDK_VERSION).as_deref() != Some(EXPECTED_OOXMLSDK_VERSION)
    {
        return Err(SandboxError::SandboxViolation {
            violation_type: "IMAGE_IDENTITY_MISMATCH".to_string(),
            detail: format!(
                "Local image '{image}' PDFium/ooxmlsdk identity labels do not match pinned build truth"
            ),
        });
    }
    Ok(())
}

/// Terminates the ACTUAL OCI parser container by W014-generated name.
///
/// Runs bounded `docker rm -f <name>` (best effort, re-issued while the
/// container is still observed) and then proves absence with bounded
/// `docker inspect <name>`: only a container that is STILL present after a
/// bounded re-verification grace period counts as surviving (a single
/// immediate `inspect` can race daemon-side `--rm` removal of an
/// already-exited container).
///
/// # Errors
/// Fails closed with `SandboxViolation(CONTAINER_TERMINATION_FAILED)` when
/// the container provably survives or when absence cannot be established.
/// Never returns success while a live container may remain.
pub async fn terminate_container_by_name(
    docker: &Path,
    container_name: &str,
) -> Result<(), SandboxError> {
    if !is_valid_container_name(container_name) {
        return Err(SandboxError::SandboxViolation {
            violation_type: "INVALID_CONTAINER_IDENTITY".to_string(),
            detail: "Refusing to terminate an invalid OCI container identity".to_string(),
        });
    }
    let start = std::time::Instant::now();
    let grace = Duration::from_secs(10);
    loop {
        let _ = run_docker_bounded(
            docker,
            &["rm", "-f", container_name],
            Duration::from_secs(CONTAINER_RM_TIMEOUT_SECS),
        )
        .await;
        match run_docker_bounded(
            docker,
            &["inspect", container_name],
            Duration::from_secs(CONTAINER_INSPECT_TIMEOUT_SECS),
        )
        .await
        {
            Ok(output) if !output.status.success() => return Ok(()),
            Ok(_) if start.elapsed() >= grace => {
                return Err(SandboxError::SandboxViolation {
                    violation_type: "CONTAINER_TERMINATION_FAILED".to_string(),
                    detail: format!(
                        "OCI container '{container_name}' survives termination; failing closed instead of reporting an ordinary execution error"
                    ),
                });
            }
            Ok(_) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(detail) => {
                if start.elapsed() >= grace {
                    return Err(SandboxError::SandboxViolation {
                        violation_type: "CONTAINER_TERMINATION_FAILED".to_string(),
                        detail: format!(
                            "OCI container '{container_name}' termination cannot be established ({detail}); failing closed"
                        ),
                    });
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

/// Returns true when a container identity is currently present in the daemon.
///
/// Bounded `docker inspect`; any failure or non-zero exit counts as absent.
/// Test/verification helper only; never used to weaken abort termination.
pub async fn container_present(docker: &Path, container_name: &str) -> bool {
    if !is_valid_container_name(container_name) {
        return false;
    }
    run_docker_bounded(
        docker,
        &["inspect", container_name],
        Duration::from_secs(CONTAINER_INSPECT_TIMEOUT_SECS),
    )
    .await
    .map(|output| output.status.success())
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_only_docker_is_approved_backend() {
        assert!(is_approved_isolation_binary(Path::new(
            "/usr/local/bin/docker"
        )));
        assert!(is_approved_isolation_binary(Path::new("docker")));
        assert!(!is_approved_isolation_binary(Path::new("/bin/sh")));
        assert!(!is_approved_isolation_binary(Path::new("/usr/bin/env")));
        assert!(!is_approved_isolation_binary(Path::new("/usr/bin/bwrap")));
        assert!(!is_approved_isolation_binary(Path::new(
            "/usr/bin/sandbox-exec"
        )));
        assert!(!is_approved_isolation_binary(Path::new(
            "/tmp/custom-harness"
        )));
    }

    #[test]
    fn test_generated_container_identity_is_server_controlled_and_unique() {
        let mut seen = HashSet::new();
        for _ in 0..256 {
            let name = generate_container_name();
            assert!(
                name.starts_with(CONTAINER_NAME_PREFIX),
                "container identity must carry the W014 prefix: {name}"
            );
            assert!(
                is_valid_container_name(&name),
                "generated identity must be Docker-safe: {name}"
            );
            assert!(seen.insert(name), "container identities must be unique");
        }
    }

    #[test]
    fn test_container_identity_rejects_user_controlled_shapes() {
        for hostile in [
            "",
            " ",
            "/bin/sh",
            "a/b",
            "name with spaces",
            "name;rm -rf /",
            "name$(id)",
            "name`id`",
            "name|cat",
            "-leading-dash",
            ".leading-dot",
            "_leading-underscore",
        ] {
            assert!(
                !is_valid_container_name(hostile),
                "hostile identity must be rejected: '{hostile}'"
            );
        }
    }

    #[test]
    fn test_expected_revision_is_server_controlled_default() {
        // Without the server environment selector, compiled build truth applies.
        let _guard = EnvGuard::remove(ENV_EXPECTED_IMAGE_REVISION);
        assert_eq!(expected_image_revision(), DEFAULT_EXPECTED_IMAGE_REVISION);
        assert!(!DEFAULT_EXPECTED_IMAGE_REVISION.trim().is_empty());
    }

    /// Serializes access to process-global environment in unit tests.
    ///
    /// Unit tests in this module run in the same process as each other but in
    /// a different process from integration test binaries, so process-global
    /// env mutation here cannot leak across test targets.
    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn remove(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            unsafe {
                std::env::remove_var(key);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                if let Some(value) = self.previous.take() {
                    std::env::set_var(self.key, value);
                } else {
                    std::env::remove_var(self.key);
                }
            }
        }
    }
}
