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

use std::path::{Path, PathBuf};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
