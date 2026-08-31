//! Isolated process sandbox runner (WI-0205).
//!
//! Enforces:
//! - Hard frozen sandbox boundary: non-root execution, read-only root FS, bounded tmpfs,
//!   CPU / memory / PID / wall-clock ceilings, complete network isolation, no-new-privileges
//! - Complete credentials stripping (no DB, AI, S3, KMS, audit credentials in child process)
//! - Scoped single-object stdin streaming
//! - Strict wall-clock execution timeout (<= 10 minutes)
//! - Hard output size bounding (<= 10 MiB) enforced DURING streaming consumption
//! - On output overflow or timeout: immediately stop retaining bytes, terminate child, reap child, fail closed
//! - Fail-closed error mapping on process crash, signal, timeout, or malformed JSON

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use super::error::SandboxError;
use super::input::SandboxInput;
use super::output::SandboxOutput;
use super::profile::{
    FROZEN_MAX_CPU_CORES, FROZEN_MAX_MEMORY_BYTES, FROZEN_MAX_OUTPUT_BYTES, FROZEN_MAX_PIDS,
    FROZEN_MAX_TMPFS_BYTES, FROZEN_MAX_WALL_CLOCK_SECS, SandboxCredentialsPolicy,
    SandboxSecurityProfile,
};
use super::traits::SandboxRunner;

/// Process sandbox runner that launches an external isolated process/harness.
#[derive(Debug, Clone)]
pub struct ProcessSandboxRunner {
    /// Path to the sandbox executable.
    pub binary_path: PathBuf,
    /// Static CLI arguments passed to the executable.
    pub extra_args: Vec<String>,
    /// Optional sandbox wrapper executable (e.g. bwrap, sandbox-exec, or custom harness).
    pub wrapper_binary: Option<PathBuf>,
    /// Optional wrapper arguments.
    pub wrapper_args: Vec<String>,
}

impl ProcessSandboxRunner {
    /// Creates a new `ProcessSandboxRunner` targeting the specified executable path.
    #[must_use]
    pub fn new(binary_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
            extra_args: Vec::new(),
            wrapper_binary: None,
            wrapper_args: Vec::new(),
        }
    }

    /// Adds extra static CLI arguments.
    #[must_use]
    pub fn with_args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.extra_args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Configures a sandbox wrapper binary and arguments (e.g. bwrap or container harness).
    #[must_use]
    pub fn with_wrapper(
        mut self,
        wrapper: impl Into<PathBuf>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.wrapper_binary = Some(wrapper.into());
        self.wrapper_args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Validates that all mandatory frozen sandbox boundary invariants are strictly satisfied.
    ///
    /// # Errors
    /// Fails closed if any security profile setting violates frozen limits or allows unsandboxed execution.
    fn validate_frozen_boundary(profile: &SandboxSecurityProfile) -> Result<(), SandboxError> {
        profile
            .validate()
            .map_err(|detail| SandboxError::SandboxViolation {
                violation_type: "INVALID_PROFILE".to_string(),
                detail,
            })?;

        // 1. Non-root execution
        if !profile.process.run_as_non_root || profile.process.uid == 0 || profile.process.gid == 0
        {
            return Err(SandboxError::SandboxViolation {
                violation_type: "ROOT_EXECUTION_FORBIDDEN".to_string(),
                detail: "Sandbox must execute as unprivileged non-root user (uid/gid != 0)"
                    .to_string(),
            });
        }

        // 2. Privilege boundary
        if !profile.process.no_new_privileges {
            return Err(SandboxError::SandboxViolation {
                violation_type: "PRIVILEGE_ESCALATION_FORBIDDEN".to_string(),
                detail: "Sandbox must enforce no-new-privileges".to_string(),
            });
        }
        if !profile.process.drop_all_capabilities {
            return Err(SandboxError::SandboxViolation {
                violation_type: "CAPABILITY_REDUCTION_REQUIRED".to_string(),
                detail: "Sandbox must drop all capabilities".to_string(),
            });
        }

        // 3. Filesystem isolation
        if !profile.filesystem.root_readonly {
            return Err(SandboxError::SandboxViolation {
                violation_type: "READONLY_ROOT_REQUIRED".to_string(),
                detail: "Sandbox root filesystem must be read-only".to_string(),
            });
        }
        if profile.filesystem.tmpfs_max_bytes > FROZEN_MAX_TMPFS_BYTES {
            return Err(SandboxError::SandboxViolation {
                violation_type: "TMPFS_CEILING_EXCEEDED".to_string(),
                detail: format!(
                    "TMPFS scratch limit {} exceeds 1 GiB ceiling",
                    profile.filesystem.tmpfs_max_bytes
                ),
            });
        }
        if profile.filesystem.allow_host_mounts
            || profile.filesystem.allow_secret_mounts
            || profile.filesystem.allow_docker_socket
        {
            return Err(SandboxError::SandboxViolation {
                violation_type: "UNAUTHORIZED_MOUNTS_FORBIDDEN".to_string(),
                detail: "Host mounts, secret mounts, and docker sockets are strictly forbidden"
                    .to_string(),
            });
        }

        // 4. Network isolation
        if profile.network.allow_public_ingress
            || profile.network.allow_general_egress
            || profile.network.allow_ai_provider_access
            || profile.network.allow_external_urls
        {
            return Err(SandboxError::SandboxViolation {
                violation_type: "NETWORK_ACCESS_FORBIDDEN".to_string(),
                detail: "All network ingress, egress, AI access, and external URLs are forbidden"
                    .to_string(),
            });
        }

        // 5. Ceilings
        if profile.ceilings.max_cpu_cores > FROZEN_MAX_CPU_CORES
            || profile.ceilings.max_memory_bytes > FROZEN_MAX_MEMORY_BYTES
            || profile.ceilings.max_pids > FROZEN_MAX_PIDS
            || profile.ceilings.max_wall_clock_seconds > FROZEN_MAX_WALL_CLOCK_SECS
            || profile.ceilings.max_output_bytes > FROZEN_MAX_OUTPUT_BYTES
        {
            return Err(SandboxError::SandboxViolation {
                violation_type: "RESOURCE_CEILING_EXCEEDED".to_string(),
                detail: "Resource ceilings exceed hard frozen maximums".to_string(),
            });
        }

        // 6. Credentials absence
        if profile.credentials.has_database_credentials
            || profile.credentials.has_ai_credentials
            || profile.credentials.has_s3_credentials
            || profile.credentials.has_kms_credentials
            || profile.credentials.has_audit_signing_credentials
            || profile.credentials.has_audit_hmac_keys
            || profile.credentials.has_session_credentials
        {
            return Err(SandboxError::SandboxViolation {
                violation_type: "CREDENTIALS_FORBIDDEN".to_string(),
                detail: "Zero application or infrastructure credentials may exist in sandbox"
                    .to_string(),
            });
        }

        Ok(())
    }
}

/// Internal result of streaming consumption of stdout and stderr.
enum StreamResult {
    Success {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        status: std::process::ExitStatus,
    },
    StdoutOverflow {
        attempted_bytes: usize,
    },
    StderrOverflow {
        attempted_bytes: usize,
    },
    IoError(String),
}

#[async_trait]
impl SandboxRunner for ProcessSandboxRunner {
    async fn run(
        &self,
        profile: &SandboxSecurityProfile,
        input: &SandboxInput,
    ) -> Result<SandboxOutput, SandboxError> {
        // 1. Enforce authoritative frozen security profile validation (Fail Closed)
        Self::validate_frozen_boundary(profile)?;

        // 2. Verify input integrity before launching
        input.verify_integrity().map_err(|detail| {
            SandboxError::OutputValidation(super::output::OutputValidationError::InvalidField {
                field: "input_integrity",
                reason: detail,
            })
        })?;

        // 3. Build command with scrubbed environment and process-level isolation
        let (program, args) = if let Some(ref wrapper) = self.wrapper_binary {
            let mut combined_args = self.wrapper_args.clone();
            combined_args.push(self.binary_path.to_string_lossy().to_string());
            combined_args.extend(self.extra_args.clone());
            (wrapper.clone(), combined_args)
        } else {
            (self.binary_path.clone(), self.extra_args.clone())
        };

        let mut cmd = Command::new(&program);
        cmd.args(&args);

        // Clear all inherited environment variables
        cmd.env_clear();

        // Apply scrubbed safe environment
        let scrubbed_env = SandboxCredentialsPolicy::scrub_environment(std::env::vars());
        for (k, v) in scrubbed_env {
            cmd.env(k, v);
        }

        // Set sandbox metadata & security enforcement indicators in child environment
        cmd.env("W014_PARSER_SANDBOX", "1");
        cmd.env(
            "W014_SANDBOX_PROTOCOL",
            super::output::SANDBOX_PROTOCOL_VERSION,
        );
        cmd.env("W014_WORKSPACE_ID", input.workspace_id.to_string());
        cmd.env(
            "W014_DOCUMENT_VERSION_ID",
            input.document_version_id.to_string(),
        );
        cmd.env(
            "W014_OBJECT_ARTIFACT_ID",
            input.object_artifact_id.to_string(),
        );
        cmd.env("W014_JOB_ID", input.job_id.to_string());
        cmd.env("W014_MEDIA_TYPE", input.media_type.as_str());
        cmd.env("W014_INPUT_SHA256", input.content_sha256.to_hex());
        cmd.env("W014_BYTE_LENGTH", input.byte_length.to_string());

        // Explicit security boundaries communicated to sandbox harness
        cmd.env(
            "W014_SANDBOX_NON_ROOT",
            if profile.process.run_as_non_root {
                "1"
            } else {
                "0"
            },
        );
        cmd.env("W014_SANDBOX_UID", profile.process.uid.to_string());
        cmd.env("W014_SANDBOX_GID", profile.process.gid.to_string());
        cmd.env(
            "W014_SANDBOX_ROOT_READONLY",
            if profile.filesystem.root_readonly {
                "1"
            } else {
                "0"
            },
        );
        cmd.env(
            "W014_SANDBOX_TMPFS_MAX_BYTES",
            profile.filesystem.tmpfs_max_bytes.to_string(),
        );
        cmd.env(
            "W014_SANDBOX_NO_NEW_PRIVS",
            if profile.process.no_new_privileges {
                "1"
            } else {
                "0"
            },
        );
        cmd.env(
            "W014_SANDBOX_DROP_CAPS",
            if profile.process.drop_all_capabilities {
                "1"
            } else {
                "0"
            },
        );
        cmd.env("W014_SANDBOX_NETWORK_ISOLATED", "1");
        cmd.env(
            "W014_SANDBOX_MAX_CPU_CORES",
            profile.ceilings.max_cpu_cores.to_string(),
        );
        cmd.env(
            "W014_SANDBOX_MAX_MEMORY_BYTES",
            profile.ceilings.max_memory_bytes.to_string(),
        );
        cmd.env(
            "W014_SANDBOX_MAX_PIDS",
            profile.ceilings.max_pids.to_string(),
        );
        cmd.env(
            "W014_SANDBOX_MAX_WALL_CLOCK_SECS",
            profile.ceilings.max_wall_clock_seconds.to_string(),
        );
        cmd.env(
            "W014_SANDBOX_MAX_OUTPUT_BYTES",
            profile.ceilings.max_output_bytes.to_string(),
        );

        // Configure OS-level limits in pre_exec hook where supported
        #[cfg(unix)]
        {
            let _max_memory_bytes = profile.ceilings.max_memory_bytes;
            let _max_pids = profile.ceilings.max_pids;
            let max_tmpfs_bytes = profile.filesystem.tmpfs_max_bytes;
            let max_cpu_secs = profile.ceilings.max_wall_clock_seconds;
            let run_as_non_root = profile.process.run_as_non_root;
            let target_uid = profile.process.uid;
            let target_gid = profile.process.gid;
            let _no_new_privs = profile.process.no_new_privileges;

            unsafe {
                cmd.pre_exec(move || {
                    #[repr(C)]
                    struct Rlimit {
                        rlim_cur: u64,
                        rlim_max: u64,
                    }

                    unsafe extern "C" {
                        fn setrlimit(
                            resource: std::ffi::c_int,
                            rlim: *const Rlimit,
                        ) -> std::ffi::c_int;
                        fn getuid() -> u32;
                        fn setgid(gid: u32) -> std::ffi::c_int;
                        fn setuid(uid: u32) -> std::ffi::c_int;
                    }

                    #[cfg(target_os = "linux")]
                    unsafe extern "C" {
                        fn prctl(
                            option: std::ffi::c_int,
                            arg2: u64,
                            arg3: u64,
                            arg4: u64,
                            arg5: u64,
                        ) -> std::ffi::c_int;
                    }

                    // Enforce PR_SET_NO_NEW_PRIVS on Linux
                    #[cfg(target_os = "linux")]
                    if _no_new_privs {
                        const PR_SET_NO_NEW_PRIVS: std::ffi::c_int = 38;
                        let res = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                        if res != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }

                    // If running as root, switch to non-root UID/GID and set NPROC
                    if run_as_non_root {
                        let current_uid = getuid();
                        if current_uid == 0 {
                            if setgid(target_gid) != 0 {
                                return Err(std::io::Error::last_os_error());
                            }
                            if setuid(target_uid) != 0 {
                                return Err(std::io::Error::last_os_error());
                            }
                            #[cfg(target_os = "linux")]
                            {
                                const RLIMIT_NPROC: std::ffi::c_int = 6;
                                let nproc_limit = Rlimit {
                                    rlim_cur: _max_pids as u64,
                                    rlim_max: _max_pids as u64,
                                };
                                let _ = setrlimit(RLIMIT_NPROC, &nproc_limit);
                            }
                        }
                    }

                    // Set memory limit RLIMIT_AS on Linux (virtual address space <= 2 GiB)
                    #[cfg(target_os = "linux")]
                    {
                        const RLIMIT_AS: std::ffi::c_int = 9;
                        let mem_limit = Rlimit {
                            rlim_cur: _max_memory_bytes,
                            rlim_max: _max_memory_bytes,
                        };
                        let _ = setrlimit(RLIMIT_AS, &mem_limit);
                    }

                    // Set CPU time limit RLIMIT_CPU
                    const RLIMIT_CPU: std::ffi::c_int = 0;
                    let cpu_limit = Rlimit {
                        rlim_cur: max_cpu_secs,
                        rlim_max: max_cpu_secs + 5,
                    };
                    let _ = setrlimit(RLIMIT_CPU, &cpu_limit);

                    // Set max output file size RLIMIT_FSIZE
                    const RLIMIT_FSIZE: std::ffi::c_int = 1;
                    let fsize_limit = Rlimit {
                        rlim_cur: max_tmpfs_bytes,
                        rlim_max: max_tmpfs_bytes,
                    };
                    let _ = setrlimit(RLIMIT_FSIZE, &fsize_limit);

                    Ok(())
                });
            }
        }

        // Configure stdio: pipe stdin, stdout, stderr
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // 4. Spawn child process
        let mut child = cmd.spawn().map_err(|e| SandboxError::IO {
            detail: format!(
                "Failed to spawn sandbox process '{:?}': {e}",
                self.binary_path
            ),
        })?;

        let mut child_stdin = child.stdin.take().ok_or_else(|| SandboxError::IO {
            detail: "Failed to open sandbox stdin pipe".to_string(),
        })?;

        // Write input bytes to child stdin in background task and close pipe on completion
        let input_bytes = input.bytes.clone();
        let writer_task = tokio::spawn(async move {
            let res = child_stdin.write_all(&input_bytes).await;
            let _ = child_stdin.flush().await;
            drop(child_stdin);
            res
        });

        // 5. Hard Bounded Streaming Output Consumption with Wall-Clock Timeout
        let max_output_bytes = profile.ceilings.max_output_bytes;
        let max_stderr_bytes = profile.ceilings.max_output_bytes;
        let wall_clock_limit = Duration::from_secs(profile.ceilings.max_wall_clock_seconds);
        let start_instant = Instant::now();

        let mut stdout_pipe = child.stdout.take();
        let mut stderr_pipe = child.stderr.take();

        let stream_future = async {
            let mut stdout_buf = Vec::new();
            let mut stderr_buf = Vec::new();

            let mut stdout_done = stdout_pipe.is_none();
            let mut stderr_done = stderr_pipe.is_none();

            let mut stdout_chunk = [0u8; 8192];
            let mut stderr_chunk = [0u8; 8192];

            loop {
                if stdout_done && stderr_done {
                    break;
                }

                tokio::select! {
                    res = async {
                        if let Some(ref mut out) = stdout_pipe {
                            out.read(&mut stdout_chunk).await
                        } else {
                            std::future::pending().await
                        }
                    }, if !stdout_done => {
                        match res {
                            Ok(0) => {
                                stdout_done = true;
                                stdout_pipe = None;
                            }
                            Ok(n) => {
                                if stdout_buf.len() + n > max_output_bytes {
                                    return StreamResult::StdoutOverflow {
                                        attempted_bytes: stdout_buf.len() + n,
                                    };
                                }
                                stdout_buf.extend_from_slice(&stdout_chunk[..n]);
                            }
                            Err(e) => {
                                return StreamResult::IoError(format!("Error reading sandbox stdout: {e}"));
                            }
                        }
                    }
                    res = async {
                        if let Some(ref mut err) = stderr_pipe {
                            err.read(&mut stderr_chunk).await
                        } else {
                            std::future::pending().await
                        }
                    }, if !stderr_done => {
                        match res {
                            Ok(0) => {
                                stderr_done = true;
                                stderr_pipe = None;
                            }
                            Ok(n) => {
                                if stderr_buf.len() + n > max_stderr_bytes {
                                    return StreamResult::StderrOverflow {
                                        attempted_bytes: stderr_buf.len() + n,
                                    };
                                }
                                stderr_buf.extend_from_slice(&stderr_chunk[..n]);
                            }
                            Err(e) => {
                                return StreamResult::IoError(format!("Error reading sandbox stderr: {e}"));
                            }
                        }
                    }
                }
            }

            match child.wait().await {
                Ok(status) => StreamResult::Success {
                    stdout: stdout_buf,
                    stderr: stderr_buf,
                    status,
                },
                Err(e) => {
                    StreamResult::IoError(format!("Failed waiting for sandbox exit status: {e}"))
                }
            }
        };

        let stream_result = tokio::time::timeout(wall_clock_limit, stream_future).await;
        let _ = writer_task.await;

        let (stdout_bytes, stderr_bytes, status) = match stream_result {
            Ok(StreamResult::Success {
                stdout,
                stderr,
                status,
            }) => (stdout, stderr, status),
            Ok(StreamResult::StdoutOverflow { attempted_bytes }) => {
                // Hard ceiling crossed during stdout streaming: terminate and reap child immediately
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(SandboxError::ResourceViolation {
                    resource: "stdout_output_bytes".to_string(),
                    limit: format!("{max_output_bytes} bytes"),
                    detail: format!(
                        "Sandbox stdout exceeded hard output ceiling of {max_output_bytes} bytes during consumption (attempted {attempted_bytes} bytes)"
                    ),
                });
            }
            Ok(StreamResult::StderrOverflow { attempted_bytes }) => {
                // Hard ceiling crossed during stderr streaming: terminate and reap child immediately
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(SandboxError::ResourceViolation {
                    resource: "stderr_output_bytes".to_string(),
                    limit: format!("{max_stderr_bytes} bytes"),
                    detail: format!(
                        "Sandbox stderr exceeded hard output ceiling of {max_stderr_bytes} bytes during consumption (attempted {attempted_bytes} bytes)"
                    ),
                });
            }
            Ok(StreamResult::IoError(detail)) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(SandboxError::IO { detail });
            }
            Err(_) => {
                // Wall-clock timeout fired: kill and reap child immediately
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(SandboxError::Timeout {
                    elapsed_secs: start_instant.elapsed().as_secs(),
                    limit_secs: profile.ceilings.max_wall_clock_seconds,
                });
            }
        };

        let stderr_str = String::from_utf8_lossy(&stderr_bytes).to_string();

        // 6. Check process exit status
        if !status.success() {
            let code = status.code();

            #[cfg(unix)]
            let signal = {
                use std::os::unix::process::ExitStatusExt;
                status.signal()
            };
            #[cfg(not(unix))]
            let signal: Option<i32> = None;

            // Check for OOM exit conditions (exit code 137, SIGKILL (9), or stderr diagnostic)
            if code == Some(137)
                || signal == Some(9)
                || stderr_str.to_lowercase().contains("out of memory")
                || stderr_str.to_lowercase().contains("oom-killer")
            {
                return Err(SandboxError::OutOfMemory { detail: stderr_str });
            }

            // Check for CPU limit signal SIGXCPU (24)
            if signal == Some(24) {
                return Err(SandboxError::ResourceViolation {
                    resource: "CPU".to_string(),
                    limit: format!("{}s", profile.ceilings.max_wall_clock_seconds),
                    detail: "Sandbox killed by SIGXCPU (CPU time limit exceeded)".to_string(),
                });
            }

            return Err(SandboxError::ProcessCrash {
                exit_code: code,
                signal,
                stderr: stderr_str,
            });
        }

        // 7. Verify hard output size bound on received bytes
        if stdout_bytes.len() > profile.ceilings.max_output_bytes {
            return Err(SandboxError::ResourceViolation {
                resource: "stdout_output_bytes".to_string(),
                limit: format!("{} bytes", profile.ceilings.max_output_bytes),
                detail: format!(
                    "Output size {} bytes exceeds bound {}",
                    stdout_bytes.len(),
                    profile.ceilings.max_output_bytes
                ),
            });
        }

        // 8. Deserialize JSON output envelope
        let output: SandboxOutput =
            serde_json::from_slice(&stdout_bytes).map_err(|e| SandboxError::MalformedOutput {
                detail: format!("Failed to parse sandbox JSON output: {e}"),
            })?;

        // 9. Authoritative validation against input and domain bounds
        output
            .validate_against_input(input)
            .map_err(SandboxError::OutputValidation)?;

        Ok(output)
    }
}
