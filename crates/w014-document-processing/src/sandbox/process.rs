//! Isolated process sandbox runner (WI-0205).
//!
//! Enforces:
//! - Environment variable scrubbing (no DB, AI, S3, KMS, audit credentials in child process)
//! - Scoped single-object stdin streaming
//! - Strict wall-clock execution timeout (<= 10 minutes)
//! - Output size bounding (<= 10 MiB)
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
use super::profile::{SandboxCredentialsPolicy, SandboxSecurityProfile};
use super::traits::SandboxRunner;

/// Process sandbox runner that launches an external isolated process/harness.
#[derive(Debug, Clone)]
pub struct ProcessSandboxRunner {
    /// Path to the sandbox executable.
    pub binary_path: PathBuf,
    /// Static CLI arguments passed to the executable.
    pub extra_args: Vec<String>,
}

impl ProcessSandboxRunner {
    /// Creates a new `ProcessSandboxRunner` targeting the specified executable path.
    #[must_use]
    pub fn new(binary_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
            extra_args: Vec::new(),
        }
    }

    /// Adds extra static CLI arguments.
    #[must_use]
    pub fn with_args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.extra_args = args.into_iter().map(Into::into).collect();
        self
    }
}

#[async_trait]
impl SandboxRunner for ProcessSandboxRunner {
    async fn run(
        &self,
        profile: &SandboxSecurityProfile,
        input: &SandboxInput,
    ) -> Result<SandboxOutput, SandboxError> {
        // 1. Validate security profile
        profile
            .validate()
            .map_err(|detail| SandboxError::SandboxViolation {
                violation_type: "INVALID_PROFILE".to_string(),
                detail,
            })?;

        // 2. Verify input integrity before launching
        input.verify_integrity().map_err(|detail| {
            SandboxError::OutputValidation(super::output::OutputValidationError::InvalidField {
                field: "input_integrity",
                reason: detail,
            })
        })?;

        // 3. Build command with scrubbed environment
        let mut cmd = Command::new(&self.binary_path);
        cmd.args(&self.extra_args);

        // Clear all inherited environment variables
        cmd.env_clear();

        // Apply scrubbed safe environment
        let scrubbed_env = SandboxCredentialsPolicy::scrub_environment(std::env::vars());
        for (k, v) in scrubbed_env {
            cmd.env(k, v);
        }

        // Set sandbox metadata in child environment
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

        // Write input bytes to child stdin in background
        let input_bytes = input.bytes.clone();
        let writer_task = tokio::spawn(async move {
            let res = child_stdin.write_all(&input_bytes).await;
            let _ = child_stdin.flush().await;
            res
        });

        // 5. Execute with wall-clock timeout
        let wall_clock_limit = Duration::from_secs(profile.ceilings.max_wall_clock_seconds);
        let start_instant = Instant::now();

        let wait_result = tokio::time::timeout(wall_clock_limit, async {
            let mut stdout_buf = Vec::new();
            let mut stderr_buf = Vec::new();

            if let Some(mut stdout) = child.stdout.take() {
                let _ = stdout.read_to_end(&mut stdout_buf).await;
            }
            if let Some(mut stderr) = child.stderr.take() {
                let _ = stderr.read_to_end(&mut stderr_buf).await;
            }

            let status = child.wait().await;
            (status, stdout_buf, stderr_buf)
        })
        .await;

        let _ = writer_task.await;

        let (status_res, stdout_bytes, stderr_bytes) = match wait_result {
            Ok(tuple) => tuple,
            Err(_) => {
                // Kill timed out child process
                let _ = child.kill().await;
                return Err(SandboxError::Timeout {
                    elapsed_secs: start_instant.elapsed().as_secs(),
                    limit_secs: profile.ceilings.max_wall_clock_seconds,
                });
            }
        };

        let status = status_res.map_err(|e| SandboxError::IO {
            detail: format!("Failed waiting for sandbox exit status: {e}"),
        })?;

        let stderr_str = String::from_utf8_lossy(&stderr_bytes).to_string();

        // 6. Check exit code
        if !status.success() {
            let code = status.code();
            // Check for common OOM exit codes (e.g. 137 = SIGKILL / 9)
            if code == Some(137) || stderr_str.to_lowercase().contains("out of memory") {
                return Err(SandboxError::OutOfMemory { detail: stderr_str });
            }

            return Err(SandboxError::ProcessCrash {
                exit_code: code,
                signal: None,
                stderr: stderr_str,
            });
        }

        // 7. Enforce output bounds
        if stdout_bytes.len() > profile.ceilings.max_output_bytes {
            return Err(SandboxError::MalformedOutput {
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

        // 9. Validate output against input
        output
            .validate_against_input(input)
            .map_err(SandboxError::OutputValidation)?;

        Ok(output)
    }
}
