//! Parser sandbox security profile and resource ceilings (WI-0205).
//!
//! Enforces:
//! - Hard frozen resource ceilings: <= 2 vCPU, <= 2 GiB RAM, <= 1 GiB tmpfs, <= 64 PIDs, <= 10 min wall clock
//! - Dedicated unprivileged non-root identity (uid: 65534, gid: 65534)
//! - Complete credentials stripping (no DB, AI, S3, KMS, audit signing, or session secrets)
//! - Strict network isolation (no ingress, no egress, no external URLs)
//! - Read-only root filesystem with bounded tmpfs scratch only
//! - Capability dropping, no-new-privileges, seccomp/apparmor isolation

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Maximum CPU cores allocated to the sandbox (<= 2 vCPU).
pub const FROZEN_MAX_CPU_CORES: f64 = 2.0;

/// Maximum RAM in bytes allocated to the sandbox (<= 2 GiB).
pub const FROZEN_MAX_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Maximum TMPFS scratch space in bytes (<= 1 GiB).
pub const FROZEN_MAX_TMPFS_BYTES: u64 = 1024 * 1024 * 1024;

/// Maximum process/thread IDs allowed in the sandbox (<= 64).
pub const FROZEN_MAX_PIDS: u32 = 64;

/// Maximum wall-clock execution time in seconds (<= 10 minutes).
pub const FROZEN_MAX_WALL_CLOCK_SECS: u64 = 600;

/// Maximum output size in bytes permitted from the sandbox (10 MiB).
pub const FROZEN_MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;

/// Default non-root user ID for untrusted execution.
pub const NON_ROOT_UID: u32 = 65534;

/// Default non-root group ID for untrusted execution.
pub const NON_ROOT_GID: u32 = 65534;

/// Hard frozen resource ceilings for parser sandbox execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxResourceCeilings {
    /// CPU cores ceiling (<= 2.0).
    pub max_cpu_cores: f64,
    /// Memory ceiling in bytes (<= 2 GiB).
    pub max_memory_bytes: u64,
    /// TMPFS scratch space ceiling in bytes (<= 1 GiB).
    pub max_tmpfs_bytes: u64,
    /// Maximum PID/threads limit (<= 64).
    pub max_pids: u32,
    /// Wall clock timeout in seconds (<= 600s).
    pub max_wall_clock_seconds: u64,
    /// Maximum output payload size in bytes (<= 10 MiB).
    pub max_output_bytes: usize,
}

impl Default for SandboxResourceCeilings {
    fn default() -> Self {
        Self {
            max_cpu_cores: FROZEN_MAX_CPU_CORES,
            max_memory_bytes: FROZEN_MAX_MEMORY_BYTES,
            max_tmpfs_bytes: FROZEN_MAX_TMPFS_BYTES,
            max_pids: FROZEN_MAX_PIDS,
            max_wall_clock_seconds: FROZEN_MAX_WALL_CLOCK_SECS,
            max_output_bytes: FROZEN_MAX_OUTPUT_BYTES,
        }
    }
}

impl SandboxResourceCeilings {
    /// Validates that all resource ceilings are within the frozen security limits.
    ///
    /// # Errors
    /// Fails closed if any limit exceeds the frozen maximum.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_cpu_cores <= 0.0 || self.max_cpu_cores > FROZEN_MAX_CPU_CORES {
            return Err(format!(
                "CPU limit {:.1} exceeds frozen ceiling {:.1} vCPU",
                self.max_cpu_cores, FROZEN_MAX_CPU_CORES
            ));
        }
        if self.max_memory_bytes == 0 || self.max_memory_bytes > FROZEN_MAX_MEMORY_BYTES {
            return Err(format!(
                "Memory limit {} bytes exceeds frozen ceiling {} bytes (2 GiB)",
                self.max_memory_bytes, FROZEN_MAX_MEMORY_BYTES
            ));
        }
        if self.max_tmpfs_bytes > FROZEN_MAX_TMPFS_BYTES {
            return Err(format!(
                "TMPFS limit {} bytes exceeds frozen ceiling {} bytes (1 GiB)",
                self.max_tmpfs_bytes, FROZEN_MAX_TMPFS_BYTES
            ));
        }
        if self.max_pids == 0 || self.max_pids > FROZEN_MAX_PIDS {
            return Err(format!(
                "PID limit {} exceeds frozen ceiling {}",
                self.max_pids, FROZEN_MAX_PIDS
            ));
        }
        if self.max_wall_clock_seconds == 0
            || self.max_wall_clock_seconds > FROZEN_MAX_WALL_CLOCK_SECS
        {
            return Err(format!(
                "Wall clock limit {}s exceeds frozen ceiling {}s (10 min)",
                self.max_wall_clock_seconds, FROZEN_MAX_WALL_CLOCK_SECS
            ));
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > FROZEN_MAX_OUTPUT_BYTES {
            return Err(format!(
                "Output size limit {} bytes exceeds frozen ceiling {} bytes (10 MiB)",
                self.max_output_bytes, FROZEN_MAX_OUTPUT_BYTES
            ));
        }
        Ok(())
    }
}

/// Network boundary policy for the parser sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxNetworkPolicy {
    /// Ingress network traffic is strictly forbidden.
    pub allow_public_ingress: bool,
    /// Egress network traffic is strictly forbidden.
    pub allow_general_egress: bool,
    /// AI provider endpoint access is strictly forbidden.
    pub allow_ai_provider_access: bool,
    /// URL fetching from document text is strictly forbidden.
    pub allow_external_urls: bool,
}

impl SandboxNetworkPolicy {
    /// Validates that network policy strictly isolates the sandbox.
    pub fn validate(&self) -> Result<(), String> {
        if self.allow_public_ingress {
            return Err("Public ingress is strictly forbidden in parser sandbox".to_string());
        }
        if self.allow_general_egress {
            return Err("General egress is strictly forbidden in parser sandbox".to_string());
        }
        if self.allow_ai_provider_access {
            return Err("AI provider access is strictly forbidden in parser sandbox".to_string());
        }
        if self.allow_external_urls {
            return Err(
                "External URL fetching is strictly forbidden in parser sandbox".to_string(),
            );
        }
        Ok(())
    }
}

/// Filesystem boundary policy for the parser sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxFilesystemPolicy {
    /// Root filesystem must be mounted read-only.
    pub root_readonly: bool,
    /// Scratch filesystem is tmpfs only with bounded size.
    pub tmpfs_max_bytes: u64,
    /// Generic host mounts are forbidden.
    pub allow_host_mounts: bool,
    /// Secret mounts are forbidden.
    pub allow_secret_mounts: bool,
    /// Docker socket mounting is strictly forbidden.
    pub allow_docker_socket: bool,
}

impl Default for SandboxFilesystemPolicy {
    fn default() -> Self {
        Self {
            root_readonly: true,
            tmpfs_max_bytes: FROZEN_MAX_TMPFS_BYTES,
            allow_host_mounts: false,
            allow_secret_mounts: false,
            allow_docker_socket: false,
        }
    }
}

impl SandboxFilesystemPolicy {
    /// Validates that filesystem policy strictly isolates the sandbox.
    pub fn validate(&self) -> Result<(), String> {
        if !self.root_readonly {
            return Err("Root filesystem must be read-only in parser sandbox".to_string());
        }
        if self.tmpfs_max_bytes > FROZEN_MAX_TMPFS_BYTES {
            return Err(format!(
                "TMPFS scratch limit {} exceeds 1 GiB bound",
                self.tmpfs_max_bytes
            ));
        }
        if self.allow_host_mounts {
            return Err("Host mounts are forbidden in parser sandbox".to_string());
        }
        if self.allow_secret_mounts {
            return Err("Secret mounts are forbidden in parser sandbox".to_string());
        }
        if self.allow_docker_socket {
            return Err("Docker socket access is strictly forbidden in parser sandbox".to_string());
        }
        Ok(())
    }
}

/// Process and privilege boundary policy for the parser sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProcessPolicy {
    /// Must execute as non-root user.
    pub run_as_non_root: bool,
    /// Unprivileged UID.
    pub uid: u32,
    /// Unprivileged GID.
    pub gid: u32,
    /// All Linux/container capabilities must be dropped.
    pub drop_all_capabilities: bool,
    /// PR_SET_NO_NEW_PRIVS / no-new-privileges flag.
    pub no_new_privileges: bool,
    /// Seccomp profile identifier.
    pub seccomp_profile: String,
}

impl Default for SandboxProcessPolicy {
    fn default() -> Self {
        Self {
            run_as_non_root: true,
            uid: NON_ROOT_UID,
            gid: NON_ROOT_GID,
            drop_all_capabilities: true,
            no_new_privileges: true,
            seccomp_profile: "restricted-default-deny".to_string(),
        }
    }
}

impl SandboxProcessPolicy {
    /// Validates that process policy strictly adheres to unprivileged execution.
    pub fn validate(&self) -> Result<(), String> {
        if !self.run_as_non_root {
            return Err("Parser sandbox must run as non-root".to_string());
        }
        if self.uid == 0 || self.gid == 0 {
            return Err("Root UID/GID (0) is strictly forbidden in parser sandbox".to_string());
        }
        if !self.drop_all_capabilities {
            return Err("Parser sandbox must drop all capabilities".to_string());
        }
        if !self.no_new_privileges {
            return Err("Parser sandbox must enforce no-new-privileges".to_string());
        }
        Ok(())
    }
}

/// Credentials absence policy: guarantees zero sensitive authority inside sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxCredentialsPolicy {
    pub has_database_credentials: bool,
    pub has_ai_credentials: bool,
    pub has_s3_credentials: bool,
    pub has_kms_credentials: bool,
    pub has_audit_signing_credentials: bool,
    pub has_audit_hmac_keys: bool,
    pub has_session_credentials: bool,
}

impl SandboxCredentialsPolicy {
    /// Validates that zero application credentials are present in sandbox policy.
    pub fn validate(&self) -> Result<(), String> {
        if self.has_database_credentials {
            return Err("Database credentials must not exist in parser sandbox".to_string());
        }
        if self.has_ai_credentials {
            return Err("AI provider credentials must not exist in parser sandbox".to_string());
        }
        if self.has_s3_credentials {
            return Err(
                "Generic S3/object-store credentials must not exist in parser sandbox".to_string(),
            );
        }
        if self.has_kms_credentials {
            return Err("KMS credentials must not exist in parser sandbox".to_string());
        }
        if self.has_audit_signing_credentials {
            return Err("Audit signing credentials must not exist in parser sandbox".to_string());
        }
        if self.has_audit_hmac_keys {
            return Err("Audit HMAC keys must not exist in parser sandbox".to_string());
        }
        if self.has_session_credentials {
            return Err("Session credentials must not exist in parser sandbox".to_string());
        }
        Ok(())
    }

    /// Scrubs an environment map, removing ANY sensitive credentials or tokens.
    #[must_use]
    pub fn scrub_environment(
        input_env: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
    ) -> HashMap<String, String> {
        let prohibited_fragments = [
            "database",
            "postgres",
            "sqlx",
            "db_url",
            "db_pass",
            "aws_",
            "s3_",
            "minio",
            "azure_",
            "gcp_",
            "openai",
            "anthropic",
            "gemini",
            "bedrock",
            "cohere",
            "api_key",
            "apikey",
            "secret",
            "password",
            "passwd",
            "token",
            "session",
            "auth",
            "jwt",
            "bearer",
            "kms",
            "hmac",
            "signing_key",
            "private_key",
            "certificate",
            "cookie",
            "credential",
            "storage",
            "bucket",
            "access_key",
            "secret_key",
            "mistral",
            "ollama",
        ];

        let allowed_exact_keys: HashSet<&str> = [
            "PATH",
            "LANG",
            "LC_ALL",
            "TZ",
            "TMPDIR",
            "TEMP",
            "TMP",
            "W014_PARSER_SANDBOX",
            "W014_SANDBOX_PROTOCOL",
        ]
        .into_iter()
        .collect();

        let mut scrubbed = HashMap::new();
        for (k, v) in input_env {
            let key = k.as_ref();
            let val = v.as_ref();
            let lower_key = key.to_ascii_lowercase();

            if allowed_exact_keys.contains(key) {
                scrubbed.insert(key.to_string(), val.to_string());
                continue;
            }

            let contains_sensitive = prohibited_fragments
                .iter()
                .any(|frag| lower_key.contains(frag));

            if !contains_sensitive {
                scrubbed.insert(key.to_string(), val.to_string());
            }
        }
        scrubbed
    }
}

/// Comprehensive Authoritative Sandbox Security Profile.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SandboxSecurityProfile {
    pub ceilings: SandboxResourceCeilings,
    pub network: SandboxNetworkPolicy,
    pub filesystem: SandboxFilesystemPolicy,
    pub process: SandboxProcessPolicy,
    pub credentials: SandboxCredentialsPolicy,
}

impl SandboxSecurityProfile {
    /// Creates the frozen default sandbox security profile.
    #[must_use]
    pub fn frozen_default() -> Self {
        Self::default()
    }

    /// Validates all sub-policies in this profile.
    ///
    /// # Errors
    /// Fails closed if any security ceiling or policy rule is violated.
    pub fn validate(&self) -> Result<(), String> {
        self.ceilings.validate()?;
        self.network.validate()?;
        self.filesystem.validate()?;
        self.process.validate()?;
        self.credentials.validate()?;
        Ok(())
    }
}
