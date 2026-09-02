//! Unit and contract test suite for parser sandbox profile, ceilings, and bounds (WI-0205).
//!
//! Validates:
//! - Hard frozen resource ceilings (<= 2 vCPU, <= 2 GiB RAM, <= 1 GiB tmpfs, <= 64 PIDs, <= 10 min wall clock, <= 10 MiB output)
//! - Out-of-bounds ceilings fail validation
//! - Network isolation policy (no public ingress, no general egress, no AI access, no external URLs)
//! - Filesystem boundary policy (read-only root, bounded tmpfs, no host mounts, no secret mounts)
//! - Process isolation policy (non-root UID/GID 65534, drop all capabilities, no-new-privileges)
//! - Credentials scrubbing: zero DB/AI/S3/KMS/audit/session credentials in sandbox environment
//! - Scoped single-object handoff integrity validation
//! - Typed bounded output validation and tamper detection
//! - Fail-closed error taxonomy and retryability classification
//! - Mock sandbox runner deterministic execution modes

use uuid::Uuid;
use w014_document_processing::sandbox::{
    FROZEN_MAX_CPU_CORES, FROZEN_MAX_MEMORY_BYTES, FROZEN_MAX_OUTPUT_BYTES, FROZEN_MAX_PIDS,
    FROZEN_MAX_TMPFS_BYTES, FROZEN_MAX_WALL_CLOCK_SECS, MockSandboxBehavior, MockSandboxRunner,
    NON_ROOT_GID, NON_ROOT_UID, OutputValidationError, ProcessSandboxRunner,
    SANDBOX_PROTOCOL_VERSION, SandboxCredentialsPolicy, SandboxError, SandboxFilesystemPolicy,
    SandboxInput, SandboxNetworkPolicy, SandboxOutput, SandboxProcessPolicy,
    SandboxResourceCeilings, SandboxRunner, SandboxSecurityProfile, SandboxStatus,
};
use w014_domain::ids::{DocumentVersionId, ObjectArtifactId, WorkspaceId};
use w014_domain::{LocatorVersion, Sha256, StoredMediaType};

#[test]
fn test_default_sandbox_profile_satisfies_all_frozen_ceilings() {
    let profile = SandboxSecurityProfile::frozen_default();
    assert!(profile.validate().is_ok());

    assert_eq!(profile.ceilings.max_cpu_cores, FROZEN_MAX_CPU_CORES);
    assert_eq!(profile.ceilings.max_memory_bytes, FROZEN_MAX_MEMORY_BYTES);
    assert_eq!(profile.ceilings.max_tmpfs_bytes, FROZEN_MAX_TMPFS_BYTES);
    assert_eq!(profile.ceilings.max_pids, FROZEN_MAX_PIDS);
    assert_eq!(
        profile.ceilings.max_wall_clock_seconds,
        FROZEN_MAX_WALL_CLOCK_SECS
    );
    assert_eq!(profile.ceilings.max_output_bytes, FROZEN_MAX_OUTPUT_BYTES);

    assert!(!profile.network.allow_public_ingress);
    assert!(!profile.network.allow_general_egress);
    assert!(!profile.network.allow_ai_provider_access);
    assert!(!profile.network.allow_external_urls);

    assert!(profile.filesystem.root_readonly);
    assert_eq!(profile.filesystem.tmpfs_max_bytes, FROZEN_MAX_TMPFS_BYTES);
    assert!(!profile.filesystem.allow_host_mounts);
    assert!(!profile.filesystem.allow_secret_mounts);
    assert!(!profile.filesystem.allow_docker_socket);

    assert!(profile.process.run_as_non_root);
    assert_eq!(profile.process.uid, NON_ROOT_UID);
    assert_eq!(profile.process.gid, NON_ROOT_GID);
    assert!(profile.process.drop_all_capabilities);
    assert!(profile.process.no_new_privileges);

    assert!(!profile.credentials.has_database_credentials);
    assert!(!profile.credentials.has_ai_credentials);
    assert!(!profile.credentials.has_s3_credentials);
    assert!(!profile.credentials.has_kms_credentials);
    assert!(!profile.credentials.has_audit_signing_credentials);
    assert!(!profile.credentials.has_audit_hmac_keys);
    assert!(!profile.credentials.has_session_credentials);
}

#[test]
fn test_resource_ceilings_fail_closed_on_excess() {
    // Excessive CPU
    let c = SandboxResourceCeilings {
        max_cpu_cores: 2.1,
        ..Default::default()
    };
    assert!(c.validate().is_err());

    // Excessive Memory (> 2 GiB)
    let c = SandboxResourceCeilings {
        max_memory_bytes: 2 * 1024 * 1024 * 1024 + 1,
        ..Default::default()
    };
    assert!(c.validate().is_err());

    // Excessive TMPFS (> 1 GiB)
    let c = SandboxResourceCeilings {
        max_tmpfs_bytes: 1024 * 1024 * 1024 + 1,
        ..Default::default()
    };
    assert!(c.validate().is_err());

    // Excessive PIDs (> 64)
    let c = SandboxResourceCeilings {
        max_pids: 65,
        ..Default::default()
    };
    assert!(c.validate().is_err());

    // Excessive Wall Clock (> 600s)
    let c = SandboxResourceCeilings {
        max_wall_clock_seconds: 601,
        ..Default::default()
    };
    assert!(c.validate().is_err());

    // Excessive Output (> 10 MiB)
    let c = SandboxResourceCeilings {
        max_output_bytes: 10 * 1024 * 1024 + 1,
        ..Default::default()
    };
    assert!(c.validate().is_err());
}

#[test]
fn test_security_policies_reject_permissive_settings() {
    let net = SandboxNetworkPolicy {
        allow_public_ingress: true,
        ..Default::default()
    };
    assert!(net.validate().is_err());

    let net = SandboxNetworkPolicy {
        allow_general_egress: true,
        ..Default::default()
    };
    assert!(net.validate().is_err());

    let net = SandboxNetworkPolicy {
        allow_ai_provider_access: true,
        ..Default::default()
    };
    assert!(net.validate().is_err());

    let fs = SandboxFilesystemPolicy {
        root_readonly: false,
        ..Default::default()
    };
    assert!(fs.validate().is_err());

    let fs = SandboxFilesystemPolicy {
        allow_host_mounts: true,
        ..Default::default()
    };
    assert!(fs.validate().is_err());

    let proc = SandboxProcessPolicy {
        run_as_non_root: false,
        ..Default::default()
    };
    assert!(proc.validate().is_err());

    let proc = SandboxProcessPolicy {
        uid: 0, // root
        ..Default::default()
    };
    assert!(proc.validate().is_err());

    let creds = SandboxCredentialsPolicy {
        has_database_credentials: true,
        ..Default::default()
    };
    assert!(creds.validate().is_err());

    let creds = SandboxCredentialsPolicy {
        has_ai_credentials: true,
        ..Default::default()
    };
    assert!(creds.validate().is_err());

    let creds = SandboxCredentialsPolicy {
        has_s3_credentials: true,
        ..Default::default()
    };
    assert!(creds.validate().is_err());
}

#[test]
fn test_credentials_scrubbing_removes_sensitive_environment() {
    let raw_env = vec![
        ("PATH", "/usr/bin:/bin"),
        ("LANG", "en_US.UTF-8"),
        ("DATABASE_URL", "postgres://user:pass@localhost/db"),
        ("SQLX_OFFLINE", "true"),
        ("POSTGRES_PASSWORD", "secret123"),
        ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
        (
            "AWS_SECRET_ACCESS_KEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ),
        ("S3_BUCKET_NAME", "w014-documents"),
        ("OPENAI_API_KEY", "sk-proj-test-123456"),
        ("ANTHROPIC_API_KEY", "sk-ant-test-123456"),
        ("GEMINI_API_KEY", "AIzaSyTest123"),
        ("APP_SESSION_TOKEN", "sess_xyz789"),
        ("KMS_KEY_ARN", "arn:aws:kms:us-east-1:123456:key/abc"),
        ("AUDIT_HMAC_SECRET", "super-secret-hmac-key"),
        ("SAFE_VAR", "benign_non_sensitive_value"),
    ];

    let scrubbed = SandboxCredentialsPolicy::scrub_environment(raw_env);

    assert_eq!(scrubbed.get("PATH").unwrap(), "/usr/bin:/bin");
    assert_eq!(scrubbed.get("LANG").unwrap(), "en_US.UTF-8");
    assert_eq!(
        scrubbed.get("SAFE_VAR").unwrap(),
        "benign_non_sensitive_value"
    );

    assert!(!scrubbed.contains_key("DATABASE_URL"));
    assert!(!scrubbed.contains_key("SQLX_OFFLINE"));
    assert!(!scrubbed.contains_key("POSTGRES_PASSWORD"));
    assert!(!scrubbed.contains_key("AWS_ACCESS_KEY_ID"));
    assert!(!scrubbed.contains_key("AWS_SECRET_ACCESS_KEY"));
    assert!(!scrubbed.contains_key("S3_BUCKET_NAME"));
    assert!(!scrubbed.contains_key("OPENAI_API_KEY"));
    assert!(!scrubbed.contains_key("ANTHROPIC_API_KEY"));
    assert!(!scrubbed.contains_key("GEMINI_API_KEY"));
    assert!(!scrubbed.contains_key("APP_SESSION_TOKEN"));
    assert!(!scrubbed.contains_key("KMS_KEY_ARN"));
    assert!(!scrubbed.contains_key("AUDIT_HMAC_SECRET"));
}

#[test]
fn test_scoped_single_object_handoff_input_validation() {
    let ws_id = WorkspaceId::new();
    let dv_id = DocumentVersionId::new();
    let oa_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let media_type = StoredMediaType::new("application/pdf").unwrap();
    let sample_bytes = b"%PDF-1.7 scoped test document bytes".to_vec();
    let expected_sha = Sha256::digest(&sample_bytes);
    let expected_len = sample_bytes.len() as i64;

    // Valid handoff
    let input = SandboxInput::new(
        ws_id,
        dv_id,
        oa_id,
        job_id,
        media_type.clone(),
        expected_sha,
        expected_len,
        sample_bytes.clone(),
    );
    assert!(input.is_ok());
    let valid_input = input.unwrap();
    assert!(valid_input.is_single_object());
    assert!(valid_input.verify_integrity().is_ok());

    // Length mismatch
    let bad_len = SandboxInput::new(
        ws_id,
        dv_id,
        oa_id,
        job_id,
        media_type.clone(),
        expected_sha,
        expected_len + 10,
        sample_bytes.clone(),
    );
    assert!(bad_len.is_err());

    // SHA-256 mismatch
    let tampered_bytes = b"%PDF-1.7 tampered bytes".to_vec();
    let bad_sha = SandboxInput::new(
        ws_id,
        dv_id,
        oa_id,
        job_id,
        media_type,
        expected_sha,
        tampered_bytes.len() as i64,
        tampered_bytes,
    );
    assert!(bad_sha.is_err());
}

#[test]
fn test_typed_bounded_output_validation() {
    let ws_id = WorkspaceId::new();
    let dv_id = DocumentVersionId::new();
    let oa_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let media_type = StoredMediaType::new("application/pdf").unwrap();
    let sample_bytes = b"%PDF-1.7 scoped test document bytes".to_vec();
    let expected_sha = Sha256::digest(&sample_bytes);
    let expected_len = sample_bytes.len() as i64;

    let input = SandboxInput::new(
        ws_id,
        dv_id,
        oa_id,
        job_id,
        media_type,
        expected_sha,
        expected_len,
        sample_bytes,
    )
    .unwrap();

    let locator = LocatorVersion::new("w014-loc-v1").unwrap();

    // Valid output matching input
    let valid_output = SandboxOutput {
        protocol_version: SANDBOX_PROTOCOL_VERSION.to_string(),
        document_version_id: dv_id,
        object_artifact_id: oa_id,
        input_sha256: expected_sha,
        status: SandboxStatus::Success,
        parser_name: "test-parser".to_string(),
        parser_version: "1.0.0".to_string(),
        locator_version: locator.clone(),
        page_count: 5,
        block_count: 50,
        span_count: 100,
        text_sha256: Some(expected_sha),
        execution_duration_ms: 120,
        failure_code: None,
        failure_detail: None,
        parsed_artifact: None,
    };
    assert!(valid_output.validate_against_input(&input).is_ok());

    // Protocol version mismatch
    let mut bad_protocol = valid_output.clone();
    bad_protocol.protocol_version = "parser-sandbox-v99".to_string();
    assert!(matches!(
        bad_protocol.validate_against_input(&input),
        Err(OutputValidationError::ProtocolMismatch { .. })
    ));

    // DocumentVersionId mismatch
    let mut bad_dv = valid_output.clone();
    bad_dv.document_version_id = DocumentVersionId::new();
    assert!(matches!(
        bad_dv.validate_against_input(&input),
        Err(OutputValidationError::DocumentVersionMismatch { .. })
    ));

    // ObjectArtifactId mismatch
    let mut bad_oa = valid_output.clone();
    bad_oa.object_artifact_id = ObjectArtifactId::new();
    assert!(matches!(
        bad_oa.validate_against_input(&input),
        Err(OutputValidationError::ObjectArtifactMismatch { .. })
    ));

    // Input SHA-256 mismatch
    let mut bad_hash = valid_output.clone();
    bad_hash.input_sha256 = Sha256::digest(b"different content");
    assert!(matches!(
        bad_hash.validate_against_input(&input),
        Err(OutputValidationError::InputHashMismatch { .. })
    ));

    // Out of bounds page count (< 0 or > 10,000)
    let mut bad_pages = valid_output.clone();
    bad_pages.page_count = -1;
    assert!(matches!(
        bad_pages.validate_against_input(&input),
        Err(OutputValidationError::PageCountOutOfBounds { .. })
    ));

    let mut bad_pages = valid_output.clone();
    bad_pages.page_count = 10_001;
    assert!(matches!(
        bad_pages.validate_against_input(&input),
        Err(OutputValidationError::PageCountOutOfBounds { .. })
    ));

    // Failed status requires failure_code
    let mut failed_without_code = valid_output.clone();
    failed_without_code.status = SandboxStatus::Failed;
    failed_without_code.failure_code = None;
    assert!(matches!(
        failed_without_code.validate_against_input(&input),
        Err(OutputValidationError::MissingFailureCode)
    ));
}

#[test]
fn test_sandbox_error_retryability_and_codes() {
    let timeout = SandboxError::Timeout {
        elapsed_secs: 601,
        limit_secs: 600,
    };
    assert!(timeout.is_retryable());
    assert_eq!(timeout.error_code(), "SANDBOX_TIMEOUT");

    let oom = SandboxError::OutOfMemory {
        detail: "Killed by OOM killer".into(),
    };
    assert!(oom.is_retryable());
    assert_eq!(oom.error_code(), "SANDBOX_OOM");

    let crash = SandboxError::ProcessCrash {
        exit_code: Some(1),
        signal: None,
        stderr: "Segfault".into(),
    };
    assert!(crash.is_retryable());
    assert_eq!(crash.error_code(), "SANDBOX_CRASH");

    let violation = SandboxError::SandboxViolation {
        violation_type: "NETWORK_EGRESS".into(),
        detail: "Attempted socket connect to 8.8.8.8".into(),
    };
    assert!(!violation.is_retryable());
    assert_eq!(violation.error_code(), "SANDBOX_VIOLATION");

    let malformed = SandboxError::MalformedOutput {
        detail: "Truncated JSON".into(),
    };
    assert!(!malformed.is_retryable());
    assert_eq!(malformed.error_code(), "SANDBOX_MALFORMED_OUTPUT");
}

#[tokio::test]
async fn test_mock_sandbox_runner_deterministic_execution() {
    let ws_id = WorkspaceId::new();
    let dv_id = DocumentVersionId::new();
    let oa_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let media_type = StoredMediaType::new("application/pdf").unwrap();
    let sample_bytes = b"%PDF-1.7 test".to_vec();
    let expected_sha = Sha256::digest(&sample_bytes);
    let expected_len = sample_bytes.len() as i64;

    let input = SandboxInput::new(
        ws_id,
        dv_id,
        oa_id,
        job_id,
        media_type,
        expected_sha,
        expected_len,
        sample_bytes,
    )
    .unwrap();
    let profile = SandboxSecurityProfile::frozen_default();

    // 1. Automatic success
    let runner = MockSandboxRunner::new();
    let res = runner.run(&profile, &input).await.unwrap();
    assert_eq!(res.status, SandboxStatus::Success);
    assert_eq!(res.document_version_id, dv_id);
    assert_eq!(res.object_artifact_id, oa_id);
    assert_eq!(res.input_sha256, expected_sha);
    assert_eq!(runner.execution_count(), 1);

    // 2. Timeout behavior
    let runner = MockSandboxRunner::new().with_behavior(MockSandboxBehavior::Timeout(601));
    let err = runner.run(&profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::Timeout { .. }));

    // 3. OOM behavior
    let runner = MockSandboxRunner::new().with_behavior(MockSandboxBehavior::OutOfMemory);
    let err = runner.run(&profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::OutOfMemory { .. }));

    // 4. Security violation behavior
    let runner = MockSandboxRunner::new().with_behavior(MockSandboxBehavior::SandboxViolation(
        "Network connect attempted".into(),
    ));
    let err = runner.run(&profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));
}

#[tokio::test]
async fn test_process_sandbox_profile_enforcement_fail_closed_matrix() {
    use w014_document_processing::sandbox::ProcessSandboxRunner;

    let ws_id = WorkspaceId::new();
    let dv_id = DocumentVersionId::new();
    let oa_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let media_type = StoredMediaType::new("application/pdf").unwrap();
    let sample_bytes = b"%PDF-1.7 scoped test bytes".to_vec();
    let input = SandboxInput::new(
        ws_id,
        dv_id,
        oa_id,
        job_id,
        media_type,
        Sha256::digest(&sample_bytes),
        sample_bytes.len() as i64,
        sample_bytes,
    )
    .unwrap();

    let runner = ProcessSandboxRunner::new("/bin/sh").with_args(["-c", "exit 0"]);

    // Case 1: Permissive network ingress -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.network.allow_public_ingress = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 2: Permissive network egress -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.network.allow_general_egress = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 3: Permissive AI provider access -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.network.allow_ai_provider_access = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 4: Permissive external URL fetching -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.network.allow_external_urls = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 5: Root filesystem not read-only -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.filesystem.root_readonly = false;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 6: Host mounts allowed -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.filesystem.allow_host_mounts = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 7: Secret mounts allowed -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.filesystem.allow_secret_mounts = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 8: Docker socket allowed -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.filesystem.allow_docker_socket = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 9: TMPFS exceeds 1 GiB -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.filesystem.tmpfs_max_bytes = 1024 * 1024 * 1024 + 1;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 10: Root UID (0) -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.process.uid = 0;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 11: Non-root flag disabled -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.process.run_as_non_root = false;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 12: No-new-privileges disabled -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.process.no_new_privileges = false;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 13: Capability dropping disabled -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.process.drop_all_capabilities = false;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 14: Database credentials present in profile -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.credentials.has_database_credentials = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 15: AI credentials present in profile -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.credentials.has_ai_credentials = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 16: S3 credentials present in profile -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.credentials.has_s3_credentials = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 17: KMS credentials present in profile -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.credentials.has_kms_credentials = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 18: Audit signing credentials present in profile -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.credentials.has_audit_signing_credentials = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 19: Audit HMAC keys present in profile -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.credentials.has_audit_hmac_keys = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 20: Session credentials present in profile -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.credentials.has_session_credentials = true;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 21: CPU limit exceeds 2 vCPU -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.ceilings.max_cpu_cores = 2.5;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 22: Memory limit exceeds 2 GiB -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.ceilings.max_memory_bytes = 3 * 1024 * 1024 * 1024;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 23: PID limit exceeds 64 -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.ceilings.max_pids = 128;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 24: Wall clock exceeds 600s -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.ceilings.max_wall_clock_seconds = 601;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 25: Output ceiling exceeds 10 MiB -> Fail closed
    let mut bad_profile = SandboxSecurityProfile::frozen_default();
    bad_profile.ceilings.max_output_bytes = 10 * 1024 * 1024 + 1;
    let err = runner.run(&bad_profile, &input).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxViolation { .. }));

    // Case 26: Valid profile BUT missing isolation wrapper -> Fail closed (unsandboxed direct execution impossible)
    let good_profile = SandboxSecurityProfile::frozen_default();
    let unisolated_runner = ProcessSandboxRunner::new("/bin/sh").with_args(["-c", "exit 0"]);
    let err = unisolated_runner
        .run(&good_profile, &input)
        .await
        .unwrap_err();
    match err {
        SandboxError::SandboxViolation {
            ref violation_type,
            ref detail,
        } => {
            assert_eq!(violation_type, "MISSING_ISOLATION_WRAPPER");
            assert!(detail.contains("isolation wrapper"));
        }
        other => panic!("Expected MISSING_ISOLATION_WRAPPER, got {other:?}"),
    }

    // Case 27: Nonexistent isolation wrapper -> Fail closed
    let bad_wrapper_runner = ProcessSandboxRunner::new("/bin/sh")
        .with_wrapper("/nonexistent/bin/sandbox-wrapper-404", ["--isolated"]);
    let err = bad_wrapper_runner
        .run(&good_profile, &input)
        .await
        .unwrap_err();
    match err {
        SandboxError::SandboxViolation {
            ref violation_type,
            ref detail,
        } => {
            assert_eq!(violation_type, "ISOLATION_WRAPPER_NOT_FOUND");
            assert!(detail.contains("sandbox-wrapper-404"));
        }
        other => panic!("Expected ISOLATION_WRAPPER_NOT_FOUND, got {other:?}"),
    }
}

fn create_test_runner(args: &[&str]) -> ProcessSandboxRunner {
    let runner = ProcessSandboxRunner::new("/bin/sh").with_args(args.iter().copied());
    if let Some((wb, wa)) = ProcessSandboxRunner::platform_default_wrapper() {
        runner.with_wrapper(wb, wa)
    } else {
        runner.with_wrapper("/usr/bin/env", ["--"])
    }
}

#[tokio::test]
async fn test_process_sandbox_credential_and_environment_scrubbing() {
    // Set sensitive variables in parent environment
    unsafe {
        std::env::set_var("DATABASE_URL", "postgres://user:pass@localhost:5432/db");
        std::env::set_var("OPENAI_API_KEY", "sk-proj-secret123456");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "secret-aws-key");
        std::env::set_var("KMS_KEY_ARN", "arn:aws:kms:us-east-1:1234:key/test");
        std::env::set_var("AUDIT_HMAC_SECRET", "super-secret-hmac");
        std::env::set_var("APP_SESSION_TOKEN", "sess_9999");
    }

    let ws_id = WorkspaceId::new();
    let dv_id = DocumentVersionId::new();
    let oa_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let media_type = StoredMediaType::new("application/pdf").unwrap();
    let sample_bytes = b"%PDF-1.7 scoped test bytes".to_vec();
    let input = SandboxInput::new(
        ws_id,
        dv_id,
        oa_id,
        job_id,
        media_type,
        Sha256::digest(&sample_bytes),
        sample_bytes.len() as i64,
        sample_bytes,
    )
    .unwrap();

    let profile = SandboxSecurityProfile::frozen_default();

    // Launch a process that checks for sensitive environment variables
    let check_script = r#"
        if env | grep -iE 'DATABASE_URL|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|KMS_KEY_ARN|AUDIT_HMAC_SECRET|APP_SESSION_TOKEN'; then
            echo "LEAKED_CREDENTIALS" >&2
            exit 1
        fi
        printf '{"protocol_version":"parser-sandbox-v1","document_version_id":"%s","object_artifact_id":"%s","input_sha256":"%s","status":"success","parser_name":"test-parser","parser_version":"1.0.0","locator_version":"w014-loc-v1","page_count":1,"block_count":1,"span_count":1,"text_sha256":"%s","execution_duration_ms":10,"failure_code":null,"failure_detail":null,"parsed_artifact":null}' "$W014_DOCUMENT_VERSION_ID" "$W014_OBJECT_ARTIFACT_ID" "$W014_INPUT_SHA256" "$W014_INPUT_SHA256"
    "#;

    let runner = create_test_runner(&["-c", check_script]);
    let output = runner
        .run(&profile, &input)
        .await
        .expect("scrubbed execution must succeed");

    assert_eq!(output.status, SandboxStatus::Success);
    assert_eq!(output.document_version_id, dv_id);
    assert_eq!(output.object_artifact_id, oa_id);
}

#[tokio::test]
async fn test_process_sandbox_wall_clock_timeout_terminates_and_reaps() {
    use std::time::Instant;

    let ws_id = WorkspaceId::new();
    let dv_id = DocumentVersionId::new();
    let oa_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let media_type = StoredMediaType::new("application/pdf").unwrap();
    let sample_bytes = b"%PDF-1.7 scoped test bytes".to_vec();
    let input = SandboxInput::new(
        ws_id,
        dv_id,
        oa_id,
        job_id,
        media_type,
        Sha256::digest(&sample_bytes),
        sample_bytes.len() as i64,
        sample_bytes,
    )
    .unwrap();

    let mut profile = SandboxSecurityProfile::frozen_default();
    profile.ceilings.max_wall_clock_seconds = 1; // Strict 1 second timeout

    // Run a process that attempts to sleep for 10 seconds
    let runner = create_test_runner(&["-c", "sleep 10"]);

    let start = Instant::now();
    let err = runner.run(&profile, &input).await.unwrap_err();
    let elapsed = start.elapsed();

    assert!(matches!(err, SandboxError::Timeout { .. }));
    assert!(
        elapsed.as_secs() <= 3,
        "Timeout must enforce termination promptly (elapsed: {elapsed:?})"
    );
}

#[tokio::test]
async fn test_process_sandbox_oversized_stdout_terminates_during_streaming() {
    let ws_id = WorkspaceId::new();
    let dv_id = DocumentVersionId::new();
    let oa_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let media_type = StoredMediaType::new("application/pdf").unwrap();
    let sample_bytes = b"%PDF-1.7 scoped test bytes".to_vec();
    let input = SandboxInput::new(
        ws_id,
        dv_id,
        oa_id,
        job_id,
        media_type,
        Sha256::digest(&sample_bytes),
        sample_bytes.len() as i64,
        sample_bytes,
    )
    .unwrap();

    let mut profile = SandboxSecurityProfile::frozen_default();
    profile.ceilings.max_output_bytes = 4096; // Tight 4 KB bound for test

    // Script generates 100 KB of stdout (well exceeding the 4 KB bound)
    let runner = create_test_runner(&["-c", "head -c 102400 /dev/zero | tr '\\000' 'A'"]);

    let err = runner.run(&profile, &input).await.unwrap_err();
    match err {
        SandboxError::ResourceViolation {
            resource, limit, ..
        } => {
            assert_eq!(resource, "stdout_output_bytes");
            assert!(limit.contains("4096"));
        }
        other => panic!("Expected ResourceViolation for stdout overflow, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_process_sandbox_oversized_stderr_terminates_during_streaming() {
    let ws_id = WorkspaceId::new();
    let dv_id = DocumentVersionId::new();
    let oa_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let media_type = StoredMediaType::new("application/pdf").unwrap();
    let sample_bytes = b"%PDF-1.7 scoped test bytes".to_vec();
    let input = SandboxInput::new(
        ws_id,
        dv_id,
        oa_id,
        job_id,
        media_type,
        Sha256::digest(&sample_bytes),
        sample_bytes.len() as i64,
        sample_bytes,
    )
    .unwrap();

    let mut profile = SandboxSecurityProfile::frozen_default();
    profile.ceilings.max_output_bytes = 4096; // Tight 4 KB bound for test

    // Script generates 100 KB of stderr (well exceeding the 4 KB bound)
    let runner = create_test_runner(&["-c", "head -c 102400 /dev/zero | tr '\\000' 'E' >&2"]);

    let err = runner.run(&profile, &input).await.unwrap_err();
    match err {
        SandboxError::ResourceViolation {
            resource, limit, ..
        } => {
            assert_eq!(resource, "stderr_output_bytes");
            assert!(limit.contains("4096"));
        }
        other => panic!("Expected ResourceViolation for stderr overflow, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_process_sandbox_crash_captures_bounded_stderr_and_fails_closed() {
    let ws_id = WorkspaceId::new();
    let dv_id = DocumentVersionId::new();
    let oa_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let media_type = StoredMediaType::new("application/pdf").unwrap();
    let sample_bytes = b"%PDF-1.7 scoped test bytes".to_vec();
    let input = SandboxInput::new(
        ws_id,
        dv_id,
        oa_id,
        job_id,
        media_type,
        Sha256::digest(&sample_bytes),
        sample_bytes.len() as i64,
        sample_bytes,
    )
    .unwrap();

    let profile = SandboxSecurityProfile::frozen_default();

    let runner = create_test_runner(&["-c", "echo 'Fatal memory fault inside parser' >&2; exit 2"]);

    let err = runner.run(&profile, &input).await.unwrap_err();
    match err {
        SandboxError::ProcessCrash {
            exit_code, stderr, ..
        } => {
            assert_eq!(exit_code, Some(2));
            assert!(stderr.contains("Fatal memory fault inside parser"));
        }
        other => panic!("Expected ProcessCrash, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_process_sandbox_real_os_boundary_enforcement() {
    let ws_id = WorkspaceId::new();
    let dv_id = DocumentVersionId::new();
    let oa_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let media_type = StoredMediaType::new("application/pdf").unwrap();
    let sample_bytes = b"%PDF-1.7 scoped test bytes".to_vec();
    let input = SandboxInput::new(
        ws_id,
        dv_id,
        oa_id,
        job_id,
        media_type,
        Sha256::digest(&sample_bytes),
        sample_bytes.len() as i64,
        sample_bytes,
    )
    .unwrap();

    let profile = SandboxSecurityProfile::frozen_default();

    // 1. Missing wrapper deterministically fails closed (direct execution is impossible)
    let direct_runner = ProcessSandboxRunner::new("/bin/sh").with_args(["-c", "exit 0"]);
    let err = direct_runner.run(&profile, &input).await.unwrap_err();
    assert!(matches!(
        err,
        SandboxError::SandboxViolation {
            ref violation_type,
            ..
        } if violation_type == "MISSING_ISOLATION_WRAPPER"
    ));

    // 2. If a platform wrapper is available, verify real OS boundary enforcement
    if let Some((wb, wa)) = ProcessSandboxRunner::platform_default_wrapper() {
        // Sub-test A: Root filesystem write is blocked by OS boundary (Fail Closed)
        let write_attempt_script = "touch /etc/w014_hacked_root 2>&1";
        let runner_write = ProcessSandboxRunner::new("/bin/sh")
            .with_wrapper(wb.clone(), wa.clone())
            .with_args(["-c", write_attempt_script]);
        let err = runner_write.run(&profile, &input).await.unwrap_err();
        assert!(
            matches!(err, SandboxError::ProcessCrash { .. }),
            "Attempt to write to root filesystem must fail closed via OS boundary, got {err:?}"
        );

        // Sub-test B: Network socket connect is blocked by OS boundary (Fail Closed)
        let network_attempt_script = "nc -z -w 1 8.8.8.8 53 2>&1 || exit 42";
        let runner_net = ProcessSandboxRunner::new("/bin/sh")
            .with_wrapper(wb.clone(), wa.clone())
            .with_args(["-c", network_attempt_script]);
        let err = runner_net.run(&profile, &input).await.unwrap_err();
        assert!(
            matches!(err, SandboxError::ProcessCrash { .. }),
            "Attempt to access network must fail closed via OS boundary, got {err:?}"
        );

        // Sub-test C: Docker socket communication is blocked by OS boundary
        let docker_socket_script = "nc -U /var/run/docker.sock </dev/null 2>&1 || exit 88";
        let runner_docker = ProcessSandboxRunner::new("/bin/sh")
            .with_wrapper(wb, wa)
            .with_args(["-c", docker_socket_script]);
        let err = runner_docker.run(&profile, &input).await.unwrap_err();
        assert!(
            matches!(err, SandboxError::ProcessCrash { .. }),
            "Docker socket communication must be blocked by OS boundary, got {err:?}"
        );
    }
}
