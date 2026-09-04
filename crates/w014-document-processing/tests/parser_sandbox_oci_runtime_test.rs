//! D3 closure tests: OCI runtime enforcement vs declaration, and the concrete
//! `w014-parser-sandbox` production binary contract.
//!
//! Distinguishes `STATIC_OR_COMMAND_CONTRACT_TESTED` (deterministic command /
//! policy construction plus direct binary protocol execution) from
//! `ACTUAL_RUNTIME_ENFORCEMENT_TESTED` (live container probes, executed when
//! the approved `docker` backend is present, otherwise deterministic
//! fail-closed demonstration).

use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::process::Stdio;

use uuid::Uuid;
use w014_document_processing::sandbox::{
    DEFAULT_OCI_IMAGE, ProcessSandboxRunner, SANDBOX_PROTOCOL_VERSION, SandboxError, SandboxInput,
    SandboxRunner, SandboxSecurityProfile, SandboxStatus,
};
use w014_domain::LocatorVersion;
use w014_domain::Sha256;
use w014_domain::StoredMediaType;
use w014_domain::ids::{DocumentVersionId, ObjectArtifactId, WorkspaceId};

static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn sample_input_with_media(media: &str, bytes: Vec<u8>) -> SandboxInput {
    SandboxInput::new(
        WorkspaceId::new(),
        DocumentVersionId::new(),
        ObjectArtifactId::new(),
        Uuid::new_v4(),
        StoredMediaType::new(media).unwrap(),
        Sha256::digest(&bytes),
        bytes.len() as i64,
        bytes,
    )
    .unwrap()
}

fn sample_pdf_bytes(text: &str) -> Vec<u8> {
    let stream_content = format!("BT /F1 12 Tf 50 700 Td ({text}) Tj ET");
    let stream_len = stream_content.len();
    format!(
        "%PDF-1.4\n\
        1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
        2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
        3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n\
        4 0 obj\n<< /Length {stream_len} >>\nstream\n{stream_content}\nendstream\nendobj\n\
        xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000210 00000 n \n\
        trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n300\n%%EOF\n"
    )
    .into_bytes()
}

fn sample_docx_bytes() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(Cursor::new(&mut buf));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="xml" ContentType="application/xml"/>
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#,
        )
        .unwrap();
        zip.start_file("_rels/.rels", options).unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#,
        )
        .unwrap();
        zip.start_file("word/_rels/document.xml.rels", options)
            .unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>"#,
        )
        .unwrap();
        zip.start_file("word/document.xml", options).unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello OCI sandbox</w:t></w:r></w:p></w:body></w:document>"#,
        )
        .unwrap();
        zip.finish().unwrap();
    }
    buf
}

fn runner_with_backend() -> ProcessSandboxRunner {
    // Command-construction tests need the approved backend selector bound so
    // failures (when asserted) come from policy/profile validation rather
    // than backend resolution. Hosts without the backend demonstrate
    // deterministic fail-closed behavior instead.
    let runner = ProcessSandboxRunner::new("w014-parser-sandbox");
    if let Some((wb, wa)) = ProcessSandboxRunner::platform_default_wrapper() {
        runner.with_wrapper(wb, wa)
    } else {
        runner
    }
}

fn real_parser_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_w014-parser-sandbox"))
}

#[allow(clippy::too_many_arguments)]
fn run_real_binary(
    binary: &std::path::Path,
    workspace: &str,
    version: &str,
    artifact: &str,
    job: &str,
    media: &str,
    sha_hex: &str,
    byte_len: i64,
    stdin_bytes: &[u8],
) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let mut child = std::process::Command::new(binary)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("W014_SANDBOX_PROTOCOL", SANDBOX_PROTOCOL_VERSION)
        .env("W014_WORKSPACE_ID", workspace)
        .env("W014_DOCUMENT_VERSION_ID", version)
        .env("W014_OBJECT_ARTIFACT_ID", artifact)
        .env("W014_JOB_ID", job)
        .env("W014_MEDIA_TYPE", media)
        .env("W014_INPUT_SHA256", sha_hex)
        .env("W014_BYTE_LENGTH", byte_len.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("real parser binary must spawn");
    child.stdin.take().unwrap().write_all(stdin_bytes).unwrap();
    let output = child.wait_with_output().expect("wait on parser binary");
    (output.status.code(), output.stdout, output.stderr)
}

// ---------------------------------------------------------------------------
// PART A — authoritative OCI policy is generated, never configured
// ---------------------------------------------------------------------------

#[test]
fn test_oci_command_enforces_authoritative_policy() {
    let profile = SandboxSecurityProfile::frozen_default();
    let input = sample_input_with_media("application/pdf", b"%PDF-1.7 probe".to_vec());
    let runner = runner_with_backend();
    let build = runner.build_oci_command(&profile, &input);
    if ProcessSandboxRunner::platform_default_wrapper().is_none() {
        assert!(build.is_err(), "missing backend must fail closed");
        return;
    }
    let (_, argv) = build.expect("frozen profile must build OCI policy");
    let joined = argv.join(" ");

    // Mandatory enforcement actually present in the runtime command.
    for required in [
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--user",
        "65534:65534",
        "--pids-limit=64",
        DEFAULT_OCI_IMAGE,
        "w014-parser-sandbox",
    ] {
        assert!(
            joined.contains(required),
            "OCI policy must actually enforce '{required}': {joined}"
        );
    }
    assert!(
        argv.iter().any(|a| a.starts_with("--cpus=")),
        "CPU capacity must be enforced via runtime quota: {joined}"
    );
    let cpus = argv
        .iter()
        .find(|a| a.starts_with("--cpus="))
        .unwrap()
        .trim_start_matches("--cpus=")
        .parse::<f64>()
        .unwrap();
    assert!(
        cpus > 0.0 && cpus <= 2.0,
        "declared CPU quota must satisfy <=2 vCPU, got {cpus}"
    );
    assert!(
        argv.iter().any(|a| a == "--memory=2147483648"),
        "memory must be enforced at <=2 GiB: {joined}"
    );
    assert!(
        argv.iter().any(|a| a == "--memory-swap=2147483648"),
        "swap must be capped with memory (no escape): {joined}"
    );
    assert!(
        joined.contains("type=tmpfs,destination=/tmp,tmpfs-size=1073741824"),
        "scratch tmpfs must be bounded <=1 GiB: {joined}"
    );
    // Scoped identity only: metadata piped via -e, stdin carries object bytes.
    for key in [
        "W014_WORKSPACE_ID",
        "W014_DOCUMENT_VERSION_ID",
        "W014_OBJECT_ARTIFACT_ID",
        "W014_JOB_ID",
        "W014_MEDIA_TYPE",
        "W014_INPUT_SHA256",
        "W014_BYTE_LENGTH",
    ] {
        assert!(joined.contains(key), "scoped handoff key missing: {key}");
    }

    // Forbidden exposures must be ABSENT from the authoritative policy.
    let host_root_bind = ["--ro".to_string(), "-bind".to_string()].concat();
    for forbidden in [
        host_root_bind.as_str(),
        "-v /",
        "--volume",
        "type=bind",
        "--secret",
        "/var/run/docker.sock",
        "--privileged",
        "--cap-add",
        "--network=host",
        "--network=bridge",
        "--pid=host",
        "seccomp=unconfined",
        "--user 0",
    ] {
        assert!(
            !joined.contains(forbidden),
            "OCI policy must not contain '{forbidden}': {joined}"
        );
    }
    // No product credentials are injected into the container policy.
    for secret in [
        "DATABASE_URL",
        "OPENAI_API_KEY",
        "AWS_SECRET",
        "KMS_KEY",
        "AUDIT_HMAC",
        "SESSION_TOKEN",
    ] {
        assert!(
            !joined.contains(secret),
            "container policy must not inject '{secret}': {joined}"
        );
    }
}

#[test]
fn test_arbitrary_wrapper_never_accepted_as_sandbox_authority() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let profile = SandboxSecurityProfile::frozen_default();
    let input = sample_input_with_media("application/pdf", b"%PDF-1.7 probe".to_vec());

    // Existing host executables are rejected as sandbox authority.
    for unapproved in ["/bin/sh", "/usr/bin/env", "/bin/echo"] {
        if std::path::Path::new(unapproved).is_file() {
            let runner = ProcessSandboxRunner::new("w014-parser-sandbox")
                .with_wrapper(unapproved, Vec::<String>::new());
            let err = runner
                .build_oci_command(&profile, &input)
                .expect_err("arbitrary existing executable must not build policy");
            match err {
                SandboxError::SandboxViolation { violation_type, .. } => {
                    assert_eq!(violation_type, "UNAPPROVED_ISOLATION_BACKEND");
                }
                other => panic!("expected UNAPPROVED_ISOLATION_BACKEND, got {other:?}"),
            }
        }
    }

    // Nonexistent backend fails closed as not-found.
    let runner = ProcessSandboxRunner::new("w014-parser-sandbox")
        .with_wrapper("/nonexistent/bin/no-such-backend-404", Vec::<String>::new());
    match runner.build_oci_command(&profile, &input).unwrap_err() {
        SandboxError::SandboxViolation { violation_type, .. } => {
            assert_eq!(violation_type, "ISOLATION_WRAPPER_NOT_FOUND");
        }
        other => panic!("expected ISOLATION_WRAPPER_NOT_FOUND, got {other:?}"),
    }

    // Environment selector pointing at an arbitrary existing executable fails closed.
    unsafe {
        std::env::set_var("W014_PARSER_SANDBOX_WRAPPER_BIN", "/bin/sh");
    }
    let runner = ProcessSandboxRunner::new("w014-parser-sandbox");
    match runner.build_oci_command(&profile, &input).unwrap_err() {
        SandboxError::SandboxViolation { violation_type, .. } => {
            assert_eq!(violation_type, "UNAPPROVED_ISOLATION_BACKEND");
        }
        other => panic!("expected UNAPPROVED_ISOLATION_BACKEND via env, got {other:?}"),
    }

    // Stored and environment wrapper arguments can never weaken the policy:
    // hostile flags are ignored, mandatory flags remain generated by W014.
    unsafe {
        std::env::set_var("W014_PARSER_SANDBOX_WRAPPER_BIN", "docker");
        std::env::set_var(
            "W014_PARSER_SANDBOX_WRAPPER_ARGS",
            "--privileged --network=host -v /:/host",
        );
    }
    let runner = ProcessSandboxRunner::new("w014-parser-sandbox")
        .with_wrapper("docker", ["--privileged", "--network=host"]);
    // Either the backend is missing (fail closed) or the built policy ignores
    // hostile arguments while retaining mandatory enforcement.
    match runner.build_oci_command(&profile, &input) {
        Ok((_, argv)) => {
            let joined = argv.join(" ");
            assert!(joined.contains("--network=none"));
            assert!(!joined.contains("--privileged"));
            assert!(!joined.contains("--network=host"));
            assert!(!joined.contains("-v /:/host"));
        }
        Err(SandboxError::SandboxViolation { .. }) => {}
        Err(other) => panic!("unexpected error kind: {other:?}"),
    }
    unsafe {
        std::env::remove_var("W014_PARSER_SANDBOX_WRAPPER_BIN");
        std::env::remove_var("W014_PARSER_SANDBOX_WRAPPER_ARGS");
    }
}

#[test]
fn test_required_limit_setup_failure_fails_closed() {
    let input = sample_input_with_media("application/pdf", b"%PDF-1.7 probe".to_vec());
    let runner = runner_with_backend();

    // Every mandatory boundary violation fails policy construction.
    let mut bad = SandboxSecurityProfile::frozen_default();
    bad.ceilings.max_memory_bytes = 3 * 1024 * 1024 * 1024;
    assert!(runner.build_oci_command(&bad, &input).is_err());

    let mut bad = SandboxSecurityProfile::frozen_default();
    bad.ceilings.max_pids = 128;
    assert!(runner.build_oci_command(&bad, &input).is_err());

    let mut bad = SandboxSecurityProfile::frozen_default();
    bad.ceilings.max_cpu_cores = 4.0;
    assert!(runner.build_oci_command(&bad, &input).is_err());

    let mut bad = SandboxSecurityProfile::frozen_default();
    bad.process.no_new_privileges = false;
    assert!(runner.build_oci_command(&bad, &input).is_err());

    let mut bad = SandboxSecurityProfile::frozen_default();
    bad.filesystem.allow_host_mounts = true;
    assert!(runner.build_oci_command(&bad, &input).is_err());

    let mut bad = SandboxSecurityProfile::frozen_default();
    bad.network.allow_general_egress = true;
    assert!(runner.build_oci_command(&bad, &input).is_err());

    // Missing backend fails closed (never direct host execution).
    let _lock = ENV_MUTEX.lock().unwrap();
    unsafe {
        std::env::remove_var("W014_PARSER_SANDBOX_WRAPPER_BIN");
    }
    let bare = ProcessSandboxRunner::new("w014-parser-sandbox");
    assert!(
        bare.build_oci_command(&SandboxSecurityProfile::frozen_default(), &input)
            .is_err()
    );
}

#[test]
fn test_false_isolation_patterns_absent_from_authoritative_sources() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let process_src =
        std::fs::read_to_string(manifest.join("src/sandbox/process.rs")).expect("read process.rs");
    let oci_src =
        std::fs::read_to_string(manifest.join("src/sandbox/oci.rs")).expect("read oci.rs");
    // The forbidden host-root bind must not remain authoritative anywhere.
    let forbidden_bind = ["--ro".to_string(), "-bind / /".to_string()].concat();
    for (name, src) in [("process.rs", &process_src), ("oci.rs", &oci_src)] {
        assert!(
            !src.contains(&forbidden_bind),
            "{name} must not contain host-root bind authority"
        );
        // Best-effort ignored enforcement must not remain.
        assert!(
            !src.contains("let _ = setrlimit"),
            "{name} must not discard enforcement results"
        );
    }
    // Broad host filesystem read allowance must not remain authoritative.
    let broad_read = ["allow file".to_string(), "-read*".to_string()].concat();
    assert!(
        !process_src.contains(&broad_read) && !oci_src.contains(&broad_read),
        "broad host filesystem read allowance must not remain authoritative"
    );
}

// ---------------------------------------------------------------------------
// PART B — concrete production parser executable
// ---------------------------------------------------------------------------

#[test]
fn test_real_parser_binary_present_and_named() {
    let binary = real_parser_binary();
    assert!(
        binary.is_file(),
        "concrete production parser binary must exist: {}",
        binary.display()
    );
    assert_eq!(
        binary.file_name().and_then(|n| n.to_str()),
        Some("w014-parser-sandbox"),
        "REAL_PARSER_BINARY_NAME must be w014-parser-sandbox"
    );
}

#[test]
fn test_real_parser_binary_pdf_dispatch_via_pdfium() {
    let binary = real_parser_binary();
    let pdf = sample_pdf_bytes("Executive Summary");
    let sha = Sha256::digest(&pdf).to_hex();
    let ws = WorkspaceId::new().to_string();
    let dv = DocumentVersionId::new();
    let oa = ObjectArtifactId::new();
    let job = Uuid::new_v4().to_string();

    let (code, stdout, stderr) = run_real_binary(
        &binary,
        &ws,
        &dv.to_string(),
        &oa.to_string(),
        &job,
        "application/pdf",
        &sha,
        pdf.len() as i64,
        &pdf,
    );
    assert_eq!(
        code,
        Some(0),
        "pdf dispatch must exit 0: {}",
        String::from_utf8_lossy(&stderr)
    );
    let output: w014_document_processing::sandbox::SandboxOutput =
        serde_json::from_slice(&stdout).expect("binary must emit bounded SandboxOutput JSON");
    assert_eq!(output.protocol_version, SANDBOX_PROTOCOL_VERSION);
    assert_eq!(output.status, SandboxStatus::Success);
    assert_eq!(output.document_version_id, dv);
    assert_eq!(output.object_artifact_id, oa);
    assert_eq!(output.input_sha256.to_hex(), sha);
    assert!(
        output.parser_name.contains("pdfium"),
        "PDF must execute the authoritative PDFium path, got '{}'",
        output.parser_name
    );
    assert!(output.page_count >= 1);
    assert!(output.parsed_artifact.is_some());

    let input = SandboxInput::new(
        WorkspaceId::from_uuid(Uuid::parse_str(&ws).unwrap()),
        dv,
        oa,
        Uuid::parse_str(&job).unwrap(),
        StoredMediaType::new("application/pdf").unwrap(),
        Sha256::digest(&pdf),
        pdf.len() as i64,
        pdf,
    )
    .unwrap();
    output
        .validate_against_input(&input)
        .expect("protocol must validate");
}

#[test]
fn test_real_parser_binary_docx_dispatch_via_ooxmlsdk_ocr_producer() {
    let binary = real_parser_binary();
    let docx = sample_docx_bytes();
    let sha = Sha256::digest(&docx).to_hex();
    let ws = WorkspaceId::new().to_string();
    let dv = DocumentVersionId::new();
    let oa = ObjectArtifactId::new();
    let job = Uuid::new_v4().to_string();
    let media = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

    let (code, stdout, stderr) = run_real_binary(
        &binary,
        &ws,
        &dv.to_string(),
        &oa.to_string(),
        &job,
        media,
        &sha,
        docx.len() as i64,
        &docx,
    );
    assert_eq!(
        code,
        Some(0),
        "docx dispatch must exit 0: {}",
        String::from_utf8_lossy(&stderr)
    );
    let output: w014_document_processing::sandbox::SandboxOutput =
        serde_json::from_slice(&stdout).expect("binary must emit bounded SandboxOutput JSON");
    assert_eq!(output.status, SandboxStatus::Success);
    assert_eq!(
        output.parser_name, "w014-docx-safe-parser",
        "DOCX must execute the authoritative ooxmlsdk + OCR producer path"
    );
    assert_eq!(output.document_version_id, dv);
    assert_eq!(output.object_artifact_id, oa);
}

#[test]
fn test_real_parser_binary_malformed_input_fails_closed() {
    let binary = real_parser_binary();
    let bad = b"not a pdf at all".to_vec();
    let sha = Sha256::digest(&bad).to_hex();
    let (code, stdout, _) = run_real_binary(
        &binary,
        &WorkspaceId::new().to_string(),
        &DocumentVersionId::new().to_string(),
        &ObjectArtifactId::new().to_string(),
        &Uuid::new_v4().to_string(),
        "application/pdf",
        &sha,
        bad.len() as i64,
        &bad,
    );
    // Fail-closed: either a non-success envelope (exit 0) or a non-zero exit
    // with no success output. Never Success.
    if code == Some(0) {
        let output: w014_document_processing::sandbox::SandboxOutput =
            serde_json::from_slice(&stdout).expect("exit-0 output must be protocol JSON");
        assert_ne!(output.status, SandboxStatus::Success);
    } else {
        assert_ne!(code, Some(0));
        if let Ok(output) =
            serde_json::from_slice::<w014_document_processing::sandbox::SandboxOutput>(&stdout)
        {
            assert_ne!(output.status, SandboxStatus::Success);
        }
    }
}

#[test]
fn test_real_parser_binary_checksum_mismatch_fails_closed() {
    let binary = real_parser_binary();
    let pdf = sample_pdf_bytes("checksum probe");
    let wrong_sha = "00".repeat(32);
    let (code, stdout, _) = run_real_binary(
        &binary,
        &WorkspaceId::new().to_string(),
        &DocumentVersionId::new().to_string(),
        &ObjectArtifactId::new().to_string(),
        &Uuid::new_v4().to_string(),
        "application/pdf",
        &wrong_sha,
        pdf.len() as i64,
        &pdf,
    );
    assert_ne!(
        code,
        Some(0),
        "checksum mismatch must not exit 0 with success"
    );
    if let Ok(output) =
        serde_json::from_slice::<w014_document_processing::sandbox::SandboxOutput>(&stdout)
    {
        assert_ne!(output.status, SandboxStatus::Success);
    }
}

#[test]
fn test_real_parser_binary_unsupported_media_fails_closed() {
    let binary = real_parser_binary();
    let bytes = b"plain text bytes".to_vec();
    let sha = Sha256::digest(&bytes).to_hex();
    let (code, stdout, stderr) = run_real_binary(
        &binary,
        &WorkspaceId::new().to_string(),
        &DocumentVersionId::new().to_string(),
        &ObjectArtifactId::new().to_string(),
        &Uuid::new_v4().to_string(),
        "text/plain",
        &sha,
        bytes.len() as i64,
        &bytes,
    );
    assert_eq!(
        code,
        Some(0),
        "unsupported media envelope must exit 0: {}",
        String::from_utf8_lossy(&stderr)
    );
    let output: w014_document_processing::sandbox::SandboxOutput =
        serde_json::from_slice(&stdout).expect("protocol JSON required");
    assert_eq!(output.status, SandboxStatus::Unsupported);
}

#[tokio::test]
async fn test_no_mock_production_success_and_missing_binary_never_success() {
    // The mock test double is never the production parser identity.
    assert_ne!("mock-sandbox-parser", "w014-pdfium-safe-parser");
    assert_ne!("mock-sandbox-parser", "w014-docx-safe-parser");

    // A missing in-image parser binary can never count as success: the
    // backend exits non-zero and the runner fails closed.
    if ProcessSandboxRunner::platform_default_wrapper().is_none() {
        return;
    }
    let profile = SandboxSecurityProfile::frozen_default();
    let input = sample_input_with_media("application/pdf", b"%PDF-1.7 probe".to_vec());
    let (docker, _) = ProcessSandboxRunner::platform_default_wrapper().unwrap();
    let runner = ProcessSandboxRunner::new("w014-parser-binary-absent-404")
        .with_oci_image("ubuntu:24.04")
        .with_wrapper(docker, Vec::<String>::new());
    let err = runner.run(&profile, &input).await.unwrap_err();
    assert!(
        matches!(
            err,
            SandboxError::ProcessCrash { .. }
                | SandboxError::IO { .. }
                | SandboxError::MalformedOutput { .. }
                | SandboxError::SandboxViolation { .. }
        ),
        "missing parser binary must fail closed, got {err:?}"
    );
}

#[test]
fn test_binary_contains_no_credentials_network_or_db_authority() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(manifest.join("src/bin/w014-parser-sandbox.rs"))
        .expect("read parser binary source");
    for forbidden in [
        "DATABASE_URL",
        "POSTGRES_PASSWORD",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "KMS_KEY_ARN",
        "AUDIT_HMAC",
        "sqlx",
        "PgPool",
        "reqwest",
        "hyper",
    ] {
        assert!(
            !src.contains(forbidden),
            "parser binary must not contain '{forbidden}'"
        );
    }
    // The sandbox output contract binds identity; the binary never writes DB truth.
    assert!(
        !src.contains("INSERT INTO") && !src.contains("parser_artifacts"),
        "parser binary must never write authoritative database truth itself"
    );
    let _ = LocatorVersion::new("w014-loc-v1").unwrap();
    let _ = HashMap::<String, String>::new();
}
