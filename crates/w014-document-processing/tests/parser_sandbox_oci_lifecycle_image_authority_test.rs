//! E1 sandbox OCI lifecycle + image authority tests (WI0205 blockers).
//!
//! Proves the two confirmed W2 repairs:
//! - DEFECT A: ONE authoritative global wall-clock deadline covers the complete
//!   execution lifecycle (OCI launch, stdin handoff, stdout/stderr drain,
//!   container execution, backend wait, abort processing); the stdin writer is
//!   always joined inside that deadline and can never extend execution past it.
//! - DEFECT B: the ACTUAL OCI container carries a W014-generated identity and
//!   is deterministically terminated (`docker rm -f <name>`, bounded) on every
//!   abort; unestablished termination fails closed.
//! - DEFECT C: production Docker invocation uses `--pull=never` with a local
//!   image preflight (`w014-parser-sandbox:local` existence + revision and
//!   identity labels); missing images fail closed without any registry pull.
//!
//! Hermetic fake-`docker` backends prove argument/preflight/failure semantics
//! without a daemon; live Docker tests provide ACTUAL OCI lifecycle evidence
//! for container-termination claims wherever the daemon is available.

use std::path::{Path, PathBuf};
use std::time::Duration;

use uuid::Uuid;
use w014_document_processing::sandbox::{
    ProcessSandboxRunner, SandboxError, SandboxInput, SandboxRunner, SandboxSecurityProfile,
    expected_image_revision, is_valid_container_name, preflight_local_image,
};
use w014_domain::Sha256;
use w014_domain::StoredMediaType;
use w014_domain::ids::{DocumentVersionId, ObjectArtifactId, WorkspaceId};

static ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn sample_input(media: &str, bytes: Vec<u8>) -> SandboxInput {
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
    .expect("valid sandbox input")
}

fn authoritative_labels_with_revision(revision: &str) -> String {
    serde_json::json!({
        "org.opencontainers.image.title": "w014-parser-sandbox",
        "org.opencontainers.image.revision": revision,
        "w014.parser.binary": "w014-parser-sandbox",
        "w014.pdfium.version": "pdfium-151.0.7881.0",
        "w014.pdfium.sha256": "6252fce3da45e7f0dc5b27f4d4e1a1456ca3f7734cdb04f927967df772127478",
        "w014.ooxmlsdk.version": "0.12.0"
    })
    .to_string()
}

/// Hermetic fake `docker` backend: an executable shell script literally named
/// `docker` (the only approved backend name) with baked behavior.
///
/// `inspect_body` runs for `image inspect` (emit labels JSON + exit 0, or
/// exit 1 for a missing image); `run_body` runs for `docker run`; `rm`
/// succeeds; bare `inspect` (container presence) reports absent (exit 1).
/// Every invocation argv line is appended to the baked log path.
struct FakeDocker {
    _dir: tempfile::TempDir,
    docker: PathBuf,
    log: PathBuf,
}

fn fake_docker(inspect_body: &str, run_body: &str) -> FakeDocker {
    let dir = tempfile::tempdir().expect("tempdir for fake docker");
    let docker = dir.path().join("docker");
    let log = dir.path().join("calls.log");
    let script = format!(
        "#!/bin/sh\nLOG=\"{}\"\nprintf '%s\\n' \"$*\" >> \"$LOG\"\nif [ \"$1\" = \"image\" ]; then\n{}\nfi\nif [ \"$1\" = \"run\" ]; then\n{}\nfi\nif [ \"$1\" = \"rm\" ]; then\nexit 0\nfi\nexit 1\n",
        log.display(),
        inspect_body,
        run_body
    );
    std::fs::write(&docker, script).expect("write fake docker");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake docker");
    }
    FakeDocker {
        _dir: dir,
        docker,
        log,
    }
}

fn fake_calls(fake: &FakeDocker) -> Vec<String> {
    let content = std::fs::read_to_string(&fake.log).unwrap_or_default();
    content.lines().map(str::to_string).collect()
}

fn runner_with_fake(fake: &FakeDocker, binary: &str) -> ProcessSandboxRunner {
    ProcessSandboxRunner::new(binary).with_wrapper(fake.docker.clone(), Vec::<String>::new())
}

fn live_docker_available() -> bool {
    if ProcessSandboxRunner::platform_default_wrapper().is_none() {
        return false;
    }
    std::process::Command::new("docker")
        .args(["image", "inspect", "ubuntu:24.04"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn live_authoritative_image_present() -> bool {
    std::process::Command::new("docker")
        .args(["image", "inspect", "w014-parser-sandbox:local"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn require_live(test_name: &str) -> bool {
    if live_docker_available() {
        return true;
    }
    eprintln!("SKIP {test_name}: live docker/ubuntu:24.04 absent (no actual-runtime evidence)");
    false
}

fn live_runner(binary: &str, image: &str, args: &[&str]) -> ProcessSandboxRunner {
    let (wrapper_bin, wrapper_args) =
        ProcessSandboxRunner::platform_default_wrapper().expect("live docker present");
    ProcessSandboxRunner::new(binary)
        .with_oci_image(image)
        .with_wrapper(wrapper_bin, wrapper_args)
        .with_args(args.iter().copied())
}

fn live_docker_binary() -> PathBuf {
    ProcessSandboxRunner::platform_default_wrapper()
        .expect("live docker present")
        .0
}

/// Polls until the named container is provably absent (inspect fails AND
/// `docker ps -a` no longer lists it), panicking while it may remain alive.
fn assert_container_absent(container_name: &str) {
    let docker = live_docker_binary();
    for _ in 0..60 {
        let inspect_absent = std::process::Command::new(&docker)
            .args(["inspect", container_name])
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true);
        let ps_list = std::process::Command::new(&docker)
            .args(["ps", "-aq", "--filter", &format!("name={container_name}")])
            .output();
        let ps_empty = ps_list
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().is_empty())
            .unwrap_or(true);
        if inspect_absent && ps_empty {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("ORPHAN_CONTAINER: '{container_name}' survives abort; termination not established");
}

// ---------------------------------------------------------------------------
// DEFECT C — argument + preflight authority (hermetic)
// ---------------------------------------------------------------------------

#[test]
fn test_docker_run_has_pull_never_and_generated_identity() {
    let fake = fake_docker("exit 0", "exit 0");
    let profile = SandboxSecurityProfile::frozen_default();
    let input = sample_input("application/pdf", b"%PDF-1.7 probe".to_vec());
    let runner = runner_with_fake(&fake, "w014-parser-sandbox");
    let (_, argv) = runner
        .build_oci_command(&profile, &input)
        .expect("frozen profile must build OCI policy");
    let joined = argv.join(" ");
    assert!(
        argv.iter().any(|a| a == "--pull=never"),
        "DOCKER_RUN_HAS_PULL_NEVER: production invocation must carry --pull=never: {joined}"
    );
    assert!(
        argv.iter().any(|a| a == "--rm"),
        "normal exit must preserve --rm: {joined}"
    );
    let name_pos = argv
        .iter()
        .position(|a| a == "--name")
        .expect("docker run must carry a W014-generated --name identity");
    let container_name = argv.get(name_pos + 1).expect("--name requires a value");
    assert!(
        container_name.starts_with("w014-parser-sandbox-"),
        "container identity must be W014-generated, got '{container_name}'"
    );
    assert!(
        is_valid_container_name(container_name),
        "container identity must be Docker-safe, got '{container_name}'"
    );
}

#[test]
fn test_container_identity_never_derives_from_input() {
    let fake = fake_docker("exit 0", "exit 0");
    let profile = SandboxSecurityProfile::frozen_default();
    let input = sample_input("application/pdf", b"%PDF-1.7 probe".to_vec());
    let runner = runner_with_fake(&fake, "w014-parser-sandbox");
    let name_of = |runner: &ProcessSandboxRunner| {
        let (_, argv) = runner.build_oci_command(&profile, &input).unwrap();
        let pos = argv.iter().position(|a| a == "--name").unwrap();
        argv[pos + 1].clone()
    };
    let first = name_of(&runner);
    let second = name_of(&runner);
    assert_ne!(
        first, second,
        "each execution must mint a fresh identity (no input-derived reuse)"
    );
    for name in [&first, &second] {
        assert!(is_valid_container_name(name));
        assert!(!name.contains(&input.job_id.to_string()));
        assert!(!name.contains(&input.workspace_id.to_string().replace('-', "")));
    }
}

#[test]
fn test_authoritative_image_with_wrong_binary_fails_closed() {
    let fake = fake_docker("exit 0", "exit 0");
    let profile = SandboxSecurityProfile::frozen_default();
    let input = sample_input("application/pdf", b"%PDF-1.7 probe".to_vec());
    let runner = runner_with_fake(&fake, "sh").with_oci_image("w014-parser-sandbox:local");
    match runner.build_oci_command(&profile, &input).unwrap_err() {
        SandboxError::SandboxViolation { violation_type, .. } => {
            assert_eq!(violation_type, "INVALID_PARSER_BINARY_IDENTITY")
        }
        other => panic!("expected INVALID_PARSER_BINARY_IDENTITY, got {other:?}"),
    }
}

#[tokio::test]
async fn test_missing_local_image_fails_closed_without_pull() {
    let _lock = ENV_MUTEX.lock().await;
    let fake = fake_docker("exit 1", "exit 0");
    let profile = SandboxSecurityProfile::frozen_default();
    let input = sample_input("application/pdf", b"%PDF-1.7 probe".to_vec());
    let runner = runner_with_fake(&fake, "w014-parser-sandbox");
    let err = runner.run(&profile, &input).await.unwrap_err();
    match err {
        SandboxError::SandboxViolation { violation_type, .. } => {
            assert_eq!(violation_type, "MISSING_LOCAL_IMAGE")
        }
        other => panic!("expected MISSING_LOCAL_IMAGE, got {other:?}"),
    }
    let calls = fake_calls(&fake);
    assert!(
        calls.iter().any(|c| c.starts_with("image inspect")),
        "preflight must inspect the local image first: {calls:?}"
    );
    assert!(
        !calls.iter().any(|c| c.split(' ').next() == Some("pull")),
        "REGISTRY_PULL_ON_MISSING_IMAGE must be impossible (no pull invocation): {calls:?}"
    );
    assert!(
        !calls.iter().any(|c| c.split(' ').next() == Some("run")),
        "missing image must fail before any container launch: {calls:?}"
    );
}

#[tokio::test]
async fn test_image_revision_match_preflight() {
    let _lock = ENV_MUTEX.lock().await;
    let labels = authoritative_labels_with_revision(&expected_image_revision());
    let fake = fake_docker(&format!("printf '%s' '{labels}'\nexit 0"), "exit 0");
    preflight_local_image(&fake.docker, "w014-parser-sandbox:local")
        .await
        .expect("IMAGE_REVISION_MATCH: authoritative labels must pass preflight");
}

#[tokio::test]
async fn test_image_revision_mismatch_fails_closed() {
    let _lock = ENV_MUTEX.lock().await;
    let labels = authoritative_labels_with_revision("ffffffffffffffffffffffffffffffffffffffff");
    let fake = fake_docker(&format!("printf '%s' '{labels}'\nexit 0"), "exit 0");
    match preflight_local_image(&fake.docker, "w014-parser-sandbox:local")
        .await
        .unwrap_err()
    {
        SandboxError::SandboxViolation { violation_type, .. } => {
            assert_eq!(violation_type, "IMAGE_REVISION_MISMATCH")
        }
        other => panic!("expected IMAGE_REVISION_MISMATCH, got {other:?}"),
    }
}

#[tokio::test]
async fn test_image_revision_label_missing_fails_closed() {
    let _lock = ENV_MUTEX.lock().await;
    let fake = fake_docker("printf '%s' '{}'\nexit 0", "exit 0");
    match preflight_local_image(&fake.docker, "w014-parser-sandbox:local")
        .await
        .unwrap_err()
    {
        SandboxError::SandboxViolation { violation_type, .. } => {
            assert_eq!(violation_type, "IMAGE_REVISION_LABEL_MISSING")
        }
        other => panic!("expected IMAGE_REVISION_LABEL_MISSING, got {other:?}"),
    }
}

#[tokio::test]
async fn test_image_wrong_parser_identity_fails_closed() {
    let _lock = ENV_MUTEX.lock().await;
    let mut value: serde_json::Value = serde_json::from_str(&authoritative_labels_with_revision(
        &expected_image_revision(),
    ))
    .unwrap();
    value["w014.parser.binary"] = serde_json::json!("evil-parser");
    let fake = fake_docker(&format!("printf '%s' '{value}'\nexit 0"), "exit 0");
    match preflight_local_image(&fake.docker, "w014-parser-sandbox:local")
        .await
        .unwrap_err()
    {
        SandboxError::SandboxViolation { violation_type, .. } => {
            assert_eq!(violation_type, "INVALID_PARSER_BINARY_IDENTITY")
        }
        other => panic!("expected INVALID_PARSER_BINARY_IDENTITY, got {other:?}"),
    }
}

#[tokio::test]
async fn test_image_wrong_pdfium_identity_fails_closed() {
    let _lock = ENV_MUTEX.lock().await;
    let mut value: serde_json::Value = serde_json::from_str(&authoritative_labels_with_revision(
        &expected_image_revision(),
    ))
    .unwrap();
    value["w014.pdfium.sha256"] = serde_json::json!("00".repeat(32));
    let fake = fake_docker(&format!("printf '%s' '{value}'\nexit 0"), "exit 0");
    match preflight_local_image(&fake.docker, "w014-parser-sandbox:local")
        .await
        .unwrap_err()
    {
        SandboxError::SandboxViolation { violation_type, .. } => {
            assert_eq!(violation_type, "IMAGE_IDENTITY_MISMATCH")
        }
        other => panic!("expected IMAGE_IDENTITY_MISMATCH, got {other:?}"),
    }
}

#[tokio::test]
async fn test_server_revision_override_wins_over_default() {
    let _lock = ENV_MUTEX.lock().await;
    let custom = "custom-server-controlled-revision-1";
    let previous = std::env::var("W014_PARSER_SANDBOX_EXPECTED_REVISION").ok();
    unsafe {
        std::env::set_var("W014_PARSER_SANDBOX_EXPECTED_REVISION", custom);
    }
    let observed = expected_image_revision();
    if let Some(prev) = previous {
        unsafe {
            std::env::set_var("W014_PARSER_SANDBOX_EXPECTED_REVISION", prev);
        }
    } else {
        unsafe {
            std::env::remove_var("W014_PARSER_SANDBOX_EXPECTED_REVISION");
        }
    }
    assert_eq!(
        observed, custom,
        "server environment selector must override the compiled default"
    );
}

// ---------------------------------------------------------------------------
// DEFECT A — writer bound by the single global deadline (hermetic)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_writer_is_bound_by_global_deadline() {
    let _lock = ENV_MUTEX.lock().await;
    // Fake backend never reads stdin and sleeps 30s: a writer awaited outside
    // the deadline would extend execution to ~30s. The 5s global deadline
    // (comfortably above helper-spawn latency under parallel load, far below
    // the 30s sleep) must bound the complete lifecycle instead.
    let labels = authoritative_labels_with_revision(&expected_image_revision());
    let fake = fake_docker(
        &format!("printf '%s' '{labels}'\nexit 0"),
        "sleep 30\nexit 0",
    );
    let big_input = vec![0x41u8; 2 * 1024 * 1024];
    let input = sample_input("application/pdf", big_input);
    let mut profile = SandboxSecurityProfile::frozen_default();
    profile.ceilings.max_wall_clock_seconds = 5;
    let runner = runner_with_fake(&fake, "w014-parser-sandbox");
    let start = std::time::Instant::now();
    let err = runner.run(&profile, &input).await.unwrap_err();
    let elapsed = start.elapsed();
    assert!(
        matches!(err, SandboxError::Timeout { .. }),
        "WRITER_IS_BOUND_BY_GLOBAL_DEADLINE: expected Timeout, got {err:?}"
    );
    assert!(
        elapsed.as_secs() < 20,
        "blocked writer must not extend execution past the deadline (elapsed {elapsed:?})"
    );
    let calls = fake_calls(&fake);
    assert!(
        calls.iter().any(|c| c.split(' ').next() == Some("rm")),
        "timeout must terminate the actual container via rm: {calls:?}"
    );
}

// ---------------------------------------------------------------------------
// DEFECTS A+B — actual OCI lifecycle evidence (live Docker)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_global_timeout_terminates_actual_container() {
    if !require_live("global_timeout_terminates_actual_container") {
        return;
    }
    let input = sample_input("application/pdf", b"%PDF-1.7 probe".to_vec());
    let mut profile = SandboxSecurityProfile::frozen_default();
    profile.ceilings.max_wall_clock_seconds = 2;
    let runner = live_runner("sh", "ubuntu:24.04", &["-c", "sleep 30"]);
    let start = std::time::Instant::now();
    let err = runner.run(&profile, &input).await.unwrap_err();
    let elapsed = start.elapsed();
    assert!(
        matches!(err, SandboxError::Timeout { .. }),
        "GLOBAL_TIMEOUT must surface Timeout, got {err:?}"
    );
    assert!(
        elapsed.as_secs() < 30,
        "global deadline must bound execution (elapsed {elapsed:?})"
    );
    let name = runner
        .last_container_name()
        .expect("W014-generated identity must be recorded");
    assert_container_absent(&name);
}

#[tokio::test]
async fn test_global_timeout_leaves_no_container() {
    if !require_live("global_timeout_leaves_no_container") {
        return;
    }
    let input = sample_input("application/pdf", b"%PDF-1.7 probe".to_vec());
    let mut profile = SandboxSecurityProfile::frozen_default();
    profile.ceilings.max_wall_clock_seconds = 2;
    let runner = live_runner("sh", "ubuntu:24.04", &["-c", "sleep 30"]);
    let err = runner.run(&profile, &input).await.unwrap_err();
    assert!(
        matches!(err, SandboxError::Timeout { .. }),
        "expected Timeout, got {err:?}"
    );
    let name = runner.last_container_name().expect("identity recorded");
    let docker = live_docker_binary();
    let mut listed = String::new();
    for _ in 0..60 {
        let out = std::process::Command::new(&docker)
            .args(["ps", "-a", "--filter", &format!("name={name}")])
            .output()
            .expect("docker ps");
        listed = String::from_utf8_lossy(&out.stdout).to_string();
        if listed.lines().count() <= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(
        listed.lines().count(),
        1,
        "GLOBAL_TIMEOUT_LEAVES_NO_CONTAINER: container must be reaped/removed, docker ps shows:\n{listed}"
    );
}

#[tokio::test]
async fn test_stdout_overflow_terminates_actual_container() {
    if !require_live("stdout_overflow_terminates_actual_container") {
        return;
    }
    let input = sample_input("application/pdf", b"%PDF-1.7 probe".to_vec());
    let mut profile = SandboxSecurityProfile::frozen_default();
    profile.ceilings.max_output_bytes = 4096;
    let runner = live_runner(
        "sh",
        "ubuntu:24.04",
        &["-c", "head -c 102400 /dev/zero | tr '\\000' 'A'"],
    );
    let err = runner.run(&profile, &input).await.unwrap_err();
    match err {
        SandboxError::ResourceViolation { resource, .. } => {
            assert_eq!(resource, "stdout_output_bytes")
        }
        other => panic!("expected stdout ResourceViolation, got {other:?}"),
    }
    let name = runner.last_container_name().expect("identity recorded");
    assert_container_absent(&name);
}

#[tokio::test]
async fn test_stderr_overflow_terminates_actual_container() {
    if !require_live("stderr_overflow_terminates_actual_container") {
        return;
    }
    let input = sample_input("application/pdf", b"%PDF-1.7 probe".to_vec());
    let mut profile = SandboxSecurityProfile::frozen_default();
    profile.ceilings.max_output_bytes = 4096;
    let runner = live_runner(
        "sh",
        "ubuntu:24.04",
        &["-c", "head -c 102400 /dev/zero | tr '\\000' 'E' >&2"],
    );
    let err = runner.run(&profile, &input).await.unwrap_err();
    match err {
        SandboxError::ResourceViolation { resource, .. } => {
            assert_eq!(resource, "stderr_output_bytes")
        }
        other => panic!("expected stderr ResourceViolation, got {other:?}"),
    }
    let name = runner.last_container_name().expect("identity recorded");
    assert_container_absent(&name);
}

#[tokio::test]
async fn test_stdin_writer_failure_terminates_container_without_pull() {
    let _lock = ENV_MUTEX.lock().await;
    // Fake backend exits immediately without draining stdin; 8 MiB can never
    // fit the pipe buffer, so the writer deterministically fails (broken
    // pipe) and the abort path must still terminate the container identity.
    let labels = authoritative_labels_with_revision(&expected_image_revision());
    let fake = fake_docker(&format!("printf '%s' '{labels}'\nexit 0"), "exit 0");
    let big_input = vec![0x25u8; 8 * 1024 * 1024];
    let input = sample_input("application/pdf", big_input);
    let profile = SandboxSecurityProfile::frozen_default();
    let runner = runner_with_fake(&fake, "w014-parser-sandbox");
    let err = runner.run(&profile, &input).await.unwrap_err();
    match err {
        SandboxError::IO { detail } => assert!(
            detail.contains("stdin"),
            "writer failure must be reported, got '{detail}'"
        ),
        other => panic!("expected IO writer failure, got {other:?}"),
    }
    let calls = fake_calls(&fake);
    assert!(
        calls.iter().any(|c| c.split(' ').next() == Some("rm")),
        "writer failure must terminate the actual container via rm: {calls:?}"
    );
    assert!(
        !calls.iter().any(|c| c.split(' ').next() == Some("pull")),
        "no registry pull may occur on any abort path: {calls:?}"
    );
}

#[tokio::test]
async fn test_stream_failure_terminates_actual_container() {
    if !require_live("stream_failure_terminates_actual_container") {
        return;
    }
    // True orphan scenario: SIGKILL the `docker run` CLIENT while the actual
    // container (`sleep 30`) keeps running with 128 MiB of stdin in flight.
    // Killing only the client is insufficient by design; the abort path must
    // still terminate the ACTUAL container via `docker rm -f <name>`.
    let big_input = vec![0x25u8; 128 * 1024 * 1024];
    let input = sample_input("application/pdf", big_input);
    let mut profile = SandboxSecurityProfile::frozen_default();
    profile.ceilings.max_wall_clock_seconds = 30;
    let runner = live_runner("sh", "ubuntu:24.04", &["-c", "sleep 30"]);
    let killer_runner = runner.clone();
    let killer = tokio::spawn(async move {
        let name = loop {
            if let Some(name) = killer_runner.last_container_name() {
                break name;
            }
            tokio::task::yield_now().await;
        };
        // Let execution (and the 128 MiB handoff) get going, then orphan the
        // container by SIGKILLing the client. 128 MiB cannot complete first.
        tokio::time::sleep(Duration::from_millis(300)).await;
        for _ in 0..100 {
            let pids = std::process::Command::new("pgrep")
                .args(["-f", &name])
                .output()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .split_whitespace()
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !pids.is_empty() {
                for pid in &pids {
                    let _ = std::process::Command::new("kill")
                        .args(["-9", pid])
                        .output();
                }
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    });
    let start = std::time::Instant::now();
    let err = runner.run(&profile, &input).await.unwrap_err();
    let elapsed = start.elapsed();
    let killed = tokio::time::timeout(Duration::from_secs(15), killer)
        .await
        .expect("killer task must finish")
        .expect("killer task must not panic");
    assert!(
        killed,
        "killer must have SIGKILLed the docker client to create the orphan"
    );
    assert!(
        matches!(err, SandboxError::IO { .. }),
        "STREAM_FAILURE must surface fail-closed IO, got {err:?}"
    );
    assert!(
        elapsed.as_secs() < 30,
        "orphan abort must resolve via the deadline machinery (elapsed {elapsed:?})"
    );
    let name = runner.last_container_name().expect("identity recorded");
    assert_container_absent(&name);
}

#[tokio::test]
async fn test_docker_client_reaped_after_timeout() {
    if !require_live("docker_client_reaped_after_timeout") {
        return;
    }
    let input = sample_input("application/pdf", b"%PDF-1.7 probe".to_vec());
    let mut profile = SandboxSecurityProfile::frozen_default();
    profile.ceilings.max_wall_clock_seconds = 2;
    let runner = live_runner("sh", "ubuntu:24.04", &["-c", "sleep 30"]);
    let err = runner.run(&profile, &input).await.unwrap_err();
    assert!(
        matches!(err, SandboxError::Timeout { .. }),
        "expected Timeout, got {err:?}"
    );
    let name = runner.last_container_name().expect("identity recorded");
    let out = std::process::Command::new("pgrep")
        .args(["-f", &name])
        .output()
        .expect("pgrep must run");
    assert!(
        !out.status.success(),
        "DOCKER_CLIENT_REAPED: no live process may reference '{name}' after return"
    );
    assert_container_absent(&name);
}

#[tokio::test]
async fn test_live_authoritative_image_revision_match() {
    let _lock = ENV_MUTEX.lock().await;
    if !require_live("live_authoritative_image_revision_match") {
        return;
    }
    if !live_authoritative_image_present() {
        eprintln!("SKIP live_authoritative_image_revision_match: w014-parser-sandbox:local absent");
        return;
    }
    let docker = live_docker_binary();
    preflight_local_image(&docker, "w014-parser-sandbox:local")
        .await
        .expect("IMAGE_REVISION_MATCH: live authoritative image must pass preflight");
}

// ---------------------------------------------------------------------------
// Shared preservation — no host fallback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_no_host_fallback() {
    // Async-aware mutex may be held across `.await`; no other test in this
    // binary touches this selector.
    let _lock = ENV_MUTEX.lock().await;
    let previous = std::env::var("W014_PARSER_SANDBOX_WRAPPER_BIN").ok();
    unsafe {
        std::env::remove_var("W014_PARSER_SANDBOX_WRAPPER_BIN");
    }
    let profile = SandboxSecurityProfile::frozen_default();
    let input = sample_input("application/pdf", b"%PDF-1.7 probe".to_vec());

    let bare = ProcessSandboxRunner::new("w014-parser-sandbox");
    let bare_result = bare.run(&profile, &input).await.unwrap_err();
    let unapproved_result = if Path::new("/bin/sh").is_file() {
        let runner = ProcessSandboxRunner::new("w014-parser-sandbox")
            .with_wrapper("/bin/sh", Vec::<String>::new());
        Some(runner.run(&profile, &input).await.unwrap_err())
    } else {
        None
    };

    if let Some(prev) = previous {
        unsafe {
            std::env::set_var("W014_PARSER_SANDBOX_WRAPPER_BIN", prev);
        }
    } else {
        unsafe {
            std::env::remove_var("W014_PARSER_SANDBOX_WRAPPER_BIN");
        }
    }

    match bare_result {
        SandboxError::SandboxViolation { violation_type, .. } => {
            assert_eq!(violation_type, "MISSING_ISOLATION_WRAPPER");
        }
        other => panic!("NO_HOST_FALLBACK: expected MISSING_ISOLATION_WRAPPER, got {other:?}"),
    }

    if let Some(err) = unapproved_result {
        match err {
            SandboxError::SandboxViolation { violation_type, .. } => {
                assert_eq!(violation_type, "UNAPPROVED_ISOLATION_BACKEND");
            }
            other => {
                panic!("NO_HOST_FALLBACK: expected UNAPPROVED_ISOLATION_BACKEND, got {other:?}")
            }
        }
    }
}
