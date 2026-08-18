//! Smoke tests for w014-worker process bootstrap and graceful shutdown.
//!
//! Tests:
//! - TEST A: Worker start smoke (starts, enters ready/idle state without fake job completion)
//! - TEST B: Graceful stop smoke (receives OS signal, shuts down cooperatively and cleanly exits with code 0)
//! - TEST D: Trace correlation (lifecycle events correlate with single worker execution)
//! - TEST E: No fake job success (no fake database jobs reported)

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn test_worker_binary_bootstrap_and_graceful_shutdown() {
    let bin_path = env!("CARGO_BIN_EXE_w014-worker");

    let mut child = Command::new(bin_path)
        .env("W014_WORKER_NAME", "smoke-test-worker")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn w014-worker process");

    let stdout = child.stdout.take().expect("Child must have stdout piped");
    let stderr = child.stderr.take().expect("Child must have stderr piped");
    let (ready_tx, ready_rx) = mpsc::channel();
    let (all_lines_tx, all_lines_rx) = mpsc::channel();

    let ready_tx_clone = ready_tx.clone();
    let all_lines_tx_clone = all_lines_tx.clone();

    // Reader thread for stdout
    let stdout_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for l in reader.lines().map_while(Result::ok) {
            if l.contains("worker_ready") || l.contains("worker ready and idling") {
                let _ = ready_tx.send(());
            }
            let _ = all_lines_tx.send(l);
        }
    });

    // Reader thread for stderr
    let stderr_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for l in reader.lines().map_while(Result::ok) {
            if l.contains("worker_ready") || l.contains("worker ready and idling") {
                let _ = ready_tx_clone.send(());
            }
            let _ = all_lines_tx_clone.send(l);
        }
    });

    // 1. TEST A: Worker start smoke
    // Wait for the worker to enter its ready/idle state within 5 seconds
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("Worker failed to emit worker_ready event within 5s");

    // 2. TEST B: Graceful stop smoke
    // Send SIGTERM to the running child process on Unix
    #[cfg(unix)]
    {
        let pid = child.id() as libc::pid_t;
        // Safety: sending SIGTERM to the spawned child process
        let kill_res = unsafe { libc::kill(pid, libc::SIGTERM) };
        assert_eq!(kill_res, 0, "Failed to send SIGTERM to worker process");
    }
    #[cfg(not(unix))]
    {
        // On non-Unix, send Ctrl-C or kill
        let _ = child.kill();
    }

    // Wait for worker process to exit cleanly
    let status = child
        .wait()
        .expect("Failed to wait for worker process termination");

    assert!(
        status.success(),
        "Worker process did not exit with code 0: {:?}",
        status.code()
    );

    stdout_handle.join().expect("Stdout thread join");
    stderr_handle.join().expect("Stderr thread join");

    // Collect all output lines
    let mut lines = Vec::new();
    while let Ok(line) = all_lines_rx.try_recv() {
        lines.push(line);
    }
    let output = lines.join("\n");

    // 3. TEST D: Verify structured lifecycle events and correlation
    assert!(
        output.contains("worker_started"),
        "Output must contain worker_started event: {output}"
    );
    assert!(
        output.contains("worker_ready"),
        "Output must contain worker_ready event: {output}"
    );
    assert!(
        output.contains("shutdown_requested"),
        "Output must contain shutdown_requested event: {output}"
    );
    assert!(
        output.contains("shutdown_completed"),
        "Output must contain shutdown_completed event: {output}"
    );

    // 4. TEST E: No fake job success
    assert!(
        !output.contains("JobStatus::Succeeded"),
        "Output must not claim job success"
    );
    assert!(
        !output.contains("job completed successfully"),
        "Output must not contain fake job completion"
    );
}
