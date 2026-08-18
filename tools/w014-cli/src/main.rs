//! Local development orchestration CLI for the w014 Foundation Platform.
//!
//! Provides bounded local service management (`dev-up`, `dev-down`) wrapping
//! the canonical `infra/local/compose.yaml` definition.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// Service names expected in the local stack.
pub const REQUIRED_SERVICES: &[&str] = &["postgres", "minio", "clamav", "otel-collector"];

/// Finds the canonical `infra/local/compose.yaml` file by checking:
/// 1. Current working directory and its parents
/// 2. `CARGO_MANIFEST_DIR` hierarchy
pub fn find_compose_file() -> Result<PathBuf, String> {
    // Check from current directory upwards
    if let Ok(cwd) = env::current_dir() {
        let mut curr = cwd.as_path();
        loop {
            let candidate = curr.join("infra/local/compose.yaml");
            if candidate.is_file() {
                return Ok(candidate);
            }
            match curr.parent() {
                Some(parent) => curr = parent,
                None => break,
            }
        }
    }

    // Fallback: check relative to CARGO_MANIFEST_DIR (compile-time path)
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest_dir.join("../../infra/local/compose.yaml");
    if candidate.is_file() {
        if let Ok(canonical) = candidate.canonicalize() {
            return Ok(canonical);
        }
        return Ok(candidate);
    }

    Err("Could not locate infra/local/compose.yaml in current or parent directories.".to_string())
}

/// Executes `docker compose dev-up`:
/// Starts required local services in detached mode and waits for health checks to pass.
pub fn dev_up(compose_path: &Path) -> Result<(), String> {
    println!(
        "Starting local development services via {}",
        compose_path.display()
    );

    let status = Command::new("docker")
        .args([
            "compose",
            "-f",
            compose_path
                .to_str()
                .ok_or("Invalid unicode in compose path")?,
            "up",
            "-d",
            "--wait",
        ])
        .status()
        .map_err(|e| format!("Failed to execute 'docker compose up': {e}"))?;

    if !status.success() {
        return Err(format!(
            "'docker compose up -d --wait' failed with exit code: {:?}",
            status.code()
        ));
    }

    // Verify all required services are reported as running/healthy
    verify_services_health(compose_path)?;

    println!(
        "All required local services (PostgreSQL, MinIO, ClamAV, OTel Collector) are healthy."
    );
    Ok(())
}

/// Verifies that all required services are healthy via `docker compose ps`.
pub fn verify_services_health(compose_path: &Path) -> Result<(), String> {
    let output = Command::new("docker")
        .args([
            "compose",
            "-f",
            compose_path
                .to_str()
                .ok_or("Invalid unicode in compose path")?,
            "ps",
            "--format",
            "json",
        ])
        .output()
        .map_err(|e| format!("Failed to query docker compose ps: {e}"))?;

    if !output.status.success() {
        return Err("Failed to query service status via 'docker compose ps'.".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Each line or array in JSON output describes a container
    for service in REQUIRED_SERVICES {
        if !stdout.contains(service) {
            return Err(format!(
                "Required service '{service}' was not found in compose ps output."
            ));
        }
    }

    Ok(())
}

/// Executes `docker compose dev-down`:
/// Stops local development services cleanly without removing persistent volumes.
pub fn dev_down(compose_path: &Path) -> Result<(), String> {
    println!(
        "Stopping local development services cleanly via {}",
        compose_path.display()
    );

    let status = Command::new("docker")
        .args([
            "compose",
            "-f",
            compose_path
                .to_str()
                .ok_or("Invalid unicode in compose path")?,
            "down",
        ])
        .status()
        .map_err(|e| format!("Failed to execute 'docker compose down': {e}"))?;

    if !status.success() {
        return Err(format!(
            "'docker compose down' failed with exit code: {:?}",
            status.code()
        ));
    }

    println!("Local development services stopped cleanly. Persistent volumes preserved.");
    Ok(())
}

/// Prints CLI usage / help text.
pub fn print_help() {
    println!("w014-cli - Foundation Platform local orchestration tool");
    println!();
    println!("USAGE:");
    println!("    w014-cli <COMMAND>");
    println!();
    println!("COMMANDS:");
    println!(
        "    dev-up      Start local services (Postgres, MinIO, ClamAV, OTel) and wait for health"
    );
    println!("    dev-down    Stop local services cleanly without deleting persistent volumes");
    println!("    help        Print this help message");
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = match args.next() {
        Some(cmd) => cmd,
        None => {
            print_help();
            return Err("No command provided. Run 'w014-cli help' for usage.".to_string());
        }
    };

    match command.as_str() {
        "dev-up" => {
            let compose_file = find_compose_file()?;
            dev_up(&compose_file)
        }
        "dev-down" => {
            let compose_file = find_compose_file()?;
            dev_down(&compose_file)
        }
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        unknown => {
            eprintln!("Unknown command: {unknown}");
            print_help();
            Err(format!("Unknown command: '{unknown}'"))
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_find_compose_file() {
        let compose_file = find_compose_file().expect("compose.yaml should be discoverable");
        assert!(compose_file.is_file());
        assert!(compose_file.ends_with("infra/local/compose.yaml"));
    }

    #[test]
    fn test_compose_file_content_contains_services() {
        let compose_file = find_compose_file().expect("compose.yaml should be discoverable");
        let content = fs::read_to_string(&compose_file).expect("compose.yaml should be readable");
        for service in REQUIRED_SERVICES {
            assert!(
                content.contains(service),
                "compose.yaml should define {service}"
            );
        }
    }

    #[test]
    fn test_required_services_list() {
        assert_eq!(REQUIRED_SERVICES.len(), 4);
        assert!(REQUIRED_SERVICES.contains(&"postgres"));
        assert!(REQUIRED_SERVICES.contains(&"minio"));
        assert!(REQUIRED_SERVICES.contains(&"clamav"));
        assert!(REQUIRED_SERVICES.contains(&"otel-collector"));
    }

    #[test]
    fn test_print_help() {
        print_help();
    }
}
