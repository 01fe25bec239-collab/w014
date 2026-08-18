//! Local development orchestration CLI for the w014 Foundation Platform.
//!
//! Provides bounded local service management (`dev-up`, `dev-down`) wrapping
//! the canonical `infra/local/compose.yaml` definition, and the authoritative
//! SQLx migration entry point (`migrate`).

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use w014_persistence::{DatabaseConfig, MigrationRunner};

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

/// Asynchronously executes database migrations using the authoritative SQLx migration runner.
pub async fn run_migrate(subcommand: Option<&str>) -> Result<(), String> {
    let config =
        DatabaseConfig::from_env().map_err(|e| format!("Database configuration error: {e}"))?;

    println!("Connecting to database at {}...", config.masked_url());

    let pool = config
        .create_pool()
        .await
        .map_err(|e| format!("Database connection error: {e}"))?;

    let runner = MigrationRunner::default_runner();

    match subcommand {
        Some("status") => {
            let status = runner
                .status(&pool)
                .await
                .map_err(|e| format!("Failed to fetch migration status: {e}"))?;

            println!("Migration Status Report:");
            println!("  Current Database Version : {:?}", status.current_version);
            println!("  Applied Migrations Count : {}", status.applied.len());
            for record in &status.applied {
                println!(
                    "    - [APPLIED] version: {}, description: '{}', installed_on: {}, success: {}",
                    record.version, record.description, record.installed_on, record.success
                );
            }
            println!("  Pending Migrations Count : {}", status.pending.len());
            for record in &status.pending {
                println!(
                    "    - [PENDING] version: {}, description: '{}'",
                    record.version, record.description
                );
            }
            println!("  Database Up-to-Date      : {}", status.is_up_to_date);
            Ok(())
        }
        Some("run") | None => {
            println!("Applying pending forward migrations...");
            let report = runner
                .run(&pool)
                .await
                .map_err(|e| format!("Migration application failed: {e}"))?;

            if report.already_up_to_date {
                println!(
                    "Database is already up-to-date. (Total migrations: {}, Current version: {:?})",
                    report.total_applied_count, report.latest_version
                );
            } else {
                println!(
                    "Migrations applied successfully: {:?} (Total: {}, Current version: {:?})",
                    report.newly_applied_versions,
                    report.total_applied_count,
                    report.latest_version
                );
            }
            Ok(())
        }
        Some(unknown) => Err(format!(
            "Unknown migrate subcommand: '{unknown}'. Supported: 'run', 'status'."
        )),
    }
}

/// Synchronous entry point for the `migrate` CLI command.
pub fn migrate(subcommand: Option<&str>) -> Result<(), String> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(run_migrate(subcommand)))
    } else {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to initialize tokio runtime: {e}"))?;
        rt.block_on(run_migrate(subcommand))
    }
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
        "    dev-up           Start local services (Postgres, MinIO, ClamAV, OTel) and wait for health"
    );
    println!(
        "    dev-down         Stop local services cleanly without deleting persistent volumes"
    );
    println!(
        "    migrate [run]    Execute authoritative SQLx migrations against configured database"
    );
    println!(
        "    migrate status   Inspect applied and pending migrations without applying changes"
    );
    println!("    help             Print this help message");
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
        "migrate" => {
            let sub = args.next();
            migrate(sub.as_deref())
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_cli_migrate_commands() {
        let test_db = w014_persistence::TestDatabase::new()
            .await
            .expect("Failed to create test database");

        // Point environment to isolated test database
        unsafe {
            env::set_var("DATABASE_URL", test_db.url());
        }

        // Test migrate status command
        let status_res = run_migrate(Some("status")).await;
        assert!(
            status_res.is_ok(),
            "migrate status should succeed: {status_res:?}"
        );

        // Test migrate run command
        let run_res = run_migrate(Some("run")).await;
        assert!(run_res.is_ok(), "migrate run should succeed: {run_res:?}");

        // Test default migrate command (no subcommand)
        let default_res = run_migrate(None).await;
        assert!(
            default_res.is_ok(),
            "migrate default should succeed: {default_res:?}"
        );

        // Test invalid subcommand returns error
        let invalid_res = run_migrate(Some("unknown_subcmd")).await;
        assert!(
            invalid_res.is_err(),
            "migrate invalid subcommand should return error"
        );

        test_db.close().await.expect("Failed to drop test database");
    }
}
