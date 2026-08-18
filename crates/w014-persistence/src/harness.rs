//! Reusable W0 Fresh and Upgrade Migration Test Harness against PostgreSQL 18.

use serde::{Deserialize, Serialize};
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::str::FromStr;
use url::Url;

use crate::config::DatabaseConfig;
use crate::error::PersistenceError;
use crate::runner::{MigrationReport, MigrationRunner, MigrationStatus};

/// An isolated, uniquely named PostgreSQL test database.
///
/// Automatically creates a dedicated database upon initialization and
/// drops it with force upon teardown.
pub struct TestDatabase {
    db_name: String,
    admin_url: String,
    db_url: String,
    pool: PgPool,
}

impl TestDatabase {
    /// Creates a new isolated test database with a unique name against PostgreSQL.
    pub async fn new() -> Result<Self, PersistenceError> {
        let base_config = DatabaseConfig::from_env()?;
        let base_url = base_config.url.clone();

        // Parse base URL and connect to default maintenance database ("postgres" or configured DB)
        let mut parsed_url = Url::parse(&base_url)
            .map_err(|e| PersistenceError::Config(format!("Invalid base DATABASE_URL: {e}")))?;

        let admin_url = base_url.clone();
        let admin_opts = PgConnectOptions::from_str(&admin_url).map_err(|e| {
            PersistenceError::Config(format!("Failed to parse admin connect opts: {e}"))
        })?;

        let admin_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(admin_opts)
            .await
            .map_err(|e| {
                PersistenceError::TestDatabase(format!("Failed to connect admin pool: {e}"))
            })?;

        let unique_suffix = uuid::Uuid::new_v4().simple();
        let db_name = format!("w014_test_{unique_suffix}");

        // Create the isolated database
        let create_query = format!("CREATE DATABASE \"{db_name}\"");
        sqlx::query(sqlx::AssertSqlSafe(create_query))
            .execute(&admin_pool)
            .await
            .map_err(|e| {
                PersistenceError::TestDatabase(format!(
                    "Failed to create test database '{db_name}': {e}"
                ))
            })?;

        admin_pool.close().await;

        // Build target test database URL
        parsed_url.set_path(&format!("/{db_name}"));
        let db_url = parsed_url.to_string();

        let db_opts = PgConnectOptions::from_str(&db_url)
            .map_err(|e| PersistenceError::Config(format!("Failed to parse test db URL: {e}")))?;

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(db_opts)
            .await
            .map_err(|e| {
                PersistenceError::TestDatabase(format!(
                    "Failed to connect to test db '{db_name}': {e}"
                ))
            })?;

        Ok(Self {
            db_name,
            admin_url,
            db_url,
            pool,
        })
    }

    /// Returns a reference to the connection pool for this test database.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Returns the connection URL for this test database.
    pub fn url(&self) -> &str {
        &self.db_url
    }

    /// Returns the unique name of this test database.
    pub fn db_name(&self) -> &str {
        &self.db_name
    }

    /// Explicitly closes the test database pool and drops the database with force.
    pub async fn close(self) -> Result<(), PersistenceError> {
        self.pool.close().await;

        let admin_opts = PgConnectOptions::from_str(&self.admin_url).map_err(|e| {
            PersistenceError::Config(format!("Failed to parse admin connect opts: {e}"))
        })?;

        let admin_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(admin_opts)
            .await
            .map_err(|e| {
                PersistenceError::TestDatabase(format!(
                    "Failed to connect admin pool for drop: {e}"
                ))
            })?;

        let drop_query = format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", self.db_name);
        sqlx::query(sqlx::AssertSqlSafe(drop_query))
            .execute(&admin_pool)
            .await
            .map_err(|e| {
                PersistenceError::TestDatabase(format!(
                    "Failed to drop test database '{}': {e}",
                    self.db_name
                ))
            })?;

        admin_pool.close().await;
        Ok(())
    }
}

/// Comprehensive outcome of running the fresh migration test harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshHarnessResult {
    /// State of the database before any migrations are applied.
    pub initial_status: MigrationStatus,
    /// Report from the first migration application.
    pub first_run_report: MigrationReport,
    /// Status after the first migration application.
    pub post_migration_status: MigrationStatus,
    /// Report from the second migration run (verifying repeat-run safety and idempotency).
    pub repeat_run_report: MigrationReport,
    /// Final status after the repeat run.
    pub final_status: MigrationStatus,
}

/// Comprehensive outcome of running the upgrade migration test harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeHarnessResult {
    /// Report from applying the baseline / earlier migration bundle.
    pub initial_migration_report: MigrationReport,
    /// Status after applying the initial baseline bundle.
    pub intermediate_status: MigrationStatus,
    /// Report from applying the target / upgrade migration bundle.
    pub upgrade_migration_report: MigrationReport,
    /// Status after applying the upgrade bundle.
    pub final_status: MigrationStatus,
    /// Report from repeating the upgrade run (verifying idempotency).
    pub repeat_upgrade_report: MigrationReport,
}

/// Executes the W0 Fresh-Migration Harness against a real PostgreSQL 18 database.
///
/// Proves:
/// 1. Clean test database verification (0 applied migrations).
/// 2. Invocation of the authoritative SQLx runner.
/// 3. Migrations complete successfully.
/// 4. SQLx migration-history state is inspectable and recorded.
/// 5. A second execution is safe/current rather than duplicating migration effects.
/// 6. Final state matches expectations.
pub async fn run_fresh_migration_harness(
    pool: &PgPool,
    migrator: &Migrator,
) -> Result<FreshHarnessResult, PersistenceError> {
    let runner = MigrationRunner::new(migrator);

    // 1. Inspect initial state (should be clean / unmigrated)
    let initial_status = runner.status(pool).await?;

    // 2. Execute first migration run
    let first_run_report = runner.run(pool).await?;

    // 3. Inspect post-migration status
    let post_migration_status = runner.status(pool).await?;

    // 4. Execute repeat run to prove idempotency
    let repeat_run_report = runner.run(pool).await?;

    // 5. Inspect final status
    let final_status = runner.status(pool).await?;

    Ok(FreshHarnessResult {
        initial_status,
        first_run_report,
        post_migration_status,
        repeat_run_report,
        final_status,
    })
}

/// Executes the W0 Upgrade-Migration Harness against a real PostgreSQL 18 database.
///
/// Proves:
/// 1. Applies baseline / earlier migration bundle to clean database.
/// 2. Verifies intermediate migration state.
/// 3. Applies upgraded / forward migration bundle without manual DB repair.
/// 4. Verifies all migrations from target bundle are recorded as successful.
/// 5. Verifies repeat execution of the upgrade bundle is idempotent.
pub async fn run_upgrade_migration_harness(
    pool: &PgPool,
    initial_migrator: &Migrator,
    target_migrator: &Migrator,
) -> Result<UpgradeHarnessResult, PersistenceError> {
    let initial_runner = MigrationRunner::new(initial_migrator);
    let target_runner = MigrationRunner::new(target_migrator);

    // 1. Run baseline migrations
    let initial_migration_report = initial_runner.run(pool).await?;
    let intermediate_status = initial_runner.status(pool).await?;

    // 2. Run target / upgrade migrations
    let upgrade_migration_report = target_runner.run(pool).await?;
    let final_status = target_runner.status(pool).await?;

    // 3. Repeat upgrade run to verify idempotency
    let repeat_upgrade_report = target_runner.run(pool).await?;

    Ok(UpgradeHarnessResult {
        initial_migration_report,
        intermediate_status,
        upgrade_migration_report,
        final_status,
        repeat_upgrade_report,
    })
}

/// Executes a migration that is expected to fail and asserts that the failure is propagated.
pub async fn run_failing_migration_harness(
    pool: &PgPool,
    failing_migrator: &Migrator,
) -> Result<sqlx::migrate::MigrateError, PersistenceError> {
    let runner = MigrationRunner::new(failing_migrator);
    match runner.run(pool).await {
        Ok(report) => Err(PersistenceError::Operation(format!(
            "Expected migration to fail, but it succeeded with report: {report:?}"
        ))),
        Err(PersistenceError::Migration(migrate_err)) => Ok(migrate_err),
        Err(other) => Err(other),
    }
}
