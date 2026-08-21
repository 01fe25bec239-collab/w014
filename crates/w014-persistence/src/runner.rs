//! Authoritative SQLx migration runner and migration status inspection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
pub use sqlx::migrate::Migrator;
use sqlx::postgres::PgPool;
use std::collections::HashSet;

use crate::error::PersistenceError;

/// Compile-time embedded production migration bundle (M001R + M001R-F1 + M002R).
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Record of an applied migration stored in `_sqlx_migrations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedMigrationRecord {
    /// Numerical timestamp version of the migration.
    pub version: i64,
    /// Descriptive name of the migration.
    pub description: String,
    /// UTC timestamp when the migration was applied.
    pub installed_on: DateTime<Utc>,
    /// Whether the migration completed successfully.
    pub success: bool,
    /// SHA384/SHA256 checksum of the migration file contents.
    pub checksum: Vec<u8>,
    /// Execution time in nanoseconds.
    pub execution_time: i64,
}

/// Information about a migration defined in a `Migrator` but not yet applied to the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingMigrationRecord {
    /// Numerical timestamp version of the migration.
    pub version: i64,
    /// Descriptive name of the migration.
    pub description: String,
    /// Migration type (e.g., "ReversibleUp", "Simple").
    pub migration_type: String,
}

/// Full migration state report for a database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationStatus {
    /// The latest applied migration version in the database, if any.
    pub current_version: Option<i64>,
    /// Chronological list of all migrations recorded in `_sqlx_migrations`.
    pub applied: Vec<AppliedMigrationRecord>,
    /// List of migrations defined in the migrator that have not yet been applied.
    pub pending: Vec<PendingMigrationRecord>,
    /// Whether all known migrations in the migrator are applied and the database is up-to-date.
    pub is_up_to_date: bool,
}

/// Execution summary returned by `MigrationRunner::run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReport {
    /// Migration versions that were newly applied in this run.
    pub newly_applied_versions: Vec<i64>,
    /// Total count of applied migrations present in the database after the run.
    pub total_applied_count: usize,
    /// Latest migration version in the database after the run.
    pub latest_version: Option<i64>,
    /// Whether the database was already current prior to this run.
    pub already_up_to_date: bool,
}

/// Authoritative SQLx migration runner wrapping a `sqlx::migrate::Migrator`.
pub struct MigrationRunner<'a> {
    migrator: &'a Migrator,
}

impl<'a> MigrationRunner<'a> {
    /// Creates a runner with a specific `Migrator` reference.
    pub fn new(migrator: &'a Migrator) -> Self {
        Self { migrator }
    }

    /// Creates a runner using the authoritative default embedded production `MIGRATOR`.
    pub fn default_runner() -> MigrationRunner<'static> {
        MigrationRunner::new(&MIGRATOR)
    }

    /// Returns the underlying `Migrator` reference.
    pub fn migrator(&self) -> &Migrator {
        self.migrator
    }

    /// Queries the applied migrations directly from `_sqlx_migrations`.
    /// Returns an empty list if `_sqlx_migrations` does not exist yet.
    pub async fn fetch_applied_migrations(
        pool: &PgPool,
    ) -> Result<Vec<AppliedMigrationRecord>, PersistenceError> {
        let query = "SELECT version, description, installed_on, success, checksum, execution_time FROM _sqlx_migrations ORDER BY version ASC";
        match sqlx::query(query).fetch_all(pool).await {
            Ok(rows) => {
                let records = rows
                    .into_iter()
                    .map(|row| AppliedMigrationRecord {
                        version: row.get("version"),
                        description: row.get("description"),
                        installed_on: row.get("installed_on"),
                        success: row.get("success"),
                        checksum: row.get("checksum"),
                        execution_time: row.get("execution_time"),
                    })
                    .collect();
                Ok(records)
            }
            Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("42P01") => {
                // Table _sqlx_migrations does not exist yet -> fresh database
                Ok(Vec::new())
            }
            Err(e) => Err(PersistenceError::Connection(e)),
        }
    }

    /// Inspects the current database migration status against this runner's migrator.
    pub async fn status(&self, pool: &PgPool) -> Result<MigrationStatus, PersistenceError> {
        let applied = Self::fetch_applied_migrations(pool).await?;
        let applied_versions: HashSet<i64> = applied.iter().map(|m| m.version).collect();

        let mut pending = Vec::new();
        for m in self.migrator.iter() {
            if !applied_versions.contains(&m.version) {
                pending.push(PendingMigrationRecord {
                    version: m.version,
                    description: m.description.to_string(),
                    migration_type: format!("{:?}", m.migration_type),
                });
            }
        }

        let current_version = applied.iter().map(|m| m.version).max();
        let is_up_to_date = pending.is_empty() && applied.iter().all(|m| m.success);

        Ok(MigrationStatus {
            current_version,
            applied,
            pending,
            is_up_to_date,
        })
    }

    /// Executes all pending migrations deterministically against the provided database pool.
    ///
    /// Returns a structured `MigrationReport` detailing what was applied.
    /// Safe to invoke repeatedly when the database is already current.
    pub async fn run(&self, pool: &PgPool) -> Result<MigrationReport, PersistenceError> {
        let before_applied = Self::fetch_applied_migrations(pool).await?;
        let before_versions: HashSet<i64> = before_applied.iter().map(|m| m.version).collect();

        // Run SQLx migrator
        self.migrator
            .run(pool)
            .await
            .map_err(PersistenceError::Migration)?;

        let after_applied = Self::fetch_applied_migrations(pool).await?;
        let newly_applied_versions: Vec<i64> = after_applied
            .iter()
            .map(|m| m.version)
            .filter(|v| !before_versions.contains(v))
            .collect();

        let total_applied_count = after_applied.len();
        let latest_version = after_applied.iter().map(|m| m.version).max();
        let already_up_to_date = newly_applied_versions.is_empty();

        Ok(MigrationReport {
            newly_applied_versions,
            total_applied_count,
            latest_version,
            already_up_to_date,
        })
    }
}
