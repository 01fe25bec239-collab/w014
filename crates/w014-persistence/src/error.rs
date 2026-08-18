//! Error definitions for persistence and migration operations.

use thiserror::Error;

/// Core error type for persistence operations, database connections, and migrations.
#[derive(Debug, Error)]
pub enum PersistenceError {
    /// Error in database configuration or connection string parsing.
    #[error("Database configuration error: {0}")]
    Config(String),

    /// Error establishing or using database connections / pools.
    #[error("Database connection error: {0}")]
    Connection(#[from] sqlx::Error),

    /// Error executing SQLx migrations.
    #[error("Migration execution error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// Error in test database lifecycle (creation, teardown).
    #[error("Test database lifecycle error: {0}")]
    TestDatabase(String),

    /// Generic persistence query or operation error.
    #[error("Persistence operation error: {0}")]
    Operation(String),
}
