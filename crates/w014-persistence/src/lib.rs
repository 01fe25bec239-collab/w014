//! SQLx Migration Runner and Persistence Infrastructure for W-014.
//!
//! Provides the authoritative migration runner, database configuration management,
//! credential masking, and the reusable fresh/upgrade migration test harness.

pub mod audit;
pub mod config;
pub mod error;
pub mod harness;
pub mod idempotency;
pub mod rls;
pub mod runner;

pub use audit::{
    AppendAuditParams, AuditAppendContract, AuditChainHashContract, AuditChainHasher,
    AuditChainHeadRecord, AuditEventRecord, CanonicalAuditEnvelope, GENESIS_HASH,
    PostgresAuditStore,
};
pub use config::{DEFAULT_LOCAL_DATABASE_URL, DatabaseConfig};
pub use error::{AuditIntegrityError, PersistenceError};
pub use harness::{
    FreshHarnessResult, TestDatabase, UpgradeHarnessResult, run_failing_migration_harness,
    run_fresh_migration_harness, run_upgrade_migration_harness,
};
pub use idempotency::{
    IdempotencyCheckResult, IdempotencyHasher, IdempotencyRecord, IdempotencyStatus,
    IdempotencyStore, PostgresIdempotencyStore,
};
pub use rls::{clear_session_workspace_id, set_session_workspace_id};
pub use runner::{
    AppliedMigrationRecord, MIGRATOR, MigrationReport, MigrationRunner, MigrationStatus,
    PendingMigrationRecord,
};
pub use sqlx::migrate::Migrator;
