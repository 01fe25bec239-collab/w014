//! Error definitions for persistence, migrations, audit chains, and idempotency operations.

use thiserror::Error;
use uuid::Uuid;

/// Core error type for persistence operations, database connections, migrations,
/// authoritative audit chains, and idempotency stores.
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

    /// Error in audit chain hashing, sequence ordering, or tamper detection.
    #[error("Audit integrity error: {0}")]
    AuditIntegrity(#[from] AuditIntegrityError),

    /// Error in idempotency store operations or key mismatch.
    #[error("Idempotency error: {0}")]
    Idempotency(String),

    /// Row-level security session context error.
    #[error("RLS error: {0}")]
    Rls(String),

    /// Generic persistence query or operation error.
    #[error("Persistence operation error: {0}")]
    Operation(String),
}

/// Errors detected when validating audit chain integrity and hash linkages.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum AuditIntegrityError {
    /// A sequence gap was detected in the audit event chain.
    #[error("Audit sequence gap at index {index}: expected sequence {expected}, got {actual}")]
    SequenceGap {
        index: usize,
        expected: i64,
        actual: i64,
    },

    /// Sequence numbers are not strictly increasing.
    #[error(
        "Audit sequence disorder at index {index}: previous sequence {previous}, current sequence {current}"
    )]
    SequenceDisorder {
        index: usize,
        previous: i64,
        current: i64,
    },

    /// The previous_event_hash of an event does not match the prior event's hash (or genesis).
    #[error(
        "Audit previous hash mismatch at sequence {sequence_num}: expected '{expected}', got '{actual}'"
    )]
    PreviousHashMismatch {
        sequence_num: i64,
        expected: String,
        actual: String,
    },

    /// The recomputed SHA-256 hash of an audit event does not match its stored hash (tamper detected).
    #[error(
        "Audit event hash tamper detected at sequence {sequence_num}: stored '{recorded_hash}', recomputed '{computed_hash}'"
    )]
    HashTamperDetected {
        sequence_num: i64,
        recorded_hash: String,
        computed_hash: String,
    },

    /// An event in the chain belongs to an unexpected workspace.
    #[error(
        "Workspace ID mismatch in audit chain at sequence {sequence_num}: expected '{expected}', got '{actual}'"
    )]
    WorkspaceMismatch {
        sequence_num: i64,
        expected: Uuid,
        actual: Uuid,
    },

    /// An audit chain head was not found for the specified workspace.
    #[error("Audit chain head not found for workspace {0}")]
    ChainHeadNotFound(Uuid),
}
