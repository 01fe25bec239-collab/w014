//! Authoritative W1 Audit Chain Substrate for W-014.
//!
//! Provides the immutable audit event store, per-workspace cryptographic hash chain,
//! genesis anchoring, and tamper/gap detection.

pub mod append;
pub mod envelope;
pub mod hasher;

pub use append::{AppendAuditParams, AuditAppendContract, PostgresAuditStore};
pub use envelope::{AuditChainHeadRecord, AuditEventRecord, CanonicalAuditEnvelope};
pub use hasher::{AuditChainHashContract, AuditChainHasher, GENESIS_HASH};
