//! Authoritative W1 Audit Chain Substrate for W-014 conforming to Prompt-12 / Prompt-13.
//!
//! Provides the immutable audit event store, per-workspace cryptographic hash chain,
//! RFC-8785 JSON canonicalization, and tamper/gap detection.

pub mod append;
pub mod envelope;
pub mod hasher;

pub use append::{AppendAuditParams, AuditAppendContract, PostgresAuditStore};
pub use envelope::{AuditChainHeadRecord, AuditEventRecord, CanonicalAuditEnvelope};
pub use hasher::{AuditChainHashContract, AuditChainHasher, canonicalize_json};
