//! Authoritative Idempotency Store Substrate for W-014.
//!
//! Provides request hashing, key lifecycle management, duplicate prevention,
//! in-flight serialization, and authoritative response replay.

pub mod store;

pub use store::{
    IdempotencyCheckResult, IdempotencyHasher, IdempotencyRecord, IdempotencyStatus,
    IdempotencyStore, PostgresIdempotencyStore,
};
