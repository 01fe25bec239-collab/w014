//! Authoritative Idempotency Store Substrate for W-014 conforming to Prompt-12 / Prompt-13.
//!
//! Provides HMAC key hashing, RFC-8785 request hashing, fill-once lifecycle management,
//! duplicate prevention, in-flight serialization, and authoritative response replay.

pub mod store;

pub use store::{
    IdempotencyCheckResult, IdempotencyHasher, IdempotencyRecord, IdempotencyStore,
    PostgresIdempotencyStore,
};
