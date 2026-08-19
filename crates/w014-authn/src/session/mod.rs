//! Server-side session domain primitives, token hashing, evaluation, and cookie management.

pub mod cookie;
pub mod entity;
pub mod manager;

pub use cookie::SessionCookieBuilder;
pub use entity::{Session, SessionId, SessionStatus};
pub use manager::{SessionConfig, SessionEvaluator, generate_session_token, hash_session_token};
