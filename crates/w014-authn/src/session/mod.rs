//! Server-side session domain primitives, token hashing, evaluation, and cookie management.

pub mod cookie;
pub mod entity;
pub mod manager;

pub use cookie::SessionCookieBuilder;
pub use entity::{Session, SessionId, SessionStatus};
pub use manager::{
    AuthenticationResult, SessionConfig, SessionEvaluator, generate_session_token,
    hash_session_handle, hash_session_token,
};
