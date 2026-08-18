//! API route handlers module.

pub mod health;

pub use health::{HealthResponse, health_alias_handler, healthz_handler};
