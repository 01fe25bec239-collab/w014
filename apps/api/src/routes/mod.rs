//! API route handlers module.

pub mod auth;
pub mod health;
pub mod session;

pub use auth::{
    CallbackQuery, CallbackResponse, LoginQuery, LoginResponse, callback_handler, login_handler,
};
pub use health::{HealthResponse, health_alias_handler, healthz_handler};
pub use session::{LogoutResponse, SessionResponse, get_session_handler, logout_handler};
