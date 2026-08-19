//! Authentication and session domain primitives and protocol execution for W-014.
//!
//! Provides:
//! - Authoritative OIDC Authorization Code + S256 PKCE protocol execution
//! - Key allowlist, exact issuer binding, audience/azp, nonce, and clock-skew validation
//! - Rust authoritative server-side opaque sessions with keyed HMAC-SHA256 token hashing
//! - Append-style session rotation and revocation lifecycle
//! - __Host- cookie semantics and CSRF Exact Origin and X-W014-CSRF token validation

pub mod csrf;
pub mod error;
pub mod identity;
pub mod middleware;
pub mod oidc;
pub mod rotation;
pub mod session;
pub mod transaction;

pub use csrf::{CSRF_HEADER_NAME, CsrfConfig, CsrfProtector, constant_time_eq, derive_csrf_token};
pub use error::AuthnError;
pub use identity::{OidcIdentity, OidcIdentityId};
pub use middleware::AuthenticatedSession;
pub use oidc::{
    AuthorizationParameters, IdTokenClaims, IdTokenValidator, Jwk, Jwks, JwksCache, OidcClient,
    OidcConfig, OidcTokenResponse, PkceCodeChallenge, PkceCodeVerifier, PkceMethod,
};
pub use rotation::{SessionRotation, SessionRotationId};
pub use session::{
    Session, SessionConfig, SessionCookieBuilder, SessionEvaluator, SessionId, SessionStatus,
    generate_session_token, hash_session_token,
};
pub use transaction::{OidcTransaction, OidcTransactionId};
