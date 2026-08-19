//! Authentication and session domain primitives for W-014.
//!
//! Provides persistence-facing representations of OIDC identities, server-side sessions,
//! append-style session rotations, and OIDC transaction tokens.
//!
//! Note: Full protocol execution flows (WI-0102) are deferred.

pub mod error;
pub mod identity;
pub mod rotation;
pub mod session;
pub mod transaction;

pub use error::AuthnError;
pub use identity::{OidcIdentity, OidcIdentityId};
pub use rotation::{SessionRotation, SessionRotationId};
pub use session::{Session, SessionId, SessionStatus};
pub use transaction::{OidcTransaction, OidcTransactionId};
