//! OIDC protocol primitives, PKCE enforcement, JWKS key management, and ID token validation.

pub mod client;
pub mod jwks;
pub mod pkce;
pub mod token;

pub use client::{AuthorizationParameters, OidcClient, OidcConfig, OidcTokenResponse};
pub use jwks::{ALLOWED_ASYMMETRIC_ALGORITHMS, Jwk, Jwks, JwksCache, validate_algorithm};
pub use pkce::{PkceCodeChallenge, PkceCodeVerifier, PkceMethod};
pub use token::{AudienceClaim, IdTokenClaims, IdTokenValidator};
