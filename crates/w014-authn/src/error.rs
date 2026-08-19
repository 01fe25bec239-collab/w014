//! Authentication, session, and OIDC error definitions.

use thiserror::Error;

/// Error type for authentication, session, OIDC transactions, and protocol validation.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum AuthnError {
    /// A required field was empty or whitespace.
    #[error("Required field '{0}' cannot be empty or whitespace")]
    EmptyField(&'static str),

    /// Invalid issuer format or not in allowlist.
    #[error("Invalid OIDC issuer: '{0}'")]
    InvalidIssuer(String),

    /// Invalid subject format.
    #[error("Invalid OIDC subject: '{0}'")]
    InvalidSubject(String),

    /// Invalid session status string.
    #[error("Invalid session status '{0}': expected 'active', 'revoked', or 'expired'")]
    InvalidSessionStatus(String),

    /// Session is revoked.
    #[error("Session '{0}' is revoked")]
    SessionRevoked(String),

    /// Session is expired.
    #[error("Session '{0}' is expired")]
    SessionExpired(String),

    /// Session was not found.
    #[error("Session not found")]
    SessionNotFound,

    /// Old and new token hashes in a session rotation must not be identical.
    #[error("Session rotation old and new token hashes cannot be identical")]
    IdenticalRotationHashes,

    /// Invalid expiration timestamp (e.g., expiry in the past or before creation).
    #[error("Invalid expiration timestamp: {0}")]
    InvalidExpiry(String),

    /// OIDC state token mismatch or missing.
    #[error("OIDC state mismatch: state token not found or does not match transaction")]
    StateMismatch,

    /// OIDC transaction not found.
    #[error("OIDC transaction not found")]
    TransactionNotFound,

    /// OIDC transaction expired.
    #[error("OIDC transaction has expired")]
    TransactionExpired,

    /// OIDC nonce mismatch.
    #[error("OIDC nonce mismatch: ID token nonce does not match transaction nonce")]
    NonceMismatch,

    /// Unapproved or insecure algorithm.
    #[error("Algorithm '{0}' is not in the approved asymmetric algorithm allowlist")]
    AlgorithmNotAllowed(String),

    /// Algorithm 'none' is explicitly rejected.
    #[error("Algorithm 'none' is prohibited")]
    AlgorithmNoneRejected,

    /// Symmetric algorithm rejected for OIDC ID token validation.
    #[error("Symmetric algorithm '{0}' is prohibited for ID token validation")]
    SymmetricAlgorithmRejected(String),

    /// Audience validation failed.
    #[error("Audience validation failed: expected client ID '{expected}', found '{found:?}'")]
    InvalidAudience {
        expected: String,
        found: Vec<String>,
    },

    /// Authorized party (azp) validation failed.
    #[error("Authorized party validation failed: expected client ID '{expected}', found '{found}'")]
    InvalidAzp { expected: String, found: String },

    /// Token has expired.
    #[error("ID token has expired (exp: {exp}, now: {now}, skew: {skew_secs}s)")]
    TokenExpired { exp: i64, now: i64, skew_secs: i64 },

    /// Token is not yet valid (nbf).
    #[error("ID token is not yet valid (nbf: {nbf}, now: {now}, skew: {skew_secs}s)")]
    TokenNotYetValid { nbf: i64, now: i64, skew_secs: i64 },

    /// Issued-at timestamp is in the future beyond allowed clock skew.
    #[error(
        "ID token issued-at is in the future beyond allowed clock skew (iat: {iat}, now: {now})"
    )]
    InvalidIssuedAt { iat: i64, now: i64 },

    /// JWK key ID not found in JWKS.
    #[error("Key ID '{0}' not found in JWKS")]
    KeyNotFound(String),

    /// Cryptographic signature verification failed.
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// IdP communication error.
    #[error("IdP communication error: {0}")]
    IdpCommunicationError(String),

    /// IdP token exchange error returned from IdP.
    #[error("IdP token exchange error: {error} - {description}")]
    IdpTokenExchangeError { error: String, description: String },

    /// JWKS retrieval failure.
    #[error("JWKS fetch error: {0}")]
    JwksFetchError(String),

    /// Invalid PKCE parameters or verifier.
    #[error("Invalid PKCE: {0}")]
    InvalidPkce(String),

    /// CSRF origin mismatch, malformed origin, or non-allowlisted origin.
    #[error("CSRF check failed: Origin '{0}' does not match allowed origin or is invalid")]
    CsrfOriginMismatch(String),

    /// CSRF missing Origin header on unsafe request.
    #[error("CSRF check failed: missing required Origin header on unsafe request")]
    CsrfMissingOrigin,

    /// CSRF missing required X-W014-CSRF header on unsafe request.
    #[error("CSRF check failed: missing required X-W014-CSRF header")]
    CsrfMissingHeader,

    /// CSRF token mismatch on X-W014-CSRF header.
    #[error("CSRF check failed: X-W014-CSRF token does not match expected session CSRF token")]
    CsrfTokenMismatch,

    /// Request is unauthenticated.
    #[error("Unauthenticated: valid session cookie required")]
    Unauthenticated,

    /// Malformed token or invalid structure.
    #[error("Invalid token format: {0}")]
    InvalidToken(String),

    /// Malformed cookie format.
    #[error("Invalid cookie: {0}")]
    InvalidCookie(String),
}
