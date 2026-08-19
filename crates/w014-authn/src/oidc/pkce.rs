//! PKCE (Proof Key for Code Exchange, RFC 7636) implementation.
//!
//! Enforces `S256` code challenge method exclusively. Rejects `plain` and unapproved methods.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::error::AuthnError;

/// PKCE Code Challenge Method. Strictly S256 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PkceMethod {
    #[default]
    S256,
}

impl PkceMethod {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::S256 => "S256",
        }
    }
}

/// High-entropy PKCE code verifier (RFC 7636 Section 4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceCodeVerifier(String);

impl PkceCodeVerifier {
    /// Generates a cryptographically random PKCE code verifier (43-128 chars, URL-safe).
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        Self(verifier)
    }

    /// Wraps an existing verifier string, validating RFC 7636 length and charset constraints.
    pub fn new(verifier: impl Into<String>) -> Result<Self, AuthnError> {
        let s = verifier.into();
        let trimmed = s.trim();
        if trimmed.len() < 43 || trimmed.len() > 128 {
            return Err(AuthnError::InvalidPkce(format!(
                "code_verifier length must be between 43 and 128 characters, got {}",
                trimmed.len()
            )));
        }

        // Must contain only unreserved characters: [A-Za-z0-9\-._~]
        if !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~')
        {
            return Err(AuthnError::InvalidPkce(
                "code_verifier contains invalid characters; must be [A-Za-z0-9-._~]".to_string(),
            ));
        }

        Ok(Self(trimmed.to_string()))
    }

    pub fn secret(&self) -> &str {
        &self.0
    }

    /// Derives the S256 PKCE code challenge.
    pub fn challenge(&self) -> PkceCodeChallenge {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        let hash = hasher.finalize();
        let challenge = URL_SAFE_NO_PAD.encode(hash);
        PkceCodeChallenge {
            challenge,
            method: PkceMethod::S256,
        }
    }
}

/// PKCE Code Challenge and Method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceCodeChallenge {
    pub challenge: String,
    pub method: PkceMethod,
}

impl PkceCodeChallenge {
    pub fn as_str(&self) -> &str {
        &self.challenge
    }

    pub fn method(&self) -> PkceMethod {
        self.method
    }

    /// Verifies that a given code verifier matches this code challenge using S256.
    pub fn verify(&self, verifier: &PkceCodeVerifier) -> bool {
        let derived = verifier.challenge();
        derived.challenge == self.challenge && self.method == PkceMethod::S256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_generation_and_challenge() {
        let verifier = PkceCodeVerifier::generate();
        assert!(verifier.secret().len() >= 43);
        assert!(verifier.secret().len() <= 128);

        let challenge = verifier.challenge();
        assert_eq!(challenge.method(), PkceMethod::S256);
        assert!(!challenge.as_str().is_empty());

        assert!(challenge.verify(&verifier));

        let other_verifier = PkceCodeVerifier::generate();
        assert!(!challenge.verify(&other_verifier));
    }

    #[test]
    fn test_rfc7636_test_vector() {
        // RFC 7636 Section 4.2 Appendix B test vector
        let verifier_str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let verifier = PkceCodeVerifier::new(verifier_str).unwrap();
        let challenge = verifier.challenge();

        assert_eq!(challenge.challenge, expected_challenge);
        assert!(challenge.verify(&verifier));
    }

    #[test]
    fn test_pkce_verifier_validation_length() {
        // Too short (< 43)
        assert!(PkceCodeVerifier::new("too_short").is_err());
        // Too long (> 128)
        let too_long = "a".repeat(129);
        assert!(PkceCodeVerifier::new(too_long).is_err());
    }
}
