//! OIDC ID Token validation and claims extraction.
//!
//! Enforces:
//! - Exact issuer binding against issuer allowlist
//! - Asymmetric algorithm allowlist (strictly rejects `alg=none` and symmetric algs)
//! - Client ID audience validation & azp matching rules
//! - Nonce exact matching
//! - Timestamp validation with controlled clock-skew tolerance
//! - Keying identity strictly by (issuer, subject)

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::error::AuthnError;
use crate::oidc::jwks::{JwksCache, validate_algorithm};

/// Raw intermediate claims representation for JSON deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawIdTokenClaims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub aud: AudienceClaim,
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Audience claim supporting either a single string or an array of strings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum AudienceClaim {
    Single(String),
    Multiple(Vec<String>),
}

impl Default for AudienceClaim {
    fn default() -> Self {
        Self::Multiple(Vec::new())
    }
}

impl AudienceClaim {
    pub fn contains(&self, client_id: &str) -> bool {
        match self {
            Self::Single(s) => s == client_id,
            Self::Multiple(list) => list.iter().any(|s| s == client_id),
        }
    }

    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::Single(s) => vec![s.clone()],
            Self::Multiple(list) => list.clone(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Multiple(list) => list.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Single(s) => s.is_empty(),
            Self::Multiple(list) => list.is_empty(),
        }
    }
}

/// Authoritative verified OIDC ID token claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdTokenClaims {
    pub issuer: String,
    pub subject: String,
    /// Informational snapshot only; NOT the authentication identity.
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub issued_at: DateTime<Utc>,
    pub claims: serde_json::Value,
}

impl IdTokenClaims {
    /// Returns the unique composite identity key `(issuer, subject)`.
    pub fn identity_key(&self) -> (&str, &str) {
        (&self.issuer, &self.subject)
    }
}

/// Validator for OIDC ID tokens enforcing frozen protocol requirements.
#[derive(Clone)]
pub struct IdTokenValidator {
    expected_issuer: String,
    issuer_allowlist: HashSet<String>,
    client_id: String,
    clock_skew: Duration,
}

impl IdTokenValidator {
    /// Creates a new validator with the specified issuer, allowlist, and client ID.
    pub fn new(
        expected_issuer: impl Into<String>,
        issuer_allowlist: Vec<String>,
        client_id: impl Into<String>,
    ) -> Self {
        let iss = expected_issuer.into();
        let mut allowlist: HashSet<String> = issuer_allowlist.into_iter().collect();
        allowlist.insert(iss.clone());

        Self {
            expected_issuer: iss,
            issuer_allowlist: allowlist,
            client_id: client_id.into(),
            clock_skew: Duration::seconds(60), // Frozen clock skew tolerance: 60s
        }
    }

    /// Sets custom clock skew tolerance.
    pub fn with_clock_skew(mut self, clock_skew: Duration) -> Self {
        self.clock_skew = clock_skew;
        self
    }

    /// Validates an ID token string against JWKS and expected nonce.
    pub async fn validate_token(
        &self,
        token_str: &str,
        expected_nonce: &str,
        jwks_cache: &JwksCache,
    ) -> Result<IdTokenClaims, AuthnError> {
        // 1. Decode and validate header
        let header = decode_header(token_str)
            .map_err(|e| AuthnError::InvalidToken(format!("Malformed JWT header: {e}")))?;

        // Validate algorithm against allowlist & reject none/symmetric
        validate_algorithm(header.alg)?;

        // 2. Obtain key from JWKS
        let decoding_key = jwks_cache.get_decoding_key(header.kid.as_deref()).await?;

        // 3. Decode token payload with signature check
        self.validate_with_key(token_str, expected_nonce, &decoding_key, header.alg)
    }

    /// Validates token using a known decoding key and algorithm.
    pub fn validate_with_key(
        &self,
        token_str: &str,
        expected_nonce: &str,
        key: &DecodingKey,
        alg: Algorithm,
    ) -> Result<IdTokenClaims, AuthnError> {
        // Enforce algorithm constraints
        validate_algorithm(alg)?;

        let mut validation = Validation::new(alg);
        validation.validate_exp = false; // We validate exp manually for exact error types and clock skew
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["iss", "sub", "exp", "iat"]);

        let token_data = decode::<RawIdTokenClaims>(token_str, key, &validation)
            .map_err(|e| AuthnError::SignatureVerificationFailed(e.to_string()))?;

        let raw = token_data.claims;
        let now = Utc::now();

        // 4. Validate Issuer
        if raw.iss != self.expected_issuer {
            return Err(AuthnError::InvalidIssuer(format!(
                "Token issuer '{}' does not match expected '{}'",
                raw.iss, self.expected_issuer
            )));
        }

        if !self.issuer_allowlist.contains(&raw.iss) {
            return Err(AuthnError::InvalidIssuer(format!(
                "Issuer '{}' is not in the approved issuer allowlist",
                raw.iss
            )));
        }

        // 5. Validate Subject
        if raw.sub.trim().is_empty() {
            return Err(AuthnError::InvalidSubject(
                "ID token subject claim 'sub' is empty".to_string(),
            ));
        }

        // 6. Validate Audience & azp
        if !raw.aud.contains(&self.client_id) {
            return Err(AuthnError::InvalidAudience {
                expected: self.client_id.clone(),
                found: raw.aud.to_vec(),
            });
        }

        if raw.aud.len() > 1 {
            // OIDC Core 1.0 Section 3.1.3.7: If multiple audiences, azp is required and must equal client_id
            match raw.azp.as_deref() {
                Some(azp_val) if azp_val == self.client_id => {}
                Some(azp_val) => {
                    return Err(AuthnError::InvalidAzp {
                        expected: self.client_id.clone(),
                        found: azp_val.to_string(),
                    });
                }
                None => {
                    return Err(AuthnError::InvalidAzp {
                        expected: self.client_id.clone(),
                        found: "missing (required when multiple audiences present)".to_string(),
                    });
                }
            }
        } else if let Some(azp_val) = raw
            .azp
            .as_ref()
            .filter(|azp| azp.as_str() != self.client_id.as_str())
        {
            return Err(AuthnError::InvalidAzp {
                expected: self.client_id.clone(),
                found: azp_val.clone(),
            });
        }

        // 7. Validate Nonce
        match raw.nonce.as_deref() {
            Some(n) if n == expected_nonce => {}
            _ => return Err(AuthnError::NonceMismatch),
        }

        // 8. Validate Timestamps with clock-skew tolerance
        let now_ts = now.timestamp();
        let skew_secs = self.clock_skew.num_seconds();

        if now_ts >= raw.exp + skew_secs {
            return Err(AuthnError::TokenExpired {
                exp: raw.exp,
                now: now_ts,
                skew_secs,
            });
        }

        if let Some(nbf_val) = raw.nbf.filter(|&nbf_val| nbf_val > now_ts + skew_secs) {
            return Err(AuthnError::TokenNotYetValid {
                nbf: nbf_val,
                now: now_ts,
                skew_secs,
            });
        }

        if raw.iat > now_ts + skew_secs {
            return Err(AuthnError::InvalidIssuedAt {
                iat: raw.iat,
                now: now_ts,
            });
        }

        let expires_at = DateTime::from_timestamp(raw.exp, 0).unwrap_or(now);
        let issued_at = DateTime::from_timestamp(raw.iat, 0).unwrap_or(now);

        let claims_value = serde_json::to_value(&raw)
            .unwrap_or_else(|_| serde_json::json!({"sub": raw.sub, "iss": raw.iss}));

        Ok(IdTokenClaims {
            issuer: raw.iss,
            subject: raw.sub,
            email: raw.email,
            email_verified: raw.email_verified,
            name: raw.name,
            nonce: raw.nonce,
            expires_at,
            issued_at,
            claims: claims_value,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audience_claim_parsing() {
        let single = AudienceClaim::Single("client-123".to_string());
        assert!(single.contains("client-123"));
        assert!(!single.contains("client-456"));
        assert_eq!(single.len(), 1);

        let multi =
            AudienceClaim::Multiple(vec!["client-123".to_string(), "client-789".to_string()]);
        assert!(multi.contains("client-123"));
        assert!(multi.contains("client-789"));
        assert!(!multi.contains("client-456"));
        assert_eq!(multi.len(), 2);
    }
}
