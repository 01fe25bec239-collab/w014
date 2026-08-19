//! OIDC Identity persistence-facing domain semantics.
//!
//! Note: The identity key is (issuer, subject). The email snapshot is informational only,
//! NOT authentication identity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;
use w014_domain::ids::PrincipalId;

use crate::error::AuthnError;

/// Authoritative identifier for an OIDC Identity linkage record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OidcIdentityId(pub Uuid);

impl OidcIdentityId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for OidcIdentityId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for OidcIdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for OidcIdentityId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<OidcIdentityId> for Uuid {
    fn from(id: OidcIdentityId) -> Self {
        id.0
    }
}

impl FromStr for OidcIdentityId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::from_str(s).map(Self)
    }
}

/// Persistence-facing representation of an OIDC identity linked to a principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcIdentity {
    pub id: OidcIdentityId,
    pub principal_id: PrincipalId,
    pub issuer: String,
    pub subject: String,
    /// Informational snapshot only; NOT the authentication identity.
    pub email: Option<String>,
    pub claims: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl OidcIdentity {
    /// Creates a new OIDC identity domain representation.
    pub fn new(
        principal_id: PrincipalId,
        issuer: impl AsRef<str>,
        subject: impl AsRef<str>,
        email: Option<impl AsRef<str>>,
        claims: serde_json::Value,
    ) -> Result<Self, AuthnError> {
        let trimmed_issuer = issuer.as_ref().trim();
        if trimmed_issuer.is_empty() {
            return Err(AuthnError::EmptyField("issuer"));
        }

        let trimmed_subject = subject.as_ref().trim();
        if trimmed_subject.is_empty() {
            return Err(AuthnError::EmptyField("subject"));
        }

        let email_opt = email.and_then(|e| {
            let t = e.as_ref().trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        });

        let now = Utc::now();
        Ok(Self {
            id: OidcIdentityId::new(),
            principal_id,
            issuer: trimmed_issuer.to_string(),
            subject: trimmed_subject.to_string(),
            email: email_opt,
            claims,
            created_at: now,
            updated_at: now,
        })
    }

    /// Reconstructs an existing OIDC identity from persistent storage.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: OidcIdentityId,
        principal_id: PrincipalId,
        issuer: String,
        subject: String,
        email: Option<String>,
        claims: serde_json::Value,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, AuthnError> {
        let trimmed_issuer = issuer.trim();
        if trimmed_issuer.is_empty() {
            return Err(AuthnError::EmptyField("issuer"));
        }

        let trimmed_subject = subject.trim();
        if trimmed_subject.is_empty() {
            return Err(AuthnError::EmptyField("subject"));
        }

        Ok(Self {
            id,
            principal_id,
            issuer: trimmed_issuer.to_string(),
            subject: trimmed_subject.to_string(),
            email,
            claims,
            created_at,
            updated_at,
        })
    }

    /// Returns the unique composite identity key `(issuer, subject)`.
    pub fn identity_key(&self) -> (&str, &str) {
        (&self.issuer, &self.subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_identity_creation() {
        let p_id = PrincipalId::new();
        let claims = serde_json::json!({"hd": "example.com"});
        let id = OidcIdentity::new(
            p_id,
            "https://accounts.google.com",
            "sub_1234567890",
            Some("alice@example.com"),
            claims.clone(),
        )
        .unwrap();

        assert_eq!(id.principal_id, p_id);
        assert_eq!(id.issuer, "https://accounts.google.com");
        assert_eq!(id.subject, "sub_1234567890");
        assert_eq!(id.email.as_deref(), Some("alice@example.com"));
        assert_eq!(
            id.identity_key(),
            ("https://accounts.google.com", "sub_1234567890")
        );
    }
}
