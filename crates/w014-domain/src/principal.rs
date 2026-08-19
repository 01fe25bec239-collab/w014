//! Principal identity semantics.
//!
//! Principal identity is authoritative. Principal email is informational only,
//! NOT authentication identity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::DomainError;
use crate::ids::{OrganizationId, PrincipalId};
use crate::validation::validate_non_empty;

/// Type category of a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalType {
    User,
    Service,
    System,
}

impl PrincipalType {
    /// Returns the database-compatible string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Service => "service",
            Self::System => "system",
        }
    }
}

impl fmt::Display for PrincipalType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for PrincipalType {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "user" => Ok(Self::User),
            "service" => Ok(Self::Service),
            "system" => Ok(Self::System),
            other => Err(DomainError::InvalidPrincipalType(other.to_string())),
        }
    }
}

/// Authoritative domain representation of a Principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,
    pub organization_id: OrganizationId,
    pub principal_type: PrincipalType,
    pub email: Option<String>,
    pub display_name: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Principal {
    /// Creates a new active Principal domain entity.
    pub fn new(
        organization_id: OrganizationId,
        principal_type: PrincipalType,
        email: Option<impl AsRef<str>>,
        display_name: impl AsRef<str>,
    ) -> Result<Self, DomainError> {
        let valid_display_name =
            validate_non_empty("display_name", display_name.as_ref())?.to_string();
        let valid_email = match email {
            Some(e) => {
                let trimmed = validate_non_empty("email", e.as_ref())?;
                Some(trimmed.to_string())
            }
            None => None,
        };
        let now = Utc::now();

        Ok(Self {
            id: PrincipalId::new(),
            organization_id,
            principal_type,
            email: valid_email,
            display_name: valid_display_name,
            is_active: true,
            created_at: now,
            updated_at: now,
        })
    }

    /// Reconstructs an existing Principal from persistent storage.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: PrincipalId,
        organization_id: OrganizationId,
        principal_type: PrincipalType,
        email: Option<String>,
        display_name: String,
        is_active: bool,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        let valid_display_name = validate_non_empty("display_name", &display_name)?.to_string();
        let valid_email = match email {
            Some(ref e) => Some(validate_non_empty("email", e)?.to_string()),
            None => None,
        };

        Ok(Self {
            id,
            organization_id,
            principal_type,
            email: valid_email,
            display_name: valid_display_name,
            is_active,
            created_at,
            updated_at,
        })
    }

    /// Deactivates the principal.
    pub fn deactivate(&mut self) {
        self.is_active = false;
        self.updated_at = Utc::now();
    }

    /// Activates the principal.
    pub fn activate(&mut self) {
        self.is_active = true;
        self.updated_at = Utc::now();
    }

    /// Updates display name, advancing `updated_at`.
    pub fn update_display_name(&mut self, new_name: impl AsRef<str>) -> Result<(), DomainError> {
        let valid_name = validate_non_empty("display_name", new_name.as_ref())?.to_string();
        self.display_name = valid_name;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Updates informational email snapshot.
    pub fn update_email(&mut self, new_email: Option<impl AsRef<str>>) -> Result<(), DomainError> {
        self.email = match new_email {
            Some(e) => Some(validate_non_empty("email", e.as_ref())?.to_string()),
            None => None,
        };
        self.updated_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_type_parsing() {
        assert_eq!(
            "user".parse::<PrincipalType>().unwrap(),
            PrincipalType::User
        );
        assert_eq!(
            "service".parse::<PrincipalType>().unwrap(),
            PrincipalType::Service
        );
        assert_eq!(
            "system".parse::<PrincipalType>().unwrap(),
            PrincipalType::System
        );
        assert!("invalid".parse::<PrincipalType>().is_err());
    }

    #[test]
    fn test_principal_creation_and_lifecycle() {
        let org_id = OrganizationId::new();
        let mut p = Principal::new(
            org_id,
            PrincipalType::User,
            Some("user@example.com"),
            "Alice User",
        )
        .unwrap();

        assert!(p.is_active);
        assert_eq!(p.display_name, "Alice User");
        assert_eq!(p.email.as_deref(), Some("user@example.com"));

        p.deactivate();
        assert!(!p.is_active);

        p.activate();
        assert!(p.is_active);
    }

    #[test]
    fn test_principal_empty_display_name_rejected() {
        let org_id = OrganizationId::new();
        let err = Principal::new(org_id, PrincipalType::User, None::<&str>, "  ").unwrap_err();
        assert_eq!(err, DomainError::EmptyField("display_name"));
    }
}
