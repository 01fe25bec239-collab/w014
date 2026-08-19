//! Organization tenant identity semantics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::ids::OrganizationId;
use crate::validation::{validate_non_empty, validate_slug};

/// Authoritative domain representation of an Organization tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub id: OrganizationId,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Organization {
    /// Creates a new Organization domain entity enforcing name and slug invariants.
    pub fn new(name: impl AsRef<str>, slug: impl AsRef<str>) -> Result<Self, DomainError> {
        let valid_name = validate_non_empty("name", name.as_ref())?.to_string();
        let valid_slug = validate_slug(slug.as_ref())?;
        let now = Utc::now();

        Ok(Self {
            id: OrganizationId::new(),
            name: valid_name,
            slug: valid_slug,
            created_at: now,
            updated_at: now,
        })
    }

    /// Reconstructs an existing Organization from persistent storage.
    pub fn reconstruct(
        id: OrganizationId,
        name: String,
        slug: String,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        let valid_name = validate_non_empty("name", &name)?.to_string();
        let valid_slug = validate_slug(&slug)?;

        Ok(Self {
            id,
            name: valid_name,
            slug: valid_slug,
            created_at,
            updated_at,
        })
    }

    /// Renames the organization, validating the new name and advancing `updated_at`.
    pub fn rename(&mut self, new_name: impl AsRef<str>) -> Result<(), DomainError> {
        let valid_name = validate_non_empty("name", new_name.as_ref())?.to_string();
        self.name = valid_name;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Updates the organization slug, validating the new slug and advancing `updated_at`.
    pub fn update_slug(&mut self, new_slug: impl AsRef<str>) -> Result<(), DomainError> {
        let valid_slug = validate_slug(new_slug.as_ref())?;
        self.slug = valid_slug;
        self.updated_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organization_creation_valid() {
        let org = Organization::new("Acme Corp", "acme-corp").unwrap();
        assert_eq!(org.name, "Acme Corp");
        assert_eq!(org.slug, "acme-corp");
    }

    #[test]
    fn test_organization_creation_empty_name_fails() {
        let err = Organization::new("   ", "acme-corp").unwrap_err();
        assert_eq!(err, DomainError::EmptyField("name"));
    }

    #[test]
    fn test_organization_creation_invalid_slug_fails() {
        let err = Organization::new("Acme Corp", "Acme Corp").unwrap_err();
        assert_eq!(err, DomainError::InvalidSlug("Acme Corp".to_string()));
    }
}
