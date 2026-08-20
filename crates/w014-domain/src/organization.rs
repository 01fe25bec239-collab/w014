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
    pub display_name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
}

impl Organization {
    /// Creates a new Organization domain entity enforcing display_name and slug invariants.
    pub fn new(display_name: impl AsRef<str>, slug: impl AsRef<str>) -> Result<Self, DomainError> {
        let valid_name = validate_non_empty("display_name", display_name.as_ref())?.to_string();
        let valid_slug = validate_slug(slug.as_ref())?;
        let now = Utc::now();

        Ok(Self {
            id: OrganizationId::new(),
            display_name: valid_name,
            slug: valid_slug,
            created_at: now,
        })
    }

    /// Reconstructs an existing Organization from persistent storage.
    pub fn reconstruct(
        id: OrganizationId,
        display_name: String,
        slug: String,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        let valid_name = validate_non_empty("display_name", &display_name)?.to_string();
        let valid_slug = validate_slug(&slug)?;

        Ok(Self {
            id,
            display_name: valid_name,
            slug: valid_slug,
            created_at,
        })
    }

    /// Convenience getter for display name.
    pub fn name(&self) -> &str {
        &self.display_name
    }

    /// Renames the organization, validating the new display name.
    pub fn rename(&mut self, new_name: impl AsRef<str>) -> Result<(), DomainError> {
        let valid_name = validate_non_empty("display_name", new_name.as_ref())?.to_string();
        self.display_name = valid_name;
        Ok(())
    }

    /// Updates the organization slug, validating the new slug.
    pub fn update_slug(&mut self, new_slug: impl AsRef<str>) -> Result<(), DomainError> {
        let valid_slug = validate_slug(new_slug.as_ref())?;
        self.slug = valid_slug;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organization_creation_valid() {
        let org = Organization::new("Acme Corp", "acme-corp").unwrap();
        assert_eq!(org.display_name, "Acme Corp");
        assert_eq!(org.slug, "acme-corp");
    }

    #[test]
    fn test_organization_creation_empty_name_fails() {
        let err = Organization::new("   ", "acme-corp").unwrap_err();
        assert_eq!(err, DomainError::EmptyField("display_name"));
    }

    #[test]
    fn test_organization_creation_invalid_slug_fails() {
        let err = Organization::new("Acme Corp", "Acme Corp").unwrap_err();
        assert_eq!(err, DomainError::InvalidSlug("Acme Corp".to_string()));
    }
}
