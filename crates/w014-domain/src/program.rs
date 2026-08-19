//! Program identity semantics within an organization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::ids::{OrganizationId, ProgramId};
use crate::validation::{validate_non_empty, validate_slug};

/// Authoritative domain representation of a Program within an Organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    pub id: ProgramId,
    pub organization_id: OrganizationId,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Program {
    /// Creates a new Program domain entity.
    pub fn new(
        organization_id: OrganizationId,
        name: impl AsRef<str>,
        slug: impl AsRef<str>,
        description: Option<impl AsRef<str>>,
    ) -> Result<Self, DomainError> {
        let valid_name = validate_non_empty("name", name.as_ref())?.to_string();
        let valid_slug = validate_slug(slug.as_ref())?;
        let desc = description.map(|d| d.as_ref().trim().to_string());
        let now = Utc::now();

        Ok(Self {
            id: ProgramId::new(),
            organization_id,
            name: valid_name,
            slug: valid_slug,
            description: desc,
            created_at: now,
            updated_at: now,
        })
    }

    /// Reconstructs an existing Program from persistent storage.
    pub fn reconstruct(
        id: ProgramId,
        organization_id: OrganizationId,
        name: String,
        slug: String,
        description: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        let valid_name = validate_non_empty("name", &name)?.to_string();
        let valid_slug = validate_slug(&slug)?;

        Ok(Self {
            id,
            organization_id,
            name: valid_name,
            slug: valid_slug,
            description,
            created_at,
            updated_at,
        })
    }

    /// Updates program details, validating fields and advancing `updated_at`.
    pub fn update_details(
        &mut self,
        name: impl AsRef<str>,
        slug: impl AsRef<str>,
        description: Option<impl AsRef<str>>,
    ) -> Result<(), DomainError> {
        let valid_name = validate_non_empty("name", name.as_ref())?.to_string();
        let valid_slug = validate_slug(slug.as_ref())?;
        self.name = valid_name;
        self.slug = valid_slug;
        self.description = description.map(|d| d.as_ref().trim().to_string());
        self.updated_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_creation() {
        let org_id = OrganizationId::new();
        let program = Program::new(
            org_id,
            "Core Platform",
            "core-platform",
            Some("Main platform"),
        )
        .unwrap();
        assert_eq!(program.organization_id, org_id);
        assert_eq!(program.name, "Core Platform");
        assert_eq!(program.slug, "core-platform");
        assert_eq!(program.description.as_deref(), Some("Main platform"));
    }
}
