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
    pub program_code: String,
    pub name: String,
    pub row_version: i32,
    pub created_at: DateTime<Utc>,
}

impl Program {
    /// Creates a new Program domain entity.
    pub fn new(
        organization_id: OrganizationId,
        name: impl AsRef<str>,
        program_code: impl AsRef<str>,
    ) -> Result<Self, DomainError> {
        let valid_name = validate_non_empty("name", name.as_ref())?.to_string();
        let valid_code = validate_slug(program_code.as_ref())?;
        let now = Utc::now();

        Ok(Self {
            id: ProgramId::new(),
            organization_id,
            program_code: valid_code,
            name: valid_name,
            row_version: 1,
            created_at: now,
        })
    }

    /// Reconstructs an existing Program from persistent storage.
    pub fn reconstruct(
        id: ProgramId,
        organization_id: OrganizationId,
        program_code: String,
        name: String,
        row_version: i32,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        let valid_name = validate_non_empty("name", &name)?.to_string();
        let valid_code = validate_slug(&program_code)?;

        Ok(Self {
            id,
            organization_id,
            program_code: valid_code,
            name: valid_name,
            row_version,
            created_at,
        })
    }

    /// Convenience getter for slug / program code.
    pub fn slug(&self) -> &str {
        &self.program_code
    }

    /// Updates program details, validating fields and incrementing row_version.
    pub fn update_details(
        &mut self,
        name: impl AsRef<str>,
        program_code: impl AsRef<str>,
    ) -> Result<(), DomainError> {
        let valid_name = validate_non_empty("name", name.as_ref())?.to_string();
        let valid_code = validate_slug(program_code.as_ref())?;
        self.name = valid_name;
        self.program_code = valid_code;
        self.row_version += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_creation() {
        let org_id = OrganizationId::new();
        let program = Program::new(org_id, "Core Platform", "core-platform").unwrap();
        assert_eq!(program.organization_id, org_id);
        assert_eq!(program.name, "Core Platform");
        assert_eq!(program.program_code, "core-platform");
        assert_eq!(program.slug(), "core-platform");
        assert_eq!(program.row_version, 1);
    }
}
