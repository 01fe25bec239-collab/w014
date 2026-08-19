//! Workspace identity semantics within a program and organization.
//!
//! Preserves tenant/workspace isolation relationships and staged-FK constraints:
//! `current_source_state_id` remains nullable and deferred in W1.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;
use crate::ids::{OrganizationId, ProgramId, WorkspaceId};
use crate::validation::{validate_non_empty, validate_slug};

/// Authoritative domain representation of a Workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub program_id: ProgramId,
    pub organization_id: OrganizationId,
    pub name: String,
    pub slug: String,
    /// STAGED FK: Nullable in W1, NO FK to effective_contract_states (deferred to W3).
    pub current_source_state_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Workspace {
    /// Creates a new Workspace domain entity with unassigned `current_source_state_id`.
    pub fn new(
        program_id: ProgramId,
        organization_id: OrganizationId,
        name: impl AsRef<str>,
        slug: impl AsRef<str>,
    ) -> Result<Self, DomainError> {
        let valid_name = validate_non_empty("name", name.as_ref())?.to_string();
        let valid_slug = validate_slug(slug.as_ref())?;
        let now = Utc::now();

        Ok(Self {
            id: WorkspaceId::new(),
            program_id,
            organization_id,
            name: valid_name,
            slug: valid_slug,
            current_source_state_id: None,
            created_at: now,
            updated_at: now,
        })
    }

    /// Reconstructs an existing Workspace from persistent storage.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: WorkspaceId,
        program_id: ProgramId,
        organization_id: OrganizationId,
        name: String,
        slug: String,
        current_source_state_id: Option<Uuid>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        let valid_name = validate_non_empty("name", &name)?.to_string();
        let valid_slug = validate_slug(&slug)?;

        Ok(Self {
            id,
            program_id,
            organization_id,
            name: valid_name,
            slug: valid_slug,
            current_source_state_id,
            created_at,
            updated_at,
        })
    }

    /// Updates workspace details, validating fields and advancing `updated_at`.
    pub fn update_details(
        &mut self,
        name: impl AsRef<str>,
        slug: impl AsRef<str>,
    ) -> Result<(), DomainError> {
        let valid_name = validate_non_empty("name", name.as_ref())?.to_string();
        let valid_slug = validate_slug(slug.as_ref())?;
        self.name = valid_name;
        self.slug = valid_slug;
        self.updated_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_creation() {
        let org_id = OrganizationId::new();
        let prog_id = ProgramId::new();
        let ws = Workspace::new(prog_id, org_id, "Dev Workspace", "dev-workspace").unwrap();

        assert_eq!(ws.program_id, prog_id);
        assert_eq!(ws.organization_id, org_id);
        assert_eq!(ws.name, "Dev Workspace");
        assert_eq!(ws.slug, "dev-workspace");
        assert_eq!(ws.current_source_state_id, None);
    }
}
