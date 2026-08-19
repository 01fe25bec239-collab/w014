//! PostgreSQL repository operations for Organizations, Principals, Programs, and Workspaces.

use sqlx::{PgConnection, Row};
use w014_domain::ids::{OrganizationId, PrincipalId, ProgramId, WorkspaceId};
use w014_domain::membership::{Membership, MembershipRole};
use w014_domain::organization::Organization;
use w014_domain::principal::{Principal, PrincipalType};
use w014_domain::program::Program;
use w014_domain::workspace::Workspace;
use w014_persistence::error::PersistenceError;

/// Repository operations for Organizations.
pub struct OrganizationRepository;

impl OrganizationRepository {
    pub async fn insert(tx: &mut PgConnection, org: &Organization) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(org.id.as_uuid())
        .bind(&org.name)
        .bind(&org.slug)
        .bind(org.created_at)
        .bind(org.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn get_by_id(
        tx: &mut PgConnection,
        id: OrganizationId,
    ) -> Result<Option<Organization>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, name, slug, created_at, updated_at
             FROM organizations
             WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let org = Organization::reconstruct(
                    OrganizationId::from_uuid(row.get("id")),
                    row.get("name"),
                    row.get("slug"),
                    row.get("created_at"),
                    row.get("updated_at"),
                )
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(org))
            }
            None => Ok(None),
        }
    }

    pub async fn get_by_slug(
        tx: &mut PgConnection,
        slug: &str,
    ) -> Result<Option<Organization>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, name, slug, created_at, updated_at
             FROM organizations
             WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let org = Organization::reconstruct(
                    OrganizationId::from_uuid(row.get("id")),
                    row.get("name"),
                    row.get("slug"),
                    row.get("created_at"),
                    row.get("updated_at"),
                )
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(org))
            }
            None => Ok(None),
        }
    }
}

/// Repository operations for Principals.
pub struct PrincipalRepository;

impl PrincipalRepository {
    pub async fn insert(
        tx: &mut PgConnection,
        principal: &Principal,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO principals (id, organization_id, principal_type, email, display_name, is_active, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(principal.id.as_uuid())
        .bind(principal.organization_id.as_uuid())
        .bind(principal.principal_type.as_str())
        .bind(&principal.email)
        .bind(&principal.display_name)
        .bind(principal.is_active)
        .bind(principal.created_at)
        .bind(principal.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn get_by_id(
        tx: &mut PgConnection,
        id: PrincipalId,
    ) -> Result<Option<Principal>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, organization_id, principal_type, email, display_name, is_active, created_at, updated_at
             FROM principals
             WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let p_type_str: String = row.get("principal_type");
                let principal_type: PrincipalType =
                    p_type_str
                        .parse()
                        .map_err(|e: w014_domain::error::DomainError| {
                            PersistenceError::Operation(e.to_string())
                        })?;

                let p = Principal::reconstruct(
                    PrincipalId::from_uuid(row.get("id")),
                    OrganizationId::from_uuid(row.get("organization_id")),
                    principal_type,
                    row.get("email"),
                    row.get("display_name"),
                    row.get("is_active"),
                    row.get("created_at"),
                    row.get("updated_at"),
                )
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(p))
            }
            None => Ok(None),
        }
    }

    pub async fn update(
        tx: &mut PgConnection,
        principal: &Principal,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "UPDATE principals
             SET display_name = $2, email = $3, is_active = $4, updated_at = $5
             WHERE id = $1",
        )
        .bind(principal.id.as_uuid())
        .bind(&principal.display_name)
        .bind(&principal.email)
        .bind(principal.is_active)
        .bind(principal.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }
}

/// Repository operations for Programs.
pub struct ProgramRepository;

impl ProgramRepository {
    pub async fn insert(tx: &mut PgConnection, program: &Program) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO programs (id, organization_id, name, slug, description, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(program.id.as_uuid())
        .bind(program.organization_id.as_uuid())
        .bind(&program.name)
        .bind(&program.slug)
        .bind(&program.description)
        .bind(program.created_at)
        .bind(program.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn get_by_id(
        tx: &mut PgConnection,
        id: ProgramId,
    ) -> Result<Option<Program>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, organization_id, name, slug, description, created_at, updated_at
             FROM programs
             WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let p = Program::reconstruct(
                    ProgramId::from_uuid(row.get("id")),
                    OrganizationId::from_uuid(row.get("organization_id")),
                    row.get("name"),
                    row.get("slug"),
                    row.get("description"),
                    row.get("created_at"),
                    row.get("updated_at"),
                )
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(p))
            }
            None => Ok(None),
        }
    }

    pub async fn get_by_organization_and_slug(
        tx: &mut PgConnection,
        org_id: OrganizationId,
        slug: &str,
    ) -> Result<Option<Program>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, organization_id, name, slug, description, created_at, updated_at
             FROM programs
             WHERE organization_id = $1 AND slug = $2",
        )
        .bind(org_id.as_uuid())
        .bind(slug)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let p = Program::reconstruct(
                    ProgramId::from_uuid(row.get("id")),
                    OrganizationId::from_uuid(row.get("organization_id")),
                    row.get("name"),
                    row.get("slug"),
                    row.get("description"),
                    row.get("created_at"),
                    row.get("updated_at"),
                )
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(p))
            }
            None => Ok(None),
        }
    }

    pub async fn list_by_organization(
        tx: &mut PgConnection,
        org_id: OrganizationId,
        cursor: Option<uuid::Uuid>,
        limit: i64,
    ) -> Result<(Vec<Program>, Option<String>, bool), PersistenceError> {
        let fetch_limit = limit + 1;
        let rows = sqlx::query(
            "SELECT id, organization_id, name, slug, description, created_at, updated_at
             FROM programs
             WHERE organization_id = $1
               AND ($2::uuid IS NULL OR id > $2)
             ORDER BY id ASC
             LIMIT $3",
        )
        .bind(org_id.as_uuid())
        .bind(cursor)
        .bind(fetch_limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let has_more = rows.len() as i64 > limit;
        let mut programs = Vec::with_capacity(rows.len().min(limit as usize));
        for row in rows.into_iter().take(limit as usize) {
            let p = Program::reconstruct(
                ProgramId::from_uuid(row.get("id")),
                OrganizationId::from_uuid(row.get("organization_id")),
                row.get("name"),
                row.get("slug"),
                row.get("description"),
                row.get("created_at"),
                row.get("updated_at"),
            )
            .map_err(|e| PersistenceError::Operation(e.to_string()))?;
            programs.push(p);
        }

        let next_cursor = if has_more {
            programs.last().map(|p| p.id.to_string())
        } else {
            None
        };

        Ok((programs, next_cursor, has_more))
    }
}

/// Repository operations for Workspaces.
pub struct WorkspaceRepository;

impl WorkspaceRepository {
    pub async fn insert(tx: &mut PgConnection, ws: &Workspace) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO workspaces (id, program_id, organization_id, name, slug, current_source_state_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(ws.id.as_uuid())
        .bind(ws.program_id.as_uuid())
        .bind(ws.organization_id.as_uuid())
        .bind(&ws.name)
        .bind(&ws.slug)
        .bind(ws.current_source_state_id)
        .bind(ws.created_at)
        .bind(ws.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn get_by_id(
        tx: &mut PgConnection,
        id: WorkspaceId,
    ) -> Result<Option<Workspace>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, program_id, organization_id, name, slug, current_source_state_id, created_at, updated_at
             FROM workspaces
             WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let ws = Workspace::reconstruct(
                    WorkspaceId::from_uuid(row.get("id")),
                    ProgramId::from_uuid(row.get("program_id")),
                    OrganizationId::from_uuid(row.get("organization_id")),
                    row.get("name"),
                    row.get("slug"),
                    row.get("current_source_state_id"),
                    row.get("created_at"),
                    row.get("updated_at"),
                )
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(ws))
            }
            None => Ok(None),
        }
    }

    pub async fn get_by_program_and_slug(
        tx: &mut PgConnection,
        program_id: ProgramId,
        slug: &str,
    ) -> Result<Option<Workspace>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, program_id, organization_id, name, slug, current_source_state_id, created_at, updated_at
             FROM workspaces
             WHERE program_id = $1 AND slug = $2",
        )
        .bind(program_id.as_uuid())
        .bind(slug)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let ws = Workspace::reconstruct(
                    WorkspaceId::from_uuid(row.get("id")),
                    ProgramId::from_uuid(row.get("program_id")),
                    OrganizationId::from_uuid(row.get("organization_id")),
                    row.get("name"),
                    row.get("slug"),
                    row.get("current_source_state_id"),
                    row.get("created_at"),
                    row.get("updated_at"),
                )
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(ws))
            }
            None => Ok(None),
        }
    }

    pub async fn list_by_program(
        tx: &mut PgConnection,
        program_id: ProgramId,
        cursor: Option<uuid::Uuid>,
        limit: i64,
    ) -> Result<(Vec<Workspace>, Option<String>, bool), PersistenceError> {
        let fetch_limit = limit + 1;
        let rows = sqlx::query(
            "SELECT id, program_id, organization_id, name, slug, current_source_state_id, created_at, updated_at
             FROM workspaces
             WHERE program_id = $1
               AND ($2::uuid IS NULL OR id > $2)
             ORDER BY id ASC
             LIMIT $3",
        )
        .bind(program_id.as_uuid())
        .bind(cursor)
        .bind(fetch_limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let has_more = rows.len() as i64 > limit;
        let mut workspaces = Vec::with_capacity(rows.len().min(limit as usize));
        for row in rows.into_iter().take(limit as usize) {
            let ws = Workspace::reconstruct(
                WorkspaceId::from_uuid(row.get("id")),
                ProgramId::from_uuid(row.get("program_id")),
                OrganizationId::from_uuid(row.get("organization_id")),
                row.get("name"),
                row.get("slug"),
                row.get("current_source_state_id"),
                row.get("created_at"),
                row.get("updated_at"),
            )
            .map_err(|e| PersistenceError::Operation(e.to_string()))?;
            workspaces.push(ws);
        }

        let next_cursor = if has_more {
            workspaces.last().map(|w| w.id.to_string())
        } else {
            None
        };

        Ok((workspaces, next_cursor, has_more))
    }
}

/// Repository operations for Memberships.
pub struct MembershipRepository;

impl MembershipRepository {
    pub async fn insert(
        tx: &mut PgConnection,
        membership: &Membership,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO memberships (id, workspace_id, principal_id, role, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(membership.id.as_uuid())
        .bind(membership.workspace_id.as_uuid())
        .bind(membership.principal_id.as_uuid())
        .bind(membership.role.as_str())
        .bind(membership.created_at)
        .bind(membership.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn get_by_id(
        tx: &mut PgConnection,
        id: w014_domain::ids::MembershipId,
    ) -> Result<Option<Membership>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, workspace_id, principal_id, role, created_at, updated_at
             FROM memberships
             WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let role_str: String = row.get("role");
                let role: MembershipRole =
                    role_str
                        .parse()
                        .map_err(|e: w014_domain::error::DomainError| {
                            PersistenceError::Operation(e.to_string())
                        })?;

                Ok(Some(Membership::reconstruct(
                    w014_domain::ids::MembershipId::from_uuid(row.get("id")),
                    WorkspaceId::from_uuid(row.get("workspace_id")),
                    PrincipalId::from_uuid(row.get("principal_id")),
                    role,
                    row.get("created_at"),
                    row.get("updated_at"),
                )))
            }
            None => Ok(None),
        }
    }

    pub async fn get_by_workspace_and_principal(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
    ) -> Result<Option<Membership>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT id, workspace_id, principal_id, role, created_at, updated_at
             FROM memberships
             WHERE workspace_id = $1 AND principal_id = $2",
        )
        .bind(workspace_id.as_uuid())
        .bind(principal_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let role_str: String = row.get("role");
                let role: MembershipRole =
                    role_str
                        .parse()
                        .map_err(|e: w014_domain::error::DomainError| {
                            PersistenceError::Operation(e.to_string())
                        })?;

                Ok(Some(Membership::reconstruct(
                    w014_domain::ids::MembershipId::from_uuid(row.get("id")),
                    WorkspaceId::from_uuid(row.get("workspace_id")),
                    PrincipalId::from_uuid(row.get("principal_id")),
                    role,
                    row.get("created_at"),
                    row.get("updated_at"),
                )))
            }
            None => Ok(None),
        }
    }

    pub async fn list_by_workspace(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        cursor: Option<uuid::Uuid>,
        limit: i64,
    ) -> Result<(Vec<Membership>, Option<String>, bool), PersistenceError> {
        let fetch_limit = limit + 1;
        let rows = sqlx::query(
            "SELECT id, workspace_id, principal_id, role, created_at, updated_at
             FROM memberships
             WHERE workspace_id = $1
               AND ($2::uuid IS NULL OR id > $2)
             ORDER BY id ASC
             LIMIT $3",
        )
        .bind(workspace_id.as_uuid())
        .bind(cursor)
        .bind(fetch_limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let has_more = rows.len() as i64 > limit;
        let mut memberships = Vec::with_capacity(rows.len().min(limit as usize));
        for row in rows.into_iter().take(limit as usize) {
            let role_str: String = row.get("role");
            let role: MembershipRole =
                role_str
                    .parse()
                    .map_err(|e: w014_domain::error::DomainError| {
                        PersistenceError::Operation(e.to_string())
                    })?;

            memberships.push(Membership::reconstruct(
                w014_domain::ids::MembershipId::from_uuid(row.get("id")),
                WorkspaceId::from_uuid(row.get("workspace_id")),
                PrincipalId::from_uuid(row.get("principal_id")),
                role,
                row.get("created_at"),
                row.get("updated_at"),
            ));
        }

        let next_cursor = if has_more {
            memberships.last().map(|m| m.id.to_string())
        } else {
            None
        };

        Ok((memberships, next_cursor, has_more))
    }

    pub async fn update_role(
        tx: &mut PgConnection,
        membership: &Membership,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "UPDATE memberships
             SET role = $2, updated_at = $3
             WHERE id = $1",
        )
        .bind(membership.id.as_uuid())
        .bind(membership.role.as_str())
        .bind(membership.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }
}
