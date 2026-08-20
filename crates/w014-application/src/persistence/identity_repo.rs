//! PostgreSQL repository operations for Organizations, Principals, Programs, and Workspaces.

use sqlx::{PgConnection, Row};
use w014_domain::ids::{MembershipId, OrganizationId, PrincipalId, ProgramId, WorkspaceId};
use w014_domain::membership::{Membership, MembershipRole};
use w014_domain::organization::Organization;
use w014_domain::principal::Principal;
use w014_domain::program::Program;
use w014_domain::workspace::Workspace;
use w014_persistence::error::PersistenceError;

/// Repository operations for Organizations.
pub struct OrganizationRepository;

impl OrganizationRepository {
    pub async fn insert(tx: &mut PgConnection, org: &Organization) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO organizations (organization_id, display_name, slug, created_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(org.id.as_uuid())
        .bind(&org.display_name)
        .bind(&org.slug)
        .bind(org.created_at)
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
            "SELECT organization_id, display_name, slug, created_at
             FROM organizations
             WHERE organization_id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let org = Organization::reconstruct(
                    OrganizationId::from_uuid(row.get("organization_id")),
                    row.get("display_name"),
                    row.get("slug"),
                    row.get("created_at"),
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
            "SELECT organization_id, display_name, slug, created_at
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
                    OrganizationId::from_uuid(row.get("organization_id")),
                    row.get("display_name"),
                    row.get("slug"),
                    row.get("created_at"),
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
            "INSERT INTO principals (principal_id, display_name, email, status, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(principal.id.as_uuid())
        .bind(&principal.display_name)
        .bind(&principal.email)
        .bind(&principal.status)
        .bind(principal.created_at)
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
            "SELECT principal_id, display_name, email, status, created_at
             FROM principals
             WHERE principal_id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let p = Principal::reconstruct(
                    PrincipalId::from_uuid(row.get("principal_id")),
                    row.get("display_name"),
                    row.get("email"),
                    row.get("status"),
                    row.get("created_at"),
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
             SET display_name = $2, email = $3, status = $4
             WHERE principal_id = $1",
        )
        .bind(principal.id.as_uuid())
        .bind(&principal.display_name)
        .bind(&principal.email)
        .bind(&principal.status)
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
            "INSERT INTO programs (program_id, organization_id, program_code, name, row_version, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(program.id.as_uuid())
        .bind(program.organization_id.as_uuid())
        .bind(&program.program_code)
        .bind(&program.name)
        .bind(program.row_version)
        .bind(program.created_at)
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
            "SELECT program_id, organization_id, program_code, name, row_version, created_at
             FROM programs
             WHERE program_id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let p = Program::reconstruct(
                    ProgramId::from_uuid(row.get("program_id")),
                    OrganizationId::from_uuid(row.get("organization_id")),
                    row.get("program_code"),
                    row.get("name"),
                    row.get("row_version"),
                    row.get("created_at"),
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
        Self::get_by_organization_and_code(tx, org_id, slug).await
    }

    pub async fn get_by_organization_and_code(
        tx: &mut PgConnection,
        org_id: OrganizationId,
        program_code: &str,
    ) -> Result<Option<Program>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT program_id, organization_id, program_code, name, row_version, created_at
             FROM programs
             WHERE organization_id = $1 AND program_code = $2",
        )
        .bind(org_id.as_uuid())
        .bind(program_code)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let p = Program::reconstruct(
                    ProgramId::from_uuid(row.get("program_id")),
                    OrganizationId::from_uuid(row.get("organization_id")),
                    row.get("program_code"),
                    row.get("name"),
                    row.get("row_version"),
                    row.get("created_at"),
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
            "SELECT program_id, organization_id, program_code, name, row_version, created_at
             FROM programs
             WHERE organization_id = $1
               AND ($2::uuid IS NULL OR program_id > $2)
             ORDER BY program_id ASC
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
                ProgramId::from_uuid(row.get("program_id")),
                OrganizationId::from_uuid(row.get("organization_id")),
                row.get("program_code"),
                row.get("name"),
                row.get("row_version"),
                row.get("created_at"),
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

    pub async fn list_all(
        tx: &mut PgConnection,
        cursor: Option<uuid::Uuid>,
        limit: i64,
    ) -> Result<(Vec<Program>, Option<String>, bool), PersistenceError> {
        let fetch_limit = limit + 1;
        let rows = sqlx::query(
            "SELECT program_id, organization_id, program_code, name, row_version, created_at
             FROM programs
             WHERE ($1::uuid IS NULL OR program_id > $1)
             ORDER BY program_id ASC
             LIMIT $2",
        )
        .bind(cursor)
        .bind(fetch_limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let has_more = rows.len() as i64 > limit;
        let mut programs = Vec::with_capacity(rows.len().min(limit as usize));
        for row in rows.into_iter().take(limit as usize) {
            let p = Program::reconstruct(
                ProgramId::from_uuid(row.get("program_id")),
                OrganizationId::from_uuid(row.get("organization_id")),
                row.get("program_code"),
                row.get("name"),
                row.get("row_version"),
                row.get("created_at"),
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
            "INSERT INTO workspaces (workspace_id, program_id, organization_id, workspace_code, name, current_source_state_id, row_version, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(ws.id.as_uuid())
        .bind(ws.program_id.as_uuid())
        .bind(ws.organization_id.as_uuid())
        .bind(&ws.workspace_code)
        .bind(&ws.name)
        .bind(ws.current_source_state_id)
        .bind(ws.row_version)
        .bind(ws.created_at)
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
            "SELECT workspace_id, program_id, organization_id, workspace_code, name, current_source_state_id, row_version, created_at
             FROM workspaces
             WHERE workspace_id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let ws = Workspace::reconstruct(
                    WorkspaceId::from_uuid(row.get("workspace_id")),
                    ProgramId::from_uuid(row.get("program_id")),
                    OrganizationId::from_uuid(row.get("organization_id")),
                    row.get("workspace_code"),
                    row.get("name"),
                    row.get("current_source_state_id"),
                    row.get("row_version"),
                    row.get("created_at"),
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
        Self::get_by_program_and_code(tx, program_id, slug).await
    }

    pub async fn get_by_program_and_code(
        tx: &mut PgConnection,
        program_id: ProgramId,
        workspace_code: &str,
    ) -> Result<Option<Workspace>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT workspace_id, program_id, organization_id, workspace_code, name, current_source_state_id, row_version, created_at
             FROM workspaces
             WHERE program_id = $1 AND workspace_code = $2",
        )
        .bind(program_id.as_uuid())
        .bind(workspace_code)
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let ws = Workspace::reconstruct(
                    WorkspaceId::from_uuid(row.get("workspace_id")),
                    ProgramId::from_uuid(row.get("program_id")),
                    OrganizationId::from_uuid(row.get("organization_id")),
                    row.get("workspace_code"),
                    row.get("name"),
                    row.get("current_source_state_id"),
                    row.get("row_version"),
                    row.get("created_at"),
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
            "SELECT workspace_id, program_id, organization_id, workspace_code, name, current_source_state_id, row_version, created_at
             FROM workspaces
             WHERE program_id = $1
               AND ($2::uuid IS NULL OR workspace_id > $2)
             ORDER BY workspace_id ASC
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
                WorkspaceId::from_uuid(row.get("workspace_id")),
                ProgramId::from_uuid(row.get("program_id")),
                OrganizationId::from_uuid(row.get("organization_id")),
                row.get("workspace_code"),
                row.get("name"),
                row.get("current_source_state_id"),
                row.get("row_version"),
                row.get("created_at"),
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
            "INSERT INTO memberships (membership_id, workspace_id, principal_id, role_code, status, valid_from, valid_until, row_version, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(membership.id.as_uuid())
        .bind(membership.workspace_id.as_uuid())
        .bind(membership.principal_id.as_uuid())
        .bind(membership.role().as_str())
        .bind(&membership.status)
        .bind(membership.valid_from)
        .bind(membership.valid_until)
        .bind(membership.row_version)
        .bind(membership.created_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn get_by_id(
        tx: &mut PgConnection,
        id: MembershipId,
    ) -> Result<Option<Membership>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT membership_id, workspace_id, principal_id, role_code, status, valid_from, valid_until, row_version, created_at
             FROM memberships
             WHERE membership_id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let role_str: String = row.get("role_code");
                let role: MembershipRole =
                    role_str
                        .parse()
                        .map_err(|e: w014_domain::error::DomainError| {
                            PersistenceError::Operation(e.to_string())
                        })?;

                Ok(Some(Membership::reconstruct(
                    MembershipId::from_uuid(row.get("membership_id")),
                    WorkspaceId::from_uuid(row.get("workspace_id")),
                    PrincipalId::from_uuid(row.get("principal_id")),
                    role,
                    row.get("status"),
                    row.get("valid_from"),
                    row.get("valid_until"),
                    row.get("row_version"),
                    row.get("created_at"),
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
            "SELECT membership_id, workspace_id, principal_id, role_code, status, valid_from, valid_until, row_version, created_at
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
                let role_str: String = row.get("role_code");
                let role: MembershipRole =
                    role_str
                        .parse()
                        .map_err(|e: w014_domain::error::DomainError| {
                            PersistenceError::Operation(e.to_string())
                        })?;

                Ok(Some(Membership::reconstruct(
                    MembershipId::from_uuid(row.get("membership_id")),
                    WorkspaceId::from_uuid(row.get("workspace_id")),
                    PrincipalId::from_uuid(row.get("principal_id")),
                    role,
                    row.get("status"),
                    row.get("valid_from"),
                    row.get("valid_until"),
                    row.get("row_version"),
                    row.get("created_at"),
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
            "SELECT membership_id, workspace_id, principal_id, role_code, status, valid_from, valid_until, row_version, created_at
             FROM memberships
             WHERE workspace_id = $1
               AND ($2::uuid IS NULL OR membership_id > $2)
             ORDER BY membership_id ASC
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
            let role_str: String = row.get("role_code");
            let role: MembershipRole =
                role_str
                    .parse()
                    .map_err(|e: w014_domain::error::DomainError| {
                        PersistenceError::Operation(e.to_string())
                    })?;

            memberships.push(Membership::reconstruct(
                MembershipId::from_uuid(row.get("membership_id")),
                WorkspaceId::from_uuid(row.get("workspace_id")),
                PrincipalId::from_uuid(row.get("principal_id")),
                role,
                row.get("status"),
                row.get("valid_from"),
                row.get("valid_until"),
                row.get("row_version"),
                row.get("created_at"),
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
             SET role_code = $2, row_version = row_version + 1
             WHERE membership_id = $1",
        )
        .bind(membership.id.as_uuid())
        .bind(membership.role().as_str())
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }
}
