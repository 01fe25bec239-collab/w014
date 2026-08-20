//! PostgreSQL repository operations for Capability Grants.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
use w014_authz::capability::{Capability, CapabilityGrantId};
use w014_authz::grant::CapabilityGrant;
use w014_domain::ids::{PrincipalId, ProgramId, WorkspaceId};
use w014_persistence::error::PersistenceError;

/// Repository operations for Capability Grants.
pub struct CapabilityGrantRepository;

impl CapabilityGrantRepository {
    pub async fn insert(
        tx: &mut PgConnection,
        grant: &CapabilityGrant,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO capability_grants (capability_grant_id, workspace_id, program_id, principal_id, capability_code, granted_by_principal_id, granted_at, expires_at, revoked_at, revoked_by_principal_id, grant_reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(grant.id.as_uuid())
        .bind(grant.workspace_id.map(|id| id.as_uuid()))
        .bind(grant.program_id.map(|id| id.as_uuid()))
        .bind(grant.principal_id.as_uuid())
        .bind(grant.capability.as_str())
        .bind(grant.granted_by.map(|id| id.as_uuid()))
        .bind(grant.granted_at)
        .bind(grant.expires_at)
        .bind(grant.revoked_at)
        .bind(grant.revoked_by.map(|id| id.as_uuid()))
        .bind(&grant.grant_reason)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn get_by_id(
        tx: &mut PgConnection,
        id: CapabilityGrantId,
    ) -> Result<Option<CapabilityGrant>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT capability_grant_id, workspace_id, program_id, principal_id, capability_code, granted_by_principal_id, granted_at, expires_at, revoked_at, revoked_by_principal_id, grant_reason
             FROM capability_grants
             WHERE capability_grant_id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let cap_str: String = row.get("capability_code");
                let capability: Capability =
                    cap_str
                        .parse()
                        .map_err(|e: w014_authz::error::AuthzError| {
                            PersistenceError::Operation(e.to_string())
                        })?;

                let ws_uuid: Option<Uuid> = row.get("workspace_id");
                let prog_uuid: Option<Uuid> = row.get("program_id");
                let granted_by_uuid: Option<Uuid> = row.get("granted_by_principal_id");
                let revoked_by_uuid: Option<Uuid> = row.get("revoked_by_principal_id");

                Ok(Some(CapabilityGrant::reconstruct(
                    CapabilityGrantId::from_uuid(row.get("capability_grant_id")),
                    ws_uuid.map(WorkspaceId::from_uuid),
                    prog_uuid.map(ProgramId::from_uuid),
                    PrincipalId::from_uuid(row.get("principal_id")),
                    capability,
                    granted_by_uuid.map(PrincipalId::from_uuid),
                    row.get("granted_at"),
                    row.get("expires_at"),
                    row.get("revoked_at"),
                    revoked_by_uuid.map(PrincipalId::from_uuid),
                    row.get("grant_reason"),
                )))
            }
            None => Ok(None),
        }
    }

    pub async fn get_by_workspace_principal_capability(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        capability: &Capability,
    ) -> Result<Option<CapabilityGrant>, PersistenceError> {
        let row_opt = sqlx::query(
            "SELECT capability_grant_id, workspace_id, program_id, principal_id, capability_code, granted_by_principal_id, granted_at, expires_at, revoked_at, revoked_by_principal_id, grant_reason
             FROM capability_grants
             WHERE workspace_id = $1 AND principal_id = $2 AND capability_code = $3 AND revoked_at IS NULL",
        )
        .bind(workspace_id.as_uuid())
        .bind(principal_id.as_uuid())
        .bind(capability.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let cap_str: String = row.get("capability_code");
                let cap: Capability =
                    cap_str
                        .parse()
                        .map_err(|e: w014_authz::error::AuthzError| {
                            PersistenceError::Operation(e.to_string())
                        })?;

                let ws_uuid: Option<Uuid> = row.get("workspace_id");
                let prog_uuid: Option<Uuid> = row.get("program_id");
                let granted_by_uuid: Option<Uuid> = row.get("granted_by_principal_id");
                let revoked_by_uuid: Option<Uuid> = row.get("revoked_by_principal_id");

                Ok(Some(CapabilityGrant::reconstruct(
                    CapabilityGrantId::from_uuid(row.get("capability_grant_id")),
                    ws_uuid.map(WorkspaceId::from_uuid),
                    prog_uuid.map(ProgramId::from_uuid),
                    PrincipalId::from_uuid(row.get("principal_id")),
                    cap,
                    granted_by_uuid.map(PrincipalId::from_uuid),
                    row.get("granted_at"),
                    row.get("expires_at"),
                    row.get("revoked_at"),
                    revoked_by_uuid.map(PrincipalId::from_uuid),
                    row.get("grant_reason"),
                )))
            }
            None => Ok(None),
        }
    }

    pub async fn get_by_workspace_and_principal(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
    ) -> Result<Vec<CapabilityGrant>, PersistenceError> {
        let rows = sqlx::query(
            "SELECT capability_grant_id, workspace_id, program_id, principal_id, capability_code, granted_by_principal_id, granted_at, expires_at, revoked_at, revoked_by_principal_id, grant_reason
             FROM capability_grants
             WHERE workspace_id = $1 AND principal_id = $2 AND revoked_at IS NULL
             ORDER BY granted_at ASC",
        )
        .bind(workspace_id.as_uuid())
        .bind(principal_id.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let mut grants = Vec::with_capacity(rows.len());
        for row in rows {
            let cap_str: String = row.get("capability_code");
            let capability: Capability =
                cap_str
                    .parse()
                    .map_err(|e: w014_authz::error::AuthzError| {
                        PersistenceError::Operation(e.to_string())
                    })?;

            let ws_uuid: Option<Uuid> = row.get("workspace_id");
            let prog_uuid: Option<Uuid> = row.get("program_id");
            let granted_by_uuid: Option<Uuid> = row.get("granted_by_principal_id");
            let revoked_by_uuid: Option<Uuid> = row.get("revoked_by_principal_id");

            grants.push(CapabilityGrant::reconstruct(
                CapabilityGrantId::from_uuid(row.get("capability_grant_id")),
                ws_uuid.map(WorkspaceId::from_uuid),
                prog_uuid.map(ProgramId::from_uuid),
                PrincipalId::from_uuid(row.get("principal_id")),
                capability,
                granted_by_uuid.map(PrincipalId::from_uuid),
                row.get("granted_at"),
                row.get("expires_at"),
                row.get("revoked_at"),
                revoked_by_uuid.map(PrincipalId::from_uuid),
                row.get("grant_reason"),
            ));
        }

        Ok(grants)
    }

    pub async fn get_active_for_context(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        program_id: ProgramId,
        principal_id: PrincipalId,
    ) -> Result<Vec<CapabilityGrant>, PersistenceError> {
        let rows = sqlx::query(
            "SELECT capability_grant_id, workspace_id, program_id, principal_id, capability_code, granted_by_principal_id, granted_at, expires_at, revoked_at, revoked_by_principal_id, grant_reason
             FROM capability_grants
             WHERE (workspace_id = $1 OR program_id = $2)
               AND principal_id = $3
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
             ORDER BY granted_at ASC",
        )
        .bind(workspace_id.as_uuid())
        .bind(program_id.as_uuid())
        .bind(principal_id.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let mut grants = Vec::with_capacity(rows.len());
        for row in rows {
            let cap_str: String = row.get("capability_code");
            let capability: Capability =
                cap_str
                    .parse()
                    .map_err(|e: w014_authz::error::AuthzError| {
                        PersistenceError::Operation(e.to_string())
                    })?;

            let ws_uuid: Option<Uuid> = row.get("workspace_id");
            let prog_uuid: Option<Uuid> = row.get("program_id");
            let granted_by_uuid: Option<Uuid> = row.get("granted_by_principal_id");
            let revoked_by_uuid: Option<Uuid> = row.get("revoked_by_principal_id");

            grants.push(CapabilityGrant::reconstruct(
                CapabilityGrantId::from_uuid(row.get("capability_grant_id")),
                ws_uuid.map(WorkspaceId::from_uuid),
                prog_uuid.map(ProgramId::from_uuid),
                PrincipalId::from_uuid(row.get("principal_id")),
                capability,
                granted_by_uuid.map(PrincipalId::from_uuid),
                row.get("granted_at"),
                row.get("expires_at"),
                row.get("revoked_at"),
                revoked_by_uuid.map(PrincipalId::from_uuid),
                row.get("grant_reason"),
            ));
        }

        Ok(grants)
    }

    pub async fn revoke(
        tx: &mut PgConnection,
        grant_id: CapabilityGrantId,
        revoked_at: DateTime<Utc>,
        revoked_by: Option<PrincipalId>,
        reason: Option<&str>,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "UPDATE capability_grants
             SET revoked_at = $2, revoked_by_principal_id = $3, grant_reason = COALESCE($4, grant_reason)
             WHERE capability_grant_id = $1 AND revoked_at IS NULL",
        )
        .bind(grant_id.as_uuid())
        .bind(revoked_at)
        .bind(revoked_by.map(|id| id.as_uuid()))
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn update_expiry(
        tx: &mut PgConnection,
        grant_id: CapabilityGrantId,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "UPDATE capability_grants
             SET expires_at = $2
             WHERE capability_grant_id = $1",
        )
        .bind(grant_id.as_uuid())
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    pub async fn list_by_workspace(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        cursor: Option<uuid::Uuid>,
        limit: i64,
    ) -> Result<(Vec<CapabilityGrant>, Option<String>, bool), PersistenceError> {
        let fetch_limit = limit + 1;
        let rows = sqlx::query(
            "SELECT capability_grant_id, workspace_id, program_id, principal_id, capability_code, granted_by_principal_id, granted_at, expires_at, revoked_at, revoked_by_principal_id, grant_reason
             FROM capability_grants
             WHERE workspace_id = $1
               AND ($2::uuid IS NULL OR capability_grant_id > $2)
             ORDER BY capability_grant_id ASC
             LIMIT $3",
        )
        .bind(workspace_id.as_uuid())
        .bind(cursor)
        .bind(fetch_limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let has_more = rows.len() as i64 > limit;
        let mut grants = Vec::with_capacity(rows.len().min(limit as usize));
        for row in rows.into_iter().take(limit as usize) {
            let cap_str: String = row.get("capability_code");
            let capability: Capability =
                cap_str
                    .parse()
                    .map_err(|e: w014_authz::error::AuthzError| {
                        PersistenceError::Operation(e.to_string())
                    })?;
            let ws_uuid: Option<Uuid> = row.get("workspace_id");
            let prog_uuid: Option<Uuid> = row.get("program_id");
            let granted_by_uuid: Option<Uuid> = row.get("granted_by_principal_id");
            let revoked_by_uuid: Option<Uuid> = row.get("revoked_by_principal_id");

            grants.push(CapabilityGrant::reconstruct(
                CapabilityGrantId::from_uuid(row.get("capability_grant_id")),
                ws_uuid.map(WorkspaceId::from_uuid),
                prog_uuid.map(ProgramId::from_uuid),
                PrincipalId::from_uuid(row.get("principal_id")),
                capability,
                granted_by_uuid.map(PrincipalId::from_uuid),
                row.get("granted_at"),
                row.get("expires_at"),
                row.get("revoked_at"),
                revoked_by_uuid.map(PrincipalId::from_uuid),
                row.get("grant_reason"),
            ));
        }

        let next_cursor = if has_more {
            grants.last().map(|g| g.id.to_string())
        } else {
            None
        };

        Ok((grants, next_cursor, has_more))
    }
}
