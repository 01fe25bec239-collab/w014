//! PostgreSQL repository operations for Capability Grants.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
use w014_authz::capability::{Capability, CapabilityGrantId};
use w014_authz::grant::CapabilityGrant;
use w014_domain::ids::{PrincipalId, WorkspaceId};
use w014_persistence::error::PersistenceError;

/// Repository operations for Capability Grants.
pub struct CapabilityGrantRepository;

impl CapabilityGrantRepository {
    pub async fn insert(
        tx: &mut PgConnection,
        grant: &CapabilityGrant,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO capability_grants (id, workspace_id, principal_id, capability, granted_by, granted_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(grant.id.as_uuid())
        .bind(grant.workspace_id.as_uuid())
        .bind(grant.principal_id.as_uuid())
        .bind(grant.capability.as_str())
        .bind(grant.granted_by.map(|id| id.as_uuid()))
        .bind(grant.granted_at)
        .bind(grant.expires_at)
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
            "SELECT id, workspace_id, principal_id, capability, granted_by, granted_at, expires_at
             FROM capability_grants
             WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let cap_str: String = row.get("capability");
                let capability: Capability =
                    cap_str
                        .parse()
                        .map_err(|e: w014_authz::error::AuthzError| {
                            PersistenceError::Operation(e.to_string())
                        })?;

                let granted_by_uuid: Option<Uuid> = row.get("granted_by");

                Ok(Some(CapabilityGrant::reconstruct(
                    CapabilityGrantId::from_uuid(row.get("id")),
                    WorkspaceId::from_uuid(row.get("workspace_id")),
                    PrincipalId::from_uuid(row.get("principal_id")),
                    capability,
                    granted_by_uuid.map(PrincipalId::from_uuid),
                    row.get("granted_at"),
                    row.get("expires_at"),
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
            "SELECT id, workspace_id, principal_id, capability, granted_by, granted_at, expires_at
             FROM capability_grants
             WHERE workspace_id = $1 AND principal_id = $2 AND capability = $3",
        )
        .bind(workspace_id.as_uuid())
        .bind(principal_id.as_uuid())
        .bind(capability.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let cap_str: String = row.get("capability");
                let cap: Capability =
                    cap_str
                        .parse()
                        .map_err(|e: w014_authz::error::AuthzError| {
                            PersistenceError::Operation(e.to_string())
                        })?;

                let granted_by_uuid: Option<Uuid> = row.get("granted_by");

                Ok(Some(CapabilityGrant::reconstruct(
                    CapabilityGrantId::from_uuid(row.get("id")),
                    WorkspaceId::from_uuid(row.get("workspace_id")),
                    PrincipalId::from_uuid(row.get("principal_id")),
                    cap,
                    granted_by_uuid.map(PrincipalId::from_uuid),
                    row.get("granted_at"),
                    row.get("expires_at"),
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
            "SELECT id, workspace_id, principal_id, capability, granted_by, granted_at, expires_at
             FROM capability_grants
             WHERE workspace_id = $1 AND principal_id = $2
             ORDER BY granted_at ASC",
        )
        .bind(workspace_id.as_uuid())
        .bind(principal_id.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let mut grants = Vec::with_capacity(rows.len());
        for row in rows {
            let cap_str: String = row.get("capability");
            let capability: Capability =
                cap_str
                    .parse()
                    .map_err(|e: w014_authz::error::AuthzError| {
                        PersistenceError::Operation(e.to_string())
                    })?;

            let granted_by_uuid: Option<Uuid> = row.get("granted_by");

            grants.push(CapabilityGrant::reconstruct(
                CapabilityGrantId::from_uuid(row.get("id")),
                WorkspaceId::from_uuid(row.get("workspace_id")),
                PrincipalId::from_uuid(row.get("principal_id")),
                capability,
                granted_by_uuid.map(PrincipalId::from_uuid),
                row.get("granted_at"),
                row.get("expires_at"),
            ));
        }

        Ok(grants)
    }

    pub async fn update_expiry(
        tx: &mut PgConnection,
        grant_id: CapabilityGrantId,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "UPDATE capability_grants
             SET expires_at = $2
             WHERE id = $1",
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
            "SELECT id, workspace_id, principal_id, capability, granted_by, granted_at, expires_at
             FROM capability_grants
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
        let mut grants = Vec::with_capacity(rows.len().min(limit as usize));
        for row in rows.into_iter().take(limit as usize) {
            let cap_str: String = row.get("capability");
            let capability: Capability =
                cap_str
                    .parse()
                    .map_err(|e: w014_authz::error::AuthzError| {
                        PersistenceError::Operation(e.to_string())
                    })?;
            let granted_by_uuid: Option<Uuid> = row.get("granted_by");

            grants.push(CapabilityGrant::reconstruct(
                CapabilityGrantId::from_uuid(row.get("id")),
                WorkspaceId::from_uuid(row.get("workspace_id")),
                PrincipalId::from_uuid(row.get("principal_id")),
                capability,
                granted_by_uuid.map(PrincipalId::from_uuid),
                row.get("granted_at"),
                row.get("expires_at"),
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
