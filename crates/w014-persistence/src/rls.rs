//! PostgreSQL Row-Level Security (RLS) Session Management.
//!
//! Provides defense-in-depth tenant isolation by setting session-local PostgreSQL configuration
//! variables within transaction boundaries.

use sqlx::PgConnection;
use uuid::Uuid;

use crate::error::PersistenceError;

/// Sets the session-level current workspace identifier for Row-Level Security (RLS) evaluation.
///
/// Scoped locally to the current transaction (`is_local = true`).
pub async fn set_session_workspace_id(
    tx: &mut PgConnection,
    workspace_id: Uuid,
) -> Result<(), PersistenceError> {
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(tx)
        .await
        .map_err(|e| PersistenceError::Rls(format!("Failed to set RLS workspace context: {e}")))?;

    Ok(())
}

/// Clears the session-level workspace identifier, resetting RLS evaluation to default (restricted) state.
pub async fn clear_session_workspace_id(tx: &mut PgConnection) -> Result<(), PersistenceError> {
    sqlx::query("SELECT set_config('app.current_workspace_id', '', true)")
        .execute(tx)
        .await
        .map_err(|e| {
            PersistenceError::Rls(format!("Failed to clear RLS workspace context: {e}"))
        })?;

    Ok(())
}

/// Retrieves the current session-level workspace identifier, if set.
pub async fn get_session_workspace_id(
    tx: &mut PgConnection,
) -> Result<Option<Uuid>, PersistenceError> {
    let row: Option<String> =
        sqlx::query_scalar("SELECT NULLIF(current_setting('app.current_workspace_id', true), '')")
            .fetch_optional(tx)
            .await
            .map_err(|e| {
                PersistenceError::Rls(format!("Failed to query RLS workspace context: {e}"))
            })?;

    match row {
        Some(s) if !s.is_empty() => {
            let id = Uuid::parse_str(&s)
                .map_err(|e| PersistenceError::Rls(format!("Invalid UUID in RLS context: {e}")))?;
            Ok(Some(id))
        }
        _ => Ok(None),
    }
}
