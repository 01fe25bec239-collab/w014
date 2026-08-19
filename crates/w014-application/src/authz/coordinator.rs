//! Workspace Transaction Coordinator and Context Binding.
//!
//! Enforces the required workspace execution order:
//! 1. Authenticate using accepted WI-0102 semantics.
//! 2. Authorize using accepted WI-0103 `AuthorizedWorkspaceContext` / capability semantics.
//! 3. Validate untrusted client-supplied workspace selector against `AuthorizedWorkspaceContext`.
//! 4. Begin owning SQLx application transaction.
//! 5. Set authorized workspace transaction-locally (`set_session_workspace_id`, `is_local = true`).
//! 6. Verify `get_session_workspace_id` equals `AuthorizedWorkspaceContext.workspace_id()`.
//! 7. ONLY THEN execute workspace-scoped tenant SQL operations.
//! 8. Commit/rollback ends and clears the transaction-local context.

use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use std::future::Future;
use uuid::Uuid;
use w014_authz::authority::SpecialAuthority;
use w014_authz::authorized_workspace_context::AuthorizedWorkspaceContext;
use w014_authz::capability::Capability;
use w014_authz::error::AuthzError;
use w014_domain::ids::WorkspaceId;
use w014_persistence::error::PersistenceError;
use w014_persistence::rls::set_session_workspace_id;

use crate::error::ApplicationError;

/// Queries the current transaction-local RLS workspace ID, returning `None` if unset.
pub async fn get_current_workspace_id(
    tx: &mut PgConnection,
) -> Result<Option<Uuid>, ApplicationError> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT NULLIF(current_setting('app.current_workspace_id', true), '')")
            .fetch_one(tx)
            .await
            .map_err(|e| ApplicationError::Persistence(PersistenceError::Connection(e)))?;

    match raw {
        Some(s) if !s.trim().is_empty() => {
            let id = Uuid::parse_str(s.trim()).map_err(|e| {
                ApplicationError::Internal(format!("Invalid UUID in RLS context: {e}"))
            })?;
            Ok(Some(id))
        }
        _ => Ok(None),
    }
}

/// Database roles for scoped PostgreSQL execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseRole {
    App,
    Readonly,
}

impl DatabaseRole {
    pub const fn as_set_role_sql(&self) -> &'static str {
        match self {
            Self::App => "SET LOCAL ROLE w014_app",
            Self::Readonly => "SET LOCAL ROLE w014_readonly",
        }
    }
}

/// Configuration options for workspace-scoped transactions.
#[derive(Debug, Clone, Default)]
pub struct WorkspaceTxOptions {
    /// Untrusted client-supplied workspace ID selector (e.g. from URL path or body).
    pub client_workspace_id: Option<WorkspaceId>,
    /// Capabilities required for this operation (checked in Rust authz before SQL).
    pub required_capabilities: Vec<Capability>,
    /// Special authorities required for this operation (checked in Rust authz before SQL).
    pub required_special_authorities: Vec<SpecialAuthority>,
    /// Optional PostgreSQL role to switch to for this transaction (e.g. `w014_app`).
    pub db_role: Option<DatabaseRole>,
}

impl WorkspaceTxOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_client_workspace(mut self, ws_id: WorkspaceId) -> Self {
        self.client_workspace_id = Some(ws_id);
        self
    }

    pub fn with_capability(mut self, capability: Capability) -> Self {
        self.required_capabilities.push(capability);
        self
    }

    pub fn with_capabilities(mut self, capabilities: impl IntoIterator<Item = Capability>) -> Self {
        self.required_capabilities.extend(capabilities);
        self
    }

    pub fn with_special_authority(mut self, authority: SpecialAuthority) -> Self {
        self.required_special_authorities.push(authority);
        self
    }

    pub fn with_role(mut self, role: DatabaseRole) -> Self {
        self.db_role = Some(role);
        self
    }
}

/// An active workspace-scoped application transaction.
///
/// Owns the underlying SQLx transaction and binds the authoritative `AuthorizedWorkspaceContext`
/// to PostgreSQL transaction-local RLS (`app.current_workspace_id`).
pub struct WorkspaceTransaction<'a> {
    tx: Transaction<'a, Postgres>,
    awc: &'a AuthorizedWorkspaceContext,
}

impl<'a> WorkspaceTransaction<'a> {
    /// Begins an outer application transaction with verified RLS context binding.
    pub async fn begin(
        pool: &'a PgPool,
        awc: &'a AuthorizedWorkspaceContext,
        options: WorkspaceTxOptions,
    ) -> Result<Self, ApplicationError> {
        // 1. Validate client selector
        WorkspaceTransactionCoordinator::validate_client_workspace(
            awc,
            options.client_workspace_id,
        )?;

        // 2. Primary Rust authorization check
        WorkspaceTransactionCoordinator::evaluate_rust_authz(awc, &options)?;

        // 3. Begin transaction
        let mut tx = pool.begin().await.map_err(PersistenceError::Connection)?;

        // 4. Role switch if configured
        if let Some(role) = options.db_role {
            match sqlx::query(role.as_set_role_sql()).execute(&mut *tx).await {
                Ok(_) => {}
                Err(e) => {
                    let _ = tx.rollback().await;
                    return Err(ApplicationError::Persistence(PersistenceError::Connection(
                        e,
                    )));
                }
            }
        }

        // 5. Set transaction-local RLS context
        if let Err(e) = set_session_workspace_id(&mut tx, awc.workspace_id().into_uuid()).await {
            let _ = tx.rollback().await;
            return Err(ApplicationError::Persistence(e));
        }

        // 6. Verify RLS context
        match get_current_workspace_id(&mut tx).await {
            Ok(Some(ws_id)) if ws_id == awc.workspace_id().into_uuid() => {
                // Verified
            }
            Ok(other) => {
                let _ = tx.rollback().await;
                return Err(ApplicationError::RlsContextVerificationFailed {
                    expected: awc.workspace_id().into_uuid(),
                    actual: other,
                });
            }
            Err(e) => {
                let _ = tx.rollback().await;
                return Err(e);
            }
        }

        Ok(Self { tx, awc })
    }

    /// Access the transaction's database connection.
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    /// Access the authoritative workspace context.
    pub fn awc(&self) -> &AuthorizedWorkspaceContext {
        self.awc
    }

    /// Commits the outer transaction, ending and clearing the transaction-local RLS context.
    pub async fn commit(self) -> Result<(), ApplicationError> {
        self.tx
            .commit()
            .await
            .map_err(|e| ApplicationError::Persistence(PersistenceError::Connection(e)))
    }

    /// Rolls back the outer transaction, ending and clearing the transaction-local RLS context.
    pub async fn rollback(self) -> Result<(), ApplicationError> {
        self.tx
            .rollback()
            .await
            .map_err(|e| ApplicationError::Persistence(PersistenceError::Connection(e)))
    }
}

/// Coordinator for workspace-scoped application transactions.
pub struct WorkspaceTransactionCoordinator;

impl WorkspaceTransactionCoordinator {
    /// Validates an untrusted client-supplied workspace selector against the authoritative context.
    ///
    /// Fails closed if the client-supplied workspace selector does not match the authoritative context.
    pub fn validate_client_workspace(
        awc: &AuthorizedWorkspaceContext,
        client_workspace_id: Option<WorkspaceId>,
    ) -> Result<(), ApplicationError> {
        if let Some(client_ws) = client_workspace_id
            && client_ws != awc.workspace_id()
        {
            return Err(ApplicationError::Authz(AuthzError::WorkspaceMismatch {
                expected: awc.workspace_id(),
                actual: client_ws,
            }));
        }
        Ok(())
    }

    /// Evaluates primary Rust authorization requirements against the authoritative context.
    ///
    /// Fails closed before any database transaction or tenant SQL is executed.
    pub fn evaluate_rust_authz(
        awc: &AuthorizedWorkspaceContext,
        options: &WorkspaceTxOptions,
    ) -> Result<(), ApplicationError> {
        for capability in &options.required_capabilities {
            awc.require(capability).map_err(ApplicationError::Authz)?;
        }
        for authority in &options.required_special_authorities {
            awc.require_special_authority(*authority)
                .map_err(ApplicationError::Authz)?;
        }
        Ok(())
    }

    /// Binds and verifies transaction-local RLS context on an existing transaction.
    ///
    /// Execution order:
    /// 1. Validates client workspace match.
    /// 2. Evaluates Rust capability requirements (Primary authz).
    /// 3. Sets optional local database role (if configured).
    /// 4. Sets transaction-local RLS workspace ID (`is_local = true`).
    /// 5. Queries and verifies `current_setting('app.current_workspace_id', true)` matches `awc.workspace_id()`.
    pub async fn bind_and_verify_tx(
        tx: &mut PgConnection,
        awc: &AuthorizedWorkspaceContext,
        options: &WorkspaceTxOptions,
    ) -> Result<(), ApplicationError> {
        // 1. Validate client selector
        Self::validate_client_workspace(awc, options.client_workspace_id)?;

        // 2. Primary Rust authorization check
        Self::evaluate_rust_authz(awc, options)?;

        // 3. Optional DB role switch
        if let Some(role) = options.db_role {
            sqlx::query(role.as_set_role_sql())
                .execute(&mut *tx)
                .await
                .map_err(PersistenceError::Connection)?;
        }

        // 4. Set transaction-local RLS context
        set_session_workspace_id(tx, awc.workspace_id().into_uuid()).await?;

        // 5. Verify RLS context
        let current_ctx = get_current_workspace_id(tx).await?;
        if current_ctx != Some(awc.workspace_id().into_uuid()) {
            return Err(ApplicationError::RlsContextVerificationFailed {
                expected: awc.workspace_id().into_uuid(),
                actual: current_ctx,
            });
        }

        Ok(())
    }

    /// Executes a workspace-scoped tenant operation within an isolated, outer-owned application transaction.
    ///
    /// Guarantees:
    /// - Untrusted client selector validation before SQL.
    /// - Primary Rust capability and special-authority checks before SQL.
    /// - Transaction-local RLS workspace context set and verified before tenant operation.
    /// - Outer transaction owns commit / rollback.
    /// - Connection pool isolation: context is wiped on transaction termination (commit or rollback).
    pub async fn execute_in_scope<Fut, T>(
        pool: &PgPool,
        awc: &AuthorizedWorkspaceContext,
        options: WorkspaceTxOptions,
        operation: impl FnOnce(&mut PgConnection, &AuthorizedWorkspaceContext) -> Fut,
    ) -> Result<T, ApplicationError>
    where
        Fut: Future<Output = Result<T, ApplicationError>>,
    {
        let mut ws_tx = WorkspaceTransaction::begin(pool, awc, options).await?;
        let op_result = operation(ws_tx.conn(), awc).await;
        match op_result {
            Ok(value) => {
                ws_tx.commit().await?;
                Ok(value)
            }
            Err(err) => {
                let _ = ws_tx.rollback().await;
                Err(err)
            }
        }
    }

    /// Convenience wrapper to execute an operation requiring a single capability.
    pub async fn execute_with_capability<Fut, T>(
        pool: &PgPool,
        awc: &AuthorizedWorkspaceContext,
        capability: Capability,
        operation: impl FnOnce(&mut PgConnection, &AuthorizedWorkspaceContext) -> Fut,
    ) -> Result<T, ApplicationError>
    where
        Fut: Future<Output = Result<T, ApplicationError>>,
    {
        Self::execute_in_scope(
            pool,
            awc,
            WorkspaceTxOptions::new().with_capability(capability),
            operation,
        )
        .await
    }
}
