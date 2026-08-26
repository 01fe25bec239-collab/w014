//! Error surface for Document-Pipeline persistence-facing row contracts.

use thiserror::Error;
use w014_domain::DomainError;

/// Errors raised while projecting domain facts onto physical rows or
/// reconstructing domain facts from stored rows.
#[derive(Debug, Error)]
pub enum ContractError {
    /// The stored row violated a frozen closed-domain, bound, or lifecycle
    /// invariant during reconstruction.
    #[error("row shape violation in {table}.{field}: {reason}")]
    RowShape {
        table: &'static str,
        field: &'static str,
        reason: String,
    },

    /// A JSONB fixed-key convention value was missing or ill-formed.
    #[error("json convention violation for key '{key}' in {context}: {reason}")]
    JsonConvention {
        key: &'static str,
        context: &'static str,
        reason: String,
    },

    /// A domain invariant failed during projection or reconstruction.
    #[error(transparent)]
    Domain(#[from] DomainError),
}

/// Convenient result alias for the contract layer.
pub type ContractResult<T> = Result<T, ContractError>;
