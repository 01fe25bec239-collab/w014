//! Authorization primitives and capability grant representations for W-014.
//!
//! Note: The WI-0103 capability engine and AuthorizedWorkspaceContext are explicitly deferred.

pub mod capability;
pub mod error;
pub mod grant;

pub use capability::{Capability, CapabilityGrantId};
pub use error::AuthzError;
pub use grant::CapabilityGrant;
