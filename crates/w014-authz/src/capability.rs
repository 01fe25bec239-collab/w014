//! Closed capability representation and identifier types.
//!
//! Distinct special authorities:
//! - OVERRIDE_BLOCK
//! - RIGHTS_REVIEW
//! - RULE_ACTIVATION
//! - GRANT_AUTHORITY (remains independent)

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::AuthzError;

/// Authoritative identifier for a Capability Grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityGrantId(pub Uuid);

impl CapabilityGrantId {
    /// Generates a new random UUID-backed capability grant identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Creates a typed identifier from an existing UUID.
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the underlying raw UUID.
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Consumes self and returns the underlying raw UUID.
    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for CapabilityGrantId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CapabilityGrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for CapabilityGrantId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<CapabilityGrantId> for Uuid {
    fn from(id: CapabilityGrantId) -> Self {
        id.0
    }
}

impl FromStr for CapabilityGrantId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::from_str(s).map(Self)
    }
}

/// Closed semantic representation of system and workspace capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Capability {
    // Special authorities (frozen as distinct)
    OverrideBlock,
    RightsReview,
    RuleActivation,
    GrantAuthority,

    // Standard workspace capabilities
    WorkspaceAdmin,
    WorkspaceRead,
    WorkspaceWrite,
    AuditRead,

    // Named capability for extensible authorization scopes
    Named(String),
}

impl Capability {
    /// Special authority constant strings
    pub const OVERRIDE_BLOCK: &'static str = "OVERRIDE_BLOCK";
    pub const RIGHTS_REVIEW: &'static str = "RIGHTS_REVIEW";
    pub const RULE_ACTIVATION: &'static str = "RULE_ACTIVATION";
    pub const GRANT_AUTHORITY: &'static str = "GRANT_AUTHORITY";

    pub const WORKSPACE_ADMIN: &'static str = "WORKSPACE_ADMIN";
    pub const WORKSPACE_READ: &'static str = "WORKSPACE_READ";
    pub const WORKSPACE_WRITE: &'static str = "WORKSPACE_WRITE";
    pub const AUDIT_READ: &'static str = "AUDIT_READ";

    /// Returns the canonical string representation for persistence and tokens.
    pub fn as_str(&self) -> &str {
        match self {
            Self::OverrideBlock => Self::OVERRIDE_BLOCK,
            Self::RightsReview => Self::RIGHTS_REVIEW,
            Self::RuleActivation => Self::RULE_ACTIVATION,
            Self::GrantAuthority => Self::GRANT_AUTHORITY,
            Self::WorkspaceAdmin => Self::WORKSPACE_ADMIN,
            Self::WorkspaceRead => Self::WORKSPACE_READ,
            Self::WorkspaceWrite => Self::WORKSPACE_WRITE,
            Self::AuditRead => Self::AUDIT_READ,
            Self::Named(name) => name.as_str(),
        }
    }

    /// Checks if this capability is one of the four special authorities.
    pub const fn is_special_authority(&self) -> bool {
        matches!(
            self,
            Self::OverrideBlock | Self::RightsReview | Self::RuleActivation | Self::GrantAuthority
        )
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Capability {
    type Err = AuthzError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(AuthzError::EmptyCapability);
        }

        match trimmed.to_ascii_uppercase().as_str() {
            Self::OVERRIDE_BLOCK => Ok(Self::OverrideBlock),
            Self::RIGHTS_REVIEW => Ok(Self::RightsReview),
            Self::RULE_ACTIVATION => Ok(Self::RuleActivation),
            Self::GRANT_AUTHORITY => Ok(Self::GrantAuthority),
            Self::WORKSPACE_ADMIN => Ok(Self::WorkspaceAdmin),
            Self::WORKSPACE_READ => Ok(Self::WorkspaceRead),
            Self::WORKSPACE_WRITE => Ok(Self::WorkspaceWrite),
            Self::AUDIT_READ => Ok(Self::AuditRead),
            other => {
                // Ensure valid identifier format: uppercase alphanumeric and underscores
                if other
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
                {
                    Ok(Self::Named(other.to_string()))
                } else {
                    Err(AuthzError::InvalidCapability(other.to_string()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_special_authorities_are_distinct() {
        let ob = Capability::OverrideBlock;
        let rr = Capability::RightsReview;
        let ra = Capability::RuleActivation;
        let ga = Capability::GrantAuthority;

        assert_ne!(ob, rr);
        assert_ne!(ob, ra);
        assert_ne!(ob, ga);
        assert_ne!(rr, ra);
        assert_ne!(rr, ga);
        assert_ne!(ra, ga);

        assert!(ob.is_special_authority());
        assert!(rr.is_special_authority());
        assert!(ra.is_special_authority());
        assert!(ga.is_special_authority());

        assert!(!Capability::WorkspaceRead.is_special_authority());
    }

    #[test]
    fn test_capability_roundtrip() {
        let cap: Capability = "OVERRIDE_BLOCK".parse().unwrap();
        assert_eq!(cap, Capability::OverrideBlock);
        assert_eq!(cap.to_string(), "OVERRIDE_BLOCK");

        let custom: Capability = "custom_tool:execute".parse().unwrap();
        assert_eq!(custom, Capability::Named("CUSTOM_TOOL:EXECUTE".to_string()));
    }
}
