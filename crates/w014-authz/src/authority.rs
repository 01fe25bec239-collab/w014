//! Frozen special authority representations and separation invariants.
//!
//! Distinct special authorities:
//! - OVERRIDE_BLOCK: Authority to override workflow or system safety blocks.
//! - RIGHTS_REVIEW: Authority to conduct compliance, rights, and access reviews.
//! - RULE_ACTIVATION: Authority to activate, deactivate, or modify enforcement rules.
//! - GRANT_AUTHORITY: Authority to grant capabilities to other principals.
//!
//! Invariants:
//! 1. Distinctness: Each special authority is mutually exclusive and distinct from all others.
//! 2. Independence: No special authority implies or inherits any other special authority.
//! 3. Separation from Roles: Special authorities are NEVER granted implicitly through role profiles
//!    (including Owner and Admin). They MUST be granted via explicit, individual CapabilityGrant.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::capability::Capability;
use crate::error::AuthzError;

/// Enumeration of frozen special authorities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpecialAuthority {
    OverrideBlock,
    RightsReview,
    RuleActivation,
    GrantAuthority,
}

impl SpecialAuthority {
    pub const OVERRIDE_BLOCK: &'static str = "OVERRIDE_BLOCK";
    pub const RIGHTS_REVIEW: &'static str = "RIGHTS_REVIEW";
    pub const RULE_ACTIVATION: &'static str = "RULE_ACTIVATION";
    pub const GRANT_AUTHORITY: &'static str = "GRANT_AUTHORITY";

    /// All special authorities defined in the frozen model.
    pub const ALL: &'static [SpecialAuthority] = &[
        Self::OverrideBlock,
        Self::RightsReview,
        Self::RuleActivation,
        Self::GrantAuthority,
    ];

    /// Returns the canonical string representation for this special authority.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::OverrideBlock => Self::OVERRIDE_BLOCK,
            Self::RightsReview => Self::RIGHTS_REVIEW,
            Self::RuleActivation => Self::RULE_ACTIVATION,
            Self::GrantAuthority => Self::GRANT_AUTHORITY,
        }
    }

    /// Converts this special authority into its corresponding `Capability`.
    pub fn to_capability(&self) -> Capability {
        match self {
            Self::OverrideBlock => Capability::OverrideBlock,
            Self::RightsReview => Capability::RightsReview,
            Self::RuleActivation => Capability::RuleActivation,
            Self::GrantAuthority => Capability::GrantAuthority,
        }
    }

    /// Attempts to extract a `SpecialAuthority` from a `Capability`.
    pub fn from_capability(cap: &Capability) -> Option<Self> {
        match cap {
            Capability::OverrideBlock => Some(Self::OverrideBlock),
            Capability::RightsReview => Some(Self::RightsReview),
            Capability::RuleActivation => Some(Self::RuleActivation),
            Capability::GrantAuthority => Some(Self::GrantAuthority),
            _ => None,
        }
    }

    /// Checks whether the given capability string matches a special authority.
    pub fn is_special_str(s: &str) -> bool {
        matches!(
            s.trim().to_ascii_uppercase().as_str(),
            Self::OVERRIDE_BLOCK
                | Self::RIGHTS_REVIEW
                | Self::RULE_ACTIVATION
                | Self::GRANT_AUTHORITY
        )
    }
}

impl fmt::Display for SpecialAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for SpecialAuthority {
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
            other => Err(AuthzError::InvalidCapability(other.to_string())),
        }
    }
}

impl From<SpecialAuthority> for Capability {
    fn from(auth: SpecialAuthority) -> Self {
        auth.to_capability()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_special_authority_constants_and_roundtrip() {
        for auth in SpecialAuthority::ALL {
            let s = auth.as_str();
            let parsed: SpecialAuthority = s.parse().unwrap();
            assert_eq!(*auth, parsed);

            let cap = auth.to_capability();
            assert_eq!(SpecialAuthority::from_capability(&cap), Some(*auth));
            assert!(cap.is_special_authority());
        }
    }

    #[test]
    fn test_special_authority_distinctness() {
        let all = SpecialAuthority::ALL;
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j]);
                assert_ne!(all[i].as_str(), all[j].as_str());
                assert_ne!(all[i].to_capability(), all[j].to_capability());
            }
        }
    }

    #[test]
    fn test_non_special_capability_returns_none() {
        assert_eq!(
            SpecialAuthority::from_capability(&Capability::WorkspaceAdmin),
            None
        );
        assert_eq!(
            SpecialAuthority::from_capability(&Capability::WorkspaceRead),
            None
        );
        assert_eq!(
            SpecialAuthority::from_capability(&Capability::WorkspaceWrite),
            None
        );
        assert_eq!(
            SpecialAuthority::from_capability(&Capability::AuditRead),
            None
        );
        assert_eq!(
            SpecialAuthority::from_capability(&Capability::Named("CUSTOM".to_string())),
            None
        );
    }
}
