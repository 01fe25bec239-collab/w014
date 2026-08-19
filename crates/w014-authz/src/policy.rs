//! Policy rules, deterministic allow/deny decisions, and policy evaluation engine.

use serde::{Deserialize, Serialize};

use crate::authority::SpecialAuthority;
use crate::capability::Capability;
use crate::capability_set::CapabilitySet;
use crate::error::AuthzError;

/// Specification of capability requirements for an authorization policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyRule {
    /// Requires a single specific capability.
    Require(Capability),
    /// Requires all specified capabilities to be present.
    RequireAll(Vec<Capability>),
    /// Requires at least one of the specified capabilities to be present.
    RequireAny(Vec<Capability>),
    /// Requires a specific frozen special authority.
    RequireSpecial(SpecialAuthority),
}

impl PolicyRule {
    pub fn require(cap: Capability) -> Self {
        Self::Require(cap)
    }

    pub fn require_all(caps: impl IntoIterator<Item = Capability>) -> Self {
        Self::RequireAll(caps.into_iter().collect())
    }

    pub fn require_any(caps: impl IntoIterator<Item = Capability>) -> Self {
        Self::RequireAny(caps.into_iter().collect())
    }

    pub fn require_special(auth: SpecialAuthority) -> Self {
        Self::RequireSpecial(auth)
    }
}

/// Detailed reason why an authorization request was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyReason {
    MissingCapability(Capability),
    MissingAllOf(Vec<Capability>),
    MissingAnyOf(Vec<Capability>),
    MissingSpecialAuthority(SpecialAuthority),
    Custom(String),
}

impl DenyReason {
    pub fn to_authz_error(&self) -> AuthzError {
        match self {
            Self::MissingCapability(cap) => AuthzError::PermissionDenied(cap.to_string()),
            Self::MissingAllOf(caps) => {
                AuthzError::MissingAllCapabilities(caps.iter().map(|c| c.to_string()).collect())
            }
            Self::MissingAnyOf(caps) => {
                AuthzError::MissingAnyCapability(caps.iter().map(|c| c.to_string()).collect())
            }
            Self::MissingSpecialAuthority(auth) => {
                AuthzError::SpecialAuthorityDenied(auth.to_string())
            }
            Self::Custom(msg) => AuthzError::PermissionDenied(msg.clone()),
        }
    }
}

/// Deterministic authorization evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

impl Decision {
    /// Returns `true` if access was granted.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if access was denied.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny(_))
    }

    /// Converts this decision into a `Result<(), AuthzError>`.
    pub fn into_result(self) -> Result<(), AuthzError> {
        match self {
            Self::Allow => Ok(()),
            Self::Deny(reason) => Err(reason.to_authz_error()),
        }
    }
}

/// Deterministic policy evaluation engine.
pub struct PolicyEngine;

impl PolicyEngine {
    /// Evaluates a `PolicyRule` against a `CapabilitySet`.
    pub fn evaluate_rule(capabilities: &CapabilitySet, rule: &PolicyRule) -> Decision {
        match rule {
            PolicyRule::Require(cap) => Self::evaluate_capability(capabilities, cap),
            PolicyRule::RequireAll(caps) => Self::evaluate_all(capabilities, caps),
            PolicyRule::RequireAny(caps) => Self::evaluate_any(capabilities, caps),
            PolicyRule::RequireSpecial(auth) => Self::evaluate_special(capabilities, *auth),
        }
    }

    /// Evaluates a single required capability against a `CapabilitySet`.
    pub fn evaluate_capability(capabilities: &CapabilitySet, required: &Capability) -> Decision {
        if capabilities.contains(required) {
            Decision::Allow
        } else if let Some(special) = required.as_special_authority() {
            Decision::Deny(DenyReason::MissingSpecialAuthority(special))
        } else {
            Decision::Deny(DenyReason::MissingCapability(required.clone()))
        }
    }

    /// Evaluates whether all required capabilities are present.
    pub fn evaluate_all(capabilities: &CapabilitySet, required: &[Capability]) -> Decision {
        let missing: Vec<Capability> = required
            .iter()
            .filter(|cap| !capabilities.contains(cap))
            .cloned()
            .collect();

        if missing.is_empty() {
            Decision::Allow
        } else {
            Decision::Deny(DenyReason::MissingAllOf(missing))
        }
    }

    /// Evaluates whether at least one of the required capabilities is present.
    pub fn evaluate_any(capabilities: &CapabilitySet, required: &[Capability]) -> Decision {
        if required.is_empty() {
            return Decision::Deny(DenyReason::MissingAnyOf(Vec::new()));
        }

        if capabilities.contains_any(required) {
            Decision::Allow
        } else {
            Decision::Deny(DenyReason::MissingAnyOf(required.to_vec()))
        }
    }

    /// Evaluates whether a specific special authority is present.
    pub fn evaluate_special(capabilities: &CapabilitySet, authority: SpecialAuthority) -> Decision {
        if capabilities.has_special_authority(authority) {
            Decision::Allow
        } else {
            Decision::Deny(DenyReason::MissingSpecialAuthority(authority))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_engine_allow_deny() {
        let mut caps = CapabilitySet::new();
        caps.insert(Capability::WorkspaceRead);

        let allow_dec = PolicyEngine::evaluate_capability(&caps, &Capability::WorkspaceRead);
        assert!(allow_dec.is_allowed());
        assert!(allow_dec.into_result().is_ok());

        let deny_dec = PolicyEngine::evaluate_capability(&caps, &Capability::WorkspaceWrite);
        assert!(deny_dec.is_denied());
        assert!(deny_dec.into_result().is_err());
    }

    #[test]
    fn test_policy_engine_require_all_and_any() {
        let mut caps = CapabilitySet::new();
        caps.insert(Capability::WorkspaceRead);
        caps.insert(Capability::WorkspaceWrite);

        let all_rule =
            PolicyRule::require_all(vec![Capability::WorkspaceRead, Capability::WorkspaceWrite]);
        assert!(PolicyEngine::evaluate_rule(&caps, &all_rule).is_allowed());

        let missing_all_rule =
            PolicyRule::require_all(vec![Capability::WorkspaceRead, Capability::WorkspaceAdmin]);
        assert!(PolicyEngine::evaluate_rule(&caps, &missing_all_rule).is_denied());

        let any_rule =
            PolicyRule::require_any(vec![Capability::WorkspaceAdmin, Capability::WorkspaceRead]);
        assert!(PolicyEngine::evaluate_rule(&caps, &any_rule).is_allowed());

        let missing_any_rule =
            PolicyRule::require_any(vec![Capability::WorkspaceAdmin, Capability::AuditRead]);
        assert!(PolicyEngine::evaluate_rule(&caps, &missing_any_rule).is_denied());
    }

    #[test]
    fn test_policy_engine_special_authority_evaluation() {
        let mut caps = CapabilitySet::new();
        caps.insert(Capability::WorkspaceAdmin);

        let special_rule = PolicyRule::require_special(SpecialAuthority::OverrideBlock);
        let dec = PolicyEngine::evaluate_rule(&caps, &special_rule);
        assert!(dec.is_denied());

        caps.insert(Capability::OverrideBlock);
        let dec_allowed = PolicyEngine::evaluate_rule(&caps, &special_rule);
        assert!(dec_allowed.is_allowed());
    }
}
