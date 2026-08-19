//! Strongly-typed Capability Set representation and predicate engine.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::authority::SpecialAuthority;
use crate::capability::Capability;

/// A strongly-typed, deterministic collection of capabilities with predicate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    capabilities: BTreeSet<Capability>,
}

impl CapabilitySet {
    /// Creates an empty `CapabilitySet`.
    pub fn new() -> Self {
        Self {
            capabilities: BTreeSet::new(),
        }
    }

    /// Creates an empty `CapabilitySet`.
    pub fn empty() -> Self {
        Self::new()
    }

    /// Creates a `CapabilitySet` containing all standard workspace capabilities.
    pub fn all_standard() -> Self {
        Self::from_iter(Capability::standard_capabilities().iter().cloned())
    }

    /// Inserts a capability into the set. Returns `true` if the capability was newly inserted.
    pub fn insert(&mut self, capability: Capability) -> bool {
        self.capabilities.insert(capability)
    }

    /// Removes a capability from the set. Returns `true` if the capability was present.
    pub fn remove(&mut self, capability: &Capability) -> bool {
        self.capabilities.remove(capability)
    }

    /// Checks if the set contains the given capability.
    pub fn contains(&self, capability: &Capability) -> bool {
        self.capabilities.contains(capability)
    }

    /// Checks if the set contains all capabilities in the provided slice.
    pub fn contains_all(&self, capabilities: &[Capability]) -> bool {
        capabilities.iter().all(|c| self.contains(c))
    }

    /// Checks if the set contains at least one capability in the provided slice.
    pub fn contains_any(&self, capabilities: &[Capability]) -> bool {
        if capabilities.is_empty() {
            return false;
        }
        capabilities.iter().any(|c| self.contains(c))
    }

    /// Checks if the set contains a named capability (case-insensitive search).
    pub fn contains_named(&self, name: &str) -> bool {
        let upper = name.trim().to_ascii_uppercase();
        self.capabilities.iter().any(|c| match c {
            Capability::Named(n) => n.eq_ignore_ascii_case(&upper),
            _ => c.as_str().eq_ignore_ascii_case(&upper),
        })
    }

    /// Checks if the set contains the specified special authority.
    pub fn has_special_authority(&self, authority: SpecialAuthority) -> bool {
        self.contains(&authority.to_capability())
    }

    /// Returns `true` if the set contains ANY of the four special authorities.
    pub fn has_any_special_authority(&self) -> bool {
        self.capabilities.iter().any(|c| c.is_special_authority())
    }

    /// Returns the set of all special authorities present in this capability set.
    pub fn special_authorities(&self) -> BTreeSet<SpecialAuthority> {
        self.capabilities
            .iter()
            .filter_map(|c| c.as_special_authority())
            .collect()
    }

    /// Returns the set of standard (non-special) capabilities present in this set.
    pub fn standard_capabilities(&self) -> BTreeSet<Capability> {
        self.capabilities
            .iter()
            .filter(|c| !c.is_special_authority())
            .cloned()
            .collect()
    }

    /// Returns the union of `self` and `other`.
    pub fn union(&self, other: &Self) -> Self {
        let union_set = self
            .capabilities
            .union(&other.capabilities)
            .cloned()
            .collect();
        Self {
            capabilities: union_set,
        }
    }

    /// Returns the intersection of `self` and `other`.
    pub fn intersection(&self, other: &Self) -> Self {
        let inter_set = self
            .capabilities
            .intersection(&other.capabilities)
            .cloned()
            .collect();
        Self {
            capabilities: inter_set,
        }
    }

    /// Returns the difference of `self` and `other` (`self \ other`).
    pub fn difference(&self, other: &Self) -> Self {
        let diff_set = self
            .capabilities
            .difference(&other.capabilities)
            .cloned()
            .collect();
        Self {
            capabilities: diff_set,
        }
    }

    /// Checks whether `self` is a subset of `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.capabilities.is_subset(&other.capabilities)
    }

    /// Checks whether `self` is a superset of `other`.
    pub fn is_superset(&self, other: &Self) -> bool {
        self.capabilities.is_superset(&other.capabilities)
    }

    /// Returns the number of capabilities in the set.
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Returns an iterator over the capabilities in deterministic sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.capabilities.iter()
    }

    // Predicates for standard capabilities
    pub fn can_read_workspace(&self) -> bool {
        self.contains(&Capability::WorkspaceRead)
    }

    pub fn can_write_workspace(&self) -> bool {
        self.contains(&Capability::WorkspaceWrite)
    }

    pub fn can_admin_workspace(&self) -> bool {
        self.contains(&Capability::WorkspaceAdmin)
    }

    pub fn can_read_audit(&self) -> bool {
        self.contains(&Capability::AuditRead)
    }

    // Predicates for special authorities
    pub fn can_override_block(&self) -> bool {
        self.contains(&Capability::OverrideBlock)
    }

    pub fn can_review_rights(&self) -> bool {
        self.contains(&Capability::RightsReview)
    }

    pub fn can_activate_rule(&self) -> bool {
        self.contains(&Capability::RuleActivation)
    }

    pub fn can_grant_authority(&self) -> bool {
        self.contains(&Capability::GrantAuthority)
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<T: IntoIterator<Item = Capability>>(iter: T) -> Self {
        Self {
            capabilities: iter.into_iter().collect(),
        }
    }
}

impl IntoIterator for CapabilitySet {
    type Item = Capability;
    type IntoIter = std::collections::btree_set::IntoIter<Capability>;

    fn into_iter(self) -> Self::IntoIter {
        self.capabilities.into_iter()
    }
}

impl<'a> IntoIterator for &'a CapabilitySet {
    type Item = &'a Capability;
    type IntoIter = std::collections::btree_set::Iter<'a, Capability>;

    fn into_iter(self) -> Self::IntoIter {
        self.capabilities.iter()
    }
}

impl Extend<Capability> for CapabilitySet {
    fn extend<T: IntoIterator<Item = Capability>>(&mut self, iter: T) {
        self.capabilities.extend(iter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_set_predicates_and_operations() {
        let mut set = CapabilitySet::new();
        assert!(set.is_empty());
        assert!(!set.can_read_workspace());
        assert!(!set.can_write_workspace());
        assert!(!set.can_admin_workspace());
        assert!(!set.can_read_audit());
        assert!(!set.can_override_block());
        assert!(!set.can_review_rights());
        assert!(!set.can_activate_rule());
        assert!(!set.can_grant_authority());

        set.insert(Capability::WorkspaceRead);
        set.insert(Capability::WorkspaceWrite);

        assert_eq!(set.len(), 2);
        assert!(set.can_read_workspace());
        assert!(set.can_write_workspace());
        assert!(!set.can_admin_workspace());
        assert!(!set.has_any_special_authority());

        assert!(set.contains_all(&[Capability::WorkspaceRead, Capability::WorkspaceWrite]));
        assert!(!set.contains_all(&[Capability::WorkspaceRead, Capability::AuditRead]));
        assert!(set.contains_any(&[Capability::AuditRead, Capability::WorkspaceRead]));
        assert!(!set.contains_any(&[Capability::AuditRead, Capability::OverrideBlock]));
    }

    #[test]
    fn test_special_authority_predicates() {
        let mut set = CapabilitySet::new();
        set.insert(Capability::OverrideBlock);

        assert!(set.can_override_block());
        assert!(!set.can_review_rights());
        assert!(!set.can_activate_rule());
        assert!(!set.can_grant_authority());
        assert!(set.has_special_authority(SpecialAuthority::OverrideBlock));
        assert!(!set.has_special_authority(SpecialAuthority::RightsReview));
        assert!(set.has_any_special_authority());

        let special_set = set.special_authorities();
        assert_eq!(special_set.len(), 1);
        assert!(special_set.contains(&SpecialAuthority::OverrideBlock));
    }

    #[test]
    fn test_set_algebra() {
        let set_a =
            CapabilitySet::from_iter(vec![Capability::WorkspaceRead, Capability::WorkspaceWrite]);
        let set_b =
            CapabilitySet::from_iter(vec![Capability::WorkspaceWrite, Capability::WorkspaceAdmin]);

        let union = set_a.union(&set_b);
        assert_eq!(union.len(), 3);
        assert!(union.contains(&Capability::WorkspaceRead));
        assert!(union.contains(&Capability::WorkspaceWrite));
        assert!(union.contains(&Capability::WorkspaceAdmin));

        let inter = set_a.intersection(&set_b);
        assert_eq!(inter.len(), 1);
        assert!(inter.contains(&Capability::WorkspaceWrite));

        let diff = set_a.difference(&set_b);
        assert_eq!(diff.len(), 1);
        assert!(diff.contains(&Capability::WorkspaceRead));
    }
}
