//! Role profile convenience mappings to base capability sets.
//!
//! Important Authorization Invariants:
//! 1. Roles are convenience capability profiles only.
//! 2. Roles are NOT authorization truth independent of capability evaluation.
//! 3. Special authorities (`OVERRIDE_BLOCK`, `RIGHTS_REVIEW`, `RULE_ACTIVATION`, `GRANT_AUTHORITY`)
//!    are NEVER implied or included in any role profile (including `Owner` and `Admin`).

use w014_domain::membership::MembershipRole;

use crate::capability::Capability;
use crate::capability_set::CapabilitySet;

/// Role profile provider mapping domain membership roles to base capability sets.
pub struct RoleProfile;

impl RoleProfile {
    /// Returns the slice of all defined membership roles.
    pub const ALL_ROLES: &'static [MembershipRole] = &[
        MembershipRole::Owner,
        MembershipRole::Admin,
        MembershipRole::Member,
        MembershipRole::Viewer,
        MembershipRole::Auditor,
    ];

    /// Returns the base capability set associated with a membership role.
    ///
    /// Special authorities are strictly excluded from all role profiles.
    pub fn base_capabilities(role: MembershipRole) -> CapabilitySet {
        let mut caps = CapabilitySet::new();

        match role {
            MembershipRole::Owner => {
                caps.insert(Capability::WorkspaceAdmin);
                caps.insert(Capability::WorkspaceRead);
                caps.insert(Capability::WorkspaceWrite);
                caps.insert(Capability::AuditRead);
            }
            MembershipRole::Admin => {
                caps.insert(Capability::WorkspaceAdmin);
                caps.insert(Capability::WorkspaceRead);
                caps.insert(Capability::WorkspaceWrite);
                caps.insert(Capability::AuditRead);
            }
            MembershipRole::Member => {
                caps.insert(Capability::WorkspaceRead);
                caps.insert(Capability::WorkspaceWrite);
            }
            MembershipRole::Viewer => {
                caps.insert(Capability::WorkspaceRead);
            }
            MembershipRole::Auditor => {
                caps.insert(Capability::WorkspaceRead);
                caps.insert(Capability::AuditRead);
            }
        }

        caps
    }

    /// Verifies that no role profile contains any special authorities.
    pub fn verify_special_authority_isolation() -> bool {
        for &role in Self::ALL_ROLES {
            let caps = Self::base_capabilities(role);
            if caps.has_any_special_authority() {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::SpecialAuthority;

    #[test]
    fn test_role_profile_mappings() {
        let owner_caps = RoleProfile::base_capabilities(MembershipRole::Owner);
        assert!(owner_caps.can_admin_workspace());
        assert!(owner_caps.can_read_workspace());
        assert!(owner_caps.can_write_workspace());
        assert!(owner_caps.can_read_audit());

        let admin_caps = RoleProfile::base_capabilities(MembershipRole::Admin);
        assert!(admin_caps.can_admin_workspace());
        assert!(admin_caps.can_read_workspace());
        assert!(admin_caps.can_write_workspace());
        assert!(admin_caps.can_read_audit());

        let member_caps = RoleProfile::base_capabilities(MembershipRole::Member);
        assert!(!member_caps.can_admin_workspace());
        assert!(member_caps.can_read_workspace());
        assert!(member_caps.can_write_workspace());
        assert!(!member_caps.can_read_audit());

        let viewer_caps = RoleProfile::base_capabilities(MembershipRole::Viewer);
        assert!(!viewer_caps.can_admin_workspace());
        assert!(viewer_caps.can_read_workspace());
        assert!(!viewer_caps.can_write_workspace());
        assert!(!viewer_caps.can_read_audit());

        let auditor_caps = RoleProfile::base_capabilities(MembershipRole::Auditor);
        assert!(!auditor_caps.can_admin_workspace());
        assert!(auditor_caps.can_read_workspace());
        assert!(!auditor_caps.can_write_workspace());
        assert!(auditor_caps.can_read_audit());
    }

    #[test]
    fn test_special_authority_isolation_across_all_roles() {
        assert!(RoleProfile::verify_special_authority_isolation());

        for &role in RoleProfile::ALL_ROLES {
            let caps = RoleProfile::base_capabilities(role);
            assert!(
                !caps.has_any_special_authority(),
                "Role '{:?}' must NEVER have implicit special authorities!",
                role
            );
            for &auth in SpecialAuthority::ALL {
                assert!(
                    !caps.has_special_authority(auth),
                    "Role '{:?}' must not have special authority '{:?}'",
                    role,
                    auth
                );
            }
        }
    }
}
