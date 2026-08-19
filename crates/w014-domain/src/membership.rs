//! Workspace membership semantics.
//!
//! Captures the relationship between principals and workspaces with role code semantics.
//! Note: The WI-0103 authorization/policy engine is deferred to WI-0103.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::DomainError;
use crate::ids::{MembershipId, PrincipalId, WorkspaceId};

/// Role code semantics for workspace membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MembershipRole {
    Owner,
    Admin,
    Member,
    Viewer,
    Auditor,
}

impl MembershipRole {
    /// Returns the database-compatible string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Viewer => "viewer",
            Self::Auditor => "auditor",
        }
    }
}

impl fmt::Display for MembershipRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for MembershipRole {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            "viewer" => Ok(Self::Viewer),
            "auditor" => Ok(Self::Auditor),
            other => Err(DomainError::InvalidMembershipRole(other.to_string())),
        }
    }
}

/// Authoritative domain representation of a Membership in a Workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub id: MembershipId,
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub role: MembershipRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Membership {
    /// Creates a new Membership domain entity.
    pub fn new(workspace_id: WorkspaceId, principal_id: PrincipalId, role: MembershipRole) -> Self {
        let now = Utc::now();
        Self {
            id: MembershipId::new(),
            workspace_id,
            principal_id,
            role,
            created_at: now,
            updated_at: now,
        }
    }

    /// Reconstructs an existing Membership from persistent storage.
    pub fn reconstruct(
        id: MembershipId,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        role: MembershipRole,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            workspace_id,
            principal_id,
            role,
            created_at,
            updated_at,
        }
    }

    /// Changes the membership role, advancing `updated_at`.
    pub fn change_role(&mut self, new_role: MembershipRole) {
        self.role = new_role;
        self.updated_at = Utc::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_membership_roles() {
        assert_eq!(
            "owner".parse::<MembershipRole>().unwrap(),
            MembershipRole::Owner
        );
        assert_eq!(
            "admin".parse::<MembershipRole>().unwrap(),
            MembershipRole::Admin
        );
        assert_eq!(
            "member".parse::<MembershipRole>().unwrap(),
            MembershipRole::Member
        );
        assert_eq!(
            "viewer".parse::<MembershipRole>().unwrap(),
            MembershipRole::Viewer
        );
        assert_eq!(
            "auditor".parse::<MembershipRole>().unwrap(),
            MembershipRole::Auditor
        );
        assert!("superuser".parse::<MembershipRole>().is_err());
    }

    #[test]
    fn test_membership_creation_and_role_change() {
        let ws_id = WorkspaceId::new();
        let p_id = PrincipalId::new();
        let mut m = Membership::new(ws_id, p_id, MembershipRole::Member);
        assert_eq!(m.role, MembershipRole::Member);

        m.change_role(MembershipRole::Admin);
        assert_eq!(m.role, MembershipRole::Admin);
    }
}
