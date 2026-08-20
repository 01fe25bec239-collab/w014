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
    Admin,
    Operator,
    Reviewer,
    Reader,
}

impl MembershipRole {
    /// Returns the database-compatible string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Reviewer => "reviewer",
            Self::Reader => "reader",
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
            "admin" => Ok(Self::Admin),
            "operator" => Ok(Self::Operator),
            "reviewer" => Ok(Self::Reviewer),
            "reader" => Ok(Self::Reader),
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
    pub role_code: MembershipRole,
    pub status: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub row_version: i32,
    pub created_at: DateTime<Utc>,
}

impl Membership {
    /// Creates a new active Membership domain entity.
    pub fn new(
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        role_code: MembershipRole,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: MembershipId::new(),
            workspace_id,
            principal_id,
            role_code,
            status: "active".to_string(),
            valid_from: now,
            valid_until: None,
            row_version: 1,
            created_at: now,
        }
    }

    /// Reconstructs an existing Membership from persistent storage.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: MembershipId,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        role_code: MembershipRole,
        status: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        row_version: i32,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            workspace_id,
            principal_id,
            role_code,
            status,
            valid_from,
            valid_until,
            row_version,
            created_at,
        }
    }

    /// Convenience getter for role.
    pub fn role(&self) -> MembershipRole {
        self.role_code
    }

    /// Evaluates if membership is active at the given timestamp.
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.status == "active"
            && self.valid_from <= now
            && self.valid_until.is_none_or(|u| u > now)
    }

    /// Changes the membership role, advancing `row_version`.
    pub fn change_role(&mut self, new_role: MembershipRole) {
        self.role_code = new_role;
        self.row_version += 1;
    }

    /// Revokes the membership.
    pub fn revoke(&mut self) {
        self.status = "revoked".to_string();
        self.row_version += 1;
    }

    /// Suspends the membership.
    pub fn suspend(&mut self) {
        self.status = "suspended".to_string();
        self.row_version += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_membership_roles() {
        assert_eq!(
            "admin".parse::<MembershipRole>().unwrap(),
            MembershipRole::Admin
        );
        assert_eq!(
            "operator".parse::<MembershipRole>().unwrap(),
            MembershipRole::Operator
        );
        assert_eq!(
            "reviewer".parse::<MembershipRole>().unwrap(),
            MembershipRole::Reviewer
        );
        assert_eq!(
            "reader".parse::<MembershipRole>().unwrap(),
            MembershipRole::Reader
        );
        assert!("owner".parse::<MembershipRole>().is_err());
        assert!("member".parse::<MembershipRole>().is_err());
        assert!("viewer".parse::<MembershipRole>().is_err());
        assert!("auditor".parse::<MembershipRole>().is_err());
        assert!("superuser".parse::<MembershipRole>().is_err());
    }

    #[test]
    fn test_membership_creation_and_role_change() {
        let ws_id = WorkspaceId::new();
        let p_id = PrincipalId::new();
        let mut m = Membership::new(ws_id, p_id, MembershipRole::Reader);
        assert_eq!(m.role(), MembershipRole::Reader);
        assert_eq!(m.role_code, MembershipRole::Reader);
        assert!(m.is_active_at(Utc::now()));

        m.change_role(MembershipRole::Admin);
        assert_eq!(m.role(), MembershipRole::Admin);
        assert_eq!(m.row_version, 2);
    }
}
