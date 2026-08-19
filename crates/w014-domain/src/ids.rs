//! Strongly-typed domain identifiers for W-014.
//!
//! Encapsulates UUIDs within distinct domain types to prevent identifier confusion
//! and enforce compile-time safety across boundaries.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

macro_rules! define_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Generates a new random UUIDv4-backed domain identifier.
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

            /// Returns the nil/zero UUID identifier.
            pub const fn nil() -> Self {
                Self(Uuid::nil())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl AsRef<Uuid> for $name {
            fn as_ref(&self) -> &Uuid {
                &self.0
            }
        }

        impl std::ops::Deref for $name {
            type Target = Uuid;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::from_str(s).map(Self)
            }
        }
    };
}

define_id!(
    OrganizationId,
    "Authoritative identifier for an Organization tenant."
);
define_id!(
    PrincipalId,
    "Authoritative identifier for a Principal (user, service, or system)."
);
define_id!(
    ProgramId,
    "Authoritative identifier for a Program within an Organization."
);
define_id!(
    WorkspaceId,
    "Authoritative identifier for a Workspace within a Program/Organization."
);
define_id!(
    MembershipId,
    "Authoritative identifier for a Principal's Membership in a Workspace."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_type_safety_and_roundtrip() {
        let org_id = OrganizationId::new();
        let s = org_id.to_string();
        let parsed: OrganizationId = s.parse().unwrap();
        assert_eq!(org_id, parsed);
        assert_eq!(org_id.as_uuid(), parsed.into_uuid());

        let json = serde_json::to_string(&org_id).unwrap();
        let deserialized: OrganizationId = serde_json::from_str(&json).unwrap();
        assert_eq!(org_id, deserialized);
    }
}
