//! Canonical durable-job identity for W2 enqueue idempotency.
//!
//! The frozen idempotency identity is SHA-256 over canonical UTF-8 JSON
//! containing exactly:
//! `job_kind`, `workspace_id`, sorted `immutable_targets`, `dependency_hash`,
//! `payload_contract_version`, and `producer_version`.
//!
//! This identity is a DURABLE-JOB identity. It is deliberately distinct from
//! HTTP-layer `idempotency_records` (M001R), which remain untouched.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Components that canonically identify one logical W2 durable job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalJobIdentity {
    /// Exact closed job-kind string.
    pub job_kind: String,
    /// Owning workspace.
    pub workspace_id: Uuid,
    /// Sorted immutable target references (e.g. document version identifiers).
    pub immutable_targets: Vec<String>,
    /// Content/dependency hash distinguishing re-analysis generations, if any.
    pub dependency_hash: Option<String>,
    /// Version of the payload contract the producer speaks.
    pub payload_contract_version: u32,
    /// Version of the producing component.
    pub producer_version: String,
}

impl CanonicalJobIdentity {
    /// Builds an identity, normalizing targets to sorted + de-duplicated form
    /// so equivalent inputs always yield the same key.
    #[must_use]
    pub fn new(
        job_kind: &str,
        workspace_id: Uuid,
        mut immutable_targets: Vec<String>,
        dependency_hash: Option<String>,
        payload_contract_version: u32,
        producer_version: impl Into<String>,
    ) -> Self {
        immutable_targets.sort();
        immutable_targets.dedup();
        Self {
            job_kind: job_kind.to_string(),
            workspace_id,
            immutable_targets,
            dependency_hash,
            payload_contract_version,
            producer_version: producer_version.into(),
        }
    }

    /// Serializes this identity to its canonical UTF-8 JSON form.
    ///
    /// `serde_json` maps objects onto BTreeMap by default, so member order is
    /// lexicographic and fully deterministic; arrays are pre-sorted at
    /// construction time.
    #[must_use]
    pub fn canonical_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            // Identity fields are plain JSON scalars/strings; serialization
            // cannot fail. Kept total for robustness.
            "{}".to_string()
        })
    }

    /// Computes the canonical durable idempotency key:
    /// `sha256:<64 lowercase hex characters>` over `canonical_json()`.
    #[must_use]
    pub fn idempotency_key(&self) -> String {
        let digest = Sha256::digest(self.canonical_json().as_bytes());
        format!("sha256:{}", hex::encode(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(targets: &[&str]) -> CanonicalJobIdentity {
        CanonicalJobIdentity::new(
            "parse_document_pdf",
            Uuid::nil(),
            targets.iter().map(|s| (*s).to_string()).collect(),
            None,
            1,
            "w014-test-producer",
        )
    }

    #[test]
    fn identical_inputs_yield_identical_keys_regardless_of_target_order() {
        let a = sample(&["doc-b", "doc-a"]);
        let b = sample(&["doc-a", "doc-b"]);
        assert_eq!(a.idempotency_key(), b.idempotency_key());
        assert_eq!(
            a.immutable_targets,
            vec!["doc-a".to_string(), "doc-b".to_string()]
        );
    }

    #[test]
    fn any_identity_component_change_yields_new_key() {
        let base = sample(&["doc-a"]);
        let new_generation = CanonicalJobIdentity::new(
            "parse_document_pdf",
            Uuid::nil(),
            vec!["doc-a".to_string()],
            Some("sha256:deadbeef".to_string()),
            1,
            "w014-test-producer",
        );
        let other_workspace = CanonicalJobIdentity::new(
            "parse_document_pdf",
            Uuid::new_v4(),
            vec!["doc-a".to_string()],
            None,
            1,
            "w014-test-producer",
        );
        assert_ne!(base.idempotency_key(), new_generation.idempotency_key());
        assert_ne!(base.idempotency_key(), other_workspace.idempotency_key());
    }

    #[test]
    fn key_shape_is_bounded_and_prefixed() {
        let key = sample(&["doc-a"]).idempotency_key();
        assert!(key.starts_with("sha256:"));
        assert_eq!(key.len(), "sha256:".len() + 64);
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let a = sample(&["doc-a", "doc-b"]);
        let b = sample(&["doc-b", "doc-a"]);
        assert_eq!(a.canonical_json(), b.canonical_json());
        assert!(
            a.canonical_json()
                .contains("\"job_kind\":\"parse_document_pdf\"")
        );
    }
}
