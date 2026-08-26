//! WI-0201-C Document-Pipeline domain invariant tests.
//!
//! Proves, at the domain layer only (no infrastructure):
//! - immutable DocumentVersion facts separated from the mutable Document
//!   projection;
//! - upload-intent prerequisites (bounds, allowlist, TTL, one-way markers,
//!   server object-key authority);
//! - fixed-width SHA-256 validation incl. canonical base64 form;
//! - object-artifact immutability and server-owned key shape;
//! - quarantine closed-outcome prerequisites;
//! - parser identity/status progression, page bounds/hashes/extraction,
//!   block offsets/bbox/kinds;
//! - canonical SourceSpan offsets/hash/provenance binding;
//! - cross-workspace composition rejection everywhere;
//! - ownership boundaries: no Jobs-AI or Source-Evidence contract
//!   redefinition lives in this crate.

use uuid::Uuid;
use w014_domain::{
    ArtifactKind, BlockKind, BoundedJson, BoundingBox, DOCUMENT_PIPELINE_OWNED_OBJECTS, Document,
    DocumentClass, DocumentStatus, DocumentVersion, EncryptionMode, ExtractionMethod, IntentStatus,
    LocatorVersion, MediaType, ObjectArtifact, ObjectArtifactId, ObjectKey, OffsetRange,
    ParserArtifact, ParserBlock, ParserPage, QuarantineRecord, QuarantineStatus, SectionPath,
    Sha256, SourceSpan, SpanProvenance, StorageTier, StoredMediaType, TrustState, UploadIntent,
    VersionOrdinal,
};

fn document(title: &str) -> Document {
    Document::new(
        w014_domain::WorkspaceId::new(),
        title,
        DocumentClass::Pdf,
        None,
    )
    .unwrap()
}

fn version(doc: &Document) -> DocumentVersion {
    DocumentVersion::new(
        doc,
        VersionOrdinal::new(1).unwrap(),
        ObjectArtifactId::new(),
        2048,
        Sha256::digest(b"version-bytes"),
        "contract.pdf",
        None,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Document / DocumentVersion separation
// ---------------------------------------------------------------------------

#[test]
fn document_projection_is_mutable_while_version_facts_are_immutable() {
    let doc = document("Separation");
    let v = version(&doc);

    // The projection pointer moves on the DOCUMENT under guarded concurrency.
    let mut projected = doc.clone();
    projected
        .project_current_version(v.id, projected.row_version, projected.updated_at)
        .unwrap();
    assert_eq!(projected.current_version_id, Some(v.id));

    // The VERSION fact is untouched by any projection move.
    assert_eq!(v.trust_state, TrustState::Pending);
    assert_eq!(v.version_ordinal.get(), 1);
}

#[test]
fn document_version_reconstruction_rejects_zero_ordinals_and_bad_digests() {
    // Zero ordinal rejected.
    assert!(VersionOrdinal::new(0).is_err());
    // Wrong digest width rejected.
    assert!(Sha256::from_slice("sha256_hash", &[0u8; 31]).is_err());
    assert!(Sha256::from_slice("sha256_hash", &[0u8; 32]).is_ok());
}

#[test]
fn document_status_domain_is_closed_one_way() {
    assert_eq!(DocumentStatus::Active.as_str(), "active");
    assert!(DocumentStatus::parse("active").is_ok());
    assert!(DocumentStatus::parse("paused").is_err());

    let mut doc = document("Lifecycle");
    doc.transition_status(DocumentStatus::Archived, doc.row_version)
        .unwrap();
    assert!(
        doc.transition_status(DocumentStatus::Active, doc.row_version)
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Upload-intent prerequisites
// ---------------------------------------------------------------------------

#[test]
fn upload_intent_prerequisites_fail_closed() {
    let ws = w014_domain::WorkspaceId::new();
    let creator = w014_domain::PrincipalId::new();
    let soon = chrono::Utc::now() + chrono::Duration::seconds(300);

    // Valid NULL-document intent (future NEW logical document).
    let intent = UploadIntent::new(
        ws,
        creator,
        None,
        "upload.pdf",
        MediaType::ApplicationPdf,
        1,
        None,
        soon,
    )
    .unwrap();
    assert_eq!(intent.status, IntentStatus::Initiated);

    // Invalid: zero length, oversize, over-TTL, empty filename.
    assert!(
        UploadIntent::new(
            ws,
            creator,
            None,
            "z.pdf",
            MediaType::ApplicationPdf,
            0,
            None,
            soon
        )
        .is_err()
    );
    assert!(
        UploadIntent::new(
            ws,
            creator,
            None,
            "big.pdf",
            MediaType::ApplicationPdf,
            101 * 1024 * 1024,
            None,
            soon
        )
        .is_err()
    );
    assert!(
        UploadIntent::new(
            ws,
            creator,
            None,
            "late.pdf",
            MediaType::ApplicationPdf,
            10,
            None,
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .is_err()
    );
    assert!(
        UploadIntent::new(
            ws,
            creator,
            None,
            "   ",
            MediaType::ApplicationPdf,
            10,
            None,
            soon
        )
        .is_err()
    );

    // Non-allowlist media type is unrepresentable by construction.
    assert!(MediaType::parse("application/x-msdownload").is_err());
}

#[test]
fn upload_intent_terminal_markers_are_one_way_and_exclusive() {
    let mut intent = UploadIntent::new(
        w014_domain::WorkspaceId::new(),
        w014_domain::PrincipalId::new(),
        None,
        "flow.pdf",
        MediaType::ApplicationPdf,
        4096,
        Some(Sha256::digest(b"declared")),
        chrono::Utc::now() + chrono::Duration::seconds(600),
    )
    .unwrap();
    intent.mark_uploaded().unwrap();
    intent.finalize_verified(chrono::Utc::now()).unwrap();

    assert_eq!(
        intent.finalized_at.is_some(),
        intent.status == IntentStatus::Verified
    );
    assert!(intent.abandoned_at.is_none());
    assert!(
        intent.abandon(chrono::Utc::now()).is_err(),
        "verified intents never abandon"
    );
    assert!(
        intent.mark_uploaded().is_err(),
        "terminal intents never resurrect"
    );
}

// ---------------------------------------------------------------------------
// Server object-key authority + fixed-width hashes
// ---------------------------------------------------------------------------

#[test]
fn object_keys_are_server_authoritative() {
    // Server minting always yields a frozen-shape key.
    let minted = ObjectKey::generate_server_key("documents");
    assert!(minted.as_str().starts_with("documents/"));
    assert!(ObjectKey::reconstruct(minted.as_str()).is_ok());

    // Client-shaped traversal/whitespace keys fail closed.
    for bad in ["../escape", "/abs", "//double", "a..b", "with space"] {
        assert!(ObjectKey::reconstruct(bad).is_err());
    }
}

#[test]
fn sha256_is_exactly_32_bytes_with_canonical_base64() {
    let digest = Sha256::digest(b"w014-wi0201-c");
    assert_eq!(digest.as_bytes().len(), 32);
    let b64 = digest.to_base64();
    assert_eq!(
        b64.len(),
        44,
        "canonical base64 matches the physical b64 CHECK shape"
    );
    assert_eq!(Sha256::from_base64("h", &b64).unwrap(), digest);
}

// ---------------------------------------------------------------------------
// Object artifacts: insert-only immutable facts
// ---------------------------------------------------------------------------

#[test]
fn object_artifact_facts_are_immutable_registrations() {
    let artifact = ObjectArtifact::new(
        w014_domain::WorkspaceId::new(),
        ArtifactKind::Original,
        "w014-bucket",
        StoredMediaType::new("application/pdf").unwrap(),
        Sha256::digest(b"bytes"),
        128,
        StorageTier::Hot,
        EncryptionMode::None,
        None,
    )
    .unwrap();
    assert_eq!(artifact.kind, ArtifactKind::Original);
    assert_eq!(artifact.content_sha256.as_bytes().len(), 32);
    assert!(artifact.byte_length >= 0);
    // No mutation API exists on ObjectArtifact: immutability is structural.
    let _clone = artifact.clone();
}

// ---------------------------------------------------------------------------
// Quarantine prerequisites
// ---------------------------------------------------------------------------

#[test]
fn quarantine_outcomes_use_only_the_frozen_domain() {
    for raw in [
        "pending",
        "clean",
        "malware",
        "integrity_failed",
        "unsupported",
    ] {
        assert!(QuarantineStatus::parse(raw).is_ok());
    }
    for obsolete in ["quarantined", "released", "purged"] {
        assert!(QuarantineStatus::parse(obsolete).is_err());
    }
    let record = QuarantineRecord::new(
        w014_domain::WorkspaceId::new(),
        w014_domain::UploadIntentId::new(),
        QuarantineStatus::IntegrityFailed,
        "clamav-scanner",
        Some("1.3.0".to_string()),
        Some("DECLARED_LENGTH_MISMATCH".to_string()),
        None,
        None,
        chrono::Utc::now(),
        BoundedJson::empty(),
    )
    .unwrap();
    assert!(!record.allows_trust());
}

// ---------------------------------------------------------------------------
// Parser persistence-facing invariants
// ---------------------------------------------------------------------------

fn open_parser(doc_version: w014_domain::DocumentVersionId) -> ParserArtifact {
    ParserArtifact::new(
        w014_domain::WorkspaceId::new(),
        doc_version,
        Some(Uuid::new_v4()),
        "w014-parser",
        "v1",
        LocatorVersion::new("locator-v1").unwrap(),
    )
    .unwrap()
}

#[test]
fn parser_artifact_progression_is_single_shot_and_identity_bound() {
    let artifact = open_parser(w014_domain::DocumentVersionId::new());
    assert_eq!(artifact.status, w014_domain::ParserStatus::Processing);
    assert!(artifact.completed_at.is_none());
    assert!(artifact.failure_code.is_none());

    let completed = artifact
        .clone()
        .complete(chrono::Utc::now(), 3, 12, 40, Some(250))
        .unwrap();
    assert_eq!(completed.status, w014_domain::ParserStatus::Completed);
    assert!(completed.completed_at.is_some());

    // Terminal: exactly-once transitions.
    assert!(
        completed
            .clone()
            .complete(chrono::Utc::now(), 1, 1, 1, None)
            .is_err()
    );
    assert!(
        completed
            .fail(chrono::Utc::now(), "OCR_DECODE_FAILURE")
            .is_err()
    );

    let failed = open_parser(w014_domain::DocumentVersionId::new())
        .fail(chrono::Utc::now(), "UNSUPPORTED_MEDIA")
        .unwrap();
    assert_eq!(failed.failure_code.as_deref(), Some("UNSUPPORTED_MEDIA"));
    // Failure without a code is unrepresentable.
    assert!(
        ParserArtifact::reconstruct(
            failed.id,
            failed.document_version_id,
            failed.workspace_id,
            failed.job_id,
            failed.parser_name.clone(),
            failed.parser_version.clone(),
            failed.locator_version.clone(),
            w014_domain::ParserStatus::Failed,
            None,
            None,
            0,
            0,
            0,
            None,
            None,
            failed.started_at,
            failed.completed_at,
        )
        .is_err()
    );
    // Locator identity is REQUIRED.
    assert!(LocatorVersion::new("").is_err());
}

#[test]
fn parser_pages_bounded_hashed_and_extraction_typed() {
    let artifact = open_parser(w014_domain::DocumentVersionId::new());
    let page = ParserPage::new(
        &artifact,
        1,
        "normalized page text",
        ExtractionMethod::NativeText,
        false,
        Some(0.98),
        Some(612.0),
        Some(792.0),
        w014_domain::Rotation::Deg0,
    )
    .unwrap();
    assert!(page.verify_normalized_hash(&page.normalized_sha256()));
    assert!(!page.verify_normalized_hash(&Sha256::digest(b"other")));

    // Page numbers are 1-based and bounded.
    assert!(
        ParserPage::new(
            &artifact,
            0,
            "",
            ExtractionMethod::Ocr,
            true,
            None,
            None,
            None,
            w014_domain::Rotation::Deg90
        )
        .is_err()
    );
    assert!(
        ParserPage::new(
            &artifact,
            u32::MAX,
            "",
            ExtractionMethod::Mixed,
            true,
            None,
            None,
            None,
            w014_domain::Rotation::Deg180
        )
        .is_err()
    );
    // Quality scores outside 0..=1 rejected.
    assert!(
        ParserPage::new(
            &artifact,
            2,
            "t",
            ExtractionMethod::NativeText,
            false,
            Some(1.5),
            None,
            None,
            w014_domain::Rotation::Deg0
        )
        .is_err()
    );
    // Extraction method domain closed.
    assert!(ExtractionMethod::parse("handwritten").is_err());
}

#[test]
fn parser_blocks_validate_offsets_bbox_kinds() {
    let artifact = open_parser(w014_domain::DocumentVersionId::new());
    let page = ParserPage::new(
        &artifact,
        1,
        "block text payload",
        ExtractionMethod::NativeText,
        false,
        None,
        None,
        None,
        w014_domain::Rotation::Deg0,
    )
    .unwrap();
    let bbox = Some(BoundingBox::new(10.0, 20.0, 30.0, 40.0).unwrap());
    let block = ParserBlock::new(
        &page,
        0,
        BlockKind::Paragraph,
        0,
        17,
        bbox,
        vec!["Chapter 1".to_string()],
        "block text payload",
        Some(0.9),
    )
    .unwrap();
    block.bind_to_page(&page).unwrap();

    // Inverted offsets rejected.
    assert!(ParserBlock::new(&page, 1, BlockKind::Heading, 9, 5, None, vec![], "x", None).is_err());
    // Offsets beyond the page-normalized text rejected.
    assert!(
        ParserBlock::new(
            &page,
            2,
            BlockKind::Other,
            0,
            999_999,
            None,
            vec![],
            "x",
            None
        )
        .is_err()
    );
    // Degenerate bbox rejected.
    assert!(BoundingBox::new(0.0, 0.0, -1.0, 5.0).is_err());
    // Closed kind domain.
    assert!(BlockKind::parse("sidebar").is_err());
    // Confidence bound.
    assert!(
        ParserBlock::new(
            &page,
            3,
            BlockKind::TableCell,
            0,
            1,
            None,
            vec![],
            "c",
            Some(7.0)
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// Canonical SourceSpan identity
// ---------------------------------------------------------------------------

#[test]
fn source_span_hash_binds_every_frozen_input() {
    let provenance = SpanProvenance::new(
        w014_domain::WorkspaceId::new(),
        w014_domain::DocumentVersionId::new(),
        w014_domain::ParserArtifactId::new(),
        LocatorVersion::new("locator-v1").unwrap(),
        2,
    )
    .unwrap();
    let span = SourceSpan::new(
        provenance.clone(),
        4,
        OffsetRange::new(8, 21).unwrap(),
        Some(OffsetRange::new(80, 93).unwrap()),
        Some(BoundingBox::new(1.0, 1.0, 2.0, 2.0).unwrap()),
        Some(SectionPath::new(vec!["A".to_string(), "B".to_string()]).unwrap()),
        "span text",
        ExtractionMethod::NativeText,
        Some(0.97),
    )
    .unwrap();
    let identity = span.span_sha256();

    // Frozen-input mutations all produce NEW identities.
    let mut moved_locator = span.clone();
    moved_locator.provenance.locator_version = LocatorVersion::new("locator-v2").unwrap();
    assert_ne!(moved_locator.span_sha256(), identity);

    let mut moved_version = span.clone();
    moved_version.provenance.document_version_id = w014_domain::DocumentVersionId::new();
    assert_ne!(moved_version.span_sha256(), identity);

    let mut moved_page = span.clone();
    moved_page.provenance.page_number = 3;
    assert_ne!(moved_page.span_sha256(), identity);

    let mut moved_offsets = span.clone();
    moved_offsets.normalized_range = OffsetRange::new(9, 22).unwrap();
    assert_ne!(moved_offsets.span_sha256(), identity);

    let mut moved_text = span.clone();
    moved_text.text = "changed".to_string();
    assert_ne!(moved_text.span_sha256(), identity);
}

#[test]
fn source_span_provenance_cannot_float_across_workspaces() {
    let provenance = SpanProvenance::new(
        w014_domain::WorkspaceId::new(),
        w014_domain::DocumentVersionId::new(),
        w014_domain::ParserArtifactId::new(),
        LocatorVersion::new("locator-v1").unwrap(),
        1,
    )
    .unwrap();
    let span = SourceSpan::new(
        provenance.clone(),
        0,
        OffsetRange::new(0, 4).unwrap(),
        None,
        None,
        None,
        "text",
        ExtractionMethod::Ocr,
        None,
    )
    .unwrap();

    let foreign_workspace = SpanProvenance {
        workspace_id: w014_domain::WorkspaceId::new(),
        ..provenance.clone()
    };
    assert!(span.compose_with_provenance(&foreign_workspace).is_err());
    assert!(span.compose_with_provenance(&provenance).is_ok());

    // Over-bound span text (>64 KiB) fails closed.
    let big = "x".repeat(65 * 1024);
    assert!(
        SourceSpan::new(
            provenance,
            1,
            OffsetRange::new(0, 0).unwrap(),
            None,
            None,
            None,
            big,
            ExtractionMethod::Mixed,
            None
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// Ownership boundaries (no cross-A2 contract redefinition)
// ---------------------------------------------------------------------------

#[test]
fn owned_object_catalog_is_exactly_ten_document_pipeline_tables() {
    assert_eq!(DOCUMENT_PIPELINE_OWNED_OBJECTS.len(), 10);
    // No Jobs-AI-owned queue substrate and no Source-Evidence ledger objects
    // are claimed or redefined by the Document-Pipeline domain surface.
    for job_owned in [
        "jobs",
        "job_attempts",
        "job_dependencies",
        "job_progress",
        "dead_letter_entries",
    ] {
        assert!(
            !DOCUMENT_PIPELINE_OWNED_OBJECTS.contains(&job_owned),
            "{job_owned} is Jobs-AI-owned"
        );
    }
    for evidence_owned in ["dependency_keys", "change_events"] {
        assert!(
            !DOCUMENT_PIPELINE_OWNED_OBJECTS.contains(&evidence_owned),
            "{evidence_owned} is Source-Evidence-owned"
        );
    }
}
