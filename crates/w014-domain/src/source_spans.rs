//! Canonical SourceSpan identity and provenance.
//!
//! A source span is a citable identity anchored to one exact immutable
//! document version through one exact parser artifact, page, and normalized
//! offset range. The canonical span hash binds the frozen inputs —
//! `locator_version`, `document_version_id`, `page_number`, normalized
//! offsets, and the normalized span text — so changed parser/locator output
//! always produces NEW spans; citation identity never floats to a new
//! document version.

use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::ids::{DocumentVersionId, ParserArtifactId, SourceSpanId, WorkspaceId};
use crate::limits::{MAX_SECTION_DEPTH, MAX_SECTION_SEGMENT_BYTES, MAX_SPAN_TEXT_BYTES};
use crate::parser::{BoundingBox, ExtractionMethod, LocatorVersion};
use crate::sha256::Sha256;
use crate::validation::validate_bounded_non_empty;

/// Domain-separation prefix for the canonical span-hash encoding.
const SPAN_HASH_DOMAIN: &[u8] = b"W014-SOURCE-SPAN-V1";

/// Valid half-open normalized offset range (`start <= end`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OffsetRange {
    pub start: u32,
    pub end: u32,
}

impl OffsetRange {
    /// Validates a normalized range.
    ///
    /// # Errors
    /// Fails closed when `end < start`.
    pub fn new(start: u32, end: u32) -> Result<Self, DomainError> {
        if end < start {
            return Err(DomainError::ValidationError {
                field: "offset_range",
                reason: format!("range start {start} exceeds end {end}"),
            });
        }
        Ok(Self { start, end })
    }
}

/// Bounded ordered section path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SectionPath(Vec<String>);

impl SectionPath {
    /// Validates depth and segment bounds.
    ///
    /// # Errors
    /// Fails closed on over-depth paths or empty/over-bound segments.
    pub fn new(segments: Vec<String>) -> Result<Self, DomainError> {
        if segments.len() > MAX_SECTION_DEPTH {
            return Err(DomainError::ValidationError {
                field: "section_path",
                reason: format!("depth {} exceeds {MAX_SECTION_DEPTH}", segments.len()),
            });
        }
        for segment in &segments {
            validate_bounded_non_empty("section_path_segment", segment, MAX_SECTION_SEGMENT_BYTES)?;
        }
        Ok(Self(segments))
    }

    /// The validated segments.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.0
    }
}

/// Frozen provenance chain anchoring a span to its exact immutable version.
///
/// Every component is required: spans without full provenance are not
/// representable, so citation identity can never float.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpanProvenance {
    pub workspace_id: WorkspaceId,
    pub document_version_id: DocumentVersionId,
    pub parser_artifact_id: ParserArtifactId,
    pub locator_version: LocatorVersion,
    /// 1-based bounded page number.
    pub page_number: u32,
}

impl SpanProvenance {
    /// Validates the provenance chain.
    ///
    /// # Errors
    /// Fails closed on zero page numbers.
    pub fn new(
        workspace_id: WorkspaceId,
        document_version_id: DocumentVersionId,
        parser_artifact_id: ParserArtifactId,
        locator_version: LocatorVersion,
        page_number: u32,
    ) -> Result<Self, DomainError> {
        if page_number == 0 || page_number > crate::limits::MAX_PAGE_NUMBER {
            return Err(DomainError::ValidationError {
                field: "page_number",
                reason: format!("provenance page number {page_number} out of bounds"),
            });
        }
        Ok(Self {
            workspace_id,
            document_version_id,
            parser_artifact_id,
            locator_version,
            page_number,
        })
    }
}

/// Canonical citable source span (insert-only identity).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub id: SourceSpanId,
    pub provenance: SpanProvenance,
    /// Insert-only ordinal within its owning block/page emission.
    pub span_sequence: u32,
    /// Normalized half-open offset range into the page-normalized text.
    pub normalized_range: OffsetRange,
    /// Optional raw byte range in the hostile original bytes (inert data).
    pub raw_range: Option<OffsetRange>,
    /// Optional normalized bounding box.
    pub bbox: Option<BoundingBox>,
    /// Optional bounded section path.
    pub section_path: Option<SectionPath>,
    /// Bounded normalized span text (<= 64 KiB), inert data.
    pub text: String,
    /// Extraction method for this span's text.
    pub extraction: ExtractionMethod,
    /// Optional quality score in 0..=1.
    pub quality_score: Option<f64>,
}

impl SourceSpan {
    /// Creates a new insert-only span whose canonical hash is computed from
    /// the frozen inputs at construction time.
    ///
    /// # Errors
    /// Fails closed on over-bound span text or invalid components.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provenance: SpanProvenance,
        span_sequence: u32,
        normalized_range: OffsetRange,
        raw_range: Option<OffsetRange>,
        bbox: Option<BoundingBox>,
        section_path: Option<SectionPath>,
        text: impl Into<String>,
        extraction: ExtractionMethod,
        quality_score: Option<f64>,
    ) -> Result<Self, DomainError> {
        let span = Self {
            id: SourceSpanId::new(),
            provenance,
            span_sequence,
            normalized_range,
            raw_range,
            bbox,
            section_path,
            text: text.into(),
            extraction,
            quality_score,
        };
        span.validate_components()?;
        Ok(span)
    }

    /// Reconstructs a stored span from its row facts together with the
    /// join-resolved provenance chain, re-verifying the stored canonical
    /// hash fail-closed.
    ///
    /// # Errors
    /// Fails closed on invalid components or canonical-hash mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct_with_hash(
        id: SourceSpanId,
        provenance: SpanProvenance,
        span_sequence: u32,
        normalized_range: OffsetRange,
        raw_range: Option<OffsetRange>,
        bbox: Option<BoundingBox>,
        section_path: Option<SectionPath>,
        text: impl Into<String>,
        extraction: ExtractionMethod,
        quality_score: Option<f64>,
        claimed_span_sha256: &Sha256,
    ) -> Result<Self, DomainError> {
        let span = Self {
            id,
            provenance,
            span_sequence,
            normalized_range,
            raw_range,
            bbox,
            section_path,
            text: text.into(),
            extraction,
            quality_score,
        };
        span.validate_components()?;
        if derive_span_hash(&span) != *claimed_span_sha256 {
            return Err(DomainError::ValidationError {
                field: "span_sha256",
                reason: "stored canonical span hash does not bind the frozen inputs".to_string(),
            });
        }
        Ok(span)
    }

    /// The canonical span hash recomputed from this instance's frozen inputs.
    #[must_use]
    pub fn span_sha256(&self) -> Sha256 {
        derive_span_hash(self)
    }

    /// Composition check against a candidate provenance chain resolved by
    /// joins: rejects cross-workspace or floating-identity pairings.
    ///
    /// # Errors
    /// Fails closed on any provenance mismatch.
    pub fn compose_with_provenance(&self, candidate: &SpanProvenance) -> Result<(), DomainError> {
        if *candidate != self.provenance {
            return Err(DomainError::CrossWorkspaceComposition {
                field: "source_span.provenance",
            });
        }
        Ok(())
    }

    fn validate_components(&self) -> Result<(), DomainError> {
        if self.text.len() > MAX_SPAN_TEXT_BYTES {
            return Err(DomainError::ValidationError {
                field: "span_text",
                reason: format!(
                    "span text length {} exceeds frozen 64 KiB bound",
                    self.text.len()
                ),
            });
        }
        if let Some(q) = self.quality_score
            && (!(0.0..=1.0).contains(&q) || !q.is_finite())
        {
            return Err(DomainError::ValidationError {
                field: "quality_score",
                reason: format!("quality score {q} outside 0..=1"),
            });
        }
        // Normalized ranges must land inside their own page's text length is
        // enforced by the composing adapter against the stored page; here we
        // enforce internal validity only.
        if self.normalized_range.end < self.normalized_range.start {
            return Err(DomainError::ValidationError {
                field: "normalized_range",
                reason: "inverted normalized range".to_string(),
            });
        }
        Ok(())
    }
}

/// Derives the canonical span hash binding the frozen inputs:
/// locator_version + document_version_id + page_number + normalized offsets +
/// normalized span text, under an explicit domain-separation prefix.
#[must_use]
pub fn derive_span_hash(span: &SourceSpan) -> Sha256 {
    let mut material = Vec::with_capacity(
        SPAN_HASH_DOMAIN.len()
            + span.provenance.locator_version.as_str().len()
            + 16
            + 4
            + 8
            + span.text.len()
            + 4,
    );
    material.extend_from_slice(SPAN_HASH_DOMAIN);
    material.push(0);
    material.extend_from_slice(span.provenance.locator_version.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(span.provenance.document_version_id.as_uuid().as_bytes());
    material.extend_from_slice(&span.provenance.page_number.to_be_bytes());
    material.extend_from_slice(&span.normalized_range.start.to_be_bytes());
    material.extend_from_slice(&span.normalized_range.end.to_be_bytes());
    material.extend_from_slice(span.text.as_bytes());
    Sha256::digest(&material)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::ParserArtifactId;

    fn provenance(locator: &str) -> SpanProvenance {
        SpanProvenance::new(
            WorkspaceId::new(),
            DocumentVersionId::new(),
            ParserArtifactId::new(),
            LocatorVersion::new(locator).unwrap(),
            3,
        )
        .unwrap()
    }

    fn sample() -> SourceSpan {
        SourceSpan::new(
            provenance("locator-v1"),
            0,
            OffsetRange::new(10, 42).unwrap(),
            Some(OffsetRange::new(100, 132).unwrap()),
            Some(BoundingBox::new(1.0, 2.0, 3.0, 4.0).unwrap()),
            Some(SectionPath::new(vec!["Chapter 1".to_string(), "Intro".to_string()]).unwrap()),
            "citable inert text".to_string(),
            ExtractionMethod::NativeText,
            Some(0.99),
        )
        .unwrap()
    }

    #[test]
    fn test_canonical_hash_binds_all_frozen_inputs() {
        let span = sample();
        let base = span.span_sha256();

        // Any change to a frozen input changes identity => NEW span fact.
        let mut moved = span.clone();
        moved.provenance.locator_version = LocatorVersion::new("locator-v2").unwrap();
        assert_ne!(moved.span_sha256(), base);

        let mut other_version = span.clone();
        other_version.provenance.document_version_id = DocumentVersionId::new();
        assert_ne!(other_version.span_sha256(), base);

        let mut other_page = span.clone();
        other_page.provenance.page_number = 4;
        assert_ne!(other_page.span_sha256(), base);

        let mut shifted = span.clone();
        shifted.normalized_range = OffsetRange::new(11, 43).unwrap();
        assert_ne!(shifted.span_sha256(), base);

        let mut edited = span.clone();
        edited.text.push('!');
        assert_ne!(edited.span_sha256(), base);

        // Non-frozen presentation data does not move citation identity.
        let mut cosmetic = span.clone();
        cosmetic.id = SourceSpanId::new();
        assert_eq!(cosmetic.span_sha256(), base);
    }

    #[test]
    fn test_reconstruct_verifies_stored_hash_fail_closed() {
        let span = sample();
        let good = span.span_sha256();
        let forged = Sha256::from_bytes([7u8; 32]);
        assert!(
            SourceSpan::reconstruct_with_hash(
                span.id,
                span.provenance.clone(),
                span.span_sequence,
                span.normalized_range,
                span.raw_range,
                span.bbox,
                span.section_path.clone(),
                span.text.clone(),
                span.extraction,
                span.quality_score,
                &good,
            )
            .is_ok()
        );
        assert!(
            SourceSpan::reconstruct_with_hash(
                span.id,
                span.provenance.clone(),
                span.span_sequence,
                span.normalized_range,
                span.raw_range,
                span.bbox,
                span.section_path.clone(),
                span.text.clone(),
                span.extraction,
                span.quality_score,
                &forged,
            )
            .is_err()
        );
    }

    #[test]
    fn test_bounds_and_provenance_validation() {
        assert!(LocatorVersion::new("").is_err());
        assert!(
            SpanProvenance::new(
                WorkspaceId::new(),
                DocumentVersionId::new(),
                ParserArtifactId::new(),
                LocatorVersion::new("l").unwrap(),
                0
            )
            .is_err()
        );
        assert!(OffsetRange::new(5, 4).is_err());
        assert!(SectionPath::new(vec![String::new()]).is_err());

        // Over-bound span text fails closed.
        let big = "x".repeat(MAX_SPAN_TEXT_BYTES + 1);
        assert!(
            SourceSpan::new(
                provenance("l"),
                0,
                OffsetRange::new(0, 0).unwrap(),
                None,
                None,
                None,
                big,
                ExtractionMethod::Ocr,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn test_composition_rejects_floating_identity() {
        let span = sample();
        assert!(span.compose_with_provenance(&span.provenance).is_ok());
        let foreign_ws = SpanProvenance {
            workspace_id: WorkspaceId::new(),
            ..span.provenance.clone()
        };
        assert!(span.compose_with_provenance(&foreign_ws).is_err());
    }
}
