//! OCR provenance builder and SourceSpan construction (WI-0207).
//!
//! Enforces:
//! - Preserves full provenance chain: `workspace_id`, `document_version_id`, `parser_artifact_id`, `locator_version`, `page_number`
//! - Distinguishes native vs OCR extraction methods (`ExtractionMethod::NativeText`, `ExtractionMethod::Ocr`, `ExtractionMethod::Mixed`)
//! - Sets `raw_range = None` for OCR spans where no trustworthy byte offset exists in the hostile package
//! - Canonical span hash derived via `derive_span_hash`

use w014_domain::ids::{DocumentVersionId, ParserArtifactId, WorkspaceId};
use w014_domain::{
    ExtractionMethod, LocatorVersion, OffsetRange, SectionPath, SourceSpan, SpanProvenance,
};

use crate::normalization::normalize_nfc;

/// Factory for creating citable `SourceSpan` entities preserving exact provenance.
pub struct SpanProvenanceFactory {
    pub workspace_id: WorkspaceId,
    pub document_version_id: DocumentVersionId,
    pub parser_artifact_id: ParserArtifactId,
    pub locator_version: LocatorVersion,
}

impl SpanProvenanceFactory {
    /// Creates a new provenance factory bound to an exact parser artifact run.
    #[must_use]
    pub fn new(
        workspace_id: WorkspaceId,
        document_version_id: DocumentVersionId,
        parser_artifact_id: ParserArtifactId,
        locator_version: LocatorVersion,
    ) -> Self {
        Self {
            workspace_id,
            document_version_id,
            parser_artifact_id,
            locator_version,
        }
    }

    /// Builds a citable `SourceSpan` fact for native text with optional raw byte range.
    ///
    /// # Errors
    /// Fails closed on invalid ranges or over-bound span text.
    pub fn build_native_span(
        &self,
        page_number: u32,
        span_sequence: u32,
        normalized_range: OffsetRange,
        raw_range: Option<OffsetRange>,
        section_path: Option<Vec<String>>,
        text: impl Into<String>,
    ) -> Result<SourceSpan, w014_domain::DomainError> {
        let prov = SpanProvenance::new(
            self.workspace_id,
            self.document_version_id,
            self.parser_artifact_id,
            self.locator_version.clone(),
            page_number,
        )?;

        let sec_path = match section_path {
            Some(segs) if !segs.is_empty() => Some(SectionPath::new(segs)?),
            _ => None,
        };

        let norm_text = normalize_nfc(&text.into());

        SourceSpan::new(
            prov,
            span_sequence,
            normalized_range,
            raw_range,
            None,
            sec_path,
            norm_text,
            ExtractionMethod::NativeText,
            Some(1.0),
        )
    }

    /// Builds a citable `SourceSpan` fact for OCR-derived text.
    /// Note: `raw_range` is strictly `None` because OCR has no trustworthy raw byte offsets in the source package.
    ///
    /// # Errors
    /// Fails closed on invalid ranges or over-bound span text.
    pub fn build_ocr_span(
        &self,
        page_number: u32,
        span_sequence: u32,
        normalized_range: OffsetRange,
        section_path: Option<Vec<String>>,
        text: impl Into<String>,
        confidence: Option<f64>,
    ) -> Result<SourceSpan, w014_domain::DomainError> {
        let prov = SpanProvenance::new(
            self.workspace_id,
            self.document_version_id,
            self.parser_artifact_id,
            self.locator_version.clone(),
            page_number,
        )?;

        let sec_path = match section_path {
            Some(segs) if !segs.is_empty() => Some(SectionPath::new(segs)?),
            _ => None,
        };

        let norm_text = normalize_nfc(&text.into());

        SourceSpan::new(
            prov,
            span_sequence,
            normalized_range,
            None, // strictly None for OCR spans
            None,
            sec_path,
            norm_text,
            ExtractionMethod::Ocr,
            confidence,
        )
    }
}
