//! Canonical ParserArtifact, Page, Block, and Span data models (WI-0206).
//!
//! Preserves:
//! - Canonical `ParserArtifactData` representation
//! - 1-based page numbering
//! - Normalized NFC text content per page
//! - Structural blocks with kinds, normalized ranges, bounding boxes, section paths
//! - Fine-grained source spans with normalized & raw offset ranges, bounding boxes,
//!   inert text, and canonical span hash
//! - Quality metrics, warnings, tool versions, and deterministic artifact digests

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use w014_domain::ids::{
    DocumentVersionId, ParserArtifactId, ParserBlockId, ParserPageId, WorkspaceId,
};
use w014_domain::{
    BlockKind, BoundingBox, ExtractionMethod, LocatorVersion, OffsetRange, ParserArtifact,
    ParserBlock, ParserPage, ParserStatus, Rotation, SectionPath, Sha256, SourceSpan,
    SpanProvenance,
};

use super::normalization::TextWarning;

/// Geometry for a single parsed page.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PageGeometry {
    /// 1-based page number.
    pub page_number: u32,
    /// Page width in points (or normalized units).
    pub width: f64,
    /// Page height in points (or normalized units).
    pub height: f64,
    /// Page rotation degrees (0, 90, 180, 270).
    pub rotation: Rotation,
}

/// Parser warning descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParserWarning {
    /// Machine-readable warning code.
    pub code: String,
    /// 1-based page number if associated with a specific page.
    pub page_number: Option<u32>,
    /// Diagnostic detail message.
    pub message: String,
}

impl From<TextWarning> for ParserWarning {
    fn from(tw: TextWarning) -> Self {
        Self {
            code: tw.code,
            page_number: None,
            message: tw.message,
        }
    }
}

/// Quality metrics for a parsed document artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParserQualityMetrics {
    /// Aggregate quality score in 0.0..=1.0.
    pub overall_quality_score: f64,
    /// Total characters extracted.
    pub char_count: u32,
    /// Total words extracted.
    pub word_count: u32,
    /// Ratio of non-ASCII characters to total characters.
    pub non_ascii_char_ratio: f64,
    /// Count of Unicode replacement characters (U+FFFD).
    pub replacement_char_count: u32,
    /// Count of non-standard control characters.
    pub control_char_count: u32,
    /// Count of zero-width / invisible characters.
    pub zero_width_char_count: u32,
}

impl Default for ParserQualityMetrics {
    fn default() -> Self {
        Self {
            overall_quality_score: 1.0,
            char_count: 0,
            word_count: 0,
            non_ascii_char_ratio: 0.0,
            replacement_char_count: 0,
            control_char_count: 0,
            zero_width_char_count: 0,
        }
    }
}

/// Data for one parsed page inside `ParserArtifactData`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedPageData {
    /// 1-based page number.
    pub page_number: u32,
    /// Normalized NFC text content (authoritative extracted text).
    pub normalized_text: String,
    /// Original raw text (evidence preservation).
    pub raw_text: String,
    /// Extraction method for page text.
    pub extraction: ExtractionMethod,
    /// Whether OCR participated in extraction.
    pub ocr_used: bool,
    /// Optional quality score in 0..=1.
    pub quality_score: Option<f64>,
    /// Page width in points.
    pub width: Option<f64>,
    /// Page height in points.
    pub height: Option<f64>,
    /// Page rotation degrees.
    pub rotation: Rotation,
}

/// Data for one structural block inside `ParserArtifactData`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedBlockData {
    /// 0-based block sequence within page.
    pub ordinal: u32,
    /// 1-based page number where block resides.
    pub page_number: u32,
    /// Structural block kind.
    pub kind: BlockKind,
    /// Half-open character offset start in page's normalized text.
    pub norm_start: u32,
    /// Half-open character offset end in page's normalized text.
    pub norm_end: u32,
    /// Optional normalized bounding box.
    pub bbox: Option<BoundingBox>,
    /// Ordered section path hierarchy.
    pub section_path: Vec<String>,
    /// Block text content.
    pub text: String,
    /// Confidence score in 0..=1.
    pub confidence: Option<f64>,
}

/// Data for one granular source span inside `ParserArtifactData`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedSpanData {
    /// 0-based span sequence across document or block.
    pub span_sequence: u32,
    /// 1-based page number.
    pub page_number: u32,
    /// Block ordinal within the page.
    pub block_ordinal: u32,
    /// Normalized character offset range into page's normalized text.
    pub normalized_range: OffsetRange,
    /// Raw character offset range into raw text.
    pub raw_range: Option<OffsetRange>,
    /// Optional normalized bounding box.
    pub bbox: Option<BoundingBox>,
    /// Optional section path.
    pub section_path: Option<SectionPath>,
    /// Normalized inert span text (<= 64 KiB).
    pub text: String,
    /// Extraction method.
    pub extraction: ExtractionMethod,
    /// Quality score in 0..=1.
    pub quality_score: Option<f64>,
}

/// Canonical typed in-memory representation of a parsed document artifact (WI-0206).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParserArtifactData {
    /// Canonical artifact contract version.
    pub artifact_version: String,
    /// SHA-256 digest of original input document bytes.
    pub input_sha256: Sha256,
    /// Total page count (bounded <= 2000).
    pub page_count: u32,
    /// Parsed pages in ascending 1-based order.
    pub pages: Vec<ParsedPageData>,
    /// Parsed structural blocks.
    pub blocks: Vec<ParsedBlockData>,
    /// Parsed source spans.
    pub spans: Vec<ParsedSpanData>,
    /// Text normalization contract version.
    pub text_normalization_version: String,
    /// Page geometries.
    pub geometry: Vec<PageGeometry>,
    /// Parser warnings.
    pub parser_warnings: Vec<ParserWarning>,
    /// Overall quality metrics.
    pub quality_metrics: ParserQualityMetrics,
    /// Optional OCR pages (None in WI-0206; OCR not implemented).
    pub ocr_pages: Option<Vec<serde_json::Value>>,
    /// Tool and engine versions.
    pub tool_versions: HashMap<String, String>,
    /// Full-text SHA-256 digest of concatenated page normalized text.
    pub text_sha256: Sha256,
    /// Deterministic content digest over all canonical artifact facts.
    pub artifact_sha256: Sha256,
}

impl ParserArtifactData {
    /// Constructs and computes digests for a new `ParserArtifactData`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_version: impl Into<String>,
        input_sha256: Sha256,
        pages: Vec<ParsedPageData>,
        blocks: Vec<ParsedBlockData>,
        spans: Vec<ParsedSpanData>,
        geometry: Vec<PageGeometry>,
        parser_warnings: Vec<ParserWarning>,
        quality_metrics: ParserQualityMetrics,
        tool_versions: HashMap<String, String>,
    ) -> Self {
        let page_count = pages.len() as u32;
        let text_normalization_version =
            super::request::DEFAULT_TEXT_NORMALIZATION_VERSION.to_string();

        // Compute full-text SHA-256
        let mut text_bytes = Vec::new();
        for page in &pages {
            text_bytes.extend_from_slice(page.normalized_text.as_bytes());
            text_bytes.push(b'\n');
        }
        let text_sha256 = Sha256::digest(&text_bytes);

        let mut data = Self {
            artifact_version: artifact_version.into(),
            input_sha256,
            page_count,
            pages,
            blocks,
            spans,
            text_normalization_version,
            geometry,
            parser_warnings,
            quality_metrics,
            ocr_pages: None,
            tool_versions,
            text_sha256,
            artifact_sha256: Sha256::from_bytes([0u8; 32]), // Temporary
        };

        data.artifact_sha256 = data.compute_artifact_sha256();
        data
    }

    /// Computes the deterministic artifact digest binding all frozen parsed facts.
    #[must_use]
    pub fn compute_artifact_sha256(&self) -> Sha256 {
        let mut material = Vec::new();
        material.extend_from_slice(b"W014-PARSER-ARTIFACT-V1\0");
        material.extend_from_slice(self.artifact_version.as_bytes());
        material.push(0);
        material.extend_from_slice(self.input_sha256.as_bytes());
        material.extend_from_slice(&self.page_count.to_be_bytes());
        material.extend_from_slice(self.text_sha256.as_bytes());

        for page in &self.pages {
            material.extend_from_slice(&page.page_number.to_be_bytes());
            material.extend_from_slice(page.normalized_text.as_bytes());
            material.extend_from_slice(page.extraction.as_str().as_bytes());
        }

        for block in &self.blocks {
            material.extend_from_slice(&block.page_number.to_be_bytes());
            material.extend_from_slice(&block.ordinal.to_be_bytes());
            material.extend_from_slice(block.kind.as_str().as_bytes());
            material.extend_from_slice(&block.norm_start.to_be_bytes());
            material.extend_from_slice(&block.norm_end.to_be_bytes());
            material.extend_from_slice(block.text.as_bytes());
        }

        for span in &self.spans {
            material.extend_from_slice(&span.span_sequence.to_be_bytes());
            material.extend_from_slice(&span.page_number.to_be_bytes());
            material.extend_from_slice(&span.normalized_range.start.to_be_bytes());
            material.extend_from_slice(&span.normalized_range.end.to_be_bytes());
            material.extend_from_slice(span.text.as_bytes());
        }

        Sha256::digest(&material)
    }

    /// Converts this in-memory artifact data into domain entities bound to an exact document version.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn into_domain_entities(
        &self,
        workspace_id: WorkspaceId,
        document_version_id: DocumentVersionId,
        parser_artifact_id: ParserArtifactId,
        locator_version: LocatorVersion,
        parser_name: String,
        parser_version: String,
        started_at: chrono::DateTime<chrono::Utc>,
        completed_at: chrono::DateTime<chrono::Utc>,
        duration_ms: Option<i64>,
    ) -> Result<
        (
            ParserArtifact,
            Vec<ParserPage>,
            Vec<ParserBlock>,
            Vec<SourceSpan>,
        ),
        w014_domain::DomainError,
    > {
        let domain_artifact = ParserArtifact::reconstruct(
            parser_artifact_id,
            document_version_id,
            workspace_id,
            None,
            parser_name,
            parser_version,
            locator_version.clone(),
            ParserStatus::Completed,
            None,
            Some(self.text_sha256),
            self.page_count as i32,
            self.blocks.len() as i32,
            self.spans.len() as i32,
            duration_ms,
            None,
            started_at,
            Some(completed_at),
        )?;

        let mut domain_pages = Vec::with_capacity(self.pages.len());
        let mut page_id_map: HashMap<u32, ParserPageId> = HashMap::new();

        for page in &self.pages {
            let page_id = ParserPageId::new();
            page_id_map.insert(page.page_number, page_id);

            let dom_page = ParserPage::reconstruct(
                page_id,
                parser_artifact_id,
                workspace_id,
                page.page_number,
                page.normalized_text.clone(),
                page.extraction,
                page.ocr_used,
                page.quality_score,
                page.width,
                page.height,
                page.rotation,
                completed_at,
            )?;
            domain_pages.push(dom_page);
        }

        let mut domain_blocks = Vec::with_capacity(self.blocks.len());
        let mut block_id_map: HashMap<(u32, u32), ParserBlockId> = HashMap::new();

        for block in &self.blocks {
            let page_id = *page_id_map.get(&block.page_number).ok_or_else(|| {
                w014_domain::DomainError::ValidationError {
                    field: "block.page_number",
                    reason: format!("Page {} not found in parsed pages", block.page_number),
                }
            })?;

            let block_id = ParserBlockId::new();
            block_id_map.insert((block.page_number, block.ordinal), block_id);

            let dom_block = ParserBlock::reconstruct(
                block_id,
                page_id,
                workspace_id,
                block.ordinal,
                block.kind,
                block.norm_start,
                block.norm_end,
                block.bbox,
                block.section_path.clone(),
                block.text.clone(),
                block.confidence,
                completed_at,
            )?;
            domain_blocks.push(dom_block);
        }

        let mut domain_spans = Vec::with_capacity(self.spans.len());
        for span in &self.spans {
            let prov = SpanProvenance::new(
                workspace_id,
                document_version_id,
                parser_artifact_id,
                locator_version.clone(),
                span.page_number,
            )?;

            let dom_span = SourceSpan::new(
                prov,
                span.span_sequence,
                span.normalized_range,
                span.raw_range,
                span.bbox,
                span.section_path.clone(),
                span.text.clone(),
                span.extraction,
                span.quality_score,
            )?;
            domain_spans.push(dom_span);
        }

        Ok((domain_artifact, domain_pages, domain_blocks, domain_spans))
    }
}
