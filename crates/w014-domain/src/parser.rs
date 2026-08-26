//! Parser persistence-facing semantics
//! (M002R `parser_artifacts` / `parser_pages` / `parser_blocks`).
//!
//! Preserves parser-run identity, closed status domains, guarded one-way
//! terminal transitions, page bounds/hashes/extraction methods, and block
//! offsets/bbox/kinds as insert-only facts. No parser worker execution and no
//! sandbox behavior belongs here.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;
use crate::ids::{
    DocumentVersionId, ObjectArtifactId, ParserArtifactId, ParserBlockId, ParserPageId, WorkspaceId,
};
use crate::limits::{MAX_PAGE_NUMBER, MAX_SHORT_LABEL_BYTES};
use crate::sha256::Sha256;
use crate::validation::{validate_bounded_non_empty, validate_non_empty};

/// Canonical span-locator algorithm identity.
///
/// REQUIRED on every parser artifact: spans cannot verify citation identity
/// without it. Bounded, non-empty, printable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LocatorVersion(String);

impl LocatorVersion {
    /// Validates and wraps a locator identity.
    ///
    /// # Errors
    /// Fails closed when empty or over-bound.
    pub fn new(raw: impl AsRef<str>) -> Result<Self, DomainError> {
        Ok(Self(
            validate_bounded_non_empty("locator_version", raw.as_ref(), MAX_SHORT_LABEL_BYTES)?
                .to_string(),
        ))
    }

    /// The validated locator identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed parser-status domain (matches physical CHECK vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParserStatus {
    /// Run opened; result not yet recorded.
    Processing,
    /// Terminal success.
    Completed,
    /// Terminal failure with a required failure code.
    Failed,
}

impl ParserStatus {
    /// Canonical physical representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Processing => "processing",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    /// Parses a stored status into the closed domain; fails closed.
    ///
    /// # Errors
    /// Fails closed for unknown vocabulary.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "processing" => Ok(Self::Processing),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            other => Err(DomainError::ValidationError {
                field: "parser_status",
                reason: format!("'{other}' is not in the closed parser-status domain"),
            }),
        }
    }
}

/// Closed extraction-method domain for normalized text provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExtractionMethod {
    NativeText,
    Ocr,
    Mixed,
}

impl ExtractionMethod {
    /// Canonical representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NativeText => "native_text",
            Self::Ocr => "ocr",
            Self::Mixed => "mixed",
        }
    }

    /// Parses a stored method into the closed domain; fails closed.
    ///
    /// # Errors
    /// Fails closed for unknown vocabulary.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "native_text" => Ok(Self::NativeText),
            "ocr" => Ok(Self::Ocr),
            "mixed" => Ok(Self::Mixed),
            other => Err(DomainError::ValidationError {
                field: "extraction_method",
                reason: format!("'{other}' is not in the closed extraction-method domain"),
            }),
        }
    }
}

/// Closed block-kind domain (frozen Prompt-12 vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockKind {
    Heading,
    Paragraph,
    TableCell,
    Header,
    Footer,
    ImageText,
    Other,
}

impl BlockKind {
    /// Canonical representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Heading => "heading",
            Self::Paragraph => "paragraph",
            Self::TableCell => "table_cell",
            Self::Header => "header",
            Self::Footer => "footer",
            Self::ImageText => "image_text",
            Self::Other => "other",
        }
    }

    /// Parses a stored kind into the closed domain; fails closed.
    ///
    /// # Errors
    /// Fails closed for unknown vocabulary.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "heading" => Ok(Self::Heading),
            "paragraph" => Ok(Self::Paragraph),
            "table_cell" => Ok(Self::TableCell),
            "header" => Ok(Self::Header),
            "footer" => Ok(Self::Footer),
            "image_text" => Ok(Self::ImageText),
            "other" => Ok(Self::Other),
            other => Err(DomainError::ValidationError {
                field: "block_kind",
                reason: format!("'{other}' is not in the closed block-kind domain"),
            }),
        }
    }
}

/// Frozen page-rotation domain (matches physical CHECK vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Rotation {
    Deg0,
    Deg90,
    Deg180,
    Deg270,
}

impl Rotation {
    /// Canonical physical representation (degrees).
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        match self {
            Self::Deg0 => 0,
            Self::Deg90 => 90,
            Self::Deg180 => 180,
            Self::Deg270 => 270,
        }
    }

    /// Parses a stored rotation into the closed domain; fails closed.
    ///
    /// # Errors
    /// Fails closed outside {0, 90, 180, 270}.
    pub fn parse(raw: i32) -> Result<Self, DomainError> {
        match raw {
            0 => Ok(Self::Deg0),
            90 => Ok(Self::Deg90),
            180 => Ok(Self::Deg180),
            270 => Ok(Self::Deg270),
            other => Err(DomainError::ValidationError {
                field: "rotation",
                reason: format!("rotation {other} outside frozen {{0, 90, 180, 270}}"),
            }),
        }
    }
}

/// Optional normalized bounding box; components must be finite with positive
/// width/height.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BoundingBox {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl BoundingBox {
    /// Validates component values.
    ///
    /// # Errors
    /// Fails closed on non-finite or non-positive extents.
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Result<Self, DomainError> {
        if !x.is_finite() || !y.is_finite() || !width.is_finite() || !height.is_finite() {
            return Err(DomainError::ValidationError {
                field: "bounding_box",
                reason: "bounding-box components must be finite".to_string(),
            });
        }
        if width <= 0.0 || height <= 0.0 {
            return Err(DomainError::ValidationError {
                field: "bounding_box",
                reason: "bounding-box extents must be positive".to_string(),
            });
        }
        Ok(Self {
            x,
            y,
            width,
            height,
        })
    }
}

impl Eq for BoundingBox {}

/// Authoritative domain representation of one parser run over one exact
/// immutable document version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserArtifact {
    pub id: ParserArtifactId,
    pub document_version_id: DocumentVersionId,
    pub workspace_id: WorkspaceId,
    pub job_id: Option<Uuid>,
    pub parser_name: String,
    pub parser_version: String,
    /// REQUIRED canonical span-algorithm identity.
    pub locator_version: LocatorVersion,
    pub status: ParserStatus,
    /// Optional derived-text object reference (immutable once written).
    pub artifact_object_id: Option<ObjectArtifactId>,
    /// Optional full-text digest (exactly 32 bytes when present).
    pub text_sha256: Option<Sha256>,
    pub page_count: i32,
    pub block_count: i32,
    pub span_count: i32,
    pub execution_duration_ms: Option<i64>,
    /// Required exactly when status is `failed`.
    pub failure_code: Option<String>,
    pub started_at: DateTime<Utc>,
    /// Present exactly when status is terminal.
    pub completed_at: Option<DateTime<Utc>>,
}

impl ParserArtifact {
    /// Opens a new processing parser run bound to an exact version inside an
    /// exact workspace.
    ///
    /// # Errors
    /// Fails closed on invalid identities/labels.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        document_version_id: DocumentVersionId,
        job_id: Option<Uuid>,
        parser_name: impl AsRef<str>,
        parser_version: impl AsRef<str>,
        locator_version: LocatorVersion,
    ) -> Result<Self, DomainError> {
        let now = Utc::now();
        Self::reconstruct(
            ParserArtifactId::new(),
            document_version_id,
            workspace_id,
            job_id,
            parser_name.as_ref().to_string(),
            parser_version.as_ref().to_string(),
            locator_version,
            ParserStatus::Processing,
            None,
            None,
            0,
            0,
            0,
            None,
            None,
            now,
            None,
        )
    }

    /// Reconstructs a stored parser run fail-closed. All facts come from the
    /// stored row itself.
    ///
    /// # Errors
    /// Fails closed on violated lifecycle invariants (processing/completed_at
    /// agreement, failed-requires-code, negative counts, bad timestamps).
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: ParserArtifactId,
        document_version_id: DocumentVersionId,
        workspace_id: WorkspaceId,
        job_id: Option<Uuid>,
        parser_name: String,
        parser_version: String,
        locator_version: LocatorVersion,
        status: ParserStatus,
        artifact_object_id: Option<ObjectArtifactId>,
        text_sha256: Option<Sha256>,
        page_count: i32,
        block_count: i32,
        span_count: i32,
        execution_duration_ms: Option<i64>,
        failure_code: Option<String>,
        started_at: DateTime<Utc>,
        completed_at: Option<DateTime<Utc>>,
    ) -> Result<Self, DomainError> {
        validate_bounded_non_empty("parser_name", &parser_name, MAX_SHORT_LABEL_BYTES)?;
        validate_bounded_non_empty("parser_version", &parser_version, MAX_SHORT_LABEL_BYTES)?;
        for count in [
            ("page_count", page_count),
            ("block_count", block_count),
            ("span_count", span_count),
        ] {
            if count.1 < 0 {
                return Err(DomainError::ValidationError {
                    field: count.0,
                    reason: format!("count must be non-negative, got {}", count.1),
                });
            }
        }
        if let Some(ms) = execution_duration_ms
            && ms < 0
        {
            return Err(DomainError::ValidationError {
                field: "execution_duration_ms",
                reason: format!("duration must be non-negative, got {ms}"),
            });
        }
        // Physical mirror: (status = 'processing') = (completed_at IS NULL).
        if (status == ParserStatus::Processing) != completed_at.is_none() {
            return Err(DomainError::ValidationError {
                field: "completed_at",
                reason: "processing artifacts cannot carry completed_at; terminal ones must"
                    .to_string(),
            });
        }
        if let Some(done) = completed_at
            && done < started_at
        {
            return Err(DomainError::ValidationError {
                field: "completed_at",
                reason: "completion cannot precede start".to_string(),
            });
        }
        if status == ParserStatus::Failed && failure_code.is_none() {
            return Err(DomainError::ValidationError {
                field: "failure_code",
                reason: "failed artifacts require failure_code".to_string(),
            });
        }
        Ok(Self {
            id,
            document_version_id,
            workspace_id,
            job_id,
            parser_name,
            parser_version,
            locator_version,
            status,
            artifact_object_id,
            text_sha256,
            page_count,
            block_count,
            span_count,
            execution_duration_ms,
            failure_code,
            started_at,
            completed_at,
        })
    }

    /// Single guarded completion transition `processing -> completed`.
    ///
    /// # Errors
    /// Fails unless currently processing; counts must be non-negative.
    #[allow(clippy::too_many_arguments)]
    pub fn complete(
        self,
        at: DateTime<Utc>,
        page_count: i32,
        block_count: i32,
        span_count: i32,
        execution_duration_ms: Option<i64>,
    ) -> Result<Self, DomainError> {
        if self.status != ParserStatus::Processing {
            return Err(DomainError::IllegalStateTransition {
                from: self.status.as_str().to_string(),
                to: ParserStatus::Completed.as_str().to_string(),
                reason: "terminal transitions are one-way".to_string(),
            });
        }
        let done = at.max(self.started_at);
        self.reconstruct_terminal(
            ParserStatus::Completed,
            done,
            page_count,
            block_count,
            span_count,
            execution_duration_ms,
            None,
        )
    }

    /// Single guarded failure transition `processing -> failed`; requires a
    /// failure code.
    ///
    /// # Errors
    /// Fails unless currently processing or when the code is missing.
    pub fn fail(
        self,
        at: DateTime<Utc>,
        failure_code: impl AsRef<str>,
    ) -> Result<Self, DomainError> {
        if self.status != ParserStatus::Processing {
            return Err(DomainError::IllegalStateTransition {
                from: self.status.as_str().to_string(),
                to: ParserStatus::Failed.as_str().to_string(),
                reason: "terminal transitions are one-way".to_string(),
            });
        }
        let code = validate_bounded_non_empty(
            "failure_code",
            failure_code.as_ref(),
            MAX_SHORT_LABEL_BYTES,
        )?
        .to_string();
        let done = at.max(self.started_at);
        let page_count = self.page_count;
        let block_count = self.block_count;
        let span_count = self.span_count;
        let duration = self.execution_duration_ms;
        self.reconstruct_terminal(
            ParserStatus::Failed,
            done,
            page_count,
            block_count,
            span_count,
            duration,
            Some(code),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn reconstruct_terminal(
        self,
        status: ParserStatus,
        completed_at: DateTime<Utc>,
        page_count: i32,
        block_count: i32,
        span_count: i32,
        execution_duration_ms: Option<i64>,
        failure_code: Option<String>,
    ) -> Result<Self, DomainError> {
        Self::reconstruct(
            self.id,
            self.document_version_id,
            self.workspace_id,
            self.job_id,
            self.parser_name,
            self.parser_version,
            self.locator_version,
            status,
            self.artifact_object_id,
            self.text_sha256,
            page_count,
            block_count,
            span_count,
            execution_duration_ms,
            failure_code,
            self.started_at,
            Some(completed_at),
        )
    }
}

/// Authoritative domain representation of one parsed page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParserPage {
    pub id: ParserPageId,
    pub parser_artifact_id: ParserArtifactId,
    pub workspace_id: WorkspaceId,
    /// 1-based bounded page number.
    pub page_number: u32,
    /// Normalized inert text (extracted data, never instruction authority).
    pub normalized_text: String,
    /// Extraction method for this page's text.
    pub extraction: ExtractionMethod,
    /// Whether OCR participated in producing this page.
    pub ocr_used: bool,
    /// Optional quality score in 0..=1.
    pub quality_score: Option<f64>,
    pub width: Option<f64>,
    pub height: Option<f64>,
    pub rotation: Rotation,
    pub created_at: DateTime<Utc>,
}

impl ParserPage {
    /// Creates a new insert-only page fact under an exact artifact/workspace.
    ///
    /// # Errors
    /// Fails closed on out-of-bounds page numbers, zero dimensions, or
    /// out-of-range quality scores.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parser_artifact: &ParserArtifact,
        page_number: u32,
        normalized_text: impl Into<String>,
        extraction: ExtractionMethod,
        ocr_used: bool,
        quality_score: Option<f64>,
        width: Option<f64>,
        height: Option<f64>,
        rotation: Rotation,
    ) -> Result<Self, DomainError> {
        let now = Utc::now();
        let page = Self::reconstruct(
            ParserPageId::new(),
            parser_artifact.id,
            parser_artifact.workspace_id,
            page_number,
            normalized_text.into(),
            extraction,
            ocr_used,
            quality_score,
            width,
            height,
            rotation,
            now,
        )?;
        if page.workspace_id != parser_artifact.workspace_id {
            return Err(DomainError::CrossWorkspaceComposition {
                field: "parser_page.workspace_id",
            });
        }
        Ok(page)
    }

    /// Reconstructs a stored page fact fail-closed.
    ///
    /// # Errors
    /// Fails closed on violated bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: ParserPageId,
        parser_artifact_id: ParserArtifactId,
        workspace_id: WorkspaceId,
        page_number: u32,
        normalized_text: String,
        extraction: ExtractionMethod,
        ocr_used: bool,
        quality_score: Option<f64>,
        width: Option<f64>,
        height: Option<f64>,
        rotation: Rotation,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        if page_number == 0 || page_number > MAX_PAGE_NUMBER {
            return Err(DomainError::ValidationError {
                field: "page_number",
                reason: format!("page number {page_number} outside 1..={MAX_PAGE_NUMBER}"),
            });
        }
        if let Some(q) = quality_score
            && (!(0.0..=1.0).contains(&q) || !q.is_finite())
        {
            return Err(DomainError::ValidationError {
                field: "quality_score",
                reason: format!("quality score {q} outside 0..=1"),
            });
        }
        match (width, height) {
            (None, None) => {}
            (Some(w), Some(h)) if w > 0.0 && h > 0.0 && w.is_finite() && h.is_finite() => {}
            _ => {
                return Err(DomainError::ValidationError {
                    field: "page_dimensions",
                    reason: "dimensions must be jointly present and positive".to_string(),
                });
            }
        }
        Ok(Self {
            id,
            parser_artifact_id,
            workspace_id,
            page_number,
            normalized_text,
            extraction,
            ocr_used,
            quality_score,
            width,
            height,
            rotation,
            created_at,
        })
    }

    /// Deterministic digest of the exact normalized text bytes.
    #[must_use]
    pub fn normalized_sha256(&self) -> Sha256 {
        Sha256::digest(self.normalized_text.as_bytes())
    }

    /// True when `claimed` matches the recomputed normalized digest.
    #[must_use]
    pub fn verify_normalized_hash(&self, claimed: &Sha256) -> bool {
        self.normalized_sha256() == *claimed
    }
}

/// Authoritative domain representation of one parsed block within a page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParserBlock {
    pub id: ParserBlockId,
    pub parser_page_id: ParserPageId,
    pub workspace_id: WorkspaceId,
    /// Block ordinal >= 0 within its page.
    pub ordinal: u32,
    pub kind: BlockKind,
    /// Valid half-open range into the page's normalized text.
    pub norm_start: u32,
    pub norm_end: u32,
    /// Optional normalized bounding box.
    pub bbox: Option<BoundingBox>,
    /// Ordered section path segments (bounded).
    pub section_path: Vec<String>,
    /// Inert block text.
    pub text: String,
    /// Optional confidence in 0..=1.
    pub confidence: Option<f64>,
    pub created_at: DateTime<Utc>,
}

impl ParserBlock {
    /// Creates a new insert-only block fact under an exact page/workspace.
    ///
    /// # Errors
    /// Fails closed on inverted offsets, out-of-page ranges, over-bound
    /// section paths, or out-of-range confidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        page: &ParserPage,
        ordinal: u32,
        kind: BlockKind,
        norm_start: u32,
        norm_end: u32,
        bbox: Option<BoundingBox>,
        section_path: Vec<String>,
        text: impl Into<String>,
        confidence: Option<f64>,
    ) -> Result<Self, DomainError> {
        let now = Utc::now();
        let block = Self::reconstruct(
            ParserBlockId::new(),
            page.id,
            page.workspace_id,
            ordinal,
            kind,
            norm_start,
            norm_end,
            bbox,
            section_path,
            text.into(),
            confidence,
            now,
        )?;
        if block.norm_end as usize > page.normalized_text.len() {
            return Err(DomainError::ValidationError {
                field: "norm_end",
                reason: "block range exceeds page-normalized text length".to_string(),
            });
        }
        if block.workspace_id != page.workspace_id {
            return Err(DomainError::CrossWorkspaceComposition {
                field: "parser_block.workspace_id",
            });
        }
        Ok(block)
    }

    /// Reconstructs a stored block fact fail-closed.
    ///
    /// # Errors
    /// Fails closed on violated bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        id: ParserBlockId,
        parser_page_id: ParserPageId,
        workspace_id: WorkspaceId,
        ordinal: u32,
        kind: BlockKind,
        norm_start: u32,
        norm_end: u32,
        bbox: Option<BoundingBox>,
        section_path: Vec<String>,
        text: String,
        confidence: Option<f64>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        if norm_end < norm_start {
            return Err(DomainError::ValidationError {
                field: "norm_offsets",
                reason: format!("norm_start {norm_start} exceeds norm_end {norm_end}"),
            });
        }
        if section_path.len() > crate::limits::MAX_SECTION_DEPTH {
            return Err(DomainError::ValidationError {
                field: "section_path",
                reason: format!(
                    "section path depth {} exceeds {}",
                    section_path.len(),
                    crate::limits::MAX_SECTION_DEPTH
                ),
            });
        }
        for segment in &section_path {
            validate_non_empty("section_path_segment", segment)?;
            if segment.len() > crate::limits::MAX_SECTION_SEGMENT_BYTES {
                return Err(DomainError::ValidationError {
                    field: "section_path_segment",
                    reason: "section-path segment exceeds frozen bound".to_string(),
                });
            }
        }
        if let Some(c) = confidence
            && (!(0.0..=1.0).contains(&c) || !c.is_finite())
        {
            return Err(DomainError::ValidationError {
                field: "confidence",
                reason: format!("confidence {c} outside 0..=1"),
            });
        }
        Ok(Self {
            id,
            parser_page_id,
            workspace_id,
            ordinal,
            kind,
            norm_start,
            norm_end,
            bbox,
            section_path,
            text,
            confidence,
            created_at,
        })
    }

    /// Composition check against the owning stored page row.
    ///
    /// # Errors
    /// Fails with [`DomainError::CrossWorkspaceComposition`] on mismatch.
    pub fn bind_to_page(&self, page: &ParserPage) -> Result<(), DomainError> {
        if self.workspace_id != page.workspace_id {
            return Err(DomainError::CrossWorkspaceComposition {
                field: "parser_block.workspace_id",
            });
        }
        if self.parser_page_id != page.id {
            return Err(DomainError::ValidationError {
                field: "parser_block.parser_page_id",
                reason: "block does not belong to the given page".to_string(),
            });
        }
        Ok(())
    }

    /// Deterministic digest of the exact block text bytes.
    #[must_use]
    pub fn text_sha256(&self) -> Sha256 {
        Sha256::digest(self.text.as_bytes())
    }
}
