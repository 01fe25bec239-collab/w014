//! Row contract for `source_spans` (M002R physical columns 1:1).
//!
//! Explicit physical facts (`span_sequence`, `start_char`, `end_char`,
//! `text_content`, `bounding_box`, `confidence`) are consumed directly.
//! Frozen Prompt-12 span facts without a dedicated column (raw offsets,
//! section path, extraction method, quality score, and the canonical
//! `span_sha256`) travel under the fixed [`conventions`] keys inside the
//! sanctioned bounded `metadata` JSONB column.
//!
//! Provenance resolution rule (no caller-context substitution): the canonical
//! provenance chain — workspace, document_version_id, parser_artifact_id,
//! locator_version, page_number — has no columns on `source_spans` by design;
//! it is resolved exclusively through the authoritative block→page→artifact
//! joins. [`SpanProvenanceJoin`] is constructed only from those stored rows.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;
use w014_domain::{
    BoundingBox, DocumentVersionId, DomainError, ExtractionMethod, LocatorVersion, OffsetRange,
    ParserArtifactId, SectionPath, SourceSpan, SourceSpanId, SpanProvenance, WorkspaceId,
};

use crate::conventions;
use crate::error::{ContractError, ContractResult};

/// Authoritative column list of the `source_spans` physical read shape.
pub const SOURCE_SPAN_COLUMNS: &str = "source_span_id, parser_block_id, workspace_id, \
     span_sequence, start_char, end_char, text_content, bounding_box, confidence, metadata, \
     created_at";

/// Exact read shape of a `source_spans` row.
#[derive(Debug, Clone, FromRow)]
pub struct SourceSpanRow {
    pub source_span_id: Uuid,
    pub parser_block_id: Uuid,
    pub workspace_id: Uuid,
    /// Insert-only ordinal (explicit physical fact).
    pub span_sequence: i32,
    /// Normalized start offset (explicit physical fact).
    pub start_char: i32,
    /// Normalized end offset (explicit physical fact).
    pub end_char: i32,
    /// Bounded normalized span text (explicit physical fact).
    pub text_content: String,
    /// JSONB `{x, y, width, height}` or SQL NULL.
    pub bounding_box: Option<serde_json::Value>,
    pub confidence: Option<f64>,
    /// Bounded metadata JSONB carrying fixed-key Prompt-12 span facts.
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Exact insert shape of a new insert-only span fact.
#[derive(Debug, Clone)]
pub struct NewSourceSpanRow {
    pub source_span_id: Uuid,
    pub parser_block_id: Uuid,
    pub workspace_id: Uuid,
    pub span_sequence: i32,
    pub start_char: i32,
    pub end_char: i32,
    pub text_content: String,
    pub bounding_box: Option<serde_json::Value>,
    pub confidence: Option<f64>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Parameterized INSERT statement matching [`NewSourceSpanRow`] exactly
/// (insert-only: no UPDATE/DELETE statements exist in this module).
pub const INSERT_SOURCE_SPAN: &str = "INSERT INTO source_spans \
     (source_span_id, parser_block_id, workspace_id, span_sequence, start_char, end_char, \
      text_content, bounding_box, confidence, metadata, created_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";

/// Authoritative join projection resolving the canonical span-provenance
/// chain from its stored parent rows (block → page → artifact). Constructed
/// ONLY from stored rows; never from caller-fabricated context.
#[derive(Debug, Clone, FromRow)]
pub struct SpanProvenanceJoin {
    /// Resolved through `parser_blocks.workspace_id`.
    pub workspace_id: Uuid,
    /// Resolved through `parser_artifacts.document_version_id`.
    pub document_version_id: Uuid,
    /// Resolved through `parser_pages.parser_artifact_id`.
    pub parser_artifact_id: Uuid,
    /// Resolved through `parser_artifacts.locator_version`.
    pub locator_version: String,
    /// Resolved through `parser_pages.page_number`.
    pub page_number: i32,
}

impl SpanProvenanceJoin {
    /// Validates the resolved chain against the stored span row: proves the
    /// join actually anchored inside the span's own workspace.
    ///
    /// # Errors
    /// Fails closed on cross-workspace resolutions.
    pub fn validate_against_stored(&self, span_row: &SourceSpanRow) -> Result<(), DomainError> {
        if self.workspace_id != span_row.workspace_id {
            return Err(DomainError::CrossWorkspaceComposition {
                field: "source_span.provenance.workspace_id",
            });
        }
        Ok(())
    }

    /// Converts the validated join projection into domain provenance.
    ///
    /// # Errors
    /// Fails closed on out-of-bounds page numbers or invalid locator labels.
    pub fn into_domain(self) -> ContractResult<SpanProvenance> {
        let page_number = u32::try_from(self.page_number).map_err(|_| ContractError::RowShape {
            table: "parser_pages",
            field: "page_number",
            reason: format!(
                "stored page number {} is not representable",
                self.page_number
            ),
        })?;
        Ok(SpanProvenance::new(
            WorkspaceId::from_uuid(self.workspace_id),
            DocumentVersionId::from_uuid(self.document_version_id),
            ParserArtifactId::from_uuid(self.parser_artifact_id),
            LocatorVersion::new(self.locator_version).map_err(|_| ContractError::RowShape {
                table: "parser_artifacts",
                field: "locator_version",
                reason: "joined locator identity violates the frozen label contract".to_string(),
            })?,
            page_number,
        )?)
    }
}

const CONTEXT: &str = "source_spans";

fn bbox_to_json(bbox: Option<BoundingBox>) -> Option<serde_json::Value> {
    bbox.map(|b| {
        serde_json::json!({
            "x": b.x,
            "y": b.y,
            "width": b.width,
            "height": b.height,
        })
    })
}

fn bbox_from_json(value: &Option<serde_json::Value>) -> ContractResult<Option<BoundingBox>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => {
            let obj = v.as_object().ok_or_else(|| ContractError::JsonConvention {
                key: "bounding_box",
                context: CONTEXT,
                reason: "bounding box must be a JSON object".to_string(),
            })?;
            let num = |field: &'static str| -> ContractResult<f64> {
                obj.get(field)
                    .and_then(serde_json::Value::as_f64)
                    .ok_or_else(|| ContractError::JsonConvention {
                        key: field,
                        context: CONTEXT,
                        reason: "bounding box component must be numeric".to_string(),
                    })
            };
            Ok(Some(BoundingBox::new(
                num("x")?,
                num("y")?,
                num("width")?,
                num("height")?,
            )?))
        }
    }
}

fn optional_range(value: Option<(u32, u32)>) -> ContractResult<Option<OffsetRange>> {
    value
        .map(|(s, e)| OffsetRange::new(s, e))
        .transpose()
        .map_err(ContractError::from)
}

fn section_path(metadata: &serde_json::Value) -> ContractResult<Option<SectionPath>> {
    match metadata.get(conventions::SECTION_PATH) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Array(items)) => {
            let mut segments = Vec::with_capacity(items.len());
            for item in items {
                let s = item.as_str().ok_or_else(|| ContractError::JsonConvention {
                    key: conventions::SECTION_PATH,
                    context: CONTEXT,
                    reason: "section path entries must be strings".to_string(),
                })?;
                segments.push(s.to_string());
            }
            if segments.is_empty() {
                return Ok(None);
            }
            SectionPath::new(segments)
                .map(Some)
                .map_err(ContractError::from)
        }
        Some(_) => Err(ContractError::JsonConvention {
            key: conventions::SECTION_PATH,
            context: CONTEXT,
            reason: "section path must be an array of strings".to_string(),
        }),
    }
}

/// Projects an authoritative [`SourceSpan`] onto its insert shape under the
/// given owning stored block row.
///
/// # Errors
/// Fails closed on cross-workspace pairing or out-of-INT offsets.
pub fn new_row_from_span(
    span: &SourceSpan,
    parser_block_id: Uuid,
    block_workspace_id: Uuid,
) -> ContractResult<NewSourceSpanRow> {
    if span.provenance.workspace_id.into_uuid() != block_workspace_id {
        return Err(ContractError::Domain(
            DomainError::CrossWorkspaceComposition {
                field: "source_span.parser_block_id",
            },
        ));
    }
    let mut metadata = serde_json::Value::Object(serde_json::Map::new());
    conventions::put_offset_pair(
        &mut metadata,
        conventions::RAW_OFFSET_RANGE,
        span.raw_range.map(|r| (r.start, r.end)),
    )?;
    if let Some(path) = &span.section_path {
        metadata.as_object_mut().expect("fresh object").insert(
            conventions::SECTION_PATH.to_string(),
            serde_json::Value::Array(
                path.segments()
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    conventions::put_str(
        &mut metadata,
        conventions::EXTRACTION_METHOD,
        Some(span.extraction.as_str()),
    )?;
    conventions::put_f64(
        &mut metadata,
        conventions::QUALITY_SCORE,
        span.quality_score,
    )?;
    metadata.as_object_mut().expect("fresh object").insert(
        conventions::SPAN_SHA256.to_string(),
        serde_json::Value::String(span.span_sha256().to_hex()),
    );

    Ok(NewSourceSpanRow {
        source_span_id: span.id.into_uuid(),
        parser_block_id,
        workspace_id: span.provenance.workspace_id.into_uuid(),
        span_sequence: i32::try_from(span.span_sequence).map_err(|_| ContractError::RowShape {
            table: "source_spans",
            field: "span_sequence",
            reason: format!("sequence {} exceeds INT4", span.span_sequence),
        })?,
        start_char: i32::try_from(span.normalized_range.start).map_err(|_| {
            ContractError::RowShape {
                table: "source_spans",
                field: "start_char",
                reason: format!("offset {} exceeds INT4", span.normalized_range.start),
            }
        })?,
        end_char: i32::try_from(span.normalized_range.end).map_err(|_| {
            ContractError::RowShape {
                table: "source_spans",
                field: "end_char",
                reason: format!("offset {} exceeds INT4", span.normalized_range.end),
            }
        })?,
        text_content: span.text.clone(),
        bounding_box: bbox_to_json(span.bbox),
        confidence: span.quality_score,
        metadata,
        created_at: Utc::now(),
    })
}

/// Reconstructs the authoritative [`SourceSpan`] from the stored row ALONE
/// plus the join-resolved provenance chain, re-verifying the canonical hash
/// fail-closed.
///
/// # Errors
/// Fails closed on malformed convention values, over-bound text, or
/// canonical-hash mismatches.
pub fn span_from_row(
    row: &SourceSpanRow,
    provenance_join: SpanProvenanceJoin,
) -> ContractResult<SourceSpan> {
    provenance_join.validate_against_stored(row)?;
    let provenance = provenance_join.into_domain()?;
    let sequence = u32::try_from(row.span_sequence).map_err(|_| ContractError::RowShape {
        table: "source_spans",
        field: "span_sequence",
        reason: format!("stored sequence {} is not representable", row.span_sequence),
    })?;
    let start = u32::try_from(row.start_char.max(0)).map_err(|_| ContractError::RowShape {
        table: "source_spans",
        field: "start_char",
        reason: format!("stored offset {} is not representable", row.start_char),
    })?;
    let end = u32::try_from(row.end_char.max(0)).map_err(|_| ContractError::RowShape {
        table: "source_spans",
        field: "end_char",
        reason: format!("stored offset {} is not representable", row.end_char),
    })?;
    let raw_range = optional_range(conventions::get_offset_pair(
        &row.metadata,
        conventions::RAW_OFFSET_RANGE,
        CONTEXT,
    )?)?;
    let extraction_raw =
        conventions::get_str(&row.metadata, conventions::EXTRACTION_METHOD, CONTEXT)?
            .ok_or_else(|| ContractError::JsonConvention {
                key: conventions::EXTRACTION_METHOD,
                context: CONTEXT,
                reason: "extraction method fact is missing".to_string(),
            })?
            .to_string();
    let extraction =
        ExtractionMethod::parse(&extraction_raw).map_err(|_| ContractError::JsonConvention {
            key: conventions::EXTRACTION_METHOD,
            context: CONTEXT,
            reason: format!("'{extraction_raw}' outside closed extraction-method domain"),
        })?;
    let claimed_hex = conventions::get_str(&row.metadata, conventions::SPAN_SHA256, CONTEXT)?
        .ok_or_else(|| ContractError::JsonConvention {
            key: conventions::SPAN_SHA256,
            context: CONTEXT,
            reason: "canonical span hash fact is missing".to_string(),
        })?
        .to_string();
    let claimed = w014_domain::Sha256::from_hex("span_sha256", &claimed_hex).map_err(|_| {
        ContractError::JsonConvention {
            key: conventions::SPAN_SHA256,
            context: CONTEXT,
            reason: "stored span hash is not 64 hex characters".to_string(),
        }
    })?;

    SourceSpan::reconstruct_with_hash(
        SourceSpanId::from_uuid(row.source_span_id),
        provenance,
        sequence,
        OffsetRange::new(start, end)?,
        raw_range,
        bbox_from_json(&row.bounding_box)?,
        section_path(&row.metadata)?,
        row.text_content.clone(),
        extraction,
        row.confidence,
        &claimed,
    )
    .map_err(ContractError::from)
}
