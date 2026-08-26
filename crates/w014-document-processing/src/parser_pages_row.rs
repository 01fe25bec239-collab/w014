//! Row contract for `parser_pages` (M002R physical columns 1:1).
//!
//! Explicit physical facts (`page_number`, `text_content`, dimensions,
//! `rotation`) are consumed directly. Frozen Prompt-12 page facts without a
//! dedicated column (extraction method, OCR participation, quality score)
//! travel under the fixed [`conventions`] keys inside the sanctioned
//! bounded `metadata` JSONB column — never as substitutes for explicit
//! columns.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;
use w014_domain::{
    ExtractionMethod, ParserArtifactId, ParserPage, ParserPageId, Rotation, WorkspaceId,
};

use crate::conventions;
use crate::error::{ContractError, ContractResult};

/// Authoritative column list of the `parser_pages` physical read shape.
pub const PARSER_PAGE_COLUMNS: &str = "parser_page_id, parser_artifact_id, workspace_id, \
     page_number, width, height, rotation, text_content, metadata, created_at";

/// Exact read shape of a `parser_pages` row.
#[derive(Debug, Clone, FromRow)]
pub struct ParserPageRow {
    pub parser_page_id: Uuid,
    pub parser_artifact_id: Uuid,
    pub workspace_id: Uuid,
    /// 1-based bounded page number (explicit physical fact).
    pub page_number: i32,
    pub width: Option<f64>,
    pub height: Option<f64>,
    pub rotation: i32,
    /// Normalized inert text (explicit physical fact).
    pub text_content: String,
    /// Bounded metadata JSONB carrying fixed-key Prompt-12 page facts.
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Exact insert shape of a new insert-only page fact.
#[derive(Debug, Clone)]
pub struct NewParserPageRow {
    pub parser_page_id: Uuid,
    pub parser_artifact_id: Uuid,
    pub workspace_id: Uuid,
    pub page_number: i32,
    pub width: Option<f64>,
    pub height: Option<f64>,
    pub rotation: i32,
    pub text_content: String,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Parameterized INSERT statement matching [`NewParserPageRow`] exactly
/// (insert-only: no UPDATE/DELETE statements exist in this module).
pub const INSERT_PARSER_PAGE: &str = "INSERT INTO parser_pages \
     (parser_page_id, parser_artifact_id, workspace_id, page_number, width, height, rotation, \
      text_content, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";

/// Projects an authoritative [`ParserPage`] onto its insert shape under its
/// owning artifact's identity and workspace scope.
///
/// # Errors
/// Fails closed on cross-workspace pairing or out-of-INT page numbers.
pub fn new_row_from_page(
    page: &ParserPage,
    parser_artifact_workspace_id: WorkspaceId,
) -> ContractResult<NewParserPageRow> {
    if page.workspace_id != parser_artifact_workspace_id {
        return Err(ContractError::Domain(
            w014_domain::DomainError::CrossWorkspaceComposition {
                field: "parser_page.workspace_id",
            },
        ));
    }
    let mut metadata = serde_json::Value::Object(serde_json::Map::new());
    conventions::put_str(
        &mut metadata,
        conventions::EXTRACTION_METHOD,
        Some(page.extraction.as_str()),
    )?;
    conventions::put_bool(&mut metadata, conventions::OCR_USED, Some(page.ocr_used))?;
    conventions::put_f64(
        &mut metadata,
        conventions::QUALITY_SCORE,
        page.quality_score,
    )?;
    Ok(NewParserPageRow {
        parser_page_id: page.id.into_uuid(),
        parser_artifact_id: page.parser_artifact_id.into_uuid(),
        workspace_id: page.workspace_id.into_uuid(),
        page_number: i32::try_from(page.page_number).map_err(|_| ContractError::RowShape {
            table: "parser_pages",
            field: "page_number",
            reason: format!("page {} exceeds INT4", page.page_number),
        })?,
        width: page.width,
        height: page.height,
        rotation: page.rotation.as_i32(),
        text_content: page.normalized_text.clone(),
        metadata,
        created_at: page.created_at,
    })
}

/// Reconstructs the authoritative [`ParserPage`] from the stored row ALONE.
///
/// # Errors
/// Fails closed on out-of-bounds page numbers, malformed convention values,
/// or violated bounds.
pub fn page_from_row(row: &ParserPageRow) -> ContractResult<ParserPage> {
    let page_number = u32::try_from(row.page_number).map_err(|_| ContractError::RowShape {
        table: "parser_pages",
        field: "page_number",
        reason: format!(
            "stored page number {} is not representable",
            row.page_number
        ),
    })?;
    let extraction_raw = conventions::get_str(
        &row.metadata,
        conventions::EXTRACTION_METHOD,
        "parser_pages",
    )?
    .ok_or_else(|| ContractError::JsonConvention {
        key: conventions::EXTRACTION_METHOD,
        context: "parser_pages",
        reason: "extraction method fact is missing".to_string(),
    })?;
    let extraction =
        ExtractionMethod::parse(extraction_raw).map_err(|_| ContractError::JsonConvention {
            key: conventions::EXTRACTION_METHOD,
            context: "parser_pages",
            reason: format!("'{extraction_raw}' outside closed extraction-method domain"),
        })?;
    let ocr_used = conventions::get_bool(&row.metadata, conventions::OCR_USED, "parser_pages")?
        .unwrap_or(false);
    ParserPage::reconstruct(
        ParserPageId::from_uuid(row.parser_page_id),
        ParserArtifactId::from_uuid(row.parser_artifact_id),
        WorkspaceId::from_uuid(row.workspace_id),
        page_number,
        row.text_content.clone(),
        extraction,
        ocr_used,
        conventions::get_f64(&row.metadata, conventions::QUALITY_SCORE, "parser_pages")?,
        row.width,
        row.height,
        Rotation::parse(row.rotation).map_err(|_| ContractError::RowShape {
            table: "parser_pages",
            field: "rotation",
            reason: format!("stored rotation {} outside frozen domain", row.rotation),
        })?,
        row.created_at,
    )
    .map_err(ContractError::from)
}
