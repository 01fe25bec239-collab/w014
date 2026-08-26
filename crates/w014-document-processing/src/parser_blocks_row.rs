//! Row contract for `parser_blocks` (M002R physical columns 1:1).
//!
//! Explicit physical facts (`block_sequence`, `block_type`, `bounding_box`,
//! `text_content`, `confidence`) are consumed directly. Frozen Prompt-12
//! block facts without a dedicated column (section path) travel under the
//! fixed [`conventions`] keys inside the sanctioned bounded `metadata` JSONB
//! column — never as substitutes for explicit columns.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;
use w014_domain::{
    BlockKind, BoundingBox, DomainError, ParserBlock, ParserBlockId, ParserPageId, WorkspaceId,
};

use crate::conventions;
use crate::error::{ContractError, ContractResult};

/// Authoritative column list of the `parser_blocks` physical read shape.
pub const PARSER_BLOCK_COLUMNS: &str = "parser_block_id, parser_page_id, workspace_id, \
     block_sequence, block_type, bounding_box, text_content, confidence, metadata, created_at";

/// Exact read shape of a `parser_blocks` row.
#[derive(Debug, Clone, FromRow)]
pub struct ParserBlockRow {
    pub parser_block_id: Uuid,
    pub parser_page_id: Uuid,
    pub workspace_id: Uuid,
    /// Block ordinal >= 0 (explicit physical fact).
    pub block_sequence: i32,
    /// Closed block-kind domain (explicit physical fact).
    pub block_type: String,
    /// JSONB `{x, y, width, height}` or SQL NULL.
    pub bounding_box: Option<serde_json::Value>,
    pub text_content: String,
    pub confidence: Option<f64>,
    /// Bounded metadata JSONB carrying fixed-key Prompt-12 block facts.
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Exact insert shape of a new insert-only block fact.
#[derive(Debug, Clone)]
pub struct NewParserBlockRow {
    pub parser_block_id: Uuid,
    pub parser_page_id: Uuid,
    pub workspace_id: Uuid,
    pub block_sequence: i32,
    pub block_type: String,
    pub bounding_box: Option<serde_json::Value>,
    pub text_content: String,
    pub confidence: Option<f64>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Parameterized INSERT statement matching [`NewParserBlockRow`] exactly
/// (insert-only: no UPDATE/DELETE statements exist in this module).
pub const INSERT_PARSER_BLOCK: &str = "INSERT INTO parser_blocks \
     (parser_block_id, parser_page_id, workspace_id, block_sequence, block_type, bounding_box, \
      text_content, confidence, metadata, created_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";

const CONTEXT: &str = "parser_blocks";

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

fn section_path_from_metadata(metadata: &serde_json::Value) -> ContractResult<Vec<String>> {
    match metadata.get(conventions::SECTION_PATH) {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let s = item.as_str().ok_or_else(|| ContractError::JsonConvention {
                    key: conventions::SECTION_PATH,
                    context: CONTEXT,
                    reason: "section path entries must be strings".to_string(),
                })?;
                out.push(s.to_string());
            }
            Ok(out)
        }
        Some(_) => Err(ContractError::JsonConvention {
            key: conventions::SECTION_PATH,
            context: CONTEXT,
            reason: "section path must be an array of strings".to_string(),
        }),
    }
}

/// Projects an authoritative [`ParserBlock`] onto its insert shape under its
/// owning page's identity and workspace scope.
///
/// # Errors
/// Fails closed on cross-workspace pairing or out-of-INT ordinals.
pub fn new_row_from_block(
    block: &ParserBlock,
    parser_page_workspace_id: WorkspaceId,
) -> ContractResult<NewParserBlockRow> {
    if block.workspace_id != parser_page_workspace_id {
        return Err(ContractError::Domain(
            DomainError::CrossWorkspaceComposition {
                field: "parser_block.workspace_id",
            },
        ));
    }
    let mut metadata = serde_json::Value::Object(serde_json::Map::new());
    if !block.section_path.is_empty() {
        metadata.as_object_mut().expect("fresh object").insert(
            conventions::SECTION_PATH.to_string(),
            serde_json::Value::Array(
                block
                    .section_path
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    conventions::put_offset_pair(
        &mut metadata,
        conventions::NORM_OFFSET_RANGE,
        Some((block.norm_start, block.norm_end)),
    )?;
    Ok(NewParserBlockRow {
        parser_block_id: block.id.into_uuid(),
        parser_page_id: block.parser_page_id.into_uuid(),
        workspace_id: block.workspace_id.into_uuid(),
        block_sequence: i32::try_from(block.ordinal).map_err(|_| ContractError::RowShape {
            table: "parser_blocks",
            field: "block_sequence",
            reason: format!("ordinal {} exceeds INT4", block.ordinal),
        })?,
        block_type: block.kind.as_str().to_string(),
        bounding_box: bbox_to_json(block.bbox),
        text_content: block.text.clone(),
        confidence: block.confidence,
        metadata,
        created_at: block.created_at,
    })
}

/// Reconstructs the authoritative [`ParserBlock`] from the stored row ALONE.
///
/// # Errors
/// Fails closed on closed-domain violations or malformed convention values.
pub fn block_from_row(row: &ParserBlockRow) -> ContractResult<ParserBlock> {
    let ordinal = u32::try_from(row.block_sequence).map_err(|_| ContractError::RowShape {
        table: "parser_blocks",
        field: "block_sequence",
        reason: format!("stored ordinal {} is not representable", row.block_sequence),
    })?;
    let kind = BlockKind::parse(&row.block_type).map_err(|_| ContractError::RowShape {
        table: "parser_blocks",
        field: "block_type",
        reason: format!("'{}' outside closed block-kind domain", row.block_type),
    })?;
    let (norm_start, norm_end) =
        conventions::get_offset_pair(&row.metadata, conventions::NORM_OFFSET_RANGE, CONTEXT)?
            .unwrap_or((0, 0));
    ParserBlock::reconstruct(
        ParserBlockId::from_uuid(row.parser_block_id),
        ParserPageId::from_uuid(row.parser_page_id),
        WorkspaceId::from_uuid(row.workspace_id),
        ordinal,
        kind,
        norm_start,
        norm_end,
        bbox_from_json(&row.bounding_box)?,
        section_path_from_metadata(&row.metadata)?,
        row.text_content.clone(),
        row.confidence,
        row.created_at,
    )
    .map_err(ContractError::from)
}
