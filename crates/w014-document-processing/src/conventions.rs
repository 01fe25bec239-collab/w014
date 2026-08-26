//! Fixed-key JSONB conventions for frozen Prompt-12 facts that have NO
//! dedicated physical column in the repaired M002R catalog.
//!
//! Scope guard (WI-0201-C): these conventions exist ONLY for facts without
//! an explicit column. Every fact that the Persistence-State repair exposed
//! as an explicit PostgreSQL column is consumed directly by its row contract
//! and NEVER routed through this module:
//!   documents.current_version_id
//!   document_versions.object_artifact_id / .original_filename
//!   upload_intents.opaque_object_key / .expected_media_type /
//!     .expected_length / .expected_sha256_b64
//!   object_artifacts.artifact_kind / .object_key / .content_sha256 /
//!     .sse_mode / .kms_key_ref
//!   quarantine_records.upload_intent_id / .status / .scanner_version /
//!     .reason_code
//!   parser_artifacts.locator_version / .artifact_object_id / .text_sha256

use serde_json::{Value, json};

use crate::error::{ContractError, ContractResult};

/// Declared revision (data only) inside `document_version_metadata.metadata`.
pub const DECLARED_REVISION: &str = "w014.declared_revision";
/// Internal revision (data only) inside `document_version_metadata.metadata`.
pub const INTERNAL_REVISION: &str = "w014.internal_revision";
/// Extraction method key inside page/block/span `metadata` columns.
pub const EXTRACTION_METHOD: &str = "w014.extraction_method";
/// OCR participation flag inside page/span `metadata` columns.
pub const OCR_USED: &str = "w014.ocr_used";
/// Optional quality score inside page/block/span `metadata` columns.
pub const QUALITY_SCORE: &str = "w014.quality_score";
/// Ordered section path inside block/span `metadata` columns.
pub const SECTION_PATH: &str = "w014.section_path";
/// Normalized offset range inside block `metadata` columns.
pub const NORM_OFFSET_RANGE: &str = "w014.norm_offset_range";
/// Optional raw byte offset range inside span `metadata` columns.
pub const RAW_OFFSET_RANGE: &str = "w014.raw_offset_range";
/// Canonical span hash (hex) inside span `metadata` columns.
pub const SPAN_SHA256: &str = "w014.span_sha256";

/// Reads an optional i64 under a fixed key.
///
/// # Errors
/// Fails when present but not an integer.
pub fn get_i64(
    value: &Value,
    key: &'static str,
    context: &'static str,
) -> ContractResult<Option<i64>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .map(Some)
            .ok_or_else(|| ContractError::JsonConvention {
                key,
                context,
                reason: "expected an integer".to_string(),
            }),
    }
}

/// Writes an optional i64 under a fixed key into an owned object.
///
/// # Errors
/// Fails when the target value is not a JSON object.
pub fn put_i64(target: &mut Value, key: &'static str, val: Option<i64>) -> ContractResult<()> {
    let obj = target
        .as_object_mut()
        .ok_or_else(|| ContractError::JsonConvention {
            key,
            context: "put_i64",
            reason: "target must be a JSON object".to_string(),
        })?;
    if let Some(v) = val {
        obj.insert(key.to_string(), json!(v));
    }
    Ok(())
}

/// Reads an optional boolean under a fixed key.
///
/// # Errors
/// Fails when present but not a boolean.
pub fn get_bool(
    value: &Value,
    key: &'static str,
    context: &'static str,
) -> ContractResult<Option<bool>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_bool()
            .map(Some)
            .ok_or_else(|| ContractError::JsonConvention {
                key,
                context,
                reason: "expected a boolean".to_string(),
            }),
    }
}

/// Writes an optional boolean under a fixed key into an owned object.
///
/// # Errors
/// Fails when the target value is not a JSON object.
pub fn put_bool(target: &mut Value, key: &'static str, val: Option<bool>) -> ContractResult<()> {
    let obj = target
        .as_object_mut()
        .ok_or_else(|| ContractError::JsonConvention {
            key,
            context: "put_bool",
            reason: "target must be a JSON object".to_string(),
        })?;
    if let Some(v) = val {
        obj.insert(key.to_string(), json!(v));
    }
    Ok(())
}

/// Reads an optional f64 under a fixed key.
///
/// # Errors
/// Fails when present but not a finite number.
pub fn get_f64(
    value: &Value,
    key: &'static str,
    context: &'static str,
) -> ContractResult<Option<f64>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_f64()
            .filter(|f| f.is_finite())
            .map(Some)
            .ok_or_else(|| ContractError::JsonConvention {
                key,
                context,
                reason: "expected a finite number".to_string(),
            }),
    }
}

/// Writes an optional f64 under a fixed key into an owned object.
///
/// # Errors
/// Fails when the target value is not a JSON object.
pub fn put_f64(target: &mut Value, key: &'static str, val: Option<f64>) -> ContractResult<()> {
    let obj = target
        .as_object_mut()
        .ok_or_else(|| ContractError::JsonConvention {
            key,
            context: "put_f64",
            reason: "target must be a JSON object".to_string(),
        })?;
    if let Some(v) = val {
        obj.insert(key.to_string(), json!(v));
    }
    Ok(())
}

/// Reads an optional string under a fixed key.
///
/// # Errors
/// Fails when present but not a string.
pub fn get_str<'a>(
    value: &'a Value,
    key: &'static str,
    context: &'static str,
) -> ContractResult<Option<&'a str>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .map(Some)
            .ok_or_else(|| ContractError::JsonConvention {
                key,
                context,
                reason: "expected a string".to_string(),
            }),
    }
}

/// Writes an optional string under a fixed key into an owned object.
///
/// # Errors
/// Fails when the target value is not a JSON object.
pub fn put_str(target: &mut Value, key: &'static str, val: Option<&str>) -> ContractResult<()> {
    let obj = target
        .as_object_mut()
        .ok_or_else(|| ContractError::JsonConvention {
            key,
            context: "put_str",
            reason: "target must be a JSON object".to_string(),
        })?;
    if let Some(v) = val {
        obj.insert(key.to_string(), json!(v));
    }
    Ok(())
}

/// Reads an optional `{start, end}` integer pair under a fixed key.
///
/// # Errors
/// Fails when present but malformed.
pub fn get_offset_pair(
    value: &Value,
    key: &'static str,
    context: &'static str,
) -> ContractResult<Option<(u32, u32)>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let obj = v.as_object().ok_or_else(|| ContractError::JsonConvention {
                key,
                context,
                reason: "expected a {start, end} object".to_string(),
            })?;
            let start = obj.get("start").and_then(Value::as_u64).ok_or_else(|| {
                ContractError::JsonConvention {
                    key,
                    context,
                    reason: "missing/invalid 'start'".to_string(),
                }
            })?;
            let end = obj.get("end").and_then(Value::as_u64).ok_or_else(|| {
                ContractError::JsonConvention {
                    key,
                    context,
                    reason: "missing/invalid 'end'".to_string(),
                }
            })?;
            let start = u32::try_from(start).map_err(|_| ContractError::JsonConvention {
                key,
                context,
                reason: "'start' out of range".to_string(),
            })?;
            let end = u32::try_from(end).map_err(|_| ContractError::JsonConvention {
                key,
                context,
                reason: "'end' out of range".to_string(),
            })?;
            Ok(Some((start, end)))
        }
    }
}

/// Writes an optional `{start, end}` pair under a fixed key.
///
/// # Errors
/// Fails when the target value is not a JSON object.
pub fn put_offset_pair(
    target: &mut Value,
    key: &'static str,
    pair: Option<(u32, u32)>,
) -> ContractResult<()> {
    let obj = target
        .as_object_mut()
        .ok_or_else(|| ContractError::JsonConvention {
            key,
            context: "put_offset_pair",
            reason: "target must be a JSON object".to_string(),
        })?;
    if let Some((start, end)) = pair {
        obj.insert(key.to_string(), json!({"start": start, "end": end}));
    }
    Ok(())
}
