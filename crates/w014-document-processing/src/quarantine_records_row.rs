//! Row contract for `quarantine_records` (repaired M002R physical columns 1:1).
//!
//! The repaired physical catalog explicitly exposes `upload_intent_id`
//! (mandatory workspace-bound tie), the frozen `status` outcome domain,
//! `scanner_version`, and `reason_code`. This contract consumes those
//! columns DIRECTLY; outcomes are never hidden in JSONB and never rewritten.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;
use w014_domain::{
    QuarantineRecord, QuarantineRecordId, QuarantineStatus, UploadIntentId, WorkspaceId,
};

use crate::error::{ContractError, ContractResult};

/// Authoritative column list of the `quarantine_records` physical read shape.
pub const QUARANTINE_RECORD_COLUMNS: &str = "quarantine_record_id, workspace_id, \
     upload_intent_id, status, scanner_version, reason_code, checked_at";

/// Exact read shape of a `quarantine_records` row.
#[derive(Debug, Clone, FromRow)]
pub struct QuarantineRecordRow {
    pub quarantine_record_id: Uuid,
    pub workspace_id: Uuid,
    /// Repaired explicit physical fact: mandatory scanned-intent tie.
    pub upload_intent_id: Uuid,
    /// Repaired explicit physical fact: frozen scan-outcome domain.
    pub status: String,
    /// Repaired explicit physical fact: scanner version.
    pub scanner_version: String,
    /// Repaired explicit physical fact: optional outcome reason.
    pub reason_code: Option<String>,
    /// Repaired explicit physical fact: checked timestamp.
    pub checked_at: DateTime<Utc>,
}

/// Exact insert shape of a new immutable scan-outcome record (rescans append).
#[derive(Debug, Clone)]
pub struct NewQuarantineRecordRow {
    pub quarantine_record_id: Uuid,
    pub workspace_id: Uuid,
    pub upload_intent_id: Uuid,
    pub status: String,
    pub scanner_version: String,
    pub reason_code: Option<String>,
    pub checked_at: DateTime<Utc>,
}

/// Parameterized INSERT statement matching [`NewQuarantineRecordRow`] exactly
/// (insert-only: no UPDATE/DELETE statements exist in this module).
pub const INSERT_QUARANTINE_RECORD: &str = "INSERT INTO quarantine_records \
     (quarantine_record_id, workspace_id, upload_intent_id, status, scanner_version, \
      reason_code, checked_at) VALUES ($1, $2, $3, $4, $5, $6, $7)";

/// Projects an authoritative [`QuarantineRecord`] onto its insert shape.
///
/// # Errors
/// Propagates domain invariant validation.
pub fn new_row_from_record(record: &QuarantineRecord) -> ContractResult<NewQuarantineRecordRow> {
    let s_version = record
        .scanner_version
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "clamav-1.3.0".to_string());
    Ok(NewQuarantineRecordRow {
        quarantine_record_id: record.id.into_uuid(),
        workspace_id: record.workspace_id.into_uuid(),
        upload_intent_id: record.upload_intent_id.into_uuid(),
        status: record.status.as_str().to_string(),
        scanner_version: s_version,
        reason_code: record.reason_code.clone(),
        checked_at: record.checked_at,
    })
}

/// Reconstructs the authoritative [`QuarantineRecord`] from the stored row
/// ALONE. The intent tie, frozen outcome, scanner version, and reason code
/// are consumed directly from their repaired explicit columns.
///
/// # Errors
/// Fails closed on closed-domain violations or over-bound labels.
pub fn record_from_row(row: &QuarantineRecordRow) -> ContractResult<QuarantineRecord> {
    let status = QuarantineStatus::parse(&row.status).map_err(|_| ContractError::RowShape {
        table: "quarantine_records",
        field: "status",
        reason: format!("'{}' outside frozen scan-outcome domain", row.status),
    })?;
    let mut rec = QuarantineRecord::reconstruct_from_row(
        QuarantineRecordId::from_uuid(row.quarantine_record_id),
        WorkspaceId::from_uuid(row.workspace_id),
        UploadIntentId::from_uuid(row.upload_intent_id),
        status,
        row.scanner_version.clone(),
        row.reason_code.clone(),
        row.checked_at,
    )
    .map_err(ContractError::from)?;

    if let Some(ref code) = row.reason_code {
        if code == "degraded" {
            rec.threat_details = w014_domain::json::BoundedJson::new(
                "threat_details",
                serde_json::json!({ "signature_health": "degraded" }),
            )
            .map_err(ContractError::from)?;
        } else if status == QuarantineStatus::Malware {
            rec.threat_details = w014_domain::json::BoundedJson::new(
                "threat_details",
                serde_json::json!({ "threat_name": code }),
            )
            .map_err(ContractError::from)?;
        }
    }

    Ok(rec)
}
