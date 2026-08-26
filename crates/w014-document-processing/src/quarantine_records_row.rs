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
    BoundedJson, DocumentVersionId, ObjectArtifactId, QuarantineRecord, QuarantineRecordId,
    QuarantineStatus, UploadIntentId, WorkspaceId,
};

use crate::error::{ContractError, ContractResult};

/// Authoritative column list of the `quarantine_records` physical read shape.
pub const QUARANTINE_RECORD_COLUMNS: &str = "quarantine_record_id, workspace_id, \
     upload_intent_id, document_version_id, object_artifact_id, scanner_name, scanner_version, \
     reason_code, status, checked_at, threat_details";

/// Exact read shape of a `quarantine_records` row.
#[derive(Debug, Clone, FromRow)]
pub struct QuarantineRecordRow {
    pub quarantine_record_id: Uuid,
    pub workspace_id: Uuid,
    /// Repaired explicit physical fact: mandatory scanned-intent tie.
    pub upload_intent_id: Uuid,
    pub document_version_id: Option<Uuid>,
    pub object_artifact_id: Option<Uuid>,
    pub scanner_name: String,
    /// Repaired explicit physical fact: optional scanner identity.
    pub scanner_version: Option<String>,
    /// Repaired explicit physical fact: optional outcome reason.
    pub reason_code: Option<String>,
    /// Repaired explicit physical fact: frozen scan-outcome domain.
    pub status: String,
    /// Repaired explicit physical fact: checked timestamp.
    pub checked_at: DateTime<Utc>,
    pub threat_details: serde_json::Value,
}

/// Exact insert shape of a new immutable scan-outcome record (rescans append).
#[derive(Debug, Clone)]
pub struct NewQuarantineRecordRow {
    pub quarantine_record_id: Uuid,
    pub workspace_id: Uuid,
    pub upload_intent_id: Uuid,
    pub document_version_id: Option<Uuid>,
    pub object_artifact_id: Option<Uuid>,
    pub scanner_name: String,
    pub scanner_version: Option<String>,
    pub reason_code: Option<String>,
    pub status: String,
    pub checked_at: DateTime<Utc>,
    pub threat_details: serde_json::Value,
}

/// Parameterized INSERT statement matching [`NewQuarantineRecordRow`] exactly
/// (insert-only: no UPDATE/DELETE statements exist in this module).
pub const INSERT_QUARANTINE_RECORD: &str = "INSERT INTO quarantine_records \
     (quarantine_record_id, workspace_id, upload_intent_id, document_version_id, \
      object_artifact_id, scanner_name, scanner_version, reason_code, status, checked_at, \
      threat_details) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";

fn to_bounded(value: &serde_json::Value) -> ContractResult<BoundedJson> {
    BoundedJson::new("threat_details", value.clone()).map_err(|_| ContractError::RowShape {
        table: "quarantine_records",
        field: "threat_details",
        reason: "stored threat details exceed the frozen bounded-JSON contract".to_string(),
    })
}

/// Projects an authoritative [`QuarantineRecord`] onto its insert shape.
///
/// # Errors
/// Propagates domain invariant validation.
pub fn new_row_from_record(record: &QuarantineRecord) -> ContractResult<NewQuarantineRecordRow> {
    Ok(NewQuarantineRecordRow {
        quarantine_record_id: record.id.into_uuid(),
        workspace_id: record.workspace_id.into_uuid(),
        upload_intent_id: record.upload_intent_id.into_uuid(),
        document_version_id: record.document_version_id.map(DocumentVersionId::into_uuid),
        object_artifact_id: record.object_artifact_id.map(ObjectArtifactId::into_uuid),
        scanner_name: record.scanner_name.clone(),
        scanner_version: record.scanner_version.clone(),
        reason_code: record.reason_code.clone(),
        status: record.status.as_str().to_string(),
        checked_at: record.checked_at,
        threat_details: record.threat_details.as_value().clone(),
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
    QuarantineRecord::reconstruct(
        QuarantineRecordId::from_uuid(row.quarantine_record_id),
        WorkspaceId::from_uuid(row.workspace_id),
        UploadIntentId::from_uuid(row.upload_intent_id),
        row.document_version_id.map(DocumentVersionId::from_uuid),
        row.object_artifact_id.map(ObjectArtifactId::from_uuid),
        status,
        row.scanner_name.clone(),
        row.scanner_version.clone(),
        row.reason_code.clone(),
        row.checked_at,
        to_bounded(&row.threat_details)?,
    )
    .map_err(ContractError::from)
}
