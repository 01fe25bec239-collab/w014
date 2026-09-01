//! Persistence repository implementations for Document Pipeline entities.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256 as Sha256Hasher};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
use w014_document_processing::document_versions_row::{
    DocumentVersionRow, INSERT_DOCUMENT_VERSION, new_row_from_version, version_from_row,
};
use w014_document_processing::documents_row::{
    DocumentRow, INSERT_DOCUMENT, UPDATE_CURRENT_VERSION, document_from_row, new_row_from_document,
};
use w014_document_processing::object_artifacts_row::{
    INSERT_OBJECT_ARTIFACT, ObjectArtifactRow, artifact_from_row, new_row_from_artifact,
};
use w014_document_processing::parser_artifacts_row::{
    COMPLETE_PARSER_ARTIFACT, FAIL_PARSER_ARTIFACT, INSERT_PARSER_ARTIFACT, ParserArtifactRow,
    new_row_from_parser_artifact, parser_artifact_from_row,
};
use w014_document_processing::parser_blocks_row::{
    INSERT_PARSER_BLOCK, ParserBlockRow, block_from_row, new_row_from_block,
};
use w014_document_processing::parser_pages_row::{
    INSERT_PARSER_PAGE, ParserPageRow, new_row_from_page, page_from_row,
};
use w014_document_processing::quarantine_records_row::{
    INSERT_QUARANTINE_RECORD, QuarantineRecordRow, new_row_from_record, record_from_row,
};
use w014_document_processing::source_spans_row::{
    INSERT_SOURCE_SPAN, SourceSpanRow, SpanProvenanceJoin, new_row_from_span, span_from_row,
};
use w014_document_processing::upload_intents_row::{
    INSERT_UPLOAD_INTENT, UPDATE_INTENT_STATUS, UploadIntentRow, intent_from_row,
    new_row_from_intent,
};
use w014_domain::ids::{
    DocumentId, DocumentVersionId, ObjectArtifactId, ParserArtifactId, ParserBlockId, ParserPageId,
    QuarantineRecordId, SourceSpanId, UploadIntentId, WorkspaceId,
};
use w014_domain::{
    Document, DocumentVersion, IntentStatus, ObjectArtifact, ParserArtifact, ParserBlock,
    ParserPage, QuarantineRecord, SourceSpan, UploadIntent,
};
use w014_persistence::error::PersistenceError;

const SELECT_DOCUMENT_BY_ID: &str = "SELECT document_id, workspace_id, title, document_type, status, current_version_id, created_by, created_at, updated_at, row_version \
     FROM documents WHERE workspace_id = $1 AND document_id = $2";

const SELECT_DOCUMENT_BY_ID_FOR_UPDATE: &str = "SELECT document_id, workspace_id, title, document_type, status, current_version_id, created_by, created_at, updated_at, row_version \
     FROM documents WHERE workspace_id = $1 AND document_id = $2 FOR UPDATE";

const SELECT_DOCUMENTS_BY_WORKSPACE: &str = "SELECT document_id, workspace_id, title, document_type, status, current_version_id, created_by, created_at, updated_at, row_version \
     FROM documents WHERE workspace_id = $1 ORDER BY document_id ASC LIMIT $2";

const SELECT_DOCUMENTS_BY_WORKSPACE_PAGINATED: &str = "SELECT document_id, workspace_id, title, document_type, status, current_version_id, created_by, created_at, updated_at, row_version \
     FROM documents WHERE workspace_id = $1 AND document_id > $2 ORDER BY document_id ASC LIMIT $3";

const SELECT_VERSION_BY_ID: &str = "SELECT document_version_id, document_id, workspace_id, version_number, object_artifact_id, byte_size, sha256_hash, content_type, original_filename, trust_state, submitted_by, created_at \
     FROM document_versions WHERE workspace_id = $1 AND document_version_id = $2";

const SELECT_VERSIONS_BY_DOCUMENT: &str = "SELECT document_version_id, document_id, workspace_id, version_number, object_artifact_id, byte_size, sha256_hash, content_type, original_filename, trust_state, submitted_by, created_at \
     FROM document_versions WHERE workspace_id = $1 AND document_id = $2 ORDER BY version_number ASC, document_version_id ASC LIMIT $3";

const SELECT_VERSIONS_BY_DOCUMENT_PAGINATED: &str = "SELECT document_version_id, document_id, workspace_id, version_number, object_artifact_id, byte_size, sha256_hash, content_type, original_filename, trust_state, submitted_by, created_at \
     FROM document_versions WHERE workspace_id = $1 AND document_id = $2 AND document_version_id > $3 ORDER BY version_number ASC, document_version_id ASC LIMIT $4";

const SELECT_UPLOAD_INTENT_BY_ID: &str = "SELECT upload_intent_id, workspace_id, created_by, document_id, filename, expected_media_type, expected_length, expected_sha256_b64, object_artifact_id, opaque_object_key, status, expires_at, finalized_at, abandoned_at, created_at \
     FROM upload_intents WHERE workspace_id = $1 AND upload_intent_id = $2";

const SELECT_UPLOAD_INTENT_BY_ID_FOR_UPDATE: &str = "SELECT upload_intent_id, workspace_id, created_by, document_id, filename, expected_media_type, expected_length, expected_sha256_b64, object_artifact_id, opaque_object_key, status, expires_at, finalized_at, abandoned_at, created_at \
     FROM upload_intents WHERE workspace_id = $1 AND upload_intent_id = $2 FOR UPDATE";

const FINALIZE_UPLOAD_INTENT: &str = "UPDATE upload_intents \
     SET object_artifact_id = $1, status = 'verified', finalized_at = $2 \
     WHERE workspace_id = $3 AND upload_intent_id = $4 AND status IN ('initiated', 'uploaded')";

const SELECT_OBJECT_ARTIFACT_BY_ID: &str = "SELECT object_artifact_id, workspace_id, artifact_kind, object_key, byte_length, content_sha256, media_type, sse_mode, kms_key_ref, retention_until, created_at \
     FROM object_artifacts WHERE workspace_id = $1 AND object_artifact_id = $2";

const SELECT_QUARANTINE_RECORD_BY_ID: &str = "SELECT quarantine_record_id, workspace_id, upload_intent_id, status, scanner_version, reason_code, checked_at \
     FROM quarantine_records WHERE workspace_id = $1 AND quarantine_record_id = $2";

const SELECT_QUARANTINE_RECORD_BY_INTENT: &str = "SELECT quarantine_record_id, workspace_id, upload_intent_id, status, scanner_version, reason_code, checked_at \
     FROM quarantine_records WHERE workspace_id = $1 AND upload_intent_id = $2 ORDER BY checked_at DESC LIMIT 1";

const SELECT_QUARANTINE_RECORD_BY_VERSION: &str = "SELECT qr.quarantine_record_id, qr.workspace_id, qr.upload_intent_id, qr.status, qr.scanner_version, qr.reason_code, qr.checked_at \
     FROM quarantine_records qr \
     JOIN upload_intents ui ON qr.upload_intent_id = ui.upload_intent_id AND qr.workspace_id = ui.workspace_id \
     JOIN document_versions dv ON dv.object_artifact_id = ui.object_artifact_id AND dv.workspace_id = ui.workspace_id \
     WHERE dv.workspace_id = $1 AND dv.document_version_id = $2 ORDER BY qr.checked_at DESC LIMIT 1";

/// Repository operations for logical Documents.
pub struct DocumentRepository;

impl DocumentRepository {
    /// Inserts a new logical document.
    pub async fn insert(tx: &mut PgConnection, doc: &Document) -> Result<(), PersistenceError> {
        let new_row =
            new_row_from_document(doc).map_err(|e| PersistenceError::Operation(e.to_string()))?;

        sqlx::query(INSERT_DOCUMENT)
            .bind(new_row.document_id)
            .bind(new_row.workspace_id)
            .bind(&new_row.title)
            .bind(&new_row.document_type)
            .bind(&new_row.status)
            .bind(new_row.current_version_id)
            .bind(new_row.created_by)
            .bind(new_row.created_at)
            .bind(new_row.updated_at)
            .bind(new_row.row_version)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    /// Fetches a document by workspace and document ID.
    pub async fn get_by_id(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        document_id: DocumentId,
    ) -> Result<Option<Document>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, DocumentRow>(SELECT_DOCUMENT_BY_ID)
            .bind(workspace_id.as_uuid())
            .bind(document_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let doc = document_from_row(&row)
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(doc))
            }
            None => Ok(None),
        }
    }

    /// Fetches and locks a document row FOR UPDATE by workspace and document ID.
    pub async fn get_by_id_for_update(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        document_id: DocumentId,
    ) -> Result<Option<Document>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, DocumentRow>(SELECT_DOCUMENT_BY_ID_FOR_UPDATE)
            .bind(workspace_id.as_uuid())
            .bind(document_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let doc = document_from_row(&row)
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(doc))
            }
            None => Ok(None),
        }
    }

    /// Lists documents within a workspace with cursor-based pagination.
    pub async fn list_by_workspace(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        cursor_uuid: Option<Uuid>,
        limit: i64,
    ) -> Result<(Vec<Document>, Option<String>, bool), PersistenceError> {
        let fetch_limit = limit + 1;
        let rows: Vec<DocumentRow> = if let Some(cursor) = cursor_uuid {
            sqlx::query_as::<_, DocumentRow>(SELECT_DOCUMENTS_BY_WORKSPACE_PAGINATED)
                .bind(workspace_id.as_uuid())
                .bind(cursor)
                .bind(fetch_limit)
                .fetch_all(&mut *tx)
                .await
                .map_err(PersistenceError::Connection)?
        } else {
            sqlx::query_as::<_, DocumentRow>(SELECT_DOCUMENTS_BY_WORKSPACE)
                .bind(workspace_id.as_uuid())
                .bind(fetch_limit)
                .fetch_all(&mut *tx)
                .await
                .map_err(PersistenceError::Connection)?
        };

        let has_more = rows.len() > limit as usize;
        let page_rows = if has_more {
            &rows[..limit as usize]
        } else {
            &rows[..]
        };

        let mut items = Vec::with_capacity(page_rows.len());
        for row in page_rows {
            let doc =
                document_from_row(row).map_err(|e| PersistenceError::Operation(e.to_string()))?;
            items.push(doc);
        }

        let next_cursor = if has_more {
            items.last().map(|d| d.id.to_string())
        } else {
            None
        };

        Ok((items, next_cursor, has_more))
    }

    /// Updates the current version pointer and advances row_version under optimistic concurrency.
    pub async fn update_current_version(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        document_id: DocumentId,
        version_id: DocumentVersionId,
        expected_row_version: i32,
        updated_at: DateTime<Utc>,
    ) -> Result<bool, PersistenceError> {
        let res = sqlx::query(UPDATE_CURRENT_VERSION)
            .bind(version_id.as_uuid())
            .bind(updated_at)
            .bind(document_id.as_uuid())
            .bind(workspace_id.as_uuid())
            .bind(expected_row_version)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(res.rows_affected() == 1)
    }
}

/// Repository operations for immutable Document Versions.
pub struct DocumentVersionRepository;

impl DocumentVersionRepository {
    /// Inserts an immutable document version.
    pub async fn insert(
        tx: &mut PgConnection,
        version: &DocumentVersion,
    ) -> Result<(), PersistenceError> {
        let new_row = new_row_from_version(version)
            .map_err(|e| PersistenceError::Operation(e.to_string()))?;

        sqlx::query(INSERT_DOCUMENT_VERSION)
            .bind(new_row.document_version_id)
            .bind(new_row.document_id)
            .bind(new_row.workspace_id)
            .bind(new_row.version_number)
            .bind(new_row.object_artifact_id)
            .bind(new_row.byte_size)
            .bind(&new_row.sha256_hash)
            .bind(&new_row.content_type)
            .bind(&new_row.original_filename)
            .bind(&new_row.trust_state)
            .bind(new_row.submitted_by)
            .bind(new_row.created_at)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    /// Fetches an immutable version by workspace and version ID.
    pub async fn get_by_id(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        version_id: DocumentVersionId,
    ) -> Result<Option<DocumentVersion>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, DocumentVersionRow>(SELECT_VERSION_BY_ID)
            .bind(workspace_id.as_uuid())
            .bind(version_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let v = version_from_row(&row)
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }

    /// Lists immutable versions for a document in workspace with cursor pagination.
    pub async fn list_by_document(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        document_id: DocumentId,
        cursor_uuid: Option<Uuid>,
        limit: i64,
    ) -> Result<(Vec<DocumentVersion>, Option<String>, bool), PersistenceError> {
        let fetch_limit = limit + 1;
        let rows: Vec<DocumentVersionRow> = if let Some(cursor) = cursor_uuid {
            sqlx::query_as::<_, DocumentVersionRow>(SELECT_VERSIONS_BY_DOCUMENT_PAGINATED)
                .bind(workspace_id.as_uuid())
                .bind(document_id.as_uuid())
                .bind(cursor)
                .bind(fetch_limit)
                .fetch_all(&mut *tx)
                .await
                .map_err(PersistenceError::Connection)?
        } else {
            sqlx::query_as::<_, DocumentVersionRow>(SELECT_VERSIONS_BY_DOCUMENT)
                .bind(workspace_id.as_uuid())
                .bind(document_id.as_uuid())
                .bind(fetch_limit)
                .fetch_all(&mut *tx)
                .await
                .map_err(PersistenceError::Connection)?
        };

        let has_more = rows.len() > limit as usize;
        let page_rows = if has_more {
            &rows[..limit as usize]
        } else {
            &rows[..]
        };

        let mut items = Vec::with_capacity(page_rows.len());
        for row in page_rows {
            let v =
                version_from_row(row).map_err(|e| PersistenceError::Operation(e.to_string()))?;
            items.push(v);
        }

        let next_cursor = if has_more {
            items.last().map(|v| v.id.to_string())
        } else {
            None
        };

        Ok((items, next_cursor, has_more))
    }

    /// Gets the next version ordinal number for a document in a workspace.
    pub async fn get_next_version_number(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        document_id: DocumentId,
    ) -> Result<u32, PersistenceError> {
        let row = sqlx::query(
            "SELECT COALESCE(MAX(version_number), 0) + 1 AS next_ver \
             FROM document_versions WHERE workspace_id = $1 AND document_id = $2",
        )
        .bind(workspace_id.as_uuid())
        .bind(document_id.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let next_ver: i32 = row.get("next_ver");
        Ok(next_ver as u32)
    }
}

/// Repository operations for Upload Intents.
pub struct UploadIntentRepository;

impl UploadIntentRepository {
    /// Inserts a new upload intent.
    pub async fn insert(
        tx: &mut PgConnection,
        intent: &UploadIntent,
    ) -> Result<(), PersistenceError> {
        let new_row =
            new_row_from_intent(intent).map_err(|e| PersistenceError::Operation(e.to_string()))?;

        sqlx::query(INSERT_UPLOAD_INTENT)
            .bind(new_row.upload_intent_id)
            .bind(new_row.workspace_id)
            .bind(new_row.created_by)
            .bind(new_row.document_id)
            .bind(&new_row.filename)
            .bind(&new_row.expected_media_type)
            .bind(new_row.expected_length)
            .bind(new_row.expected_sha256_b64.as_deref())
            .bind(new_row.object_artifact_id)
            .bind(&new_row.opaque_object_key)
            .bind(&new_row.status)
            .bind(new_row.expires_at)
            .bind(new_row.finalized_at)
            .bind(new_row.abandoned_at)
            .bind(new_row.created_at)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    /// Fetches an upload intent by workspace and intent ID.
    pub async fn get_by_id(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        intent_id: UploadIntentId,
    ) -> Result<Option<UploadIntent>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, UploadIntentRow>(SELECT_UPLOAD_INTENT_BY_ID)
            .bind(workspace_id.as_uuid())
            .bind(intent_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let intent = intent_from_row(&row)
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(intent))
            }
            None => Ok(None),
        }
    }

    /// Fetches and locks an upload intent FOR UPDATE by workspace and intent ID.
    pub async fn get_by_id_for_update(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        intent_id: UploadIntentId,
    ) -> Result<Option<UploadIntent>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, UploadIntentRow>(SELECT_UPLOAD_INTENT_BY_ID_FOR_UPDATE)
            .bind(workspace_id.as_uuid())
            .bind(intent_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let intent = intent_from_row(&row)
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(intent))
            }
            None => Ok(None),
        }
    }

    /// Finalizes an upload intent by binding an object artifact and setting verified status with finalized_at timestamp.
    pub async fn finalize_intent(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        intent_id: UploadIntentId,
        artifact_id: ObjectArtifactId,
        finalized_at: DateTime<Utc>,
    ) -> Result<bool, PersistenceError> {
        let res = sqlx::query(FINALIZE_UPLOAD_INTENT)
            .bind(artifact_id.as_uuid())
            .bind(finalized_at)
            .bind(workspace_id.as_uuid())
            .bind(intent_id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(res.rows_affected() == 1)
    }

    /// Updates the terminal status of an upload intent.
    pub async fn update_status(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        intent_id: UploadIntentId,
        status: IntentStatus,
        finalized_at: Option<DateTime<Utc>>,
        abandoned_at: Option<DateTime<Utc>>,
    ) -> Result<bool, PersistenceError> {
        let res = sqlx::query(UPDATE_INTENT_STATUS)
            .bind(status.as_str())
            .bind(finalized_at)
            .bind(abandoned_at)
            .bind(intent_id.as_uuid())
            .bind(workspace_id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(res.rows_affected() == 1)
    }
}

/// Repository operations for Object Artifacts.
pub struct ObjectArtifactRepository;

impl ObjectArtifactRepository {
    /// Inserts an immutable object artifact.
    pub async fn insert(
        tx: &mut PgConnection,
        artifact: &ObjectArtifact,
    ) -> Result<(), PersistenceError> {
        let new_row = new_row_from_artifact(artifact)
            .map_err(|e| PersistenceError::Operation(e.to_string()))?;

        sqlx::query(INSERT_OBJECT_ARTIFACT)
            .bind(new_row.object_artifact_id)
            .bind(new_row.workspace_id)
            .bind(&new_row.artifact_kind)
            .bind(&new_row.object_key)
            .bind(&new_row.content_sha256)
            .bind(new_row.byte_length)
            .bind(&new_row.media_type)
            .bind(&new_row.sse_mode)
            .bind(new_row.kms_key_ref.as_deref())
            .bind(new_row.retention_until)
            .bind(new_row.created_at)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    /// Fetches an object artifact by workspace and artifact ID.
    pub async fn get_by_id(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        artifact_id: ObjectArtifactId,
    ) -> Result<Option<ObjectArtifact>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, ObjectArtifactRow>(SELECT_OBJECT_ARTIFACT_BY_ID)
            .bind(workspace_id.as_uuid())
            .bind(artifact_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let artifact = artifact_from_row(&row)
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(artifact))
            }
            None => Ok(None),
        }
    }
}

/// Repository operations for Dependency Keys.
pub struct DependencyKeyRepository;

impl DependencyKeyRepository {
    /// Resolves or creates a canonical DependencyKey in the given workspace.
    pub async fn get_or_create(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        key_type: &str,
        key_value: &str,
    ) -> Result<Uuid, PersistenceError> {
        let mut hasher = Sha256Hasher::new();
        hasher.update(format!("{key_type}:{key_value}").as_bytes());
        let hash_arr: [u8; 32] = hasher.finalize().into();

        let new_id = Uuid::new_v4();
        let now = Utc::now();

        let row = sqlx::query(
            "INSERT INTO dependency_keys (dependency_key_id, workspace_id, key_type, key_value, key_hash, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (workspace_id, key_hash) DO UPDATE SET key_type = EXCLUDED.key_type \
             RETURNING dependency_key_id",
        )
        .bind(new_id)
        .bind(workspace_id.as_uuid())
        .bind(key_type)
        .bind(key_value)
        .bind(hash_arr.as_slice())
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let dep_key_id: Uuid = row.get("dependency_key_id");
        Ok(dep_key_id)
    }
}

/// Repository operations for Change Events.
pub struct ChangeEventRepository;

impl ChangeEventRepository {
    /// Appends a change event associated with a dependency key.
    #[allow(clippy::too_many_arguments)]
    pub async fn append(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        dependency_key_id: Option<Uuid>,
        event_type: &str,
        entity_type: &str,
        entity_id: &str,
        change_payload: serde_json::Value,
        detected_at: DateTime<Utc>,
    ) -> Result<Uuid, PersistenceError> {
        let change_event_id = Uuid::new_v4();
        let now = Utc::now();

        let row = sqlx::query(
            "INSERT INTO change_events (change_event_id, workspace_id, dependency_key_id, event_type, entity_type, entity_id, change_payload, detected_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             RETURNING change_event_id",
        )
        .bind(change_event_id)
        .bind(workspace_id.as_uuid())
        .bind(dependency_key_id)
        .bind(event_type)
        .bind(entity_type)
        .bind(entity_id)
        .bind(change_payload)
        .bind(detected_at)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(PersistenceError::Connection)?;

        let id: Uuid = row.get("change_event_id");
        Ok(id)
    }
}

/// Repository operations for Quarantine Records.
pub struct QuarantineRecordRepository;

impl QuarantineRecordRepository {
    /// Inserts an immutable quarantine record.
    pub async fn insert(
        tx: &mut PgConnection,
        record: &QuarantineRecord,
    ) -> Result<(), PersistenceError> {
        let new_row =
            new_row_from_record(record).map_err(|e| PersistenceError::Operation(e.to_string()))?;

        sqlx::query(INSERT_QUARANTINE_RECORD)
            .bind(new_row.quarantine_record_id)
            .bind(new_row.workspace_id)
            .bind(new_row.upload_intent_id)
            .bind(&new_row.status)
            .bind(&new_row.scanner_version)
            .bind(new_row.reason_code.as_deref())
            .bind(new_row.checked_at)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    /// Fetches a quarantine record by workspace and record ID.
    pub async fn get_by_id(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        record_id: QuarantineRecordId,
    ) -> Result<Option<QuarantineRecord>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, QuarantineRecordRow>(SELECT_QUARANTINE_RECORD_BY_ID)
            .bind(workspace_id.as_uuid())
            .bind(record_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let rec = record_from_row(&row)
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    /// Fetches the latest quarantine record for an upload intent.
    pub async fn get_latest_by_intent(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        intent_id: UploadIntentId,
    ) -> Result<Option<QuarantineRecord>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, QuarantineRecordRow>(SELECT_QUARANTINE_RECORD_BY_INTENT)
            .bind(workspace_id.as_uuid())
            .bind(intent_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let rec = record_from_row(&row)
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(rec))
            }
            None => {
                let intent_created_at: Option<DateTime<Utc>> = sqlx::query_scalar(
                    "SELECT created_at FROM upload_intents WHERE workspace_id = $1 AND upload_intent_id = $2",
                )
                .bind(workspace_id.as_uuid())
                .bind(intent_id.as_uuid())
                .fetch_optional(&mut *tx)
                .await
                .map_err(PersistenceError::Connection)?;

                if let Some(created_at) = intent_created_at {
                    let pending = QuarantineRecord::from_outcome(
                        workspace_id,
                        intent_id,
                        w014_domain::QuarantineStatus::Pending,
                        "pipeline-intake",
                        None,
                        created_at,
                    )
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                    Ok(Some(pending))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Fetches the latest quarantine record for a document version.
    pub async fn get_latest_by_document_version(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        version_id: DocumentVersionId,
    ) -> Result<Option<QuarantineRecord>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, QuarantineRecordRow>(SELECT_QUARANTINE_RECORD_BY_VERSION)
            .bind(workspace_id.as_uuid())
            .bind(version_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let rec = record_from_row(&row)
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(rec))
            }
            None => {
                let intent_info: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as(
                    "SELECT ui.upload_intent_id, ui.created_at \
                     FROM upload_intents ui \
                     JOIN document_versions dv ON dv.object_artifact_id = ui.object_artifact_id AND dv.workspace_id = ui.workspace_id \
                     WHERE dv.workspace_id = $1 AND dv.document_version_id = $2",
                )
                .bind(workspace_id.as_uuid())
                .bind(version_id.as_uuid())
                .fetch_optional(&mut *tx)
                .await
                .map_err(PersistenceError::Connection)?;

                if let Some((intent_uuid, created_at)) = intent_info {
                    let pending = QuarantineRecord::from_outcome(
                        workspace_id,
                        UploadIntentId::from_uuid(intent_uuid),
                        w014_domain::QuarantineStatus::Pending,
                        "pipeline-intake",
                        None,
                        created_at,
                    )
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                    Ok(Some(pending))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

const SELECT_PARSER_ARTIFACT_BY_ID: &str = "SELECT parser_artifact_id, document_version_id, workspace_id, job_id, parser_name, parser_version, locator_version, status, artifact_object_id, text_sha256, page_count, block_count, span_count, execution_duration_ms, failure_code, started_at, completed_at FROM parser_artifacts WHERE workspace_id = $1 AND parser_artifact_id = $2";

const SELECT_PARSER_ARTIFACT_BY_VERSION: &str = "SELECT parser_artifact_id, document_version_id, workspace_id, job_id, parser_name, parser_version, locator_version, status, artifact_object_id, text_sha256, page_count, block_count, span_count, execution_duration_ms, failure_code, started_at, completed_at FROM parser_artifacts WHERE workspace_id = $1 AND document_version_id = $2 ORDER BY started_at DESC LIMIT 1";

const SELECT_PARSER_PAGE_BY_ID: &str = "SELECT parser_page_id, parser_artifact_id, workspace_id, page_number, width, height, rotation, text_content, metadata, created_at FROM parser_pages WHERE workspace_id = $1 AND parser_page_id = $2";

const SELECT_PARSER_PAGES_BY_ARTIFACT: &str = "SELECT parser_page_id, parser_artifact_id, workspace_id, page_number, width, height, rotation, text_content, metadata, created_at FROM parser_pages WHERE workspace_id = $1 AND parser_artifact_id = $2 ORDER BY page_number ASC";

const SELECT_PARSER_BLOCK_BY_ID: &str = "SELECT parser_block_id, parser_page_id, workspace_id, block_sequence, block_type, bounding_box, text_content, confidence, metadata, created_at FROM parser_blocks WHERE workspace_id = $1 AND parser_block_id = $2";

const SELECT_PARSER_BLOCKS_BY_PAGE: &str = "SELECT parser_block_id, parser_page_id, workspace_id, block_sequence, block_type, bounding_box, text_content, confidence, metadata, created_at FROM parser_blocks WHERE workspace_id = $1 AND parser_page_id = $2 ORDER BY block_sequence ASC";

const SELECT_SOURCE_SPAN_BY_ID: &str = "SELECT source_span_id, parser_block_id, workspace_id, span_sequence, start_char, end_char, text_content, bounding_box, confidence, metadata, created_at FROM source_spans WHERE workspace_id = $1 AND source_span_id = $2";

const SELECT_SOURCE_SPANS_BY_BLOCK: &str = "SELECT source_span_id, parser_block_id, workspace_id, span_sequence, start_char, end_char, text_content, bounding_box, confidence, metadata, created_at FROM source_spans WHERE workspace_id = $1 AND parser_block_id = $2 ORDER BY span_sequence ASC";

const SELECT_SPAN_PROVENANCE_FOR_BLOCK: &str = "SELECT b.workspace_id, a.document_version_id, p.parser_artifact_id, a.locator_version, p.page_number FROM parser_blocks b JOIN parser_pages p ON p.parser_page_id = b.parser_page_id AND p.workspace_id = b.workspace_id JOIN parser_artifacts a ON a.parser_artifact_id = p.parser_artifact_id AND a.workspace_id = p.workspace_id WHERE b.parser_block_id = $1 AND b.workspace_id = $2";

/// Repository operations for Parser Artifacts.
pub struct ParserArtifactRepository;

impl ParserArtifactRepository {
    /// Inserts a new parser artifact row.
    pub async fn insert(
        tx: &mut PgConnection,
        artifact: &ParserArtifact,
    ) -> Result<(), PersistenceError> {
        let new_row = new_row_from_parser_artifact(artifact)
            .map_err(|e| PersistenceError::Operation(e.to_string()))?;

        sqlx::query(INSERT_PARSER_ARTIFACT)
            .bind(new_row.parser_artifact_id)
            .bind(new_row.document_version_id)
            .bind(new_row.workspace_id)
            .bind(new_row.job_id)
            .bind(&new_row.parser_name)
            .bind(&new_row.parser_version)
            .bind(&new_row.locator_version)
            .bind(&new_row.status)
            .bind(new_row.artifact_object_id)
            .bind(new_row.text_sha256.as_deref())
            .bind(new_row.page_count)
            .bind(new_row.block_count)
            .bind(new_row.span_count)
            .bind(new_row.execution_duration_ms)
            .bind(new_row.failure_code.as_deref())
            .bind(new_row.started_at)
            .bind(new_row.completed_at)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    /// Fetches a parser artifact by ID.
    pub async fn get_by_id(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        artifact_id: ParserArtifactId,
    ) -> Result<Option<ParserArtifact>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, ParserArtifactRow>(SELECT_PARSER_ARTIFACT_BY_ID)
            .bind(workspace_id.as_uuid())
            .bind(artifact_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let art = parser_artifact_from_row(&row)
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(art))
            }
            None => Ok(None),
        }
    }

    /// Fetches the latest parser artifact for a document version.
    pub async fn get_latest_by_document_version(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        version_id: DocumentVersionId,
    ) -> Result<Option<ParserArtifact>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, ParserArtifactRow>(SELECT_PARSER_ARTIFACT_BY_VERSION)
            .bind(workspace_id.as_uuid())
            .bind(version_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let art = parser_artifact_from_row(&row)
                    .map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(art))
            }
            None => Ok(None),
        }
    }

    /// Transitions a processing artifact to completed.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        artifact_id: ParserArtifactId,
        completed_at: DateTime<Utc>,
        page_count: i32,
        block_count: i32,
        span_count: i32,
        execution_duration_ms: Option<i64>,
    ) -> Result<(), PersistenceError> {
        let res = sqlx::query(COMPLETE_PARSER_ARTIFACT)
            .bind(completed_at)
            .bind(page_count)
            .bind(block_count)
            .bind(span_count)
            .bind(execution_duration_ms)
            .bind(artifact_id.as_uuid())
            .bind(workspace_id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        if res.rows_affected() != 1 {
            return Err(PersistenceError::Operation(format!(
                "Failed to complete parser artifact '{artifact_id}'"
            )));
        }

        Ok(())
    }

    /// Transitions a processing artifact to failed.
    pub async fn fail(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        artifact_id: ParserArtifactId,
        completed_at: DateTime<Utc>,
        failure_code: &str,
    ) -> Result<(), PersistenceError> {
        let res = sqlx::query(FAIL_PARSER_ARTIFACT)
            .bind(completed_at)
            .bind(failure_code)
            .bind(artifact_id.as_uuid())
            .bind(workspace_id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        if res.rows_affected() != 1 {
            return Err(PersistenceError::Operation(format!(
                "Failed to fail parser artifact '{artifact_id}'"
            )));
        }

        Ok(())
    }
}

/// Repository operations for Parser Pages.
pub struct ParserPageRepository;

impl ParserPageRepository {
    /// Inserts a new parser page row.
    pub async fn insert(
        tx: &mut PgConnection,
        page: &ParserPage,
        artifact_workspace_id: WorkspaceId,
    ) -> Result<(), PersistenceError> {
        let new_row = new_row_from_page(page, artifact_workspace_id)
            .map_err(|e| PersistenceError::Operation(e.to_string()))?;

        sqlx::query(INSERT_PARSER_PAGE)
            .bind(new_row.parser_page_id)
            .bind(new_row.parser_artifact_id)
            .bind(new_row.workspace_id)
            .bind(new_row.page_number)
            .bind(new_row.width)
            .bind(new_row.height)
            .bind(new_row.rotation)
            .bind(&new_row.text_content)
            .bind(&new_row.metadata)
            .bind(new_row.created_at)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    /// Inserts a batch of parser pages.
    pub async fn insert_batch(
        tx: &mut PgConnection,
        pages: &[ParserPage],
        artifact_workspace_id: WorkspaceId,
    ) -> Result<(), PersistenceError> {
        for page in pages {
            Self::insert(tx, page, artifact_workspace_id).await?;
        }
        Ok(())
    }

    /// Fetches a page by ID.
    pub async fn get_by_id(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        page_id: ParserPageId,
    ) -> Result<Option<ParserPage>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, ParserPageRow>(SELECT_PARSER_PAGE_BY_ID)
            .bind(workspace_id.as_uuid())
            .bind(page_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let page =
                    page_from_row(&row).map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(page))
            }
            None => Ok(None),
        }
    }

    /// Lists all pages for a parser artifact in page_number order.
    pub async fn list_by_artifact(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        artifact_id: ParserArtifactId,
    ) -> Result<Vec<ParserPage>, PersistenceError> {
        let rows = sqlx::query_as::<_, ParserPageRow>(SELECT_PARSER_PAGES_BY_ARTIFACT)
            .bind(workspace_id.as_uuid())
            .bind(artifact_id.as_uuid())
            .fetch_all(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        let mut pages = Vec::with_capacity(rows.len());
        for row in rows {
            let page =
                page_from_row(&row).map_err(|e| PersistenceError::Operation(e.to_string()))?;
            pages.push(page);
        }
        Ok(pages)
    }
}

/// Repository operations for Parser Blocks.
pub struct ParserBlockRepository;

impl ParserBlockRepository {
    /// Inserts a new parser block row.
    pub async fn insert(
        tx: &mut PgConnection,
        block: &ParserBlock,
        page_workspace_id: WorkspaceId,
    ) -> Result<(), PersistenceError> {
        let new_row = new_row_from_block(block, page_workspace_id)
            .map_err(|e| PersistenceError::Operation(e.to_string()))?;

        sqlx::query(INSERT_PARSER_BLOCK)
            .bind(new_row.parser_block_id)
            .bind(new_row.parser_page_id)
            .bind(new_row.workspace_id)
            .bind(new_row.block_sequence)
            .bind(&new_row.block_type)
            .bind(&new_row.bounding_box)
            .bind(&new_row.text_content)
            .bind(new_row.confidence)
            .bind(&new_row.metadata)
            .bind(new_row.created_at)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    /// Inserts a batch of parser blocks.
    pub async fn insert_batch(
        tx: &mut PgConnection,
        blocks: &[ParserBlock],
        page_workspace_id: WorkspaceId,
    ) -> Result<(), PersistenceError> {
        for block in blocks {
            Self::insert(tx, block, page_workspace_id).await?;
        }
        Ok(())
    }

    /// Fetches a block by ID.
    pub async fn get_by_id(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        block_id: ParserBlockId,
    ) -> Result<Option<ParserBlock>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, ParserBlockRow>(SELECT_PARSER_BLOCK_BY_ID)
            .bind(workspace_id.as_uuid())
            .bind(block_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        match row_opt {
            Some(row) => {
                let block =
                    block_from_row(&row).map_err(|e| PersistenceError::Operation(e.to_string()))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Lists all blocks for a page in sequence order.
    pub async fn list_by_page(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        page_id: ParserPageId,
    ) -> Result<Vec<ParserBlock>, PersistenceError> {
        let rows = sqlx::query_as::<_, ParserBlockRow>(SELECT_PARSER_BLOCKS_BY_PAGE)
            .bind(workspace_id.as_uuid())
            .bind(page_id.as_uuid())
            .fetch_all(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        let mut blocks = Vec::with_capacity(rows.len());
        for row in rows {
            let block =
                block_from_row(&row).map_err(|e| PersistenceError::Operation(e.to_string()))?;
            blocks.push(block);
        }
        Ok(blocks)
    }
}

/// Repository operations for Source Spans.
pub struct SourceSpanRepository;

impl SourceSpanRepository {
    /// Inserts a new source span row under its owning parser block.
    pub async fn insert(
        tx: &mut PgConnection,
        span: &SourceSpan,
        parser_block_id: ParserBlockId,
    ) -> Result<(), PersistenceError> {
        let new_row = new_row_from_span(
            span,
            parser_block_id.into_uuid(),
            span.provenance.workspace_id.into_uuid(),
        )
        .map_err(|e| PersistenceError::Operation(e.to_string()))?;

        sqlx::query(INSERT_SOURCE_SPAN)
            .bind(new_row.source_span_id)
            .bind(new_row.parser_block_id)
            .bind(new_row.workspace_id)
            .bind(new_row.span_sequence)
            .bind(new_row.start_char)
            .bind(new_row.end_char)
            .bind(&new_row.text_content)
            .bind(&new_row.bounding_box)
            .bind(new_row.confidence)
            .bind(&new_row.metadata)
            .bind(new_row.created_at)
            .execute(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        Ok(())
    }

    /// Inserts a batch of source spans.
    pub async fn insert_batch(
        tx: &mut PgConnection,
        spans: &[(SourceSpan, ParserBlockId)],
    ) -> Result<(), PersistenceError> {
        for (span, block_id) in spans {
            Self::insert(tx, span, *block_id).await?;
        }
        Ok(())
    }

    /// Fetches a source span by ID, resolving provenance exclusively through authoritative joins.
    pub async fn get_by_id(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        span_id: SourceSpanId,
    ) -> Result<Option<SourceSpan>, PersistenceError> {
        let row_opt = sqlx::query_as::<_, SourceSpanRow>(SELECT_SOURCE_SPAN_BY_ID)
            .bind(workspace_id.as_uuid())
            .bind(span_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        let Some(span_row) = row_opt else {
            return Ok(None);
        };

        // Resolve provenance chain through block -> page -> artifact joins
        let provenance_join =
            sqlx::query_as::<_, SpanProvenanceJoin>(SELECT_SPAN_PROVENANCE_FOR_BLOCK)
                .bind(span_row.parser_block_id)
                .bind(workspace_id.as_uuid())
                .fetch_optional(&mut *tx)
                .await
                .map_err(PersistenceError::Connection)?
                .ok_or_else(|| {
                    PersistenceError::Operation(
                        "Failed to resolve provenance chain for source span".to_string(),
                    )
                })?;

        let span = span_from_row(&span_row, provenance_join)
            .map_err(|e| PersistenceError::Operation(e.to_string()))?;

        Ok(Some(span))
    }

    /// Lists all source spans for a block in sequence order.
    pub async fn list_by_block(
        tx: &mut PgConnection,
        workspace_id: WorkspaceId,
        block_id: ParserBlockId,
    ) -> Result<Vec<SourceSpan>, PersistenceError> {
        let rows = sqlx::query_as::<_, SourceSpanRow>(SELECT_SOURCE_SPANS_BY_BLOCK)
            .bind(workspace_id.as_uuid())
            .bind(block_id.as_uuid())
            .fetch_all(&mut *tx)
            .await
            .map_err(PersistenceError::Connection)?;

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let provenance_join =
            sqlx::query_as::<_, SpanProvenanceJoin>(SELECT_SPAN_PROVENANCE_FOR_BLOCK)
                .bind(block_id.as_uuid())
                .bind(workspace_id.as_uuid())
                .fetch_optional(&mut *tx)
                .await
                .map_err(PersistenceError::Connection)?
                .ok_or_else(|| {
                    PersistenceError::Operation(
                        "Failed to resolve provenance chain for source spans".to_string(),
                    )
                })?;

        let mut spans = Vec::with_capacity(rows.len());
        for row in rows {
            let span = span_from_row(&row, provenance_join.clone())
                .map_err(|e| PersistenceError::Operation(e.to_string()))?;
            spans.push(span);
        }
        Ok(spans)
    }
}
