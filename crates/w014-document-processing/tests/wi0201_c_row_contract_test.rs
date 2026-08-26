//! WI-0201-C real-PostgreSQL row-contract evidence tests.
//!
//! Proves against the repaired M002R substrate that every Document-Pipeline
//! row contract consumes the repaired EXPLICIT physical columns directly:
//! - documents.current_version_id (staged tri-column composite FK pointer)
//! - document_versions.object_artifact_id / .original_filename
//! - upload_intents.opaque_object_key / .expected_media_type /
//!   .expected_length / .expected_sha256_b64 (+ one-way terminal markers)
//! - object_artifacts.artifact_kind / .object_key / .content_sha256 /
//!   .sse_mode / .kms_key_ref (insert-only)
//! - quarantine_records.upload_intent_id / .status / .scanner_version /
//!   .reason_code (insert-only)
//! - parser_artifacts.locator_version / .artifact_object_id /
//!   .text_sha256 (guarded one-way terminal transitions)
//!
//! and that canonical SourceSpan provenance resolves exclusively through the
//! authoritative block→page→artifact joins (never caller context), with the
//! canonical span hash verified fail-closed on reconstruction.
//!
//! CALLER_CONTEXT_SUBSTITUTION_FOR_EXPLICIT_FIELDS: NO
//! JSONB_SUBSTITUTION_FOR_EXPLICIT_FIELDS: NO

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;
use w014_document_processing::document_version_metadata_row::{
    DOCUMENT_VERSION_METADATA_COLUMNS, INSERT_DOCUMENT_VERSION_METADATA, metadata_from_row,
    new_row_from_metadata,
};
use w014_document_processing::document_versions_row::{
    DOCUMENT_VERSION_COLUMNS, INSERT_DOCUMENT_VERSION, UPDATE_TRUST_STATE, new_row_from_version,
    version_from_row,
};
use w014_document_processing::documents_row::{
    DOCUMENT_COLUMNS, INSERT_DOCUMENT, UPDATE_CURRENT_VERSION, check_pointer_scope,
    document_from_row, new_row_from_document,
};
use w014_document_processing::object_artifacts_row::{
    INSERT_OBJECT_ARTIFACT, OBJECT_ARTIFACT_COLUMNS, artifact_from_row, new_row_from_artifact,
};
use w014_document_processing::parser_artifacts_row::{
    COMPLETE_PARSER_ARTIFACT, FAIL_PARSER_ARTIFACT, INSERT_PARSER_ARTIFACT,
    PARSER_ARTIFACT_COLUMNS, new_row_from_parser_artifact, parser_artifact_from_row,
};
use w014_document_processing::parser_blocks_row::{
    INSERT_PARSER_BLOCK, PARSER_BLOCK_COLUMNS, block_from_row, new_row_from_block,
};
use w014_document_processing::parser_pages_row::{
    INSERT_PARSER_PAGE, PARSER_PAGE_COLUMNS, new_row_from_page, page_from_row,
};
use w014_document_processing::quarantine_records_row::{
    INSERT_QUARANTINE_RECORD, QUARANTINE_RECORD_COLUMNS, new_row_from_record, record_from_row,
};
use w014_document_processing::source_spans_row::{
    INSERT_SOURCE_SPAN, SOURCE_SPAN_COLUMNS, SpanProvenanceJoin, new_row_from_span, span_from_row,
};
use w014_document_processing::upload_intents_row::{
    BIND_INTENT_ARTIFACT, INSERT_UPLOAD_INTENT, UPDATE_INTENT_STATUS, UPLOAD_INTENT_COLUMNS,
    check_binding_scope, intent_from_row, new_row_from_intent,
};
use w014_domain::{
    ArtifactKind, BlockKind, BoundingBox, DocumentClass, DocumentVersionMetadata, EncryptionMode,
    ExtractionMethod, LocatorVersion, MediaType, ObjectArtifact, OffsetRange, ParserArtifact,
    ParserBlock, ParserPage, QuarantineRecord, QuarantineStatus, Rotation, Sha256, SourceSpan,
    SpanProvenance, StoredMediaType, TrustState, UploadIntent, VersionOrdinal,
};
use w014_persistence::{MIGRATOR, MigrationRunner, TestDatabase};

struct Ctx {
    _db: TestDatabase,
    pool: PgPool,
    org: Uuid,
    prog: Uuid,
    ws_a: Uuid,
    ws_b: Uuid,
}

async fn provision() -> Ctx {
    let db = TestDatabase::new()
        .await
        .expect("provision isolated test database");
    let pool = db.pool().clone();
    MigrationRunner::new(&MIGRATOR)
        .run(&pool)
        .await
        .expect("apply M001R + M001R-F1 + M002R");

    let org = Uuid::new_v4();
    let prog = Uuid::new_v4();
    let ws_a = Uuid::new_v4();
    let ws_b = Uuid::new_v4();

    sqlx::query("INSERT INTO organizations (organization_id, display_name, slug) VALUES ($1, 'WI0201C Org', $2)")
        .bind(org)
        .bind(format!("wi0201c-org-{org}"))
        .execute(&pool)
        .await
        .expect("insert organization");
    sqlx::query("INSERT INTO programs (program_id, organization_id, name, program_code) VALUES ($1, $2, 'WI0201C Prog', $3)")
        .bind(prog)
        .bind(org)
        .bind(format!("wi0201c-prog-{prog}"))
        .execute(&pool)
        .await
        .expect("insert program");
    sqlx::query("INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code) VALUES ($1, $2, $3, 'WS A', $4), ($5, $6, $7, 'WS B', $8)")
        .bind(ws_a)
        .bind(prog)
        .bind(org)
        .bind(format!("wi0201c-ws-a-{ws_a}"))
        .bind(ws_b)
        .bind(prog)
        .bind(org)
        .bind(format!("wi0201c-ws-b-{ws_b}"))
        .execute(&pool)
        .await
        .expect("insert workspaces");

    Ctx {
        _db: db,
        pool,
        org,
        prog,
        ws_a,
        ws_b,
    }
}

async fn principal(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO principals (principal_id, display_name, email, status) VALUES ($1, 'WI0201C User', $2, 'active')")
        .bind(id)
        .bind(format!("wi0201c-{}@example.test", id.simple()))
        .execute(pool)
        .await
        .expect("insert principal");
    id
}

/// Registers an immutable object fact through the contract layer.
async fn register_artifact(ctx: &Ctx, kind: ArtifactKind, sse: EncryptionMode) -> ObjectArtifact {
    let artifact = ObjectArtifact::new(
        w014_domain::WorkspaceId::from_uuid(ctx.ws_a),
        kind,
        "w014-test-bucket",
        StoredMediaType::new("application/pdf").unwrap(),
        Sha256::digest(kind.as_str().as_bytes()),
        128,
        w014_domain::StorageTier::Hot,
        sse,
        Some("arn:aws:kms:us-east-1:1:key/wi0201c".to_string()),
    )
    .unwrap();
    let row = new_row_from_artifact(&artifact).unwrap();
    sqlx::query(INSERT_OBJECT_ARTIFACT)
        .bind(row.object_artifact_id)
        .bind(row.workspace_id)
        .bind(&row.artifact_kind)
        .bind(&row.storage_bucket)
        .bind(&row.object_key)
        .bind(row.byte_length)
        .bind(&row.content_sha256)
        .bind(&row.content_type)
        .bind(&row.storage_tier)
        .bind(&row.sse_mode)
        .bind(&row.kms_key_ref)
        .bind(row.created_at)
        .execute(&ctx.pool)
        .await
        .expect("insert object artifact");
    artifact
}

#[tokio::test]
async fn document_row_consumes_current_version_pointer_directly() {
    let ctx = provision().await;
    let creator = principal(&ctx.pool).await;

    // 1. Insert a logical document through the contract layer.
    let mut doc = w014_domain::Document::new(
        w014_domain::WorkspaceId::from_uuid(ctx.ws_a),
        "Pointer Doc",
        DocumentClass::Pdf,
        Some(w014_domain::PrincipalId::from_uuid(creator)),
    )
    .unwrap();
    let row = new_row_from_document(&doc).unwrap();
    sqlx::query(INSERT_DOCUMENT)
        .bind(row.document_id)
        .bind(row.workspace_id)
        .bind(&row.title)
        .bind(&row.document_type)
        .bind(&row.status)
        .bind(row.current_version_id)
        .bind(row.created_by)
        .bind(row.created_at)
        .bind(row.updated_at)
        .bind(row.row_version)
        .execute(&ctx.pool)
        .await
        .unwrap();

    // 2. Register bytes + immutable version (explicit repaired facts).
    let artifact = register_artifact(&ctx, ArtifactKind::Original, EncryptionMode::None).await;
    let version = w014_domain::DocumentVersion::new(
        &doc,
        VersionOrdinal::new(1).unwrap(),
        artifact.id,
        128,
        Sha256::digest(b"version-bytes"),
        "original.pdf",
        None,
    )
    .unwrap();
    let vrow = new_row_from_version(&version).unwrap();
    sqlx::query(INSERT_DOCUMENT_VERSION)
        .bind(vrow.document_version_id)
        .bind(vrow.document_id)
        .bind(vrow.workspace_id)
        .bind(vrow.version_number)
        .bind(vrow.object_artifact_id)
        .bind(vrow.byte_size)
        .bind(&vrow.sha256_hash)
        .bind(&vrow.content_type)
        .bind(&vrow.original_filename)
        .bind(&vrow.trust_state)
        .bind(vrow.submitted_by)
        .bind(vrow.created_at)
        .execute(&ctx.pool)
        .await
        .unwrap();

    let fetched_ver: w014_document_processing::DocumentVersionRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {DOCUMENT_VERSION_COLUMNS} FROM document_versions WHERE document_version_id = $1"
    )))
    .bind(version.id.into_uuid())
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    let reconstructed_ver = version_from_row(&fetched_ver).unwrap();
    assert_eq!(reconstructed_ver, version);

    // 3. Move the projection pointer under guarded concurrency.
    check_pointer_scope(
        doc.workspace_id,
        w014_domain::WorkspaceId::from_uuid(ctx.ws_a),
    )
    .unwrap();
    doc.project_current_version(version.id, doc.row_version, Utc::now())
        .unwrap();
    let updated = sqlx::query(UPDATE_CURRENT_VERSION)
        .bind(version.id.into_uuid())
        .bind(doc.updated_at)
        .bind(doc.id.into_uuid())
        .bind(ctx.ws_a)
        .bind(1_i32)
        .execute(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(
        updated.rows_affected(),
        1,
        "guarded pointer update matches row_version"
    );

    // 4. Read the stored row with the exact physical column list and
    //    reconstruct the Document from the ROW ALONE: the pointer arrives
    //    from documents.current_version_id, never from caller context.
    let fetched: w014_document_processing::DocumentRow = sqlx::query_as(sqlx::AssertSqlSafe(
        format!("SELECT {DOCUMENT_COLUMNS} FROM documents WHERE document_id = $1"),
    ))
    .bind(doc.id.into_uuid())
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert_eq!(fetched.current_version_id, Some(version.id.into_uuid()));
    assert_eq!(fetched.row_version, 2);

    let reconstructed = document_from_row(&fetched).unwrap();
    assert_eq!(reconstructed.current_version_id, Some(version.id));
    assert_eq!(reconstructed.title, "Pointer Doc");
    assert_eq!(
        reconstructed.created_by.map(|p| p.into_uuid()),
        Some(creator)
    );
    assert_eq!(reconstructed, doc);

    ctx._db.close().await.unwrap();
}

#[tokio::test]
async fn upload_intent_row_consumes_declarations_authority_and_markers_directly() {
    let ctx = provision().await;
    let creator = principal(&ctx.pool).await;

    let mut intent = UploadIntent::new(
        w014_domain::WorkspaceId::from_uuid(ctx.ws_a),
        w014_domain::PrincipalId::from_uuid(creator),
        None,
        "declared.pdf",
        MediaType::ApplicationPdf,
        4096,
        Some(Sha256::digest(b"declared-bytes")),
        Utc::now() + chrono::Duration::seconds(600),
    )
    .unwrap();

    // Server minted the opaque key; clients never choose object authority.
    assert!(
        intent
            .opaque_object_key
            .as_str()
            .starts_with("upload-intents/")
    );
    let row = new_row_from_intent(&intent).unwrap();
    sqlx::query(INSERT_UPLOAD_INTENT)
        .bind(row.upload_intent_id)
        .bind(row.workspace_id)
        .bind(row.created_by)
        .bind(row.document_id)
        .bind(&row.filename)
        .bind(&row.expected_media_type)
        .bind(row.expected_length)
        .bind(&row.expected_sha256_b64)
        .bind(row.object_artifact_id)
        .bind(&row.opaque_object_key)
        .bind(&row.status)
        .bind(row.expires_at)
        .bind(row.finalized_at)
        .bind(row.abandoned_at)
        .bind(row.created_at)
        .execute(&ctx.pool)
        .await
        .unwrap();

    // Client-chosen traversal keys are rejected by the physical CHECK.
    let spoof = sqlx::query(
        "INSERT INTO upload_intents (workspace_id, created_by, filename, expected_media_type, expected_length, opaque_object_key, expires_at) \
         VALUES ($1, $2, 'evil.pdf', 'application/pdf', 10, '../escape', clock_timestamp() + INTERVAL '5 minutes')",
    )
    .bind(ctx.ws_a)
    .bind(creator)
    .execute(&ctx.pool)
    .await;
    assert!(
        spoof.is_err(),
        "client-supplied traversal keys must fail closed at chk_upload_intents_key_shape"
    );

    // Bind the artifact exactly once through the guarded statement.
    let artifact = register_artifact(&ctx, ArtifactKind::Original, EncryptionMode::SseAes256).await;
    check_binding_scope(intent.workspace_id, artifact.workspace_id).unwrap();
    sqlx::query(BIND_INTENT_ARTIFACT)
        .bind(artifact.id.into_uuid())
        .bind(intent.id.into_uuid())
        .bind(ctx.ws_a)
        .execute(&ctx.pool)
        .await
        .unwrap();
    intent
        .bind_object_artifact(artifact.id, artifact.workspace_id)
        .unwrap();

    // Read back the row ALONE and reconstruct: declarations, authority key,
    // binding, and markers all arrive from their explicit physical columns.
    let fetched: w014_document_processing::UploadIntentRow = sqlx::query_as(sqlx::AssertSqlSafe(
        format!("SELECT {UPLOAD_INTENT_COLUMNS} FROM upload_intents WHERE upload_intent_id = $1"),
    ))
    .bind(intent.id.into_uuid())
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert_eq!(
        fetched.expected_sha256_b64.as_deref(),
        Some(Sha256::digest(b"declared-bytes").to_base64()).as_deref()
    );
    assert_eq!(fetched.expected_length, 4096);
    assert_eq!(fetched.expected_media_type, "application/pdf");
    assert_eq!(fetched.opaque_object_key, intent.opaque_object_key.as_str());
    assert_eq!(fetched.finalized_at, None);
    assert_eq!(fetched.abandoned_at, None);

    let reconstructed = intent_from_row(&fetched).unwrap();
    assert_eq!(
        reconstructed.expected_sha256_b64,
        Some(Sha256::digest(b"declared-bytes"))
    );
    assert_eq!(reconstructed.opaque_object_key, intent.opaque_object_key);
    assert_eq!(reconstructed.object_artifact_id, Some(artifact.id));
    assert_eq!(reconstructed.status, w014_domain::IntentStatus::Initiated);

    // One-way finalize marker rides its explicit column.
    intent.mark_uploaded().unwrap();
    intent.finalize_verified(Utc::now()).unwrap();
    sqlx::query(UPDATE_INTENT_STATUS)
        .bind("verified")
        .bind(intent.finalized_at)
        .bind(Option::<chrono::DateTime<Utc>>::None)
        .bind(intent.id.into_uuid())
        .bind(ctx.ws_a)
        .execute(&ctx.pool)
        .await
        .unwrap();
    let after: w014_document_processing::UploadIntentRow = sqlx::query_as(sqlx::AssertSqlSafe(
        format!("SELECT {UPLOAD_INTENT_COLUMNS} FROM upload_intents WHERE upload_intent_id = $1"),
    ))
    .bind(intent.id.into_uuid())
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert!(
        after.finalized_at.is_some(),
        "finalized_at consumed from its physical column"
    );
    assert_eq!(after.status, "verified");
    assert!(intent_from_row(&after).is_ok());

    ctx._db.close().await.unwrap();
}

#[tokio::test]
async fn object_artifact_row_consumes_explicit_object_facts() {
    let ctx = provision().await;
    let artifact = register_artifact(&ctx, ArtifactKind::Derived, EncryptionMode::SseAes256).await;

    let fetched: w014_document_processing::ObjectArtifactRow =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {OBJECT_ARTIFACT_COLUMNS} FROM object_artifacts WHERE object_artifact_id = $1"
        )))
        .bind(artifact.id.into_uuid())
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    // Explicit physical facts, consumed directly.
    assert_eq!(fetched.artifact_kind, "derived");
    assert_eq!(fetched.object_key, artifact.key.as_str());
    assert_eq!(
        fetched.content_sha256,
        Sha256::digest("derived".as_bytes()).as_bytes().to_vec()
    );
    assert_eq!(fetched.byte_length, 128);
    assert_eq!(fetched.sse_mode, "sse_aes256");
    assert_eq!(
        fetched.kms_key_ref.as_deref(),
        Some("arn:aws:kms:us-east-1:1:key/wi0201c")
    );

    let reconstructed = artifact_from_row(&fetched).unwrap();
    assert_eq!(reconstructed, artifact);

    // Insert-only posture: UPDATE/DELETE are physically prohibited.
    let mutation =
        sqlx::query("UPDATE object_artifacts SET byte_length = 9999 WHERE object_artifact_id = $1")
            .bind(artifact.id.into_uuid())
            .execute(&ctx.pool)
            .await;
    assert!(mutation.is_err(), "immutable object facts refuse UPDATE");

    ctx._db.close().await.unwrap();
}

#[tokio::test]
async fn quarantine_row_consumes_intent_tie_status_scanner_reason_directly() {
    let ctx = provision().await;
    let creator = principal(&ctx.pool).await;

    let intent = UploadIntent::new(
        w014_domain::WorkspaceId::from_uuid(ctx.ws_a),
        w014_domain::PrincipalId::from_uuid(creator),
        None,
        "scan-me.pdf",
        MediaType::ApplicationPdf,
        1024,
        None,
        Utc::now() + chrono::Duration::seconds(300),
    )
    .unwrap();
    let irow = new_row_from_intent(&intent).unwrap();
    sqlx::query(INSERT_UPLOAD_INTENT)
        .bind(irow.upload_intent_id)
        .bind(irow.workspace_id)
        .bind(irow.created_by)
        .bind(irow.document_id)
        .bind(&irow.filename)
        .bind(&irow.expected_media_type)
        .bind(irow.expected_length)
        .bind(&irow.expected_sha256_b64)
        .bind(irow.object_artifact_id)
        .bind(&irow.opaque_object_key)
        .bind(&irow.status)
        .bind(irow.expires_at)
        .bind(irow.finalized_at)
        .bind(irow.abandoned_at)
        .bind(irow.created_at)
        .execute(&ctx.pool)
        .await
        .unwrap();

    let record = QuarantineRecord::new(
        w014_domain::WorkspaceId::from_uuid(ctx.ws_a),
        intent.id,
        QuarantineStatus::Malware,
        "clamav-scanner",
        Some("1.3.0".to_string()),
        Some("EICAR_SIGNATURE".to_string()),
        None,
        None,
        Utc::now(),
        w014_domain::BoundedJson::empty(),
    )
    .unwrap();
    let qrow = new_row_from_record(&record).unwrap();
    sqlx::query(INSERT_QUARANTINE_RECORD)
        .bind(qrow.quarantine_record_id)
        .bind(qrow.workspace_id)
        .bind(qrow.upload_intent_id)
        .bind(qrow.document_version_id)
        .bind(qrow.object_artifact_id)
        .bind(&qrow.scanner_name)
        .bind(&qrow.scanner_version)
        .bind(&qrow.reason_code)
        .bind(&qrow.status)
        .bind(qrow.checked_at)
        .bind(&qrow.threat_details)
        .execute(&ctx.pool)
        .await
        .unwrap();

    let fetched: w014_document_processing::QuarantineRecordRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {QUARANTINE_RECORD_COLUMNS} FROM quarantine_records WHERE quarantine_record_id = $1"
    )))
    .bind(record.id.into_uuid())
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    // Explicit repaired facts consumed directly.
    assert_eq!(fetched.upload_intent_id, intent.id.into_uuid());
    assert_eq!(fetched.status, "malware");
    assert_eq!(fetched.scanner_version.as_deref(), Some("1.3.0"));
    assert_eq!(fetched.reason_code.as_deref(), Some("EICAR_SIGNATURE"));

    let reconstructed = record_from_row(&fetched).unwrap();
    assert_eq!(reconstructed, record);

    // Cross-workspace intent tie is rejected by fk_quarantine_records_intent_ws.
    let foreign = sqlx::query(INSERT_QUARANTINE_RECORD)
        .bind(Uuid::new_v4())
        .bind(ctx.ws_b)
        .bind(intent.id.into_uuid())
        .bind(Option::<Uuid>::None)
        .bind(Option::<Uuid>::None)
        .bind("clamav-scanner")
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind("clean")
        .bind(Utc::now())
        .bind(serde_json::json!({}))
        .execute(&ctx.pool)
        .await;
    assert!(
        foreign.is_err(),
        "cross-workspace scan-outcome ties must be rejected by the composite FK"
    );

    ctx._db.close().await.unwrap();
}

#[tokio::test]
async fn parser_artifact_row_consumes_locator_references_and_guarded_transitions() {
    let ctx = provision().await;

    // Parent chain: document -> artifact -> version.
    let creator = principal(&ctx.pool).await;
    let doc = w014_domain::Document::new(
        w014_domain::WorkspaceId::from_uuid(ctx.ws_a),
        "Parsed Doc",
        DocumentClass::Pdf,
        Some(w014_domain::PrincipalId::from_uuid(creator)),
    )
    .unwrap();
    let drow = new_row_from_document(&doc).unwrap();
    sqlx::query(INSERT_DOCUMENT)
        .bind(drow.document_id)
        .bind(drow.workspace_id)
        .bind(&drow.title)
        .bind(&drow.document_type)
        .bind(&drow.status)
        .bind(drow.current_version_id)
        .bind(drow.created_by)
        .bind(drow.created_at)
        .bind(drow.updated_at)
        .bind(drow.row_version)
        .execute(&ctx.pool)
        .await
        .unwrap();
    let original = register_artifact(&ctx, ArtifactKind::Original, EncryptionMode::None).await;
    let version = w014_domain::DocumentVersion::new(
        &doc,
        VersionOrdinal::new(1).unwrap(),
        original.id,
        128,
        Sha256::digest(b"parsed"),
        "parsed.pdf",
        None,
    )
    .unwrap();
    let vrow = new_row_from_version(&version).unwrap();
    sqlx::query(INSERT_DOCUMENT_VERSION)
        .bind(vrow.document_version_id)
        .bind(vrow.document_id)
        .bind(vrow.workspace_id)
        .bind(vrow.version_number)
        .bind(vrow.object_artifact_id)
        .bind(vrow.byte_size)
        .bind(&vrow.sha256_hash)
        .bind(&vrow.content_type)
        .bind(&vrow.original_filename)
        .bind(&vrow.trust_state)
        .bind(vrow.submitted_by)
        .bind(vrow.created_at)
        .execute(&ctx.pool)
        .await
        .unwrap();

    // Open the parser run with derived-text references bound in-workspace.
    let derived = register_artifact(&ctx, ArtifactKind::Derived, EncryptionMode::None).await;
    let mut artifact = ParserArtifact::new(
        w014_domain::WorkspaceId::from_uuid(ctx.ws_a),
        version.id,
        None,
        "w014-parser",
        "v1",
        LocatorVersion::new("locator-v1").unwrap(),
    )
    .unwrap();
    artifact.artifact_object_id = Some(derived.id);
    artifact.text_sha256 = Some(Sha256::digest(b"full normalized text"));
    let prow = new_row_from_parser_artifact(&artifact).unwrap();
    sqlx::query(INSERT_PARSER_ARTIFACT)
        .bind(prow.parser_artifact_id)
        .bind(prow.document_version_id)
        .bind(prow.workspace_id)
        .bind(prow.job_id)
        .bind(&prow.parser_name)
        .bind(&prow.parser_version)
        .bind(&prow.locator_version)
        .bind(&prow.status)
        .bind(prow.artifact_object_id)
        .bind(prow.text_sha256)
        .bind(prow.page_count)
        .bind(prow.block_count)
        .bind(prow.span_count)
        .bind(prow.execution_duration_ms)
        .bind(&prow.failure_code)
        .bind(prow.started_at)
        .bind(prow.completed_at)
        .execute(&ctx.pool)
        .await
        .unwrap();

    // Foreign-workspace derived-text references are rejected by the composite FK.
    let foreign_derived = {
        let foreign_artifact = ObjectArtifact::new(
            w014_domain::WorkspaceId::from_uuid(ctx.ws_b),
            ArtifactKind::Derived,
            "w014-test-bucket",
            StoredMediaType::new("text/plain").unwrap(),
            Sha256::digest(b"foreign"),
            8,
            w014_domain::StorageTier::Warm,
            EncryptionMode::None,
            None,
        )
        .unwrap();
        let frow = new_row_from_artifact(&foreign_artifact).unwrap();
        sqlx::query(INSERT_OBJECT_ARTIFACT)
            .bind(frow.object_artifact_id)
            .bind(frow.workspace_id)
            .bind(&frow.artifact_kind)
            .bind(&frow.storage_bucket)
            .bind(&frow.object_key)
            .bind(frow.byte_length)
            .bind(&frow.content_sha256)
            .bind(&frow.content_type)
            .bind(&frow.storage_tier)
            .bind(&frow.sse_mode)
            .bind(&frow.kms_key_ref)
            .bind(frow.created_at)
            .execute(&ctx.pool)
            .await
            .unwrap();
        foreign_artifact
    };
    let spoofed = sqlx::query(
        "INSERT INTO parser_artifacts (parser_artifact_id, document_version_id, workspace_id, parser_name, parser_version, locator_version, artifact_object_id) \
         VALUES ($1, $2, $3, 'w014-parser', 'v1', 'locator-v1', $4)",
    )
    .bind(Uuid::new_v4())
    .bind(version.id.into_uuid())
    .bind(ctx.ws_a)
    .bind(foreign_derived.id.into_uuid())
    .execute(&ctx.pool)
    .await;
    assert!(
        spoofed.is_err(),
        "foreign-workspace artifact references must be rejected by fk_parser_artifacts_artifact_ws"
    );

    // Guarded single-shot completion transition.
    let done = artifact
        .clone()
        .complete(Utc::now(), 2, 6, 11, Some(120))
        .unwrap();
    let updated = sqlx::query(COMPLETE_PARSER_ARTIFACT)
        .bind(done.completed_at.unwrap())
        .bind(done.page_count)
        .bind(done.block_count)
        .bind(done.span_count)
        .bind(done.execution_duration_ms)
        .bind(done.id.into_uuid())
        .bind(ctx.ws_a)
        .execute(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(updated.rows_affected(), 1);

    let fetched: w014_document_processing::ParserArtifactRow =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {PARSER_ARTIFACT_COLUMNS} FROM parser_artifacts WHERE parser_artifact_id = $1"
        )))
        .bind(done.id.into_uuid())
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    // Explicit repaired facts consumed directly.
    assert_eq!(fetched.locator_version, "locator-v1");
    assert_eq!(fetched.artifact_object_id, Some(derived.id.into_uuid()));
    assert_eq!(
        fetched.text_sha256,
        Some(Sha256::digest(b"full normalized text").as_bytes().to_vec())
    );
    assert_eq!(fetched.failure_code, None);
    let reconstructed = parser_artifact_from_row(&fetched).unwrap();
    assert_eq!(reconstructed, done);
    assert!(reconstructed.completed_at.is_some());

    // Terminal rows refuse further updates (one-way trigger).
    let second = sqlx::query(COMPLETE_PARSER_ARTIFACT)
        .bind(Utc::now())
        .bind(9_i32)
        .bind(9_i32)
        .bind(9_i32)
        .bind(Some(9_i64))
        .bind(done.id.into_uuid())
        .bind(ctx.ws_a)
        .execute(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(
        second.rows_affected(),
        0,
        "guarded completion matches 0 rows on terminal artifact"
    );

    let direct_update =
        sqlx::query("UPDATE parser_artifacts SET page_count = 9 WHERE parser_artifact_id = $1")
            .bind(done.id.into_uuid())
            .execute(&ctx.pool)
            .await;
    assert!(
        direct_update.is_err(),
        "terminal parser artifacts are frozen physically by trigger"
    );

    // Failure transitions require failure_code (physical CHECK).
    let failing = ParserArtifact::new(
        w014_domain::WorkspaceId::from_uuid(ctx.ws_a),
        version.id,
        None,
        "w014-parser",
        "v1",
        LocatorVersion::new("locator-v1").unwrap(),
    )
    .unwrap();
    let frow = new_row_from_parser_artifact(&failing).unwrap();
    sqlx::query(INSERT_PARSER_ARTIFACT)
        .bind(frow.parser_artifact_id)
        .bind(frow.document_version_id)
        .bind(frow.workspace_id)
        .bind(frow.job_id)
        .bind(&frow.parser_name)
        .bind(&frow.parser_version)
        .bind(&frow.locator_version)
        .bind(&frow.status)
        .bind(frow.artifact_object_id)
        .bind(frow.text_sha256)
        .bind(frow.page_count)
        .bind(frow.block_count)
        .bind(frow.span_count)
        .bind(frow.execution_duration_ms)
        .bind(&frow.failure_code)
        .bind(frow.started_at)
        .bind(frow.completed_at)
        .execute(&ctx.pool)
        .await
        .unwrap();
    let missing_code = sqlx::query(FAIL_PARSER_ARTIFACT)
        .bind(Utc::now())
        .bind(Option::<String>::None)
        .bind(failing.id.into_uuid())
        .bind(ctx.ws_a)
        .execute(&ctx.pool)
        .await;
    assert!(
        missing_code.is_err(),
        "failed artifacts require failure_code (chk_parser_artifacts_failed_failure_code)"
    );

    ctx._db.close().await.unwrap();
}

#[tokio::test]
async fn span_chain_round_trips_through_physical_rows_with_join_resolved_provenance() {
    let ctx = provision().await;
    let creator = principal(&ctx.pool).await;

    // Full parent chain: document -> original artifact -> version ->
    // parser artifact -> page -> block -> span.
    let doc = w014_domain::Document::new(
        w014_domain::WorkspaceId::from_uuid(ctx.ws_a),
        "Span Doc",
        DocumentClass::Docx,
        Some(w014_domain::PrincipalId::from_uuid(creator)),
    )
    .unwrap();
    let drow = new_row_from_document(&doc).unwrap();
    sqlx::query(INSERT_DOCUMENT)
        .bind(drow.document_id)
        .bind(drow.workspace_id)
        .bind(&drow.title)
        .bind(&drow.document_type)
        .bind(&drow.status)
        .bind(drow.current_version_id)
        .bind(drow.created_by)
        .bind(drow.created_at)
        .bind(drow.updated_at)
        .bind(drow.row_version)
        .execute(&ctx.pool)
        .await
        .unwrap();

    let original = register_artifact(&ctx, ArtifactKind::Original, EncryptionMode::SseAes256).await;
    let version = w014_domain::DocumentVersion::new(
        &doc,
        VersionOrdinal::new(1).unwrap(),
        original.id,
        512,
        Sha256::digest(b"span-chain"),
        "report.docx",
        None,
    )
    .unwrap();
    let vrow = new_row_from_version(&version).unwrap();
    sqlx::query(INSERT_DOCUMENT_VERSION)
        .bind(vrow.document_version_id)
        .bind(vrow.document_id)
        .bind(vrow.workspace_id)
        .bind(vrow.version_number)
        .bind(vrow.object_artifact_id)
        .bind(vrow.byte_size)
        .bind(&vrow.sha256_hash)
        .bind(&vrow.content_type)
        .bind(&vrow.original_filename)
        .bind(&vrow.trust_state)
        .bind(vrow.submitted_by)
        .bind(vrow.created_at)
        .execute(&ctx.pool)
        .await
        .unwrap();

    // Trust projection advances along the frozen one-way table (pending -> scanning -> trusted).
    let scanning = version.with_advanced_trust(TrustState::Scanning).unwrap();
    sqlx::query(UPDATE_TRUST_STATE)
        .bind(scanning.trust_state.as_str())
        .bind(scanning.id.into_uuid())
        .bind(ctx.ws_a)
        .execute(&ctx.pool)
        .await
        .unwrap();

    let trusted = scanning.with_advanced_trust(TrustState::Trusted).unwrap();
    sqlx::query(UPDATE_TRUST_STATE)
        .bind(trusted.trust_state.as_str())
        .bind(trusted.id.into_uuid())
        .bind(ctx.ws_a)
        .execute(&ctx.pool)
        .await
        .unwrap();

    let parser = ParserArtifact::new(
        w014_domain::WorkspaceId::from_uuid(ctx.ws_a),
        version.id,
        None,
        "w014-parser",
        "v1",
        LocatorVersion::new("locator-v7").unwrap(),
    )
    .unwrap();
    let prow = new_row_from_parser_artifact(&parser).unwrap();
    sqlx::query(INSERT_PARSER_ARTIFACT)
        .bind(prow.parser_artifact_id)
        .bind(prow.document_version_id)
        .bind(prow.workspace_id)
        .bind(prow.job_id)
        .bind(&prow.parser_name)
        .bind(&prow.parser_version)
        .bind(&prow.locator_version)
        .bind(&prow.status)
        .bind(prow.artifact_object_id)
        .bind(prow.text_sha256)
        .bind(prow.page_count)
        .bind(prow.block_count)
        .bind(prow.span_count)
        .bind(prow.execution_duration_ms)
        .bind(&prow.failure_code)
        .bind(prow.started_at)
        .bind(prow.completed_at)
        .execute(&ctx.pool)
        .await
        .unwrap();

    let page_text = "The quick brown fox jumps over the lazy dog.";
    let page = ParserPage::new(
        &parser,
        1,
        page_text,
        ExtractionMethod::Mixed,
        true,
        Some(0.93),
        Some(612.0),
        Some(792.0),
        Rotation::Deg0,
    )
    .unwrap();
    let pagerow = new_row_from_page(&page, page.workspace_id).unwrap();
    sqlx::query(INSERT_PARSER_PAGE)
        .bind(pagerow.parser_page_id)
        .bind(pagerow.parser_artifact_id)
        .bind(pagerow.workspace_id)
        .bind(pagerow.page_number)
        .bind(pagerow.width)
        .bind(pagerow.height)
        .bind(pagerow.rotation)
        .bind(&pagerow.text_content)
        .bind(&pagerow.metadata)
        .bind(pagerow.created_at)
        .execute(&ctx.pool)
        .await
        .unwrap();

    let fetched_page: w014_document_processing::ParserPageRow =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {PARSER_PAGE_COLUMNS} FROM parser_pages WHERE parser_page_id = $1"
        )))
        .bind(page.id.into_uuid())
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    let reconstructed_page = page_from_row(&fetched_page).unwrap();
    assert_eq!(reconstructed_page, page);

    let block_text = "The quick brown fox";
    let block = ParserBlock::new(
        &page,
        0,
        BlockKind::Paragraph,
        0,
        19,
        BoundingBox::new(1.0, 2.0, 30.0, 8.0).ok(),
        vec!["Chapter 1".to_string()],
        block_text,
        Some(0.95),
    )
    .unwrap();
    let blockrow = new_row_from_block(&block, block.workspace_id).unwrap();
    sqlx::query(INSERT_PARSER_BLOCK)
        .bind(blockrow.parser_block_id)
        .bind(blockrow.parser_page_id)
        .bind(blockrow.workspace_id)
        .bind(blockrow.block_sequence)
        .bind(&blockrow.block_type)
        .bind(&blockrow.bounding_box)
        .bind(&blockrow.text_content)
        .bind(blockrow.confidence)
        .bind(&blockrow.metadata)
        .bind(blockrow.created_at)
        .execute(&ctx.pool)
        .await
        .unwrap();

    let fetched_block: w014_document_processing::ParserBlockRow =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {PARSER_BLOCK_COLUMNS} FROM parser_blocks WHERE parser_block_id = $1"
        )))
        .bind(block.id.into_uuid())
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    let reconstructed_block = block_from_row(&fetched_block).unwrap();
    assert_eq!(reconstructed_block, block);

    let span = SourceSpan::new(
        SpanProvenance::new(
            page.workspace_id,
            version.id,
            parser.id,
            LocatorVersion::new(parser.locator_version.as_str()).unwrap(),
            page.page_number,
        )
        .unwrap(),
        0,
        OffsetRange::new(4, 13).unwrap(),
        Some(OffsetRange::new(400, 409).unwrap()),
        BoundingBox::new(1.5, 2.5, 28.0, 6.0).ok(),
        Some(w014_domain::SectionPath::new(vec!["Chapter 1".to_string()]).unwrap()),
        block_text,
        ExtractionMethod::NativeText,
        Some(0.97),
    )
    .unwrap();
    let spanrow = new_row_from_span(&span, block.id.into_uuid(), ctx.ws_a).unwrap();
    sqlx::query(INSERT_SOURCE_SPAN)
        .bind(spanrow.source_span_id)
        .bind(spanrow.parser_block_id)
        .bind(spanrow.workspace_id)
        .bind(spanrow.span_sequence)
        .bind(spanrow.start_char)
        .bind(spanrow.end_char)
        .bind(&spanrow.text_content)
        .bind(&spanrow.bounding_box)
        .bind(spanrow.confidence)
        .bind(&spanrow.metadata)
        .bind(spanrow.created_at)
        .execute(&ctx.pool)
        .await
        .unwrap();

    // Metadata JSONB conventions carry ONLY non-explicit facts; the canonical
    // hash is recorded there and re-verified on reconstruction.
    let stored_hash = spanrow
        .metadata
        .get("w014.span_sha256")
        .and_then(serde_json::Value::as_str)
        .expect("canonical span hash recorded under fixed key");
    assert_eq!(stored_hash.len(), 64);
    assert_eq!(stored_hash, span.span_sha256().to_hex());

    // PROVENANCE RESOLUTION VIA AUTHORITATIVE JOINS ONLY:
    // block -> page -> artifact yields the canonical chain.
    let joined: SpanProvenanceJoin = sqlx::query_as(
        "SELECT ss.workspace_id, pa.document_version_id, pp.parser_artifact_id, pa.locator_version, pp.page_number \
         FROM source_spans ss \
         JOIN parser_blocks pb ON pb.parser_block_id = ss.parser_block_id AND pb.workspace_id = ss.workspace_id \
         JOIN parser_pages pp ON pp.parser_page_id = pb.parser_page_id AND pp.workspace_id = pb.workspace_id \
         JOIN parser_artifacts pa ON pa.parser_artifact_id = pp.parser_artifact_id AND pa.workspace_id = pp.workspace_id \
         WHERE ss.source_span_id = $1",
    )
    .bind(span.id.into_uuid())
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert_eq!(joined.document_version_id, version.id.into_uuid());
    assert_eq!(joined.parser_artifact_id, parser.id.into_uuid());
    assert_eq!(joined.locator_version, "locator-v7");
    assert_eq!(joined.page_number, 1);

    let fetched: w014_document_processing::SourceSpanRow = sqlx::query_as(sqlx::AssertSqlSafe(
        format!("SELECT {SOURCE_SPAN_COLUMNS} FROM source_spans WHERE source_span_id = $1"),
    ))
    .bind(span.id.into_uuid())
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    // Explicit physical facts consumed directly.
    assert_eq!(fetched.span_sequence, 0);
    assert_eq!(fetched.start_char, 4);
    assert_eq!(fetched.end_char, 13);
    assert_eq!(fetched.text_content, block_text);

    // Reconstruction re-verifies the canonical hash fail-closed.
    let reconstructed = span_from_row(&fetched, joined).unwrap();
    assert_eq!(reconstructed, span);

    // Tampered canonical hashes fail closed.
    let mut tampered = fetched.clone();
    if let Some(obj) = tampered.metadata.as_object_mut() {
        obj.insert(
            "w014.span_sha256".to_string(),
            serde_json::Value::String(Sha256::digest(b"forged").to_hex()),
        );
    }
    let joined_again: SpanProvenanceJoin = sqlx::query_as(
        "SELECT ss.workspace_id, pa.document_version_id, pp.parser_artifact_id, pa.locator_version, pp.page_number \
         FROM source_spans ss \
         JOIN parser_blocks pb ON pb.parser_block_id = ss.parser_block_id AND pb.workspace_id = ss.workspace_id \
         JOIN parser_pages pp ON pp.parser_page_id = pb.parser_page_id AND pp.workspace_id = pb.workspace_id \
         JOIN parser_artifacts pa ON pa.parser_artifact_id = pp.parser_artifact_id AND pa.workspace_id = pp.workspace_id \
         WHERE ss.source_span_id = $1",
    )
    .bind(span.id.into_uuid())
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert!(
        span_from_row(&tampered, joined_again).is_err(),
        "forged span identities must fail closed"
    );

    ctx._db.close().await.unwrap();
}

#[tokio::test]
async fn metadata_snapshot_round_trips_and_workspace_isolation_holds_via_rls() {
    let ctx = provision().await;
    let creator = principal(&ctx.pool).await;

    let doc = w014_domain::Document::new(
        w014_domain::WorkspaceId::from_uuid(ctx.ws_a),
        "Meta Doc",
        DocumentClass::Pdf,
        Some(w014_domain::PrincipalId::from_uuid(creator)),
    )
    .unwrap();
    let drow = new_row_from_document(&doc).unwrap();
    sqlx::query(INSERT_DOCUMENT)
        .bind(drow.document_id)
        .bind(drow.workspace_id)
        .bind(&drow.title)
        .bind(&drow.document_type)
        .bind(&drow.status)
        .bind(drow.current_version_id)
        .bind(drow.created_by)
        .bind(drow.created_at)
        .bind(drow.updated_at)
        .bind(drow.row_version)
        .execute(&ctx.pool)
        .await
        .unwrap();
    let original = register_artifact(&ctx, ArtifactKind::Original, EncryptionMode::None).await;
    let version = w014_domain::DocumentVersion::new(
        &doc,
        VersionOrdinal::new(1).unwrap(),
        original.id,
        64,
        Sha256::digest(b"meta"),
        "meta.pdf",
        None,
    )
    .unwrap();
    let vrow = new_row_from_version(&version).unwrap();
    sqlx::query(INSERT_DOCUMENT_VERSION)
        .bind(vrow.document_version_id)
        .bind(vrow.document_id)
        .bind(vrow.workspace_id)
        .bind(vrow.version_number)
        .bind(vrow.object_artifact_id)
        .bind(vrow.byte_size)
        .bind(&vrow.sha256_hash)
        .bind(&vrow.content_type)
        .bind(&vrow.original_filename)
        .bind(&vrow.trust_state)
        .bind(vrow.submitted_by)
        .bind(vrow.created_at)
        .execute(&ctx.pool)
        .await
        .unwrap();

    let snapshot = DocumentVersionMetadata::new(
        version.id,
        doc.workspace_id,
        Some(3),
        Some(1),
        Some(12),
        Some(4500),
        Some("Author".to_string()),
        Some("Meta Title".to_string()),
        w014_domain::BoundedJson::new("metadata", serde_json::json!({"lang": "en"})).unwrap(),
        w014_domain::BoundedJson::empty(),
    )
    .unwrap();
    let mrow = new_row_from_metadata(&snapshot).unwrap();
    sqlx::query(INSERT_DOCUMENT_VERSION_METADATA)
        .bind(mrow.document_version_metadata_id)
        .bind(mrow.document_version_id)
        .bind(mrow.workspace_id)
        .bind(&mrow.metadata)
        .bind(&mrow.custom_fields)
        .bind(&mrow.extracted_author)
        .bind(&mrow.extracted_title)
        .bind(mrow.page_count)
        .bind(mrow.word_count)
        .bind(mrow.created_at)
        .execute(&ctx.pool)
        .await
        .unwrap();

    let fetched: w014_document_processing::DocumentVersionMetadataRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {DOCUMENT_VERSION_METADATA_COLUMNS} FROM document_version_metadata WHERE document_version_metadata_id = $1"
    )))
    .bind(snapshot.id.into_uuid())
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    let reconstructed = metadata_from_row(&fetched).unwrap();
    assert_eq!(reconstructed.declared_revision, Some(3));
    assert_eq!(reconstructed.internal_revision, Some(1));
    assert_eq!(reconstructed.page_count, Some(12));
    assert_eq!(reconstructed.extracted_title.as_deref(), Some("Meta Title"));

    // Workspace isolation through RLS: session scoped to WS A sees nothing
    // of WS B, and cross-workspace writes fail WITH CHECK.
    sqlx::query("INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code) VALUES ($1, $2, $3, 'Isolation Probe', $4)")
        .bind(ctx.ws_b)
        .bind(ctx.prog)
        .bind(ctx.org)
        .bind(format!("wi0201c-ws-b2-{}", Uuid::new_v4()))
        .execute(&ctx.pool)
        .await
        .ok(); // ws_b already exists; probe row optional

    {
        let mut tx = ctx.pool.begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        w014_persistence::set_session_workspace_id(&mut tx, ctx.ws_a)
            .await
            .unwrap();

        let visible_docs: Vec<Uuid> = sqlx::query_scalar("SELECT document_id FROM documents")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        assert_eq!(
            visible_docs,
            vec![doc.id.into_uuid()],
            "RLS exposes only own-workspace documents"
        );

        let spoofed = sqlx::query(
            "INSERT INTO documents (workspace_id, title, document_type) VALUES ($1, 'Spoof', 'pdf')",
        )
        .bind(ctx.ws_b)
        .execute(&mut *tx)
        .await;
        assert!(
            spoofed.is_err(),
            "cross-workspace writes rejected by RLS WITH CHECK"
        );
        tx.rollback().await.unwrap();
    }

    ctx._db.close().await.unwrap();
}
