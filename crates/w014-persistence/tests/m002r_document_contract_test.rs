//! M002R Document/Object/Parser Physical Contract Evidence Tests (real PostgreSQL).
//!
//! Proves the repaired frozen Prompt-12 physical contracts for the ten
//! Document-Pipeline tables after the Persistence-State repair:
//! - documents.current_version_id: nullable deferred pointer with a staged
//!   tri-column composite FK enforcing same-document + same-workspace composition
//! - document_versions: immutable rows, explicit object_artifact_id and
//!   original_filename facts, guarded one-way trust_state transitions
//! - upload_intents: server-generated opaque object key authority, explicit
//!   expected media/length/sha256 declarations, one-way finalize/abandon markers
//!   that can never contradict
//! - object_artifacts: insert-only immutable object facts with closed domains
//! - quarantine_records: physical upload-intent tie, frozen scan-outcome domain,
//!   insert-only rescan-append semantics (outcome never hidden in JSONB)
//! - parser_artifacts: REQUIRED locator_version identity, artifact/digest refs,
//!   exact started_at/completed_at/failure_code lifecycle, guarded terminal
//!   transitions
//! - RLS / FORCE RLS / cross-workspace isolation across all document tables

use sqlx::PgPool;
use uuid::Uuid;
use w014_persistence::{
    MIGRATOR, MigrationRunner, TestDatabase, clear_session_workspace_id, set_session_workspace_id,
};

struct Ctx {
    db: TestDatabase,
    ws_a: Uuid,
    ws_b: Uuid,
}

impl Ctx {
    fn pool(&self) -> &PgPool {
        self.db.pool()
    }

    async fn close(self) {
        self.db.close().await.expect("Failed to drop test database");
    }
}

/// Provisions an isolated migrated database with two workspaces and principals.
async fn provision() -> Ctx {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R + M001R-F1 + M002R migrations");

    let org = Uuid::new_v4();
    let prog = Uuid::new_v4();
    let ws_a = Uuid::new_v4();
    let ws_b = Uuid::new_v4();

    sqlx::query("INSERT INTO organizations (organization_id, display_name, slug) VALUES ($1, 'Doc Org', $2)")
        .bind(org)
        .bind(format!("doc-contract-org-{org}"))
        .execute(test_db.pool())
        .await
        .expect("Failed to insert organization");

    sqlx::query("INSERT INTO programs (program_id, organization_id, name, program_code) VALUES ($1, $2, 'Doc Prog', $3)")
        .bind(prog)
        .bind(org)
        .bind(format!("doc-contract-prog-{prog}"))
        .execute(test_db.pool())
        .await
        .expect("Failed to insert program");

    sqlx::query("INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code) VALUES ($1, $2, $3, 'WS A', $4), ($5, $6, $7, 'WS B', $8)")
        .bind(ws_a)
        .bind(prog)
        .bind(org)
        .bind(format!("doc-contract-ws-a-{ws_a}"))
        .bind(ws_b)
        .bind(prog)
        .bind(org)
        .bind(format!("doc-contract-ws-b-{ws_b}"))
        .execute(test_db.pool())
        .await
        .expect("Failed to insert workspaces");

    Ctx {
        db: test_db,
        ws_a,
        ws_b,
    }
}

async fn insert_principal(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO principals (principal_id, display_name, email, status) VALUES ($1, 'Doc User', $2, 'active')")
        .bind(id)
        .bind(format!("doc-user-{}@example.test", id.simple()))
        .execute(pool)
        .await
        .expect("Failed to insert principal");
    id
}

async fn insert_document(pool: &PgPool, workspace_id: Uuid, title: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO documents (document_id, workspace_id, title, document_type) VALUES ($1, $2, $3, 'pdf')")
        .bind(id)
        .bind(workspace_id)
        .bind(title)
        .execute(pool)
        .await
        .expect("Failed to insert document");
    id
}

async fn insert_artifact(pool: &PgPool, workspace_id: Uuid, kind: &str, sse_mode: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO object_artifacts (object_artifact_id, workspace_id, artifact_kind, storage_bucket, object_key, byte_length, content_sha256, content_type, sse_mode) \
         VALUES ($1, $2, $3, 'w014-test-bucket', $4, 128, $5, 'application/pdf', $6)",
    )
    .bind(id)
    .bind(workspace_id)
    .bind(kind)
    .bind(format!("documents/{}", id.simple()))
    .bind(vec![7u8; 32])
    .bind(sse_mode)
    .execute(pool)
    .await
    .expect("Failed to insert object artifact");
    id
}

#[allow(clippy::too_many_arguments)]
async fn insert_version(
    pool: &PgPool,
    document_id: Uuid,
    workspace_id: Uuid,
    artifact_id: Uuid,
    version_number: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO document_versions (document_version_id, document_id, workspace_id, version_number, object_artifact_id, byte_size, sha256_hash, content_type, original_filename) \
         VALUES ($1, $2, $3, $4, $5, 128, $6, 'application/pdf', 'original.pdf')",
    )
    .bind(id)
    .bind(document_id)
    .bind(workspace_id)
    .bind(version_number)
    .bind(artifact_id)
    .bind(vec![9u8; 32])
    .execute(pool)
    .await
    .expect("Failed to insert document version");
    id
}

/// Inserts a minimal flow intent labeled by `queue` for finalize/abandon paths.
async fn insert_flow_intent(
    pool: &PgPool,
    workspace_id: Uuid,
    created_by: Uuid,
    queue: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_intents (upload_intent_id, workspace_id, created_by, filename, expected_media_type, expected_length, opaque_object_key, expires_at) \
         VALUES ($1, $2, $3, 'flow.pdf', 'application/pdf', 1024, $4, clock_timestamp() + INTERVAL '30 minutes')",
    )
    .bind(id)
    .bind(workspace_id)
    .bind(created_by)
    .bind(format!("upload-intents/{queue}-{}", id.simple()))
    .execute(pool)
    .await
    .expect("intent insert failed");
    id
}

// ---------------------------------------------------------------------------
// documents.current_version_id deferred pointer contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_documents_current_version_pointer_is_staged_same_document_fk() {
    let ctx = provision().await;
    let pool = ctx.pool();

    // Physical shape: nullable UUID column with a composite FK into document_versions.
    let nullable: bool = sqlx::query_scalar(
        "SELECT is_nullable = 'YES' FROM information_schema.columns \
         WHERE table_name = 'documents' AND column_name = 'current_version_id'",
    )
    .fetch_one(pool)
    .await
    .expect("inspect current_version_id");
    assert!(
        nullable,
        "current_version_id must be a nullable deferred pointer"
    );

    let fk_cols: Vec<String> = sqlx::query_scalar(
        "SELECT kcu.column_name FROM information_schema.table_constraints tc \
         JOIN information_schema.key_column_usage kcu \
           ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema \
         WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_name = 'documents' \
           AND tc.constraint_name = 'fk_documents_current_version_workspace' \
         ORDER BY kcu.ordinal_position",
    )
    .fetch_all(pool)
    .await
    .expect("inspect staged pointer FK");
    assert_eq!(
        fk_cols,
        vec!["current_version_id", "document_id", "workspace_id"],
        "pointer FK must be the staged tri-column same-document/same-workspace composite"
    );

    let doc = insert_document(pool, ctx.ws_a, "Pointer Doc").await;
    let artifact = insert_artifact(pool, ctx.ws_a, "original", "none").await;
    let version = insert_version(pool, doc, ctx.ws_a, artifact, 1).await;

    // NULL default is representable; setting the pointer to its own document's version works.
    let updated = sqlx::query("UPDATE documents SET current_version_id = $1, row_version = row_version + 1 WHERE document_id = $2")
        .bind(version)
        .bind(doc)
        .execute(pool)
        .await
        .expect("pointer update must succeed");
    assert_eq!(updated.rows_affected(), 1);

    // The frozen row-version concurrency rules still apply to pointer updates.
    let row_version: i32 =
        sqlx::query_scalar("SELECT row_version FROM documents WHERE document_id = $1")
            .bind(doc)
            .fetch_one(pool)
            .await
            .expect("read row_version");
    assert_eq!(
        row_version, 2,
        "pointer updates ride on the frozen row-version field"
    );

    // Same-workspace but WRONG-DOCUMENT pointer must be rejected by the composite FK.
    let other_doc = insert_document(pool, ctx.ws_a, "Other Doc").await;
    let wrong_doc_pointer =
        sqlx::query("UPDATE documents SET current_version_id = $1 WHERE document_id = $2")
            .bind(version)
            .bind(other_doc)
            .execute(pool)
            .await;
    let err_msg = wrong_doc_pointer
        .expect_err("cross-document pointer must be rejected")
        .to_string();
    assert!(
        err_msg.contains("fk_documents_current_version_workspace"),
        "wrong-document pointer must violate the staged composite FK, got: {err_msg}"
    );

    // Cross-workspace pointer must be rejected as well.
    let foreign_doc = insert_document(pool, ctx.ws_b, "Foreign Doc").await;
    let foreign_artifact = insert_artifact(pool, ctx.ws_b, "original", "none").await;
    let foreign_version = insert_version(pool, foreign_doc, ctx.ws_b, foreign_artifact, 1).await;
    let cross_ws_pointer =
        sqlx::query("UPDATE documents SET current_version_id = $1 WHERE document_id = $2")
            .bind(foreign_version)
            .bind(doc)
            .execute(pool)
            .await;
    assert!(
        cross_ws_pointer.is_err(),
        "cross-workspace pointer must be rejected by the staged composite FK"
    );

    // Clearing the pointer back to NULL remains valid deferred semantics.
    sqlx::query("UPDATE documents SET current_version_id = NULL WHERE document_id = $1")
        .bind(doc)
        .execute(pool)
        .await
        .expect("clearing the deferred pointer must be allowed");

    ctx.close().await;
}

// ---------------------------------------------------------------------------
// document_versions immutability + trust-state transition contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_document_versions_explicit_facts_immutability_and_trust_chain() {
    let ctx = provision().await;
    let pool = ctx.pool();

    let doc = insert_document(pool, ctx.ws_a, "Immutable Doc").await;
    let artifact = insert_artifact(pool, ctx.ws_a, "original", "none").await;

    // original_filename and object_artifact_id are mandatory physical facts.
    let missing_filename = sqlx::query(
        "INSERT INTO document_versions (document_version_id, document_id, workspace_id, version_number, object_artifact_id, byte_size, sha256_hash, content_type) \
         VALUES ($1, $2, $3, 1, $4, 10, $5, 'application/pdf')",
    )
    .bind(Uuid::new_v4())
    .bind(doc)
    .bind(ctx.ws_a)
    .bind(artifact)
    .bind(vec![1u8; 32])
    .execute(pool)
    .await;
    let err_msg = missing_filename
        .expect_err("missing original_filename must be rejected")
        .to_string();
    assert!(
        err_msg.contains("original_filename"),
        "NOT NULL original_filename must fail closed, got: {err_msg}"
    );

    let missing_binding = sqlx::query(
        "INSERT INTO document_versions (document_version_id, document_id, workspace_id, version_number, byte_size, sha256_hash, content_type, original_filename) \
         VALUES ($1, $2, $3, 1, 10, $4, 'application/pdf', 'no-binding.pdf')",
    )
    .bind(Uuid::new_v4())
    .bind(doc)
    .bind(ctx.ws_a)
    .bind(vec![1u8; 32])
    .execute(pool)
    .await;
    let err_msg = missing_binding
        .expect_err("missing object_artifact_id binding must be rejected")
        .to_string();
    assert!(
        err_msg.contains("object_artifact_id"),
        "NOT NULL object binding must fail closed, got: {err_msg}"
    );

    // Cross-workspace artifact binding is rejected by the composite FK.
    let foreign_artifact = insert_artifact(pool, ctx.ws_b, "original", "none").await;
    let spoofed_binding = sqlx::query(
        "INSERT INTO document_versions (document_version_id, document_id, workspace_id, version_number, object_artifact_id, byte_size, sha256_hash, content_type, original_filename) \
         VALUES ($1, $2, $3, 1, $4, 10, $5, 'application/pdf', 'spoofed.pdf')",
    )
    .bind(Uuid::new_v4())
    .bind(doc)
    .bind(ctx.ws_a)
    .bind(foreign_artifact)
    .bind(vec![1u8; 32])
    .execute(pool)
    .await;
    assert!(
        spoofed_binding.is_err(),
        "binding a foreign-workspace artifact must be rejected by fk_document_versions_artifact_ws"
    );

    let version = insert_version(pool, doc, ctx.ws_a, artifact, 1).await;

    // Identity/content fields are immutable.
    for mutation in [
        "UPDATE document_versions SET original_filename = 'rewritten.pdf' WHERE document_version_id = $1",
        "UPDATE document_versions SET sha256_hash = decode('0000000000000000000000000000000000000000000000000000000000000042','hex') WHERE document_version_id = $1",
        "UPDATE document_versions SET object_artifact_id = NULL WHERE document_version_id = $1",
        "UPDATE document_versions SET created_at = created_at + INTERVAL '1 hour' WHERE document_version_id = $1",
    ] {
        let res = sqlx::query(mutation).bind(version).execute(pool).await;
        let err_msg = res
            .expect_err("document_versions identity/content mutation must be rejected")
            .to_string();
        assert!(
            err_msg.contains("document_versions rows are immutable"),
            "expected immutability violation, got: {err_msg}"
        );
    }

    // Frozen one-way trust chain: pending -> scanning -> { trusted | quarantined | rejected }.
    sqlx::query(
        "UPDATE document_versions SET trust_state = 'scanning' WHERE document_version_id = $1",
    )
    .bind(version)
    .execute(pool)
    .await
    .expect("legal transition to 'scanning' failed");
    let mut probe_ordinal: i32 = 2;
    for terminal in ["trusted", "quarantined", "rejected"] {
        let probe = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO document_versions (document_version_id, document_id, workspace_id, version_number, object_artifact_id, byte_size, sha256_hash, content_type, original_filename, trust_state) \
             VALUES ($1, $2, $3, $4, $5, 10, $6, 'application/pdf', 'probe.pdf', 'scanning')",
        )
        .bind(probe)
        .bind(doc)
        .bind(ctx.ws_a)
        .bind(probe_ordinal)
        .bind(artifact)
        .bind(vec![2u8; 32])
        .execute(pool)
        .await
        .expect("scanning probe insert failed");
        probe_ordinal += 1;
        sqlx::query("UPDATE document_versions SET trust_state = $1 WHERE document_version_id = $2")
            .bind(terminal)
            .bind(probe)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("legal terminal transition to '{terminal}' failed: {e}"));
    }

    // Illegal transitions must be rejected by the frozen table.
    for (from, to) in [
        ("pending", "trusted"),
        ("pending", "quarantined"),
        ("pending", "rejected"),
        ("trusted", "scanning"),
        ("trusted", "pending"),
        ("quarantined", "trusted"),
        ("rejected", "scanning"),
        ("scanning", "pending"),
    ] {
        let probe = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO document_versions (document_version_id, document_id, workspace_id, version_number, object_artifact_id, byte_size, sha256_hash, content_type, original_filename, trust_state) \
             VALUES ($1, $2, $3, $4, $5, 10, $6, 'application/pdf', 'illegal.pdf', $7)",
        )
        .bind(probe)
        .bind(doc)
        .bind(ctx.ws_a)
        .bind(probe_ordinal)
        .bind(artifact)
        .bind(vec![3u8; 32])
        .bind(from)
        .execute(pool)
        .await
        .expect("illegal-transition probe insert failed");
        probe_ordinal += 1;
        let res = sqlx::query(
            "UPDATE document_versions SET trust_state = $1 WHERE document_version_id = $2",
        )
        .bind(to)
        .bind(probe)
        .execute(pool)
        .await;
        let err_msg = res
            .expect_err(&format!("'{from}' -> '{to}' must be rejected"))
            .to_string();
        assert!(
            err_msg.contains("frozen one-way table"),
            "transition rejection must come from the frozen trust table, got: {err_msg}"
        );
    }

    // Direct DELETE is prohibited; parent-driven cascade remains the only path.
    let direct_delete = sqlx::query("DELETE FROM document_versions WHERE document_version_id = $1")
        .bind(version)
        .execute(pool)
        .await;
    let err_msg = direct_delete
        .expect_err("direct DELETE of version history must be prohibited")
        .to_string();
    assert!(err_msg.contains("append-only history"), "got: {err_msg}");

    ctx.close().await;
}

// ---------------------------------------------------------------------------
// upload_intents declaration authority + one-way finalize/abandon contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_upload_intents_server_authority_and_declaration_facts() {
    let ctx = provision().await;
    let pool = ctx.pool();
    let creator = insert_principal(pool).await;

    // Server-minted opaque key shape is enforced physically: traversal-shaped,
    // double-slash, slash-prefixed, whitespace-bearing and oversized keys fail closed.
    let bad_keys = [
        "../escape".to_string(),
        "upload-intents//double".to_string(),
        "/leading-slash".to_string(),
        "has space".to_string(),
        format!("upload-intents/{}", "x".repeat(1024)),
    ];
    for bad in bad_keys {
        let res = sqlx::query(
            "INSERT INTO upload_intents (workspace_id, created_by, filename, expected_media_type, expected_length, opaque_object_key, expires_at) \
             VALUES ($1, $2, 'bad-key.pdf', 'application/pdf', 1024, $3, clock_timestamp() + INTERVAL '10 minutes')",
        )
        .bind(ctx.ws_a)
        .bind(creator)
        .bind(&bad)
        .execute(pool)
        .await;
        let err_msg = res
            .expect_err(&format!("client-supplied key '{bad}' must be rejected"))
            .to_string();
        assert!(
            err_msg.contains("chk_upload_intents_key_shape"),
            "key-shape rejection must come from chk_upload_intents_key_shape, got: {err_msg}"
        );
    }

    // Valid intent inserts; declaration digest accepts only canonical base64 shape.
    let good_digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let intent_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_intents (upload_intent_id, workspace_id, created_by, filename, expected_media_type, expected_length, expected_sha256_b64, opaque_object_key, expires_at) \
         VALUES ($1, $2, $3, 'declared.pdf', 'application/pdf', 2048, $4, $5, clock_timestamp() + INTERVAL '15 minutes')",
    )
    .bind(intent_id)
    .bind(ctx.ws_a)
    .bind(creator)
    .bind(good_digest)
    .bind(format!("upload-intents/{}", intent_id.simple()))
    .execute(pool)
    .await
    .expect("intent with canonical b64 digest must insert");

    for bad_digest in [
        "not-base64!!",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=A",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
    ] {
        let res = sqlx::query(
            "INSERT INTO upload_intents (workspace_id, created_by, filename, expected_media_type, expected_length, expected_sha256_b64, opaque_object_key, expires_at) \
             VALUES ($1, $2, 'bad-digest.pdf', 'application/pdf', 1024, $3, $4, clock_timestamp() + INTERVAL '10 minutes')",
        )
        .bind(ctx.ws_a)
        .bind(creator)
        .bind(bad_digest)
        .bind(format!("upload-intents/bad-{}", Uuid::new_v4().simple()))
        .execute(pool)
        .await;
        let err_msg = res
            .expect_err(&format!("malformed digest '{bad_digest}' must be rejected"))
            .to_string();
        assert!(
            err_msg.contains("chk_upload_intents_sha256_b64_shape"),
            "got: {err_msg}"
        );
    }

    // Declaration fields are immutable.
    for mutation in [
        "UPDATE upload_intents SET filename = 'renamed.pdf' WHERE upload_intent_id = $1",
        "UPDATE upload_intents SET expected_length = 99 WHERE upload_intent_id = $1",
        "UPDATE upload_intents SET expected_sha256_b64 = NULL WHERE upload_intent_id = $1",
        "UPDATE upload_intents SET opaque_object_key = 'upload-intents/hijacked' WHERE upload_intent_id = $1",
        "UPDATE upload_intents SET expires_at = expires_at + INTERVAL '1 day' WHERE upload_intent_id = $1",
    ] {
        let res = sqlx::query(mutation).bind(intent_id).execute(pool).await;
        let err_msg = res
            .expect_err("declaration mutation must be rejected")
            .to_string();
        assert!(
            err_msg.contains("declaration fields are immutable"),
            "got: {err_msg}"
        );
    }

    ctx.close().await;
}

#[tokio::test]
async fn test_upload_intents_finalize_abandon_one_way_and_no_contradiction() {
    let ctx = provision().await;
    let pool = ctx.pool();
    let creator = insert_principal(pool).await;

    // verified requires finalized_at; aborted requires abandoned_at.
    let res = sqlx::query(
        "INSERT INTO upload_intents (workspace_id, created_by, filename, expected_media_type, expected_length, opaque_object_key, status, expires_at) \
         VALUES ($1, $2, 'marker.pdf', 'application/pdf', 1024, $3, 'verified', clock_timestamp() + INTERVAL '10 minutes')",
    )
    .bind(ctx.ws_a)
    .bind(creator)
    .bind(format!("upload-intents/nomarker-{}", Uuid::new_v4().simple()))
    .execute(pool)
    .await;
    let err_msg = res
        .expect_err("'verified' without finalized_at must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_upload_intents_finalized_marker"),
        "got: {err_msg}"
    );

    // Finalized and abandoned markers are mutually exclusive.
    let res = sqlx::query(
        "INSERT INTO upload_intents (workspace_id, created_by, filename, expected_media_type, expected_length, opaque_object_key, status, finalized_at, abandoned_at, expires_at) \
         VALUES ($1, $2, 'both.pdf', 'application/pdf', 1024, $3, 'verified', clock_timestamp(), clock_timestamp(), clock_timestamp() + INTERVAL '10 minutes')",
    )
    .bind(ctx.ws_a)
    .bind(creator)
    .bind(format!("upload-intents/both-{}", Uuid::new_v4().simple()))
    .execute(pool)
    .await;
    let err_msg = res
        .expect_err("contradictory finalized+abandoned state must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_upload_intents_no_contradiction")
            || err_msg.contains("chk_upload_intents_finalized_marker")
            || err_msg.contains("chk_upload_intents_abandoned_marker"),
        "contradictory markers must be rejected by the marker CHECKs, got: {err_msg}"
    );

    // Happy path: initiated -> uploaded -> verified(finalized), then locked forever.
    let flow = insert_flow_intent(pool, ctx.ws_a, creator, "finalize").await;
    sqlx::query("UPDATE upload_intents SET status = 'uploaded' WHERE upload_intent_id = $1")
        .bind(flow)
        .execute(pool)
        .await
        .expect("initiated -> uploaded must succeed");
    sqlx::query("UPDATE upload_intents SET status = 'verified', finalized_at = clock_timestamp() WHERE upload_intent_id = $1")
        .bind(flow)
        .execute(pool)
        .await
        .expect("uploaded -> verified(finalized) must succeed");
    for locked in [
        "UPDATE upload_intents SET status = 'initiated', finalized_at = NULL WHERE upload_intent_id = $1",
        "UPDATE upload_intents SET finalized_at = finalized_at + INTERVAL '1 second' WHERE upload_intent_id = $1",
        "UPDATE upload_intents SET status = 'aborted', abandoned_at = clock_timestamp(), finalized_at = NULL WHERE upload_intent_id = $1",
    ] {
        let res = sqlx::query(locked).bind(flow).execute(pool).await;
        let err_msg = res
            .expect_err("terminal intents are one-way and must refuse further updates")
            .to_string();
        assert!(err_msg.contains("one-way"), "got: {err_msg}");
    }

    // Abandon path: initiated -> aborted(abandoned).
    let abandon = insert_flow_intent(pool, ctx.ws_a, creator, "abandon").await;
    sqlx::query("UPDATE upload_intents SET status = 'aborted', abandoned_at = clock_timestamp() WHERE upload_intent_id = $1")
        .bind(abandon)
        .execute(pool)
        .await
        .expect("initiated -> aborted(abandoned) must succeed");
    let res =
        sqlx::query("UPDATE upload_intents SET status = 'uploaded' WHERE upload_intent_id = $1")
            .bind(abandon)
            .execute(pool)
            .await;
    assert!(res.is_err(), "abandoned intents must never resurrect");

    // Object-artifact binding is immutable once registered.
    let binder = insert_flow_intent(pool, ctx.ws_a, creator, "bind").await;
    let artifact = insert_artifact(pool, ctx.ws_a, "original", "none").await;
    sqlx::query("UPDATE upload_intents SET object_artifact_id = $1 WHERE upload_intent_id = $2")
        .bind(artifact)
        .bind(binder)
        .execute(pool)
        .await
        .expect("first registration of the binding must succeed");
    let other_artifact = insert_artifact(pool, ctx.ws_a, "derived", "sse_aes256").await;
    let res = sqlx::query(
        "UPDATE upload_intents SET object_artifact_id = $1 WHERE upload_intent_id = $2",
    )
    .bind(other_artifact)
    .bind(binder)
    .execute(pool)
    .await;
    let err_msg = res.expect_err("re-binding must be rejected").to_string();
    assert!(
        err_msg.contains("immutable once registered"),
        "got: {err_msg}"
    );

    ctx.close().await;
}

// ---------------------------------------------------------------------------
// object_artifacts immutable server-owned facts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_object_artifacts_immutable_closed_domain_facts() {
    let ctx = provision().await;
    let pool = ctx.pool();

    // Closed domains enforced by CHECK constraints.
    let kind_res = sqlx::query(
        "INSERT INTO object_artifacts (workspace_id, artifact_kind, storage_bucket, object_key, byte_length, content_sha256, content_type, sse_mode) \
         VALUES ($1, 'replica', 'b', $2, 1, decode('0000000000000000000000000000000000000000000000000000000000000001','hex'), 'application/octet-stream', 'none')",
    )
    .bind(ctx.ws_a)
    .bind(format!("documents/{}", Uuid::new_v4().simple()))
    .execute(pool)
    .await;
    let err_msg = kind_res
        .expect_err("artifact_kind outside frozen domain must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_object_artifacts_kind"),
        "got: {err_msg}"
    );

    let sse_res = sqlx::query(
        "INSERT INTO object_artifacts (workspace_id, artifact_kind, storage_bucket, object_key, byte_length, content_sha256, content_type, sse_mode) \
         VALUES ($1, 'original', 'b', $2, 1, decode('0000000000000000000000000000000000000000000000000000000000000001','hex'), 'application/octet-stream', 'envelope')",
    )
    .bind(ctx.ws_a)
    .bind(format!("documents/{}", Uuid::new_v4().simple()))
    .execute(pool)
    .await;
    let err_msg = sse_res
        .expect_err("sse_mode outside frozen domain must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_object_artifacts_sse_mode"),
        "got: {err_msg}"
    );

    // Digest length is enforced.
    let short_digest = sqlx::query(
        "INSERT INTO object_artifacts (workspace_id, artifact_kind, storage_bucket, object_key, byte_length, content_sha256, content_type, sse_mode) \
         VALUES ($1, 'original', 'b', $2, 1, decode('000000','hex'), 'application/octet-stream', 'none')",
    )
    .bind(ctx.ws_a)
    .bind(format!("documents/{}", Uuid::new_v4().simple()))
    .execute(pool)
    .await;
    let err_msg = short_digest
        .expect_err("short content digest must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_object_artifacts_content_sha256_len"),
        "got: {err_msg}"
    );

    // Client-chosen traversal keys are rejected: object authority stays server-owned.
    let traversal = sqlx::query(
        "INSERT INTO object_artifacts (workspace_id, artifact_kind, storage_bucket, object_key, byte_length, content_sha256, content_type, sse_mode) \
         VALUES ($1, 'original', 'b', '../../etc/passwd', 1, decode('0000000000000000000000000000000000000000000000000000000000000001','hex'), 'application/octet-stream', 'none')",
    )
    .bind(ctx.ws_a)
    .execute(pool)
    .await;
    let err_msg = traversal
        .expect_err("traversal-shaped client key must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_object_artifacts_key_shape"),
        "got: {err_msg}"
    );

    // Rows are immutable object facts.
    let artifact = insert_artifact(pool, ctx.ws_a, "original", "none").await;
    let update_res = sqlx::query(
        "UPDATE object_artifacts SET byte_length = 999999 WHERE object_artifact_id = $1",
    )
    .bind(artifact)
    .execute(pool)
    .await;
    let err_msg = update_res
        .expect_err("UPDATE on immutable object fact must be prohibited")
        .to_string();
    assert!(err_msg.contains("immutable object facts"), "got: {err_msg}");

    let delete_res = sqlx::query("DELETE FROM object_artifacts WHERE object_artifact_id = $1")
        .bind(artifact)
        .execute(pool)
        .await;
    let err_msg = delete_res
        .expect_err("direct DELETE of an object fact must be prohibited")
        .to_string();
    assert!(err_msg.contains("append-only"), "got: {err_msg}");

    ctx.close().await;
}

// ---------------------------------------------------------------------------
// quarantine_records physical intent tie + frozen outcome domain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_quarantine_records_intent_tie_outcome_domain_and_insert_only() {
    let ctx = provision().await;
    let pool = ctx.pool();
    let creator = insert_principal(pool).await;

    let intent_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_intents (upload_intent_id, workspace_id, created_by, filename, expected_media_type, expected_length, opaque_object_key, expires_at) \
         VALUES ($1, $2, $3, 'scan-me.pdf', 'application/pdf', 4096, $4, clock_timestamp() + INTERVAL '30 minutes')",
    )
    .bind(intent_id)
    .bind(ctx.ws_a)
    .bind(creator)
    .bind(format!("upload-intents/{}", intent_id.simple()))
    .execute(pool)
    .await
    .expect("intent insert failed");

    // The scan outcome lives in the frozen closed domain, not hidden JSONB.
    for status in [
        "pending",
        "clean",
        "malware",
        "integrity_failed",
        "unsupported",
    ] {
        sqlx::query(
            "INSERT INTO quarantine_records (workspace_id, upload_intent_id, status, scanner_name, reason_code, checked_at) \
             VALUES ($1, $2, $3, 'clamav-scanner', $4, clock_timestamp())",
        )
        .bind(ctx.ws_a)
        .bind(intent_id)
        .bind(status)
        .bind(if status == "clean" { None } else { Some("EICAR") })
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("frozen outcome '{status}' must be representable: {e}"));
    }

    // Obsolete lifecycle substitutes are rejected.
    for obsolete in ["quarantined", "released", "purged"] {
        let res = sqlx::query(
            "INSERT INTO quarantine_records (workspace_id, upload_intent_id, status, scanner_name, checked_at) \
             VALUES ($1, $2, $3, 'clamav-scanner', clock_timestamp())",
        )
        .bind(ctx.ws_a)
        .bind(intent_id)
        .bind(obsolete)
        .execute(pool)
        .await;
        let err_msg = res
            .expect_err(&format!("obsolete outcome '{obsolete}' must be rejected"))
            .to_string();
        assert!(
            err_msg.contains("chk_quarantine_records_status"),
            "got: {err_msg}"
        );
    }

    // The intent tie is mandatory and workspace-bound through the composite FK.
    let no_tie = sqlx::query(
        "INSERT INTO quarantine_records (workspace_id, status, scanner_name, checked_at) \
         VALUES ($1, 'malware', 'clamav-scanner', clock_timestamp())",
    )
    .bind(ctx.ws_a)
    .execute(pool)
    .await;
    let err_msg = no_tie
        .expect_err("missing upload_intent_id tie must be rejected")
        .to_string();
    assert!(err_msg.contains("upload_intent_id"), "got: {err_msg}");

    let foreign_tie = sqlx::query(
        "INSERT INTO quarantine_records (workspace_id, upload_intent_id, status, scanner_name, checked_at) \
         VALUES ($1, $2, 'malware', 'clamav-scanner', clock_timestamp())",
    )
    .bind(ctx.ws_b)
    .bind(intent_id)
    .execute(pool)
    .await;
    assert!(
        foreign_tie.is_err(),
        "cross-workspace intent tie must be rejected by fk_quarantine_records_intent_ws"
    );

    // Rescan appends a NEW immutable record; recorded results are never rewritten.
    let first = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO quarantine_records (quarantine_record_id, workspace_id, upload_intent_id, status, scanner_name, checked_at) \
         VALUES ($1, $2, $3, 'malware', 'clamav-scanner', clock_timestamp())",
    )
    .bind(first)
    .bind(ctx.ws_a)
    .bind(intent_id)
    .execute(pool)
    .await
    .expect("initial record insert failed");
    let update_res = sqlx::query(
        "UPDATE quarantine_records SET status = 'clean' WHERE quarantine_record_id = $1",
    )
    .bind(first)
    .execute(pool)
    .await;
    let err_msg = update_res
        .expect_err("recorded outcomes must never be rewritten")
        .to_string();
    assert!(
        err_msg.contains("immutable once recorded"),
        "got: {err_msg}"
    );
    let delete_res = sqlx::query("DELETE FROM quarantine_records WHERE quarantine_record_id = $1")
        .bind(first)
        .execute(pool)
        .await;
    let err_msg = delete_res
        .expect_err("recorded outcomes must never be deleted directly")
        .to_string();
    assert!(
        err_msg.contains("rescan appends a new record"),
        "got: {err_msg}"
    );

    // Rescan: brand-new independent fact for the same intent.
    sqlx::query(
        "INSERT INTO quarantine_records (workspace_id, upload_intent_id, status, scanner_name, scanner_version, reason_code, checked_at) \
         VALUES ($1, $2, 'clean', 'clamav-scanner', '1.3.0', NULL, clock_timestamp())",
    )
    .bind(ctx.ws_a)
    .bind(intent_id)
    .execute(pool)
    .await
    .expect("rescan must append a new record");

    ctx.close().await;
}

// ---------------------------------------------------------------------------
// parser_artifacts locator identity + guarded terminal transitions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_parser_artifacts_locator_identity_and_state_machine() {
    let ctx = provision().await;
    let pool = ctx.pool();

    let doc = insert_document(pool, ctx.ws_a, "Parsed Doc").await;
    let artifact = insert_artifact(pool, ctx.ws_a, "original", "none").await;
    let version = insert_version(pool, doc, ctx.ws_a, artifact, 1).await;

    // locator_version is REQUIRED identity.
    let no_locator = sqlx::query(
        "INSERT INTO parser_artifacts (document_version_id, workspace_id, parser_name, parser_version, locator_version) \
         VALUES ($1, $2, 'w014-parser', 'v1', '')",
    )
    .bind(version)
    .bind(ctx.ws_a)
    .execute(pool)
    .await;
    let err_msg = no_locator
        .expect_err("empty locator_version must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_parser_artifacts_locator_version_non_empty"),
        "got: {err_msg}"
    );

    async fn open(pool: &PgPool, version: Uuid, ws_a: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO parser_artifacts (parser_artifact_id, document_version_id, workspace_id, parser_name, parser_version, locator_version) \
             VALUES ($1, $2, $3, 'w014-parser', 'v1', 'locator-v1')",
        )
        .bind(id)
        .bind(version)
        .bind(ws_a)
        .execute(pool)
        .await
        .expect("parser artifact open failed");
        id
    }

    // processing cannot carry completed_at; failed requires failure_code.
    let early_complete = sqlx::query(
        "INSERT INTO parser_artifacts (document_version_id, workspace_id, parser_name, parser_version, locator_version, status, completed_at) \
         VALUES ($1, $2, 'w014-parser', 'v1', 'locator-v1', 'processing', clock_timestamp())",
    )
    .bind(version)
    .bind(ctx.ws_a)
    .execute(pool)
    .await;
    let err_msg = early_complete
        .expect_err("processing artifacts cannot carry completed_at")
        .to_string();
    assert!(
        err_msg.contains("chk_parser_artifacts_terminal_completion"),
        "got: {err_msg}"
    );

    let no_code = sqlx::query(
        "INSERT INTO parser_artifacts (document_version_id, workspace_id, parser_name, parser_version, locator_version, status, completed_at) \
         VALUES ($1, $2, 'w014-parser', 'v1', 'locator-v1', 'failed', clock_timestamp())",
    )
    .bind(version)
    .bind(ctx.ws_a)
    .execute(pool)
    .await;
    let err_msg = no_code
        .expect_err("failed artifacts require failure_code")
        .to_string();
    assert!(
        err_msg.contains("chk_parser_artifacts_failed_failure_code"),
        "got: {err_msg}"
    );

    // Guarded completion: exactly one processing -> completed transition.
    let completing = open(pool, version, ctx.ws_a).await;
    sqlx::query(
        "UPDATE parser_artifacts SET status = 'completed', completed_at = clock_timestamp(), page_count = 3, block_count = 12, span_count = 40, execution_duration_ms = 250 \
         WHERE parser_artifact_id = $1",
    )
    .bind(completing)
    .execute(pool)
    .await
    .expect("single completion transition must succeed");
    let stored: (String, Option<String>) = sqlx::query_as(
        "SELECT status, failure_code FROM parser_artifacts WHERE parser_artifact_id = $1",
    )
    .bind(completing)
    .fetch_one(pool)
    .await
    .expect("read completed artifact");
    assert_eq!(stored.0, "completed");
    assert_eq!(stored.1, None);

    let second_update =
        sqlx::query("UPDATE parser_artifacts SET page_count = 4 WHERE parser_artifact_id = $1")
            .bind(completing)
            .execute(pool)
            .await;
    let err_msg = second_update
        .expect_err("terminal artifacts must refuse further updates")
        .to_string();
    assert!(err_msg.contains("finalized"), "got: {err_msg}");

    // Identity fields are immutable while processing.
    let running = open(pool, version, ctx.ws_a).await;
    for mutation in [
        "UPDATE parser_artifacts SET locator_version = 'locator-v9' WHERE parser_artifact_id = $1",
        "UPDATE parser_artifacts SET started_at = started_at - INTERVAL '1 hour' WHERE parser_artifact_id = $1",
        "UPDATE parser_artifacts SET parser_version = 'v2' WHERE parser_artifact_id = $1",
    ] {
        let res = sqlx::query(mutation).bind(running).execute(pool).await;
        let err_msg = res
            .expect_err("identity mutation must be rejected")
            .to_string();
        assert!(
            err_msg.contains("identity fields are immutable"),
            "got: {err_msg}"
        );
    }

    // Failed path stores the frozen failure code exactly once.
    let failing = open(pool, version, ctx.ws_a).await;
    sqlx::query(
        "UPDATE parser_artifacts SET status = 'failed', completed_at = clock_timestamp(), failure_code = 'OCR_DECODE_FAILURE' \
         WHERE parser_artifact_id = $1",
    )
    .bind(failing)
    .execute(pool)
    .await
    .expect("failure transition must succeed");
    let code: Option<String> = sqlx::query_scalar(
        "SELECT failure_code FROM parser_artifacts WHERE parser_artifact_id = $1",
    )
    .bind(failing)
    .fetch_one(pool)
    .await
    .expect("read failure code");
    assert_eq!(code.as_deref(), Some("OCR_DECODE_FAILURE"));

    // Optional derived-text references are open-time identity facts: they bind
    // within workspace boundaries at INSERT and never change afterwards.
    let derived = insert_artifact(pool, ctx.ws_a, "derived", "sse_aes256").await;
    let referencing = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO parser_artifacts (parser_artifact_id, document_version_id, workspace_id, parser_name, parser_version, locator_version, artifact_object_id, text_sha256) \
         VALUES ($1, $2, $3, 'w014-parser', 'v1', 'locator-v1', $4, $5)",
    )
    .bind(referencing)
    .bind(version)
    .bind(ctx.ws_a)
    .bind(derived)
    .bind(vec![11u8; 32])
    .execute(pool)
    .await
    .expect("open with in-workspace artifact/text references must succeed");
    sqlx::query(
        "UPDATE parser_artifacts SET status = 'completed', completed_at = clock_timestamp() \
         WHERE parser_artifact_id = $1",
    )
    .bind(referencing)
    .execute(pool)
    .await
    .expect("completion without touching identity references must succeed");

    let foreign_derived = insert_artifact(pool, ctx.ws_b, "derived", "none").await;
    let spoofing = sqlx::query(
        "INSERT INTO parser_artifacts (parser_artifact_id, document_version_id, workspace_id, parser_name, parser_version, locator_version, artifact_object_id) \
         VALUES ($1, $2, $3, 'w014-parser', 'v1', 'locator-v1', $4)",
    )
    .bind(Uuid::new_v4())
    .bind(version)
    .bind(ctx.ws_a)
    .bind(foreign_derived)
    .execute(pool)
    .await;
    assert!(
        spoofing.is_err(),
        "foreign-workspace artifact reference must be rejected by fk_parser_artifacts_artifact_ws"
    );

    ctx.close().await;
}

// ---------------------------------------------------------------------------
// RLS / FORCE RLS / cross-workspace isolation over the document domain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_document_tables_rls_force_and_cross_workspace_isolation() {
    let ctx = provision().await;
    let pool = ctx.pool();

    let creator_a = insert_principal(pool).await;
    let _creator_b = insert_principal(pool).await;

    let doc_a = insert_document(pool, ctx.ws_a, "Doc A").await;
    let doc_b = insert_document(pool, ctx.ws_b, "Doc B").await;

    let art_a = insert_artifact(pool, ctx.ws_a, "original", "none").await;
    let art_b = insert_artifact(pool, ctx.ws_b, "original", "none").await;

    let ver_a = insert_version(pool, doc_a, ctx.ws_a, art_a, 1).await;
    let ver_b = insert_version(pool, doc_b, ctx.ws_b, art_b, 1).await;

    let intent_a = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_intents (upload_intent_id, workspace_id, created_by, filename, expected_media_type, expected_length, opaque_object_key, expires_at) \
         VALUES ($1, $2, $3, 'a.pdf', 'application/pdf', 1024, $4, clock_timestamp() + INTERVAL '30 minutes')",
    )
    .bind(intent_a)
    .bind(ctx.ws_a)
    .bind(creator_a)
    .bind(format!("upload-intents/rls-{}", intent_a.simple()))
    .execute(pool)
    .await
    .expect("intent A insert failed");
    let intent_b = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_intents (upload_intent_id, workspace_id, created_by, filename, expected_media_type, expected_length, opaque_object_key, expires_at) \
         VALUES ($1, $2, $3, 'b.pdf', 'application/pdf', 1024, $4, clock_timestamp() + INTERVAL '30 minutes')",
    )
    .bind(intent_b)
    .bind(ctx.ws_b)
    .bind(creator_a)
    .bind(format!("upload-intents/rls-{}", intent_b.simple()))
    .execute(pool)
    .await
    .expect("intent B insert failed");

    for (qr_ws, intent) in [(ctx.ws_a, intent_a), (ctx.ws_b, intent_b)] {
        sqlx::query(
            "INSERT INTO quarantine_records (workspace_id, upload_intent_id, status, scanner_name, checked_at) \
             VALUES ($1, $2, 'malware', 'clamav-scanner', clock_timestamp())",
        )
        .bind(qr_ws)
        .bind(intent)
        .execute(pool)
        .await
        .expect("quarantine fixture insert failed");
    }

    let job_a = Uuid::new_v4();
    sqlx::query("INSERT INTO jobs (job_id, workspace_id, queue_name, job_type) VALUES ($1, $2, 'parse', 'parse_pdf')")
        .bind(job_a)
        .bind(ctx.ws_a)
        .execute(pool)
        .await
        .expect("job A insert failed");
    let job_b = Uuid::new_v4();
    sqlx::query("INSERT INTO jobs (job_id, workspace_id, queue_name, job_type) VALUES ($1, $2, 'parse', 'parse_pdf')")
        .bind(job_b)
        .bind(ctx.ws_b)
        .execute(pool)
        .await
        .expect("job B insert failed");

    for (pa_ws, ver, job) in [(ctx.ws_a, ver_a, job_a), (ctx.ws_b, ver_b, job_b)] {
        sqlx::query(
            "INSERT INTO parser_artifacts (parser_artifact_id, document_version_id, workspace_id, job_id, parser_name, parser_version, locator_version) \
             VALUES ($1, $2, $3, $4, 'w014-parser', 'v1', 'locator-v1')",
        )
        .bind(Uuid::new_v4())
        .bind(ver)
        .bind(pa_ws)
        .bind(job)
        .execute(pool)
        .await
        .expect("parser artifact fixture insert failed");
    }

    sqlx::query("UPDATE documents SET current_version_id = $1 WHERE document_id = $2")
        .bind(ver_a)
        .bind(doc_a)
        .execute(pool)
        .await
        .expect("pointer fixture for doc A failed");
    sqlx::query("UPDATE documents SET current_version_id = $1 WHERE document_id = $2")
        .bind(ver_b)
        .bind(doc_b)
        .execute(pool)
        .await
        .expect("pointer fixture for doc B failed");

    // FORCE RLS is set on every M002R tenant table.
    for table in [
        "documents",
        "document_versions",
        "document_version_metadata",
        "upload_intents",
        "object_artifacts",
        "quarantine_records",
        "jobs",
        "job_attempts",
        "job_dependencies",
        "job_progress",
        "dead_letter_entries",
        "parser_artifacts",
        "parser_pages",
        "parser_blocks",
        "source_spans",
        "dependency_keys",
        "change_events",
    ] {
        let forced: bool = sqlx::query_scalar(
            "SELECT relforcerowsecurity AND relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' AND c.relname = $1",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("RLS inspection failed for '{table}': {e}"));
        assert!(
            forced,
            "{table} must have ENABLE + FORCE ROW LEVEL SECURITY"
        );
    }

    // Workspace A context sees only workspace A rows, and cannot write into B.
    {
        let mut tx = pool.begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .expect("set role");
        set_session_workspace_id(&mut tx, ctx.ws_a)
            .await
            .expect("set ws_a context");

        let docs: Vec<Uuid> =
            sqlx::query_scalar("SELECT document_id FROM documents ORDER BY document_id")
                .fetch_all(&mut *tx)
                .await
                .expect("select docs");
        assert_eq!(docs, vec![doc_a]);

        let versions: Vec<Uuid> =
            sqlx::query_scalar("SELECT document_version_id FROM document_versions")
                .fetch_all(&mut *tx)
                .await
                .expect("select versions");
        assert_eq!(versions, vec![ver_a]);

        let artifacts: Vec<Uuid> =
            sqlx::query_scalar("SELECT object_artifact_id FROM object_artifacts")
                .fetch_all(&mut *tx)
                .await
                .expect("select artifacts");
        assert_eq!(artifacts, vec![art_a]);

        let intents: Vec<Uuid> = sqlx::query_scalar("SELECT upload_intent_id FROM upload_intents")
            .fetch_all(&mut *tx)
            .await
            .expect("select intents");
        assert_eq!(intents, vec![intent_a]);

        let quarantine: Vec<Uuid> =
            sqlx::query_scalar("SELECT quarantine_record_id FROM quarantine_records")
                .fetch_all(&mut *tx)
                .await
                .expect("select quarantine");
        assert_eq!(
            quarantine.len(),
            1,
            "only workspace A quarantine records visible"
        );

        let parsers: Vec<Uuid> =
            sqlx::query_scalar("SELECT parser_artifact_id FROM parser_artifacts")
                .fetch_all(&mut *tx)
                .await
                .expect("select parsers");
        assert_eq!(parsers.len(), 1);

        // Cross-workspace INSERT attempts are rejected by RLS WITH CHECK.
        let spoof_doc = sqlx::query("INSERT INTO documents (workspace_id, title, document_type) VALUES ($1, 'Spoof', 'pdf')")
            .bind(ctx.ws_b)
            .execute(&mut *tx)
            .await;
        assert!(
            spoof_doc.is_err(),
            "cross-workspace document INSERT must fail"
        );

        let spoof_artifact = sqlx::query(
            "INSERT INTO object_artifacts (workspace_id, artifact_kind, storage_bucket, object_key, byte_length, content_sha256, content_type, sse_mode) \
             VALUES ($1, 'original', 'bucket', $2, 1, $3, 'application/pdf', 'none')",
        )
        .bind(ctx.ws_b)
        .bind(format!("documents/{}", Uuid::new_v4().simple()))
        .bind(vec![1u8; 32])
        .execute(&mut *tx)
        .await;
        assert!(
            spoof_artifact.is_err(),
            "cross-workspace artifact INSERT must fail"
        );

        tx.rollback().await.expect("rollback");
    }

    // Fail-closed: cleared context exposes nothing.
    {
        let mut tx = pool.begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .expect("set role");
        clear_session_workspace_id(&mut tx)
            .await
            .expect("clear context");

        for table in [
            "documents",
            "document_versions",
            "object_artifacts",
            "upload_intents",
            "quarantine_records",
            "parser_artifacts",
        ] {
            let sql = format!("SELECT COUNT(*) FROM {table}");
            let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
                .fetch_one(&mut *tx)
                .await
                .unwrap_or_else(|e| panic!("fail-closed count failed for {table}: {e}"));
            assert_eq!(count, 0, "cleared context must expose zero rows in {table}");
        }
        tx.rollback().await.expect("rollback");
    }

    ctx.close().await;
}
