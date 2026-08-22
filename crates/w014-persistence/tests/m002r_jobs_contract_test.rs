//! M002R Durable-Jobs Physical Contract Evidence Tests against real PostgreSQL 18.
//!
//! Validates the exact frozen Prompt-12 physical contracts for the 5 Jobs tables:
//! - jobs.status exact frozen domain (requested/queued/running/retryable/succeeded/failed/cancelled/dead_letter)
//! - Rejection of obsolete substitutes: enqueued / claimed / completed
//! - Canonical Jobs-AI semantic identity: UNIQUE(idempotency_key) across all workspaces
//! - Queue physical claim support for queued/retryable via partial indexes and claim predicate columns
//! - job_attempts: outcome domain, UNIQUE(job_id, attempt_number), append-only history,
//!   and single terminal transition mechanics
//! - job_progress: CHECK constraints, UNIQUE(job_id, sequence), multiple durable
//!   sequential rows, and insert-only enforcement
//! - job_dependencies: self/duplicate/dangling edge rejection and predecessor-success semantics
//! - dead_letter_entries: one durable record per job with bounded resolution updates
//! - RLS tenant scoping flowing through the parent jobs row for child tables
//! - Public-schema exactness: precisely the authorized 30 tables (M003R/M004R/W3 absent)

use sqlx::{PgPool, Row};
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

/// Provisions an isolated migrated database with two workspaces in distinct orgs.
async fn provision() -> Ctx {
    let test_db = TestDatabase::new()
        .await
        .expect("Failed to provision isolated test database");

    MigrationRunner::new(&MIGRATOR)
        .run(test_db.pool())
        .await
        .expect("Failed to apply M001R + M001R-F1 + M002R migrations");

    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let prog_a = Uuid::new_v4();
    let prog_b = Uuid::new_v4();
    let ws_a = Uuid::new_v4();
    let ws_b = Uuid::new_v4();

    sqlx::query("INSERT INTO organizations (organization_id, display_name, slug) VALUES ($1, 'Org A', $2), ($3, 'Org B', $4)")
        .bind(org_a)
        .bind(format!("jobs-contract-org-a-{org_a}"))
        .bind(org_b)
        .bind(format!("jobs-contract-org-b-{org_b}"))
        .execute(test_db.pool())
        .await
        .expect("Failed to insert organizations");

    sqlx::query("INSERT INTO programs (program_id, organization_id, name, program_code) VALUES ($1, $2, 'Prog A', $3), ($4, $5, 'Prog B', $6)")
        .bind(prog_a)
        .bind(org_a)
        .bind(format!("jobs-contract-prog-a-{prog_a}"))
        .bind(prog_b)
        .bind(org_b)
        .bind(format!("jobs-contract-prog-b-{prog_b}"))
        .execute(test_db.pool())
        .await
        .expect("Failed to insert programs");

    sqlx::query("INSERT INTO workspaces (workspace_id, program_id, organization_id, name, workspace_code) VALUES ($1, $2, $3, 'WS A', $4), ($5, $6, $7, 'WS B', $8)")
        .bind(ws_a)
        .bind(prog_a)
        .bind(org_a)
        .bind(format!("jobs-contract-ws-a-{ws_a}"))
        .bind(ws_b)
        .bind(prog_b)
        .bind(org_b)
        .bind(format!("jobs-contract-ws-b-{ws_b}"))
        .execute(test_db.pool())
        .await
        .expect("Failed to insert workspaces");

    Ctx {
        db: test_db,
        ws_a,
        ws_b,
    }
}

async fn insert_job(pool: &PgPool, workspace_id: Uuid, queue_name: &str, status: &str) -> Uuid {
    sqlx::query("INSERT INTO jobs (workspace_id, queue_name, job_type, status) VALUES ($1, $2, 'evidence-test', $3) RETURNING job_id")
        .bind(workspace_id)
        .bind(queue_name)
        .bind(status)
        .fetch_one(pool)
        .await
        .expect("Failed to insert job")
        .get("job_id")
}

#[tokio::test]
async fn test_jobs_status_exact_frozen_domain_and_substitute_rejection() {
    let ctx = provision().await;
    let pool = ctx.pool();

    // Default status must be exactly 'requested'
    let default_job = Uuid::new_v4();
    sqlx::query("INSERT INTO jobs (job_id, workspace_id, queue_name, job_type) VALUES ($1, $2, 'default', 'unit')")
        .bind(default_job)
        .bind(ctx.ws_a)
        .execute(pool)
        .await
        .expect("Failed to insert default-status job");
    let default_status: String = sqlx::query_scalar("SELECT status FROM jobs WHERE job_id = $1")
        .bind(default_job)
        .fetch_one(pool)
        .await
        .expect("Failed to read default job status");
    assert_eq!(
        default_status, "requested",
        "jobs.status default must be 'requested'"
    );

    // Every value of the frozen domain is physically representable
    let valid_statuses = [
        "cancelled",
        "dead_letter",
        "failed",
        "queued",
        "requested",
        "retryable",
        "running",
        "succeeded",
    ];
    for status in valid_statuses {
        let _ = insert_job(pool, ctx.ws_a, "domain-proof", status).await;
    }
    let accepted: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT status FROM jobs WHERE queue_name = 'domain-proof' ORDER BY status",
    )
    .fetch_all(pool)
    .await
    .expect("Failed to read domain-proof statuses");
    assert_eq!(
        accepted.len(),
        valid_statuses.len(),
        "All 8 frozen statuses must be physically representable"
    );
    assert_eq!(
        accepted, valid_statuses,
        "Accepted statuses must equal the exact frozen domain"
    );

    // Obsolete substitutes must be rejected by chk_jobs_status
    for obsolete in ["enqueued", "claimed", "completed"] {
        let rejected = sqlx::query(
            "INSERT INTO jobs (workspace_id, queue_name, job_type, status) VALUES ($1, 'substitute', 'unit', $2)",
        )
        .bind(ctx.ws_a)
        .bind(obsolete)
        .execute(pool)
        .await;
        let err_msg = rejected
            .expect_err(&format!(
                "Obsolete substitute '{obsolete}' must be rejected by chk_jobs_status"
            ))
            .to_string();
        assert!(
            err_msg.contains("chk_jobs_status"),
            "Rejection of '{obsolete}' must come from chk_jobs_status, got: {err_msg}"
        );
    }

    ctx.close().await;
}

#[tokio::test]
async fn test_jobs_idempotency_uniqueness_is_global_semantic_identity() {
    let ctx = provision().await;
    let pool = ctx.pool();

    let key = format!("idem-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO jobs (job_id, workspace_id, queue_name, job_type, idempotency_key) VALUES ($1, $2, 'q', 't', $3)")
        .bind(Uuid::new_v4())
        .bind(ctx.ws_a)
        .bind(&key)
        .execute(pool)
        .await
        .expect("First job with idempotency key must insert");

    // Same key in a DIFFERENT workspace must also be rejected: semantic identity is global
    let cross_ws_dup = sqlx::query(
        "INSERT INTO jobs (workspace_id, queue_name, job_type, idempotency_key) VALUES ($1, 'q', 't', $2)",
    )
    .bind(ctx.ws_b)
    .bind(&key)
    .execute(pool)
    .await;
    let err_msg = cross_ws_dup
        .expect_err("Duplicate idempotency_key across workspaces must be rejected")
        .to_string();
    assert!(
        err_msg.contains("uq_jobs_idempotency_key") || err_msg.contains("duplicate key"),
        "Expected uq_jobs_idempotency_key violation, got: {err_msg}"
    );

    // NULL idempotency keys are exempt from uniqueness
    for _ in 0..2 {
        let _ = insert_job(pool, ctx.ws_b, "null-idem", "requested").await;
    }
    let null_key_jobs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM jobs WHERE queue_name = 'null-idem' AND idempotency_key IS NULL",
    )
    .fetch_one(pool)
    .await
    .expect("Failed to count null-key jobs");
    assert_eq!(
        null_key_jobs, 2,
        "Multiple NULL idempotency keys must coexist"
    );

    ctx.close().await;
}

#[tokio::test]
async fn test_queue_claim_physical_support_for_queued_and_retryable() {
    let ctx = provision().await;
    let pool = ctx.pool();

    // Physical partial indexes backing the frozen claim predicate
    let claim_idx: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'idx_jobs_queue_claim'",
    )
    .fetch_optional(pool)
    .await
    .expect("Failed to inspect idx_jobs_queue_claim")
    .expect("idx_jobs_queue_claim partial index must exist");
    assert!(
        claim_idx.contains("'queued'")
            && claim_idx.contains("'retryable'")
            && claim_idx.contains("cancellation_requested"),
        "idx_jobs_queue_claim must encode the frozen claim predicate, got: {claim_idx}"
    );

    let lease_idx: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'idx_jobs_lease_expires'",
    )
    .fetch_optional(pool)
    .await
    .expect("Failed to inspect idx_jobs_lease_expires")
    .expect("idx_jobs_lease_expires partial index must exist");
    assert!(
        lease_idx.contains("'running'"),
        "idx_jobs_lease_expires must target running leases, got: {lease_idx}"
    );

    // Behavioral proof of the canonical claim query over representative states
    let queue = "claim-proof";
    let cancelled_queued = insert_job(pool, ctx.ws_a, queue, "queued").await;
    let deferred_retryable = insert_job(pool, ctx.ws_a, queue, "retryable").await;
    let _requested_not_claimable = insert_job(pool, ctx.ws_a, queue, "requested").await;
    let _running_not_claimable = insert_job(pool, ctx.ws_a, queue, "running").await;

    sqlx::query("UPDATE jobs SET cancellation_requested = true WHERE job_id = $1")
        .bind(cancelled_queued)
        .execute(pool)
        .await
        .expect("Failed to request cancellation");

    sqlx::query(
        "UPDATE jobs SET not_before = clock_timestamp() + INTERVAL '1 hour' WHERE job_id = $1",
    )
    .bind(deferred_retryable)
    .execute(pool)
    .await
    .expect("Failed to defer not_before");

    // A fresh queued job that satisfies every predicate clause
    let fresh_queued = Uuid::new_v4();
    sqlx::query("INSERT INTO jobs (job_id, workspace_id, queue_name, job_type, status, priority) VALUES ($1, $2, $3, 'evidence-test', 'queued', 10)")
        .bind(fresh_queued)
        .bind(ctx.ws_a)
        .bind(queue)
        .execute(pool)
        .await
        .expect("Failed to insert fresh queued job");

    let claimable: Vec<Uuid> = sqlx::query_scalar(
        "SELECT job_id FROM jobs \
         WHERE queue_name = $1 \
           AND status IN ('queued', 'retryable') \
           AND cancellation_requested = false \
           AND (lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp()) \
           AND not_before <= clock_timestamp() \
         ORDER BY priority DESC, not_before ASC \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(queue)
    .fetch_all(pool)
    .await
    .expect("Canonical claim query failed");

    assert_eq!(
        claimable,
        vec![fresh_queued],
        "Only a queued/retryable, uncancelled, due, lease-free job is claimable"
    );

    ctx.close().await;
}

#[tokio::test]
async fn test_job_attempts_outcome_domain_unique_attempt_and_terminal_completion_check() {
    let ctx = provision().await;
    let pool = ctx.pool();
    let job = insert_job(pool, ctx.ws_a, "attempts", "running").await;

    // Exact outcome domain: each transition succeeds once from 'running'
    let outcomes = [
        "succeeded",
        "retryable_failed",
        "terminal_failed",
        "cancelled",
        "lease_expired",
    ];
    for (i, outcome) in outcomes.iter().enumerate() {
        let attempt_no = i as i32 + 1;
        let attempt_id = Uuid::new_v4();
        sqlx::query("INSERT INTO job_attempts (job_attempt_id, job_id, attempt_number, worker_id) VALUES ($1, $2, $3, 'worker-a')")
            .bind(attempt_id)
            .bind(job)
            .bind(attempt_no)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Attempt {attempt_no} insert failed: {e}"));

        let updated = sqlx::query(
            "UPDATE job_attempts SET outcome = $1, completed_at = clock_timestamp(), error_code = $2 WHERE job_attempt_id = $3",
        )
        .bind(outcome)
        .bind(format!("E_{outcome}"))
        .bind(attempt_id)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("Transition to '{outcome}' failed: {e}"));
        assert_eq!(updated.rows_affected(), 1);

        let stored: String =
            sqlx::query_scalar("SELECT outcome FROM job_attempts WHERE job_attempt_id = $1")
                .bind(attempt_id)
                .fetch_one(pool)
                .await
                .expect("Failed to read finalized outcome");
        assert_eq!(&stored, outcome);

        // Second mutation on the finalized row must be refused by the trigger
        let second_update = sqlx::query(
            "UPDATE job_attempts SET error_code = 'AFTER_FINAL' WHERE job_attempt_id = $1",
        )
        .bind(attempt_id)
        .execute(pool)
        .await;
        let err_msg = second_update
            .expect_err("Finalized attempt row must refuse further mutation")
            .to_string();
        assert!(
            err_msg.contains("finalized"),
            "Second transition must be blocked as finalized, got: {err_msg}"
        );
    }

    // Values outside the frozen outcome domain must be rejected
    for invalid in ["completed", "failed", "timed_out", "enqueued"] {
        let rejected = sqlx::query(
            "INSERT INTO job_attempts (job_attempt_id, job_id, attempt_number, worker_id, outcome, completed_at) VALUES ($1, $2, 100, 'worker-a', $3, clock_timestamp())",
        )
        .bind(Uuid::new_v4())
        .bind(job)
        .bind(invalid)
        .execute(pool)
        .await;
        let err_msg = rejected
            .expect_err(&format!("Invalid outcome '{invalid}' must be rejected"))
            .to_string();
        assert!(
            err_msg.contains("chk_job_attempts_outcome"),
            "Outcome rejection must come from chk_job_attempts_outcome, got: {err_msg}"
        );
    }

    // UNIQUE(job_id, attempt_number)
    let dup = sqlx::query(
        "INSERT INTO job_attempts (job_id, attempt_number, worker_id) VALUES ($1, 1, 'worker-b')",
    )
    .bind(job)
    .execute(pool)
    .await;
    let err_msg = dup
        .expect_err("Duplicate (job_id, attempt_number) must be rejected")
        .to_string();
    assert!(
        err_msg.contains("uq_job_attempts_job_attempt") || err_msg.contains("duplicate key"),
        "Expected unique-attempt violation, got: {err_msg}"
    );

    // attempt_number >= 1
    let zero = sqlx::query(
        "INSERT INTO job_attempts (job_id, attempt_number, worker_id) VALUES ($1, 0, 'worker-a')",
    )
    .bind(job)
    .execute(pool)
    .await;
    let err_msg = zero
        .expect_err("attempt_number = 0 must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_job_attempts_attempt_number_positive"),
        "Zero attempt number must violate positive check, got: {err_msg}"
    );

    // Terminal completion consistency from chk_job_attempts_terminal_completion
    let terminal_without_time = sqlx::query(
        "INSERT INTO job_attempts (job_attempt_id, job_id, attempt_number, worker_id, outcome) VALUES ($1, $2, 200, 'worker-a', 'succeeded')",
    )
    .bind(Uuid::new_v4())
    .bind(job)
    .execute(pool)
    .await;
    let err_msg = terminal_without_time
        .expect_err("Terminal outcome without completed_at must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_job_attempts_terminal_completion"),
        "got: {err_msg}"
    );

    let running_with_time = sqlx::query(
        "INSERT INTO job_attempts (job_attempt_id, job_id, attempt_number, worker_id, completed_at) VALUES ($1, $2, 201, 'worker-a', clock_timestamp())",
    )
    .bind(Uuid::new_v4())
    .bind(job)
    .execute(pool)
    .await;
    let err_msg = running_with_time
        .expect_err("'running' outcome with completed_at must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_job_attempts_terminal_completion"),
        "got: {err_msg}"
    );

    // FK closure: attempts cannot reference a nonexistent job
    let dangling = sqlx::query(
        "INSERT INTO job_attempts (job_id, attempt_number, worker_id) VALUES ($1, 1, 'worker-a')",
    )
    .bind(Uuid::new_v4())
    .execute(pool)
    .await;
    assert!(
        dangling.is_err(),
        "job_attempts FK to jobs(job_id) must reject dangling references"
    );

    ctx.close().await;
}

#[tokio::test]
async fn test_job_attempts_append_only_identity_immutable_and_cascade_only_deletion() {
    let ctx = provision().await;
    let pool = ctx.pool();
    let job = insert_job(pool, ctx.ws_a, "append-only", "running").await;
    let attempt_id = Uuid::new_v4();
    sqlx::query("INSERT INTO job_attempts (job_attempt_id, job_id, attempt_number, worker_id) VALUES ($1, $2, 1, 'worker-a')")
        .bind(attempt_id)
        .bind(job)
        .execute(pool)
        .await
        .expect("Failed to insert attempt");

    // Identity fields are immutable
    for identity_sql in [
        "UPDATE job_attempts SET attempt_number = 9 WHERE job_attempt_id = $1",
        "UPDATE job_attempts SET worker_id = 'worker-z' WHERE job_attempt_id = $1",
        "UPDATE job_attempts SET started_at = started_at + INTERVAL '1 day' WHERE job_attempt_id = $1",
    ] {
        let res = sqlx::query(identity_sql)
            .bind(attempt_id)
            .execute(pool)
            .await;
        let err_msg = res
            .expect_err("Identity field mutation must be rejected")
            .to_string();
        assert!(
            err_msg.contains("identity fields are immutable"),
            "Expected identity immutability violation, got: {err_msg}"
        );
    }

    // UPDATE while running must transition the outcome; staying 'running' is prohibited
    let stay_running = sqlx::query(
        "UPDATE job_attempts SET error_code = 'HEARTBEAT_ONLY' WHERE job_attempt_id = $1",
    )
    .bind(attempt_id)
    .execute(pool)
    .await;
    let err_msg = stay_running
        .expect_err("Non-transitioning UPDATE while running must be rejected")
        .to_string();
    assert!(
        err_msg.contains("must transition outcome to a terminal value"),
        "Running-state UPDATE without transition must be blocked, got: {err_msg}"
    );

    // The single terminal transition records completion evidence exactly once
    sqlx::query("UPDATE job_attempts SET outcome = 'retryable_failed', completed_at = clock_timestamp(), error_code = 'E_TIMEOUT', error_detail_redacted = 'redacted-detail' WHERE job_attempt_id = $1")
        .bind(attempt_id)
        .execute(pool)
        .await
        .expect("Single terminal transition must succeed");

    let recorded: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT outcome, error_code, error_detail_redacted FROM job_attempts WHERE job_attempt_id = $1",
    )
    .bind(attempt_id)
    .fetch_one(pool)
    .await
    .expect("Failed to read finalized attempt");
    assert_eq!(recorded.0, "retryable_failed");
    assert_eq!(recorded.1.as_deref(), Some("E_TIMEOUT"));
    assert_eq!(recorded.2.as_deref(), Some("redacted-detail"));

    // Direct DELETE is prohibited; only parent-driven cascade may remove rows
    let direct_delete = sqlx::query("DELETE FROM job_attempts WHERE job_attempt_id = $1")
        .bind(attempt_id)
        .execute(pool)
        .await;
    let err_msg = direct_delete
        .expect_err("Direct DELETE on job_attempts must be prohibited")
        .to_string();
    assert!(
        err_msg.contains("append-only"),
        "Direct DELETE must raise the append-only exception, got: {err_msg}"
    );

    // Parent job deletion cascades through the referential-integrity path
    sqlx::query("DELETE FROM jobs WHERE job_id = $1")
        .bind(job)
        .execute(pool)
        .await
        .expect("Parent job cascade deletion must be permitted");
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM job_attempts WHERE job_id = $1")
        .bind(job)
        .fetch_one(pool)
        .await
        .expect("Failed to count remaining attempts");
    assert_eq!(remaining, 0, "Cascade path must have removed attempt rows");

    ctx.close().await;
}

#[tokio::test]
async fn test_job_progress_sequential_events_checks_and_insert_only() {
    let ctx = provision().await;
    let pool = ctx.pool();
    let job = insert_job(pool, ctx.ws_a, "progress", "running").await;

    // Multiple durable sequential progress events are supported
    for seq in 0..3 {
        let stage = match seq {
            0 => "PARSE_START",
            1 => "PARSE_PAGES",
            _ => "PARSE_DONE",
        };
        let message = if seq == 2 { Some("STAGE_OK") } else { None };
        sqlx::query("INSERT INTO job_progress (job_id, sequence, stage_code, current, total, message_code) VALUES ($1, $2, $3, $4, 20, $5)")
            .bind(job)
            .bind(seq)
            .bind(stage)
            .bind(seq * 10)
            .bind(message)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Sequential progress row {seq} insert failed: {e}"));
    }

    let sequences: Vec<i32> =
        sqlx::query_scalar("SELECT sequence FROM job_progress WHERE job_id = $1 ORDER BY sequence")
            .bind(job)
            .fetch_all(pool)
            .await
            .expect("Failed to read progress sequences");
    assert_eq!(
        sequences,
        vec![0, 1, 2],
        "All sequential progress rows must persist"
    );

    // Duplicate (job_id, sequence) is rejected
    let dup = sqlx::query(
        "INSERT INTO job_progress (job_id, sequence, stage_code, current) VALUES ($1, 1, 'DUP', 0)",
    )
    .bind(job)
    .execute(pool)
    .await;
    let err_msg = dup
        .expect_err("Duplicate progress sequence must be rejected")
        .to_string();
    assert!(
        err_msg.contains("uq_job_progress_job_sequence") || err_msg.contains("duplicate key"),
        "Expected unique-progress-sequence violation, got: {err_msg}"
    );

    // Negative sequence violates chk_job_progress_sequence_non_negative
    let neg_seq = sqlx::query(
        "INSERT INTO job_progress (job_id, sequence, stage_code, current) VALUES ($1, -1, 'NEG_SEQ', 0)",
    )
    .bind(job)
    .execute(pool)
    .await;
    let err_msg = neg_seq
        .expect_err("Negative sequence must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_job_progress_sequence_non_negative"),
        "got: {err_msg}"
    );

    // Negative current violates chk_job_progress_current_non_negative
    let neg_current = sqlx::query(
        "INSERT INTO job_progress (job_id, sequence, stage_code, current) VALUES ($1, 50, 'NEG_CUR', -1)",
    )
    .bind(job)
    .execute(pool)
    .await;
    let err_msg = neg_current
        .expect_err("Negative current must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_job_progress_current_non_negative"),
        "got: {err_msg}"
    );

    // total < current violates chk_job_progress_total_gte_current
    let total_lt = sqlx::query(
        "INSERT INTO job_progress (job_id, sequence, stage_code, current, total) VALUES ($1, 51, 'TOTAL_LT', 5, 4)",
    )
    .bind(job)
    .execute(pool)
    .await;
    let err_msg = total_lt
        .expect_err("total < current must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_job_progress_total_gte_current"),
        "got: {err_msg}"
    );

    // Empty stage_code violates chk_job_progress_stage_code_non_empty
    let empty_stage = sqlx::query(
        "INSERT INTO job_progress (job_id, sequence, stage_code, current) VALUES ($1, 52, '', 0)",
    )
    .bind(job)
    .execute(pool)
    .await;
    let err_msg = empty_stage
        .expect_err("Empty stage_code must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_job_progress_stage_code_non_empty"),
        "got: {err_msg}"
    );

    // Boundary-valid shapes are accepted
    sqlx::query("INSERT INTO job_progress (job_id, sequence, stage_code, current, total) VALUES ($1, 90, 'BOUNDARY_EQ', 7, 7)")
        .bind(job)
        .execute(pool)
        .await
        .expect("total == current must be accepted");
    sqlx::query("INSERT INTO job_progress (job_id, sequence, stage_code, current) VALUES ($1, 91, 'BOUNDARY_NULL_TOTAL', 0)")
        .bind(job)
        .execute(pool)
        .await
        .expect("NULL total with current=0 must be accepted");

    // Insert-only enforcement: UPDATE and DELETE are prohibited
    let update_res = sqlx::query(
        "UPDATE job_progress SET current = current + 1 WHERE job_id = $1 AND sequence = 0",
    )
    .bind(job)
    .execute(pool)
    .await;
    let err_msg = update_res
        .expect_err("UPDATE on job_progress must be prohibited")
        .to_string();
    assert!(
        err_msg.contains("insert-only"),
        "Progress UPDATE must raise insert-only exception, got: {err_msg}"
    );

    let delete_res = sqlx::query("DELETE FROM job_progress WHERE job_id = $1 AND sequence = 0")
        .bind(job)
        .execute(pool)
        .await;
    let err_msg = delete_res
        .expect_err("DELETE on job_progress must be prohibited")
        .to_string();
    assert!(
        err_msg.contains("insert-only"),
        "Progress DELETE must raise insert-only exception, got: {err_msg}"
    );

    // Parent cascade removal remains permitted
    sqlx::query("DELETE FROM jobs WHERE job_id = $1")
        .bind(job)
        .execute(pool)
        .await
        .expect("Cascade removal via parent jobs must remain permitted");
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM job_progress WHERE job_id = $1")
        .bind(job)
        .fetch_one(pool)
        .await
        .expect("Failed to count remaining progress rows");
    assert_eq!(remaining, 0, "Cascade path must have removed progress rows");

    ctx.close().await;
}

#[tokio::test]
async fn test_job_dependencies_contract_and_succeeded_predecessor_semantics() {
    let ctx = provision().await;
    let pool = ctx.pool();

    let predecessor = insert_job(pool, ctx.ws_a, "deps", "queued").await;
    let successor = insert_job(pool, ctx.ws_a, "deps", "requested").await;

    sqlx::query("INSERT INTO job_dependencies (job_id, depends_on_job_id) VALUES ($1, $2)")
        .bind(successor)
        .bind(predecessor)
        .execute(pool)
        .await
        .expect("Valid dependency edge must insert");

    // Self-dependency is rejected
    let self_dep =
        sqlx::query("INSERT INTO job_dependencies (job_id, depends_on_job_id) VALUES ($1, $1)")
            .bind(successor)
            .execute(pool)
            .await;
    let err_msg = self_dep
        .expect_err("Self-dependency must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_job_dependencies_not_self"),
        "Self-dependency must violate chk_job_dependencies_not_self, got: {err_msg}"
    );

    // Duplicate pair is rejected
    let dup_pair =
        sqlx::query("INSERT INTO job_dependencies (job_id, depends_on_job_id) VALUES ($1, $2)")
            .bind(successor)
            .bind(predecessor)
            .execute(pool)
            .await;
    let err_msg = dup_pair
        .expect_err("Duplicate dependency pair must be rejected")
        .to_string();
    assert!(
        err_msg.contains("uq_job_dependencies_pair") || err_msg.contains("duplicate key"),
        "Expected unique-pair violation, got: {err_msg}"
    );

    // Dangling predecessor reference is rejected by FK
    let dangling =
        sqlx::query("INSERT INTO job_dependencies (job_id, depends_on_job_id) VALUES ($1, $2)")
            .bind(successor)
            .bind(Uuid::new_v4())
            .execute(pool)
            .await;
    assert!(
        dangling.is_err(),
        "Dependency on a nonexistent job must be rejected by FK"
    );

    // Canonical predecessor-success eligibility: only status='succeeded' satisfies.
    for unsatisfied in [
        "queued",
        "running",
        "retryable",
        "failed",
        "cancelled",
        "dead_letter",
    ] {
        sqlx::query("UPDATE jobs SET status = $1 WHERE job_id = $2")
            .bind(unsatisfied)
            .bind(predecessor)
            .execute(pool)
            .await
            .expect("Predecessor status update failed");
        let satisfied: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM job_dependencies d \
                 JOIN jobs p ON p.job_id = d.depends_on_job_id \
                 WHERE d.job_id = $1 AND p.job_id = $2 AND p.status = 'succeeded' \
             )",
        )
        .bind(successor)
        .bind(predecessor)
        .fetch_one(pool)
        .await
        .expect("Eligibility query failed");
        assert!(
            !satisfied,
            "Predecessor status '{unsatisfied}' must NOT satisfy the dependency"
        );
    }

    sqlx::query("UPDATE jobs SET status = 'succeeded' WHERE job_id = $1")
        .bind(predecessor)
        .execute(pool)
        .await
        .expect("Predecessor success update failed");
    let satisfied: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM job_dependencies d \
             JOIN jobs p ON p.job_id = d.depends_on_job_id \
             WHERE d.job_id = $1 AND p.job_id = $2 AND p.status = 'succeeded' \
         )",
    )
    .bind(successor)
    .bind(predecessor)
    .fetch_one(pool)
    .await
    .expect("Eligibility query failed");
    assert!(
        satisfied,
        "Predecessor status 'succeeded' MUST satisfy the dependency"
    );

    // Cascade removal of the successor removes its dependency edges
    sqlx::query("DELETE FROM jobs WHERE job_id = $1")
        .bind(successor)
        .execute(pool)
        .await
        .expect("Successor cascade deletion must be permitted");
    let edges: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM job_dependencies WHERE depends_on_job_id = $1 OR job_id = $1",
    )
    .bind(successor)
    .fetch_one(pool)
    .await
    .expect("Failed to count remaining edges");
    assert_eq!(edges, 0, "Cascade must have removed dependency edges");

    ctx.close().await;
}

#[tokio::test]
async fn test_dead_letter_entries_contract() {
    let ctx = provision().await;
    let pool = ctx.pool();
    let poisoned = insert_job(pool, ctx.ws_a, "dlq", "dead_letter").await;

    sqlx::query("INSERT INTO dead_letter_entries (job_id, queue_name, job_type, attempt_count, failure_reason) VALUES ($1, 'dlq', 'evidence-test', 3, 'max attempts exhausted')")
        .bind(poisoned)
        .execute(pool)
        .await
        .expect("Valid dead-letter entry must insert");

    // One durable record per poisoned job
    let dup = sqlx::query(
        "INSERT INTO dead_letter_entries (job_id, queue_name, job_type, attempt_count, failure_reason) VALUES ($1, 'dlq', 'evidence-test', 4, 'second entry')",
    )
    .bind(poisoned)
    .execute(pool)
    .await;
    let err_msg = dup
        .expect_err("Second dead-letter record for the same job must be rejected")
        .to_string();
    assert!(
        err_msg.contains("uq_dead_letter_job") || err_msg.contains("duplicate key"),
        "Expected uq_dead_letter_job violation, got: {err_msg}"
    );

    // attempt_count > 0
    let other_job = insert_job(pool, ctx.ws_a, "dlq", "dead_letter").await;
    let zero_attempts = sqlx::query(
        "INSERT INTO dead_letter_entries (job_id, queue_name, job_type, attempt_count, failure_reason) VALUES ($1, 'dlq', 'evidence-test', 0, 'zero')",
    )
    .bind(other_job)
    .execute(pool)
    .await;
    let err_msg = zero_attempts
        .expect_err("Dead-letter attempt_count = 0 must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_dead_letter_attempt_count_positive"),
        "Zero attempt count must violate check, got: {err_msg}"
    );

    // resolved_at must not precede failed_at
    let bad_resolution = sqlx::query(
        "INSERT INTO dead_letter_entries (job_id, queue_name, job_type, attempt_count, failure_reason, failed_at, resolved_at) VALUES ($1, 'dlq', 'evidence-test', 2, 'time-travel', clock_timestamp(), clock_timestamp() - INTERVAL '1 hour')",
    )
    .bind(other_job)
    .execute(pool)
    .await;
    let err_msg = bad_resolution
        .expect_err("Resolution before failure must be rejected")
        .to_string();
    assert!(
        err_msg.contains("chk_dead_letter_resolved"),
        "Backwards resolution must violate chk_dead_letter_resolved, got: {err_msg}"
    );

    // Bounded resolution update succeeds
    sqlx::query("UPDATE dead_letter_entries SET resolved_at = clock_timestamp(), resolution_notes = 'replayed manually' WHERE job_id = $1")
        .bind(poisoned)
        .execute(pool)
        .await
        .expect("Bounded resolution update must succeed");
    let resolved: (bool, Option<String>) = sqlx::query_as(
        "SELECT resolved_at IS NOT NULL, resolution_notes FROM dead_letter_entries WHERE job_id = $1",
    )
    .bind(poisoned)
    .fetch_one(pool)
    .await
    .expect("Failed to read resolution state");
    assert!(resolved.0);
    assert_eq!(resolved.1.as_deref(), Some("replayed manually"));

    // Cascade removal follows the parent job
    sqlx::query("DELETE FROM jobs WHERE job_id = $1")
        .bind(poisoned)
        .execute(pool)
        .await
        .expect("Poisoned job cascade deletion must be permitted");
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dead_letter_entries WHERE job_id = $1")
            .bind(poisoned)
            .fetch_one(pool)
            .await
            .expect("Failed to count remaining dead-letter entries");
    assert_eq!(
        remaining, 0,
        "Cascade must have removed dead-letter entries"
    );

    ctx.close().await;
}

#[tokio::test]
async fn test_child_tables_rls_scoping_flows_through_parent_jobs() {
    let ctx = provision().await;
    let pool = ctx.pool();

    let job_a = insert_job(pool, ctx.ws_a, "rls-child", "queued").await;
    let job_b = insert_job(pool, ctx.ws_b, "rls-child", "queued").await;

    for job in [job_a, job_b] {
        sqlx::query("INSERT INTO job_attempts (job_id, attempt_number, worker_id) VALUES ($1, 1, 'worker-x')")
            .bind(job)
            .execute(pool)
            .await
            .expect("Failed to insert attempt");
        sqlx::query("INSERT INTO job_progress (job_id, sequence, stage_code, current) VALUES ($1, 0, 'RLS_STAGE', 0)")
            .bind(job)
            .execute(pool)
            .await
            .expect("Failed to insert progress");
        sqlx::query("INSERT INTO dead_letter_entries (job_id, queue_name, job_type, attempt_count, failure_reason) VALUES ($1, 'rls-child', 'evidence-test', 1, 'dlq-row')")
            .bind(job)
            .execute(pool)
            .await
            .expect("Failed to insert dead-letter entry");
    }

    // One valid non-self dependency edge per workspace
    let pred_a = insert_job(pool, ctx.ws_a, "rls-child", "succeeded").await;
    let succ_a = insert_job(pool, ctx.ws_a, "rls-child", "requested").await;
    let pred_b = insert_job(pool, ctx.ws_b, "rls-child", "succeeded").await;
    let succ_b = insert_job(pool, ctx.ws_b, "rls-child", "requested").await;
    sqlx::query(
        "INSERT INTO job_dependencies (job_id, depends_on_job_id) VALUES ($1, $2), ($3, $4)",
    )
    .bind(succ_a)
    .bind(pred_a)
    .bind(succ_b)
    .bind(pred_b)
    .execute(pool)
    .await
    .expect("Failed to insert dependency edges");

    // Workspace A context under w014_app sees ONLY workspace A children
    {
        let mut tx = pool.begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .expect("set role");
        set_session_workspace_id(&mut tx, ctx.ws_a)
            .await
            .expect("set ws_a context");

        let visible_attempts: Vec<Uuid> = sqlx::query_scalar("SELECT job_id FROM job_attempts")
            .fetch_all(&mut *tx)
            .await
            .expect("query attempts");
        assert_eq!(visible_attempts, vec![job_a]);

        let visible_progress: Vec<Uuid> = sqlx::query_scalar("SELECT job_id FROM job_progress")
            .fetch_all(&mut *tx)
            .await
            .expect("query progress");
        assert_eq!(visible_progress, vec![job_a]);

        let visible_dlq: Vec<Uuid> = sqlx::query_scalar("SELECT job_id FROM dead_letter_entries")
            .fetch_all(&mut *tx)
            .await
            .expect("query dlq");
        assert_eq!(visible_dlq, vec![job_a]);

        let visible_deps: Vec<Uuid> = sqlx::query_scalar("SELECT job_id FROM job_dependencies")
            .fetch_all(&mut *tx)
            .await
            .expect("query deps");
        assert_eq!(visible_deps, vec![succ_a]);

        // Cross-workspace child writes are rejected via parent-scoped WITH CHECK
        let cross_ws_progress = sqlx::query(
            "INSERT INTO job_progress (job_id, sequence, stage_code, current) VALUES ($1, 0, 'SPOOF', 0)",
        )
        .bind(job_b)
        .execute(&mut *tx)
        .await;
        assert!(
            cross_ws_progress.is_err(),
            "Cross-workspace job_progress insert must be rejected by RLS WITH CHECK"
        );

        let cross_ws_dep =
            sqlx::query("INSERT INTO job_dependencies (job_id, depends_on_job_id) VALUES ($1, $2)")
                .bind(job_b)
                .bind(job_a)
                .execute(&mut *tx)
                .await;
        assert!(
            cross_ws_dep.is_err(),
            "Cross-workspace job_dependencies insert must be rejected by RLS WITH CHECK"
        );

        tx.rollback().await.expect("rollback");
    }

    // Fail-closed: cleared context exposes zero child rows
    {
        let mut tx = pool.begin().await.expect("begin tx");
        sqlx::query("SET LOCAL ROLE w014_app")
            .execute(&mut *tx)
            .await
            .expect("set role");
        clear_session_workspace_id(&mut tx)
            .await
            .expect("clear ctx");

        let attempts_cleared: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM job_attempts")
            .fetch_one(&mut *tx)
            .await
            .expect("query attempts cleared");
        assert_eq!(attempts_cleared, 0);

        tx.rollback().await.expect("rollback");
    }

    ctx.close().await;
}

#[tokio::test]
async fn test_public_schema_contains_exactly_the_authorized_30_tables() {
    let ctx = provision().await;
    let pool = ctx.pool();

    let expected_tables: Vec<String> = [
        // M001R (13)
        "organizations",
        "principals",
        "programs",
        "workspaces",
        "memberships",
        "capability_grants",
        "oidc_identities",
        "sessions",
        "session_rotations",
        "oidc_transactions",
        "audit_chain_heads",
        "audit_events",
        "idempotency_records",
        // M002R (17)
        "documents",
        "document_versions",
        "document_version_metadata",
        "upload_intents",
        "object_artifacts",
        "quarantine_records",
        "parser_artifacts",
        "parser_pages",
        "parser_blocks",
        "source_spans",
        "jobs",
        "job_attempts",
        "job_dependencies",
        "job_progress",
        "dead_letter_entries",
        "dependency_keys",
        "change_events",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let mut expected_sorted = expected_tables.clone();
    expected_sorted.sort();

    let actual_tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_tables \
         WHERE schemaname = 'public' AND tablename <> '_sqlx_migrations' \
         ORDER BY tablename",
    )
    .fetch_all(pool)
    .await
    .expect("Failed to enumerate public tables");

    assert_eq!(
        actual_tables.len(),
        expected_tables.len(),
        "Public schema table count must be exactly 30"
    );
    assert_eq!(
        actual_tables, expected_sorted,
        "Public schema must contain EXACTLY the 13 M001R + 17 M002R tables (no M003R/M004R/W3 leakage)"
    );

    ctx.close().await;
}
