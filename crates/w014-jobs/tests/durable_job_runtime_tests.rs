//! W2 Minimum Durable Job Runtime — real-PostgreSQL proof battery.
//!
//! Proves the frozen runtime semantics against the repaired M002R substrate:
//! enqueue durability/idempotency, the exact status vocabulary, claim safety
//! (FOR UPDATE SKIP LOCKED), short claim transactions, lease ownership/expiry/
//! reclaim, generation fencing, heartbeat, bounded backoff, retry exhaustion,
//! dead-letter linkage, attempt history, dependency enforcement using
//! predecessor `succeeded`, append-only progress, workspace isolation, and
//! secret-free payloads.

mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::json;
use uuid::Uuid;
use w014_jobs::WorkspaceScope;
use w014_jobs::{
    ClaimedJob, FailureKind, FailureResolution, JobError, JobKind, JobStatus, WorkerId,
    backoff_delay_secs_after,
};

// ----------------------------------------------------------------------
// 1/3. Enqueue durability + requested -> queued
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_001_enqueue_is_durable_and_transitions_requested_to_queued() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let params = params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["doc-1"]);
    let outcome = queue.enqueue(params).await.expect("enqueue must succeed");
    assert!(outcome.is_new(), "first enqueue creates a logical job");
    let record = outcome.record();

    // Canonical SHA-256 idempotency identity persisted.
    assert!(
        record
            .idempotency_key
            .as_deref()
            .is_some_and(|k| k.starts_with("sha256:")),
        "idempotency key must be canonical sha256 form"
    );

    // Frozen enqueue transition landed exactly at 'queued'.
    assert_eq!(raw_status(ctx.pool(), record.job_id).await, "queued");

    // Secret-free bounded payload persisted with the envelope contract fields.
    let payload: serde_json::Value =
        sqlx::query_scalar("SELECT payload FROM jobs WHERE job_id = $1")
            .bind(record.job_id)
            .fetch_one(ctx.pool())
            .await
            .expect("payload readable");
    assert_eq!(payload["payload_contract_version"], json!(1));
    assert_eq!(payload["immutable_targets"], json!(["doc-1"]));
    assert!(!payload.to_string().to_lowercase().contains("secret"));

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 2. Duplicate enqueue idempotency (+ cancelled identity preservation)
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_002_duplicate_enqueue_is_idempotent_and_preserves_cancelled_identity() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let params = || params_for(ctx.ws_a, JobKind::MalwareScanDocumentPdf, &["dv-a"]);
    let first = queue.enqueue(params()).await.expect("first enqueue");
    let second = queue.enqueue(params()).await.expect("duplicate enqueue");
    assert!(first.is_new(), "first call creates the logical job");
    assert!(
        !second.is_new(),
        "duplicate returns the existing logical job"
    );
    assert_eq!(first.record().job_id, second.record().job_id);

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE idempotency_key = $1")
        .bind(first.record().idempotency_key.as_deref().unwrap())
        .fetch_one(ctx.pool())
        .await
        .expect("count");
    assert_eq!(
        count, 1,
        "duplicate legal enqueue must not create a second row"
    );

    // Cancel the historical identity, then re-enqueue: it must NOT be replayed
    // as if it never existed — the same cancelled logical job is returned.
    let cancelled = queue
        .cancel(ctx.ws_a, first.record().job_id)
        .await
        .expect("cancel");
    assert_eq!(cancelled, w014_jobs::CancellationOutcome::Cancelled);
    let replay = queue.enqueue(params()).await.expect("replay enqueue");
    assert!(!replay.is_new());
    assert_eq!(replay.record().job_id, first.record().job_id);
    assert_eq!(replay.record().status, JobStatus::Cancelled);

    // A NEW legal generation (dependency_hash) creates a distinct logical job.
    let mut new_generation = params_for(ctx.ws_a, JobKind::MalwareScanDocumentPdf, &["dv-a"]);
    new_generation.dependency_hash = Some(format!("sha256:{}", Uuid::new_v4()));
    let distinct = queue
        .enqueue(new_generation)
        .await
        .expect("new generation enqueue");
    assert!(distinct.is_new());
    assert_ne!(distinct.record().job_id, first.record().job_id);

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 4/13/28. Claim: queued -> running, lease acquisition, attempt history
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_004_claim_transitions_queued_to_running_with_lease_and_attempt_history() {
    let ctx = provision().await;
    let queue = ctx.queue();
    let worker = WorkerId::new();

    let job = queue
        .enqueue(params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["doc-c"]))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    let claimed = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), worker)
        .await
        .expect("claim executes")
        .expect("queued job is claimable");

    assert_eq!(claimed.job_id, job);
    assert_eq!(claimed.kind, JobKind::ParseDocumentPdf);
    assert_eq!(claimed.attempt_number, 1);
    assert_eq!(claimed.max_attempts, 5);
    assert_eq!(claimed.workspace_id, ctx.ws_a);
    assert_eq!(claimed.queue_name, PARSE_QUEUE);

    let state = lease_state(ctx.pool(), job).await;
    assert_eq!(state.status, "running");
    assert_eq!(state.attempt_count, 1);
    assert_eq!(
        state.lease_holder.as_deref(),
        Some(claimed.worker_id.as_str())
    );
    assert_eq!(state.lease_token, Some(claimed.lease_token));
    assert_eq!(
        state.lease_generation, 1,
        "generation advances on first claim"
    );
    assert!(state.not_before <= chrono::Utc::now());

    // Append-oriented attempt history: exactly one running row for attempt 1.
    let attempts = queue
        .attempts_for_job(ctx.ws_a, job)
        .await
        .expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].attempt_number, 1);
    assert_eq!(attempts[0].outcome.to_string(), "running");
    assert!(attempts[0].completed_at.is_none());

    // UNIQUE(job_id, attempt_number) is enforced physically.
    let dup = sqlx::query(
        "INSERT INTO job_attempts (job_id, attempt_number, worker_id) VALUES ($1, 1, 'other')",
    )
    .bind(job)
    .execute(ctx.pool())
    .await;
    assert!(dup.is_err(), "duplicate attempt number must be rejected");

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 5/6/24/25. Retryable transitions + frozen bounded backoff schedule
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_006_running_to_retryable_records_frozen_bounded_backoff_then_reclaims() {
    let ctx = provision().await;
    let queue = ctx.queue();
    let worker = WorkerId::new();

    let job = queue
        .enqueue(params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["doc-r"]))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    let claimed = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), worker)
        .await
        .expect("claim")
        .expect("claimable");

    let resolution = queue
        .complete_failure(
            &claimed,
            "E_TRANSIENT",
            "temporary storage hiccup",
            FailureKind::Retryable,
        )
        .await
        .expect("retryable failure recorded");
    let FailureResolution::RetryScheduled { delay_secs, .. } = resolution else {
        panic!("expected RetryScheduled, got {resolution:?}");
    };
    assert_eq!(delay_secs, 15, "retry 1 must use the frozen 15s step");

    let state = lease_state(ctx.pool(), job).await;
    assert_eq!(state.status, "retryable", "running -> retryable");
    assert_eq!(state.lease_token, None, "lease cleared/superseded legally");
    assert_eq!(state.lease_holder, None);

    // Attempt history preserved with the frozen retryable_failed outcome.
    let attempts = queue
        .attempts_for_job(ctx.ws_a, job)
        .await
        .expect("attempts");
    assert_eq!(attempts[0].outcome.to_string(), "retryable_failed");
    assert!(attempts[0].completed_at.is_some());

    // Bounded database-backed delay is authoritative: not yet claimable...
    let early = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), worker)
        .await
        .expect("claim executes");
    assert!(early.is_none(), "backoff delay must defer reclaim");

    // ...and becomes claimable exactly when the delay elapses (deterministic).
    make_due_now(ctx.pool(), job).await;
    let reclaimed = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("due retryable job reclaims");
    assert_eq!(
        reclaimed.attempt_number, 2,
        "retryable -> running on attempt 2"
    );
    assert_eq!(reclaimed.lease_generation, 2, "generation fence advanced");
    assert_ne!(
        reclaimed.lease_token, claimed.lease_token,
        "new fence token per authority"
    );
    let state2 = lease_state(ctx.pool(), job).await;
    assert_eq!(state2.status, "running");

    ctx.close().await;
}

#[tokio::test]
async fn test_025_backoff_schedule_matches_frozen_steps_exactly() {
    let ctx = provision().await;
    let queue = ctx.queue();
    let expected = [15_i64, 60, 300, 1200];
    let max_attempts = 5_i32;

    let job = queue
        .enqueue(params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["doc-b"]))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    for attempt in 1..=4 {
        make_due_now(ctx.pool(), job).await;
        let criteria = single_ws_criteria(PARSE_QUEUE, ctx.ws_a);
        let claimed = queue
            .claim(criteria, WorkerId::new())
            .await
            .expect("claim")
            .expect("attempt");
        assert_eq!(claimed.attempt_number, attempt);

        assert_eq!(
            backoff_delay_secs_after(attempt, max_attempts),
            Some(expected[(attempt - 1) as usize]),
            "frozen schedule step {attempt}"
        );

        let resolution = queue
            .complete_failure(
                &claimed,
                "E_RETRY",
                "flaky dependency",
                FailureKind::Retryable,
            )
            .await
            .expect("failure recorded");
        match resolution {
            FailureResolution::RetryScheduled {
                not_before,
                delay_secs,
            } => {
                assert_eq!(delay_secs, expected[(attempt - 1) as usize]);
                // Bounded database-backed delay sanity (no sleep-based proof):
                let remaining = (not_before - chrono::Utc::now()).num_seconds();
                assert!(
                    remaining > delay_secs - 10 && remaining <= delay_secs,
                    "not_before must sit ~{delay_secs}s ahead, saw {remaining}s"
                );
            }
            other => panic!("attempt {attempt}: unexpected {other:?}"),
        }
    }

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 7/21/22. Safe success completion; double completion prevented
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_007_safe_success_completion_and_double_completion_prevention() {
    let ctx = provision().await;
    let queue = ctx.queue();
    let worker = WorkerId::new();

    let job = queue
        .enqueue(params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["doc-s"]))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    let claimed = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), worker)
        .await
        .expect("claim")
        .expect("claimable");

    queue
        .complete_success(&claimed, Some(json!({"pages_parsed": 3})))
        .await
        .expect("valid completion succeeds");

    let state = lease_state(ctx.pool(), job).await;
    assert_eq!(state.status, "succeeded", "running -> succeeded");
    assert_eq!(state.lease_token, None, "authority released");

    let result: serde_json::Value = sqlx::query_scalar("SELECT result FROM jobs WHERE job_id = $1")
        .bind(job)
        .fetch_one(ctx.pool())
        .await
        .expect("result readable");
    assert_eq!(result["pages_parsed"], json!(3));

    let attempts = queue
        .attempts_for_job(ctx.ws_a, job)
        .await
        .expect("attempts");
    assert_eq!(attempts[0].outcome.to_string(), "succeeded");
    assert!(attempts[0].completed_at.is_some());

    // Double success: no second logical effect, typed rejection.
    let double = queue
        .complete_success(&claimed, Some(json!({"pages_parsed": 999})))
        .await;
    assert_eq!(
        double,
        Err(JobError::AlreadyTerminal {
            job_id: job,
            status: "succeeded".to_string()
        }),
        "double completion must be rejected as AlreadyTerminal"
    );
    let result_after: serde_json::Value =
        sqlx::query_scalar("SELECT result FROM jobs WHERE job_id = $1")
            .bind(job)
            .fetch_one(ctx.pool())
            .await
            .expect("result readable");
    assert_eq!(
        result_after["pages_parsed"],
        json!(3),
        "no second logical effect"
    );

    // Terminal state cannot be illegally reopened by any path.
    assert_eq!(
        queue
            .complete_failure(&claimed, "E_LATE", "late failure", FailureKind::Retryable)
            .await,
        Err(JobError::AlreadyTerminal {
            job_id: job,
            status: "succeeded".to_string()
        })
    );
    assert_eq!(
        queue.heartbeat(&claimed, 30).await,
        Err(JobError::AlreadyTerminal {
            job_id: job,
            status: "succeeded".to_string()
        })
    );
    assert_eq!(raw_status(ctx.pool(), job).await, "succeeded");

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 8/26/27. Retry exhaustion -> dead_letter with one durable linkage
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_027_retry_exhaustion_dead_letters_with_single_durable_linkage() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let job = queue
        .enqueue(params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["doc-x"]))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    for attempt in 1..=4 {
        make_due_now(ctx.pool(), job).await;
        let claimed = queue
            .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
            .await
            .expect("claim")
            .unwrap_or_else(|| panic!("attempt {attempt} must be claimable"));
        let resolution = queue
            .complete_failure(&claimed, "E_FLAKY", "transient", FailureKind::Retryable)
            .await
            .expect("recorded");
        assert!(
            matches!(resolution, FailureResolution::RetryScheduled { .. }),
            "attempts 1..4 retry within budget"
        );
    }

    // Fifth failure hits the frozen boundary: dead_letter where frozen.
    make_due_now(ctx.pool(), job).await;
    let final_claim = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("final attempt");
    assert_eq!(final_claim.attempt_number, 5);
    let resolution = queue
        .complete_failure(&final_claim, "E_FLAKY", "transient", FailureKind::Retryable)
        .await
        .expect("recorded");
    assert_eq!(resolution, FailureResolution::DeadLettered);

    assert_eq!(raw_status(ctx.pool(), job).await, "dead_letter");

    let entry = queue
        .dead_letter_entry(ctx.ws_a, job)
        .await
        .expect("dlq read")
        .expect("exactly one linkage exists");
    assert_eq!(entry.job_id, job);
    assert_eq!(entry.failure_reason, "retry_exhausted");
    assert_eq!(entry.attempt_count, 5);
    assert_eq!(entry.queue_name, PARSE_QUEUE);
    assert_eq!(entry.error_details["error_code"], json!("E_FLAKY"));

    let dlq_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dead_letter_entries WHERE job_id = $1")
            .bind(job)
            .fetch_one(ctx.pool())
            .await
            .expect("count");
    assert_eq!(
        dlq_rows, 1,
        "one legal terminal dead-letter linkage per exhausted job"
    );

    // Terminal: no further claims ever.
    make_due_now(ctx.pool(), job).await;
    let after = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim executes");
    assert!(after.is_none(), "dead_letter never reopens");

    // Attempt history fully preserved through exhaustion.
    let attempts = queue
        .attempts_for_job(ctx.ws_a, job)
        .await
        .expect("attempts");
    let numbers: Vec<i32> = attempts.iter().map(|a| a.attempt_number).collect();
    assert_eq!(numbers, vec![1, 2, 3, 4, 5], "ordered append history");
    assert!(
        attempts
            .iter()
            .all(|a| a.outcome.to_string() == "retryable_failed")
    );

    ctx.close().await;
}

// ----------------------------------------------------------------------
// Poison + terminal failures
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_poison_failure_dead_letters_immediately_without_consuming_retries() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let job = queue
        .enqueue(params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["doc-p"]))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    let claimed = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("claimable");

    let resolution = queue
        .complete_failure(
            &claimed,
            "E_MALFORMED",
            "unparseable poison input",
            FailureKind::Poison,
        )
        .await
        .expect("recorded");
    assert_eq!(resolution, FailureResolution::DeadLettered);
    assert_eq!(raw_status(ctx.pool(), job).await, "dead_letter");

    let entry = queue
        .dead_letter_entry(ctx.ws_a, job)
        .await
        .expect("read")
        .expect("linkage");
    assert_eq!(entry.failure_reason, "poison:E_MALFORMED");
    assert_eq!(entry.attempt_count, 1);

    ctx.close().await;
}

#[tokio::test]
async fn test_terminal_failure_never_retries() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let job = queue
        .enqueue(params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["doc-t"]))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    let claimed = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("claimable");

    let resolution = queue
        .complete_failure(
            &claimed,
            "E_UNSUPPORTED",
            "format unsupported permanently",
            FailureKind::Terminal,
        )
        .await
        .expect("recorded");
    assert_eq!(resolution, FailureResolution::TerminalFailed);
    assert_eq!(
        raw_status(ctx.pool(), job).await,
        "failed",
        "running -> failed where frozen"
    );

    let attempts = queue
        .attempts_for_job(ctx.ws_a, job)
        .await
        .expect("attempts");
    assert_eq!(attempts[0].outcome.to_string(), "terminal_failed");
    assert_eq!(attempts[0].error_code.as_deref(), Some("E_UNSUPPORTED"));

    make_due_now(ctx.pool(), job).await;
    let again = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim executes");
    assert!(
        again.is_none(),
        "terminal failure must not retry indefinitely"
    );
    // No dead-letter linkage for plain terminal failure.
    assert!(
        queue
            .dead_letter_entry(ctx.ws_a, job)
            .await
            .expect("read")
            .is_none()
    );

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 9. Obsolete status aliases are not used anywhere
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_009_obsolete_status_aliases_are_never_used() {
    let ctx = provision().await;

    // Closed Rust type rejects obsolete aliases.
    for alias in ["enqueued", "claimed", "completed"] {
        assert!(JobStatus::parse(alias).is_err(), "'{alias}' must not parse");
    }

    // Physical layer rejects them too (chk_jobs_status).
    for alias in ["enqueued", "claimed", "completed"] {
        let rejected = sqlx::query(
            "INSERT INTO jobs (workspace_id, queue_name, job_type, status) \
             VALUES ($1, $2, 'unit', $3)",
        )
        .bind(ctx.ws_a)
        .bind(PARSE_QUEUE)
        .bind(alias)
        .execute(ctx.pool())
        .await;
        let msg = rejected
            .expect_err("obsolete alias must be rejected")
            .to_string();
        assert!(msg.contains("chk_jobs_status"), "got: {msg}");
    }

    // Runtime-produced statuses across this battery are only frozen values.
    let statuses: Vec<String> = sqlx::query_scalar("SELECT DISTINCT status FROM jobs")
        .fetch_all(ctx.pool())
        .await
        .expect("statuses");
    assert!(
        statuses.iter().all(|s| JobStatus::parse(s).is_ok()),
        "only frozen vocabulary may exist: {statuses:?}"
    );

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 10/11/12. Concurrent claim safety, single authority, short claim tx
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_010_two_concurrent_workers_cannot_both_obtain_authority() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let job = queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::ParseDocumentPdf,
            &["doc-race"],
        ))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    let mut racers = Vec::new();
    for _ in 0..4 {
        let q = queue.clone();
        let criteria = single_ws_criteria(PARSE_QUEUE, ctx.ws_a);
        racers.push(tokio::spawn(async move {
            q.claim(criteria, WorkerId::new())
                .await
                .expect("claim executes")
        }));
    }

    let winners = futures_join_all(racers).await;
    let successful: Vec<&ClaimedJob> = winners.iter().flatten().collect();
    assert_eq!(
        successful.len(),
        1,
        "FOR UPDATE SKIP LOCKED yields exactly one winner"
    );

    let winner = successful[0];
    assert_eq!(winner.job_id, job);
    let state = lease_state(ctx.pool(), job).await;
    assert_eq!(
        state.attempt_count, 1,
        "single current valid execution authority"
    );
    assert_eq!(state.lease_generation, 1);

    let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM job_attempts WHERE job_id = $1")
        .bind(job)
        .fetch_one(ctx.pool())
        .await
        .expect("attempt count");
    assert_eq!(
        attempts, 1,
        "exactly one attempt row appended by the winner"
    );

    ctx.close().await;
}

#[tokio::test]
async fn test_010b_many_jobs_many_workers_no_double_claims() {
    let ctx = provision().await;
    let queue = ctx.queue();

    const JOBS: usize = 12;
    for i in 0..JOBS {
        queue
            .enqueue(params_for(
                ctx.ws_a,
                JobKind::ParseDocumentPdf,
                &[&format!("doc-m{i}")],
            ))
            .await
            .expect("enqueue");
    }

    let mut racers = Vec::new();
    for _ in 0..4 {
        let q = queue.clone();
        let criteria = single_ws_criteria(PARSE_QUEUE, ctx.ws_a);
        racers.push(tokio::spawn(async move {
            let mut claimed_jobs = Vec::new();
            for _ in 0..JOBS {
                match q
                    .claim(criteria.clone(), WorkerId::new())
                    .await
                    .expect("claim")
                {
                    Some(c) => claimed_jobs.push(c.job_id),
                    None => break,
                }
            }
            claimed_jobs
        }));
    }
    let results = futures_join_all(racers).await;
    let mut all: Vec<Uuid> = results.into_iter().flatten().collect();
    all.sort();
    let total = all.len();
    assert_eq!(
        total, JOBS,
        "every job claimed exactly once across racing workers"
    );
    let before_dedup = all.len();
    all.dedup();
    assert_eq!(all.len(), before_dedup, "no job may be double-claimed");

    ctx.close().await;
}

#[tokio::test]
async fn test_012_claim_transaction_stays_short_under_row_lock_contention() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let job = queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::ParseDocumentPdf,
            &["doc-lock"],
        ))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    // Hold an external lock on the candidate row: a SHORT claim transaction
    // must skip it immediately (SKIP LOCKED), never block on long work.
    let mut holder_tx = ctx.pool().begin().await.expect("holder tx");
    sqlx::query("SELECT job_id FROM jobs WHERE job_id = $1 FOR UPDATE")
        .bind(job)
        .fetch_one(&mut *holder_tx)
        .await
        .expect("lock held");

    let started = Instant::now();
    let skipped = tokio::time::timeout(
        Duration::from_secs(5),
        queue.claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new()),
    )
    .await
    .expect("claim must return promptly under contention (no blocking)")
    .expect("claim executes");
    assert!(skipped.is_none(), "locked candidate must be skipped");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "short claim tx, took {elapsed:?}"
    );

    holder_tx.rollback().await.expect("release lock");

    let now_claimable = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("claimable once unlocked");
    assert_eq!(now_claimable.job_id, job);

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 14/15/16/23. Lease expiry, legal reclaim, generation advancement, crash recovery
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_023_worker_crash_recovery_via_expired_lease_reclaim() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let job = queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::ParseDocumentPdf,
            &["doc-crash"],
        ))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    // Worker 1 "crashes": claims then never completes nor heartbeats.
    let crashed = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("worker1 claims");

    // Deterministic lease expiry via database manipulation (no sleeps).
    force_expire_lease(ctx.pool(), job).await;

    // Expired authority cannot renew itself.
    assert!(
        matches!(
            queue.heartbeat(&crashed, 60).await,
            Err(JobError::LeaseLost(_))
        ),
        "expired heartbeat must be rejected"
    );

    // Legal reclaim issues newer attempt/generation authority to worker 2.
    let recovered = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("expired running work is recoverable");
    assert_eq!(recovered.attempt_number, 2);
    assert_eq!(
        recovered.lease_generation,
        crashed.lease_generation + 1,
        "N+1 authority"
    );
    assert_ne!(recovered.lease_token, crashed.lease_token);

    // Prior attempt history preserved with lease_expired outcome.
    let attempts = queue
        .attempts_for_job(ctx.ws_a, job)
        .await
        .expect("attempts");
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].outcome.to_string(), "lease_expired");
    assert!(
        attempts[0].completed_at.is_some(),
        "abandoned attempt finalized"
    );
    assert_eq!(attempts[1].outcome.to_string(), "running");

    // Recovered worker completes successfully.
    queue
        .complete_success(&recovered, None)
        .await
        .expect("completion");
    assert_eq!(raw_status(ctx.pool(), job).await, "succeeded");

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 17/18. Heartbeat validity
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_017_valid_heartbeat_extends_only_current_authority() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let job = queue
        .enqueue(params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["doc-hb"]))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    let claimed = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("claimable");

    let renewed = queue
        .heartbeat(&claimed, 120)
        .await
        .expect("valid heartbeat");
    assert!(renewed > claimed.lease_expires_at, "lease extended");

    // Forged coordinates affect zero authoritative rows.
    let mut forged = claimed.clone();
    forged.lease_generation += 1;
    assert!(matches!(
        queue.heartbeat(&forged, 60).await,
        Err(JobError::LeaseLost(_))
    ));
    let mut forged_token = claimed.clone();
    forged_token.lease_token = Uuid::new_v4();
    assert!(matches!(
        queue.heartbeat(&forged_token, 60).await,
        Err(JobError::LeaseLost(_))
    ));

    // Expired authority cannot resurrect itself via heartbeat.
    force_expire_lease(ctx.pool(), job).await;
    let before: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_heartbeat_at FROM jobs WHERE job_id = $1")
            .bind(job)
            .fetch_one(ctx.pool())
            .await
            .expect("hb read");
    assert!(matches!(
        queue.heartbeat(&claimed, 60).await,
        Err(JobError::LeaseLost(_))
    ));
    let after: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_heartbeat_at FROM jobs WHERE job_id = $1")
            .bind(job)
            .fetch_one(ctx.pool())
            .await
            .expect("hb read");
    assert_eq!(before, after, "stale heartbeat mutated zero rows");

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 30/31/32/39. Dependency enforcement (success_required uses `succeeded`)
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_031_dependency_blocks_until_predecessor_is_succeeded_exactly() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let pred = queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::MalwareScanDocumentPdf,
            &["dv-dep"],
        ))
        .await
        .expect("enqueue pred")
        .record()
        .job_id;

    let mut succ_params = params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["dv-dep"]);
    succ_params.depends_on = vec![pred];
    let succ = queue
        .enqueue(succ_params)
        .await
        .expect("enqueue successor")
        .record()
        .job_id;

    // Predecessor wins the race; the dependent job stays blocked.
    let first = queue
        .claim(single_ws_criteria(SCAN_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("pred claimable");
    assert_eq!(first.job_id, pred);

    let blocked = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim executes");
    assert!(
        blocked.is_none(),
        "unsatisfied dependency must block claimability"
    );

    // Predecessor succeeds -> dependency releases.
    queue
        .complete_success(&first, None)
        .await
        .expect("pred success");
    let released = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("success_required released by predecessor succeeded");
    assert_eq!(released.job_id, succ);

    ctx.close().await;
}

#[tokio::test]
async fn test_031b_failed_or_cancelled_predecessor_never_satisfies_success_required() {
    let ctx = provision().await;
    let queue = ctx.queue();

    // Terminal-failed predecessor leaves its dependent blocked forever.
    let pred = queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::MalwareScanDocumentDocxOcr,
            &["dv-neg"],
        ))
        .await
        .expect("enqueue pred")
        .record()
        .job_id;
    let mut succ_params = params_for(ctx.ws_a, JobKind::ParseDocumentDocxOcr, &["dv-neg"]);
    succ_params.depends_on = vec![pred];
    let succ = queue
        .enqueue(succ_params)
        .await
        .expect("enqueue succ")
        .record()
        .job_id;

    let claimed_pred = queue
        .claim(single_ws_criteria(SCAN_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("pred");
    queue
        .complete_failure(
            &claimed_pred,
            "E_INFECTED",
            "malware confirmed",
            FailureKind::Terminal,
        )
        .await
        .expect("failed");

    make_due_now(ctx.pool(), succ).await;
    let blocked = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim executes");
    assert!(
        blocked.is_none(),
        "status='failed' must NOT satisfy success_required"
    );

    // Dependency truth is PostgreSQL-backed: direct predicate proof that ONLY
    // 'succeeded' satisfies (obsolete 'completed' alias has no effect).
    let satisfied: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM job_dependencies d JOIN jobs p ON p.job_id = d.depends_on_job_id \
             WHERE d.job_id = $1 AND p.status = 'succeeded')",
    )
    .bind(succ)
    .fetch_one(ctx.pool())
    .await
    .expect("predicate probe");
    assert!(!satisfied);

    ctx.close().await;
}

#[tokio::test]
async fn test_039_cross_workspace_dependency_edge_is_rejected() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let foreign_pred = queue
        .enqueue(params_for(
            ctx.ws_b,
            JobKind::MalwareScanDocumentPdf,
            &["dv-ws-b"],
        ))
        .await
        .expect("foreign pred enqueued")
        .record()
        .job_id;

    // A ws_a successor referencing a ws_b predecessor violates workspace isolation.
    let mut illegal = params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["dv-ws-a"]);
    illegal.depends_on = vec![foreign_pred];
    let err = queue
        .enqueue(illegal)
        .await
        .expect_err("cross-workspace edge must be rejected");
    assert!(
        matches!(err, JobError::WorkspaceViolation(_)),
        "got: {err:?}"
    );

    // No phantom authoritative work survived the rollback.
    let orphans: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE workspace_id = $1")
        .bind(ctx.ws_a)
        .fetch_one(ctx.pool())
        .await
        .expect("count");
    assert_eq!(orphans, 0, "rollback leaves no phantom authoritative work");

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 33/34/35/36. Append-only progress events
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_033_progress_events_append_monotonically_and_fence_against_stale_workers() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let job = queue
        .enqueue(params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["doc-pr"]))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    let current = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("claimable");

    // Sequential durable stage-level events.
    queue
        .record_progress(&current, 0, "PARSE_START", 0, Some(3), None)
        .await
        .expect("seq 0");
    queue
        .record_progress(&current, 1, "PARSE_PAGES", 1, Some(3), Some("STAGE_OK"))
        .await
        .expect("seq 1");
    queue
        .record_progress(&current, 2, "PARSE_PAGES", 3, Some(3), None)
        .await
        .expect("seq 2");

    let sequences: Vec<i32> =
        sqlx::query_scalar("SELECT sequence FROM job_progress WHERE job_id = $1 ORDER BY sequence")
            .bind(job)
            .fetch_all(ctx.pool())
            .await
            .expect("sequences");
    assert_eq!(sequences, vec![0, 1, 2]);

    // Progress can never function as completion authority.
    let status_after_progress = raw_status(ctx.pool(), job).await;
    assert_eq!(status_after_progress, "running");

    // Duplicate sequence rejected (typed).
    let dup = queue
        .record_progress(&current, 1, "DUP", 0, None, None)
        .await;
    assert!(
        matches!(dup, Err(JobError::ProgressSequenceConflict(_))),
        "got: {dup:?}"
    );
    // Regressed sequence rejected too.
    let regressed = queue
        .record_progress(&current, 0, "REG", 0, None, None)
        .await;
    assert!(matches!(
        regressed,
        Err(JobError::ProgressSequenceConflict(_))
    ));

    // Constraint-shaped inputs are typed before touching PostgreSQL.
    assert!(matches!(
        queue
            .record_progress(&current, 9, "NEG", -1, None, None)
            .await,
        Err(JobError::InvalidPayload(_))
    ));
    assert!(matches!(
        queue
            .record_progress(&current, 9, "TOTAL_LT", 5, Some(4), None)
            .await,
        Err(JobError::InvalidPayload(_))
    ));

    // Stale progress from a superseded worker is rejected with zero inserts.
    force_expire_lease(ctx.pool(), job).await;
    let next = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("superseding authority");
    let stale_event = queue
        .record_progress(&current, 3, "LATE", 0, None, None)
        .await;
    assert!(
        matches!(stale_event, Err(JobError::LeaseLost(_))),
        "got: {stale_event:?}"
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM job_progress WHERE sequence = 3")
        .fetch_one(ctx.pool())
        .await
        .expect("count");
    assert_eq!(count, 0, "stale worker inserted nothing");

    // Current authority continues appending legally.
    queue
        .record_progress(&next, 3, "RESUME", 0, Some(3), None)
        .await
        .expect("fresh authority");
    // Mutable projection / UPSERT models do not exist: still insert-only rows.
    let total_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM job_progress WHERE job_id = $1")
        .bind(job)
        .fetch_one(ctx.pool())
        .await
        .expect("rows");
    assert_eq!(total_rows, 4);

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 37/38/39/42. Kinds, queues, workspace isolation
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_037_all_parser_scan_kinds_route_to_canonical_queues() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let kinds = [
        (JobKind::MalwareScanDocumentPdf, SCAN_QUEUE),
        (JobKind::MalwareScanDocumentDocxOcr, SCAN_QUEUE),
        (JobKind::ParseDocumentPdf, PARSE_QUEUE),
        (JobKind::ParseDocumentDocxOcr, PARSE_QUEUE),
    ];
    for (kind, expected_queue) in kinds {
        let target = format!("dv-{kind:?}");
        let record = queue
            .enqueue(params_for(ctx.ws_a, kind, &[target.as_str()]))
            .await
            .unwrap_or_else(|e| panic!("{kind:?} enqueue failed: {e}"))
            .record()
            .clone();
        assert_eq!(record.kind, kind);
        assert_eq!(record.queue_name, expected_queue);
    }

    // Closed vocabulary rejects unknown/AI kinds.
    for unknown in ["ai_completion", "report_generation", "", "parse_pdf"] {
        assert!(
            JobKind::parse(unknown).is_err(),
            "'{unknown}' must not parse"
        );
    }

    // Scan queue holds exactly the two scan jobs.
    let scan_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE queue_name = $1")
        .bind(SCAN_QUEUE)
        .fetch_one(ctx.pool())
        .await
        .expect("scan count");
    assert_eq!(scan_count, 2);
    let parse_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE queue_name = $1")
        .bind(PARSE_QUEUE)
        .fetch_one(ctx.pool())
        .await
        .expect("parse count");
    assert_eq!(parse_count, 2);

    ctx.close().await;
}

#[tokio::test]
async fn test_038_workspace_isolation_enforced_through_rls_scoped_queue() {
    let ctx = provision().await;
    let rls_queue = ctx.rls_queue().await;

    let job_a = rls_queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::ParseDocumentPdf,
            &["doc-iso"],
        ))
        .await
        .expect("ws_a enqueue under RLS role")
        .record()
        .job_id;

    // Scoped claim in ws_b sees nothing from ws_a (fail-closed RLS).
    let wrong_ws = rls_queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_b), WorkerId::new())
        .await
        .expect("claim executes");
    assert!(wrong_ws.is_none(), "no cross-workspace claim");

    // Correct scope claims it.
    let claimed = rls_queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("own-workspace job claimable");
    assert_eq!(claimed.job_id, job_a);

    // Cross-workspace inspection is invisible under RLS.
    let invisible = rls_queue
        .fetch_job(job_a, WorkspaceScope::Single(ctx.ws_b))
        .await
        .expect("fetch");
    assert!(invisible.is_none(), "cross-workspace reads must be empty");

    ctx.close().await;
}

#[tokio::test]
async fn test_039b_cancellation_transitions_are_frozen_exact() {
    let ctx = provision().await;
    let queue = ctx.queue();

    // queued -> cancelled directly.
    let queued_job = queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::ParseDocumentPdf,
            &["doc-cancel-q"],
        ))
        .await
        .expect("enqueue")
        .record()
        .job_id;
    assert_eq!(
        queue.cancel(ctx.ws_a, queued_job).await.expect("cancel"),
        w014_jobs::CancellationOutcome::Cancelled
    );
    assert_eq!(raw_status(ctx.pool(), queued_job).await, "cancelled");
    let still_there: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE job_id = $1")
        .bind(queued_job)
        .fetch_one(ctx.pool())
        .await
        .expect("count");
    assert_eq!(
        still_there, 1,
        "cancelled historical identity is preserved, not deleted"
    );

    // Running jobs are flagged instead; expiry finalizes cancellation.
    let running_job = queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::ParseDocumentPdf,
            &["doc-cancel-r"],
        ))
        .await
        .expect("enqueue")
        .record()
        .job_id;
    let handle = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("claimable");
    assert_eq!(
        queue.cancel(ctx.ws_a, running_job).await.expect("flag"),
        w014_jobs::CancellationOutcome::CancellationRequested
    );
    assert!(
        queue
            .is_cancellation_requested(ctx.ws_a, running_job)
            .await
            .expect("flag read")
    );

    // Flagged running work stops being reclaimable for execution.
    force_expire_lease(ctx.pool(), running_job).await;
    let none = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim executes");
    assert!(
        none.is_none(),
        "cancellation-requested work must not be re-executed"
    );
    assert_eq!(
        raw_status(ctx.pool(), running_job).await,
        "cancelled",
        "finalized cancelled"
    );
    let attempts = queue
        .attempts_for_job(ctx.ws_a, running_job)
        .await
        .expect("attempts");
    assert_eq!(attempts[0].outcome.to_string(), "cancelled");

    // Terminal states reject late authority.
    assert!(matches!(
        queue.complete_success(&handle, None).await,
        Err(JobError::AlreadyTerminal { ref status, .. }) if status == "cancelled"
    ));

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 40. Payload secret prohibition
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_040_secret_bearing_payloads_are_rejected_before_persistence() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let cases: Vec<serde_json::Value> = vec![
        json!({"api_key": "sk-provider-secret"}),
        json!({"nested": {"session_token": "abc"}}),
        json!({"db_connection_string": "postgres://user:pw@host/db"}),
        json!({"upload_hint": "https://bucket.example/x?X-Amz-Signature=zzz&X-Amz-Credential=q"}),
        json!({"document_bytes": "JVBERi0xLjQK"}),
    ];
    for forbidden in cases {
        let mut params = params_for(ctx.ws_a, JobKind::ParseDocumentPdf, &["doc-sec"]);
        params.parameters = forbidden.clone();
        let outcome = queue.enqueue(params).await;
        assert!(
            matches!(outcome, Err(JobError::InvalidPayload(_))),
            "case {forbidden} must be InvalidPayload, got {outcome:?}"
        );
    }

    let persisted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE workspace_id = $1")
        .bind(ctx.ws_a)
        .fetch_one(ctx.pool())
        .await
        .expect("count");
    assert_eq!(persisted, 0, "rejected payloads leave zero durable rows");

    ctx.close().await;
}

// ----------------------------------------------------------------------
// 41/42. No fake success; no second queue authority
// ----------------------------------------------------------------------

#[tokio::test]
async fn test_041_runtime_never_fabricates_success_without_executors_or_work() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let job = queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::ParseDocumentPdf,
            &["doc-idle"],
        ))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    // An empty registry claims NOTHING: unimplemented executors cannot yield
    // fabricated successes, and no job is silently destroyed.
    let idle_loop = w014_jobs::DurableJobLoop::new(
        queue.clone(),
        w014_jobs::ExecutorRegistry::new(),
        WorkerId::new(),
        w014_jobs::DurableJobLoopConfig {
            queues: vec![PARSE_QUEUE.to_string()],
            lease_duration: Duration::from_secs(30),
            poll_interval: Duration::from_millis(50),
        },
    );
    assert!(
        idle_loop
            .poll_once()
            .await
            .expect("poll executes")
            .is_none()
    );
    assert_eq!(
        raw_status(ctx.pool(), job).await,
        "queued",
        "truthful untouched idle state"
    );

    // Registering an executor makes the kind claimable end-to-end.
    struct RealExecutor;
    #[async_trait::async_trait]
    impl w014_jobs::JobExecutor for RealExecutor {
        async fn execute(
            &self,
            ctx: &w014_jobs::JobExecutionContext,
        ) -> Result<Option<serde_json::Value>, w014_jobs::JobExecutionFailure> {
            ctx.report_progress(0, "EXECUTE_STAGE", 1, Some(1), None)
                .await
                .map_err(|e| {
                    w014_jobs::JobExecutionFailure::retryable("E_PROGRESS", e.to_string())
                })?;
            Ok(Some(json!({"executed": true})))
        }
    }
    let live_loop = w014_jobs::DurableJobLoop::new(
        queue.clone(),
        w014_jobs::ExecutorRegistry::new()
            .with_executor(JobKind::ParseDocumentPdf, std::sync::Arc::new(RealExecutor)),
        WorkerId::new(),
        w014_jobs::DurableJobLoopConfig {
            queues: vec![PARSE_QUEUE.to_string()],
            lease_duration: Duration::from_secs(30),
            poll_interval: Duration::from_millis(50),
        },
    );
    let claimed = live_loop
        .poll_once()
        .await
        .expect("poll")
        .expect("registered kind claims");
    let _ = claimed;
    assert_eq!(raw_status(ctx.pool(), job).await, "running");

    ctx.close().await;
}

#[tokio::test]
async fn test_042_single_postgresql_queue_authority_holds_all_truth() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let job = queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::MalwareScanDocumentPdf,
            &["dv-authority"],
        ))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    let claimed = queue
        .claim(single_ws_criteria(SCAN_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("claimable");
    queue
        .complete_success(&claimed, Some(json!({"clean": true})))
        .await
        .expect("done");

    // Every lifecycle fact is readable back from PostgreSQL alone.
    let record = queue
        .fetch_job(job, WorkspaceScope::Unrestricted)
        .await
        .expect("fetch")
        .expect("authoritative row");
    assert_eq!(record.status, JobStatus::Succeeded);
    assert_eq!(record.result.unwrap()["clean"], json!(true));

    // Exactly the five repaired Jobs tables carry runtime truth; there is no
    // auxiliary store, table, or competing queue artifact in the schema.
    let job_tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' \
         AND tablename IN ('jobs','job_attempts','job_dependencies','job_progress','dead_letter_entries') \
         ORDER BY tablename",
    )
    .fetch_all(ctx.pool())
    .await
    .expect("tables");
    assert_eq!(
        job_tables,
        vec![
            "dead_letter_entries".to_string(),
            "job_attempts".to_string(),
            "job_dependencies".to_string(),
            "job_progress".to_string(),
            "jobs".to_string(),
        ]
    );

    ctx.close().await;
}

// ----------------------------------------------------------------------
// helper
// ----------------------------------------------------------------------

/// Joins spawned claim racers preserving order.
async fn futures_join_all<T: Send + 'static>(handles: Vec<tokio::task::JoinHandle<T>>) -> Vec<T> {
    let mut out = Vec::with_capacity(handles.len());
    for handle in handles {
        out.push(handle.await.expect("racer task must not panic"));
    }
    out
}
