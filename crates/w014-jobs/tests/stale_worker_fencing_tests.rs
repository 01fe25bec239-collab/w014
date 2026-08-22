//! Mandatory stale-worker fencing proofs against real PostgreSQL.
//!
//! Frozen invariant under proof: worker W1 claims execution authority N ->
//! lease expires -> worker W2 obtains newer authority N+1 -> W1 returns late
//! -> W1 MUST NOT mutate authoritative current truth. Also proves stale
//! heartbeat / failure / progress are rejected where applicable.

mod common;

use common::*;
use serde_json::json;
use uuid::Uuid;
use w014_jobs::{FailureKind, JobError, JobKind, WorkerId};

/// Full authoritative-truth snapshot for zero-mutation assertions.
async fn truth_snapshot(pool: &sqlx::PgPool, job_id: Uuid) -> (String, i32) {
    let status: String = sqlx::query_scalar("SELECT status FROM jobs WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(pool)
        .await
        .expect("job exists");
    let row_version: i32 = sqlx::query_scalar("SELECT row_version FROM jobs WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(pool)
        .await
        .expect("job exists");
    (status, row_version)
}

#[tokio::test]
async fn test_mandatory_stale_worker_may_not_commit_truth_after_supersession() {
    let ctx = provision().await;
    let queue = ctx.queue();

    // ------------------------------------------------------------------
    // Setup: one durable parse job.
    // ------------------------------------------------------------------
    let job = queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::ParseDocumentPdf,
            &["doc-fence"],
        ))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    // ------------------------------------------------------------------
    // Step 1: worker 1 claims attempt/generation N.
    // ------------------------------------------------------------------
    let w1 = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim executes")
        .expect("w1 authority");
    assert_eq!(w1.attempt_number, 1);
    assert_eq!(w1.lease_generation, 1);
    let gen_n = w1.lease_generation;
    let token_n = w1.lease_token;

    // W1 performs legal progress while authoritative.
    queue
        .record_progress(&w1, 0, "SCAN_START", 0, Some(1), None)
        .await
        .expect("progress N");

    // ------------------------------------------------------------------
    // Step 2: worker 1's lease expires (deterministic DB manipulation).
    // ------------------------------------------------------------------
    force_expire_lease(ctx.pool(), job).await;

    // ------------------------------------------------------------------
    // Step 3: worker 2 obtains newer valid attempt/generation N+1.
    // ------------------------------------------------------------------
    let w2 = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim executes")
        .expect("w2 newer authority");
    assert_eq!(w2.attempt_number, 2, "attempt advanced");
    assert_eq!(w2.lease_generation, gen_n + 1, "generation fence advanced");
    assert_ne!(w2.lease_token, token_n, "fresh lease token");

    let superseded_state = lease_state(ctx.pool(), job).await;
    assert_eq!(superseded_state.status, "running");
    assert_eq!(
        superseded_state.lease_holder.as_deref(),
        Some(w2.worker_id.as_str())
    );
    assert_eq!(superseded_state.attempt_count, 2);

    // Snapshot of current truth before W1 returns late.
    let snapshot_before = truth_snapshot(ctx.pool(), job).await;

    // ------------------------------------------------------------------
    // Step 4/5: W1 returns late and attempts authoritative completion.
    // Completion MUST be rejected with zero current-authoritative mutation.
    // ------------------------------------------------------------------

    // Stale SUCCESS completion rejected; W2's result must never be overwritten.
    let stale_success = queue
        .complete_success(&w1, Some(json!({"pages_parsed": 42, "by": "stale-w1"})))
        .await;
    assert!(
        matches!(&stale_success, Err(JobError::LeaseLost(_))),
        "stale success completion must be LeaseLost-rejected, got {stale_success:?}"
    );

    // Stale FAILURE completion rejected: a stale worker cannot schedule a
    // retry, fail current truth, or dead-letter the newer generation.
    let stale_failure = queue
        .complete_failure(&w1, "E_LATE", "late failure", FailureKind::Retryable)
        .await;
    assert!(
        matches!(&stale_failure, Err(JobError::LeaseLost(_))),
        "stale failure must be LeaseLost-rejected, got {stale_failure:?}"
    );
    let poison_failure = queue
        .complete_failure(&w1, "E_POISON_LATE", "late poison", FailureKind::Poison)
        .await;
    assert!(matches!(poison_failure, Err(JobError::LeaseLost(_))));

    // Stale HEARTBEAT rejected: cannot resurrect or extend superseded authority.
    let stale_heartbeat = queue.heartbeat(&w1, 300).await;
    assert!(matches!(stale_heartbeat, Err(JobError::LeaseLost(_))));

    // Stale PROGRESS rejected: no new durable events from the dead generation.
    let stale_progress = queue
        .record_progress(&w1, 1, "LATE_STAGE", 1, Some(1), None)
        .await;
    assert!(matches!(stale_progress, Err(JobError::LeaseLost(_))));
    let seq_one_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM job_progress WHERE job_id = $1 AND sequence = 1")
            .bind(job)
            .fetch_one(ctx.pool())
            .await
            .expect("count");
    assert_eq!(seq_one_rows, 0, "stale progress inserted zero rows");

    // ------------------------------------------------------------------
    // Step 6: W1 changed ZERO current authoritative truth.
    // ------------------------------------------------------------------
    let snapshot_after = truth_snapshot(ctx.pool(), job).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "every late W1 mutation attempt must affect zero rows"
    );

    let state = lease_state(ctx.pool(), job).await;
    assert_eq!(state.status, "running");
    assert_eq!(
        state.lease_holder.as_deref(),
        Some(w2.worker_id.as_str()),
        "W2 remains authoritative"
    );
    assert_eq!(state.lease_token, Some(w2.lease_token));
    assert_eq!(state.lease_generation, gen_n + 1);
    assert_eq!(state.attempt_count, 2);

    let stored_result: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT result FROM jobs WHERE job_id = $1")
            .bind(job)
            .fetch_one(ctx.pool())
            .await
            .expect("result read");
    assert_eq!(stored_result, None, "W1's fabricated result never landed");

    let attempts = queue
        .attempts_for_job(ctx.ws_a, job)
        .await
        .expect("attempts");
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].outcome.to_string(), "lease_expired");
    assert_eq!(attempts[1].outcome.to_string(), "running");
    assert_eq!(
        attempts[1].error_code, None,
        "no failure recorded by stale worker"
    );

    // ------------------------------------------------------------------
    // Step 7: W2 remains authoritative and completes successfully.
    // ------------------------------------------------------------------
    queue
        .heartbeat(&w2, 60)
        .await
        .expect("current authority heartbeat still valid");
    queue
        .record_progress(&w2, 1, "RESUME_STAGE", 1, Some(1), None)
        .await
        .expect("W2 progress");
    queue
        .complete_success(&w2, Some(json!({"pages_parsed": 7, "by": "current-w2"})))
        .await
        .expect("valid completion succeeds");

    assert_eq!(raw_status(ctx.pool(), job).await, "succeeded");
    let final_result: serde_json::Value =
        sqlx::query_scalar("SELECT result FROM jobs WHERE job_id = $1")
            .bind(job)
            .fetch_one(ctx.pool())
            .await
            .expect("final result");
    assert_eq!(
        final_result["by"],
        json!("current-w2"),
        "only W2 committed truth"
    );

    let finalized_attempts = queue
        .attempts_for_job(ctx.ws_a, job)
        .await
        .expect("attempts");
    assert_eq!(finalized_attempts[0].outcome.to_string(), "lease_expired");
    assert_eq!(finalized_attempts[1].outcome.to_string(), "succeeded");

    ctx.close().await;
}

#[tokio::test]
async fn test_stale_worker_cannot_dead_letter_or_reopen_a_newer_generation() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let job = queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::ParseDocumentPdf,
            &["doc-dlq-fence"],
        ))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    let w1 = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("authority N");

    force_expire_lease(ctx.pool(), job).await;

    // W2 reclaims and finishes successfully first.
    let w2 = queue
        .claim(single_ws_criteria(PARSE_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("authority N+1");
    queue.complete_success(&w2, None).await.expect("success");

    // Late W1 attempts to poison/dead-letter the NEWER (now terminal) state:
    // typed rejection, and no dead-letter linkage may appear.
    let late_poison = queue
        .complete_failure(&w1, "E_STALE_POISON", "late poison", FailureKind::Poison)
        .await;
    assert!(
        matches!(
            &late_poison,
            Err(JobError::AlreadyTerminal { status, .. }) if status == "succeeded"
        ),
        "terminal protection must outrank stale authority, got {late_poison:?}"
    );
    assert!(
        queue
            .dead_letter_entry(ctx.ws_a, job)
            .await
            .expect("dlq")
            .is_none()
    );
    assert_eq!(raw_status(ctx.pool(), job).await, "succeeded");

    ctx.close().await;
}

#[tokio::test]
async fn test_double_claim_of_same_authority_cannot_double_complete() {
    let ctx = provision().await;
    let queue = ctx.queue();

    let job = queue
        .enqueue(params_for(
            ctx.ws_a,
            JobKind::MalwareScanDocumentPdf,
            &["dv-double"],
        ))
        .await
        .expect("enqueue")
        .record()
        .job_id;

    let handle = queue
        .claim(single_ws_criteria(SCAN_QUEUE, ctx.ws_a), WorkerId::new())
        .await
        .expect("claim")
        .expect("authority");

    // The same handle completing twice yields exactly one logical effect.
    queue
        .complete_success(&handle, Some(json!({"clean": true})))
        .await
        .expect("first success");
    let second = queue
        .complete_success(&handle, Some(json!({"clean": false})))
        .await;
    assert!(matches!(second, Err(JobError::AlreadyTerminal { .. })));

    let result: serde_json::Value = sqlx::query_scalar("SELECT result FROM jobs WHERE job_id = $1")
        .bind(job)
        .fetch_one(ctx.pool())
        .await
        .expect("result");
    assert_eq!(
        result["clean"],
        json!(true),
        "second logical effect impossible"
    );

    ctx.close().await;
}
