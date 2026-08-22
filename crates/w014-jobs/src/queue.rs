//! Authoritative PostgreSQL durable job queue (W2 minimum real runtime).
//!
//! All lifecycle truth lives in PostgreSQL (`jobs`, `job_attempts`,
//! `job_dependencies`, `job_progress`, `dead_letter_entries` from the accepted
//! M002R migration). There is no second queue authority: process-local
//! structures are non-authoritative execution helpers only.
//!
//! Fencing invariant: a worker may mutate current authoritative truth only
//! while it holds the current valid execution authority — matching lease
//! owner/token, current attempt number, current generation fence, unexpired
//! lease, and `status = 'running'`. Stale workers receive typed rejections
//! and mutate zero authoritative rows.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row, postgres::PgConnection};
use uuid::Uuid;

use w014_persistence::set_session_workspace_id;

use crate::error::JobError;
use crate::identity::WorkerId;
use crate::job_identity::CanonicalJobIdentity;
use crate::kind::JobKind;
use crate::models::{
    AttemptRecord, CancellationOutcome, ClaimCriteria, ClaimedJob, DeadLetterRecord,
    EnqueueOutcome, EnqueueParams, FailureKind, FailureResolution, JobRecord, ProgressEvent,
    WorkspaceScope, backoff_delay_secs_after,
};
use crate::payload::JobPayload;
use crate::status::{AttemptOutcome, JobStatus};

/// Authoritative PostgreSQL-backed durable job queue.
#[derive(Clone)]
pub struct PgJobQueue {
    pool: PgPool,
}

/// Full projection of one jobs row by primary key (static SQL for sqlx 0.9).
const SELECT_JOB_BY_ID: &str = "SELECT job_id, workspace_id, queue_name, job_type, status, \
     priority, payload, result, error_details, idempotency_key, correlation_id, \
     cancellation_requested, lease_holder, lease_token, lease_generation, lease_expires_at, \
     last_heartbeat_at, attempt_count, max_attempts, not_before, created_at, started_at, \
     completed_at FROM jobs WHERE job_id = $1";

/// Full projection of one jobs row by canonical idempotency key.
const SELECT_JOB_BY_KEY: &str = "SELECT job_id, workspace_id, queue_name, job_type, status, \
     priority, payload, result, error_details, idempotency_key, correlation_id, \
     cancellation_requested, lease_holder, lease_token, lease_generation, lease_expires_at, \
     last_heartbeat_at, attempt_count, max_attempts, not_before, created_at, started_at, \
     completed_at FROM jobs WHERE idempotency_key = $1 LIMIT 1";

impl PgJobQueue {
    /// Creates a new `PgJobQueue` backed by the provided PostgreSQL pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns a reference to the underlying connection pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // ------------------------------------------------------------------
    // ENQUEUE
    // ------------------------------------------------------------------

    /// Durably enqueues one logical W2 job against the repaired `jobs` table.
    ///
    /// Guarantees:
    /// - canonical frozen identity (SHA-256 over the frozen component set);
    /// - atomic single-transaction create performing `requested -> queued`;
    /// - duplicate enqueue is idempotent (existing logical job is returned);
    /// - rollback leaves no phantom authoritative work;
    /// - dependency edges are validated same-workspace at creation time.
    pub async fn enqueue(&self, params: EnqueueParams) -> Result<EnqueueOutcome, JobError> {
        if !(1..=32).contains(&params.max_attempts) {
            return Err(JobError::Configuration(format!(
                "max_attempts {} outside bounded range 1..=32",
                params.max_attempts
            )));
        }

        let envelope = JobPayload::validate(&serde_json::json!({
            "payload_contract_version": params.payload_contract_version,
            "producer_version": params.producer_version,
            "immutable_targets": params.immutable_targets.clone(),
            "dependency_hash": params.dependency_hash,
            "parameters": params.parameters,
        }))?;

        let identity = CanonicalJobIdentity::new(
            params.kind.as_str(),
            params.workspace_id,
            envelope.immutable_targets.clone(),
            envelope.dependency_hash.clone(),
            envelope.payload_contract_version,
            &envelope.producer_version,
        );
        let idempotency_key = identity.idempotency_key();
        let payload_json = envelope.to_json();

        let mut tx = self.pool.begin().await?;
        apply_scope(&mut tx, WorkspaceScope::Single(params.workspace_id)).await?;

        // Idempotency: any prior logical job with this key wins, whatever its
        // current status (cancelled identities are preserved, never replayed).
        if let Some(existing) = fetch_job_by_key_tx(&mut tx, &idempotency_key).await? {
            tx.commit().await?;
            return Ok(EnqueueOutcome::Existing(existing));
        }

        // Dependencies must reference existing jobs in the SAME workspace.
        if !params.depends_on.is_empty() {
            let found: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM jobs WHERE job_id = ANY($1) AND workspace_id = $2",
            )
            .bind(&params.depends_on)
            .bind(params.workspace_id)
            .fetch_one(&mut *tx)
            .await?;
            if found != params.depends_on.len() as i64 {
                return Err(JobError::WorkspaceViolation(format!(
                    "{} of {} dependency predecessors are missing from the target workspace",
                    params.depends_on.len() - usize::try_from(found).unwrap_or_default(),
                    params.depends_on.len()
                )));
            }
        }

        let inserted = sqlx::query(
            "INSERT INTO jobs \
                 (workspace_id, queue_name, job_type, status, priority, payload, \
                  idempotency_key, correlation_id, max_attempts, backoff_max_secs) \
             VALUES ($1, $2, $3, 'requested', $4, $5, $6, $7, $8, $9) \
             RETURNING job_id",
        )
        .bind(params.workspace_id)
        .bind(params.kind.default_queue())
        .bind(params.kind.as_str())
        .bind(params.priority)
        .bind(&payload_json)
        .bind(&idempotency_key)
        .bind(params.correlation_id.clone())
        .bind(params.max_attempts)
        .bind(crate::models::FROZEN_BACKOFF_MAX_SECS)
        .fetch_one(&mut *tx)
        .await;

        let new_job_id: Uuid = match inserted {
            Ok(row) => row.get("job_id"),
            Err(err) if is_unique_violation_on(&err, "uq_jobs_idempotency_key") => {
                // Concurrent enqueue of an identical identity: converge on the
                // committed winner instead of surfacing a constraint error.
                tx.rollback().await?;
                let mut retry_tx = self.pool.begin().await?;
                apply_scope(&mut retry_tx, WorkspaceScope::Single(params.workspace_id)).await?;
                if let Some(existing) = fetch_job_by_key_tx(&mut retry_tx, &idempotency_key).await?
                {
                    retry_tx.commit().await?;
                    return Ok(EnqueueOutcome::Existing(existing));
                }
                return Err(JobError::Database(
                    "enqueue lost an idempotency race without a visible winner".to_string(),
                ));
            }
            Err(err) => return Err(err.into()),
        };

        // Frozen enqueue transition: requested -> queued, atomically.
        let queued_row = sqlx::query(
            "UPDATE jobs SET status = 'queued', not_before = clock_timestamp(), \
                    row_version = row_version + 1 \
             WHERE job_id = $1 AND status = 'requested'",
        )
        .bind(new_job_id)
        .execute(&mut *tx)
        .await?;
        if queued_row.rows_affected() != 1 {
            return Err(JobError::Database(
                "enqueue failed to transition requested -> queued".to_string(),
            ));
        }

        for predecessor in &params.depends_on {
            sqlx::query("INSERT INTO job_dependencies (job_id, depends_on_job_id) VALUES ($1, $2)")
                .bind(new_job_id)
                .bind(predecessor)
                .execute(&mut *tx)
                .await?;
        }

        let created = fetch_job_by_id_tx(&mut tx, new_job_id)
            .await?
            .ok_or_else(|| {
                JobError::Database("inserted job row vanished inside enqueue".to_string())
            })?;

        tx.commit().await?;
        Ok(EnqueueOutcome::Created(created))
    }

    // ------------------------------------------------------------------
    // CLAIM
    // ------------------------------------------------------------------

    /// Attempts to claim one claimable job using `FOR UPDATE SKIP LOCKED`.
    ///
    /// The claim transaction is SHORT: only bounded database work — select and
    /// lock the candidate, verify dependencies, advance attempt identity,
    /// establish lease + generation fence, append the running attempt-history
    /// row, commit. Executors run strictly after commit; no long work ever
    /// occurs under the claim lock.
    ///
    /// Expired-running rows with budget remaining are legally reclaimed (prior
    /// open attempt finalized as `lease_expired`). Expired-running rows at the
    /// frozen attempt boundary dead-letter. Two racing workers can never both
    /// obtain currently valid execution authority for one job.
    pub async fn claim(
        &self,
        criteria: ClaimCriteria,
        worker_id: WorkerId,
    ) -> Result<Option<ClaimedJob>, JobError> {
        let worker_str = worker_id.to_string();

        let mut tx = self.pool.begin().await?;
        apply_scope(&mut tx, criteria.workspace).await?;

        let kind_filter: Option<Vec<String>> = if criteria.kinds.is_empty() {
            None
        } else {
            Some(
                criteria
                    .kinds
                    .iter()
                    .map(|k| k.as_str().to_string())
                    .collect(),
            )
        };
        let queues: Vec<String> = criteria.queues.clone();

        let candidate = sqlx::query(
            "SELECT job_id FROM jobs \
             WHERE queue_name = ANY($1) \
               AND ($2::text[] IS NULL OR job_type = ANY($2)) \
               AND ( \
                     (status IN ('queued','retryable') AND not_before <= clock_timestamp() \
                      AND cancellation_requested = false AND attempt_count < max_attempts) \
                  OR (status = 'running' AND lease_expires_at IS NOT NULL \
                      AND lease_expires_at <= clock_timestamp()) \
                   ) \
               AND NOT EXISTS ( \
                    SELECT 1 FROM job_dependencies d \
                    JOIN jobs p ON p.job_id = d.depends_on_job_id \
                    WHERE d.job_id = jobs.job_id AND p.status <> 'succeeded' \
                   ) \
             ORDER BY priority DESC, not_before ASC, created_at ASC \
             LIMIT 1 \
             FOR UPDATE SKIP LOCKED",
        )
        .bind(&queues)
        .bind(kind_filter)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(candidate_row) = candidate else {
            tx.commit().await?;
            return Ok(None);
        };
        let job_id: Uuid = candidate_row.get("job_id");

        // Re-read the locked candidate's full state to drive dispatch.
        let locked = sqlx::query(SELECT_JOB_BY_ID)
            .bind(job_id)
            .fetch_one(&mut *tx)
            .await?;
        let prev_status: String = locked.get("status");
        let attempt_count: i32 = locked.get("attempt_count");
        let max_attempts: i32 = locked.get("max_attempts");
        let was_running = prev_status == JobStatus::Running.as_str();

        // Dispatch cleanup paths that consume the candidate without issuing
        // execution authority. Both hold the row lock; both stay bounded.
        if was_running && locked.get::<bool, _>("cancellation_requested") {
            finalize_cancelled_expired(&mut tx, &handle_from_locked(&locked)).await?;
            tx.commit().await?;
            return Ok(None);
        }
        if was_running && attempt_count >= max_attempts {
            dead_letter_locked(
                &mut tx,
                &handle_from_locked(&locked),
                "lease_expired_retry_boundary",
                "LEASE_EXPIRED_FINAL_ATTEMPT",
                "lease expired after the final attempt; no reclaim budget remains",
                AttemptOutcome::LeaseExpired,
                false,
            )
            .await?;
            tx.commit().await?;
            return Ok(None);
        }
        if was_running {
            // Reclaim: preserve history by recording the frozen `lease_expired`
            // terminal outcome on the abandoned open attempt.
            finalize_open_attempt(
                &mut tx,
                job_id,
                AttemptOutcome::LeaseExpired,
                Some("LEASE_EXPIRED"),
                None,
            )
            .await?;
        }

        let new_attempt_number = attempt_count + 1;
        let lease_token = Uuid::new_v4();
        let lease_secs =
            i32::try_from(criteria.lease_duration.as_secs().min(86_400)).unwrap_or(86_400);

        let updated = sqlx::query(
            "UPDATE jobs SET \
                    status = 'running', \
                    lease_holder = $2, \
                    lease_token = $3, \
                    lease_generation = lease_generation + 1, \
                    lease_expires_at = clock_timestamp() + make_interval(secs => $4), \
                    last_heartbeat_at = clock_timestamp(), \
                    attempt_count = $5, \
                    started_at = COALESCE(started_at, clock_timestamp()), \
                    row_version = row_version + 1 \
             WHERE job_id = $1 \
             RETURNING lease_generation, workspace_id, queue_name, job_type, payload, lease_expires_at",
        )
        .bind(job_id)
        .bind(&worker_str)
        .bind(lease_token)
        .bind(lease_secs)
        .bind(new_attempt_number)
        .fetch_one(&mut *tx)
        .await?;

        let claimed = ClaimedJob {
            job_id,
            workspace_id: updated.get("workspace_id"),
            queue_name: updated.get("queue_name"),
            kind: JobKind::parse(updated.get::<String, _>("job_type").as_str())?,
            attempt_number: new_attempt_number,
            max_attempts,
            worker_id: worker_str,
            lease_token,
            lease_generation: updated.get("lease_generation"),
            lease_expires_at: updated.get("lease_expires_at"),
            payload: updated.get("payload"),
        };

        sqlx::query(
            "INSERT INTO job_attempts (job_id, attempt_number, worker_id) VALUES ($1, $2, $3)",
        )
        .bind(job_id)
        .bind(new_attempt_number)
        .bind(&claimed.worker_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some(claimed))
    }

    // ------------------------------------------------------------------
    // HEARTBEAT
    // ------------------------------------------------------------------

    /// Renews the lease; succeeds ONLY for the current valid execution authority.
    ///
    /// Stale/superseded/expired heartbeats affect zero authoritative rows and
    /// return typed errors; they can never resurrect terminal or superseded
    /// state.
    pub async fn heartbeat(
        &self,
        handle: &ClaimedJob,
        extend_secs: u32,
    ) -> Result<DateTime<Utc>, JobError> {
        let mut tx = self.pool.begin().await?;
        apply_scope(&mut tx, WorkspaceScope::Single(handle.workspace_id)).await?;

        let renewed = sqlx::query(
            "UPDATE jobs SET lease_expires_at = clock_timestamp() + make_interval(secs => $1), \
                    last_heartbeat_at = clock_timestamp(), row_version = row_version + 1 \
             WHERE job_id = $2 AND status = 'running' AND lease_holder = $3 \
               AND lease_token = $4 AND lease_generation = $5 AND attempt_count = $6 \
               AND lease_expires_at > clock_timestamp() \
             RETURNING lease_expires_at",
        )
        .bind(i32::try_from(extend_secs.min(86_400)).unwrap_or(86_400))
        .bind(handle.job_id)
        .bind(&handle.worker_id)
        .bind(handle.lease_token)
        .bind(handle.lease_generation)
        .bind(handle.attempt_number)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = renewed else {
            return Err(diagnose_authority_failure(&mut tx, handle, "heartbeat").await);
        };

        let expires_at: DateTime<Utc> = row.get("lease_expires_at");
        tx.commit().await?;
        Ok(expires_at)
    }

    // ------------------------------------------------------------------
    // SAFE SUCCESS COMPLETION
    // ------------------------------------------------------------------

    /// Atomically commits `running -> succeeded`, fenced by current valid
    /// execution authority.
    ///
    /// Double completion, expired workers, and superseded generations are all
    /// rejected with zero authoritative effect; terminal state never reopens.
    pub async fn complete_success(
        &self,
        handle: &ClaimedJob,
        result: Option<serde_json::Value>,
    ) -> Result<(), JobError> {
        let mut tx = self.pool.begin().await?;
        apply_scope(&mut tx, WorkspaceScope::Single(handle.workspace_id)).await?;

        let completed = sqlx::query(
            "UPDATE jobs SET status = 'succeeded', result = $1, completed_at = clock_timestamp(), \
                    lease_holder = NULL, lease_token = NULL, lease_expires_at = NULL, \
                    last_heartbeat_at = NULL, row_version = row_version + 1 \
             WHERE job_id = $2 AND status = 'running' AND lease_holder = $3 \
               AND lease_token = $4 AND lease_generation = $5 AND attempt_count = $6 \
               AND lease_expires_at > clock_timestamp()",
        )
        .bind(result)
        .bind(handle.job_id)
        .bind(&handle.worker_id)
        .bind(handle.lease_token)
        .bind(handle.lease_generation)
        .bind(handle.attempt_number)
        .execute(&mut *tx)
        .await?;

        if completed.rows_affected() != 1 {
            return Err(diagnose_authority_failure(&mut tx, handle, "success completion").await);
        }

        finalize_open_attempt(
            &mut tx,
            handle.job_id,
            AttemptOutcome::Succeeded,
            None,
            None,
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // SAFE FAILURE COMPLETION
    // ------------------------------------------------------------------

    /// Records an authoritative failure from the CURRENT valid execution authority.
    ///
    /// - [`FailureKind::Retryable`]: `running -> retryable` with a frozen
    ///   bounded-backoff delay; at the frozen attempt boundary the job
    ///   dead-letters instead (`retry_exhausted`).
    /// - [`FailureKind::Terminal`]: `running -> failed`; never retried.
    /// - [`FailureKind::Poison`]: dead-letter immediately without consuming
    ///   further retries.
    ///
    /// Stale failures are rejected with zero authoritative effect: a stale
    /// worker cannot schedule retries, fail current truth, or dead-letter a
    /// newer generation.
    pub async fn complete_failure(
        &self,
        handle: &ClaimedJob,
        error_code: &str,
        error_detail: &str,
        kind: FailureKind,
    ) -> Result<FailureResolution, JobError> {
        if error_code.trim().is_empty() || error_code.len() > 128 {
            return Err(JobError::Configuration(
                "error_code must be non-empty and <=128 chars".to_string(),
            ));
        }
        let redacted_detail = JobPayload::redact_error_detail(error_detail);

        let mut tx = self.pool.begin().await?;
        apply_scope(&mut tx, WorkspaceScope::Single(handle.workspace_id)).await?;

        match kind {
            FailureKind::Retryable => {
                match backoff_delay_secs_after(handle.attempt_number, handle.max_attempts) {
                    Some(delay_secs) => {
                        let scheduled = sqlx::query(
                            "UPDATE jobs SET status = 'retryable', \
                                    error_details = $1, \
                                    lease_holder = NULL, lease_token = NULL, \
                                    lease_expires_at = NULL, last_heartbeat_at = NULL, \
                                    not_before = clock_timestamp() \
                                        + make_interval(secs => LEAST($2, backoff_max_secs)), \
                                    row_version = row_version + 1 \
                             WHERE job_id = $3 AND status = 'running' AND lease_holder = $4 \
                               AND lease_token = $5 AND lease_generation = $6 \
                               AND attempt_count = $7 AND lease_expires_at > clock_timestamp() \
                             RETURNING not_before",
                        )
                        .bind(failure_details_json(error_code, &redacted_detail))
                        .bind(i32::try_from(delay_secs).unwrap_or(86_400))
                        .bind(handle.job_id)
                        .bind(&handle.worker_id)
                        .bind(handle.lease_token)
                        .bind(handle.lease_generation)
                        .bind(handle.attempt_number)
                        .fetch_optional(&mut *tx)
                        .await?;

                        let Some(row) = scheduled else {
                            return Err(diagnose_authority_failure(
                                &mut tx,
                                handle,
                                "retryable failure recording",
                            )
                            .await);
                        };

                        finalize_open_attempt(
                            &mut tx,
                            handle.job_id,
                            AttemptOutcome::RetryableFailed,
                            Some(error_code),
                            Some(redacted_detail.as_str()),
                        )
                        .await?;

                        let not_before: DateTime<Utc> = row.get("not_before");
                        tx.commit().await?;
                        Ok(FailureResolution::RetryScheduled {
                            not_before,
                            delay_secs,
                        })
                    }
                    None => {
                        // Frozen boundary: the retry budget is exhausted.
                        dead_letter_locked(
                            &mut tx,
                            handle,
                            "retry_exhausted",
                            error_code,
                            redacted_detail.as_str(),
                            AttemptOutcome::RetryableFailed,
                            true,
                        )
                        .await?;
                        tx.commit().await?;
                        Ok(FailureResolution::DeadLettered)
                    }
                }
            }
            FailureKind::Terminal => {
                let failed = sqlx::query(
                    "UPDATE jobs SET status = 'failed', completed_at = clock_timestamp(), \
                            error_details = $1, \
                            lease_holder = NULL, lease_token = NULL, \
                            lease_expires_at = NULL, last_heartbeat_at = NULL, \
                            row_version = row_version + 1 \
                     WHERE job_id = $2 AND status = 'running' AND lease_holder = $3 \
                       AND lease_token = $4 AND lease_generation = $5 AND attempt_count = $6 \
                       AND lease_expires_at > clock_timestamp()",
                )
                .bind(failure_details_json(error_code, &redacted_detail))
                .bind(handle.job_id)
                .bind(&handle.worker_id)
                .bind(handle.lease_token)
                .bind(handle.lease_generation)
                .bind(handle.attempt_number)
                .execute(&mut *tx)
                .await?;

                if failed.rows_affected() != 1 {
                    return Err(diagnose_authority_failure(
                        &mut tx,
                        handle,
                        "terminal failure recording",
                    )
                    .await);
                }

                finalize_open_attempt(
                    &mut tx,
                    handle.job_id,
                    AttemptOutcome::TerminalFailed,
                    Some(error_code),
                    Some(redacted_detail.as_str()),
                )
                .await?;

                tx.commit().await?;
                Ok(FailureResolution::TerminalFailed)
            }
            FailureKind::Poison => {
                dead_letter_locked(
                    &mut tx,
                    handle,
                    &format!("poison:{error_code}"),
                    error_code,
                    redacted_detail.as_str(),
                    AttemptOutcome::TerminalFailed,
                    true,
                )
                .await?;
                tx.commit().await?;
                Ok(FailureResolution::DeadLettered)
            }
        }
    }

    // ------------------------------------------------------------------
    // DEAD LETTER INSPECTION
    // ------------------------------------------------------------------

    /// Reads the durable dead-letter linkage for one job, if present.
    pub async fn dead_letter_entry(
        &self,
        workspace_id: Uuid,
        job_id: Uuid,
    ) -> Result<Option<DeadLetterRecord>, JobError> {
        let mut tx = self.pool.begin().await?;
        apply_scope(&mut tx, WorkspaceScope::Single(workspace_id)).await?;

        let entry = sqlx::query(
            "SELECT dead_letter_entry_id, job_id, queue_name, job_type, failed_at, \
                    attempt_count, failure_reason, error_details \
             FROM dead_letter_entries WHERE job_id = $1",
        )
        .bind(job_id)
        .fetch_optional(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(entry.map(|row| DeadLetterRecord {
            dead_letter_entry_id: row.get("dead_letter_entry_id"),
            job_id: row.get("job_id"),
            queue_name: row.get("queue_name"),
            job_type: row.get("job_type"),
            failed_at: row.get("failed_at"),
            attempt_count: row.get("attempt_count"),
            failure_reason: row.get("failure_reason"),
            error_details: row.get("error_details"),
        }))
    }

    // ------------------------------------------------------------------
    // PROGRESS EVENTS
    // ------------------------------------------------------------------

    /// Appends one durable stage-level progress event (INSERT ONLY).
    ///
    /// Gated by current valid execution authority; sequences must be strictly
    /// monotonic per job (duplicates rejected); progress can never bypass the
    /// completion fence because it never alters `jobs.status`.
    pub async fn record_progress(
        &self,
        handle: &ClaimedJob,
        sequence: i32,
        stage_code: &str,
        current: i64,
        total: Option<i64>,
        message_code: Option<&str>,
    ) -> Result<ProgressEvent, JobError> {
        if stage_code.trim().is_empty() || stage_code.len() > 128 {
            return Err(JobError::Configuration(
                "stage_code must be non-empty and <=128 chars".to_string(),
            ));
        }
        if current < 0 {
            return Err(JobError::InvalidPayload(
                "progress current must be >= 0".to_string(),
            ));
        }
        if total.is_some_and(|t| t < current) {
            return Err(JobError::InvalidPayload(
                "progress total must be NULL or >= current".to_string(),
            ));
        }
        if message_code.is_some_and(|m| m.trim().is_empty() || m.len() > 128) {
            return Err(JobError::Configuration(
                "message_code must be non-empty and <=128 chars when present".to_string(),
            ));
        }

        let mut tx = self.pool.begin().await?;
        apply_scope(&mut tx, WorkspaceScope::Single(handle.workspace_id)).await?;

        // Authority gate + per-job serialization lock (also fences against a
        // concurrent completion committing between check and insert).
        let authorized = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM jobs \
             WHERE job_id = $1 AND status = 'running' AND lease_holder = $2 \
               AND lease_token = $3 AND lease_generation = $4 AND attempt_count = $5 \
               AND lease_expires_at > clock_timestamp() \
             FOR UPDATE",
        )
        .bind(handle.job_id)
        .bind(&handle.worker_id)
        .bind(handle.lease_token)
        .bind(handle.lease_generation)
        .bind(handle.attempt_number)
        .fetch_optional(&mut *tx)
        .await?;

        if authorized.is_none() {
            return Err(diagnose_authority_failure(&mut tx, handle, "progress event").await);
        }

        let max_sequence: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(sequence), -1)::int FROM job_progress WHERE job_id = $1",
        )
        .bind(handle.job_id)
        .fetch_one(&mut *tx)
        .await?;

        if sequence <= max_sequence {
            tx.rollback().await?;
            return Err(JobError::ProgressSequenceConflict(format!(
                "sequence {sequence} is not strictly greater than existing max {max_sequence}"
            )));
        }

        let inserted = sqlx::query(
            "INSERT INTO job_progress (job_id, sequence, stage_code, current, total, message_code) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING job_progress_id, created_at",
        )
        .bind(handle.job_id)
        .bind(sequence)
        .bind(stage_code)
        .bind(current)
        .bind(total)
        .bind(message_code)
        .fetch_one(&mut *tx)
        .await?;

        let event = ProgressEvent {
            job_progress_id: inserted.get("job_progress_id"),
            job_id: handle.job_id,
            sequence,
            stage_code: stage_code.to_string(),
            current,
            total,
            message_code: message_code.map(str::to_string),
            created_at: inserted.get("created_at"),
        };

        tx.commit().await?;
        Ok(event)
    }

    // ------------------------------------------------------------------
    // CANCELLATION
    // ------------------------------------------------------------------

    /// Cancels a `queued`/`retryable` job directly, or flags a `running` job.
    ///
    /// Flagged running jobs stop being claimable immediately; once their lease
    /// expires they are deterministically finalized as `cancelled` by the
    /// reclaim path in [`Self::claim`] (open attempt outcome `cancelled`).
    pub async fn cancel(
        &self,
        workspace_id: Uuid,
        job_id: Uuid,
    ) -> Result<CancellationOutcome, JobError> {
        let mut tx = self.pool.begin().await?;
        apply_scope(&mut tx, WorkspaceScope::Single(workspace_id)).await?;

        let direct = sqlx::query(
            "UPDATE jobs SET status = 'cancelled', completed_at = clock_timestamp(), \
                    lease_holder = NULL, lease_token = NULL, lease_expires_at = NULL, \
                    last_heartbeat_at = NULL, row_version = row_version + 1 \
             WHERE job_id = $1 AND status IN ('queued','retryable')",
        )
        .bind(job_id)
        .execute(&mut *tx)
        .await?;

        if direct.rows_affected() == 1 {
            tx.commit().await?;
            return Ok(CancellationOutcome::Cancelled);
        }

        let flagged = sqlx::query(
            "UPDATE jobs SET cancellation_requested = true, row_version = row_version + 1 \
             WHERE job_id = $1 AND status = 'running'",
        )
        .bind(job_id)
        .execute(&mut *tx)
        .await?;

        if flagged.rows_affected() == 1 {
            tx.commit().await?;
            return Ok(CancellationOutcome::CancellationRequested);
        }

        Err(diagnose_terminal_or_missing(&mut tx, job_id, "cancellation").await)
    }

    // ------------------------------------------------------------------
    // INSPECTION HELPERS
    // ------------------------------------------------------------------

    /// Fetches one job record under the given workspace scope.
    pub async fn fetch_job(
        &self,
        job_id: Uuid,
        scope: WorkspaceScope,
    ) -> Result<Option<JobRecord>, JobError> {
        let mut tx = self.pool.begin().await?;
        apply_scope(&mut tx, scope).await?;
        let record = fetch_job_by_id_tx(&mut tx, job_id).await?;
        tx.commit().await?;
        Ok(record)
    }

    /// Lists the append-oriented attempt history of one job, ordered by attempt.
    pub async fn attempts_for_job(
        &self,
        workspace_id: Uuid,
        job_id: Uuid,
    ) -> Result<Vec<AttemptRecord>, JobError> {
        let mut tx = self.pool.begin().await?;
        apply_scope(&mut tx, WorkspaceScope::Single(workspace_id)).await?;

        let rows = sqlx::query(
            "SELECT job_attempt_id, job_id, attempt_number, worker_id, started_at, \
                    completed_at, outcome, error_code, error_detail_redacted \
             FROM job_attempts WHERE job_id = $1 ORDER BY attempt_number ASC",
        )
        .bind(job_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        rows.iter()
            .map(|row| {
                let outcome_text: String = row.get("outcome");
                Ok(AttemptRecord {
                    job_attempt_id: row.get("job_attempt_id"),
                    job_id: row.get("job_id"),
                    attempt_number: row.get("attempt_number"),
                    worker_id: row.get("worker_id"),
                    started_at: row.get("started_at"),
                    completed_at: row.get("completed_at"),
                    outcome: parse_attempt_outcome(&outcome_text)?,
                    error_code: row.get("error_code"),
                    error_detail_redacted: row.get("error_detail_redacted"),
                })
            })
            .collect()
    }

    /// Returns whether cancellation has been requested for one job.
    pub async fn is_cancellation_requested(
        &self,
        workspace_id: Uuid,
        job_id: Uuid,
    ) -> Result<bool, JobError> {
        let record = self
            .fetch_job(job_id, WorkspaceScope::Single(workspace_id))
            .await?
            .ok_or_else(|| JobError::WorkspaceViolation(format!("job {job_id} not visible")))?;
        Ok(record.cancellation_requested)
    }
}

// ----------------------------------------------------------------------
// Private helpers
// ----------------------------------------------------------------------

/// Applies the RLS session scope inside one transaction.
async fn apply_scope(tx: &mut PgConnection, scope: WorkspaceScope) -> Result<(), JobError> {
    match scope {
        WorkspaceScope::Single(workspace_id) => set_session_workspace_id(tx, workspace_id)
            .await
            .map_err(|e| JobError::Database(e.to_string())),
        WorkspaceScope::Unrestricted => Ok(()),
    }
}

fn is_unique_violation_on(err: &sqlx::Error, constraint: &str) -> bool {
    err.as_database_error()
        .map(|db| db.constraint() == Some(constraint))
        .unwrap_or(false)
}

fn parse_attempt_outcome(raw: &str) -> Result<AttemptOutcome, JobError> {
    match raw {
        "running" => Ok(AttemptOutcome::Running),
        "succeeded" => Ok(AttemptOutcome::Succeeded),
        "retryable_failed" => Ok(AttemptOutcome::RetryableFailed),
        "terminal_failed" => Ok(AttemptOutcome::TerminalFailed),
        "cancelled" => Ok(AttemptOutcome::Cancelled),
        "lease_expired" => Ok(AttemptOutcome::LeaseExpired),
        other => Err(JobError::Database(format!(
            "unmapped attempt outcome '{other}' in job_attempts"
        ))),
    }
}

fn failure_details_json(error_code: &str, redacted_detail: &str) -> serde_json::Value {
    serde_json::json!({
        "error_code": error_code,
        "error_detail_redacted": redacted_detail,
    })
}

fn map_job_row(row: &sqlx::postgres::PgRow) -> Result<JobRecord, JobError> {
    let status_text: String = row.try_get("status")?;
    let kind_text: String = row.try_get("job_type")?;
    Ok(JobRecord {
        job_id: row.try_get("job_id")?,
        workspace_id: row.try_get("workspace_id")?,
        queue_name: row.try_get("queue_name")?,
        kind: JobKind::parse(&kind_text)?,
        status: JobStatus::parse(&status_text)
            .map_err(|e| JobError::Database(format!("unmapped job status: {e}")))?,
        priority: row.try_get("priority")?,
        payload: row.try_get("payload")?,
        result: row.try_get("result")?,
        error_details: row.try_get("error_details")?,
        idempotency_key: row.try_get("idempotency_key")?,
        correlation_id: row.try_get("correlation_id")?,
        cancellation_requested: row.try_get("cancellation_requested")?,
        lease_holder: row.try_get("lease_holder")?,
        lease_token: row.try_get("lease_token")?,
        lease_generation: row.try_get("lease_generation")?,
        lease_expires_at: row.try_get("lease_expires_at")?,
        last_heartbeat_at: row.try_get("last_heartbeat_at")?,
        attempt_count: row.try_get("attempt_count")?,
        max_attempts: row.try_get("max_attempts")?,
        not_before: row.try_get("not_before")?,
        created_at: row.try_get("created_at")?,
        started_at: row.try_get("started_at")?,
        completed_at: row.try_get("completed_at")?,
    })
}

async fn fetch_job_by_id_tx(
    conn: &mut PgConnection,
    job_id: Uuid,
) -> Result<Option<JobRecord>, JobError> {
    let row = sqlx::query(SELECT_JOB_BY_ID)
        .bind(job_id)
        .fetch_optional(conn)
        .await?;
    row.as_ref().map(map_job_row).transpose()
}

async fn fetch_job_by_key_tx(
    conn: &mut PgConnection,
    idempotency_key: &str,
) -> Result<Option<JobRecord>, JobError> {
    let row = sqlx::query(SELECT_JOB_BY_KEY)
        .bind(idempotency_key)
        .fetch_optional(conn)
        .await?;
    row.as_ref().map(map_job_row).transpose()
}

/// Builds an inspection handle from a fully projected jobs row (claim cleanup paths).
///
/// The synthetic authority coordinates mirror the locked row's current state so
/// fenced cleanup statements target exactly the superseded execution being
/// retired.
fn handle_from_locked(row: &sqlx::postgres::PgRow) -> ClaimedJob {
    ClaimedJob {
        job_id: row.get("job_id"),
        workspace_id: row.get("workspace_id"),
        queue_name: row.get("queue_name"),
        kind: JobKind::parse(row.get::<String, _>("job_type").as_str())
            .unwrap_or(JobKind::ParseDocumentPdf),
        attempt_number: row.get("attempt_count"),
        max_attempts: row.get("max_attempts"),
        worker_id: row
            .get::<Option<String>, _>("lease_holder")
            .unwrap_or_else(|| "<unknown>".to_string()),
        lease_token: row
            .get::<Option<Uuid>, _>("lease_token")
            .unwrap_or_else(Uuid::nil),
        lease_generation: row.get("lease_generation"),
        lease_expires_at: row
            .get::<Option<DateTime<Utc>>, _>("lease_expires_at")
            .unwrap_or_else(Utc::now),
        payload: serde_json::Value::Null,
    }
}

/// Finalizes the single open (`outcome = 'running'`) attempt of a job with the
/// frozen terminal outcome. The M002R trigger guarantees this transition can
/// happen exactly once per attempt row.
async fn finalize_open_attempt(
    conn: &mut PgConnection,
    job_id: Uuid,
    outcome: AttemptOutcome,
    error_code: Option<&str>,
    error_detail_redacted: Option<&str>,
) -> Result<(), JobError> {
    let finalized = sqlx::query(
        "UPDATE job_attempts SET outcome = $2, completed_at = clock_timestamp(), \
                error_code = COALESCE($3, error_code), \
                error_detail_redacted = COALESCE($4, error_detail_redacted) \
         WHERE job_id = $1 AND outcome = 'running'",
    )
    .bind(job_id)
    .bind(outcome.as_str())
    .bind(error_code)
    .bind(error_detail_redacted)
    .execute(&mut *conn)
    .await?;

    if finalized.rows_affected() != 1 {
        return Err(JobError::Database(format!(
            "expected exactly one open attempt for job {job_id}, found {}",
            finalized.rows_affected()
        )));
    }
    Ok(())
}

/// Produces the typed rejection reason after a fenced mutation affected zero
/// rows: terminal protection, stale/superseded authority, or invisibility.
async fn diagnose_authority_failure(
    conn: &mut PgConnection,
    handle: &ClaimedJob,
    action: &str,
) -> JobError {
    diagnose_state(conn, handle.job_id, action).await
}

async fn diagnose_terminal_or_missing(
    conn: &mut PgConnection,
    job_id: Uuid,
    action: &str,
) -> JobError {
    diagnose_state(conn, job_id, action).await
}

async fn diagnose_state(conn: &mut PgConnection, job_id: Uuid, action: &str) -> JobError {
    let row =
        sqlx::query("SELECT status, lease_generation, attempt_count FROM jobs WHERE job_id = $1")
            .bind(job_id)
            .fetch_optional(&mut *conn)
            .await;

    match row {
        Err(err) => JobError::Database(err.to_string()),
        Ok(None) => JobError::WorkspaceViolation(format!(
            "{action} rejected: job {job_id} is not visible under the caller's workspace scope"
        )),
        Ok(Some(state)) => {
            let status_text: String = state.get("status");
            match JobStatus::parse(&status_text) {
                Ok(status) if status.is_terminal() => JobError::AlreadyTerminal {
                    job_id,
                    status: status.as_str().to_string(),
                },
                _ => JobError::LeaseLost(format!(
                    "{action} rejected: caller no longer holds current valid execution authority \
                     (current status '{status_text}', generation {}, attempt {})",
                    state.get::<i64, _>("lease_generation"),
                    state.get::<i32, _>("attempt_count"),
                )),
            }
        }
    }
}

/// Dead-letters a job whose CURRENT execution authority is held by `handle`
/// (fenced, unexpired), inserting the single legal durable linkage in
/// `dead_letter_entries` and finalizing the open attempt.
///
/// When `fence_unexpired` is false the fence targets an already-expired lease
/// instead (used by the claim-time recovery path holding the row lock).
#[allow(clippy::too_many_arguments)]
async fn dead_letter_locked(
    conn: &mut PgConnection,
    handle: &ClaimedJob,
    failure_reason: &str,
    error_code: &str,
    redacted_detail: &str,
    attempt_outcome: AttemptOutcome,
    fence_unexpired: bool,
) -> Result<(), JobError> {
    // $8 selects the fence mode: true = caller must hold an unexpired lease;
    // false = the already-expired lease of a locked candidate (recovery path).
    let dead_lettered = sqlx::query(
        "UPDATE jobs SET status = 'dead_letter', completed_at = clock_timestamp(), \
                error_details = $1, \
                lease_holder = NULL, lease_token = NULL, \
                lease_expires_at = NULL, last_heartbeat_at = NULL, \
                row_version = row_version + 1 \
         WHERE job_id = $2 AND status = 'running' AND lease_holder = $3 \
           AND lease_token = $4 AND lease_generation = $5 AND attempt_count = $6 \
           AND CASE WHEN $7 THEN lease_expires_at > clock_timestamp() \
                    ELSE lease_expires_at IS NOT NULL \
                         AND lease_expires_at <= clock_timestamp() END",
    )
    .bind(failure_details_json(error_code, redacted_detail))
    .bind(handle.job_id)
    .bind(&handle.worker_id)
    .bind(handle.lease_token)
    .bind(handle.lease_generation)
    .bind(handle.attempt_number)
    .bind(fence_unexpired)
    .execute(&mut *conn)
    .await?;

    if dead_lettered.rows_affected() != 1 {
        return Err(diagnose_authority_failure(conn, handle, "dead-letter recording").await);
    }

    // One legal durable terminal linkage per exhausted/poison job.
    sqlx::query(
        "INSERT INTO dead_letter_entries \
             (job_id, queue_name, job_type, failed_at, attempt_count, failure_reason, \
              error_details, payload) \
         SELECT job_id, queue_name, job_type, clock_timestamp(), attempt_count, $2, $3, payload \
         FROM jobs WHERE job_id = $1",
    )
    .bind(handle.job_id)
    .bind(failure_reason)
    .bind(failure_details_json(error_code, redacted_detail))
    .execute(&mut *conn)
    .await?;

    finalize_open_attempt(
        conn,
        handle.job_id,
        attempt_outcome,
        Some(error_code),
        Some(redacted_detail),
    )
    .await
}

/// Deterministically finalizes a running job flagged for cancellation once its
/// lease has expired: `running -> cancelled`, open attempt outcome `cancelled`.
async fn finalize_cancelled_expired(
    conn: &mut PgConnection,
    handle: &ClaimedJob,
) -> Result<(), JobError> {
    let cancelled = sqlx::query(
        "UPDATE jobs SET status = 'cancelled', completed_at = clock_timestamp(), \
                lease_holder = NULL, lease_token = NULL, lease_expires_at = NULL, \
                last_heartbeat_at = NULL, row_version = row_version + 1 \
         WHERE job_id = $1 AND status = 'running' AND cancellation_requested = true \
           AND lease_expires_at IS NOT NULL AND lease_expires_at <= clock_timestamp() \
           AND lease_holder = $2 AND lease_token = $3 AND lease_generation = $4 \
           AND attempt_count = $5",
    )
    .bind(handle.job_id)
    .bind(&handle.worker_id)
    .bind(handle.lease_token)
    .bind(handle.lease_generation)
    .bind(handle.attempt_number)
    .execute(&mut *conn)
    .await?;

    if cancelled.rows_affected() != 1 {
        return Err(diagnose_terminal_or_missing(conn, handle.job_id, "cancel finalization").await);
    }

    finalize_open_attempt(
        conn,
        handle.job_id,
        AttemptOutcome::Cancelled,
        Some("CANCELLED_BY_REQUEST"),
        None,
    )
    .await
}
