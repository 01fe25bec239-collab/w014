//! Runtime data model for the PostgreSQL durable job queue.

use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::JobError;
use crate::kind::JobKind;
use crate::status::{AttemptOutcome, JobStatus};

/// Frozen bounded-backoff schedule (seconds) applied after the Nth retryable
/// failure: retry 1 -> 15s, retry 2 -> 60s, retry 3 -> 5m, retry 4 -> 20m.
/// At the frozen attempt boundary (`attempt_count == max_attempts`) the job is
/// dead-lettered; there is no fifth delay and no infinite retry.
pub const BACKOFF_SCHEDULE_SECS: [i64; 4] = [15, 60, 300, 1200];

/// Frozen default attempt budget for W2 jobs (initial try + retries 1..4).
pub const FROZEN_MAX_ATTEMPTS: i32 = 5;

/// Frozen `backoff_max_secs` persisted at enqueue so the full schedule
/// (20 minutes) is never clamped.
pub const FROZEN_BACKOFF_MAX_SECS: i32 = 1200;

/// Returns the frozen backoff delay in seconds to apply after the given
/// number of consumed attempts fails retryably.
///
/// Attempt 1 failure -> 15s, 2 -> 60s, 3 -> 300s, 4 -> 1200s. A failure at
/// `attempt_count >= max_attempts` has no next delay (dead-letter instead).
#[must_use]
pub fn backoff_delay_secs_after(attempt_consumed: i32, max_attempts: i32) -> Option<i64> {
    if attempt_consumed < 1 || attempt_consumed >= max_attempts {
        return None;
    }
    let index = usize::try_from(attempt_consumed - 1).ok()?;
    BACKOFF_SCHEDULE_SECS.get(index).copied()
}

/// Workspace scoping for claim queries.
///
/// Production workers operate under RLS-restricted roles: `Unrestricted` is
/// fail-closed there (zero visible rows). Tests and administrative connections
/// use it deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceScope {
    /// Claim only inside this workspace (sets the RLS session context).
    Single(Uuid),
    /// Do not constrain by workspace context (fail-closed under RLS roles).
    Unrestricted,
}

/// Parameters for enqueueing one logical durable job.
#[derive(Debug, Clone)]
pub struct EnqueueParams {
    /// Owning workspace.
    pub workspace_id: Uuid,
    /// Closed W2 job kind.
    pub kind: JobKind,
    /// Sorted immutable target references.
    pub immutable_targets: Vec<String>,
    /// Optional dependency hash distinguishing re-analysis generations.
    pub dependency_hash: Option<String>,
    /// Payload contract version spoken by the producer.
    pub payload_contract_version: u32,
    /// Producer component version.
    pub producer_version: String,
    /// Screened free-form executor parameters.
    pub parameters: serde_json::Value,
    /// Predecessor job ids that must be `succeeded` before this job claims.
    pub depends_on: Vec<Uuid>,
    /// Optional correlation id for tracing.
    pub correlation_id: Option<String>,
    /// Queue priority (higher runs earlier within a queue).
    pub priority: i32,
    /// Attempt budget; defaults to the frozen boundary of 5.
    pub max_attempts: i32,
}

impl EnqueueParams {
    /// Builds minimal valid parameters for one kind/workspace/target set.
    #[must_use]
    pub fn new(workspace_id: Uuid, kind: JobKind, immutable_targets: Vec<String>) -> Self {
        Self {
            workspace_id,
            kind,
            immutable_targets,
            dependency_hash: None,
            payload_contract_version: crate::payload::PAYLOAD_CONTRACT_VERSION,
            producer_version: "w014-jobs".to_string(),
            parameters: serde_json::json!({}),
            depends_on: Vec::new(),
            correlation_id: None,
            priority: 0,
            max_attempts: FROZEN_MAX_ATTEMPTS,
        }
    }
}

/// Outcome of an enqueue call against the durable queue.
#[derive(Debug, Clone, PartialEq)]
pub enum EnqueueOutcome {
    /// A new logical job row was created durably.
    Created(JobRecord),
    /// The canonical identity already existed; the existing logical job is
    /// returned unchanged regardless of its current status (cancelled
    /// identities are preserved, never replayed as if they never existed).
    Existing(JobRecord),
}

impl EnqueueOutcome {
    /// The authoritative job record for either outcome branch.
    #[must_use]
    pub fn record(&self) -> &JobRecord {
        match self {
            Self::Created(record) | Self::Existing(record) => record,
        }
    }

    /// True when this call created a brand-new logical job.
    #[must_use]
    pub const fn is_new(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

/// Criteria for one claim poll.
#[derive(Debug, Clone)]
pub struct ClaimCriteria {
    /// Queue names to poll (canonical frozen queue identities).
    pub queues: Vec<String>,
    /// Restrict claiming to these closed kinds; empty means no restriction.
    pub kinds: Vec<JobKind>,
    /// Workspace scope for RLS-safe claiming.
    pub workspace: WorkspaceScope,
    /// Lease duration granted on success.
    pub lease_duration: Duration,
}

/// Authoritative projection of a `jobs` row.
#[derive(Debug, Clone, PartialEq)]
pub struct JobRecord {
    pub job_id: Uuid,
    pub workspace_id: Uuid,
    pub queue_name: String,
    pub kind: JobKind,
    pub status: JobStatus,
    pub priority: i32,
    pub payload: serde_json::Value,
    pub result: Option<serde_json::Value>,
    pub error_details: Option<serde_json::Value>,
    pub idempotency_key: Option<String>,
    pub correlation_id: Option<String>,
    pub cancellation_requested: bool,
    pub lease_holder: Option<String>,
    pub lease_token: Option<Uuid>,
    pub lease_generation: i64,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub not_before: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Execution authority handed to a worker by a committed claim transaction.
///
/// Carries every fencing coordinate required to mutate current truth:
/// job identity, lease owner/token, generation fence, and attempt identity.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimedJob {
    pub job_id: Uuid,
    pub workspace_id: Uuid,
    pub queue_name: String,
    pub kind: JobKind,
    pub attempt_number: i32,
    pub max_attempts: i32,
    pub worker_id: String,
    pub lease_token: Uuid,
    pub lease_generation: i64,
    pub lease_expires_at: DateTime<Utc>,
    pub payload: serde_json::Value,
}

impl ClaimedJob {
    /// Parses the stored `job_type` into the closed kind vocabulary.
    pub fn parse_kind(raw: &str) -> Result<JobKind, JobError> {
        JobKind::parse(raw)
    }
}

/// Append-oriented history record of one execution attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct AttemptRecord {
    pub job_attempt_id: Uuid,
    pub job_id: Uuid,
    pub attempt_number: i32,
    pub worker_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub outcome: AttemptOutcome,
    pub error_code: Option<String>,
    pub error_detail_redacted: Option<String>,
}

/// One durable stage-level progress event (`job_progress`, INSERT-only).
#[derive(Debug, Clone, PartialEq)]
pub struct ProgressEvent {
    pub job_progress_id: Uuid,
    pub job_id: Uuid,
    pub sequence: i32,
    pub stage_code: String,
    pub current: i64,
    pub total: Option<i64>,
    pub message_code: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Durable terminal evidence row from `dead_letter_entries`.
#[derive(Debug, Clone, PartialEq)]
pub struct DeadLetterRecord {
    pub dead_letter_entry_id: Uuid,
    pub job_id: Uuid,
    pub queue_name: String,
    pub job_type: String,
    pub failed_at: DateTime<Utc>,
    pub attempt_count: i32,
    pub failure_reason: String,
    pub error_details: serde_json::Value,
}

/// Classification attached by an executor when reporting failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Transient failure: schedule a bounded-backoff retry.
    Retryable,
    /// Permanent failure: terminate as `failed`; never retried.
    Terminal,
    /// Poison message: dead-letter immediately without consuming further
    /// retries.
    Poison,
}

/// Authoritative effect recorded by `complete_failure`.
#[derive(Debug, Clone, PartialEq)]
pub enum FailureResolution {
    /// Job moved to `retryable` with a bounded database-backed delay.
    RetryScheduled {
        /// Earliest instant the next attempt may be claimed.
        not_before: DateTime<Utc>,
        /// Frozen backoff delay applied (seconds).
        delay_secs: i64,
    },
    /// Job terminally failed (`failed`); no retry will occur.
    TerminalFailed,
    /// Retry exhaustion / poison: job dead-lettered with one durable
    /// `dead_letter_entries` linkage.
    DeadLettered,
}

/// Authoritative effect of a cancellation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationOutcome {
    /// A queued/retryable job transitioned directly to `cancelled`.
    Cancelled,
    /// A running job was flagged; it stops being reclaimable and its lease
    /// expiry path finalizes cancellation.
    CancellationRequested,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_backoff_schedule_matches_contract() {
        // After attempt N (N < max), delay follows 15s/60s/5m/20m.
        assert_eq!(backoff_delay_secs_after(1, FROZEN_MAX_ATTEMPTS), Some(15));
        assert_eq!(backoff_delay_secs_after(2, FROZEN_MAX_ATTEMPTS), Some(60));
        assert_eq!(backoff_delay_secs_after(3, FROZEN_MAX_ATTEMPTS), Some(300));
        assert_eq!(backoff_delay_secs_after(4, FROZEN_MAX_ATTEMPTS), Some(1200));
        // Boundary: no fifth delay exists; exhaustion dead-letters instead.
        assert_eq!(backoff_delay_secs_after(5, FROZEN_MAX_ATTEMPTS), None);
        assert_eq!(backoff_delay_secs_after(0, FROZEN_MAX_ATTEMPTS), None);
        assert_eq!(backoff_delay_secs_after(6, FROZEN_MAX_ATTEMPTS), None);
        // Smaller budgets exhaust earlier.
        assert_eq!(backoff_delay_secs_after(1, 2), Some(15));
        assert_eq!(backoff_delay_secs_after(2, 2), None);
    }
}
