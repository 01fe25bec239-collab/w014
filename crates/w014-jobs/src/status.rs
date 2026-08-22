//! Frozen Prompt-12 durable-job status domain.
//!
//! The authoritative `JobStatus` vocabulary is EXACTLY:
//! `requested | queued | running | retryable | succeeded | failed | cancelled | dead_letter`.
//!
//! Obsolete aliases (`enqueued`, `claimed`, `completed`) are deliberately absent
//! and must never be persisted or compared against.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Frozen authoritative lifecycle status of a durable job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Requested,
    Queued,
    Running,
    Retryable,
    Succeeded,
    Failed,
    Cancelled,
    DeadLetter,
}

impl JobStatus {
    /// Exact frozen PostgreSQL text representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Retryable => "retryable",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::DeadLetter => "dead_letter",
        }
    }

    /// Parses the frozen status from its canonical text form.
    ///
    /// Obsolete aliases are rejected by design.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "requested" => Ok(Self::Requested),
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "retryable" => Ok(Self::Retryable),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "dead_letter" => Ok(Self::DeadLetter),
            other => Err(format!(
                "unknown job status '{other}': the frozen domain is \
                 requested|queued|running|retryable|succeeded|failed|cancelled|dead_letter"
            )),
        }
    }

    /// True when the job has reached a state that can never legally reopen.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::DeadLetter
        )
    }

    /// True for states that may be selected by the frozen claim predicate
    /// (before lease/dependency/cancellation clauses are applied).
    #[must_use]
    pub const fn is_claimable_base(&self) -> bool {
        matches!(self, Self::Queued | Self::Retryable)
    }
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Frozen terminal outcome vocabulary for `job_attempts.outcome`.
///
/// Exact values: `running | succeeded | retryable_failed | terminal_failed |
/// cancelled | lease_expired`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcome {
    Running,
    Succeeded,
    RetryableFailed,
    TerminalFailed,
    Cancelled,
    LeaseExpired,
}

impl AttemptOutcome {
    /// Exact frozen PostgreSQL text representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::RetryableFailed => "retryable_failed",
            Self::TerminalFailed => "terminal_failed",
            Self::Cancelled => "cancelled",
            Self::LeaseExpired => "lease_expired",
        }
    }

    /// True while the attempt is still executing (no terminal transition yet).
    #[must_use]
    pub const fn is_open(&self) -> bool {
        matches!(self, Self::Running)
    }
}

impl fmt::Display for AttemptOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_status_domain_round_trips_exactly() {
        let all = [
            JobStatus::Requested,
            JobStatus::Queued,
            JobStatus::Running,
            JobStatus::Retryable,
            JobStatus::Succeeded,
            JobStatus::Failed,
            JobStatus::Cancelled,
            JobStatus::DeadLetter,
        ];
        for status in all {
            assert_eq!(JobStatus::parse(status.as_str()), Ok(status));
        }
    }

    #[test]
    fn obsolete_aliases_are_rejected() {
        for obsolete in ["enqueued", "claimed", "completed"] {
            assert!(
                JobStatus::parse(obsolete).is_err(),
                "obsolete alias '{obsolete}' must not parse"
            );
        }
    }

    #[test]
    fn attempt_outcome_vocabulary_is_exact() {
        let outcomes = [
            (AttemptOutcome::Running, "running"),
            (AttemptOutcome::Succeeded, "succeeded"),
            (AttemptOutcome::RetryableFailed, "retryable_failed"),
            (AttemptOutcome::TerminalFailed, "terminal_failed"),
            (AttemptOutcome::Cancelled, "cancelled"),
            (AttemptOutcome::LeaseExpired, "lease_expired"),
        ];
        for (value, text) in outcomes {
            assert_eq!(value.as_str(), text);
        }
        assert!(AttemptOutcome::Running.is_open());
        assert!(!AttemptOutcome::Succeeded.is_open());
    }

    #[test]
    fn terminal_statuses_never_reopen() {
        assert!(JobStatus::Succeeded.is_terminal());
        assert!(JobStatus::Failed.is_terminal());
        assert!(JobStatus::Cancelled.is_terminal());
        assert!(JobStatus::DeadLetter.is_terminal());
        assert!(!JobStatus::Queued.is_terminal());
        assert!(!JobStatus::Running.is_terminal());
        assert!(!JobStatus::Requested.is_terminal());
        assert!(!JobStatus::Retryable.is_terminal());
    }
}
