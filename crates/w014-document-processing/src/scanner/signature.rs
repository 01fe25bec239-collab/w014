//! Signature freshness policy for ClamAV malware scanners (Prompt-13 policy).
//!
//! Enforces:
//! - <= 8 hours: Healthy
//! - > 8 hours and <= 24 hours: Degraded (observable alert state)
//! - > 24 hours: Unhealthy (fails closed; MUST NEVER produce clean verdict)
//! - Future timestamps (> 5 minutes skew) or missing metadata: Unhealthy (fail closed).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum age in hours for signature database to be considered healthy (8 hours).
pub const SIGNATURE_HEALTHY_MAX_HOURS: i64 = 8;

/// Maximum age in hours for signature database to be considered degraded (24 hours).
/// Beyond 24 hours is UNHEALTHY and MUST fail closed.
pub const SIGNATURE_DEGRADED_MAX_HOURS: i64 = 24;

/// Maximum clock skew allowed into the future before failing closed (5 minutes = 300 seconds).
pub const MAX_FUTURE_SKEW_SECONDS: i64 = 300;

/// Typed health classification of the scanner's signature database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Database updated within 8 hours.
    Healthy,
    /// Database updated between 8 and 24 hours ago (observable degraded alert).
    Degraded,
    /// Database older than 24 hours or invalid/future timestamp (fails closed).
    Unhealthy,
}

impl SignatureStatus {
    /// Canonical string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
        }
    }

    /// True if the signature state is permissible for a scan to produce a clean verdict.
    #[must_use]
    pub const fn allows_clean_verdict(self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }
}

/// Structured evidence describing the scanner signature freshness evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureHealth {
    /// Evaluated status.
    pub status: SignatureStatus,
    /// Age in seconds of the signature database at time of evaluation.
    pub age_seconds: i64,
    /// Optional scanner / signature database version string.
    pub signature_version: Option<String>,
    /// Timestamp when the signature database was published / created.
    pub signature_timestamp: DateTime<Utc>,
    /// Timestamp when this health evaluation was performed.
    pub evaluated_at: DateTime<Utc>,
    /// Optional human/diagnostic message (e.g. degradation explanation).
    pub message: Option<String>,
}

impl SignatureHealth {
    /// True when the signature status is acceptable (Healthy or Degraded).
    #[must_use]
    pub fn is_acceptable(&self) -> bool {
        self.status.allows_clean_verdict()
    }

    /// True when the signature status is Healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self.status, SignatureStatus::Healthy)
    }

    /// True when the signature status is Degraded.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        matches!(self.status, SignatureStatus::Degraded)
    }

    /// True when the signature status is Unhealthy.
    #[must_use]
    pub fn is_unhealthy(&self) -> bool {
        matches!(self.status, SignatureStatus::Unhealthy)
    }
}

/// Signature health evaluator enforcing Prompt-13 policies.
pub struct SignatureHealthPolicy;

impl SignatureHealthPolicy {
    /// Evaluates signature database health given its timestamp and the current time.
    #[must_use]
    pub fn evaluate(
        signature_timestamp: DateTime<Utc>,
        now: DateTime<Utc>,
        signature_version: Option<String>,
    ) -> SignatureHealth {
        let age_duration = now.signed_duration_since(signature_timestamp);
        let age_seconds = age_duration.num_seconds();

        // Fail closed on timestamps in the future beyond acceptable skew
        if age_seconds < -MAX_FUTURE_SKEW_SECONDS {
            return SignatureHealth {
                status: SignatureStatus::Unhealthy,
                age_seconds,
                signature_version,
                signature_timestamp,
                evaluated_at: now,
                message: Some(format!(
                    "Signature timestamp is {age_seconds}s in the future (exceeds {MAX_FUTURE_SKEW_SECONDS}s skew limit)"
                )),
            };
        }

        // Clamp negative small clock skew to 0 for age calculation
        let effective_age_seconds = age_seconds.max(0);
        let age_hours = effective_age_seconds / 3600;

        if effective_age_seconds <= SIGNATURE_HEALTHY_MAX_HOURS * 3600 {
            SignatureHealth {
                status: SignatureStatus::Healthy,
                age_seconds: effective_age_seconds,
                signature_version,
                signature_timestamp,
                evaluated_at: now,
                message: None,
            }
        } else if effective_age_seconds <= SIGNATURE_DEGRADED_MAX_HOURS * 3600 {
            SignatureHealth {
                status: SignatureStatus::Degraded,
                age_seconds: effective_age_seconds,
                signature_version,
                signature_timestamp,
                evaluated_at: now,
                message: Some(format!(
                    "Signatures degraded: age is {age_hours}h (between 8h and 24h)"
                )),
            }
        } else {
            SignatureHealth {
                status: SignatureStatus::Unhealthy,
                age_seconds: effective_age_seconds,
                signature_version,
                signature_timestamp,
                evaluated_at: now,
                message: Some(format!(
                    "Signatures unhealthy: age is {age_hours}h (exceeds 24h maximum)"
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_signature_health_boundaries() {
        let now = Utc::now();

        // Exactly now -> Healthy
        let h0 = SignatureHealthPolicy::evaluate(now, now, Some("1.3.0".into()));
        assert_eq!(h0.status, SignatureStatus::Healthy);
        assert!(h0.is_healthy());
        assert!(h0.is_acceptable());

        // 8 hours ago -> Healthy
        let h8 =
            SignatureHealthPolicy::evaluate(now - Duration::hours(8), now, Some("1.3.0".into()));
        assert_eq!(h8.status, SignatureStatus::Healthy);
        assert!(h8.is_acceptable());

        // 8 hours + 1 minute -> Degraded
        let d8_1 = SignatureHealthPolicy::evaluate(
            now - Duration::hours(8) - Duration::minutes(1),
            now,
            Some("1.3.0".into()),
        );
        assert_eq!(d8_1.status, SignatureStatus::Degraded);
        assert!(d8_1.is_degraded());
        assert!(d8_1.is_acceptable());

        // 24 hours -> Degraded
        let d24 =
            SignatureHealthPolicy::evaluate(now - Duration::hours(24), now, Some("1.3.0".into()));
        assert_eq!(d24.status, SignatureStatus::Degraded);
        assert!(d24.is_acceptable());

        // 24 hours + 1 minute -> Unhealthy (fails closed)
        let u24_1 = SignatureHealthPolicy::evaluate(
            now - Duration::hours(24) - Duration::minutes(1),
            now,
            Some("1.3.0".into()),
        );
        assert_eq!(u24_1.status, SignatureStatus::Unhealthy);
        assert!(u24_1.is_unhealthy());
        assert!(!u24_1.is_acceptable());

        // Future timestamp (> 5 min) -> Unhealthy
        let u_future =
            SignatureHealthPolicy::evaluate(now + Duration::minutes(10), now, Some("1.3.0".into()));
        assert_eq!(u_future.status, SignatureStatus::Unhealthy);
        assert!(!u_future.is_acceptable());

        // Minor future skew (<= 5 min) -> Healthy
        let h_skew =
            SignatureHealthPolicy::evaluate(now + Duration::seconds(60), now, Some("1.3.0".into()));
        assert_eq!(h_skew.status, SignatureStatus::Healthy);
        assert!(h_skew.is_acceptable());
    }
}
