//! Scan verdicts, outcomes, and failure taxonomy for malware scanning.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::scanner::signature::SignatureHealth;

/// Typed scan outcome verdict produced by malware scanning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanVerdict {
    /// No threat was found in the inspected bytes.
    Clean,
    /// Known malware was detected.
    Malware {
        /// Bounded threat identification label (e.g. "Win.Test.EICAR_HDB-1").
        threat_name: String,
    },
}

impl ScanVerdict {
    /// True when the verdict is Clean.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        matches!(self, Self::Clean)
    }

    /// True when the verdict is Malware.
    #[must_use]
    pub const fn is_malware(&self) -> bool {
        matches!(self, Self::Malware { .. })
    }

    /// Returns the threat name if this is a Malware verdict.
    #[must_use]
    pub fn threat_name(&self) -> Option<&str> {
        match self {
            Self::Clean => None,
            Self::Malware { threat_name } => Some(threat_name),
        }
    }
}

/// Comprehensive authoritative outcome produced by a completed scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanOutcome {
    /// The scan verdict (Clean or Malware).
    pub verdict: ScanVerdict,
    /// Bounded scanner identifier (e.g. "clamav").
    pub scanner_name: String,
    /// Bounded scanner engine/daemon version (e.g. "1.3.0").
    pub scanner_version: Option<String>,
    /// Evaluated signature database health at time of scan.
    pub signature_health: SignatureHealth,
    /// Timestamp when the scan was executed.
    pub scanned_at: DateTime<Utc>,
    /// Duration of the scan operation in milliseconds.
    pub scan_duration_ms: u64,
}

/// Typed scanner execution errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ScannerError {
    /// Failed to connect to scanner daemon or network connection dropped.
    #[error("Scanner connection failed: {0}")]
    Connection(String),

    /// Scan timed out exceeding the bounded limit.
    #[error("Scan timed out after {0} seconds")]
    Timeout(u64),

    /// Scanner returned a protocol error or malformed stream framing.
    #[error("Scanner protocol error: {0}")]
    Protocol(String),

    /// Signature database is unhealthy (>24h old or invalid); fails closed.
    #[error("Scanner signatures unhealthy: {0}")]
    UnhealthySignature(String),

    /// Scanned content exceeds maximum allowable payload size.
    #[error("Scanned object length ({0} bytes) exceeds maximum allowable size ({1} bytes)")]
    Oversize(usize, usize),

    /// Internal scanner failure.
    #[error("Scanner internal error: {0}")]
    Internal(String),
}
