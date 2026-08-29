//! ClamAV malware scanner integration and INSTREAM client (WI-0204).
//!
//! Provides:
//! - ClamAV clamd INSTREAM protocol client (`ClamAvClient`)
//! - Scanner runtime configuration (`ClamAvConfig`)
//! - Signature freshness policy (`SignatureHealth`, `SignatureHealthPolicy`)
//! - Scan verdicts and error taxonomy (`ScanVerdict`, `ScanOutcome`, `ScannerError`)
//! - Scanner abstraction trait (`MalwareScanner`)
//! - Test double scanner (`MockClamAvScanner`)

pub mod client;
pub mod config;
pub mod mock;
pub mod signature;
pub mod traits;
pub mod verdict;

pub use client::{ClamAvClient, SCANNER_NAME_CLAMAV, sanitize_threat_name};
pub use config::{
    ClamAvConfig, DEFAULT_CHUNK_SIZE, DEFAULT_CLAMAV_HOST, DEFAULT_CLAMAV_PORT,
    DEFAULT_SCAN_TIMEOUT_SECS, MAX_SCAN_OBJECT_BYTES,
};
pub use mock::{EICAR_TEST_SIGNATURE, EICAR_THREAT_NAME, MockClamAvScanner, MockScanMode};
pub use signature::{
    MAX_FUTURE_SKEW_SECONDS, SIGNATURE_DEGRADED_MAX_HOURS, SIGNATURE_HEALTHY_MAX_HOURS,
    SignatureHealth, SignatureHealthPolicy, SignatureStatus,
};
pub use traits::MalwareScanner;
pub use verdict::{ScanOutcome, ScanVerdict, ScannerError};
