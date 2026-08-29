//! Malware scanner trait abstraction for dependency injection and testing.

use async_trait::async_trait;

use crate::scanner::signature::SignatureHealth;
use crate::scanner::verdict::{ScanOutcome, ScannerError};

/// Trait implemented by malware scanners (both real ClamAV daemon and test doubles).
#[async_trait]
pub trait MalwareScanner: Send + Sync {
    /// Evaluates the signature database health of the scanner.
    async fn check_signatures(&self) -> Result<SignatureHealth, ScannerError>;

    /// Scans raw bytes using the scanner's protocol (e.g. ClamAV INSTREAM).
    ///
    /// Must enforce:
    /// - Maximum byte length limit
    /// - Scan timeout (120s)
    /// - Fail-closed on connection or protocol errors
    /// - Signature health validation (fails closed on unhealthy signatures)
    async fn scan(&self, bytes: &[u8]) -> Result<ScanOutcome, ScannerError>;
}
