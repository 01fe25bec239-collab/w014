//! Mock ClamAV scanner implementation for deterministic unit, integration, and security testing.

use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use chrono::Utc;

use crate::scanner::signature::{SignatureHealth, SignatureStatus};
use crate::scanner::traits::MalwareScanner;
use crate::scanner::verdict::{ScanOutcome, ScanVerdict, ScannerError};

/// Standard harmless EICAR test string signature.
pub const EICAR_TEST_SIGNATURE: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Standard harmless EICAR malware threat name.
pub const EICAR_THREAT_NAME: &str = "Win.Test.EICAR_HDB-1";

/// Mock scanner configuration and behavior mode.
#[derive(Debug, Clone)]
pub enum MockScanMode {
    /// Normal operation: EICAR payloads detected as malware, others clean.
    Standard,
    /// Always return clean regardless of payload.
    AlwaysClean,
    /// Always return malware with the given threat name.
    AlwaysMalware(String),
    /// Simulate scanner daemon connection unavailable / network failure.
    Unavailable(String),
    /// Simulate scan timeout exceeding 120 seconds.
    Timeout(u64),
    /// Simulate protocol / internal error.
    ProtocolError(String),
}

/// In-memory test double for ClamAV malware scanning.
pub struct MockClamAvScanner {
    scanner_name: String,
    scanner_version: Option<String>,
    mode: RwLock<MockScanMode>,
    signature_health: RwLock<SignatureHealth>,
    custom_signatures: RwLock<Vec<(Vec<u8>, String)>>,
    scan_count: AtomicUsize,
    scanned_bytes: AtomicUsize,
}

impl Default for MockClamAvScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl MockClamAvScanner {
    /// Creates a default mock scanner in standard mode with healthy signatures.
    #[must_use]
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            scanner_name: "clamav".to_string(),
            scanner_version: Some("1.3.0".to_string()),
            mode: RwLock::new(MockScanMode::Standard),
            signature_health: RwLock::new(SignatureHealth {
                status: SignatureStatus::Healthy,
                age_seconds: 1800, // 30 minutes old
                signature_version: Some("27200".to_string()),
                signature_timestamp: now,
                evaluated_at: now,
                message: None,
            }),
            custom_signatures: RwLock::new(Vec::new()),
            scan_count: AtomicUsize::new(0),
            scanned_bytes: AtomicUsize::new(0),
        }
    }

    /// Builder to set the scan mode.
    #[must_use]
    pub fn with_mode(self, mode: MockScanMode) -> Self {
        *self.mode.write().unwrap() = mode;
        self
    }

    /// Builder to set the signature health.
    #[must_use]
    pub fn with_signature_health(self, health: SignatureHealth) -> Self {
        *self.signature_health.write().unwrap() = health;
        self
    }

    /// Builder to set scanner engine version.
    #[must_use]
    pub fn with_scanner_version(mut self, version: Option<String>) -> Self {
        self.scanner_version = version;
        self
    }

    /// Sets the scan mode dynamically.
    pub fn set_mode(&self, mode: MockScanMode) {
        *self.mode.write().unwrap() = mode;
    }

    /// Sets the signature health dynamically.
    pub fn set_signature_health(&self, health: SignatureHealth) {
        *self.signature_health.write().unwrap() = health;
    }

    /// Adds a custom byte pattern to trigger a specific malware threat detection.
    pub fn add_custom_signature(&self, pattern: &[u8], threat_name: impl Into<String>) {
        self.custom_signatures
            .write()
            .unwrap()
            .push((pattern.to_vec(), threat_name.into()));
    }

    /// Number of scan requests processed.
    #[must_use]
    pub fn scan_count(&self) -> usize {
        self.scan_count.load(Ordering::SeqCst)
    }

    /// Total bytes scanned.
    #[must_use]
    pub fn scanned_bytes(&self) -> usize {
        self.scanned_bytes.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl MalwareScanner for MockClamAvScanner {
    async fn check_signatures(&self) -> Result<SignatureHealth, ScannerError> {
        let health = self.signature_health.read().unwrap().clone();
        Ok(health)
    }

    async fn scan(&self, bytes: &[u8]) -> Result<ScanOutcome, ScannerError> {
        self.scan_count.fetch_add(1, Ordering::SeqCst);
        self.scanned_bytes.fetch_add(bytes.len(), Ordering::SeqCst);

        // Check signature freshness first; fail closed if unhealthy
        let sig_health = self.check_signatures().await?;
        if sig_health.is_unhealthy() {
            return Err(ScannerError::UnhealthySignature(
                sig_health
                    .message
                    .clone()
                    .unwrap_or_else(|| "Signatures exceed 24h freshness limit".to_string()),
            ));
        }

        let mode = self.mode.read().unwrap().clone();
        let verdict = match mode {
            MockScanMode::Unavailable(msg) => {
                return Err(ScannerError::Connection(msg));
            }
            MockScanMode::Timeout(secs) => {
                return Err(ScannerError::Timeout(secs));
            }
            MockScanMode::ProtocolError(msg) => {
                return Err(ScannerError::Protocol(msg));
            }
            MockScanMode::AlwaysClean => ScanVerdict::Clean,
            MockScanMode::AlwaysMalware(threat) => ScanVerdict::Malware {
                threat_name: threat,
            },
            MockScanMode::Standard => {
                // Check if payload contains EICAR test string
                if bytes
                    .windows(EICAR_TEST_SIGNATURE.len())
                    .any(|w| w == EICAR_TEST_SIGNATURE)
                {
                    ScanVerdict::Malware {
                        threat_name: EICAR_THREAT_NAME.to_string(),
                    }
                } else {
                    // Check custom registered signatures
                    let mut custom_hit = None;
                    let custom = self.custom_signatures.read().unwrap();
                    for (pat, threat) in custom.iter() {
                        if !pat.is_empty() && bytes.windows(pat.len()).any(|w| w == pat.as_slice())
                        {
                            custom_hit = Some(threat.clone());
                            break;
                        }
                    }
                    if let Some(threat) = custom_hit {
                        ScanVerdict::Malware {
                            threat_name: threat,
                        }
                    } else {
                        ScanVerdict::Clean
                    }
                }
            }
        };

        Ok(ScanOutcome {
            verdict,
            scanner_name: self.scanner_name.clone(),
            scanner_version: self.scanner_version.clone(),
            signature_health: sig_health,
            scanned_at: Utc::now(),
            scan_duration_ms: 5,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_scanner_eicar_detection() {
        let scanner = MockClamAvScanner::new();
        let outcome = scanner.scan(EICAR_TEST_SIGNATURE).await.unwrap();
        assert_eq!(
            outcome.verdict,
            ScanVerdict::Malware {
                threat_name: EICAR_THREAT_NAME.to_string()
            }
        );
    }

    #[tokio::test]
    async fn test_mock_scanner_clean_payload() {
        let scanner = MockClamAvScanner::new();
        let clean_bytes = b"%PDF-1.7 sample clean content";
        let outcome = scanner.scan(clean_bytes).await.unwrap();
        assert_eq!(outcome.verdict, ScanVerdict::Clean);
    }

    #[tokio::test]
    async fn test_mock_scanner_unavailable() {
        let scanner =
            MockClamAvScanner::new().with_mode(MockScanMode::Unavailable("Daemon down".into()));
        assert!(scanner.scan(b"test").await.is_err());
    }

    #[tokio::test]
    async fn test_mock_scanner_unhealthy_signatures_fail_closed() {
        let now = Utc::now();
        let unhealthy_health = SignatureHealth {
            status: SignatureStatus::Unhealthy,
            age_seconds: 100_000,
            signature_version: None,
            signature_timestamp: now,
            evaluated_at: now,
            message: Some("Signatures >24h old".into()),
        };
        let scanner = MockClamAvScanner::new().with_signature_health(unhealthy_health);
        let res = scanner.scan(b"clean bytes").await;
        assert!(res.is_err());
        assert!(matches!(
            res.unwrap_err(),
            ScannerError::UnhealthySignature(_)
        ));
    }
}
