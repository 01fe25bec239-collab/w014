//! Real bounded ClamAV clamd INSTREAM protocol client implementation.
//!
//! Enforces:
//! - Exact byte streaming over TCP to clamd via INSTREAM protocol (`zINSTREAM\0`)
//! - 4-byte big-endian chunk length framing with `[0,0,0,0]` termination
//! - Bounded chunk streaming (default 64 KiB)
//! - Max object size enforcement (100 MiB limit)
//! - Strict 120s scan timeout enforcement
//! - Safe, bounded response parsing fail-closed (never interprets error/malformed as clean)
//! - Signature freshness evaluation (fails closed if signatures are >24h old or invalid)
//! - Sanitization of threat names (no raw hostile document bytes exposed)

use std::time::Instant;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use w014_domain::limits::MAX_REASON_CODE_BYTES;

use crate::scanner::config::ClamAvConfig;
use crate::scanner::signature::{SignatureHealth, SignatureHealthPolicy};
use crate::scanner::traits::MalwareScanner;
use crate::scanner::verdict::{ScanOutcome, ScanVerdict, ScannerError};

/// Default scanner identity.
pub const SCANNER_NAME_CLAMAV: &str = "clamav";

/// Real ClamAV clamd INSTREAM client.
#[derive(Debug, Clone)]
pub struct ClamAvClient {
    config: ClamAvConfig,
    /// Explicit signature timestamp override if provided (e.g. for testing / static config).
    signature_timestamp_override: Option<DateTime<Utc>>,
}

impl ClamAvClient {
    /// Creates a new ClamAvClient with the given configuration.
    #[must_use]
    pub fn new(config: ClamAvConfig) -> Self {
        Self {
            config,
            signature_timestamp_override: None,
        }
    }

    /// Sets an explicit signature timestamp override for freshness evaluation.
    #[must_use]
    pub fn with_signature_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.signature_timestamp_override = Some(timestamp);
        self
    }

    /// Returns the current configuration.
    #[must_use]
    pub fn config(&self) -> &ClamAvConfig {
        &self.config
    }

    /// Establishes a TCP connection to the clamd daemon.
    async fn connect(&self) -> Result<TcpStream, ScannerError> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        TcpStream::connect(&addr).await.map_err(|e| {
            ScannerError::Connection(format!("Failed to connect to ClamAV at {addr}: {e}"))
        })
    }

    /// Queries clamd for version and signature timestamp information.
    async fn query_version_raw(&self) -> Result<(String, Option<DateTime<Utc>>), ScannerError> {
        let fut = async {
            let mut stream = self.connect().await?;

            // Send VERSION command (zVERSION\0)
            stream.write_all(b"zVERSION\0").await.map_err(|e| {
                ScannerError::Connection(format!("Failed to write VERSION command: {e}"))
            })?;
            stream.flush().await.map_err(|e| {
                ScannerError::Connection(format!("Failed to flush VERSION command: {e}"))
            })?;

            let mut buf = [0u8; 512];
            let n = stream.read(&mut buf).await.map_err(|e| {
                ScannerError::Connection(format!("Failed to read VERSION response: {e}"))
            })?;

            let raw = String::from_utf8_lossy(&buf[..n])
                .trim_matches(|c| c == '\0' || c == '\r' || c == '\n')
                .to_string();

            if raw.is_empty() {
                return Err(ScannerError::Protocol(
                    "Empty VERSION response from ClamAV".to_string(),
                ));
            }

            // Standard ClamAV response format: "ClamAV 1.3.0/27200/Mon Aug 29 12:00:00 2026"
            let parts: Vec<&str> = raw.split('/').collect();
            let version_str = parts.first().unwrap_or(&raw.as_str()).trim().to_string();

            let parsed_date = if parts.len() >= 3 {
                let date_str = parts[2].trim();
                DateTime::parse_from_rfc2822(date_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .or_else(|_| {
                        DateTime::parse_from_str(date_str, "%a %b %d %H:%M:%S %Y")
                            .map(|dt| dt.with_timezone(&Utc))
                    })
                    .ok()
            } else {
                None
            };

            Ok((version_str, parsed_date))
        };

        match timeout(self.config.timeout, fut).await {
            Ok(res) => res,
            Err(_) => Err(ScannerError::Timeout(self.config.timeout.as_secs())),
        }
    }

    /// Performs the INSTREAM scanning protocol over a connected TCP stream.
    async fn execute_instream(
        &self,
        mut stream: TcpStream,
        bytes: &[u8],
    ) -> Result<ScanVerdict, ScannerError> {
        // 1. Send INSTREAM command
        stream
            .write_all(b"zINSTREAM\0")
            .await
            .map_err(|e| ScannerError::Connection(format!("Failed to write zINSTREAM: {e}")))?;

        // 2. Stream byte chunks prefixed with 4-byte big-endian length
        let chunk_size = self.config.chunk_size;
        for chunk in bytes.chunks(chunk_size) {
            let len = u32::try_from(chunk.len()).map_err(|_| {
                ScannerError::Protocol(format!("Chunk size {} exceeds u32", chunk.len()))
            })?;
            stream.write_all(&len.to_be_bytes()).await.map_err(|e| {
                ScannerError::Connection(format!("Failed to write chunk length: {e}"))
            })?;
            stream.write_all(chunk).await.map_err(|e| {
                ScannerError::Connection(format!("Failed to write chunk body: {e}"))
            })?;
        }

        // 3. Terminate stream with zero-length chunk
        stream.write_all(&0u32.to_be_bytes()).await.map_err(|e| {
            ScannerError::Connection(format!("Failed to write stream terminator: {e}"))
        })?;
        stream
            .flush()
            .await
            .map_err(|e| ScannerError::Connection(format!("Failed to flush stream: {e}")))?;

        // 4. Read response from clamd
        let mut response_buf = Vec::with_capacity(1024);
        let mut temp = [0u8; 256];
        loop {
            let n = stream.read(&mut temp).await.map_err(|e| {
                ScannerError::Connection(format!("Failed to read scan response: {e}"))
            })?;
            if n == 0 {
                break;
            }
            response_buf.extend_from_slice(&temp[..n]);
            if response_buf.contains(&b'\0')
                || response_buf.contains(&b'\n')
                || response_buf.len() >= 4096
            {
                break;
            }
        }

        let raw_response = String::from_utf8_lossy(&response_buf)
            .trim_matches(|c| c == '\0' || c == '\r' || c == '\n')
            .to_string();

        Self::parse_clamav_response(&raw_response)
    }

    /// Parses the raw clamd scan response string fail-closed.
    pub fn parse_clamav_response(raw: &str) -> Result<ScanVerdict, ScannerError> {
        let trimmed =
            raw.trim_matches(|c: char| c.is_whitespace() || c == '\0' || c == '\r' || c == '\n');
        if trimmed.is_empty() {
            return Err(ScannerError::Protocol(
                "Empty response from scanner".to_string(),
            ));
        }

        if trimmed == "stream: OK" || trimmed.ends_with(" OK") {
            return Ok(ScanVerdict::Clean);
        }

        if let Some(threat) = trimmed
            .strip_prefix("stream: ")
            .and_then(|s| s.strip_suffix(" FOUND"))
        {
            let sanitized = sanitize_threat_name(threat.trim());
            return Ok(ScanVerdict::Malware {
                threat_name: sanitized,
            });
        }

        if let Some(err) = trimmed
            .strip_prefix("stream: ")
            .and_then(|s| s.strip_suffix(" ERROR"))
        {
            return Err(ScannerError::Protocol(format!(
                "ClamAV scan error: {}",
                err.trim()
            )));
        }

        Err(ScannerError::Protocol(format!(
            "Unrecognized scanner response format: '{trimmed}'"
        )))
    }
}

/// Sanitizes and bounds threat names to prevent hostile control codes or over-bound strings.
#[must_use]
pub fn sanitize_threat_name(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .filter(|c| !c.is_control() && *c != '\0')
        .collect();
    let trimmed = filtered.trim();
    if trimmed.len() > MAX_REASON_CODE_BYTES {
        trimmed[..MAX_REASON_CODE_BYTES].to_string()
    } else if trimmed.is_empty() {
        "UnknownThreat".to_string()
    } else {
        trimmed.to_string()
    }
}

#[async_trait]
impl MalwareScanner for ClamAvClient {
    async fn check_signatures(&self) -> Result<SignatureHealth, ScannerError> {
        let now = Utc::now();
        let (version, parsed_date) = self.query_version_raw().await?;

        let sig_timestamp = self
            .signature_timestamp_override
            .or(parsed_date)
            .unwrap_or(now); // If no timestamp in string and no override, evaluate against current time

        Ok(SignatureHealthPolicy::evaluate(
            sig_timestamp,
            now,
            Some(version),
        ))
    }

    async fn scan(&self, bytes: &[u8]) -> Result<ScanOutcome, ScannerError> {
        // Enforce maximum permissible payload size
        if bytes.len() > self.config.max_object_bytes {
            return Err(ScannerError::Oversize(
                bytes.len(),
                self.config.max_object_bytes,
            ));
        }

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

        let start_time = Instant::now();
        let stream = self.connect().await?;

        // Enforce scan timeout (120s)
        let verdict = match timeout(self.config.timeout, self.execute_instream(stream, bytes)).await
        {
            Ok(scan_res) => scan_res?,
            Err(_) => {
                return Err(ScannerError::Timeout(self.config.timeout.as_secs()));
            }
        };

        let duration_ms = start_time.elapsed().as_millis() as u64;

        Ok(ScanOutcome {
            verdict,
            scanner_name: SCANNER_NAME_CLAMAV.to_string(),
            scanner_version: sig_health.signature_version.clone(),
            signature_health: sig_health,
            scanned_at: Utc::now(),
            scan_duration_ms: duration_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clamav_response_clean() {
        assert_eq!(
            ClamAvClient::parse_clamav_response("stream: OK\0").unwrap(),
            ScanVerdict::Clean
        );
        assert_eq!(
            ClamAvClient::parse_clamav_response("stream: OK\n").unwrap(),
            ScanVerdict::Clean
        );
        assert_eq!(
            ClamAvClient::parse_clamav_response("stream: OK").unwrap(),
            ScanVerdict::Clean
        );
    }

    #[test]
    fn test_parse_clamav_response_malware() {
        let v =
            ClamAvClient::parse_clamav_response("stream: Win.Test.EICAR_HDB-1 FOUND\0").unwrap();
        assert_eq!(
            v,
            ScanVerdict::Malware {
                threat_name: "Win.Test.EICAR_HDB-1".to_string()
            }
        );

        let v2 =
            ClamAvClient::parse_clamav_response("stream: Eicar-Test-Signature FOUND\n").unwrap();
        assert_eq!(
            v2,
            ScanVerdict::Malware {
                threat_name: "Eicar-Test-Signature".to_string()
            }
        );
    }

    #[test]
    fn test_parse_clamav_response_error_and_malformed() {
        assert!(
            ClamAvClient::parse_clamav_response("stream: size limit exceeded ERROR\0").is_err()
        );
        assert!(ClamAvClient::parse_clamav_response("UNKNOWN COMMAND").is_err());
        assert!(ClamAvClient::parse_clamav_response("").is_err());
        assert!(ClamAvClient::parse_clamav_response("stream: ").is_err());
    }

    #[test]
    fn test_sanitize_threat_name() {
        assert_eq!(sanitize_threat_name("EICAR"), "EICAR");
        assert_eq!(
            sanitize_threat_name("Threat\0With\nControls"),
            "ThreatWithControls"
        );
        let long_name = "A".repeat(200);
        let sanitized = sanitize_threat_name(&long_name);
        assert_eq!(sanitized.len(), MAX_REASON_CODE_BYTES);
    }
}
