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

/// Parsed information from an authoritative ClamAV VERSION response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClamAvVersionInfo {
    /// Scanner engine version (e.g. "ClamAV 1.3.0").
    pub version: String,
    /// Signature database version/patch (e.g. "27200").
    pub signature_version: Option<String>,
    /// Authoritative parsed signature timestamp.
    pub signature_timestamp: DateTime<Utc>,
}

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
    pub async fn query_version_raw(&self) -> Result<ClamAvVersionInfo, ScannerError> {
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

            Self::parse_clamav_version_response(&raw)
        };

        match timeout(self.config.timeout, fut).await {
            Ok(res) => res,
            Err(_) => Err(ScannerError::Timeout(self.config.timeout.as_secs())),
        }
    }

    /// Parses the raw clamd VERSION response string fail-closed.
    ///
    /// Distinguishes:
    /// - VALID_PARSED_SIGNATURE_TIMESTAMP: produces `Ok(ClamAvVersionInfo)`
    /// - MISSING_SIGNATURE_TIMESTAMP: fails closed with `ScannerError::Protocol`
    /// - MALFORMED_SIGNATURE_TIMESTAMP: fails closed with `ScannerError::Protocol`
    /// - UNRECOGNIZED_VERSION_RESPONSE: fails closed with `ScannerError::Protocol`
    pub fn parse_clamav_version_response(raw: &str) -> Result<ClamAvVersionInfo, ScannerError> {
        let trimmed =
            raw.trim_matches(|c: char| c.is_whitespace() || c == '\0' || c == '\r' || c == '\n');
        if trimmed.is_empty() {
            return Err(ScannerError::Protocol(
                "Empty VERSION response from ClamAV".to_string(),
            ));
        }

        // Standard ClamAV response format: "ClamAV 1.3.0/27200/Mon Aug 29 12:00:00 2026"
        let parts: Vec<&str> = trimmed.split('/').collect();
        if parts.len() < 3 {
            if parts.len() == 1 && !trimmed.starts_with("ClamAV") {
                return Err(ScannerError::Protocol(format!(
                    "Unrecognized ClamAV VERSION response format: '{trimmed}'"
                )));
            }
            return Err(ScannerError::Protocol(format!(
                "Missing signature timestamp in ClamAV VERSION response: '{trimmed}'"
            )));
        }

        let version_str = parts[0].trim();
        if version_str.is_empty() {
            return Err(ScannerError::Protocol(format!(
                "Missing scanner engine version in ClamAV VERSION response: '{trimmed}'"
            )));
        }

        let sig_version_str = parts[1].trim();
        let sig_version = if sig_version_str.is_empty() {
            None
        } else {
            Some(sig_version_str.to_string())
        };

        let date_str = parts[2..].join("/").trim().to_string();
        if date_str.is_empty() {
            return Err(ScannerError::Protocol(format!(
                "Missing signature timestamp in ClamAV VERSION response: '{trimmed}'"
            )));
        }

        let parsed_date = parse_clamav_date(&date_str)?;

        Ok(ClamAvVersionInfo {
            version: version_str.to_string(),
            signature_version: sig_version,
            signature_timestamp: parsed_date,
        })
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

/// Parses ClamAV signature date strings across known standard formats.
///
/// Supports:
/// - RFC 2822 (e.g. "Mon, 29 Aug 2026 12:00:00 +0000")
/// - RFC 3339 / ISO 8601 (e.g. "2026-08-29T12:00:00Z")
/// - ctime format with timezone offset (e.g. "Mon Aug 29 12:00:00 2026 +0000")
/// - Standard ClamAV ctime format without timezone (assumed UTC):
///   e.g. "Mon Aug 29 12:00:00 2026", "Sun Aug  9 12:00:00 2026", "Sun Aug 09 12:00:00 2026"
pub fn parse_clamav_date(date_str: &str) -> Result<DateTime<Utc>, ScannerError> {
    let trimmed = date_str.trim();
    if trimmed.is_empty() {
        return Err(ScannerError::Protocol(
            "Empty signature date in ClamAV VERSION response".to_string(),
        ));
    }

    // 1. RFC 2822
    if let Ok(dt) = DateTime::parse_from_rfc2822(trimmed) {
        return Ok(dt.with_timezone(&Utc));
    }

    // 2. RFC 3339 / ISO 8601
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(dt.with_timezone(&Utc));
    }

    // 3. ctime format with timezone: "%a %b %e %H:%M:%S %Y %z" or "%a %b %d %H:%M:%S %Y %z"
    if let Ok(dt) = DateTime::parse_from_str(trimmed, "%a %b %e %H:%M:%S %Y %z") {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_str(trimmed, "%a %b %d %H:%M:%S %Y %z") {
        return Ok(dt.with_timezone(&Utc));
    }

    // 4. Standard ClamAV ctime format without timezone (assumed UTC):
    for fmt in &[
        "%a %b %e %H:%M:%S %Y",
        "%a %b %d %H:%M:%S %Y",
        "%a %b %_d %H:%M:%S %Y",
        "%a %b %e %T %Y",
        "%a %b %d %T %Y",
        "%Y-%m-%d %H:%M:%S",
        "%b %e %H:%M:%S %Y",
        "%b %d %H:%M:%S %Y",
        "%b %_d %H:%M:%S %Y",
    ] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, fmt) {
            return Ok(naive.and_utc());
        }
    }

    // 5. If string starts with a weekday prefix (e.g. "Mon, " or "Mon "), strip and try parsing rest:
    if let Some((_weekday, rest)) = trimmed.split_once(' ') {
        let rest = rest.trim_start_matches(',').trim();
        if let Ok(dt) = DateTime::parse_from_rfc2822(rest) {
            return Ok(dt.with_timezone(&Utc));
        }
        for fmt in &[
            "%b %e %H:%M:%S %Y",
            "%b %d %H:%M:%S %Y",
            "%b %_d %H:%M:%S %Y",
            "%b %e %T %Y",
            "%b %d %T %Y",
            "%d %b %Y %H:%M:%S",
            "%e %b %Y %H:%M:%S",
        ] {
            if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(rest, fmt) {
                return Ok(naive.and_utc());
            }
        }
    }

    Err(ScannerError::Protocol(format!(
        "Malformed or unparseable signature timestamp in ClamAV VERSION response: '{trimmed}'"
    )))
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

        if let Some(override_ts) = self.signature_timestamp_override {
            let version_str = match self.query_version_raw().await {
                Ok(info) => Some(info.version),
                Err(_) => None,
            };
            return Ok(SignatureHealthPolicy::evaluate(
                override_ts,
                now,
                version_str,
            ));
        }

        let version_info = self.query_version_raw().await?;

        Ok(SignatureHealthPolicy::evaluate(
            version_info.signature_timestamp,
            now,
            Some(version_info.version),
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
    fn test_parse_clamav_version_response_valid() {
        let res = ClamAvClient::parse_clamav_version_response(
            "ClamAV 1.3.0/27200/Sat Aug 29 12:00:00 2026\0",
        )
        .unwrap();
        assert_eq!(res.version, "ClamAV 1.3.0");
        assert_eq!(res.signature_version.as_deref(), Some("27200"));
        assert_eq!(
            res.signature_timestamp,
            DateTime::parse_from_rfc3339("2026-08-29T12:00:00Z").unwrap()
        );

        // Single digit day with space padding
        let res2 = ClamAvClient::parse_clamav_version_response(
            "ClamAV 1.3.0/27200/Sun Aug  9 12:00:00 2026",
        )
        .unwrap();
        assert_eq!(
            res2.signature_timestamp,
            DateTime::parse_from_rfc3339("2026-08-09T12:00:00Z").unwrap()
        );

        // RFC 2822 format
        let res3 = ClamAvClient::parse_clamav_version_response(
            "ClamAV 1.3.0/27200/Sat, 29 Aug 2026 12:00:00 +0000",
        )
        .unwrap();
        assert_eq!(
            res3.signature_timestamp,
            DateTime::parse_from_rfc3339("2026-08-29T12:00:00Z").unwrap()
        );

        // RFC 3339 format
        let res4 =
            ClamAvClient::parse_clamav_version_response("ClamAV 1.3.0/27200/2026-08-29T12:00:00Z")
                .unwrap();
        assert_eq!(
            res4.signature_timestamp,
            DateTime::parse_from_rfc3339("2026-08-29T12:00:00Z").unwrap()
        );
    }

    #[test]
    fn test_parse_clamav_version_response_missing_timestamp_fail_closed() {
        assert!(ClamAvClient::parse_clamav_version_response("ClamAV 1.3.0").is_err());
        assert!(ClamAvClient::parse_clamav_version_response("ClamAV 1.3.0/27200").is_err());
        assert!(ClamAvClient::parse_clamav_version_response("ClamAV 1.3.0/27200/").is_err());
        assert!(ClamAvClient::parse_clamav_version_response("ClamAV 1.3.0/27200/   ").is_err());
    }

    #[test]
    fn test_parse_clamav_version_response_malformed_timestamp_fail_closed() {
        assert!(
            ClamAvClient::parse_clamav_version_response("ClamAV 1.3.0/27200/NOT_A_DATE").is_err()
        );
        assert!(
            ClamAvClient::parse_clamav_version_response("ClamAV 1.3.0/27200/99-99-9999").is_err()
        );
    }

    #[test]
    fn test_parse_clamav_version_response_unrecognized_fail_closed() {
        assert!(ClamAvClient::parse_clamav_version_response("").is_err());
        assert!(ClamAvClient::parse_clamav_version_response("UNKNOWN COMMAND").is_err());
        assert!(ClamAvClient::parse_clamav_version_response("PONG").is_err());
        assert!(ClamAvClient::parse_clamav_version_response("ERROR: daemon busy").is_err());
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
