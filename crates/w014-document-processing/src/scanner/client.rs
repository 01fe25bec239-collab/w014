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
    /// - UNRECOGNIZED_ENGINE_IDENTITY: fails closed with `ScannerError::Protocol`
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

        let engine_str = parts[0].trim();
        if !is_valid_clamav_engine(engine_str) {
            return Err(ScannerError::Protocol(format!(
                "Unrecognized or invalid ClamAV engine identity in VERSION response: '{trimmed}'"
            )));
        }

        if parts.len() < 3 {
            return Err(ScannerError::Protocol(format!(
                "Missing signature timestamp in ClamAV VERSION response: '{trimmed}'"
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
            version: engine_str.to_string(),
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

        let raw_response = String::from_utf8_lossy(&response_buf);

        Self::parse_clamav_response(&raw_response)
    }

    /// Parses the raw clamd scan response string fail-closed.
    ///
    /// The only canonical semantic clean token is exactly `stream: OK`.
    /// Permitted transport terminators are limited to exact clamd transport
    /// framing (terminal `\0`, `\r\n`, or `\n`).
    ///
    /// Leading/trailing ASCII or Unicode whitespace is NOT framing and fails closed.
    pub fn parse_clamav_response(raw: &str) -> Result<ScanVerdict, ScannerError> {
        let unframed = strip_transport_framing(raw);
        if unframed.is_empty() {
            return Err(ScannerError::Protocol(
                "Empty response from scanner".to_string(),
            ));
        }

        if unframed == "stream: OK" {
            return Ok(ScanVerdict::Clean);
        }

        if let Some(threat) = unframed
            .strip_prefix("stream: ")
            .and_then(|s| s.strip_suffix(" FOUND"))
        {
            let threat_trimmed = threat.trim();
            if threat_trimmed.is_empty() {
                return Err(ScannerError::Protocol(
                    "Empty threat name in ClamAV FOUND response".to_string(),
                ));
            }
            let sanitized = sanitize_threat_name(threat_trimmed);
            return Ok(ScanVerdict::Malware {
                threat_name: sanitized,
            });
        }

        if let Some(err) = unframed
            .strip_prefix("stream: ")
            .and_then(|s| s.strip_suffix(" ERROR"))
        {
            let reason = err.trim();
            if reason.is_empty() {
                return Err(ScannerError::Protocol(
                    "ClamAV scan error with empty reason".to_string(),
                ));
            }
            return Err(ScannerError::Protocol(format!(
                "ClamAV scan error: {reason}"
            )));
        }

        Err(ScannerError::Protocol(format!(
            "Unrecognized scanner response format: '{unframed}'"
        )))
    }
}

/// Strips authorized clamd transport framing (terminal `\0`, `\r\n`, or `\n`).
///
/// Whitespace (ASCII space, tab, vertical tab, form feed, non-breaking space,
/// and other Unicode whitespace) is NOT framing and is never stripped.
fn strip_transport_framing(raw: &str) -> &str {
    if let Some(s) = raw.strip_suffix('\0') {
        s
    } else if let Some(s) = raw.strip_suffix("\r\n") {
        s
    } else if let Some(s) = raw.strip_suffix('\n') {
        s
    } else {
        raw
    }
}

/// Positively validates that the engine component identifies a valid ClamAV engine
/// conforming strictly to the canonical `ClamAV <version>` format.
fn is_valid_clamav_engine(engine_str: &str) -> bool {
    let trimmed = engine_str.trim();
    if let Some(version_suffix) = trimmed.strip_prefix("ClamAV ") {
        let version_part = version_suffix.trim();
        !version_part.is_empty()
            && version_part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '+')
    } else {
        false
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
///
/// Truncation is performed strictly at a valid UTF-8 character boundary so that
/// the result is valid UTF-8 and the byte length does not exceed `MAX_REASON_CODE_BYTES` (128).
#[must_use]
pub fn sanitize_threat_name(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .filter(|c| !c.is_control() && *c != '\0')
        .collect();
    let trimmed = filtered.trim();
    if trimmed.is_empty() {
        return "UnknownThreat".to_string();
    }
    if trimmed.len() > MAX_REASON_CODE_BYTES {
        let mut boundary = MAX_REASON_CODE_BYTES;
        while !trimmed.is_char_boundary(boundary) {
            boundary -= 1;
        }
        let bounded = &trimmed[..boundary];
        if bounded.is_empty() {
            "UnknownThreat".to_string()
        } else {
            bounded.to_string()
        }
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
            ClamAvClient::parse_clamav_response("stream: OK\r\n").unwrap(),
            ScanVerdict::Clean
        );
        assert_eq!(
            ClamAvClient::parse_clamav_response("stream: OK").unwrap(),
            ScanVerdict::Clean
        );
    }

    #[test]
    fn test_parse_clamav_response_clean_negative_matrix_fails_closed() {
        let malformed_clean_cases = [
            "  stream: OK  ",
            " stream: OK",
            "stream: OK ",
            "  stream: OK",
            "stream: OK  ",
            "\tstream: OK",
            "stream: OK\t",
            "\tstream: OK\t",
            "\u{00A0}stream: OK",
            "stream: OK\u{00A0}",
            "\u{2003}stream: OK",
            "stream: OK\u{2003}",
            "\x0bstream: OK",
            "stream: OK\x0b",
            "\x0cstream: OK",
            "stream: OK\x0c",
            " stream: OK\0",
            "stream: OK \0",
            "\tstream: OK\0",
            "stream: OK\t\0",
            " stream: OK\n",
            "stream: OK \n",
            "\tstream: OK\n",
            "stream: OK\t\n",
            " stream: OK\r\n",
            "stream: OK \r\n",
            "\tstream: OK\r\n",
            "stream: OK\t\r\n",
            "stream: OK\0\0",
            "stream: OK\n\n",
            "stream: OK\r\n\r\n",
            "\0stream: OK",
            "\nstream: OK",
            "\r\nstream: OK",
            "stream: OK\nstream: OK\n",
            "UNKNOWN SERVER OK",
            "foo: OK",
            "stream: MAYBE OK",
            "stream: UNKNOWN OK",
            "OK",
            "prefix stream: OK",
            "stream: OK suffix",
            "stream: OK OK",
            "stream: FOUND OK",
            "stream: ERROR OK",
            "UNKNOWN_ENGINE OK",
            "arbitrary/slash/delimited/text OK",
            "foo/bar/baz OK",
            "something\nstream: OK",
            "stream:\nOK",
            "stream: OK\nsomething",
            "",
            "   ",
            "\t",
            "\0",
            "\r\n",
            "\n",
        ];

        for case in malformed_clean_cases {
            let res = ClamAvClient::parse_clamav_response(case);
            assert!(
                res.is_err(),
                "Case '{case:?}' must fail closed with error, but got {res:?}"
            );
        }
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

        let v3 = ClamAvClient::parse_clamav_response("stream: Trojan.Generic FOUND").unwrap();
        assert_eq!(
            v3,
            ScanVerdict::Malware {
                threat_name: "Trojan.Generic".to_string()
            }
        );

        // Malformed FOUND responses must fail closed
        assert!(ClamAvClient::parse_clamav_response("stream:  FOUND").is_err());
        assert!(ClamAvClient::parse_clamav_response("stream: FOUND").is_err());
        assert!(ClamAvClient::parse_clamav_response("UNKNOWN FOUND").is_err());
        assert!(ClamAvClient::parse_clamav_response("foo: threat FOUND").is_err());
        assert!(ClamAvClient::parse_clamav_response("stream: threat FOUND OK").is_err());
    }

    #[test]
    fn test_parse_clamav_response_error_and_malformed() {
        assert!(
            ClamAvClient::parse_clamav_response("stream: size limit exceeded ERROR\0").is_err()
        );
        assert!(ClamAvClient::parse_clamav_response("stream: temporary failure ERROR").is_err());
        assert!(ClamAvClient::parse_clamav_response("UNKNOWN ERROR").is_err());
        assert!(ClamAvClient::parse_clamav_response("foo: error ERROR").is_err());
        assert!(ClamAvClient::parse_clamav_response("stream: ERROR OK").is_err());
        assert!(ClamAvClient::parse_clamav_response("stream: ERROR").is_err());
        assert!(ClamAvClient::parse_clamav_response("stream:  ERROR").is_err());
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
    fn test_parse_clamav_version_response_unknown_or_foreign_engine_fail_closed() {
        // UNKNOWN_ENGINE with valid fresh timestamp
        assert!(
            ClamAvClient::parse_clamav_version_response(
                "UNKNOWN_ENGINE/27200/Sat Aug 29 12:00:00 2026"
            )
            .is_err()
        );
        // FOREIGN_ENGINE with valid ISO timestamp
        assert!(
            ClamAvClient::parse_clamav_version_response(
                "FOREIGN_ENGINE/27200/2026-08-29T12:00:00Z"
            )
            .is_err()
        );
        // NOTCLAMAV with valid fresh timestamp
        assert!(
            ClamAvClient::parse_clamav_version_response("NOTCLAMAV/27200/Sat Aug 29 12:00:00 2026")
                .is_err()
        );
        // Lookalike ClamAVish with valid fresh timestamp
        assert!(
            ClamAvClient::parse_clamav_version_response(
                "ClamAVish 1.0/27200/Sat Aug 29 12:00:00 2026"
            )
            .is_err()
        );
        // CLAMAVISH
        assert!(
            ClamAvClient::parse_clamav_version_response("CLAMAVISH/27200/Sat Aug 29 12:00:00 2026")
                .is_err()
        );
        // Uppercase CLAMAV
        assert!(
            ClamAvClient::parse_clamav_version_response(
                "CLAMAV 1.3.0/27200/Sat Aug 29 12:00:00 2026"
            )
            .is_err()
        );
        // Lowercase clamav
        assert!(
            ClamAvClient::parse_clamav_version_response(
                "clamav 1.3.0/27200/Sat Aug 29 12:00:00 2026"
            )
            .is_err()
        );
        // Empty engine field
        assert!(
            ClamAvClient::parse_clamav_version_response("/27200/Sat Aug 29 12:00:00 2026").is_err()
        );
        // Just "ClamAV" without version
        assert!(
            ClamAvClient::parse_clamav_version_response("ClamAV/27200/Sat Aug 29 12:00:00 2026")
                .is_err()
        );
        assert!(
            ClamAvClient::parse_clamav_version_response("ClamAV /27200/Sat Aug 29 12:00:00 2026")
                .is_err()
        );
        // Non-slash single component foreign engine
        assert!(ClamAvClient::parse_clamav_version_response("UNKNOWN_ENGINE").is_err());
        assert!(ClamAvClient::parse_clamav_version_response("FOREIGN_ENGINE").is_err());
    }

    #[test]
    fn test_sanitize_threat_name() {
        assert_eq!(sanitize_threat_name("EICAR"), "EICAR");
        assert_eq!(
            sanitize_threat_name("Threat\0With\nControls"),
            "ThreatWithControls"
        );
        assert_eq!(sanitize_threat_name(""), "UnknownThreat");
        assert_eq!(sanitize_threat_name("   "), "UnknownThreat");
        assert_eq!(sanitize_threat_name("\0\r\n\t"), "UnknownThreat");

        let long_name = "A".repeat(200);
        let sanitized = sanitize_threat_name(&long_name);
        assert_eq!(sanitized.len(), MAX_REASON_CODE_BYTES);
    }

    #[test]
    fn test_sanitize_threat_name_utf8_truncation_no_panic() {
        // 127 ASCII bytes + 2-byte character ('é' = 2 bytes) -> byte 128 is inside 'é'
        let input_127_2b = format!("{}é", "A".repeat(127));
        let sanitized_127_2b = sanitize_threat_name(&input_127_2b);
        assert_eq!(sanitized_127_2b.len(), 127);
        assert_eq!(sanitized_127_2b, "A".repeat(127));
        assert!(sanitized_127_2b.len() <= MAX_REASON_CODE_BYTES);

        // 127 ASCII bytes + 3-byte character ('€' = 3 bytes) -> byte 128 is inside '€'
        let input_127_3b = format!("{}€", "A".repeat(127));
        let sanitized_127_3b = sanitize_threat_name(&input_127_3b);
        assert_eq!(sanitized_127_3b.len(), 127);
        assert_eq!(sanitized_127_3b, "A".repeat(127));
        assert!(sanitized_127_3b.len() <= MAX_REASON_CODE_BYTES);

        // 127 ASCII bytes + 4-byte emoji ('🦀' = 4 bytes) -> byte 128 is inside '🦀'
        let input_127_4b = format!("{}🦀", "A".repeat(127));
        let sanitized_127_4b = sanitize_threat_name(&input_127_4b);
        assert_eq!(sanitized_127_4b.len(), 127);
        assert_eq!(sanitized_127_4b, "A".repeat(127));
        assert!(sanitized_127_4b.len() <= MAX_REASON_CODE_BYTES);

        // Long two-byte code points: 'é' (2 bytes each) x 100 = 200 bytes
        let input_2b = "é".repeat(100);
        let sanitized_2b = sanitize_threat_name(&input_2b);
        assert_eq!(sanitized_2b.len(), 128); // 64 x 2 = 128
        assert_eq!(sanitized_2b, "é".repeat(64));
        assert!(sanitized_2b.len() <= MAX_REASON_CODE_BYTES);

        // 1 ASCII + Long two-byte code points: 1 byte + 'é'*100 (200 bytes) -> boundary lands inside 64th 'é'
        let input_1_2b = format!("X{}", "é".repeat(100));
        let sanitized_1_2b = sanitize_threat_name(&input_1_2b);
        assert_eq!(sanitized_1_2b.len(), 127); // 1 + 63*2 = 127
        assert_eq!(sanitized_1_2b, format!("X{}", "é".repeat(63)));
        assert!(sanitized_1_2b.len() <= MAX_REASON_CODE_BYTES);

        // Long three-byte code points: '€' (3 bytes each) x 60 = 180 bytes
        let input_3b = "€".repeat(60);
        let sanitized_3b = sanitize_threat_name(&input_3b);
        assert_eq!(sanitized_3b.len(), 126); // 42 x 3 = 126
        assert_eq!(sanitized_3b, "€".repeat(42));
        assert!(sanitized_3b.len() <= MAX_REASON_CODE_BYTES);

        // Long four-byte emoji: '🦀' (4 bytes each) x 50 = 200 bytes
        let input_4b = "🦀".repeat(50);
        let sanitized_4b = sanitize_threat_name(&input_4b);
        assert_eq!(sanitized_4b.len(), 128); // 32 x 4 = 128
        assert_eq!(sanitized_4b, "🦀".repeat(32));
        assert!(sanitized_4b.len() <= MAX_REASON_CODE_BYTES);

        // 1 ASCII + Long four-byte emoji: 1 byte + '🦀'*50 (200 bytes) -> boundary lands inside 32nd '🦀'
        let input_1_4b = format!("X{}", "🦀".repeat(50));
        let sanitized_1_4b = sanitize_threat_name(&input_1_4b);
        assert_eq!(sanitized_1_4b.len(), 125); // 1 + 31*4 = 125
        assert_eq!(sanitized_1_4b, format!("X{}", "🦀".repeat(31)));
        assert!(sanitized_1_4b.len() <= MAX_REASON_CODE_BYTES);

        // Control characters + multibyte content
        let input_ctrl_mb = "Trojan\0\r\n\x07\x1b🦀.Variant.€é\0";
        let sanitized_ctrl_mb = sanitize_threat_name(input_ctrl_mb);
        assert_eq!(sanitized_ctrl_mb, "Trojan🦀.Variant.€é");

        // Long multibyte response through parse_clamav_response
        let long_found_resp = format!("stream: {} FOUND\0", "🦀".repeat(50));
        let verdict = ClamAvClient::parse_clamav_response(&long_found_resp).unwrap();
        assert_eq!(
            verdict,
            ScanVerdict::Malware {
                threat_name: "🦀".repeat(32)
            }
        );

        // Long multibyte 127-boundary through parse_clamav_response
        let boundary_found_resp = format!("stream: {}{} FOUND\n", "A".repeat(127), "🦀");
        let verdict_boundary = ClamAvClient::parse_clamav_response(&boundary_found_resp).unwrap();
        assert_eq!(
            verdict_boundary,
            ScanVerdict::Malware {
                threat_name: "A".repeat(127)
            }
        );
    }
}
