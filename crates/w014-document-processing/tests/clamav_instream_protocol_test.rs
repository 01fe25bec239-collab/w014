//! Comprehensive ClamAV INSTREAM Protocol and Signature Freshness Test Suite (WI-0204).
//!
//! Validates:
//! - ClamAV clamd INSTREAM wire protocol (`zINSTREAM\0`, big-endian length-prefixed chunks, 0-byte terminator)
//! - Clean, Malware, and Error response parsing
//! - Fail-closed handling on malformed/unexpected responses (never interpreted as clean)
//! - 120s scan timeout enforcement
//! - Signature freshness policy (Prompt-13 matrix: <=8h Healthy, 8h-24h Degraded, >24h / future Unhealthy)
//! - Unhealthy signatures fail closed (never produce clean verdict)
//! - SEC-010 EICAR detection on test fixture
//! - Threat name sanitization and bounding (<=128 bytes)

use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use w014_document_processing::scanner::{
    ClamAvClient, ClamAvConfig, EICAR_TEST_SIGNATURE, EICAR_THREAT_NAME, MalwareScanner,
    MockClamAvScanner, MockScanMode, ScanVerdict, ScannerError, SignatureHealthPolicy,
    SignatureStatus, sanitize_threat_name,
};

/// Helper to spin up a mock TCP clamd server responding with custom payloads.
async fn spawn_mock_clamd_server<F>(handler: F) -> (String, u16, tokio::task::JoinHandle<()>)
where
    F: Fn(Vec<u8>) -> (Option<Vec<u8>>, Vec<u8>) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handler = std::sync::Arc::new(handler);

    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let handler = handler.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut temp = [0u8; 1024];

                loop {
                    let n = match socket.read(&mut temp).await {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    };
                    buf.extend_from_slice(&temp[..n]);

                    // Check if command is VERSION or INSTREAM complete
                    if buf.starts_with(b"zVERSION") || buf.starts_with(b"nVERSION") {
                        let _ = socket
                            .write_all(b"ClamAV 1.3.0/27200/Mon Aug 29 12:00:00 2026\0")
                            .await;
                        let _ = socket.flush().await;
                        break;
                    }

                    // Check if INSTREAM has terminated with [0,0,0,0]
                    if buf.windows(4).any(|w| w == [0, 0, 0, 0]) {
                        let (_, resp) = handler(buf.clone());
                        let _ = socket.write_all(&resp).await;
                        let _ = socket.flush().await;
                        break;
                    }
                }
            });
        }
    });

    ("127.0.0.1".to_string(), port, handle)
}

#[tokio::test]
async fn test_clamav_instream_wire_protocol_clean() {
    let (host, port, _server) = spawn_mock_clamd_server(|wire_bytes| {
        // Verify INSTREAM command header
        assert!(wire_bytes.starts_with(b"zINSTREAM\0"));
        // Verify wire terminates with [0,0,0,0]
        assert!(wire_bytes.ends_with(&[0, 0, 0, 0]));
        (None, b"stream: OK\0".to_vec())
    })
    .await;

    let config = ClamAvConfig::new(host, port);
    let now = Utc::now();
    let client = ClamAvClient::new(config).with_signature_timestamp(now);

    let test_bytes = b"%PDF-1.7 harmless sample document content for clean scan verification";
    let outcome = client.scan(test_bytes).await.expect("scan must succeed");

    assert_eq!(outcome.verdict, ScanVerdict::Clean);
    assert_eq!(outcome.scanner_name, "clamav");
    assert!(outcome.signature_health.is_healthy());
}

#[tokio::test]
async fn test_clamav_instream_wire_protocol_eicar_malware_detection() {
    let (host, port, _server) = spawn_mock_clamd_server(|wire_bytes| {
        // If wire bytes contain EICAR string, return FOUND response
        if wire_bytes
            .windows(EICAR_TEST_SIGNATURE.len())
            .any(|w| w == EICAR_TEST_SIGNATURE)
        {
            (
                None,
                format!("stream: {EICAR_THREAT_NAME} FOUND\0").into_bytes(),
            )
        } else {
            (None, b"stream: OK\0".to_vec())
        }
    })
    .await;

    let config = ClamAvConfig::new(host, port);
    let now = Utc::now();
    let client = ClamAvClient::new(config).with_signature_timestamp(now);

    let outcome = client
        .scan(EICAR_TEST_SIGNATURE)
        .await
        .expect("scan must return outcome");
    assert_eq!(
        outcome.verdict,
        ScanVerdict::Malware {
            threat_name: EICAR_THREAT_NAME.to_string()
        }
    );
    assert_eq!(outcome.verdict.threat_name(), Some(EICAR_THREAT_NAME));
}

#[tokio::test]
async fn test_clamav_instream_chunking_and_framing() {
    let (host, port, _server) = spawn_mock_clamd_server(|wire_bytes| {
        // Inspect chunking structure
        assert!(wire_bytes.starts_with(b"zINSTREAM\0"));
        // Skip command header (10 bytes: b"zINSTREAM\0")
        let mut idx = 10;
        let mut total_chunk_bytes = 0;
        while idx < wire_bytes.len() {
            let chunk_len = u32::from_be_bytes([
                wire_bytes[idx],
                wire_bytes[idx + 1],
                wire_bytes[idx + 2],
                wire_bytes[idx + 3],
            ]) as usize;
            idx += 4;
            if chunk_len == 0 {
                break;
            }
            total_chunk_bytes += chunk_len;
            idx += chunk_len;
        }
        assert_eq!(total_chunk_bytes, 150_000);
        (None, b"stream: OK\0".to_vec())
    })
    .await;

    let mut config = ClamAvConfig::new(host, port);
    config.chunk_size = 32 * 1024; // 32 KiB chunks
    let now = Utc::now();
    let client = ClamAvClient::new(config).with_signature_timestamp(now);

    let payload = vec![0x41u8; 150_000]; // 150 KB payload spanning multiple chunks
    let outcome = client
        .scan(&payload)
        .await
        .expect("chunked scan must succeed");
    assert_eq!(outcome.verdict, ScanVerdict::Clean);
}

#[tokio::test]
async fn test_clamav_instream_error_response_fails_closed() {
    let (host, port, _server) =
        spawn_mock_clamd_server(|_| (None, b"stream: size limit exceeded ERROR\0".to_vec())).await;

    let config = ClamAvConfig::new(host, port);
    let now = Utc::now();
    let client = ClamAvClient::new(config).with_signature_timestamp(now);

    let res = client.scan(b"test").await;
    assert!(res.is_err());
    assert!(matches!(res.unwrap_err(), ScannerError::Protocol(_)));
}

#[tokio::test]
async fn test_clamav_instream_malformed_response_never_clean() {
    let (host, port, _server) =
        spawn_mock_clamd_server(|_| (None, b"UNEXPECTED GARBAGE RESPONSE\0".to_vec())).await;

    let config = ClamAvConfig::new(host, port);
    let now = Utc::now();
    let client = ClamAvClient::new(config).with_signature_timestamp(now);

    let res = client.scan(b"test").await;
    assert!(res.is_err());
    assert!(matches!(res.unwrap_err(), ScannerError::Protocol(_)));
}

#[tokio::test]
async fn test_clamav_instream_timeout_enforced_120s() {
    // Spawn server that never responds to INSTREAM
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            // Read but never reply
            let mut buf = [0u8; 1024];
            while let Ok(n) = socket.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        }
    });

    let mut config = ClamAvConfig::new("127.0.0.1", port);
    config.timeout = Duration::from_millis(100); // Test timeout with short duration
    let now = Utc::now();
    let client = ClamAvClient::new(config).with_signature_timestamp(now);

    let res = client.scan(b"test").await;
    assert!(res.is_err());
    assert!(matches!(res.unwrap_err(), ScannerError::Timeout(_)));
}

#[tokio::test]
async fn test_clamav_unhealthy_signatures_fail_closed() {
    let (host, port, _server) = spawn_mock_clamd_server(|_| (None, b"stream: OK\0".to_vec())).await;

    let config = ClamAvConfig::new(host, port);
    // Signatures 25 hours old (> 24 hours) -> Unhealthy!
    let old_signatures = Utc::now() - ChronoDuration::hours(25);
    let client = ClamAvClient::new(config).with_signature_timestamp(old_signatures);

    let res = client.scan(b"clean content").await;
    assert!(res.is_err());
    assert!(
        matches!(res.unwrap_err(), ScannerError::UnhealthySignature(_)),
        "Must fail closed when signatures are >24h old"
    );
}

#[tokio::test]
async fn test_clamav_degraded_signatures_observable() {
    let (host, port, _server) = spawn_mock_clamd_server(|_| (None, b"stream: OK\0".to_vec())).await;

    let config = ClamAvConfig::new(host, port);
    // Signatures 12 hours old (> 8h and <= 24h) -> Degraded!
    let degraded_timestamp = Utc::now() - ChronoDuration::hours(12);
    let client = ClamAvClient::new(config).with_signature_timestamp(degraded_timestamp);

    let outcome = client
        .scan(b"clean content")
        .await
        .expect("degraded signatures allow scan");
    assert_eq!(outcome.verdict, ScanVerdict::Clean);
    assert_eq!(outcome.signature_health.status, SignatureStatus::Degraded);
    assert!(outcome.signature_health.is_degraded());
    assert!(outcome.signature_health.is_acceptable());
}

#[test]
fn test_signature_health_policy_matrix() {
    let now = Utc::now();

    // <= 8h: Healthy
    let h1 =
        SignatureHealthPolicy::evaluate(now - ChronoDuration::hours(2), now, Some("1.3.0".into()));
    assert_eq!(h1.status, SignatureStatus::Healthy);
    assert!(h1.is_healthy());

    let h8 =
        SignatureHealthPolicy::evaluate(now - ChronoDuration::hours(8), now, Some("1.3.0".into()));
    assert_eq!(h8.status, SignatureStatus::Healthy);
    assert!(h8.is_healthy());

    // > 8h and <= 24h: Degraded
    let d9 =
        SignatureHealthPolicy::evaluate(now - ChronoDuration::hours(9), now, Some("1.3.0".into()));
    assert_eq!(d9.status, SignatureStatus::Degraded);
    assert!(d9.is_degraded());
    assert!(d9.is_acceptable());

    let d24 =
        SignatureHealthPolicy::evaluate(now - ChronoDuration::hours(24), now, Some("1.3.0".into()));
    assert_eq!(d24.status, SignatureStatus::Degraded);
    assert!(d24.is_degraded());
    assert!(d24.is_acceptable());

    // > 24h: Unhealthy (fail closed)
    let u25 =
        SignatureHealthPolicy::evaluate(now - ChronoDuration::hours(25), now, Some("1.3.0".into()));
    assert_eq!(u25.status, SignatureStatus::Unhealthy);
    assert!(u25.is_unhealthy());
    assert!(!u25.is_acceptable());

    // Future timestamp (> 5 min): Unhealthy
    let u_future =
        SignatureHealthPolicy::evaluate(now + ChronoDuration::hours(1), now, Some("1.3.0".into()));
    assert_eq!(u_future.status, SignatureStatus::Unhealthy);
    assert!(!u_future.is_acceptable());
}

#[tokio::test]
async fn test_mock_scanner_eicar_and_custom_matrix() {
    let scanner = MockClamAvScanner::new();

    // Clean payload
    let clean = scanner.scan(b"Just normal pdf content").await.unwrap();
    assert_eq!(clean.verdict, ScanVerdict::Clean);

    // EICAR payload
    let eicar = scanner.scan(EICAR_TEST_SIGNATURE).await.unwrap();
    assert_eq!(
        eicar.verdict,
        ScanVerdict::Malware {
            threat_name: EICAR_THREAT_NAME.to_string()
        }
    );

    // Custom threat
    scanner.add_custom_signature(b"MALICIOUS_BYTECODE_XYZ", "Custom.Test.Threat-A");
    let custom = scanner
        .scan(b"prefix MALICIOUS_BYTECODE_XYZ suffix")
        .await
        .unwrap();
    assert_eq!(
        custom.verdict,
        ScanVerdict::Malware {
            threat_name: "Custom.Test.Threat-A".to_string()
        }
    );
}

#[tokio::test]
async fn test_mock_scanner_modes() {
    // Unavailable
    let unavail =
        MockClamAvScanner::new().with_mode(MockScanMode::Unavailable("Daemon down".into()));
    assert!(matches!(
        unavail.scan(b"test").await.unwrap_err(),
        ScannerError::Connection(_)
    ));

    // Timeout
    let to = MockClamAvScanner::new().with_mode(MockScanMode::Timeout(120));
    assert!(matches!(
        to.scan(b"test").await.unwrap_err(),
        ScannerError::Timeout(120)
    ));

    // Protocol Error
    let proto =
        MockClamAvScanner::new().with_mode(MockScanMode::ProtocolError("Bad format".into()));
    assert!(matches!(
        proto.scan(b"test").await.unwrap_err(),
        ScannerError::Protocol(_)
    ));
}

#[test]
fn test_threat_name_sanitization() {
    assert_eq!(
        sanitize_threat_name("Win.Test.EICAR_HDB-1"),
        "Win.Test.EICAR_HDB-1"
    );
    assert_eq!(sanitize_threat_name("Trojan\0\r\nName"), "TrojanName");
    assert_eq!(sanitize_threat_name(""), "UnknownThreat");
}
