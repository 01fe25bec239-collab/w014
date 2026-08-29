//! Runtime configuration and limits for the ClamAV clamd INSTREAM scanner.

use std::time::Duration;

/// Default clamd TCP host.
pub const DEFAULT_CLAMAV_HOST: &str = "127.0.0.1";

/// Default clamd TCP port.
pub const DEFAULT_CLAMAV_PORT: u16 = 3310;

/// Frozen scan timeout: 120 seconds for one P0 object up to 100 MiB.
pub const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 120;

/// Default streaming chunk size: 64 KiB.
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum allowable object size for scanning: 100 MiB.
pub const MAX_SCAN_OBJECT_BYTES: usize = 100 * 1024 * 1024;

/// ClamAV connection and runtime execution configuration.
#[derive(Debug, Clone)]
pub struct ClamAvConfig {
    /// Host address of the ClamAV clamd daemon.
    pub host: String,
    /// Port of the ClamAV clamd daemon.
    pub port: u16,
    /// Maximum scan timeout (enforces 120s limit).
    pub timeout: Duration,
    /// Size of chunks streamed over INSTREAM protocol.
    pub chunk_size: usize,
    /// Maximum permissible payload size.
    pub max_object_bytes: usize,
}

impl Default for ClamAvConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_CLAMAV_HOST.to_string(),
            port: DEFAULT_CLAMAV_PORT,
            timeout: Duration::from_secs(DEFAULT_SCAN_TIMEOUT_SECS),
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_object_bytes: MAX_SCAN_OBJECT_BYTES,
        }
    }
}

impl ClamAvConfig {
    /// Creates configuration using custom host and port with standard timeout defaults.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            ..Default::default()
        }
    }

    /// Loads configuration from environment variables with fallback to defaults.
    #[must_use]
    pub fn from_env() -> Self {
        let host =
            std::env::var("W014_CLAMAV_HOST").unwrap_or_else(|_| DEFAULT_CLAMAV_HOST.to_string());
        let port = std::env::var("W014_CLAMAV_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(DEFAULT_CLAMAV_PORT);
        let timeout_secs = std::env::var("W014_CLAMAV_TIMEOUT_SECS")
            .ok()
            .and_then(|t| t.parse().ok())
            .unwrap_or(DEFAULT_SCAN_TIMEOUT_SECS);

        Self {
            host,
            port,
            timeout: Duration::from_secs(timeout_secs),
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_object_bytes: MAX_SCAN_OBJECT_BYTES,
        }
    }
}
