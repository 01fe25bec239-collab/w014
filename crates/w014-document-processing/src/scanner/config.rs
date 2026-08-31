//! Runtime configuration and limits for the ClamAV clamd INSTREAM scanner.

use std::time::Duration;

/// Default clamd TCP host.
pub const DEFAULT_CLAMAV_HOST: &str = "127.0.0.1";

/// Default clamd TCP port.
pub const DEFAULT_CLAMAV_PORT: u16 = 3310;

/// Frozen scan timeout: 120 seconds for one P0 object up to 100 MiB.
pub const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 120;

/// Maximum allowable scan timeout ceiling: 120 seconds.
pub const MAX_SCAN_TIMEOUT_SECS: u64 = 120;

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
    ///
    /// The effective scan timeout is bounded by `MAX_SCAN_TIMEOUT_SECS` (120s)
    /// to ensure environment configuration cannot weaken the frozen security ceiling.
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
            .and_then(|t| t.parse::<u64>().ok())
            .unwrap_or(DEFAULT_SCAN_TIMEOUT_SECS)
            .min(MAX_SCAN_TIMEOUT_SECS);

        Self {
            host,
            port,
            timeout: Duration::from_secs(timeout_secs),
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_object_bytes: MAX_SCAN_OBJECT_BYTES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mutex to ensure environment variable tests run without interference from parallel tests.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_clamav_config_timeout_ceiling_matrix() {
        let _guard = ENV_MUTEX.lock().unwrap();

        // Case 1: ENV ABSENT -> default 120 seconds
        unsafe {
            std::env::remove_var("W014_CLAMAV_TIMEOUT_SECS");
        }
        let cfg = ClamAvConfig::from_env();
        assert_eq!(cfg.timeout, Duration::from_secs(DEFAULT_SCAN_TIMEOUT_SECS));
        assert_eq!(cfg.timeout, Duration::from_secs(120));

        // Case 2: ENV = 1 -> 1 second (<= 120 seconds)
        unsafe {
            std::env::set_var("W014_CLAMAV_TIMEOUT_SECS", "1");
        }
        let cfg = ClamAvConfig::from_env();
        assert_eq!(cfg.timeout, Duration::from_secs(1));

        // Case 3: ENV = 120 -> 120 seconds
        unsafe {
            std::env::set_var("W014_CLAMAV_TIMEOUT_SECS", "120");
        }
        let cfg = ClamAvConfig::from_env();
        assert_eq!(cfg.timeout, Duration::from_secs(120));

        // Case 4: ENV = 121 -> clamped to 120 seconds ceiling
        unsafe {
            std::env::set_var("W014_CLAMAV_TIMEOUT_SECS", "121");
        }
        let cfg = ClamAvConfig::from_env();
        assert_eq!(cfg.timeout, Duration::from_secs(120));

        // Case 5: ENV = 600 -> clamped to 120 seconds ceiling
        unsafe {
            std::env::set_var("W014_CLAMAV_TIMEOUT_SECS", "600");
        }
        let cfg = ClamAvConfig::from_env();
        assert_eq!(cfg.timeout, Duration::from_secs(120));

        // Case 6: Very large u64 -> clamped to 120 seconds ceiling
        unsafe {
            std::env::set_var("W014_CLAMAV_TIMEOUT_SECS", "18446744073709551615");
        }
        let cfg = ClamAvConfig::from_env();
        assert_eq!(cfg.timeout, Duration::from_secs(120));

        // Case 7: Unparseable large integer -> fallback to default 120 seconds
        unsafe {
            std::env::set_var(
                "W014_CLAMAV_TIMEOUT_SECS",
                "999999999999999999999999999999999999999999",
            );
        }
        let cfg = ClamAvConfig::from_env();
        assert_eq!(cfg.timeout, Duration::from_secs(120));

        // Case 8: Invalid text -> fallback to default 120 seconds
        unsafe {
            std::env::set_var("W014_CLAMAV_TIMEOUT_SECS", "not_a_valid_integer");
        }
        let cfg = ClamAvConfig::from_env();
        assert_eq!(cfg.timeout, Duration::from_secs(120));

        // Case 9: Negative integer -> parse fails -> fallback to default 120 seconds
        unsafe {
            std::env::set_var("W014_CLAMAV_TIMEOUT_SECS", "-50");
        }
        let cfg = ClamAvConfig::from_env();
        assert_eq!(cfg.timeout, Duration::from_secs(120));

        // Case 10: Empty string / whitespace -> parse fails -> fallback to default 120 seconds
        unsafe {
            std::env::set_var("W014_CLAMAV_TIMEOUT_SECS", "   ");
        }
        let cfg = ClamAvConfig::from_env();
        assert_eq!(cfg.timeout, Duration::from_secs(120));

        unsafe {
            std::env::set_var("W014_CLAMAV_TIMEOUT_SECS", "");
        }
        let cfg = ClamAvConfig::from_env();
        assert_eq!(cfg.timeout, Duration::from_secs(120));

        // Cleanup
        unsafe {
            std::env::remove_var("W014_CLAMAV_TIMEOUT_SECS");
        }
    }
}
