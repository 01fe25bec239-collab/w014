//! Database configuration and connection pool management with credential masking.

use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

use crate::error::PersistenceError;

/// Default database URL used for local development if `DATABASE_URL` is unset.
pub const DEFAULT_LOCAL_DATABASE_URL: &str = "postgres://postgres:postgres@localhost:5432/w014_dev";

/// Configuration settings for PostgreSQL database connection and pool lifecycle.
#[derive(Clone)]
pub struct DatabaseConfig {
    /// PostgreSQL connection URL.
    pub url: String,
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
    /// Minimum number of idle connections to maintain.
    pub min_connections: u32,
    /// Timeout when establishing a new connection.
    pub connect_timeout: Duration,
    /// Timeout when acquiring a connection from the pool.
    pub acquire_timeout: Duration,
    /// Maximum idle time before closing an idle connection.
    pub idle_timeout: Duration,
    /// Maximum lifetime of an active connection.
    pub max_lifetime: Duration,
}

impl DatabaseConfig {
    /// Creates a configuration from a connection URL with default pool settings.
    pub fn from_url(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            max_connections: 10,
            min_connections: 1,
            connect_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
        }
    }

    /// Loads database configuration from the `DATABASE_URL` environment variable.
    /// Falls back to the canonical local development database URL if unset.
    pub fn from_env() -> Result<Self, PersistenceError> {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| DEFAULT_LOCAL_DATABASE_URL.to_string());
        Ok(Self::from_url(url))
    }

    /// Returns the database connection URL with passwords and sensitive credentials masked.
    ///
    /// Example: `postgres://postgres:***@localhost:5432/w014_dev`
    pub fn masked_url(&self) -> String {
        mask_connection_url(&self.url)
    }

    /// Parses connection options from the configured URL.
    pub fn connect_options(&self) -> Result<PgConnectOptions, PersistenceError> {
        PgConnectOptions::from_str(&self.url)
            .map_err(|e| PersistenceError::Config(format!("Failed to parse database URL: {e}")))
    }

    /// Builds and initializes an active connection pool, connecting immediately to verify connectivity.
    pub async fn create_pool(&self) -> Result<PgPool, PersistenceError> {
        let connect_opts = self.connect_options()?;
        let pool = PgPoolOptions::new()
            .max_connections(self.max_connections)
            .min_connections(self.min_connections)
            .acquire_timeout(self.acquire_timeout)
            .idle_timeout(self.idle_timeout)
            .max_lifetime(self.max_lifetime)
            .connect_with(connect_opts)
            .await
            .map_err(|e| {
                PersistenceError::Config(format!(
                    "Failed to connect to database at {}: {e}",
                    self.masked_url()
                ))
            })?;

        Ok(pool)
    }

    /// Builds a connection pool lazily without establishing initial connections.
    pub fn create_pool_lazy(&self) -> Result<PgPool, PersistenceError> {
        let connect_opts = self.connect_options()?;
        let pool = PgPoolOptions::new()
            .max_connections(self.max_connections)
            .min_connections(self.min_connections)
            .acquire_timeout(self.acquire_timeout)
            .idle_timeout(self.idle_timeout)
            .max_lifetime(self.max_lifetime)
            .connect_lazy_with(connect_opts);

        Ok(pool)
    }
}

/// Helper function to mask passwords in database connection URLs.
pub fn mask_connection_url(raw_url: &str) -> String {
    if let Ok(mut parsed) = Url::parse(raw_url) {
        if parsed.password().is_some() {
            let _ = parsed.set_password(Some("***"));
        }
        return parsed.to_string();
    }

    if let Some((left, right)) = raw_url.split_once('@')
        && let (Some(colon), Some(slash)) = (left.rfind(':'), left.rfind("//"))
        && colon > slash
    {
        return format!("{}:***@{right}", &left[..colon]);
    }

    raw_url.to_string()
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &self.masked_url())
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .field("connect_timeout", &self.connect_timeout)
            .field("acquire_timeout", &self.acquire_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_lifetime", &self.max_lifetime)
            .finish()
    }
}

impl fmt::Display for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DatabaseConfig(url={}, max_conns={}, min_conns={})",
            self.masked_url(),
            self.max_connections,
            self.min_connections
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_connection_url() {
        let url = "postgres://admin:secret_pass_123@localhost:5432/test_db";
        let masked = mask_connection_url(url);
        assert!(!masked.contains("secret_pass_123"));
        assert!(masked.contains("***"));
        assert!(masked.contains("admin:***@localhost:5432/test_db"));
    }

    #[test]
    fn test_debug_and_display_masking() {
        let config = DatabaseConfig::from_url("postgres://user:super_secret@db.internal:5432/prod");
        let debug_str = format!("{config:?}");
        let display_str = format!("{config}");
        assert!(!debug_str.contains("super_secret"));
        assert!(!display_str.contains("super_secret"));
        assert!(debug_str.contains("***"));
        assert!(display_str.contains("***"));
    }

    #[test]
    fn test_from_env_fallback() {
        let config = DatabaseConfig::from_url(DEFAULT_LOCAL_DATABASE_URL);
        assert_eq!(config.url, DEFAULT_LOCAL_DATABASE_URL);
    }
}
