//! Strongly-typed Foundation API configuration.
//!
//! Loads and validates environment parameters for the API composition root.
//! Strictly avoids storing or logging business credentials or non-sanitized data.

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use w014_observability::{LogFormat, ObservabilityConfig};

/// Deployment environment profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppEnvironment {
    #[default]
    Development,
    Test,
    Staging,
    Production,
}

impl AppEnvironment {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }
}

impl fmt::Display for AppEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for AppEnvironment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().trim() {
            "development" | "dev" | "local" => Ok(Self::Development),
            "test" | "testing" => Ok(Self::Test),
            "staging" | "stage" => Ok(Self::Staging),
            "production" | "prod" => Ok(Self::Production),
            other => Err(format!(
                "invalid APP_ENV '{other}'; expected 'development', 'test', 'staging', or 'production'"
            )),
        }
    }
}

/// HTTP server network configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Host interface to bind on (e.g., "0.0.0.0" or "127.0.0.1").
    pub host: String,
    /// TCP port to bind on (default 8080).
    pub port: u16,
    /// Graceful shutdown timeout in seconds.
    pub shutdown_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            shutdown_timeout_secs: 30,
        }
    }
}

impl ServerConfig {
    /// Returns the socket address to bind to.
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        let addr_str = format!("{}:{}", self.host, self.port);
        addr_str
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], self.port)))
    }
}

use w014_authn::csrf::CsrfConfig;
use w014_authn::oidc::OidcConfig;
use w014_authn::session::SessionConfig;

/// Top-level Foundation API configuration.
#[derive(Clone)]
pub struct ApiConfig {
    /// Active environment profile.
    pub env: AppEnvironment,
    /// Server network configuration.
    pub server: ServerConfig,
    /// Observability and telemetry configuration.
    pub observability: ObservabilityConfig,
    /// OIDC Identity Provider integration configuration.
    pub oidc: OidcConfig,
    /// Authoritative server-side session configuration.
    pub session: SessionConfig,
    /// CSRF Exact Origin configuration.
    pub csrf: CsrfConfig,
    /// PostgreSQL connection URL (optional in unit test environments).
    pub database_url: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            env: AppEnvironment::Development,
            server: ServerConfig::default(),
            observability: ObservabilityConfig::default(),
            oidc: OidcConfig::default(),
            session: SessionConfig::default(),
            csrf: CsrfConfig::default(),
            database_url: None,
        }
    }
}

impl fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redaction-safe Debug: outputs structure without exposing any runtime secrets
        f.debug_struct("ApiConfig")
            .field("env", &self.env)
            .field("server", &self.server)
            .field("observability", &self.observability)
            .field("oidc.issuer", &self.oidc.issuer)
            .field("oidc.client_id", &self.oidc.client_id)
            .field("session.cookie_name", &self.session.cookie_name)
            .field("database_url_present", &self.database_url.is_some())
            .finish()
    }
}

impl ApiConfig {
    /// Loads configuration from standard environment variables with safe defaults.
    ///
    /// Fails fast if a specified configuration value is invalid.
    pub fn load() -> Result<Self, String> {
        let env_str = std::env::var("APP_ENV")
            .or_else(|_| std::env::var("ENVIRONMENT"))
            .unwrap_or_else(|_| "development".to_string());
        let env = AppEnvironment::from_str(&env_str)?;

        let host = std::env::var("HOST")
            .or_else(|_| std::env::var("W014_API_HOST"))
            .unwrap_or_else(|_| "0.0.0.0".to_string());

        let port_str = std::env::var("PORT")
            .or_else(|_| std::env::var("W014_API_PORT"))
            .unwrap_or_else(|_| "8080".to_string());

        let port = port_str
            .parse::<u16>()
            .map_err(|e| format!("invalid PORT '{port_str}': {e}"))?;

        let log_level = std::env::var("LOG_LEVEL")
            .or_else(|_| std::env::var("RUST_LOG"))
            .unwrap_or_else(|_| match env {
                AppEnvironment::Development => "debug".to_string(),
                AppEnvironment::Test => "warn".to_string(),
                AppEnvironment::Staging | AppEnvironment::Production => "info".to_string(),
            });

        let log_format = match env {
            AppEnvironment::Production | AppEnvironment::Staging => LogFormat::Json,
            AppEnvironment::Development | AppEnvironment::Test => LogFormat::Compact,
        };

        let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

        let observability = ObservabilityConfig {
            service_name: "w014-api".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            log_level,
            log_format,
            otlp_endpoint,
            enabled: true,
        };

        let database_url = std::env::var("DATABASE_URL").ok();

        let oidc_issuer = std::env::var("OIDC_ISSUER")
            .unwrap_or_else(|_| "https://accounts.google.com".to_string());
        let oidc_client_id =
            std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| "w014-client-id".to_string());
        let oidc_client_secret = std::env::var("OIDC_CLIENT_SECRET").ok();
        let oidc_redirect_uri = std::env::var("OIDC_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:8080/api/v1/auth/callback".to_string());
        let oidc_auth_endpoint = std::env::var("OIDC_AUTH_ENDPOINT")
            .unwrap_or_else(|_| "https://accounts.google.com/o/oauth2/v2/auth".to_string());
        let oidc_token_endpoint = std::env::var("OIDC_TOKEN_ENDPOINT")
            .unwrap_or_else(|_| "https://oauth2.googleapis.com/token".to_string());
        let oidc_jwks_uri = std::env::var("OIDC_JWKS_URI")
            .unwrap_or_else(|_| "https://www.googleapis.com/oauth2/v3/certs".to_string());

        let oidc = OidcConfig {
            issuer: oidc_issuer.clone(),
            issuer_allowlist: vec![oidc_issuer],
            authorization_endpoint: oidc_auth_endpoint,
            token_endpoint: oidc_token_endpoint,
            jwks_uri: oidc_jwks_uri,
            client_id: oidc_client_id,
            client_secret: oidc_client_secret,
            redirect_uri: oidc_redirect_uri,
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            state_ttl_secs: 600,
        };

        let session_secure = match env {
            AppEnvironment::Production | AppEnvironment::Staging => true,
            AppEnvironment::Development | AppEnvironment::Test => {
                std::env::var("SESSION_COOKIE_SECURE")
                    .map(|v| v.to_lowercase() == "true")
                    .unwrap_or(false)
            }
        };

        let session = SessionConfig {
            absolute_ttl_secs: 7 * 24 * 3600,
            idle_ttl_secs: 24 * 3600,
            cookie_name: std::env::var("SESSION_COOKIE_NAME")
                .unwrap_or_else(|_| "w014_session".to_string()),
            cookie_secure: session_secure,
            cookie_path: "/".to_string(),
        };

        let csrf = CsrfConfig::default();

        Ok(Self {
            env,
            server: ServerConfig {
                host,
                port,
                shutdown_timeout_secs: 30,
            },
            observability,
            oidc,
            session,
            csrf,
            database_url,
        })
    }

    /// Creates a test configuration.
    #[must_use]
    pub fn for_testing() -> Self {
        Self {
            env: AppEnvironment::Test,
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
                shutdown_timeout_secs: 5,
            },
            observability: ObservabilityConfig::for_testing(),
            oidc: OidcConfig::default(),
            session: SessionConfig::for_testing(),
            csrf: CsrfConfig::default(),
            database_url: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_parsing() {
        assert_eq!(
            AppEnvironment::from_str("development").unwrap(),
            AppEnvironment::Development
        );
        assert_eq!(
            AppEnvironment::from_str("dev").unwrap(),
            AppEnvironment::Development
        );
        assert_eq!(
            AppEnvironment::from_str("local").unwrap(),
            AppEnvironment::Development
        );
        assert_eq!(
            AppEnvironment::from_str("test").unwrap(),
            AppEnvironment::Test
        );
        assert_eq!(
            AppEnvironment::from_str("staging").unwrap(),
            AppEnvironment::Staging
        );
        assert_eq!(
            AppEnvironment::from_str("production").unwrap(),
            AppEnvironment::Production
        );
        assert_eq!(
            AppEnvironment::from_str("prod").unwrap(),
            AppEnvironment::Production
        );
        assert!(AppEnvironment::from_str("invalid_env").is_err());
    }

    #[test]
    fn test_server_socket_addr() {
        let server = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3000,
            shutdown_timeout_secs: 30,
        };
        let addr = server.socket_addr();
        assert_eq!(addr.port(), 3000);
    }
}
