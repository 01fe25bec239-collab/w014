//! Authoritative Rust API Server Entrypoint (Composition Root).

use std::error::Error;
use tokio::signal;
use tracing::info;
use w014_api::config::ApiConfig;
use w014_api::create_app;
use w014_observability::init_tracing;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Load strongly-typed configuration
    let config = ApiConfig::load().map_err(|e| format!("configuration error: {e}"))?;

    // 2. Initialize observability subsystem
    let _guard = init_tracing(&config.observability)
        .map_err(|e| format!("observability initialization error: {e}"))?;

    info!(
        service = %config.observability.service_name,
        version = %config.observability.service_version,
        env = %config.env,
        host = %config.server.host,
        port = %config.server.port,
        "Starting W-014 Foundation Platform API Server"
    );

    // 3. Construct the API composition root router
    let app = create_app(&config);

    // 4. Bind TCP listener
    let addr = config.server.socket_addr();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(addr = %addr, "HTTP server listening");

    // 5. Run Axum server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("HTTP server shut down gracefully");
    Ok(())
}

/// Graceful shutdown listener for SIGINT and SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {
            info!("Received SIGINT (Ctrl+C), initiating graceful shutdown");
        },
        () = terminate => {
            info!("Received SIGTERM, initiating graceful shutdown");
        },
    }
}
