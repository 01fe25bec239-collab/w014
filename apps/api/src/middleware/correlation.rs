//! Correlation middleware for Axum requests and responses.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;
use w014_observability::{CorrelationId, HEADER_CORRELATION_ID, HEADER_REQUEST_ID};

/// Axum middleware that extracts or generates a correlation identifier,
/// injects it into request extensions, sets up a tracing span,
/// and attaches the identifier to the HTTP response headers.
pub async fn correlation_middleware(mut req: Request, next: Next) -> Response {
    let corr_id = CorrelationId::extract_or_generate(req.headers());
    req.extensions_mut().insert(corr_id.clone());

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let id_str = corr_id.as_str().to_string();

    let span = tracing::info_span!(
        "http_request",
        correlation_id = %id_str,
        method = %method,
        uri = %path,
    );

    let mut res = next.run(req).instrument(span).await;

    if let Ok(hdr_val) = HeaderValue::from_str(&id_str) {
        res.headers_mut()
            .insert(HEADER_CORRELATION_ID, hdr_val.clone());
        res.headers_mut().insert(HEADER_REQUEST_ID, hdr_val);
    }

    res
}
